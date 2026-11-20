package io.github.immaghzbad.aetherst.core

import android.content.Context
import io.github.immaghzbad.aetherst.shared.data.IpInfoRepository
import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.model.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration.Companion.milliseconds

object LastMimHops {
    @Volatile var outer: String = ""
    @Volatile var inner: String = ""
    fun snapshot(): Pair<String, String> = Pair(outer, inner)
    fun clear() {
        outer = ""
        inner = ""
    }
}

private val MimOuterRegex = Regex("""selected\s+MASQUE\s+gateway\s+(\S+)""", RegexOption.IGNORE_CASE)
private val MimReadyRegex = Regex("""masque-in-masque\s+ready:?\s*(\S+)\s*\(outer\)\s+and\s+(\S+)\s*\(inner\)""", RegexOption.IGNORE_CASE)
private val ExitDetailRegex = Regex("""(?i)\b(?:gool|warp-in-warp|masque-in-masque|masque|wireguard|wg|mim)\s+exit:\s*([0-9a-fA-F.:]+),\s*([A-Za-z]{2})(?:\s+via\s+([A-Za-z0-9]+))?""")
private val SelectedWgEndpointRegex = Regex("""(?i)(?:selected|endpoint|gateway|validating|establishing|peer|using)[^\n]*?\b((?:162\.159|188\.114|198\.41)\.\d{1,3}\.\d{1,3}:\d{2,5})\b""")

class AetherProcessRunner(private val context: Context) {

    private val lock = Any()
    private var process: Process? = null
    private var runnerJob: Job? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val currentAttemptId = AtomicLong(0)
    private var lastBindAddress: String = "127.0.0.1:2021"

    private val _connectionStatus = MutableStateFlow(ConnectionStatus.STOPPED)
    val connectionStatus: StateFlow<ConnectionStatus> = _connectionStatus.asStateFlow()

    private val quickRetryPending = AtomicBoolean(false)

    fun start(config: AetherConfig, bindAddress: String, onCodeRequired: () -> Unit = {}, inputProvider: suspend () -> String = { kotlinx.coroutines.awaitCancellation() }) {
        synchronized(lock) {
            if (runnerJob?.isActive == true) return

            val attemptId = currentAttemptId.incrementAndGet()
            SocksGate.setReady(SocksReadiness.NOT_READY)
            lastBindAddress = bindAddress
            updateState(ConnectionStatus.STARTING, attemptId)
            runnerJob = scope.launch {
                var retryCount = 0

                while (isActive && (currentAttemptId.get() == attemptId)) {
                    if (!config.smartReconnect && retryCount > 0) {
                        LogRepository.e("Smart Reconnect disabled -> stopping retry")
                        updateState(ConnectionStatus.ERROR, attemptId)
                        break
                    }
                    if (config.smartReconnect && (retryCount >= config.reconnectRetryLimit)) {
                        LogRepository.e("Smart Reconnect limit reached ($retryCount). Stopping...")
                        updateState(ConnectionStatus.ERROR, attemptId)
                        break
                    }

                    if (retryCount > 0) {
                        SocksGate.setReady(SocksReadiness.NOT_READY)
                        val waitTime = if (quickRetryPending.compareAndSet(true, false)) {
                            3000L
                        } else {
                            (retryCount * 1000L).coerceAtMost(10000L)
                        }
                        LogRepository.i("Recovering connection (Retry $retryCount)...")
                        updateState(ConnectionStatus.RECONNECTING, attemptId)
                        delay(waitTime.milliseconds)
                    } else {
                        LogRepository.i("Starting system core...")
                    }

                    if (currentAttemptId.get() != attemptId) break

                    try {
                        val result = runBinary(config, attemptId, bindAddress, onCodeRequired, inputProvider)
                        if (currentAttemptId.get() != attemptId) break
                        if (!result) {
                            LogRepository.e("Stability check failed. Retrying...")
                        }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        LogRepository.e("Execution cycle critical error: ${e.localizedMessage}")
                    }

                    retryCount++
                }
            }
        }
    }

    private suspend fun runBinary(config: AetherConfig, attemptId: Long, bindAddress: String, onCodeRequired: () -> Unit, inputProvider: suspend () -> String): Boolean = coroutineScope {
        var proc: Process? = null
        try {
            val binaryFile = BinaryManager.prepareBinary(context)
            if (currentAttemptId.get() != attemptId) return@coroutineScope true

            // در حالت GOOL اگر نویز روی OFF باشد، در ایران هندشیک وایرگارد بلاک می‌شود؛ پس خودکار روی balanced قرار می‌گیرد
            val effectiveNoise = if (config.protocol == AetherProtocol.GOOL && config.noise == AetherNoise.OFF) {
                AetherNoise.BALANCED.rawValue
            } else {
                config.noise.rawValue
            }

            val commandList = mutableListOf<String>()
            commandList.add(binaryFile.absolutePath)
            commandList.add("--bind")
            commandList.add(bindAddress)

            commandList.addAll(config.primaryArguments())

            commandList.add("--scan")
            commandList.add(config.scanMode.rawValue)
            commandList.add("--noize")
            commandList.add(effectiveNoise)

            val routingFile = writeRoutingFile(config)
            if (routingFile != null) {
                commandList.add("--routes")
                commandList.add(routingFile.absolutePath)
            }

            val effectiveIp = if (config.protocol == AetherProtocol.GOOL && config.ipMode == AetherIpMode.AUTO) {
                AetherIpMode.IPV4
            } else {
                config.effectiveIpMode()
            }
            commandList.add(
                when (effectiveIp) {
                    AetherIpMode.IPV4 -> "-4"
                    AetherIpMode.IPV6 -> "-6"
                    else -> "--dual"
                }
            )

            if (config.httpProxyEnabled) {
                val httpBindHost = bindAddress.substringBefore(':')
                commandList.add("--http-proxy")
                commandList.add("$httpBindHost:${config.httpPort}")
            }

            if (config.noDataCheck) commandList.add("--no-data-check")
            if (config.quickReconnect) commandList.add("--quick-reconnect") else commandList.add("--no-quick-reconnect")

            if ((config.protocol == AetherProtocol.WG) || (config.protocol == AetherProtocol.GOOL)) {
                commandList.add("--keepalive")
                commandList.add(if (config.keepaliveEnabled) config.keepalive.toString() else "0")
            }

            if (config.tlsGroups.isNotEmpty()) {
                commandList.add("--tls-groups")
                commandList.add(config.tlsGroups)
            }

            commandList.add("--validate-secs")
            commandList.add(config.validateSecs.toString())

            commandList.add("--reconnect-secs")
            commandList.add(config.reconnectSecs.toString())

            if (config.noProfileRetry) commandList.add("--no-profile-retry")

            if (config.protocol == AetherProtocol.ZERO_TRUST) {
                if (config.teamName.isNotEmpty()) {
                    commandList.add("--team")
                    commandList.add(config.teamName)
                }
                when {
                    config.accessToken.isNotEmpty() -> {
                        commandList.add("--access-token")
                        commandList.add(config.accessToken)
                    }
                    config.accessId.isNotEmpty() || config.accessSecret.isNotEmpty() -> {
                        commandList.add("--access-id")
                        commandList.add(config.accessId)
                        commandList.add("--access-secret")
                        commandList.add(config.accessSecret)
                    }
                    config.accessEmail.isNotEmpty() -> {
                        commandList.add("--access-email")
                        commandList.add(config.accessEmail)
                    }
                }
                if (config.useGateway) commandList.add("--gateway")
            }

            if (config.dnsEnabled && config.dnsList.isNotEmpty()) {
                commandList.add("--dns")
                commandList.add(config.dnsList)
            }

            if (config.upstreamProxyEnabled && config.upstreamProxy.isNotEmpty()) {
                commandList.add("--upstream")
                commandList.add(config.upstreamProxy)
            }

            if (config.isTorActive()) {
                when (config.torMode) {
                    TorMode.TOR -> commandList.add("--tor")
                    TorMode.TOR_REVERSE -> commandList.add("--tor-reverse")
                    TorMode.TOR_ONLY -> commandList.add("--tor-only")
                }
                val torPort = TorController.activePort(config)
                commandList.add("--tor-bind")
                commandList.add("127.0.0.1:$torPort")
                val torDir = java.io.File(context.filesDir, "tor")
                if (!torDir.exists()) torDir.mkdirs()
                commandList.add("--tor-dir")
                commandList.add(torDir.absolutePath)
                when (config.torBridgesMode.trim().lowercase()) {
                    "force" -> commandList.add("--tor-bridges")
                    "off" -> commandList.add("--no-tor-bridges")
                }
                config.torBridgeLines.split(";", "\n").map { it.trim() }.filter { it.isNotEmpty() }.forEach {
                    commandList.add("--tor-bridge")
                    commandList.add(it)
                }
                val ptDir = config.torPtDir.trim().ifEmpty { torDir.absolutePath }
                commandList.add("--tor-pt-dir")
                commandList.add(ptDir)
                config.torPtBinaries.split(";", "\n").map { it.trim() }.filter { it.isNotEmpty() }.forEach {
                    commandList.add("--tor-pt")
                    commandList.add(it)
                }
            }

            if (!config.quicV2Probe) commandList.add("--no-quic-v2")
            if (config.firewallMark.isNotBlank()) {
                commandList.add("--mark")
                commandList.add(config.firewallMark.trim())
            }

            val logLevelArg = if (config.coreLogLevel == AetherLogLevel.DEBUG) "debug" else "info"

            cleanLegacyWireGuardIdentities(config, context.filesDir)
            val pb = ProcessBuilder(commandList)
            pb.directory(context.filesDir)

            val env = pb.environment()
            env["AETHER_NOIZE"] = effectiveNoise
            env["AETHER_SCAN"] = config.scanMode.rawValue
            env["AETHER_IP"] = effectiveIp.rawValue
            env["AETHER_SOCKS"] = bindAddress
            routingFile?.let { env["AETHER_ROUTES_FILE"] = it.absolutePath }

            if (config.httpProxyEnabled) {
                val httpBindHost = bindAddress.substringBefore(':')
                env["AETHER_HTTP_PROXY"] = "$httpBindHost:${config.httpPort}"
            }

            if (config.noDataCheck) {
                env["AETHER_MASQUE_NO_DATA_CHECK"] = "1"
                env["AETHER_WG_NO_DATA_CHECK"] = "1"
            }

            env["AETHER_QUICK_RECONNECT"] = if (config.quickReconnect) "1" else "0"


            env["AETHER_WG_KEEPALIVE"] = if (config.keepaliveEnabled) config.keepalive.toString() else "0"
            env["AETHER_WG_ENDPOINT_COOLDOWN_SECS"] = config.wgEndpointCooldownSecs.toString()
            env["AETHER_MASQUE_VALIDATE_SECS"] = config.validateSecs.toString()
            env["AETHER_WG_VALIDATE_SECS"] = config.validateSecs.toString()
            env["AETHER_MASQUE_RECONNECT_SECS"] = config.reconnectSecs.toString()
            env["AETHER_WG_RECONNECT_SECS"] = config.reconnectSecs.toString()

            if (config.noProfileRetry) env["AETHER_WG_NO_PROFILE_RETRY"] = "1"
            if (config.tlsGroups.isNotEmpty()) env["AETHER_TLS_GROUPS"] = config.tlsGroups
            if (config.masqueMtu > 0) env["AETHER_MASQUE_MTU"] = config.masqueMtu.toString()
            if (config.netstackTcpRx > 0) env["AETHER_NETSTACK_TCP_RX"] = config.netstackTcpRx.toString()
            if (config.netstackTcpTx > 0) env["AETHER_NETSTACK_TCP_TX"] = config.netstackTcpTx.toString()

            if (config.protocol == AetherProtocol.ZERO_TRUST) {
                if (config.teamName.isNotEmpty()) env["AETHER_TEAM"] = config.teamName
                when {
                    config.accessToken.isNotEmpty() -> env["AETHER_ACCESS_TOKEN"] = config.accessToken
                    config.accessId.isNotEmpty() || config.accessSecret.isNotEmpty() -> {
                        env["AETHER_ACCESS_ID"] = config.accessId
                        env["AETHER_ACCESS_SECRET"] = config.accessSecret
                        env["AETHER_ACCESS_CLIENT_ID"] = config.accessId
                        env["AETHER_ACCESS_CLIENT_SECRET"] = config.accessSecret
                    }
                    config.accessEmail.isNotEmpty() -> env["AETHER_ACCESS_EMAIL"] = config.accessEmail
                }
                if (config.useGateway) env["AETHER_GATEWAY"] = "1"
            }

            if (config.dnsEnabled && config.dnsList.isNotEmpty()) env["AETHER_DNS"] = config.dnsList
            if (config.upstreamProxyEnabled && config.upstreamProxy.isNotEmpty()) env["AETHER_UPSTREAM"] = config.upstreamProxy
            if (config.isTorActive()) {
                env["AETHER_TOR"] = when (config.torMode) {
                    TorMode.TOR -> "chain"
                    TorMode.TOR_REVERSE -> "reverse"
                    TorMode.TOR_ONLY -> "only"
                }
                val torPort = TorController.activePort(config)
                env["AETHER_TOR_BIND"] = "127.0.0.1:$torPort"
                val torDir = java.io.File(context.filesDir, "tor")
                if (!torDir.exists()) torDir.mkdirs()
                env["AETHER_TOR_DIR"] = torDir.absolutePath
                when (config.torBridgesMode.trim().lowercase()) {
                    "force" -> env["AETHER_TOR_BRIDGES"] = "auto"
                    "off" -> env["AETHER_TOR_BRIDGES"] = "off"
                }
                val manualBridges = config.torBridgeLines.split(";", "\n").map { it.trim() }.filter { it.isNotEmpty() }
                if (manualBridges.isNotEmpty()) env["AETHER_TOR_BRIDGES"] = manualBridges.joinToString(";")
                val ptBinaries = config.torPtBinaries.split(";", "\n").map { it.trim() }.filter { it.isNotEmpty() }
                if (ptBinaries.isNotEmpty()) env["AETHER_TOR_PT"] = ptBinaries.joinToString(";")
                env["AETHER_TOR_PT_DIR"] = config.torPtDir.trim().ifEmpty { torDir.absolutePath }
                if (config.torCountry.isNotBlank()) env["AETHER_TOR_COUNTRY"] = config.torCountry.trim().lowercase()
            }
            if (!config.quicV2Probe) env["AETHER_QUIC_V2"] = "0"
            if (config.firewallMark.isNotBlank()) env["AETHER_MARK"] = config.firewallMark.trim()
            if (config.halfCloseSecs > 0) env["AETHER_HALF_CLOSE_SECS"] = config.halfCloseSecs.toString()
            if (config.tcpKeepaliveSecs > 0) env["AETHER_TCP_KEEPALIVE_SECS"] = config.tcpKeepaliveSecs.toString()
            if (config.tcpConnectSecs > 0) env["AETHER_TCP_CONNECT_SECS"] = config.tcpConnectSecs.toString()
            if (config.maxClients > 0) env["AETHER_MAX_CLIENTS"] = config.maxClients.toString()
            env["AETHER_ROUTE_SNIFF"] = if (config.routeSniffing) "1" else "0"
            env["AETHER_ROUTE_SNIFF_MS"] = config.sniffingTimeoutMs.toString()
            env["AETHER_REPROVISION"] = if (config.reprovision) "1" else "0"

            env["AETHER_PERF_PROFILE"] = config.perfProfile.rawValue
            env["AETHER_LOG_LEVEL"] = logLevelArg

            pb.redirectErrorStream(true)
            proc = withContext(Dispatchers.IO) { pb.start() }

            synchronized(lock) {
                if (currentAttemptId.get() != attemptId) {
                    proc?.destroyForcibly()
                    return@coroutineScope true
                }
                process = proc
            }

            val inputJob = launch {
                val writer = BufferedWriter(OutputStreamWriter(proc!!.outputStream))
                try {
                    while (isActive) {
                        val text = inputProvider()
                        if (text.isNotEmpty()) {
                            writer.write(text)
                            writer.newLine()
                            writer.flush()
                        }
                    }
                } catch (_: Exception) {}
            }

            BufferedReader(InputStreamReader(proc!!.inputStream)).use { reader ->
                var line: String?
                while (currentCoroutineContext().isActive && (currentAttemptId.get() == attemptId)) {
                    line = try {
                        reader.readLine()
                    } catch (e: java.io.IOException) {
                        if (currentAttemptId.get() != attemptId) null else throw e
                    } ?: break

                    parseOutputLine(line, attemptId, config.primaryProtocol, config.exitNodeMode, onCodeRequired)
                }
            }

            inputJob.cancel()
            val exitCode = try { withContext(Dispatchers.IO) { proc.waitFor() } } catch (_: Exception) { -1 }
            if (currentAttemptId.get() == attemptId) {
                LogRepository.i("Core process terminated (Exit code: $exitCode)")
            }
            exitCode == 0
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (currentAttemptId.get() == attemptId) {
                LogRepository.e("Binary runtime error: ${e.localizedMessage}")
                return@coroutineScope false
            }
            true
        } finally {
            synchronized(lock) {
                if (process === proc) process = null
            }
            try { proc?.destroyForcibly() } catch (_: Exception) {}
        }
    }

    private fun isZeroTrustCodePrompt(line: String): Boolean {
        return line.contains("code") && (
            line.contains("enter") || line.contains("login") || line.contains("verif") ||
            line.contains("confirm") || line.contains("otp") || line.contains("one-time") ||
            line.contains("type the") || line.contains("paste") || line.contains("prompt")
        )
    }

    private suspend fun parseOutputLine(line: String, attemptId: Long, protocol: AetherProtocol, exitNodeMode: ExitNodeMode, onCodeRequired: () -> Unit) {
        if (currentAttemptId.get() != attemptId) return

        val lower = line.lowercase()

        val isBroken = lower.contains("broken pipe") || lower.contains("stream closed")
        if (!isBroken) {
            val source = if (lower.contains("tor")) "Tor" else "AetherCore"
            when {
                lower.contains(" error ") || lower.contains("[error]") || lower.startsWith("error:") -> LogRepository.e(line, source)
                lower.contains(" warn ") || lower.contains("[warn]") -> LogRepository.w(line, source)
                else -> LogRepository.i(line, source)
            }
        }

        if (protocol == AetherProtocol.ZERO_TRUST && isZeroTrustCodePrompt(lower)) {
            onCodeRequired()
            return
        }

        SelectedWgEndpointRegex.find(line)?.let { match ->
            val ep = match.groupValues.getOrNull(1)?.trim() ?: ""
            if (ep.isNotEmpty() && !ep.startsWith("127.") && !ep.startsWith("0.")) {
                runCatching { java.io.File(context.filesDir, "aether-active-endpoint.txt").writeText(ep) }
            }
        }

        ExitDetailRegex.find(line)?.let { match ->
            val ip = match.groupValues.getOrNull(1)?.trim() ?: ""
            val country = match.groupValues.getOrNull(2)?.trim()?.uppercase() ?: ""
            val colo = match.groupValues.getOrNull(3)?.trim() ?: ""
            if (ip.isNotEmpty() && country.length == 2 && exitNodeMode == ExitNodeMode.DIRECT) {
                IpInfoRepository.updateFromExitLine(ip, country, colo)
            }
        }

        if (lower.contains("masque") || lower.contains("warp-in-warp") || lower.contains("wireguard")) {
            MimOuterRegex.find(line)?.let { LastMimHops.outer = it.groupValues[1].trim().trimEnd(',', ';') }
            MimReadyRegex.find(line)?.let {
                LastMimHops.outer = it.groupValues[1].trim().trimEnd(',', ';')
                LastMimHops.inner = it.groupValues[2].trim().trimEnd(',', ';')
            }
        }

        if (lower.contains("tor")) {
            val bootstrapMatch = Regex("""bootstrapp?ed?\s+(\d{1,3})\s*%""").find(lower)
            if (bootstrapMatch != null) {
                bootstrapMatch.groupValues.getOrNull(1)?.toIntOrNull()?.let { TorController.notifyBootstrap(it) }
            }
            if (lower.contains("tor is ready") || lower.contains("leaves through tor") || lower.contains("way out")) {
                TorController.notifyCoreReady()
                TorController.notifyBootstrap(100)
                val readyPort = Regex("""127\.0\.0\.1:(\d+)""").find(line)?.groupValues?.getOrNull(1)?.toIntOrNull()
                TorController.notifySocksListening(readyPort ?: TorController.currentPort())
                TorController.notifyProxyReady(readyPort ?: TorController.currentPort())
            } else if (lower.contains("tor socks5 listening")) {
                val listenPort = Regex("""127\.0\.0\.1:(\d+)""").find(line)?.groupValues?.getOrNull(1)?.toIntOrNull()
                TorController.notifySocksListening(listenPort ?: TorController.currentPort())
            }
        }

        when (primarySignal(line, lastBindAddress)) {
            PrimarySignal.FATAL -> {
                SocksGate.setReady(SocksReadiness.NOT_READY)
                updateState(ConnectionStatus.ERROR, attemptId)
            }
            PrimarySignal.LOST -> {
                SocksGate.setReady(SocksReadiness.NOT_READY)
                quickRetryPending.set(PsiphonController.isConnected() || TorController.isConnected())
                updateState(ConnectionStatus.RECONNECTING, attemptId)
            }
            PrimarySignal.SERVING -> {
                val ok = primarySocksResponds(lastBindAddress.substringAfterLast(':').toInt())
                if (currentAttemptId.get() != attemptId) return
                if (!ok) LogRepository.e("[Primary] Core announced its SOCKS listener but did not negotiate SOCKS5")
                quickRetryPending.set(false)
                SocksGate.setReady(if (ok) SocksReadiness.PROBED_OK else SocksReadiness.NOT_READY)
                updateState(if (ok) ConnectionStatus.SOCKS_READY else ConnectionStatus.ERROR, attemptId)
            }
            PrimarySignal.SCANNING, PrimarySignal.VALIDATING -> {
                if (_connectionStatus.value == ConnectionStatus.STARTING) updateState(ConnectionStatus.VALIDATING, attemptId)
            }
            null -> Unit
        }
    }

    private fun updateState(state: ConnectionStatus, attemptId: Long = currentAttemptId.get()) {
        if (currentAttemptId.get() == attemptId) {
            _connectionStatus.value = state
        }
    }

    private fun writeRoutingFile(config: AetherConfig): java.io.File? {
        val rules = config.routingRules
        val block = rules.filter { it.mode == RoutingMode.BLOCK }
        val direct = rules.filter { it.mode == RoutingMode.DIRECT }

        if (block.isEmpty() && direct.isEmpty()) return null

        return try {
            val file = java.io.File(context.filesDir, "routing.ast")
            val content = StringBuilder()

            if (block.isNotEmpty()) {
                content.append("[block]\n")
                block.forEach { content.append(formatRoutingPattern(it.pattern)).append("\n") }
                content.append("\n")
            }

            if (direct.isNotEmpty()) {
                content.append("[direct]\n")
                direct.forEach { content.append(formatRoutingPattern(it.pattern)).append("\n") }
                content.append("\n")
            }

            file.writeText(content.toString())
            file
        } catch (e: Exception) {
            LogRepository.e("Failed to write routing file: ${e.localizedMessage}")
            null
        }
    }

    private fun formatRoutingPattern(pattern: String): String {
        val trimmed = pattern.trim()
        if (trimmed.startsWith("domain:") || trimmed.startsWith("ip:") ||
            trimmed.startsWith("keyword:") || trimmed.startsWith("regexp:") ||
            trimmed == "private") {
            return trimmed
        }

        val isIp = trimmed.all { it.isDigit() || it == '.' || it == ':' || it == '/' || (it.lowercaseChar() in 'a'..'f') } &&
                (trimmed.contains('.') || trimmed.contains(':'))

        return if (isIp) "ip:$trimmed" else "domain:$trimmed"
    }

    fun stop() {
        currentAttemptId.incrementAndGet()
        SocksGate.setReady(SocksReadiness.NOT_READY)
        LastMimHops.clear()
        _connectionStatus.value = ConnectionStatus.STOPPED

        var jobToCancel: Job?
        var procToDestroy: Process?

        synchronized(lock) {
            jobToCancel = runnerJob
            procToDestroy = process
            runnerJob = null
            process = null
        }

        jobToCancel?.cancel()
        try {
            procToDestroy?.destroyForcibly()
        } catch (_: Exception) {}

        LogRepository.i("System core shutdown initiated.")
    }

    fun release() {
        stop()
        scope.cancel()
    }

    private fun cleanLegacyWireGuardIdentities(
        config: AetherConfig,
        workDir: java.io.File
    ) {
        // Clean up any stale .corrupt or custom-wg-inner files in root workDir so Layer-1 (WG / GOOL / MASQUE)
        // always uses clean Cloudflare WARP identities without TOML deserialization failure (missing field 'ipv6').
        val innerFiles = listOf(
            java.io.File(workDir, "aether-gool.toml"),
            java.io.File(workDir, "aether-masque-gool.toml"),
            java.io.File(workDir, "aether-secondary.toml"),
            java.io.File(workDir, "aether-wg-secondary.toml")
        )
        for (f in innerFiles) {
            runCatching {
                val corrupt = java.io.File(workDir, "${f.name}.corrupt")
                if (corrupt.exists()) corrupt.delete()
                if (f.exists()) {
                    val txt = f.readText()
                    if (txt.contains("custom-wg-inner") || !txt.contains("ipv6")) {
                        f.delete()
                    }
                }
            }
        }
        val customPriv = config.customWgConfig.privateKey.trim()
        for (outerName in listOf("aether.toml", "aether-wg.toml", "aether-masque.toml")) {
            val outerFile = java.io.File(workDir, outerName)
            runCatching {
                val corrupt = java.io.File(workDir, "$outerName.corrupt")
                if (corrupt.exists()) corrupt.delete()
                if (outerFile.exists()) {
                    val txt = outerFile.readText()
                    if ((customPriv.isNotEmpty() && txt.contains(customPriv)) || !txt.contains("ipv6")) {
                        outerFile.delete()
                    }
                }
            }
        }
    }

}
