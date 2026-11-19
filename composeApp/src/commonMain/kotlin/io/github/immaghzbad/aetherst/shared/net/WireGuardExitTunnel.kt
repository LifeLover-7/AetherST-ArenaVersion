package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.model.CustomWireGuardConfig
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Userspace WireGuard Exit Tunnel Manager powered by sing-box.
 * Chains the secondary WireGuard tunnel (e.g. Proton VPN or custom WG) over Aether's
 * anti-censorship primary tunnel (WireGuard / MASQUE / Gool) without MTU blackholes,
 * Android SELinux netlink crashes, or circular DNS deadlocks.
 */
class WireGuardExitTunnel(
    private val config: CustomWireGuardConfig,
    private val binaryPath: String? = null,
    private val workingDir: String? = null,
    private val primarySocksHost: String = "127.0.0.1",
    private val primarySocksPort: Int = 2021,
    val localListenPort: Int = 10805
) {
    private val isRunning = AtomicBoolean(false)
    private var process: Process? = null
    private var logThread: Thread? = null
    private var configFile: File? = null

    @Volatile
    var verifiedExitIp: String? = null
        private set

    @Volatile
    var lastErrorMessage: String? = null
        private set

    @Synchronized
    fun start(): Boolean {
        if (isRunning.get() && isHealthy()) return true
        // Clean up any stale state before starting
        stopInternal()
        isRunning.set(true)
        verifiedExitIp = null
        lastErrorMessage = null

        if (!config.isValid()) {
            lastErrorMessage = "Invalid WireGuard config: Endpoint, PrivateKey or PublicKey is missing"
            LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
            isRunning.set(false)
            return false
        }

        val binPath = binaryPath?.takeIf { File(it).exists() } ?: findSingBoxBinary()
        if (binPath == null) {
            lastErrorMessage = "sing-box binary not found"
            LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
            isRunning.set(false)
            return false
        }

        return try {
            val rawEndpoint = config.endpoint.trim()
            val endpointHostRaw = if (rawEndpoint.startsWith("[")) {
                rawEndpoint.substringAfter('[').substringBefore(']')
            } else {
                rawEndpoint.substringBeforeLast(':')
            }.trim()
            val endpointPort = rawEndpoint.substringAfterLast(':', "51820").trim().toIntOrNull() ?: 51820

            // Pre-resolve hostname if endpoint is a domain to avoid bootstrap DNS delay
            val endpointHost = resolveEndpointHostIfNeeded(endpointHostRaw)

            val v4 = config.addressV4.substringBefore('/').trim().ifBlank { "10.2.0.2" }
            val v6 = config.addressV6.substringBefore('/').trim()

            // Clamp inner WireGuard MTU to 1120 so encapsulated packets (1120 + ~60B WG/UDP/IP overhead = 1180B)
            // always fit inside Aether's 1280B outer tunnel without silent MTU blackhole drops.
            val safeInnerMtu = config.mtu.takeIf { it in 1000..1140 } ?: INNER_WG_SAFE_MTU

            val workDirStr = workingDir ?: runCatching {
                val home = System.getProperty("user.home") ?: "."
                val dir = File(home, ".aether")
                dir.mkdirs()
                dir.absolutePath
            }.getOrDefault(".")
            val workDir = File(workDirStr)
            workDir.mkdirs()

            // Ensure no orphaned sing-box instance is still holding localListenPort
            if (isPortListening("127.0.0.1", localListenPort) || isPortListening("127.0.0.1", localListenPort - 1)) {
                LogRepository.w("[WgExit] Port $localListenPort is busy; cleaning up stale sing-box process...", "WgExit")
                killStaleSingBoxProcess(localListenPort)
                Thread.sleep(350)
            }

            val cfgJson = buildSingBoxConfig(
                listenPort = localListenPort,
                endpointHost = endpointHost,
                endpointPort = endpointPort,
                v4 = v4,
                v6 = v6,
                privateKey = config.privateKey.trim(),
                publicKey = config.publicKey.trim(),
                mtu = safeInnerMtu
            )

            val cFile = File(workDir, "singbox-wg-${localListenPort}.json")
            cFile.writeText(cfgJson)
            configFile = cFile

            val detourDesc = if (primarySocksPort > 0) "Aether Upstream ($primarySocksHost:$primarySocksPort)" else "Direct"
            LogRepository.i(
                "[WgExit] Launching sing-box (Exit: $endpointHost:$endpointPort, MTU: $safeInnerMtu, Detour: $detourDesc, LocalPort: $localListenPort)...",
                "WgExit"
            )

            val cmd = listOf(binPath, "run", "-c", cFile.absolutePath)
            val pb = ProcessBuilder(cmd)
            pb.directory(workDir)
            pb.redirectErrorStream(true)
            val proc = pb.start()
            process = proc

            val recentErrors = ArrayList<String>(8)
            logThread = Thread({
                try {
                    BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                        var line: String? = null
                        while (proc.isAlive && reader.readLine().also { line = it } != null) {
                            val l = line ?: break
                            if (l.contains("ERROR", ignoreCase = true) || l.contains("FATAL", ignoreCase = true)) {
                                synchronized(recentErrors) {
                                    if (recentErrors.size >= 6) recentErrors.removeAt(0)
                                    recentErrors.add(l)
                                }
                                LogRepository.e("[sing-box] $l", "sing-box")
                            } else if (l.contains("WARN", ignoreCase = true)) {
                                LogRepository.w("[sing-box] $l", "sing-box")
                            } else {
                                LogRepository.i("[sing-box] $l", "sing-box")
                            }
                        }
                    }
                } catch (_: Exception) {}
            }, "Aether-WgExit-Logger").apply { isDaemon = true; start() }

            var portReady = false
            val startWait = System.currentTimeMillis()
            while (System.currentTimeMillis() - startWait < 12000) {
                if (!proc.isAlive) {
                    val errTail = synchronized(recentErrors) { recentErrors.lastOrNull() }
                    lastErrorMessage = "sing-box exited prematurely (code=${proc.exitValue()})${if (errTail != null) ": $errTail" else ""}"
                    LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
                    stopInternal()
                    return false
                }
                if (isPortListening("127.0.0.1", localListenPort)) {
                    portReady = true
                    break
                }
                Thread.sleep(200)
            }

            if (!portReady) {
                lastErrorMessage = "sing-box listener failed to bind on 127.0.0.1:$localListenPort within 12s"
                LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
                stopInternal()
                return false
            }

            // Allow initial WireGuard handshake over Layer-1 tunnel
            Thread.sleep(900)

            LogRepository.i("[WgExit] Verifying end-to-end packet flow through Layer-2 WireGuard...", "WgExit")
            val verifiedIp = verifyDataPlaneWithRetry(localListenPort, maxAttempts = 5)
            if (verifiedIp != null) {
                verifiedExitIp = verifiedIp
                LogRepository.i("[WgExit] Layer-2 WireGuard exit node verified! Exit IP: $verifiedIp", "WgExit")
                true
            } else {
                lastErrorMessage = "Layer-2 WireGuard handshake failed over Layer-1 (check WG key/endpoint or ensure Layer-1 tunnel is stable)"
                LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
                stopInternal()
                false
            }
        } catch (e: Exception) {
            lastErrorMessage = "Startup exception: ${e.message}"
            LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
            stopInternal()
            false
        }
    }

    @Synchronized
    fun stop() {
        stopInternal()
    }

    private fun stopInternal() {
        isRunning.set(false)
        verifiedExitIp = null
        try {
            process?.let { p ->
                if (p.isAlive) {
                    p.destroy()
                    p.waitFor(1500, TimeUnit.MILLISECONDS)
                    if (p.isAlive) p.destroyForcibly()
                }
            }
        } catch (_: Exception) {}
        process = null

        try {
            logThread?.interrupt()
        } catch (_: Exception) {}
        logThread = null

        try {
            configFile?.delete()
        } catch (_: Exception) {}
    }

    fun isConnected(): Boolean = isRunning.get() && process?.isAlive == true && verifiedExitIp != null

    fun isHealthy(): Boolean = isRunning.get() && process?.isAlive == true && isPortListening("127.0.0.1", localListenPort)

    private fun resolveEndpointHostIfNeeded(host: String): String {
        val isIpv4 = host.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))
        val isIpv6 = host.contains(':')
        if (isIpv4 || isIpv6) return host
        return runCatching {
            InetAddress.getAllByName(host)
                .firstOrNull { it.address.size == 4 }
                ?.hostAddress ?: host
        }.getOrDefault(host)
    }

    private fun killStaleSingBoxProcess(port: Int) {
        val isWin = System.getProperty("os.name", "").lowercase().contains("win")
        runCatching {
            if (isWin) {
                ProcessBuilder("cmd", "/c", "for /f \"tokens=5\" %a in ('netstat -aon ^| findstr :$port') do taskkill /F /PID %a")
                    .start().waitFor(1500, TimeUnit.MILLISECONDS)
            } else {
                ProcessBuilder("sh", "-c", "pkill -f singbox-wg-$port.json")
                    .start().waitFor(1000, TimeUnit.MILLISECONDS)
            }
        }
    }

    private fun findSingBoxBinary(): String? {
        val binName = if (System.getProperty("os.name", "").lowercase().contains("win")) "sing-box.exe" else "sing-box"
        val candidates = listOf(
            File("composeApp/src/desktopMain/resources/bin", binName),
            File("bin", binName),
            File(binName)
        )
        return candidates.firstOrNull { it.exists() && it.isFile }?.absolutePath
    }

    private fun buildSingBoxConfig(
        listenPort: Int,
        endpointHost: String,
        endpointPort: Int,
        v4: String,
        v6: String,
        privateKey: String,
        publicKey: String,
        mtu: Int
    ): String {
        val cleanV4 = if (v4.contains('/')) v4 else "$v4/32"
        val localAddresses = mutableListOf("\"$cleanV4\"")
        if (v6.isNotBlank()) {
            val safeV6 = if (v6.contains('/')) v6 else "$v6/128"
            localAddresses.add("\"$safeV6\"")
        }

        val hasUpstreamSocks = primarySocksPort > 0
        val innerDetour = if (hasUpstreamSocks) "aether-upstream" else "direct"

        val upstreamOutbound = if (hasUpstreamSocks) {
            """
            {
              "type": "socks",
              "tag": "aether-upstream",
              "server": "$primarySocksHost",
              "server_port": $primarySocksPort,
              "version": "5",
              "udp_over_tcp": false
            },
            """.trimIndent()
        } else ""

        // Primary DNS server from user's WG config (fallback to 1.1.1.1)
        val primaryWgDns = config.dnsServers.firstOrNull {
            it.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$""")) && !it.startsWith("10.") && !it.startsWith("192.168.")
        } ?: "1.1.1.1"

        return """
        {
          "log": {
            "level": "info",
            "timestamp": true
          },
          "dns": {
            "servers": [
              {
                "tag": "dns-proton",
                "address": "tcp://$primaryWgDns",
                "detour": "proton-exit",
                "strategy": "ipv4_only"
              },
              {
                "tag": "dns-upstream",
                "address": "tcp://1.1.1.1",
                "detour": "$innerDetour",
                "strategy": "ipv4_only"
              }
            ],
            "rules": [
              {
                "outbound": "any",
                "server": "dns-upstream"
              }
            ],
            "final": "dns-proton",
            "strategy": "ipv4_only"
          },
          "inbounds": [
            {
              "type": "socks",
              "tag": "socks-in",
              "listen": "127.0.0.1",
              "listen_port": $listenPort,
              "sniff": true,
              "sniff_override_destination": false
            },
            {
              "type": "http",
              "tag": "http-in",
              "listen": "127.0.0.1",
              "listen_port": ${listenPort - 1},
              "sniff": true,
              "sniff_override_destination": false
            }
          ],
          "outbounds": [
            {
              "type": "wireguard",
              "tag": "proton-exit",
              "server": "$endpointHost",
              "server_port": $endpointPort,
              "local_address": [${localAddresses.joinToString(", ")}],
              "private_key": "$privateKey",
              "peer_public_key": "$publicKey",
              "mtu": $mtu,
              "gso": false,
              "detour": "$innerDetour"
            },
            $upstreamOutbound
            {
              "type": "dns",
              "tag": "dns-out"
            },
            {
              "type": "direct",
              "tag": "direct"
            }
          ],
          "route": {
            "rules": [
              {
                "protocol": "dns",
                "outbound": "dns-out"
              },
              {
                "port": 53,
                "outbound": "dns-out"
              },
              {
                "inbound": ["socks-in", "http-in"],
                "outbound": "proton-exit"
              }
            ],
            "final": "proton-exit",
            "auto_detect_interface": false
          }
        }
        """.trimIndent()
    }

    private fun verifyDataPlaneWithRetry(socksPort: Int, maxAttempts: Int = 5): String? {
        for (attempt in 1..maxAttempts) {
            if (process?.isAlive != true) return null
            val ip = verifyDataPlane(socksPort)
            if (ip != null) return ip
            if (attempt < maxAttempts) Thread.sleep(1000)
        }
        return null
    }

    private fun verifyDataPlane(socksPort: Int): String? {
        // Probe 1 (Zero DNS dependency): Cloudflare trace via direct IP 1.1.1.1:80
        probeCloudflareTraceByIp(socksPort, byteArrayOf(1, 1, 1, 1), "1.1.1.1")?.let { return it }

        // Probe 2 (Zero DNS dependency fallback): Cloudflare trace via 1.0.0.1:80
        probeCloudflareTraceByIp(socksPort, byteArrayOf(1, 0, 0, 1), "1.0.0.1")?.let { return it }

        // Probe 3: checkip.amazonaws.com (reliable, no strict rate limit on shared Proton IPs)
        probeSimpleHttpIp(socksPort, "checkip.amazonaws.com", "/")?.let { return it }

        // Probe 4: api.ipify.org
        probeSimpleHttpIp(socksPort, "api.ipify.org", "/")?.let { return it }

        // Probe 5: ip-api.com
        probeIpApi(socksPort)?.let { return it }

        return null
    }

    private fun probeCloudflareTraceByIp(socksPort: Int, ipv4Bytes: ByteArray, hostHeader: String): String? {
        return try {
            Socket().use { socket ->
                socket.soTimeout = 5000
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2500)
                val out = socket.getOutputStream()
                val input = socket.getInputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val authResp = ByteArray(2)
                readFully(input, authResp)
                if (authResp[0] == 0x05.toByte() && authResp[1] == 0x00.toByte()) {
                    val req = byteArrayOf(
                        0x05, 0x01, 0x00, 0x01,
                        ipv4Bytes[0], ipv4Bytes[1], ipv4Bytes[2], ipv4Bytes[3],
                        0x00, 0x50
                    )
                    out.write(req)
                    out.flush()
                    val connResp = ByteArray(4)
                    readFully(input, connResp)
                    if (connResp[1] == 0x00.toByte()) {
                        consumeSocksBoundAddress(input, connResp[3])
                        val httpReq = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: $hostHeader\r\nUser-Agent: AetherST/2.5\r\nConnection: close\r\n\r\n"
                        out.write(httpReq.toByteArray(Charsets.US_ASCII))
                        out.flush()
                        val text = input.bufferedReader(Charsets.US_ASCII).readText()
                        val ip = Regex("""(?m)^ip=(.+)$""").find(text)?.groupValues?.get(1)?.trim()
                        val loc = Regex("""(?m)^loc=(.+)$""").find(text)?.groupValues?.get(1)?.trim()?.uppercase()
                        if (!ip.isNullOrBlank() && loc != "IR") {
                            LogRepository.i("[WgExit] Cloudflare trace verified via $hostHeader: $ip ($loc)", "WgExit")
                            return ip
                        }
                    }
                }
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun probeSimpleHttpIp(socksPort: Int, targetHost: String, path: String): String? {
        return try {
            Socket().use { socket ->
                socket.soTimeout = 5500
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2500)
                val out = socket.getOutputStream()
                val input = socket.getInputStream()

                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val authResp = ByteArray(2)
                readFully(input, authResp)
                if (authResp[0] != 0x05.toByte() || authResp[1] != 0x00.toByte()) return null

                val hostBytes = targetHost.toByteArray(Charsets.US_ASCII)
                val req = ByteArray(4 + 1 + hostBytes.size + 2)
                req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03
                req[4] = hostBytes.size.toByte()
                System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
                req[req.size - 2] = 0x00
                req[req.size - 1] = 0x50
                out.write(req)
                out.flush()

                val connResp = ByteArray(4)
                readFully(input, connResp)
                if (connResp[1] != 0x00.toByte()) return null
                consumeSocksBoundAddress(input, connResp[3])

                val httpReq = "GET $path HTTP/1.1\r\nHost: $targetHost\r\nUser-Agent: AetherST/2.5\r\nConnection: close\r\n\r\n"
                out.write(httpReq.toByteArray(Charsets.US_ASCII))
                out.flush()

                val reader = BufferedReader(InputStreamReader(input, Charsets.US_ASCII))
                var inBody = false
                while (true) {
                    val line = reader.readLine() ?: break
                    if (inBody) {
                        val candidate = line.trim()
                        if (candidate.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) {
                            LogRepository.i("[WgExit] Data-plane verified via $targetHost: $candidate", "WgExit")
                            return candidate
                        }
                    } else if (line.isEmpty()) {
                        inBody = true
                    }
                }
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun probeIpApi(socksPort: Int): String? {
        val targetHost = "ip-api.com"
        return try {
            Socket().use { socket ->
                socket.soTimeout = 6000
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2500)
                val out = socket.getOutputStream()
                val input = socket.getInputStream()

                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val authResp = ByteArray(2)
                readFully(input, authResp)
                if (authResp[0] != 0x05.toByte() || authResp[1] != 0x00.toByte()) return null

                val hostBytes = targetHost.toByteArray(Charsets.US_ASCII)
                val req = ByteArray(4 + 1 + hostBytes.size + 2)
                req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03
                req[4] = hostBytes.size.toByte()
                System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
                req[req.size - 2] = 0x00
                req[req.size - 1] = 0x50
                out.write(req)
                out.flush()

                val connResp = ByteArray(4)
                readFully(input, connResp)
                if (connResp[1] != 0x00.toByte()) return null
                consumeSocksBoundAddress(input, connResp[3])

                val httpReq = "GET /line/?fields=status,countryCode,query HTTP/1.1\r\nHost: $targetHost\r\nUser-Agent: AetherST/2.5\r\nConnection: close\r\n\r\n"
                out.write(httpReq.toByteArray(Charsets.US_ASCII))
                out.flush()

                val reader = BufferedReader(InputStreamReader(input, Charsets.US_ASCII))
                var inBody = false
                val bodyLines = mutableListOf<String>()
                while (true) {
                    val line = reader.readLine() ?: break
                    if (inBody) {
                        if (line.trim().isNotBlank()) bodyLines.add(line.trim())
                    } else if (line.isEmpty()) {
                        inBody = true
                    }
                }
                if (bodyLines.isNotEmpty() && bodyLines[0].equals("success", ignoreCase = true) && bodyLines.size >= 3) {
                    val country = bodyLines[1].uppercase()
                    val ip = bodyLines[2]
                    if (country != "IR" && ip.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) {
                        return ip
                    }
                }
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun consumeSocksBoundAddress(input: java.io.InputStream, atyp: Byte) {
        when (atyp) {
            0x01.toByte() -> readFully(input, ByteArray(4 + 2))
            0x03.toByte() -> {
                val len = input.read()
                if (len > 0) readFully(input, ByteArray(len + 2))
            }
            0x04.toByte() -> readFully(input, ByteArray(16 + 2))
        }
    }

    private fun readFully(input: java.io.InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val count = input.read(buffer, offset, buffer.size - offset)
            if (count < 0) throw java.io.EOFException("Premature EOF reading from SOCKS")
            offset += count
        }
    }

    private fun isPortListening(host: String, port: Int): Boolean {
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(host, port), 200)
                true
            }
        } catch (_: Exception) {
            false
        }
    }

    companion object {
        const val INNER_WG_SAFE_MTU = 1120

        fun probeProfilesFast(
            profiles: List<CustomWireGuardConfig>,
            timeoutMs: Int = 1200
        ): List<CustomWireGuardConfig> {
            val valid = profiles.filter { it.isValid() }
            if (valid.isEmpty()) return profiles

            val executor = Executors.newFixedThreadPool(valid.size.coerceIn(1, 8))
            val updated = java.util.concurrent.ConcurrentHashMap<String, Long>()

            val futures = valid.map { cfg ->
                executor.submit {
                    val endpoint = cfg.endpoint.substringBefore(':').trim()
                    val port = cfg.endpoint.substringAfter(':', "51820").toIntOrNull() ?: 51820
                    val start = System.currentTimeMillis()
                    var ping = -1L
                    try {
                        Socket().use { s ->
                            s.connect(InetSocketAddress(endpoint, port), timeoutMs)
                            ping = System.currentTimeMillis() - start
                        }
                    } catch (_: Exception) {
                        val elapsed = System.currentTimeMillis() - start
                        if (elapsed in 10..timeoutMs) {
                            ping = elapsed
                        }
                    }
                    updated[cfg.id] = ping
                }
            }

            for (f in futures) {
                runCatching { f.get(timeoutMs.toLong() + 200, TimeUnit.MILLISECONDS) }
            }
            executor.shutdownNow()

            return profiles.map { p ->
                val newPing = updated[p.id]
                if (newPing != null && newPing > 0) p.copy(lastPingMs = newPing) else p
            }
        }

        fun selectFastestProfile(
            profiles: List<CustomWireGuardConfig>,
            fallback: CustomWireGuardConfig
        ): CustomWireGuardConfig {
            val valid = profiles.filter { it.isValid() }
            if (valid.isEmpty()) return fallback
            if (valid.size == 1) return valid.first()

            val sorted = valid.sortedBy { if (it.lastPingMs > 0) it.lastPingMs else Long.MAX_VALUE }
            return sorted.first()
        }
    }
}
