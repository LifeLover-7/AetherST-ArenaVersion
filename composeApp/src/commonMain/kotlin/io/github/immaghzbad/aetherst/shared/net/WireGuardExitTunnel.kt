package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.model.CustomWireGuardConfig
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.BufferedReader
import java.io.DataInputStream
import java.io.File
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Userspace Two-Layer WireGuard Exit Tunnel Manager.
 *
 * Root-Cause Architecture:
 *  - Disassembly of `aether.exe` (`src\socks.rs` at `0x11ce80: cmp $0x35, %ax`) proves that Aether's
 *    local SOCKS5 `UDP ASSOCIATE` listener on `127.0.0.1:2021` ONLY forwards UDP port 53 (DNS) and
 *    unconditionally drops all other UDP ports (`[-] udp to <host>:<port> cannot be carried: this
 *    listener reaches the internet over tcp only`).
 *  - Consequently, routing a `sing-box` WireGuard outbound via `"detour": "aether-upstream"` (127.0.0.1:2021)
 *    drops 100% of WireGuard UDP `:51820` handshake packets.
 *
 * Dual-Engine Solution:
 *  1. **Engine 1 (Native Aether Inner WireGuard Chaining — Zero-Overhead Bridge)**:
 *     `AetherProcessRunner` provisions `aether-gool.toml` (for `--gool`, WireGuard inside MASQUE)
 *     and `aether-secondary.toml` (for `--gool-classic`, WireGuard inside WireGuard with
 *     `--api-address 127.0.0.1:1`), so `aether`'s own Rust `smoltcp` netstack tunnels the inner
 *     Proton/Custom WireGuard hop directly inside the outer Cloudflare tunnel.
 *     When `start()` detects that `primarySocksHost:primarySocksPort` (`127.0.0.1:2021`) is already
 *     exiting through the inner non-WARP WireGuard server (`/cdn-cgi/trace` reports `warp=off` and
 *     `loc != IR`), `WireGuardExitTunnel` starts an in-process local SOCKS5 (`localListenPort`, 10805)
 *     + HTTP (`localListenPort - 1`, 10804) bridge to `127.0.0.1:2021`.
 *  2. **Engine 2 (`sing-box` Two-Stage Userspace WireGuard Chain: `outer-warp` -> `proton-exit`)**:
 *     If `127.0.0.1:2021` is only exiting through Layer-1 Cloudflare WARP (`warp=on`), `WireGuardExitTunnel`
 *     reads the outer Cloudflare WARP identity (`aether.toml`) + active scanned Cloudflare endpoint
 *     (`aether-*lastconn*.toml`), sends `aethernoize` UDP opener packets from Kotlin, and launches
 *     `sing-box` with `"outer-warp"` (`"type": "wireguard"`) -> `"proton-exit"` (`"detour": "outer-warp"`),
 *     carrying UDP `:51820` natively inside `sing-box`'s userspace netstack without touching `127.0.0.1:2021`.
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

    @Volatile private var bridgeSocksServer: ServerSocket? = null
    @Volatile private var bridgeHttpServer: ServerSocket? = null
    @Volatile private var bridgeModeActive: Boolean = false
    private val bridgeExecutor = Executors.newCachedThreadPool()

    @Volatile
    var verifiedExitIp: String? = null
        private set

    @Volatile
    var lastErrorMessage: String? = null
        private set

    data class WarpIdentity(
        val endpoint: String,
        val port: Int,
        val ipv4: String,
        val privateKey: String,
        val publicKey: String,
        val reserved: List<Int>
    )

    data class TraceProbeResult(
        val ip: String,
        val country: String,
        val warpState: String
    )

    @Synchronized
    fun start(): Boolean {
        if (isRunning.get() && isHealthy()) return true
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

        return try {
            // Engine 1: Check if Aether on primarySocksHost:primarySocksPort (127.0.0.1:2021) is ALREADY
            // exiting through the chained inner Proton/Custom WireGuard hop (via --gool or --gool-classic).
            if (primarySocksPort > 0 && !isPortListening(primarySocksHost, primarySocksPort)) {
                LogRepository.i(
                    "[WG-Chain] Waiting up to 8s for Aether SOCKS5 ($primarySocksHost:$primarySocksPort) to finish inner WireGuard handshake...",
                    "WgExit"
                )
                val deadline = System.currentTimeMillis() + 8_000L
                while (System.currentTimeMillis() < deadline && !isPortListening(primarySocksHost, primarySocksPort)) {
                    Thread.sleep(250)
                }
            }
        if (primarySocksPort > 0 && isPortListening(primarySocksHost, primarySocksPort)) {
                val primaryTrace = probeCloudflareTraceFull(primarySocksPort)
                if (primaryTrace != null &&
                    primaryTrace.country != "IR" &&
                    primaryTrace.warpState.equals("off", ignoreCase = true)
                ) {
                    LogRepository.i(
                        "[WgExit] Aether native 2-layer WireGuard chain is active on $primarySocksHost:$primarySocksPort " +
                            "(Exit IP: ${primaryTrace.ip}, Country: ${primaryTrace.country}, warp=off). Starting local bridge on $localListenPort...",
                        "WgExit"
                    )
                    if (startNativePassthroughBridge(localListenPort)) {
                        verifiedExitIp = primaryTrace.ip
                        return true
                    }
                }
            }

            // Engine 2: Launch sing-box two-stage userspace WireGuard chain (outer-warp -> proton-exit)
            val binPath = binaryPath?.takeIf { File(it).exists() } ?: findSingBoxBinary()
            if (binPath == null) {
                // If sing-box binary is absent but Aether primary port is carrying non-Iran traffic, bridge it
                val fallbackIp = if (primarySocksPort > 0) verifyDataPlane(primarySocksPort) else null
                if (fallbackIp != null && startNativePassthroughBridge(localListenPort)) {
                    verifiedExitIp = fallbackIp
                    LogRepository.i("[WgExit] Bridged active primary tunnel on port $localListenPort (Exit IP: $fallbackIp)", "WgExit")
                    return true
                }
                lastErrorMessage = "sing-box binary not found"
                LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
                stopInternal()
                return false
            }

            val rawEndpoint = config.endpoint.trim()
            val endpointHostRaw = if (rawEndpoint.startsWith("[")) {
                rawEndpoint.substringAfter('[').substringBefore(']')
            } else {
                rawEndpoint.substringBeforeLast(':')
            }.trim()
            val endpointPort = rawEndpoint.substringAfterLast(':', "51820").trim().toIntOrNull() ?: 51820
            val endpointHost = resolveEndpointHostIfNeeded(endpointHostRaw)

            val v4 = config.addressV4.substringBefore('/').trim().ifBlank { "10.2.0.2" }
            val v6 = config.addressV6.substringBefore('/').trim()
            val safeInnerMtu = config.mtu.takeIf { it in 1000..1140 } ?: INNER_WG_SAFE_MTU

            val workDirStr = workingDir ?: runCatching {
                val home = System.getProperty("user.home") ?: "."
                val dir = File(home, ".aether")
                dir.mkdirs()
                dir.absolutePath
            }.getOrDefault(".")
            val workDir = File(workDirStr)
            workDir.mkdirs()

            if (isPortListening("127.0.0.1", localListenPort) || isPortListening("127.0.0.1", localListenPort - 1)) {
                LogRepository.w("[WgExit] Port $localListenPort is busy; cleaning up stale sing-box process...", "WgExit")
                killStaleSingBoxProcess(localListenPort)
                Thread.sleep(350)
            }

            // Load or auto-register outer Cloudflare WARP identity + scanned clean endpoint
            val warpIdentity = loadOrRegisterWarpIdentity(workDir, config.privateKey.trim(), primarySocksPort)
            if (warpIdentity != null) {
                sendAetherNoizeUdpOpener(warpIdentity.endpoint, warpIdentity.port)
            }

            val cfgJson = buildSingBoxConfig(
                listenPort = localListenPort,
                endpointHost = endpointHost,
                endpointPort = endpointPort,
                v4 = v4,
                v6 = v6,
                privateKey = config.privateKey.trim(),
                publicKey = config.publicKey.trim(),
                mtu = safeInnerMtu,
                warpIdentity = warpIdentity
            )

            val cFile = File(workDir, "singbox-wg-${localListenPort}.json")
            cFile.writeText(cfgJson)
            configFile = cFile

            val detourDesc = if (warpIdentity != null) {
                "Two-Stage Userspace WG (outer-warp ${warpIdentity.endpoint}:${warpIdentity.port} -> proton-exit)"
            } else {
                "Direct WG"
            }
            LogRepository.i(
                "[WgExit] Launching sing-box (Exit: $endpointHost:$endpointPort, MTU: $safeInnerMtu, Mode: $detourDesc, LocalPort: $localListenPort)...",
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

            Thread.sleep(900)

            LogRepository.i("[WgExit] Verifying end-to-end packet flow through Layer-2 WireGuard...", "WgExit")
            val verifiedIp = verifyDataPlaneWithRetry(localListenPort, maxAttempts = 5)
            if (verifiedIp != null) {
                verifiedExitIp = verifiedIp
                LogRepository.i("[WgExit] Layer-2 WireGuard exit node verified! Exit IP: $verifiedIp", "WgExit")
                true
            } else {
                // If sing-box outer-warp UDP was blocked (e.g. strict TCP-only network where only Aether H2 MASQUE works)
                // and Aether's primarySocksPort is alive, check if Aether itself has a valid non-Iran exit
                stopSingBoxOnly()
                val primaryIp = if (primarySocksPort > 0) verifyDataPlane(primarySocksPort) else null
                if (primaryIp != null && startNativePassthroughBridge(localListenPort)) {
                    verifiedExitIp = primaryIp
                    LogRepository.i("[WgExit] Fallback to Aether native tunnel bridge on port $localListenPort (Exit IP: $primaryIp)", "WgExit")
                    return true
                }
                lastErrorMessage = "Layer-2 WireGuard handshake failed over Layer-1 (check Proton WG key/endpoint or switch protocol to MASQUE/GOOL)"
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

    private fun stopSingBoxOnly() {
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
        runCatching { logThread?.interrupt() }
        logThread = null
        runCatching { configFile?.delete() }
    }

    private fun stopInternal() {
        isRunning.set(false)
        verifiedExitIp = null
        bridgeModeActive = false
        runCatching { bridgeSocksServer?.close() }
        bridgeSocksServer = null
        runCatching { bridgeHttpServer?.close() }
        bridgeHttpServer = null
        stopSingBoxOnly()
    }

    fun isConnected(): Boolean =
        isRunning.get() && (bridgeModeActive || process?.isAlive == true) && verifiedExitIp != null

    fun isHealthy(): Boolean =
        isRunning.get() && (bridgeModeActive || process?.isAlive == true) && isPortListening("127.0.0.1", localListenPort)

    // =========================================================================
    // ENGINE 1: IN-PROCESS PASSTHROUGH BRIDGE (WHEN AETHER NATIVELY CHAINS WG)
    // =========================================================================

    private fun startNativePassthroughBridge(listenPort: Int): Boolean {
        return try {
            val socksSrv = ServerSocket()
            socksSrv.reuseAddress = true
            socksSrv.bind(InetSocketAddress("127.0.0.1", listenPort), 256)
            bridgeSocksServer = socksSrv

            val httpPort = listenPort - 1
            val httpSrv = runCatching {
                ServerSocket().apply {
                    reuseAddress = true
                    bind(InetSocketAddress("127.0.0.1", httpPort), 128)
                }
            }.getOrNull()
            bridgeHttpServer = httpSrv
            bridgeModeActive = true

            // TCP forwarder for SOCKS5 (10805 -> primarySocksHost:primarySocksPort)
            thread(start = true, isDaemon = true, name = "WgExit-SocksBridge") {
                while (isRunning.get() && bridgeModeActive && !socksSrv.isClosed) {
                    val client = try {
                        socksSrv.accept()
                    } catch (_: Exception) {
                        break
                    }
                    bridgeExecutor.execute { forwardRawTcp(client, primarySocksHost, primarySocksPort) }
                }
            }

            // HTTP CONNECT proxy on 10804 -> SOCKS5 primarySocksHost:primarySocksPort
            if (httpSrv != null) {
                thread(start = true, isDaemon = true, name = "WgExit-HttpBridge") {
                    while (isRunning.get() && bridgeModeActive && !httpSrv.isClosed) {
                        val client = try {
                            httpSrv.accept()
                        } catch (_: Exception) {
                            break
                        }
                        bridgeExecutor.execute { handleHttpToSocksClient(client, primarySocksHost, primarySocksPort) }
                    }
                }
            }
            true
        } catch (e: Exception) {
            LogRepository.w("[WgExit] Failed to bind passthrough bridge on $listenPort: ${e.message}", "WgExit")
            false
        }
    }

    private fun forwardRawTcp(client: Socket, upstreamHost: String, upstreamPort: Int) {
        val upstream = Socket()
        try {
            client.tcpNoDelay = true
            upstream.tcpNoDelay = true
            upstream.connect(InetSocketAddress(upstreamHost, upstreamPort), 8_000)

            val cIn = client.getInputStream()
            val cOut = client.getOutputStream()
            val uIn = upstream.getInputStream()
            val uOut = upstream.getOutputStream()

            val down = thread(start = true, isDaemon = true) {
                try {
                    val buf = ByteArray(32768)
                    while (isRunning.get()) {
                        val n = uIn.read(buf)
                        if (n <= 0) break
                        cOut.write(buf, 0, n)
                        cOut.flush()
                    }
                } catch (_: Exception) {
                } finally {
                    runCatching { client.shutdownOutput() }
                }
            }

            val buf = ByteArray(32768)
            while (isRunning.get()) {
                val n = cIn.read(buf)
                if (n <= 0) break
                uOut.write(buf, 0, n)
                uOut.flush()
            }
            runCatching { upstream.shutdownOutput() }
            runCatching { down.join(2000) }
        } catch (_: Exception) {
        } finally {
            runCatching { upstream.close() }
            runCatching { client.close() }
        }
    }

    private fun handleHttpToSocksClient(client: Socket, socksHost: String, socksPort: Int) {
        var upstream: Socket? = null
        try {
            client.tcpNoDelay = true
            client.soTimeout = 15_000
            val cIn = BufferedInputStream(client.getInputStream())
            val cOut = BufferedOutputStream(client.getOutputStream())

            val reqLine = readAsciiLine(cIn) ?: return
            val headers = mutableListOf<String>()
            while (true) {
                val h = readAsciiLine(cIn) ?: break
                if (h.isEmpty()) break
                headers.add(h)
            }

            val parts = reqLine.split(" ")
            if (parts.size < 2) return
            val method = parts[0].uppercase()
            val target = parts[1]

            val targetHost: String
            val targetPort: Int
            var initialPayload: ByteArray? = null

            if (method == "CONNECT") {
                targetHost = target.substringBefore(":")
                targetPort = target.substringAfter(":", "443").toIntOrNull() ?: 443
            } else {
                val url = runCatching { URL(target) }.getOrNull() ?: return
                targetHost = url.host
                targetPort = if (url.port != -1) url.port else 80
                val path = url.file.ifEmpty { "/" }
                val rebuilt = buildString {
                    append("$method $path HTTP/1.1\r\n")
                    for (h in headers) {
                        if (!h.startsWith("Proxy-", ignoreCase = true)) {
                            append(h).append("\r\n")
                        }
                    }
                    append("\r\n")
                }
                initialPayload = rebuilt.toByteArray(Charsets.ISO_8859_1)
            }

            val s = Socket()
            upstream = s
            s.tcpNoDelay = true
            s.connect(InetSocketAddress(socksHost, socksPort), 10_000)
            val uIn = DataInputStream(BufferedInputStream(s.getInputStream()))
            val uOut = BufferedOutputStream(s.getOutputStream())

            uOut.write(byteArrayOf(0x05, 0x01, 0x00))
            uOut.flush()
            if (uIn.read() != 0x05 || uIn.read() != 0x00) return

            val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
            val req = ByteArray(7 + hostBytes.size)
            req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03
            req[4] = hostBytes.size.toByte()
            System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
            req[5 + hostBytes.size] = ((targetPort ushr 8) and 0xFF).toByte()
            req[6 + hostBytes.size] = (targetPort and 0xFF).toByte()
            uOut.write(req)
            uOut.flush()

            val rVer = uIn.read()
            val rRep = uIn.read()
            uIn.read()
            val rAtyp = uIn.read()
            if (rVer != 0x05 || rRep != 0x00) return
            val skip = when (rAtyp) {
                0x01 -> 6
                0x04 -> 18
                0x03 -> uIn.readUnsignedByte() + 2
                else -> 6
            }
            uIn.skipBytes(skip)

            if (method == "CONNECT") {
                cOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                cOut.flush()
            } else if (initialPayload != null) {
                uOut.write(initialPayload)
                uOut.flush()
            }

            client.soTimeout = 0
            val down = thread(start = true, isDaemon = true) {
                try {
                    val buf = ByteArray(32768)
                    while (isRunning.get()) {
                        val n = uIn.read(buf)
                        if (n <= 0) break
                        cOut.write(buf, 0, n)
                        cOut.flush()
                    }
                } catch (_: Exception) {
                } finally {
                    runCatching { client.shutdownOutput() }
                }
            }

            val buf = ByteArray(32768)
            while (isRunning.get()) {
                val n = cIn.read(buf)
                if (n <= 0) break
                uOut.write(buf, 0, n)
                uOut.flush()
            }
            runCatching { s.shutdownOutput() }
            runCatching { down.join(2000) }
        } catch (_: Exception) {
        } finally {
            runCatching { upstream?.close() }
            runCatching { client.close() }
        }
    }

    private fun readAsciiLine(ins: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = ins.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) break
            if (b != '\r'.code) sb.append(b.toChar())
        }
        return sb.toString()
    }

    // =========================================================================
    // ENGINE 2: SING-BOX TWO-STAGE USERSPACE WIREGUARD (outer-warp -> proton-exit)
    // =========================================================================

    private fun loadOrRegisterWarpIdentity(
        workDir: File,
        customPrivateKey: String,
        aetherSocksPort: Int
    ): WarpIdentity? {
        val searchDirs = listOf(
            workDir,
            File(System.getProperty("user.home", "."), ".aether"),
            File(System.getenv("AppData") ?: ".", "AetherST-Tunnel/bin"),
            File(System.getProperty("user.dir", ".")),
            File(".")
        )
        val fileNames = listOf("aether.toml", "aether-wg.toml", "aether-masque.toml")

        val bestEndpoint = resolveBestCloudflareEndpoint(searchDirs)

        for (dir in searchDirs) {
            for (fn in fileNames) {
                val f = File(dir, fn)
                if (f.exists() && f.length() > 0) {
                    val parsed = parseWarpIdentityFromToml(f, customPrivateKey, bestEndpoint)
                    if (parsed != null) return parsed
                }
            }
        }

        return registerFreshCloudflareWarp(workDir, aetherSocksPort, bestEndpoint)
    }

    private fun resolveBestCloudflareEndpoint(searchDirs: List<File>): Pair<String, Int> {
        val epRegex = Regex("""(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})""")
        for (dir in searchDirs) {
            val files = dir.listFiles { f -> f.name.contains("lastconn", ignoreCase = true) }
                ?.sortedByDescending { it.lastModified() }
                .orEmpty()
            for (f in files) {
                val text = runCatching { f.readText() }.getOrNull() ?: continue
                val m = epRegex.find(text)
                if (m != null) {
                    val ip = m.groupValues[1]
                    val port = m.groupValues[2].toIntOrNull() ?: 2408
                    if (ip != "0.0.0.0" && !ip.startsWith("127.")) {
                        return ip to port
                    }
                }
            }
        }
        return "162.159.192.1" to 2408
    }

    private fun parseWarpIdentityFromToml(
        file: File,
        customPrivateKey: String,
        bestEndpoint: Pair<String, Int>
    ): WarpIdentity? {
        return try {
            val text = file.readText()
            var endpoint = bestEndpoint.first
            var port = bestEndpoint.second
            var ipv4 = "172.16.0.2"
            var privKey = ""
            var pubKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
            val reservedList = mutableListOf(0, 0, 0)

            for (line in text.lines()) {
                val clean = line.substringBefore('#').trim()
                if (!clean.contains('=')) continue
                val k = clean.substringBefore('=').trim().lowercase()
                val v = clean.substringAfter('=').trim().trim('"', '\'')
                when (k) {
                    "assigned_endpoint" -> {
                        if (v.isNotBlank() && !v.startsWith("0.0.0.0") && endpoint == "162.159.192.1") {
                            endpoint = v.substringBefore(':')
                            port = v.substringAfter(':', "2408").toIntOrNull() ?: 2408
                        }
                    }
                    "ipv4" -> if (v.isNotBlank()) ipv4 = v.substringBefore('/')
                    "wg_private_key" -> if (v.isNotBlank()) privKey = v
                    "wg_peer_public_key" -> if (v.isNotBlank()) pubKey = v
                    "client_id" -> {
                        if (v.isNotBlank()) {
                            runCatching {
                                val bytes = Base64.getDecoder().decode(v)
                                if (bytes.size >= 3) {
                                    reservedList[0] = bytes[0].toInt() and 0xFF
                                    reservedList[1] = bytes[1].toInt() and 0xFF
                                    reservedList[2] = bytes[2].toInt() and 0xFF
                                }
                            }
                        }
                    }
                }
            }

            if (privKey.isNotBlank() && privKey != customPrivateKey) {
                WarpIdentity(
                    endpoint = endpoint,
                    port = port,
                    ipv4 = ipv4,
                    privateKey = privKey,
                    publicKey = pubKey,
                    reserved = reservedList
                )
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun registerFreshCloudflareWarp(
        workDir: File,
        aetherSocksPort: Int,
        bestEndpoint: Pair<String, Int>
    ): WarpIdentity? {
        return try {
            val keyPair = WireGuardCrypto.generateKeyPair()
            val regBody = """{"key":"${keyPair.publicKey}","install_id":"","fcm_token":"","tos":"2026-01-01T00:00:00.000Z","model":"PC","serial_number":"${UUID.randomUUID()}","locale":"en_US"}"""
            val urls = listOf(
                "https://api.devices.cloudflare.com/v0a4471/reg",
                "https://api.cloudflareclient.com/v0a2158/reg"
            )
            for (useProxy in listOf(true, false)) {
                val proxy = if (useProxy && aetherSocksPort > 0 && isPortListening("127.0.0.1", aetherSocksPort)) {
                    Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", aetherSocksPort))
                } else Proxy.NO_PROXY

                for (urlStr in urls) {
                    try {
                        val conn = (URL(urlStr).openConnection(proxy) as HttpURLConnection).apply {
                            requestMethod = "POST"
                            connectTimeout = 8_000
                            readTimeout = 8_000
                            doOutput = true
                            setRequestProperty("Content-Type", "application/json")
                            setRequestProperty("Accept", "application/json")
                            setRequestProperty("CF-Client-Version", "a-6.30-2158")
                        }
                        conn.outputStream.use { it.write(regBody.toByteArray(Charsets.UTF_8)) }
                        if (conn.responseCode in 200..299) {
                            val resp = conn.inputStream.bufferedReader().use { it.readText() }
                            val devId = Regex(""""id"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1) ?: continue
                            val token = Regex(""""token"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1) ?: devId
                            val clientId = Regex(""""client_id"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1) ?: "AAAA"
                            val v4 = Regex(""""v4"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1)?.substringBefore("/") ?: "172.16.0.2"
                            val peerPub = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

                            val toml = buildString {
                                appendLine("""device_id = "$devId"""")
                                appendLine("""access_token = "$token"""")
                                appendLine("""ipv4 = "$v4"""")
                                appendLine("""wg_private_key = "${keyPair.privateKey}"""")
                                appendLine("""wg_peer_public_key = "$peerPub"""")
                                appendLine("""assigned_endpoint = "${bestEndpoint.first}:${bestEndpoint.second}"""")
                                appendLine("""client_id = "$clientId"""")
                            }
                            runCatching { File(workDir, "aether.toml").writeText(toml) }
                            runCatching { File(workDir, "aether-wg.toml").writeText(toml) }

                            val reserved = runCatching {
                                val b = Base64.getDecoder().decode(clientId)
                                if (b.size >= 3) listOf(b[0].toInt() and 0xFF, b[1].toInt() and 0xFF, b[2].toInt() and 0xFF)
                                else listOf(0, 0, 0)
                            }.getOrDefault(listOf(0, 0, 0))

                            return WarpIdentity(
                                endpoint = bestEndpoint.first,
                                port = bestEndpoint.second,
                                ipv4 = v4,
                                privateKey = keyPair.privateKey,
                                publicKey = peerPub,
                                reserved = reserved
                            )
                        }
                    } catch (_: Exception) {}
                }
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    private fun sendAetherNoizeUdpOpener(host: String, port: Int) {
        runCatching {
            val addr = InetAddress.getByName(host)
            val rng = SecureRandom()
            DatagramSocket().use { ds ->
                ds.soTimeout = 500
                for (size in intArrayOf(38, 64, 92, 128)) {
                    val buf = ByteArray(size)
                    rng.nextBytes(buf)
                    buf[0] = (0x80 or (buf[0].toInt() and 0x7F)).toByte()
                    ds.send(DatagramPacket(buf, buf.size, addr, port))
                    Thread.sleep(15)
                }
            }
        }
    }

    /**
     * Builds a clean, schema-valid `sing-box` 1.8..1.12+ JSON configuration with two-stage userspace
     * WireGuard chaining (`outer-warp` -> `proton-exit`) and ZERO deprecated keys (`"sniff"`, `"gso"`, `"type": "dns"`).
     */
    private fun buildSingBoxConfig(
        listenPort: Int,
        endpointHost: String,
        endpointPort: Int,
        v4: String,
        v6: String,
        privateKey: String,
        publicKey: String,
        mtu: Int,
        warpIdentity: WarpIdentity?
    ): String {
        val cleanV4 = if (v4.contains('/')) v4 else "$v4/32"
        val localAddresses = mutableListOf("\"$cleanV4\"")
        if (v6.isNotBlank()) {
            val safeV6 = if (v6.contains('/')) v6 else "$v6/128"
            localAddresses.add("\"$safeV6\"")
        }

        val primaryWgDns = config.dnsServers.firstOrNull {
            it.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))
        } ?: "10.2.0.1"

        val outerWarpBlock = if (warpIdentity != null) {
            """
            {
              "type": "wireguard",
              "tag": "outer-warp",
              "server": "${warpIdentity.endpoint}",
              "server_port": ${warpIdentity.port},
              "local_address": ["${warpIdentity.ipv4}/32"],
              "private_key": "${warpIdentity.privateKey}",
              "peer_public_key": "${warpIdentity.publicKey}",
              "reserved": [${warpIdentity.reserved.joinToString(", ")}],
              "mtu": 1280
            },
            """.trimIndent()
        } else ""

        val detourLine = if (warpIdentity != null) {
            ",\n              \"detour\": \"outer-warp\""
        } else ""

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
                "address": "udp://$primaryWgDns",
                "detour": "proton-exit"
              },
              {
                "tag": "dns-cf",
                "address": "tcp://1.1.1.1",
                "detour": "proton-exit"
              }
            ],
            "final": "dns-proton"
          },
          "inbounds": [
            {
              "type": "socks",
              "tag": "socks-in",
              "listen": "127.0.0.1",
              "listen_port": $listenPort
            },
            {
              "type": "http",
              "tag": "http-in",
              "listen": "127.0.0.1",
              "listen_port": ${listenPort - 1}
            }
          ],
          "outbounds": [
            $outerWarpBlock
            {
              "type": "wireguard",
              "tag": "proton-exit",
              "server": "$endpointHost",
              "server_port": $endpointPort,
              "local_address": [${localAddresses.joinToString(", ")}],
              "private_key": "$privateKey",
              "peer_public_key": "$publicKey",
              "mtu": $mtu$detourLine
            },
            {
              "type": "direct",
              "tag": "direct"
            }
          ],
          "route": {
            "final": "proton-exit"
          }
        }
        """.trimIndent()
    }

    private fun resolveEndpointHostIfNeeded(host: String): String {
        val isIpv4 = host.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))
        val isIpv6 = host.contains(':')
        if (isIpv4 || isIpv6) return host
        return runCatching {
            InetAddress.getAllByName(host)
                .firstOrNull { it is Inet4Address }
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

    private fun verifyDataPlaneWithRetry(socksPort: Int, maxAttempts: Int = 5): String? {
        for (attempt in 1..maxAttempts) {
            if (!bridgeModeActive && process?.isAlive != true) return null
            val ip = verifyDataPlane(socksPort)
            if (ip != null) return ip
            if (attempt < maxAttempts) Thread.sleep(1000)
        }
        return null
    }

    private fun verifyDataPlane(socksPort: Int): String? {
        probeCloudflareTraceByIp(socksPort, byteArrayOf(1, 1, 1, 1), "1.1.1.1")?.let { return it }
        probeCloudflareTraceByIp(socksPort, byteArrayOf(1, 0, 0, 1), "1.0.0.1")?.let { return it }
        probeSimpleHttpIp(socksPort, "checkip.amazonaws.com", "/")?.let { return it }
        probeSimpleHttpIp(socksPort, "api.ipify.org", "/")?.let { return it }
        probeIpApi(socksPort)?.let { return it }
        return null
    }

    private fun probeCloudflareTraceFull(socksPort: Int): TraceProbeResult? {
        for ((ipBytes, hostHdr) in listOf(
            byteArrayOf(1, 1, 1, 1) to "1.1.1.1",
            byteArrayOf(1, 0, 0, 1) to "1.0.0.1"
        )) {
            try {
                Socket().use { socket ->
                    socket.soTimeout = 4500
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
                            ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3],
                            0x00, 0x50
                        )
                        out.write(req)
                        out.flush()
                        val connResp = ByteArray(4)
                        readFully(input, connResp)
                        if (connResp[1] == 0x00.toByte()) {
                            consumeSocksBoundAddress(input, connResp[3])
                            val httpReq = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: $hostHdr\r\nUser-Agent: AetherST/2.5\r\nConnection: close\r\n\r\n"
                            out.write(httpReq.toByteArray(Charsets.US_ASCII))
                            out.flush()
                            val text = input.bufferedReader(Charsets.US_ASCII).readText()
                            val ip = Regex("""(?m)^ip=(.+)$""").find(text)?.groupValues?.get(1)?.trim()
                            val loc = Regex("""(?m)^loc=(.+)$""").find(text)?.groupValues?.get(1)?.trim()?.uppercase()
                            val warp = Regex("""(?m)^warp=(.+)$""").find(text)?.groupValues?.get(1)?.trim()?.lowercase() ?: "off"
                            if (!ip.isNullOrBlank() && !loc.isNullOrBlank()) {
                                return TraceProbeResult(ip = ip, country = loc, warpState = warp)
                            }
                        }
                    }
                }
            } catch (_: Exception) {}
        }
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

    private fun consumeSocksBoundAddress(input: InputStream, atyp: Byte) {
        when (atyp) {
            0x01.toByte() -> readFully(input, ByteArray(4 + 2))
            0x03.toByte() -> {
                val len = input.read()
                if (len > 0) readFully(input, ByteArray(len + 2))
            }
            0x04.toByte() -> readFully(input, ByteArray(16 + 2))
        }
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
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
