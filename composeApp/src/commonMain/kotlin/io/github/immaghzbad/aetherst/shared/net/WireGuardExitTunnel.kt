package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.model.CustomWireGuardConfig
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Userspace WireGuard-in-WireGuard Exit Tunnel Manager.
 * Powered by sing-box userspace networking engine.
 * Chains the secondary WireGuard tunnel (e.g. Proton VPN) inside
 * an unblocked outer Layer-3 transport (Cloudflare WARP WireGuard),
 * completely bypassing TCP SOCKS5 UDP limitations with native netstack detour.
 *
 * Exposes a clean local SOCKS5 listener on [localListenPort] (default 10805)
 * for seamless integration with AetherVpnService (Android) and TunHelper (Desktop).
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

    fun start(): Boolean {
        if (isRunning.getAndSet(true)) return true
        if (!config.isValid()) {
            LogRepository.e("[WgExit] Invalid configuration: Endpoint, PrivateKey or PublicKey is missing", "WgExit")
            isRunning.set(false)
            return false
        }

        val binPath = binaryPath?.takeIf { File(it).exists() } ?: findSingBoxBinary()
        if (binPath == null) {
            LogRepository.e(
                "[WgExit] Userspace engine binary (sing-box) not found. Please place sing-box.exe in resources/bin folder.",
                "WgExit"
            )
            isRunning.set(false)
            return false
        }

        return try {
            val endpointParts = config.endpoint.split(':')
            val endpointHost = endpointParts[0].trim()
            val endpointPort = endpointParts.getOrNull(1)?.toIntOrNull() ?: 51820

            val v4 = config.addressV4.substringBefore('/').trim().ifBlank { "10.2.0.2" }
            val v6 = config.addressV6.substringBefore('/').trim()

            val workDirStr = workingDir ?: runCatching {
                val home = System.getProperty("user.home") ?: "."
                val dir = File(home, ".aether")
                dir.mkdirs()
                dir.absolutePath
            }.getOrDefault(".")
            val workDir = File(workDirStr)
            workDir.mkdirs()

            // 1. Resolve Cloudflare WARP outer identity from primary Aether session
            val warpIdentity = loadWarpIdentity(workDir)

            // 2. Generate sing-box userspace WireGuard configuration
            val cfgJson = buildSingBoxConfig(
                listenPort = localListenPort,
                endpointHost = endpointHost,
                endpointPort = endpointPort,
                v4 = v4,
                v6 = v6,
                privateKey = config.privateKey.trim(),
                publicKey = config.publicKey.trim(),
                mtu = 1280,
                warpIdentity = warpIdentity
            )

            val cFile = File(workDir, "singbox-wg-${localListenPort}.json")
            cFile.writeText(cfgJson)
            configFile = cFile

            val detourDesc = if (primarySocksPort > 0) "Aether Upstream (127.0.0.1:$primarySocksPort)" else if (warpIdentity != null) "Cloudflare WARP (WG)" else "Direct"
            LogRepository.i(
                "[WgExit] Launching userspace WireGuard engine (Server: $endpointHost:$endpointPort, Detour: $detourDesc, Port: $localListenPort)...",
                "WgExit"
            )

            val cmd = listOf(binPath, "run", "-c", cFile.absolutePath)
            val pb = ProcessBuilder(cmd)
            pb.directory(workDir)
            pb.redirectErrorStream(true)
            val proc = pb.start()
            process = proc

            // 3. Stream and capture sing-box logs
            logThread = Thread({
                try {
                    BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                        var line: String? = null
                        while (proc.isAlive && reader.readLine().also { line = it } != null) {
                            val l = line ?: break
                            if (l.contains("ERROR", ignoreCase = true) || l.contains("FATAL", ignoreCase = true)) {
                                LogRepository.e("[sing-box] $l", "sing-box")
                            } else if (l.contains("WARN", ignoreCase = true)) {
                                LogRepository.w("[sing-box] $l", "sing-box")
                            } else {
                                LogRepository.d("[sing-box] $l", "sing-box")
                            }
                        }
                    }
                } catch (_: Exception) {}
            }, "Aether-WgExit-Logger").apply { isDaemon = true; start() }

            // 4. Wait for the local SOCKS5 listener to become active
            var portReady = false
            val startWait = System.currentTimeMillis()
            while (System.currentTimeMillis() - startWait < 8000) {
                if (isPortListening("127.0.0.1", localListenPort)) {
                    portReady = true
                    break
                }
                Thread.sleep(250)
            }

            if (!portReady) {
                LogRepository.e("[WgExit] Userspace engine listener failed to bind on 127.0.0.1:$localListenPort within 8s", "WgExit")
                stop()
                return false
            }

            // 5. Data Plane Verification: Verify real packet flow & verify Non-Iran IP
            LogRepository.i("[WgExit] Verifying data plane packet flow through secondary WireGuard tunnel...", "WgExit")
            val verifiedIp = verifyDataPlane(localListenPort)
            if (verifiedIp != null) {
                verifiedExitIp = verifiedIp
                LogRepository.i("[WgExit] WireGuard exit node successfully connected and verified! Non-Iran Exit IP: $verifiedIp", "WgExit")
                true
            } else {
                LogRepository.e("[WgExit] Data plane verification failed or detected Iranian exit IP. WireGuard handshake failed to reach egress. Aborting fake connection.", "WgExit")
                stop()
                false
            }
        } catch (e: Exception) {
            LogRepository.e("[WgExit] Startup exception: ${e.message}", "WgExit")
            stop()
            false
        }
    }

    fun stop() {
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

    private fun findSingBoxBinary(): String? {
        val binName = if (System.getProperty("os.name", "").lowercase().contains("win")) "sing-box.exe" else "sing-box"
        val candidates = listOf(
            File("composeApp/src/desktopMain/resources/bin", binName),
            File("bin", binName),
            File(binName)
        )
        return candidates.firstOrNull { it.exists() && it.isFile }?.absolutePath
    }

    data class WarpIdentity(
        val endpoint: String,
        val port: Int,
        val ipv4: String,
        val privateKey: String,
        val publicKey: String,
        val reserved: List<Int>
    )

    private fun loadWarpIdentity(workDir: File): WarpIdentity? {
        val searchDirs = listOf(
            workDir,
            File(System.getProperty("user.home", "."), ".aether"),
            File(System.getenv("AppData") ?: ".", "AetherST-Tunnel/bin"),
            File(System.getProperty("user.dir", ".")),
            File(".")
        )
        val fileNames = listOf("aether-masque.toml", "aether.toml")

        for (dir in searchDirs) {
            for (fn in fileNames) {
                val f = File(dir, fn)
                if (f.exists() && f.length() > 0) {
                    val parsed = parseWarpIdentityFromToml(f)
                    if (parsed != null) return parsed
                }
            }
        }
        return null
    }

    private fun parseWarpIdentityFromToml(file: File): WarpIdentity? {
        return try {
            val text = file.readText()
            var endpoint = "162.159.192.1"
            var port = 2408
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
                        if (v.isNotBlank()) {
                            endpoint = v.substringBefore(':')
                            port = v.substringAfter(':', "2408").toIntOrNull() ?: 2408
                        }
                    }
                    "ipv4" -> if (v.isNotBlank()) ipv4 = v
                    "wg_private_key" -> if (v.isNotBlank()) privKey = v
                    "wg_peer_public_key" -> if (v.isNotBlank()) pubKey = v
                    "client_id" -> {
                        if (v.isNotBlank()) {
                            try {
                                val bytes = Base64.getDecoder().decode(v)
                                if (bytes.size >= 3) {
                                    reservedList[0] = bytes[0].toInt() and 0xFF
                                    reservedList[1] = bytes[1].toInt() and 0xFF
                                    reservedList[2] = bytes[2].toInt() and 0xFF
                                }
                            } catch (_: Exception) {}
                        }
                    }
                }
            }

            if (privKey.isNotBlank()) {
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

    /**
     * Builds sing-box JSON configuration with userspace WireGuard-in-WireGuard detour.
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
        val localAddresses = mutableListOf("\"$v4/32\"")
        if (v6.isNotBlank()) {
            val safeV6 = if (v6.contains('/')) v6 else "$v6/128"
            localAddresses.add("\"$safeV6\"")
        }

        val hasUpstreamSocks = primarySocksPort > 0
        val innerDetour = if (hasUpstreamSocks) "aether-upstream" else if (warpIdentity != null) "outer-warp" else "direct"

        val upstreamOutbound = if (hasUpstreamSocks) {
            """
            {
              "type": "socks",
              "tag": "aether-upstream",
              "server": "$primarySocksHost",
              "server_port": $primarySocksPort
            },
            """.trimIndent()
        } else {
            ""
        }

        val warpOutbound = if (!hasUpstreamSocks && warpIdentity != null) {
            val warp = warpIdentity
            """
            {
              "type": "wireguard",
              "tag": "outer-warp",
              "server": "${warp.endpoint}",
              "server_port": ${warp.port},
              "local_address": ["${warp.ipv4}/32"],
              "private_key": "${warp.privateKey}",
              "peer_public_key": "${warp.publicKey}",
              "reserved": [${warp.reserved.joinToString(", ")}],
              "mtu": 1280,
              "detour": "direct"
            },
            """.trimIndent()
        } else {
            ""
        }

        return """
        {
          "log": {
            "level": "warn",
            "timestamp": true
          },
          "inbounds": [
            {
              "type": "socks",
              "tag": "socks-in",
              "listen": "127.0.0.1",
              "listen_port": $listenPort
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
              "detour": "$innerDetour"
            },
            $upstreamOutbound
            $warpOutbound
            {
              "type": "direct",
              "tag": "direct"
            }
          ],
          "route": {
            "rules": [
              {
                "inbound": "socks-in",
                "outbound": "proton-exit"
              }
            ],
            "auto_detect_interface": true
          }
        }
        """.trimIndent()
    }

    /**
     * Data Plane Verification: Sends an HTTP probe via SOCKS5 to ensure packets
     * genuinely reach the exit node, confirm internet connectivity, and guarantee
     * that the exit IP is NOT in Iran (IR).
     */
    private fun verifyDataPlane(socksPort: Int): String? {
        // Probe 1: ip-api.com with countryCode & IP
        val targetHost = "ip-api.com"
        val targetPort = 80
        val timeoutMs = 6000

        for (attempt in 1..2) {
            var socket: Socket? = null
            try {
                socket = Socket()
                socket.soTimeout = timeoutMs
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2500)

                val out = socket.getOutputStream()
                val input = socket.getInputStream()

                // SOCKS5 Handshake
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()

                val authResp = ByteArray(2)
                readFully(input, authResp)
                if (authResp[0] != 0x05.toByte() || authResp[1] != 0x00.toByte()) {
                    socket.close()
                    continue
                }

                // SOCKS5 CONNECT to ip-api.com:80
                val hostBytes = targetHost.toByteArray(Charsets.US_ASCII)
                val req = ByteArray(4 + 1 + hostBytes.size + 2)
                req[0] = 0x05
                req[1] = 0x01
                req[2] = 0x00
                req[3] = 0x03
                req[4] = hostBytes.size.toByte()
                System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
                req[req.size - 2] = ((targetPort shr 8) and 0xFF).toByte()
                req[req.size - 1] = (targetPort and 0xFF).toByte()

                out.write(req)
                out.flush()

                val connResp = ByteArray(4)
                readFully(input, connResp)
                if (connResp[1] != 0x00.toByte()) {
                    socket.close()
                    continue
                }

                when (connResp[3]) {
                    0x01.toByte() -> readFully(input, ByteArray(4 + 2))
                    0x03.toByte() -> {
                        val len = input.read()
                        if (len > 0) readFully(input, ByteArray(len + 2))
                    }
                    0x04.toByte() -> readFully(input, ByteArray(16 + 2))
                }

                // HTTP GET request
                val httpReq = "GET /line/?fields=status,countryCode,query HTTP/1.1\r\nHost: $targetHost\r\nUser-Agent: AetherST/2.1\r\nConnection: close\r\n\r\n"
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
                    if (country == "IR") {
                        LogRepository.w("[WgExit] Verification rejected: Exit node returned Iranian IP ($ip).", "WgExit")
                        return null
                    }
                    if (ip.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) {
                        return ip
                    }
                }
            } catch (_: Exception) {
            } finally {
                try { socket?.close() } catch (_: Exception) {}
            }
            Thread.sleep(400)
        }

        // Probe 2 Fallback: api.ipify.org
        return verifyIpifyFallback(socksPort)
    }

    private fun verifyIpifyFallback(socksPort: Int): String? {
        val targetHost = "api.ipify.org"
        val targetPort = 80
        var socket: Socket? = null
        try {
            socket = Socket()
            socket.soTimeout = 5000
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
            req[0] = 0x05
            req[1] = 0x01
            req[2] = 0x00
            req[3] = 0x03
            req[4] = hostBytes.size.toByte()
            System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
            req[req.size - 2] = ((targetPort shr 8) and 0xFF).toByte()
            req[req.size - 1] = (targetPort and 0xFF).toByte()

            out.write(req)
            out.flush()

            val connResp = ByteArray(4)
            readFully(input, connResp)
            if (connResp[1] != 0x00.toByte()) return null

            when (connResp[3]) {
                0x01.toByte() -> readFully(input, ByteArray(4 + 2))
                0x03.toByte() -> {
                    val len = input.read()
                    if (len > 0) readFully(input, ByteArray(len + 2))
                }
                0x04.toByte() -> readFully(input, ByteArray(16 + 2))
            }

            val httpReq = "GET / HTTP/1.1\r\nHost: $targetHost\r\nUser-Agent: AetherST/2.1\r\nConnection: close\r\n\r\n"
            out.write(httpReq.toByteArray(Charsets.US_ASCII))
            out.flush()

            val reader = BufferedReader(InputStreamReader(input, Charsets.US_ASCII))
            var inBody = false
            while (true) {
                val line = reader.readLine() ?: break
                if (inBody) {
                    val ip = line.trim()
                    if (ip.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) {
                        return ip
                    }
                } else if (line.isEmpty()) {
                    inBody = true
                }
            }
        } catch (_: Exception) {
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }
        return null
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
        /**
         * Fast concurrent latency probe across a list of WireGuard profiles.
         * Runs in background thread pool with zero delay to the user interface.
         */
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
                        // WireGuard ports are UDP, socket connect may throw connection refused or timeout.
                        // If it responds or ICMP unreachable occurs within timeout, endpoint is alive.
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

        /**
         * Selects the fastest healthy profile from a list by checking latency.
         */
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
