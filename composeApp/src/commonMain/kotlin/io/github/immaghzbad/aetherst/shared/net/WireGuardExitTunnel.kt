package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.model.CustomWireGuardConfig
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Userspace WireGuard-in-WireGuard Exit Tunnel Manager.
 * Powered by a userspace networking engine (sing-box / wireguard-go).
 * Runs the secondary WireGuard tunnel (e.g. Proton VPN) chained inside
 * an unblocked outer Layer-3 transport (WARP / direct detour), completely
 * bypassing TCP SOCKS5 UDP limitations.
 *
 * Exposes a clean local SOCKS5 listener on [localListenPort] (default 10805)
 * for seamless integration with AetherVpnService (Android) and TunHelper (Desktop)
 * without creating any conflicting secondary TUN adapters.
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
                "[WgExit] Userspace engine binary (sing-box) not found. Please place sing-box.exe in bin folder.",
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

            // 1. Generate userspace WireGuard configuration
            val cfgJson = buildSingBoxConfig(
                listenPort = localListenPort,
                endpointHost = endpointHost,
                endpointPort = endpointPort,
                v4 = v4,
                v6 = v6,
                privateKey = config.privateKey.trim(),
                publicKey = config.publicKey.trim(),
                dns = config.dns.ifBlank { "10.2.0.1" },
                mtu = if (config.mtu in 1200..1420) config.mtu else 1280
            )

            val cFile = File(workDir, "singbox-wg-${localListenPort}.json")
            cFile.writeText(cfgJson)
            configFile = cFile

            LogRepository.i(
                "[WgExit] Launching userspace WireGuard engine (Endpoint: $endpointHost:$endpointPort, MTU: ${config.mtu}, Port: $localListenPort)...",
                "WgExit"
            )

            val cmd = listOf(binPath, "run", "-c", cFile.absolutePath)
            val pb = ProcessBuilder(cmd)
            pb.directory(workDir)
            pb.redirectErrorStream(true)
            val proc = pb.start()
            process = proc

            // 2. Stream and capture engine logs
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

            // 3. Wait for the local SOCKS listener to become active
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

            // 4. Data Plane Verification: Verify real packet flow before claiming Connected
            LogRepository.i("[WgExit] Verifying data plane connectivity through secondary tunnel...", "WgExit")
            val verifiedIp = verifyDataPlane(localListenPort)
            if (verifiedIp != null) {
                verifiedExitIp = verifiedIp
                LogRepository.i("[WgExit] WireGuard exit node successfully connected and verified! Exit IP: $verifiedIp", "WgExit")
                true
            } else {
                LogRepository.e("[WgExit] Data plane verification timed out. WireGuard traffic did not reach exit node. Aborting fake connection.", "WgExit")
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
                    p.waitFor(1500, java.util.concurrent.TimeUnit.MILLISECONDS)
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
        dns: String,
        mtu: Int
    ): String {
        val localAddresses = mutableListOf("\"$v4/32\"")
        if (v6.isNotBlank()) {
            val safeV6 = if (v6.contains('/')) v6 else "$v6/128"
            localAddresses.add("\"$safeV6\"")
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
              "detour": "outer-warp"
            },
            {
              "type": "warp",
              "tag": "outer-warp",
              "detour": "direct"
            },
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
     * genuinely reach the exit node and read the external IP.
     */
    private fun verifyDataPlane(socksPort: Int): String? {
        val targetHost = "api.ipify.org"
        val targetPort = 80
        val timeoutMs = 7000

        for (attempt in 1..2) {
            var socket: Socket? = null
            try {
                socket = Socket()
                socket.soTimeout = timeoutMs
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2500)

                val out = socket.getOutputStream()
                val input = socket.getInputStream()

                // 1. SOCKS5 Auth Handshake: No Auth
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()

                val authResp = ByteArray(2)
                readFully(input, authResp)
                if (authResp[0] != 0x05.toByte() || authResp[1] != 0x00.toByte()) {
                    socket.close()
                    continue
                }

                // 2. SOCKS5 Connect to targetHost:80 (Domain atyp=0x03)
                val hostBytes = targetHost.toByteArray(Charsets.US_ASCII)
                val req = ByteArray(4 + 1 + hostBytes.size + 2)
                req[0] = 0x05 // VER
                req[1] = 0x01 // CMD CONNECT
                req[2] = 0x00 // RSV
                req[3] = 0x03 // ATYP DOMAIN
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

                // Skip bound address
                when (connResp[3]) {
                    0x01.toByte() -> readFully(input, ByteArray(4 + 2))
                    0x03.toByte() -> {
                        val len = input.read()
                        if (len > 0) readFully(input, ByteArray(len + 2))
                    }
                    0x04.toByte() -> readFully(input, ByteArray(16 + 2))
                }

                // 3. Send HTTP GET request
                val httpReq = "GET / HTTP/1.1\r\nHost: $targetHost\r\nUser-Agent: AetherST/2.1\r\nConnection: close\r\n\r\n"
                out.write(httpReq.toByteArray(Charsets.US_ASCII))
                out.flush()

                val reader = BufferedReader(InputStreamReader(input, Charsets.US_ASCII))
                var ipLine: String? = null
                var inBody = false
                while (true) {
                    val line = reader.readLine() ?: break
                    if (inBody) {
                        if (line.trim().isNotBlank()) {
                            ipLine = line.trim()
                            break
                        }
                    } else if (line.isEmpty()) {
                        inBody = true
                    }
                }

                if (!ipLine.isNullOrBlank() && ipLine.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) {
                    return ipLine
                }
            } catch (_: Exception) {
            } finally {
                try { socket?.close() } catch (_: Exception) {}
            }
            Thread.sleep(500)
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
         * Selects the fastest healthy profile from a list by probing ping/handshake.
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
