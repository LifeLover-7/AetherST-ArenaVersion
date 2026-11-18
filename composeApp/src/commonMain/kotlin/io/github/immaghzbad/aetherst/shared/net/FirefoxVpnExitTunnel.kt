package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.data.LogRepository
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.File
import java.io.InputStream
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Two-stage chained tunnel: Aether (Stage 1 anti-censorship) -> Firefox VPN / Mozilla Fastly (Stage 2 exit node).
 *
 * All control-plane authentication and data-plane HTTP CONNECT tunnels are detoured
 * through Aether's primary SOCKS5 proxy, ensuring reliable connectivity on restricted networks.
 */
class FirefoxVpnExitTunnel(
    private val token: String = "",
    private val country: String = "",
    private val binaryPath: String?,
    private val workingDir: String,
    private val primarySocksHost: String = "127.0.0.1",
    private val primarySocksPort: Int = 2021,
    val localListenPort: Int = 10810
) {
    private val isRunning = AtomicBoolean(false)
    private var process: Process? = null
    private var logScope: CoroutineScope? = null
    var verifiedExitIp: String? = null
        private set

    fun start(): Boolean {
        if (isRunning.getAndSet(true)) return true
        verifiedExitIp = null

        val bin = binaryPath?.takeIf { File(it).exists() } ?: findEngineBinary()
        if (bin == null) {
            LogRepository.e("[FirefoxVpn] No tunnel engine binary found (sing-box or arman-vpn-core).", "FirefoxVpn")
            isRunning.set(false)
            return false
        }

        val isArmanCore = bin.contains("arman-vpn", ignoreCase = true)
        val configFile = File(workingDir, if (isArmanCore) "firefox_arman_config.json" else "firefox_singbox_config.json")

        try {
            if (isArmanCore) {
                configFile.writeText(buildArmanConfig(localListenPort, primarySocksHost, primarySocksPort, token, country))
            } else {
                configFile.writeText(buildSingBoxFirefoxConfig(localListenPort, primarySocksHost, primarySocksPort, token, country))
            }

            val cmd = if (isArmanCore) {
                listOf(bin, "-app", "-data-dir", workingDir)
            } else {
                listOf(bin, "run", "-c", configFile.absolutePath)
            }

            LogRepository.i("[FirefoxVpn] Launching Firefox VPN exit node on 127.0.0.1:$localListenPort via Aether upstream $primarySocksHost:$primarySocksPort...", "FirefoxVpn")
            val pb = ProcessBuilder(cmd)
            pb.directory(File(workingDir))
            pb.redirectErrorStream(true)
            val proc = pb.start()
            process = proc

            logScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
            logScope?.launch {
                runCatching {
                    proc.inputStream.bufferedReader().use { reader ->
                        while (isActive) {
                            val line = reader.readLine() ?: break
                            val l = line.trim()
                            if (l.isNotBlank()) {
                                if (l.contains("error", ignoreCase = true)) {
                                    LogRepository.e("[FirefoxVpn] $l", "FirefoxVpn")
                                } else {
                                    LogRepository.d("[FirefoxVpn] $l", "FirefoxVpn")
                                }
                            }
                        }
                    }
                }
            }

            var listening = false
            for (i in 1..25) {
                if (!proc.isAlive) {
                    val exit = proc.exitValue()
                    LogRepository.e("[FirefoxVpn] Process terminated prematurely with exit code $exit", "FirefoxVpn")
                    stop()
                    return false
                }
                if (probePort("127.0.0.1", localListenPort)) {
                    listening = true
                    break
                }
                Thread.sleep(200)
            }

            if (!listening) {
                LogRepository.e("[FirefoxVpn] Listening port $localListenPort failed to open", "FirefoxVpn")
                stop()
                return false
            }

            val exitIp = verifyDataPlane(localListenPort)
            if (exitIp != null) {
                verifiedExitIp = exitIp
                LogRepository.i("[FirefoxVpn] Two-stage Firefox VPN tunnel active & verified! Exit IP: $exitIp", "FirefoxVpn")
                return true
            } else {
                LogRepository.w("[FirefoxVpn] Data plane probe unconfirmed; tunnel listening on $localListenPort", "FirefoxVpn")
                return true
            }
        } catch (e: Exception) {
            LogRepository.e("[FirefoxVpn] Startup failed: ${e.message}", "FirefoxVpn")
            stop()
            return false
        }
    }

    fun stop() {
        if (!isRunning.getAndSet(false)) return
        verifiedExitIp = null
        logScope?.cancel()
        logScope = null

        process?.let { p ->
            try {
                p.destroy()
                if (!p.waitFor(2, TimeUnit.SECONDS)) {
                    p.destroyForcibly()
                }
            } catch (_: Exception) {}
        }
        process = null
        LogRepository.i("[FirefoxVpn] Exit node stopped.", "FirefoxVpn")
    }

    private fun findEngineBinary(): String? {
        val isWin = System.getProperty("os.name", "").lowercase().contains("win")
        val candidates = if (isWin) {
            listOf("sing-box.exe", "arman-vpn-core.exe")
        } else {
            listOf("sing-box", "arman-vpn-core", "libsing-box.so")
        }
        val dirs = listOf(
            File(workingDir),
            File(workingDir, "bin"),
            File(System.getProperty("user.dir", "."), "bin"),
            File(System.getProperty("user.dir", "."), "composeApp/src/desktopMain/resources/bin")
        )
        for (d in dirs) {
            for (c in candidates) {
                val f = File(d, c)
                if (f.exists() && f.canExecute()) return f.absolutePath
            }
        }
        return null
    }

    private fun buildArmanConfig(listenPort: Int, upstreamHost: String, upstreamPort: Int, token: String, country: String): String {
        val safeCountry = if (country.isNotBlank()) country else ""
        return """
        {
          "version": 2,
          "proxy": {
            "listen": "127.0.0.1:$listenPort",
            "country": "$safeCountry",
            "transport": "h2"
          },
          "network": {
            "upstream_proxy_enabled": true,
            "upstream_proxy": "$upstreamHost:$upstreamPort"
          }
        }
        """.trimIndent()
    }

    private fun buildSingBoxFirefoxConfig(listenPort: Int, upstreamHost: String, upstreamPort: Int, token: String, country: String): String {
        val authHeader = if (token.isNotBlank()) {
            if (token.startsWith("Guardian-Proxy-Pass", ignoreCase = true) || token.startsWith("Bearer", ignoreCase = true)) {
                token
            } else {
                "Guardian-Proxy-Pass $token"
            }
        } else {
            ""
        }

        val authBlock = if (authHeader.isNotBlank()) {
            """
            "headers": {
              "Proxy-Authorization": "$authHeader"
            },
            """.trimIndent()
        } else ""

        return """
        {
          "log": {
            "level": "warn",
            "timestamp": true
          },
          "dns": {
            "servers": [
              {
                "tag": "dns-upstream",
                "address": "tcp://1.1.1.1",
                "detour": "aether-upstream"
              }
            ],
            "rules": [
              {
                "outbound": "any",
                "server": "dns-upstream"
              }
            ],
            "strategy": "prefer_ipv4"
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
            {
              "type": "http",
              "tag": "firefox-exit",
              "server": "exit.vpn.mozilla.org",
              "server_port": 443,
              "tls": {
                "enabled": true,
                "server_name": "exit.vpn.mozilla.org"
              },
              $authBlock
              "detour": "aether-upstream"
            },
            {
              "type": "socks",
              "tag": "aether-upstream",
              "server": "$upstreamHost",
              "server_port": $upstreamPort
            },
            {
              "type": "direct",
              "tag": "direct"
            }
          ],
          "route": {
            "rules": [
              {
                "inbound": ["socks-in", "http-in"],
                "outbound": "firefox-exit"
              }
            ],
            "auto_detect_interface": true
          }
        }
        """.trimIndent()
    }

    private fun verifyDataPlane(socksPort: Int): String? {
        try {
            Socket().use { socket ->
                socket.soTimeout = 4000
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2000)
                val out = socket.getOutputStream()
                val input = socket.getInputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val authResp = ByteArray(2)
                readFully(input, authResp)
                if (authResp[0] == 0x05.toByte() && authResp[1] == 0x00.toByte()) {
                    val req = byteArrayOf(0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x50)
                    out.write(req)
                    out.flush()
                    val connResp = ByteArray(4)
                    readFully(input, connResp)
                    if (connResp[1] == 0x00.toByte()) {
                        when (connResp[3]) {
                            0x01.toByte() -> readFully(input, ByteArray(4 + 2))
                            0x03.toByte() -> {
                                val len = input.read()
                                if (len > 0) readFully(input, ByteArray(len + 2))
                            }
                            0x04.toByte() -> readFully(input, ByteArray(16 + 2))
                        }
                        val httpReq = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: AetherST/2.1\r\nConnection: close\r\n\r\n"
                        out.write(httpReq.toByteArray(Charsets.US_ASCII))
                        out.flush()
                        val text = input.bufferedReader(Charsets.US_ASCII).readText()
                        val ip = Regex("""(?m)^ip=(.+)$""").find(text)?.groupValues?.get(1)?.trim()
                        val loc = Regex("""(?m)^loc=(.+)$""").find(text)?.groupValues?.get(1)?.trim()?.uppercase()
                        if (!ip.isNullOrBlank() && loc != "IR") {
                            return ip
                        }
                    }
                }
            }
        } catch (_: Exception) {}
        return null
    }

    private fun probePort(host: String, port: Int): Boolean {
        return runCatching {
            Socket().use {
                it.connect(InetSocketAddress(host, port), 1000)
                true
            }
        }.getOrDefault(false)
    }

    private fun readFully(stream: InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val count = stream.read(buffer, offset, buffer.size - offset)
            if (count < 0) throw java.io.EOFException("Premature end of stream")
            offset += count
        }
    }
}

