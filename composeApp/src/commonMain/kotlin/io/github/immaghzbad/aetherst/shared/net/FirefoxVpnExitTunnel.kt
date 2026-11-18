package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.data.LogRepository
import kotlinx.coroutines.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Two-stage chained tunnel: Aether (Stage 1 anti-censorship) -> Firefox VPN / Mozilla Fastly (Stage 2 exit node).
 * Inspired by firefox-spider-vpn / arman-vpn-client architecture.
 * Supports direct Firefox Account (FxA) sign-in to obtain Guardian ProxyPass tokens
 * and country-specific Mozilla/Fastly egress routing.
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

    @Volatile
    var verifiedExitIp: String? = null
        private set

    @Volatile
    var lastErrorMessage: String? = null
        private set

    fun start(): Boolean {
        if (isRunning.getAndSet(true)) return true
        verifiedExitIp = null
        lastErrorMessage = null

        val cleanToken = token.trim()
        if (cleanToken.isBlank()) {
            lastErrorMessage = "Firefox VPN token is empty. Please sign in with your Firefox Account or enter a ProxyPass token."
            LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
            isRunning.set(false)
            return false
        }

        val bin = binaryPath?.takeIf { File(it).exists() } ?: findEngineBinary()
        if (bin == null) {
            lastErrorMessage = "sing-box binary not found for Firefox VPN exit node"
            LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
            isRunning.set(false)
            return false
        }

        val configFile = File(workingDir, "firefox_singbox_config.json")

        try {
            // Resolve best Mozilla/Fastly exit host for the requested country via Aether upstream
            val exitHost = resolveCountryExitHost(country.trim().lowercase(), primarySocksHost, primarySocksPort)
            LogRepository.i("[FirefoxVpn] Resolved exit host for country '${country.ifBlank { "auto" }}': $exitHost", "FirefoxVpn")

            configFile.writeText(
                buildSingBoxFirefoxConfig(
                    listenPort = localListenPort,
                    upstreamHost = primarySocksHost,
                    upstreamPort = primarySocksPort,
                    token = cleanToken,
                    exitServerHost = exitHost
                )
            )

            val cmd = listOf(bin, "run", "-c", configFile.absolutePath)
            LogRepository.i("[FirefoxVpn] Launching Firefox VPN exit node on 127.0.0.1:$localListenPort via Aether ($primarySocksHost:$primarySocksPort)...", "FirefoxVpn")

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
                                if (l.contains("error", ignoreCase = true) || l.contains("fatal", ignoreCase = true)) {
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
                    lastErrorMessage = "Firefox VPN engine terminated prematurely (exit=$exit)"
                    LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
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
                lastErrorMessage = "Listening port $localListenPort failed to open"
                LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
                stop()
                return false
            }

            val exitIp = verifyDataPlane(localListenPort)
            if (exitIp != null) {
                verifiedExitIp = exitIp
                LogRepository.i("[FirefoxVpn] Two-stage Firefox VPN tunnel active & verified! Exit IP: $exitIp", "FirefoxVpn")
                return true
            } else {
                lastErrorMessage = "Firefox VPN authentication or data-plane check failed (invalid/expired token or quota exceeded)"
                LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
                stop()
                return false
            }
        } catch (e: Exception) {
            lastErrorMessage = "Firefox VPN startup failed: ${e.message}"
            LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
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
        val candidates = if (isWin) listOf("sing-box.exe") else listOf("sing-box", "libsing-box.so")
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

    private fun buildSingBoxFirefoxConfig(
        listenPort: Int,
        upstreamHost: String,
        upstreamPort: Int,
        token: String,
        exitServerHost: String
    ): String {
        val authHeader = when {
            token.startsWith("Guardian-Proxy-Pass", ignoreCase = true) ||
            token.startsWith("Bearer", ignoreCase = true) -> token
            else -> "Guardian-Proxy-Pass $token"
        }

        return """
        {
          "log": {
            "level": "warn",
            "timestamp": true
          },
          "dns": {
            "servers": [
              {
                "tag": "dns-firefox",
                "address": "tcp://1.1.1.1",
                "detour": "firefox-exit"
              },
              {
                "tag": "dns-upstream",
                "address": "tcp://1.1.1.1",
                "detour": "aether-upstream"
              }
            ],
            "rules": [
              {
                "outbound": "any",
                "server": "dns-firefox"
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
              "server": "$exitServerHost",
              "server_port": 443,
              "tls": {
                "enabled": true,
                "server_name": "$exitServerHost"
              },
              "headers": {
                "Proxy-Authorization": "$authHeader",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"
              },
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
            "final": "firefox-exit",
            "auto_detect_interface": true
          }
        }
        """.trimIndent()
    }

    private fun verifyDataPlane(socksPort: Int): String? {
        try {
            Socket().use { socket ->
                socket.soTimeout = 6000
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2500)
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
                        val httpReq = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: AetherST/2.4\r\nConnection: close\r\n\r\n"
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

    companion object {
        private val jsonParser = Json { ignoreUnknownKeys = true }

        /**
         * Resolves Mozilla Guardian / Fastly exit server hostname for a given 2-letter country code.
         * Falls back to country-prefixed Fastly/Mozilla exit gateway or exit.vpn.mozilla.org.
         */
        fun resolveCountryExitHost(countryCode: String, socksHost: String, socksPort: Int): String {
            val cc = countryCode.trim().lowercase()
            if (cc.isBlank() || cc == "auto") return "exit.vpn.mozilla.org"

            // Try querying Mozilla Guardian public server list via Aether SOCKS5 if available
            val fetched = runCatching {
                val client = buildClient(socksHost, socksPort, timeoutSec = 6)
                val req = Request.Builder()
                    .url("https://vpn.mozilla.org/api/v1/vpn/servers")
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0")
                    .get()
                    .build()
                client.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) return@runCatching null
                    val body = resp.body?.string() ?: return@runCatching null
                    val root = jsonParser.parseToJsonElement(body).jsonObject
                    val countries = root["countries"]?.jsonArray ?: return@runCatching null
                    for (cElem in countries) {
                        val cObj = cElem.jsonObject
                        val code = cObj["code"]?.jsonPrimitive?.content?.lowercase()
                        if (code == cc) {
                            val cities = cObj["cities"]?.jsonArray ?: continue
                            for (cityElem in cities) {
                                val servers = cityElem.jsonObject["servers"]?.jsonArray ?: continue
                                for (srvElem in servers) {
                                    val srvObj = srvElem.jsonObject
                                    val host = srvObj["hostname"]?.jsonPrimitive?.content
                                    if (!host.isNullOrBlank()) {
                                        return@runCatching if (host.contains(".")) host else "$host.mullvad.net"
                                    }
                                }
                            }
                        }
                    }
                    null
                }
            }.getOrNull()

            if (!fetched.isNullOrBlank()) return fetched

            // Standard Mozilla / Fastly multi-region proxy hostname pattern
            return when (cc) {
                "us", "de", "gb", "uk", "nl", "fr", "ca", "ch", "se", "au", "jp", "sg", "es", "it", "at", "be", "fi", "no", "pl" -> {
                    val normCc = if (cc == "uk") "gb" else cc
                    "$normCc.exit.vpn.mozilla.org"
                }
                else -> "exit.vpn.mozilla.org"
            }
        }

        /**
         * Signs in to Firefox Accounts (FxA) and exchanges the OAuth token for a Mozilla Guardian ProxyPass.
         * Uses Aether's local SOCKS5 proxy if running, so Iranian IP / network blocks never trigger Fastly 406 or connection resets.
         */
        suspend fun signInWithFirefoxAccount(
            email: String,
            password: String,
            socksHost: String = "127.0.0.1",
            socksPort: Int = 2021
        ): Result<String> = withContext(Dispatchers.IO) {
            runCatching {
                val cleanEmail = email.trim().lowercase()
                val cleanPass = password
                require(cleanEmail.contains("@") && cleanPass.isNotBlank()) { "Please enter a valid Firefox Account email and password." }

                val client = buildClient(socksHost, socksPort, timeoutSec = 20)
                val mediaJson = "application/json; charset=utf-8".toMediaType()

                // 1. Derive FxA stretch password (PBKDF2-HMAC-SHA256)
                val authPw = deriveFxaAuthPw(cleanEmail, cleanPass)

                // 2. Login to FxA v1/account/login
                val loginPayload = """{"email":"$cleanEmail","authPW":"$authPw","reason":"signin"}"""
                val loginReq = Request.Builder()
                    .url("https://api.accounts.firefox.com/v1/account/login?keys=true")
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0")
                    .post(loginPayload.toRequestBody(mediaJson))
                    .build()

                val sessionTokenHex: String
                client.newCall(loginReq).execute().use { resp ->
                    val bodyStr = resp.body?.string().orEmpty()
                    if (!resp.isSuccessful) {
                        val msg = runCatching {
                            jsonParser.parseToJsonElement(bodyStr).jsonObject["message"]?.jsonPrimitive?.content
                        }.getOrNull() ?: "HTTP ${resp.code}"
                        throw IllegalStateException("FxA sign-in failed: $msg")
                    }
                    val obj = jsonParser.parseToJsonElement(bodyStr).jsonObject
                    val verified = obj["verified"]?.jsonPrimitive?.content?.toBooleanStrictOrNull() ?: true
                    if (!verified) {
                        throw IllegalStateException("Firefox Account email is not verified yet. Check your inbox and verify first.")
                    }
                    sessionTokenHex = obj["sessionToken"]?.jsonPrimitive?.content
                        ?: throw IllegalStateException("Missing sessionToken from FxA response")
                }

                // 3. Exchange sessionToken for FxA OAuth Bearer token (client_id for Mozilla VPN / Firefox Proxy)
                val hawkHeader = buildHawkHeader(
                    method = "POST",
                    host = "api.accounts.firefox.com",
                    port = 443,
                    path = "/v1/oauth/token",
                    sessionTokenHex = sessionTokenHex
                )
                val oauthPayload = """{"client_id":"e6eb0d1e856335fc","grant_type":"fxa-credentials","scope":"https://identity.mozilla.com/apps/vpn profile","access_type":"online"}"""
                val oauthReq = Request.Builder()
                    .url("https://api.accounts.firefox.com/v1/oauth/token")
                    .header("Authorization", hawkHeader)
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0")
                    .post(oauthPayload.toRequestBody(mediaJson))
                    .build()

                val fxaAccessToken: String
                client.newCall(oauthReq).execute().use { resp ->
                    val bodyStr = resp.body?.string().orEmpty()
                    if (!resp.isSuccessful) {
                        throw IllegalStateException("FxA OAuth token exchange failed (HTTP ${resp.code})")
                    }
                    fxaAccessToken = jsonParser.parseToJsonElement(bodyStr).jsonObject["access_token"]?.jsonPrimitive?.content
                        ?: throw IllegalStateException("Missing access_token in OAuth response")
                }

                // 4. Request Guardian ProxyPass token from Mozilla VPN Guardian API
                val proxyPassReq = Request.Builder()
                    .url("https://vpn.mozilla.org/api/v1/vpn/proxypass")
                    .header("Authorization", "Bearer $fxaAccessToken")
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0")
                    .post("{}".toRequestBody(mediaJson))
                    .build()

                client.newCall(proxyPassReq).execute().use { resp ->
                    val bodyStr = resp.body?.string().orEmpty()
                    if (!resp.isSuccessful) {
                        if (resp.code == 406) {
                            throw IllegalStateException("Mozilla/Fastly anti-bot check (HTTP 406). Connect Aether primary tunnel first and retry.")
                        }
                        throw IllegalStateException("Guardian ProxyPass request failed (HTTP ${resp.code})")
                    }
                    val obj = jsonParser.parseToJsonElement(bodyStr).jsonObject
                    val proxyPass = obj["proxypass"]?.jsonPrimitive?.content
                        ?: obj["token"]?.jsonPrimitive?.content
                        ?: throw IllegalStateException("Guardian response did not contain a ProxyPass token")
                    proxyPass
                }
            }
        }

        private fun buildClient(socksHost: String, socksPort: Int, timeoutSec: Long): OkHttpClient {
            val builder = OkHttpClient.Builder()
                .connectTimeout(timeoutSec, TimeUnit.SECONDS)
                .readTimeout(timeoutSec, TimeUnit.SECONDS)
                .writeTimeout(timeoutSec, TimeUnit.SECONDS)

            val socksListening = runCatching {
                Socket().use { it.connect(InetSocketAddress(socksHost, socksPort), 300); true }
            }.getOrDefault(false)

            if (socksListening) {
                builder.proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort)))
            }
            return builder.build()
        }

        private fun deriveFxaAuthPw(email: String, password: String): String {
            val salt = "identity.mozilla.com/picl/v1/quickStretch:$email".toByteArray(Charsets.UTF_8)
            val spec = javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, 1000, 256)
            val skf = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val quickStretched = skf.generateSecret(spec).encoded

            // HKDF-SHA256 expand for authPW
            val info = "identity.mozilla.com/picl/v1/authPW".toByteArray(Charsets.UTF_8)
            val prk = hmacSha256(ByteArray(32), quickStretched)
            val okm = hmacSha256(prk, info + byteArrayOf(0x01))
            return okm.joinToString("") { "%02x".format(it) }
        }

        private fun buildHawkHeader(
            method: String,
            host: String,
            port: Int,
            path: String,
            sessionTokenHex: String
        ): String {
            val tokenBytes = sessionTokenHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val prk = hmacSha256(ByteArray(32), tokenBytes)
            val info = "identity.mozilla.com/picl/v1/sessionToken".toByteArray(Charsets.UTF_8)
            val derived = hmacSha256(prk, info + byteArrayOf(0x01)) +
                hmacSha256(prk, hmacSha256(prk, info + byteArrayOf(0x01)) + info + byteArrayOf(0x02))

            val tokenIdHex = derived.sliceArray(0 until 32).joinToString("") { "%02x".format(it) }
            val reqHmacKey = derived.sliceArray(32 until 64)

            val ts = System.currentTimeMillis() / 1000L
            val nonce = java.util.UUID.randomUUID().toString().replace("-", "").take(6)
            val normalized = "hawk.1.header\n$ts\n$nonce\n$method\n$path\n$host\n$port\n\n\n"
            val macBytes = hmacSha256(reqHmacKey, normalized.toByteArray(Charsets.UTF_8))
            val macB64 = java.util.Base64.getEncoder().encodeToString(macBytes)

            return """Hawk id="$tokenIdHex", ts="$ts", nonce="$nonce", mac="$macB64""""
        }

        private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            return mac.doFinal(data)
        }
    }
}
