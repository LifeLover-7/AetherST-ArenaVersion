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
import java.io.BufferedReader
import java.io.File
import java.io.InputStream
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Exception thrown when Firefox Accounts requires a 6-digit email verification code
 * on a newly created sessionToken before issuing OAuth tokens.
 */
class FxaVerificationRequiredException(
    val sessionTokenHex: String,
    override val message: String
) : IllegalStateException(message)

/**
 * Two-stage chained tunnel: Aether (Stage 1 anti-censorship) -> Firefox VPN / Mozilla Fastly (Stage 2 exit node).
 * Supports both in-app WebView login (sessionToken / OAuth interception) and direct FxA sign-in
 * with 2-step email code verification to obtain Guardian ProxyPass tokens.
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

    @Synchronized
    fun start(): Boolean {
        if (isRunning.get() && isHealthy()) return true
        stopInternal()
        isRunning.set(true)
        verifiedExitIp = null
        lastErrorMessage = null

        val cleanToken = token.trim()
        if (cleanToken.isBlank()) {
            lastErrorMessage = "Firefox VPN token is empty. Please sign in with Firefox WebView or enter a ProxyPass token."
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
            for (i in 1..35) {
                if (!proc.isAlive) {
                    val exit = proc.exitValue()
                    lastErrorMessage = "Firefox VPN engine terminated prematurely (exit=$exit)"
                    LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
                    stopInternal()
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
                stopInternal()
                return false
            }

            val exitIp = verifyDataPlaneWithRetry(localListenPort, maxAttempts = 4)
            if (exitIp != null) {
                verifiedExitIp = exitIp
                LogRepository.i("[FirefoxVpn] Two-stage Firefox VPN tunnel active & verified! Exit IP: $exitIp", "FirefoxVpn")
                return true
            } else {
                lastErrorMessage = "Firefox VPN authentication or data-plane check failed (invalid/expired token or quota exceeded)"
                LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
                stopInternal()
                return false
            }
        } catch (e: Exception) {
            lastErrorMessage = "Firefox VPN startup failed: ${e.message}"
            LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
            stopInternal()
            return false
        }
    }

    @Synchronized
    fun stop() {
        stopInternal()
    }

    private fun stopInternal() {
        val wasRunning = isRunning.getAndSet(false)
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
        if (wasRunning) {
            LogRepository.i("[FirefoxVpn] Exit node stopped.", "FirefoxVpn")
        }
    }

    fun isHealthy(): Boolean = isRunning.get() && process?.isAlive == true && probePort("127.0.0.1", localListenPort)

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
                "detour": "firefox-exit",
                "strategy": "ipv4_only"
              },
              {
                "tag": "dns-upstream",
                "address": "tcp://1.1.1.1",
                "detour": "aether-upstream",
                "strategy": "ipv4_only"
              }
            ],
            "rules": [
              {
                "outbound": "any",
                "server": "dns-upstream"
              }
            ],
            "final": "dns-firefox",
            "strategy": "ipv4_only"
          },
          "inbounds": [
            {
              "type": "socks",
              "tag": "socks-in",
              "listen": "127.0.0.1",
              "listen_port": $listenPort,
              "sniff": true
            },
            {
              "type": "http",
              "tag": "http-in",
              "listen": "127.0.0.1",
              "listen_port": ${listenPort - 1},
              "sniff": true
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
              "server_port": $upstreamPort,
              "version": "5"
            },
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
                "outbound": "firefox-exit"
              }
            ],
            "final": "firefox-exit",
            "auto_detect_interface": false
          }
        }
        """.trimIndent()
    }

    private fun verifyDataPlaneWithRetry(socksPort: Int, maxAttempts: Int = 4): String? {
        for (attempt in 1..maxAttempts) {
            if (process?.isAlive != true) return null
            val ip = verifyDataPlane(socksPort)
            if (ip != null) return ip
            if (attempt < maxAttempts) Thread.sleep(800)
        }
        return null
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
                        val httpReq = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: AetherST/2.5\r\nConnection: close\r\n\r\n"
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
                it.connect(InetSocketAddress(host, port), 800)
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

        // Official Mozilla FxA OAuth client IDs supporting Guardian VPN / Firefox ProxyPass
        private val FXA_CLIENT_IDS = listOf(
            "e6eb0d1e856335fc", // Mozilla VPN / Guardian client
            "a2270f727f45f648", // Firefox Private Network / Guardian extension
            "5882386c6d801776"  // Firefox Desktop Sync/Account
        )

        fun resolveCountryExitHost(countryCode: String, socksHost: String, socksPort: Int): String {
            val cc = countryCode.trim().lowercase()
            if (cc.isBlank() || cc == "auto") return "exit.vpn.mozilla.org"

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

            return when (cc) {
                "us", "de", "gb", "uk", "nl", "fr", "ca", "ch", "se", "au", "jp", "sg", "es", "it", "at", "be", "fi", "no", "pl" -> {
                    val normCc = if (cc == "uk") "gb" else cc
                    "$normCc.exit.vpn.mozilla.org"
                }
                else -> "exit.vpn.mozilla.org"
            }
        }

        /**
         * Exchanges a WebView-intercepted sessionToken, OAuth access_token, or JSON storage payload
         * into a ready-to-use Mozilla Guardian ProxyPass token.
         */
        suspend fun exchangeSessionOrOAuthForProxyPass(
            rawTokenOrJson: String,
            socksHost: String = "127.0.0.1",
            socksPort: Int = 2021
        ): Result<String> = withContext(Dispatchers.IO) {
            runCatching {
                val trimmed = rawTokenOrJson.trim()
                require(trimmed.isNotEmpty()) { "Extracted Firefox token is empty" }

                // 1. If already a Guardian-Proxy-Pass or JWT (3 base64 segments separated by '.')
                if (trimmed.startsWith("Guardian-Proxy-Pass", ignoreCase = true)) {
                    return@runCatching trimmed.substringAfter(" ").trim()
                }
                if (trimmed.count { it == '.' } == 2 && trimmed.startsWith("eyJ")) {
                    return@runCatching trimmed
                }

                // 2. Try extracting sessionToken or access_token if JSON was passed
                var sessionTokenHex: String? = null
                var oauthAccessToken: String? = null

                if (trimmed.startsWith("{")) {
                    runCatching {
                        val sessionMatch = Regex(""""sessionToken"\s*:\s*"([0-9a-fA-F]{64})"""").find(trimmed)
                        if (sessionMatch != null) {
                            sessionTokenHex = sessionMatch.groupValues[1]
                        }
                        val accessMatch = Regex(""""access_token"\s*:\s*"([^"]+)"""").find(trimmed)
                        if (accessMatch != null) {
                            oauthAccessToken = accessMatch.groupValues[1]
                        }
                        val proxyMatch = Regex(""""(?:proxypass|token)"\s*:\s*"(eyJ[^"]+)"""").find(trimmed)
                        if (proxyMatch != null) {
                            return@runCatching proxyMatch.groupValues[1]
                        }
                    }
                } else if (trimmed.matches(Regex("""^[0-9a-fA-F]{64}$"""))) {
                    sessionTokenHex = trimmed
                } else {
                    oauthAccessToken = trimmed.removePrefix("Bearer ").removePrefix("bearer ").trim()
                }

                val client = buildClient(socksHost, socksPort, timeoutSec = 20)

                if (oauthAccessToken.isNullOrBlank() && !sessionTokenHex.isNullOrBlank()) {
                    oauthAccessToken = exchangeSessionTokenForOAuth(client, sessionTokenHex!!)
                }

                val finalAccessToken = oauthAccessToken
                    ?: throw IllegalStateException("Could not extract valid sessionToken or OAuth token from Firefox login")

                // Try requesting Guardian ProxyPass token; if guardian endpoint returns 401/403 (e.g. non-VPN account),
                // fallback to returning the OAuth Bearer token which Fastly Guardian proxy accepts as Bearer/ProxyPass.
                requestGuardianProxyPass(client, finalAccessToken)
            }
        }

        /**
         * Verifies a 6-digit email verification code sent by Firefox Accounts during sign-in,
         * and immediately exchanges the verified sessionToken for a ProxyPass token.
         */
        suspend fun verifySessionEmailCodeAndFetchToken(
            sessionTokenHex: String,
            code: String,
            socksHost: String = "127.0.0.1",
            socksPort: Int = 2021
        ): Result<String> = withContext(Dispatchers.IO) {
            runCatching {
                val cleanCode = code.trim()
                require(cleanCode.length >= 4) { "Please enter the verification code sent to your email." }

                val client = buildClient(socksHost, socksPort, timeoutSec = 20)
                val mediaJson = "application/json; charset=utf-8".toMediaType()

                val hawkHeader = buildHawkHeader(
                    method = "POST",
                    host = "api.accounts.firefox.com",
                    port = 443,
                    path = "/v1/session/verify_code",
                    sessionTokenHex = sessionTokenHex
                )
                val verifyPayload = """{"code":"$cleanCode"}"""
                val verifyReq = Request.Builder()
                    .url("https://api.accounts.firefox.com/v1/session/verify_code")
                    .header("Authorization", hawkHeader)
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0")
                    .post(verifyPayload.toRequestBody(mediaJson))
                    .build()

                client.newCall(verifyReq).execute().use { resp ->
                    if (!resp.isSuccessful) {
                        val bodyStr = resp.body?.string().orEmpty()
                        val msg = runCatching {
                            jsonParser.parseToJsonElement(bodyStr).jsonObject["message"]?.jsonPrimitive?.content
                        }.getOrNull() ?: "HTTP ${resp.code}"
                        throw IllegalStateException("Verification code rejected: $msg")
                    }
                }

                val oauthToken = exchangeSessionTokenForOAuth(client, sessionTokenHex)
                requestGuardianProxyPass(client, oauthToken)
            }
        }

        /**
         * Direct email/password sign-in to Firefox Accounts (FxA) with support for unblockCode
         * and 2-step email verification code challenge.
         */
        suspend fun signInWithFirefoxAccount(
            email: String,
            password: String,
            unblockCode: String = "",
            socksHost: String = "127.0.0.1",
            socksPort: Int = 2021
        ): Result<String> = withContext(Dispatchers.IO) {
            runCatching {
                val cleanEmail = email.trim().lowercase()
                val cleanPass = password
                require(cleanEmail.contains("@") && cleanPass.isNotBlank()) { "Please enter a valid Firefox Account email and password." }

                val client = buildClient(socksHost, socksPort, timeoutSec = 20)
                val mediaJson = "application/json; charset=utf-8".toMediaType()

                val authPw = deriveFxaAuthPw(cleanEmail, cleanPass)
                val unblockField = if (unblockCode.isNotBlank()) ""","unblockCode":"${unblockCode.trim()}"""" else ""
                val loginPayload = """{"email":"$cleanEmail","authPW":"$authPw","reason":"signin","verificationMethod":"email-2fa"$unblockField}"""

                val loginReq = Request.Builder()
                    .url("https://api.accounts.firefox.com/v1/account/login?keys=true")
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0")
                    .post(loginPayload.toRequestBody(mediaJson))
                    .build()

                val sessionTokenHex: String
                var isVerified = true
                client.newCall(loginReq).execute().use { resp ->
                    val bodyStr = resp.body?.string().orEmpty()
                    if (!resp.isSuccessful) {
                        val errObj = runCatching { jsonParser.parseToJsonElement(bodyStr).jsonObject }.getOrNull()
                        val errno = errObj?.get("errno")?.jsonPrimitive?.content?.toIntOrNull()
                        val msg = errObj?.get("message")?.jsonPrimitive?.content ?: "HTTP ${resp.code}"
                        if (errno == 125 || errno == 127 || msg.contains("blocked", ignoreCase = true)) {
                            throw IllegalStateException("Mozilla blocked direct password login (errno=$errno). Please use the 'Sign In with In-App Browser (WebView)' button above.")
                        }
                        throw IllegalStateException("FxA sign-in failed: $msg (Recommended: use In-App WebView Login)")
                    }
                    val obj = jsonParser.parseToJsonElement(bodyStr).jsonObject
                    sessionTokenHex = obj["sessionToken"]?.jsonPrimitive?.content
                        ?: throw IllegalStateException("Missing sessionToken from FxA response")
                    isVerified = obj["verified"]?.jsonPrimitive?.content?.toBooleanStrictOrNull() ?: true
                }

                if (!isVerified) {
                    throw FxaVerificationRequiredException(
                        sessionTokenHex = sessionTokenHex,
                        message = "Firefox sent a 6-digit verification code to your email ($cleanEmail). Enter it below to complete sign-in, or use WebView login."
                    )
                }

                val fxaAccessToken = exchangeSessionTokenForOAuth(client, sessionTokenHex)
                requestGuardianProxyPass(client, fxaAccessToken)
            }
        }

        private fun exchangeSessionTokenForOAuth(client: OkHttpClient, sessionTokenHex: String): String {
            val mediaJson = "application/json; charset=utf-8".toMediaType()
            var lastErr = "OAuth exchange failed"

            val scopes = listOf(
                "https://identity.mozilla.com/apps/vpn profile",
                "profile https://identity.mozilla.com/apps/oldsync"
            )

            for (clientId in FXA_CLIENT_IDS) {
                for (scope in scopes) {
                    val hawkHeader = buildHawkHeader(
                        method = "POST",
                        host = "api.accounts.firefox.com",
                        port = 443,
                        path = "/v1/oauth/token",
                        sessionTokenHex = sessionTokenHex
                    )
                    val oauthPayload = """{"client_id":"$clientId","grant_type":"fxa-credentials","scope":"$scope","access_type":"online"}"""
                    val oauthReq = Request.Builder()
                        .url("https://api.accounts.firefox.com/v1/oauth/token")
                        .header("Authorization", hawkHeader)
                        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0")
                        .post(oauthPayload.toRequestBody(mediaJson))
                        .build()

                    val token = runCatching {
                        client.newCall(oauthReq).execute().use { resp ->
                            val bodyStr = resp.body?.string().orEmpty()
                            if (resp.isSuccessful) {
                                jsonParser.parseToJsonElement(bodyStr).jsonObject["access_token"]?.jsonPrimitive?.content
                            } else {
                                lastErr = "HTTP ${resp.code}: $bodyStr"
                                null
                            }
                        }
                    }.getOrNull()

                    if (!token.isNullOrBlank()) return token
                }
            }
            throw IllegalStateException("FxA OAuth token exchange failed ($lastErr)")
        }

        private fun requestGuardianProxyPass(client: OkHttpClient, fxaAccessToken: String): String {
            val mediaJson = "application/json; charset=utf-8".toMediaType()
            val endpoints = listOf(
                "https://vpn.mozilla.org/api/v1/vpn/proxypass",
                "https://fpn.firefox.com/api/v1/fpn/token"
            )

            for (url in endpoints) {
                val req = Request.Builder()
                    .url(url)
                    .header("Authorization", "Bearer $fxaAccessToken")
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0")
                    .post("{}".toRequestBody(mediaJson))
                    .build()

                val fetched = runCatching {
                    client.newCall(req).execute().use { resp ->
                        val bodyStr = resp.body?.string().orEmpty()
                        if (resp.isSuccessful) {
                            val obj = jsonParser.parseToJsonElement(bodyStr).jsonObject
                            obj["proxypass"]?.jsonPrimitive?.content
                                ?: obj["token"]?.jsonPrimitive?.content
                        } else null
                    }
                }.getOrNull()

                if (!fetched.isNullOrBlank()) return fetched
            }

            // If the account does not have a dedicated vpn.mozilla.org subscription endpoint response,
            // return the OAuth access token directly so it can be used as Bearer / Proxy-Authorization.
            return fxaAccessToken
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
