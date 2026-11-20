package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.data.LogRepository
import kotlinx.coroutines.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread

/**
 * Exception thrown when Firefox Accounts requires a 6-digit email verification code
 * on a newly created sessionToken before issuing OAuth tokens.
 */
class FxaVerificationRequiredException(
    val sessionTokenHex: String,
    override val message: String
) : IllegalStateException(message)

/** Authorized Firefox CONNECT proxy over the active Aether SOCKS5 hop. */
class FirefoxVpnExitTunnel internal constructor(
    private val primary: Proxy,
    val localListenPort: Int,
    private val getPass: (refresh: Boolean) -> String?,
    private val getEdges: () -> List<EdgeEndpoint>,
    private val probe: (Int) -> String?,
    private val tlsFactory: javax.net.ssl.SSLSocketFactory
) {
    constructor(token: String, country: String, primarySocksHost: String = "127.0.0.1", primarySocksPort: Int = 2021,
                localListenPort: Int = 10810) : this(
        Proxy(Proxy.Type.SOCKS, InetSocketAddress(primarySocksHost, primarySocksPort)), localListenPort,
        { refresh -> resolveLiveProxyPassJwt(token, primarySocksHost, primarySocksPort, forceRefresh = refresh) },
        { resolveCountryExitCandidates(country, primarySocksHost, primarySocksPort) },
        { ExitIpProbe(it).check() }, javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory
    )

    private val isRunning = AtomicBoolean(false)
    @Volatile private var socksServerSocket: ServerSocket? = null
    @Volatile private var httpServerSocket: ServerSocket? = null
    @Volatile private var udpRelaySocket: DatagramSocket? = null
    private val sessionLock = Any()
    @Volatile private var session: FirefoxConnectSession? = null
    private var currentEdge: EdgeEndpoint? = null
    @Volatile private var currentProxyPass = ""
    @Volatile private var rejected: ConnectRejected? = null
    private var renewalThread: Thread? = null
    private val clients = ConcurrentHashMap.newKeySet<Socket>()
    private val executor = Executors.newCachedThreadPool { r -> Thread(r, "FirefoxVPN-worker").apply { isDaemon = true } }

    @Volatile var verifiedExitIp: String? = null
        private set
    @Volatile var lastErrorMessage: String? = null
        private set

    data class EdgeEndpoint(val host: String, val port: Int, val countryCode: String)

    private fun connect(edge: EdgeEndpoint) = FirefoxConnectSession(HostPort(edge.host, edge.port), primary, tlsFactory) { currentProxyPass }

    @Synchronized
    fun start(): Boolean {
        if (isHealthy()) return true
        stop()
        lastErrorMessage = null
        isRunning.set(true)
        return try {
            require(localListenPort in 2..65535 && (primary.address() as InetSocketAddress).port !in (localListenPort - 1)..localListenPort) {
                "Invalid or overlapping Firefox proxy ports"
            }
            currentProxyPass = getPass(false)?.takeIf { it.isNotBlank() } ?: error("Firefox VPN authorization unavailable or expired")
            val edges = getEdges()
            startLocalUdpDnsRelay()
            startLocalSocks5Server(localListenPort)
            startLocalHttpServer(localListenPort - 1)
            for (edge in edges.take(4)) {
                val candidate = try { connect(edge) } catch (e: Exception) {
                    LogRepository.w("[FirefoxVpn] TLS to ${edge.host} failed (${e.javaClass.simpleName})", "FirefoxVpn")
                    continue
                }
                synchronized(sessionLock) { session = candidate; currentEdge = edge; rejected = null }
                // Probe through the actual local SOCKS handler. Never hold sessionLock while waiting for it.
                val ip = probe(localListenPort)
                if (ip != null && candidate.isAlive()) {
                    verifiedExitIp = ip
                    startProxyPassRenewalLoop()
                    LogRepository.i("[FirefoxVpn] Verified ${candidate.protocol} CONNECT via ${edge.host}; exit IP $ip", "FirefoxVpn")
                    return true
                }
                synchronized(sessionLock) { candidate.close(); session = null }
                rejected?.let { if (it.status in setOf(401, 403, 407, 429)) throw it }
            }
            error("No Firefox proxy carried traffic through the primary tunnel")
        } catch (e: Exception) {
            lastErrorMessage = e.message ?: "Firefox exit startup failed"
            LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
            stop()
            false
        }
    }

    @Synchronized
    fun stop() {
        isRunning.set(false)
        verifiedExitIp = null
        renewalThread?.interrupt()
        renewalThread = null
        runCatching { socksServerSocket?.close() }; socksServerSocket = null
        runCatching { httpServerSocket?.close() }; httpServerSocket = null
        runCatching { udpRelaySocket?.close() }; udpRelaySocket = null
        clients.forEach { runCatching { it.close() } }
        synchronized(sessionLock) { session?.close(); session = null; currentEdge = null }
        currentProxyPass = ""
    }

    fun isHealthy() = isRunning.get() && verifiedExitIp != null && session?.isAlive() == true && socksServerSocket?.isClosed == false

    private fun openStream(host: String, port: Int): ConnectPipe? {
        return try {
            val active = synchronized(sessionLock) {
                if (!isRunning.get()) return null
                session?.takeIf { it.isAlive() } ?: run {
                    if (verifiedExitIp == null) return null
                    session?.close()
                    connect(currentEdge ?: return null).also { session = it }
                }
            }
            active.open(host, port)
        } catch (e: ConnectRejected) {
            rejected = e
            LogRepository.w("[FirefoxVpn] ${e.message}", "FirefoxVpn")
            null
        } catch (_: Exception) { null }
    }

    private fun startProxyPassRenewalLoop() {
        renewalThread = thread(isDaemon = true, name = "FirefoxVPN-PassRenewal") {
            try {
                while (isRunning.get()) {
                    Thread.sleep(240_000L)
                    val refreshed = runCatching { getPass(true) }.getOrNull()
                    if (Thread.currentThread().isInterrupted || !isRunning.get()) break
                    if (!refreshed.isNullOrBlank()) currentProxyPass = refreshed
                }
            } catch (_: InterruptedException) { }
        }
    }

    private fun serve(client: Socket, handle: (Socket) -> Unit) {
        clients.add(client)
        executor.execute {
            try { if (isRunning.get()) handle(client) } finally { clients.remove(client); client.close() }
        }
    }

    private fun startLocalSocks5Server(port: Int) {
        val server = ServerSocket()
        server.reuseAddress = true
        server.bind(InetSocketAddress("127.0.0.1", port), 256)
        socksServerSocket = server

        thread(start = true, isDaemon = true, name = "FirefoxVPN-Socks5") {
            while (isRunning.get() && !server.isClosed) {
                val client = try {
                    server.accept()
                } catch (_: Exception) {
                    break
                }
                serve(client, ::handleSocks5Client)
            }
        }
    }

    private fun handleSocks5Client(client: Socket) {
        try {
            client.tcpNoDelay = true
            client.soTimeout = 15_000
            val ins = DataInputStream(BufferedInputStream(client.getInputStream()))
            val out = BufferedOutputStream(client.getOutputStream())

            if (ins.read() != 0x05) {
                client.close()
                return
            }
            val nMethods = ins.readUnsignedByte()
            ins.readFully(ByteArray(nMethods))
            out.write(byteArrayOf(0x05, 0x00))
            out.flush()

            if (ins.read() != 0x05) {
                client.close()
                return
            }
            val cmd = ins.readUnsignedByte()
            ins.readUnsignedByte()
            val atyp = ins.readUnsignedByte()

            val targetHost: String = when (atyp) {
                0x01 -> {
                    val ip = ByteArray(4)
                    ins.readFully(ip)
                    InetAddress.getByAddress(ip).hostAddress ?: "0.0.0.0"
                }
                0x03 -> {
                    val dLen = ins.readUnsignedByte()
                    val dBytes = ByteArray(dLen)
                    ins.readFully(dBytes)
                    String(dBytes, Charsets.UTF_8)
                }
                0x04 -> {
                    val ip6 = ByteArray(16)
                    ins.readFully(ip6)
                    InetAddress.getByAddress(ip6).hostAddress ?: "::"
                }
                else -> {
                    client.close()
                    return
                }
            }
            val targetPort = ins.readUnsignedShort()

            when (cmd) {
                0x01 -> { // CONNECT
                    if (targetPort == 53) {
                        out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 53))
                        out.flush()
                        handleTcpDnsOverDoH(ins, out)
                        return
                    }

                    val stream = openStream(targetHost, targetPort)
                    if (stream == null) {
                        out.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        out.flush()
                        return
                    }

                    out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0))
                    out.flush()
                    client.soTimeout = 0
                    pipeClient(client, ins, out, stream)
                }
                0x03 -> { // UDP ASSOCIATE
                    val relayPort = udpRelaySocket?.localPort ?: 0
                    if (relayPort <= 0) {
                        out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        out.flush()
                        return
                    }
                    out.write(
                        byteArrayOf(
                            0x05, 0x00, 0x00, 0x01,
                            127, 0, 0, 1,
                            ((relayPort ushr 8) and 0xFF).toByte(),
                            (relayPort and 0xFF).toByte()
                        )
                    )
                    out.flush()
                    client.soTimeout = 0
                    while (isRunning.get() && !client.isClosed) {
                        if (ins.read() < 0) break
                    }
                }
                else -> {
                    out.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    out.flush()
                }
            }
        } catch (_: Exception) {
        } finally {
            runCatching { client.close() }
        }
    }

    private fun pipeClient(client: Socket, ins: InputStream, out: OutputStream, stream: ConnectPipe) {
        fun pump(input: InputStream, output: OutputStream) {
            val buf = ByteArray(16 * 1024)
            while (isRunning.get()) {
                val count = input.read(buf)
                if (count < 0) break
                output.write(buf, 0, count)
                output.flush()
            }
        }
        stream.use {
            val down = thread(isDaemon = true, name = "FirefoxVPN-down") {
                try { pump(stream.input, out) } catch (_: Exception) { }
                finally { runCatching { client.shutdownOutput() } }
            }
            pump(ins, stream.output)
            // A client FIN is not a stream cancellation: the response may still be in flight.
            stream.finishOutput()
            down.join(120_000)
        }
    }

    private fun startLocalUdpDnsRelay() {
        val ds = DatagramSocket(InetSocketAddress("127.0.0.1", 0))
        udpRelaySocket = ds
        thread(start = true, isDaemon = true, name = "FirefoxVPN-UdpDoH") {
            val buf = ByteArray(4096)
            while (isRunning.get() && !ds.isClosed) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    ds.receive(pkt)
                    val raw = pkt.data.copyOfRange(pkt.offset, pkt.offset + pkt.length)
                    val clientAddr = pkt.socketAddress
                    executor.execute { handleSocks5UdpDatagram(ds, clientAddr, raw) }
                } catch (_: Exception) {
                    if (!isRunning.get() || ds.isClosed) break
                }
            }
        }
    }

    private fun handleSocks5UdpDatagram(ds: DatagramSocket, clientAddr: java.net.SocketAddress, raw: ByteArray) {
        if (raw.size < 10) return
        val atyp = raw[3].toInt() and 0xFF
        val headerLen = when (atyp) {
            0x01 -> 10
            0x04 -> 22
            0x03 -> 7 + (raw[4].toInt() and 0xFF)
            else -> return
        }
        if (raw.size <= headerLen) return
        val dstPort = ((raw[headerLen - 2].toInt() and 0xFF) shl 8) or (raw[headerLen - 1].toInt() and 0xFF)
        if (dstPort != 53) return

        val dnsQuery = raw.copyOfRange(headerLen, raw.size)
        val dnsResp = resolveDnsOverInTunnelDoH(dnsQuery) ?: return
        val reply = ByteArray(headerLen + dnsResp.size)
        System.arraycopy(raw, 0, reply, 0, headerLen)
        System.arraycopy(dnsResp, 0, reply, headerLen, dnsResp.size)
        runCatching { ds.send(DatagramPacket(reply, reply.size, clientAddr)) }
    }

    private fun handleTcpDnsOverDoH(ins: DataInputStream, out: OutputStream) {
        try {
            while (isRunning.get()) {
                val qLen = try {
                    ins.readUnsignedShort()
                } catch (_: Exception) {
                    break
                }
                if (qLen <= 0 || qLen > 8192) break
                val qBytes = ByteArray(qLen)
                ins.readFully(qBytes)
                val resp = resolveDnsOverInTunnelDoH(qBytes) ?: break
                out.write((resp.size ushr 8) and 0xFF)
                out.write(resp.size and 0xFF)
                out.write(resp)
                out.flush()
            }
        } catch (_: Exception) {}
    }

    private fun resolveDnsOverInTunnelDoH(dnsQuery: ByteArray): ByteArray? {
        val dohEndpoints = listOf(
            "https://1.1.1.1/dns-query",
            "https://1.0.0.1/dns-query",
            "https://9.9.9.9/dns-query"
        )
        val socksProxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", localListenPort))
        for (urlStr in dohEndpoints) {
            try {
                val conn = (URL(urlStr).openConnection(socksProxy) as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = 5_000
                    readTimeout = 5_000
                    doOutput = true
                    setRequestProperty("Content-Type", "application/dns-message")
                    setRequestProperty("Accept", "application/dns-message")
                }
                conn.outputStream.use { it.write(dnsQuery) }
                if (conn.responseCode in 200..299) {
                    val bytes = conn.inputStream.use { it.readBytes() }
                    if (bytes.size >= 12) return bytes
                }
            } catch (_: Exception) {}
        }
        return null
    }

    private fun startLocalHttpServer(port: Int) {
        val server = ServerSocket()
        server.reuseAddress = true
        server.bind(InetSocketAddress("127.0.0.1", port), 128)
        httpServerSocket = server

        thread(start = true, isDaemon = true, name = "FirefoxVPN-HttpProxy") {
            while (isRunning.get() && !server.isClosed) {
                val client = try {
                    server.accept()
                } catch (_: Exception) {
                    break
                }
                serve(client, ::handleHttpProxyClient)
            }
        }
    }

    private fun handleHttpProxyClient(client: Socket) {
        try {
            client.tcpNoDelay = true
            client.soTimeout = 15_000
            val ins = BufferedInputStream(client.getInputStream())
            val out = BufferedOutputStream(client.getOutputStream())

            val reqLine = readAsciiLine(ins) ?: return
            while (true) {
                val h = readAsciiLine(ins) ?: break
                if (h.isEmpty()) break
            }

            val parts = reqLine.split(" ")
            if (parts.size < 2 || !parts[0].equals("CONNECT", ignoreCase = true)) {
                out.write("HTTP/1.1 405 Method Not Allowed\r\n\r\n".toByteArray())
                out.flush()
                return
            }
            val target = HostPort.parse(parts[1])
            val stream = openStream(target.host, target.port) ?: run {
                out.write("HTTP/1.1 502 Bad Gateway\r\n\r\n".toByteArray())
                out.flush()
                return
            }

            out.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
            out.flush()
            client.soTimeout = 0
            pipeClient(client, ins, out, stream)
        } catch (_: Exception) {
        } finally {
            runCatching { client.close() }
        }
    }

    companion object {
        private val jsonParser = Json { ignoreUnknownKeys = true }

        // Mandatory Mozilla VPN User-Agent required by vpn.mozilla.org and Remote Settings
        private const val MOZILLA_VPN_UA = "MozillaVPN/2.35.0 (sys:linux; iap:true)"
        private const val FIREFOX_DESKTOP_UA =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0"

        private const val FXA_API_BASE = "https://api.accounts.firefox.com/v1"
        private const val FXA_OAUTH_BASE = "https://oauth.accounts.firefox.com/v1"
        private const val GUARDIAN_API_BASE = "https://vpn.mozilla.org"
        private const val REMOTE_SETTINGS_URL =
            "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"

        private const val FXA_SCOPE_VPN = "profile https://identity.mozilla.com/apps/vpn"

        private val FXA_CLIENT_IDS = listOf(
            "e6eb0d1e856335fc", // Official Mozilla VPN client ID
            "5882386c6d801776", // Official Firefox VPN proxy / Desktop FxA client ID
            "a2270f727f45f648"  // Firefox Private Network / Fenix
        )

        /**
         * Resolves live Mozilla Fastly CONNECT edge candidates (`host:port`) from Mozilla Remote Settings
         * (`vpn-serverlist` collection), falling back to official Fastly MASQUE/CONNECT aggregate hostnames
         * (`<cc>.m1.fastly-masque.net:443`).
         */
        data class FirefoxServerOption(
            val id: String,
            val countryCode: String,
            val titleFa: String,
            val titleEn: String,
            val subtitle: String
        )

        val BUILTIN_SERVER_OPTIONS: List<FirefoxServerOption> = listOf(
            FirefoxServerOption("us", "US", "آمریکا (اتوماتیک سریع‌ترین سرور)", "United States (Auto Best)", "us.m1.fastly-masque.net:443"),
            FirefoxServerOption("de", "DE", "آلمان (فرانکفورت / برلین)", "Germany (Frankfurt / Berlin)", "de.m1.fastly-masque.net:443"),
            FirefoxServerOption("nl", "NL", "هلند (آمستردام)", "Netherlands (Amsterdam)", "nl.m1.fastly-masque.net:443"),
            FirefoxServerOption("gb", "GB", "بریتانیا (لندن / منچستر)", "United Kingdom (London)", "gb.m1.fastly-masque.net:443"),
            FirefoxServerOption("fr", "FR", "فرانسه (پاریس / مارسی)", "France (Paris)", "fr.m1.fastly-masque.net:443"),
            FirefoxServerOption("ch", "CH", "سوئیس (زوریخ)", "Switzerland (Zurich)", "ch.m1.fastly-masque.net:443"),
            FirefoxServerOption("se", "SE", "سوئد (استکهلم / مالمو)", "Sweden (Stockholm)", "se.m1.fastly-masque.net:443"),
            FirefoxServerOption("fi", "FI", "فنلاند (هلسینکی)", "Finland (Helsinki)", "fi.m1.fastly-masque.net:443"),
            FirefoxServerOption("ca", "CA", "کانادا (تورنتو / مونترال / ونکوور)", "Canada (Toronto / Vancouver)", "ca.m1.fastly-masque.net:443"),
            FirefoxServerOption("at", "AT", "اتریش (وین)", "Austria (Vienna)", "at.m1.fastly-masque.net:443"),
            FirefoxServerOption("es", "ES", "اسپانیا (مادرید)", "Spain (Madrid)", "es.m1.fastly-masque.net:443"),
            FirefoxServerOption("it", "IT", "ایتالیا (میلان / رم)", "Italy (Milan / Rome)", "it.m1.fastly-masque.net:443"),
            FirefoxServerOption("jp", "JP", "ژاپن (توکیو / اوزاکا)", "Japan (Tokyo / Osaka)", "jp.m1.fastly-masque.net:443"),
            FirefoxServerOption("sg", "SG", "سنگاپور (سنگاپور)", "Singapore", "sg.m1.fastly-masque.net:443"),
            FirefoxServerOption("au", "AU", "استرالیا (سیدنی / ملبورن)", "Australia (Sydney)", "au.m1.fastly-masque.net:443"),
            FirefoxServerOption("be", "BE", "بلژیک (بروکسل)", "Belgium (Brussels)", "be.m1.fastly-masque.net:443"),
            FirefoxServerOption("dk", "DK", "دانمارک (کپنهاگ)", "Denmark (Copenhagen)", "dk.m1.fastly-masque.net:443"),
            FirefoxServerOption("ie", "IE", "ایرلند (دوبلین)", "Ireland (Dublin)", "ie.m1.fastly-masque.net:443"),
            FirefoxServerOption("no", "NO", "نروژ (اسلو)", "Norway (Oslo)", "no.m1.fastly-masque.net:443"),
            FirefoxServerOption("pl", "PL", "لهستان (ورشو)", "Poland (Warsaw)", "pl.m1.fastly-masque.net:443"),
            FirefoxServerOption("pt", "PT", "پرتغال (لیسبون)", "Portugal (Lisbon)", "pt.m1.fastly-masque.net:443"),
            FirefoxServerOption("cz", "CZ", "جمهوری چک (پراگ)", "Czechia (Prague)", "cz.m1.fastly-masque.net:443"),
            FirefoxServerOption("ro", "RO", "رومانی (بخارست)", "Romania (Bucharest)", "ro.m1.fastly-masque.net:443"),
            FirefoxServerOption("bg", "BG", "بلغارستان (صوفیه)", "Bulgaria (Sofia)", "bg.m1.fastly-masque.net:443"),
            FirefoxServerOption("hu", "HU", "مجارستان (بوداپست)", "Hungary (Budapest)", "hu.m1.fastly-masque.net:443")
        )

        fun extractCountryCode(rawSpec: String): String {
            val trimmed = rawSpec.trim()
            if (trimmed.isEmpty()) return "US"
            if (trimmed.contains("|")) {
                val cc = trimmed.substringBefore("|").trim().uppercase()
                if (cc.length == 2) return if (cc == "UK") "GB" else cc
            }
            if (trimmed.contains(".")) {
                val prefix = trimmed.substringBefore(".").trim().uppercase()
                if (prefix.length == 2) return if (prefix == "UK") "GB" else prefix
            }
            val code = trimmed.take(2).uppercase()
            return if (code == "UK") "GB" else code
        }

        suspend fun fetchLiveServerOptions(
            socksHost: String = "127.0.0.1",
            socksPort: Int = 2021
        ): List<FirefoxServerOption> = withContext(Dispatchers.IO) {
            val combined = mutableListOf<FirefoxServerOption>()
            combined.addAll(BUILTIN_SERVER_OPTIONS)

            val live = runCatching {
                val client = buildClient(socksHost, socksPort, timeoutSec = 4)
                val req = Request.Builder()
                    .url(REMOTE_SETTINGS_URL)
                    .header("User-Agent", MOZILLA_VPN_UA)
                    .header("Accept", "application/json")
                    .get()
                    .build()
                client.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) return@runCatching emptyList<FirefoxServerOption>()
                    val body = resp.body?.string() ?: return@runCatching emptyList<FirefoxServerOption>()
                    val root = jsonParser.parseToJsonElement(body).jsonObject
                    val dataArr = root["data"]?.jsonArray ?: return@runCatching emptyList<FirefoxServerOption>()
                    val discovered = mutableListOf<FirefoxServerOption>()
                    for (recElem in dataArr) {
                        val rec = recElem.jsonObject
                        val code = (rec["code"]?.jsonPrimitive?.content ?: rec["country"]?.jsonPrimitive?.content ?: "US").uppercase()
                        val countryName = rec["name"]?.jsonPrimitive?.content ?: code
                        val cities = rec["cities"]?.jsonArray ?: continue
                        for (cityElem in cities) {
                            val cityObj = cityElem.jsonObject
                            val cityName = cityObj["name"]?.jsonPrimitive?.content ?: cityObj["code"]?.jsonPrimitive?.content ?: ""
                            val servers = cityObj["servers"]?.jsonArray ?: continue
                            for (srvElem in servers) {
                                val srv = srvElem.jsonObject
                                if (srv["quarantined"]?.jsonPrimitive?.booleanOrNull == true) continue
                                val srvName = srv["hostname"]?.jsonPrimitive?.content ?: srv["name"]?.jsonPrimitive?.content ?: ""
                                val protocols = srv["protocols"]?.jsonArray
                                var connectHost: String? = null
                                var connectPort = 443
                                if (protocols != null) {
                                    for (pElem in protocols) {
                                        val pObj = pElem.jsonObject
                                        if (pObj["name"]?.jsonPrimitive?.content?.lowercase() == "connect") {
                                            connectHost = pObj["host"]?.jsonPrimitive?.content?.trim()
                                            connectPort = pObj["port"]?.jsonPrimitive?.intOrNull ?: 443
                                            if (!connectHost.isNullOrBlank()) break
                                        }
                                    }
                                }
                                if (connectHost.isNullOrBlank()) {
                                    val fallbackH = (srv["host"]?.jsonPrimitive?.content ?: srv["hostname"]?.jsonPrimitive?.content)?.trim()
                                    if (!fallbackH.isNullOrBlank() && fallbackH.contains(".")) {
                                        connectHost = fallbackH
                                        connectPort = srv["port"]?.jsonPrimitive?.intOrNull ?: 443
                                    }
                                }
                                if (!connectHost.isNullOrBlank()) {
                                    val id = "${code.lowercase()}|$connectHost:$connectPort"
                                    val cityLabel = if (cityName.isNotBlank()) "$countryName - $cityName" else countryName
                                    val shortHost = srvName.ifBlank { connectHost.substringBefore(".") }
                                    discovered.add(
                                        FirefoxServerOption(
                                            id = id,
                                            countryCode = code,
                                            titleFa = "$cityLabel ($shortHost)",
                                            titleEn = "$cityLabel ($shortHost)",
                                            subtitle = "$connectHost:$connectPort"
                                        )
                                    )
                                }
                            }
                        }
                    }
                    discovered
                }
            }.getOrDefault(emptyList())

            combined.addAll(live)
            combined.distinctBy { it.id.lowercase() }
        }

        fun resolveCountryExitCandidates(
            countryCode: String,
            socksHost: String,
            socksPort: Int
        ): List<EdgeEndpoint> {
            val results = mutableListOf<EdgeEndpoint>()
            val trimmedSpec = countryCode.trim()
            val explicitHostPort = when {
                trimmedSpec.contains("|") -> trimmedSpec.substringAfter("|").trim()
                trimmedSpec.contains(".") -> trimmedSpec
                else -> null
            }
            val rawCc = extractCountryCode(trimmedSpec)
            val targetCc = when {
                rawCc.isBlank() || rawCc == "AUTO" -> "US"
                rawCc == "UK" -> "GB"
                else -> rawCc
            }
            val fetched = runCatching {
                val client = buildClient(socksHost, socksPort, timeoutSec = 4, requirePrimary = true)
                val req = Request.Builder()
                    .url(REMOTE_SETTINGS_URL)
                    .header("User-Agent", MOZILLA_VPN_UA)
                    .header("Accept", "application/json")
                    .get()
                    .build()
                client.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) return@runCatching emptyList()
                    val body = resp.body?.string() ?: return@runCatching emptyList()
                    val root = jsonParser.parseToJsonElement(body).jsonObject
                    val dataArr = root["data"]?.jsonArray ?: return@runCatching emptyList()
                    val list = mutableListOf<EdgeEndpoint>()
                    for (recElem in dataArr) {
                        val rec = recElem.jsonObject
                        val code = (rec["code"]?.jsonPrimitive?.content ?: rec["country"]?.jsonPrimitive?.content ?: "US").uppercase()
                        val cities = rec["cities"]?.jsonArray ?: continue
                        for (cityElem in cities) {
                            val servers = cityElem.jsonObject["servers"]?.jsonArray ?: continue
                            for (srvElem in servers) {
                                val srv = srvElem.jsonObject
                                if (srv["quarantined"]?.jsonPrimitive?.booleanOrNull == true) continue
                                val protocols = srv["protocols"]?.jsonArray
                                var added = false
                                if (protocols != null) {
                                    for (pElem in protocols) {
                                        val pObj = pElem.jsonObject
                                        val pName = pObj["name"]?.jsonPrimitive?.content?.lowercase()
                                        if (pName == "connect") {
                                            val h = pObj["host"]?.jsonPrimitive?.content?.trim()
                                            val pt = pObj["port"]?.jsonPrimitive?.intOrNull ?: 443
                                            if (!h.isNullOrBlank()) {
                                                list.add(EdgeEndpoint(h, pt, code))
                                                added = true
                                            }
                                        }
                                    }
                                }
                                if (!added) {
                                    val h = (srv["host"]?.jsonPrimitive?.content ?: srv["hostname"]?.jsonPrimitive?.content)?.trim()
                                    val pt = srv["port"]?.jsonPrimitive?.intOrNull ?: 443
                                    if (!h.isNullOrBlank() && h.contains(".")) {
                                        list.add(EdgeEndpoint(h, pt, code))
                                    }
                                }
                            }
                        }
                    }
                    list
                }
            }.getOrDefault(emptyList())

            // Only provider-discovered endpoints (or the built-in Mozilla edges below) may receive a pass.
            fetched.firstOrNull { "${it.host}:${it.port}".equals(explicitHostPort, ignoreCase = true) }?.let(results::add)
            if (fetched.isNotEmpty()) {
                results.addAll(fetched.filter { it.countryCode.equals(targetCc, ignoreCase = true) })
                results.addAll(fetched.filter { it.countryCode.equals("REC", ignoreCase = true) })
                results.addAll(fetched.filter { it.countryCode.equals("US", ignoreCase = true) })
                results.addAll(fetched)
            }

            val ccLower = targetCc.takeIf { it.matches(Regex("[A-Z]{2}")) }?.lowercase() ?: "us"
            results.addAll(
                listOf(
                    EdgeEndpoint("$ccLower.m1.fastly-masque.net", 443, targetCc),
                    EdgeEndpoint("us.m1.fastly-masque.net", 443, "US"),
                    EdgeEndpoint("de.m1.fastly-masque.net", 443, "DE"),
                    EdgeEndpoint("nl.m1.fastly-masque.net", 443, "NL"),
                    EdgeEndpoint("gb.m1.fastly-masque.net", 443, "GB"),
                    EdgeEndpoint("ca.m1.fastly-masque.net", 443, "CA"),
                    EdgeEndpoint("fr.m1.fastly-masque.net", 443, "FR"),
                    EdgeEndpoint("m1.fastly-masque.net", 443, "US")
                )
            )
            return results.distinctBy { "${it.host.lowercase()}:${it.port}" }
        }

        fun resolveCountryExitHost(countryCode: String, socksHost: String, socksPort: Int): String {
            return resolveCountryExitCandidates(countryCode, socksHost, socksPort).first().host
        }

        /**
         * Resolves a stored token (`sessionToken` 64-hex, `fxa:<sessionToken>:<oauthToken>`, OAuth `access_token`,
         * or Guardian ProxyPass JWT `eyJ...`) into a live, non-expired Guardian ProxyPass JWT through Aether's SOCKS5 proxy.
         */
        fun resolveLiveProxyPassJwt(
            rawTokenOrBundle: String,
            socksHost: String = "127.0.0.1",
            socksPort: Int = 2021,
            forceRefresh: Boolean = false
        ): String? {
            val trimmed = rawTokenOrBundle.trim()
                .removePrefix("Guardian-Proxy-Pass ")
                .removePrefix("Bearer ")
                .trim()
            if (trimmed.isEmpty()) return null

            var sessionTokenHex: String? = null
            var oauthAccessToken: String? = null
            var cachedJwt: String? = null

            when {
                trimmed.startsWith("fxa:", ignoreCase = true) -> {
                    val parts = trimmed.split(":")
                    sessionTokenHex = parts.getOrNull(1)?.takeIf { it.matches(Regex("""^[0-9a-fA-F]{64}$""")) }
                    oauthAccessToken = parts.getOrNull(2)?.takeIf { it.isNotBlank() }
                    cachedJwt = parts.getOrNull(3)?.takeIf { it.startsWith("eyJ") }
                }
                trimmed.startsWith("{") -> {
                    sessionTokenHex = Regex(""""sessionToken"\s*:\s*"([0-9a-fA-F]{64})"""").find(trimmed)?.groupValues?.get(1)
                    oauthAccessToken = Regex(""""access_token"\s*:\s*"([^"]+)"""").find(trimmed)?.groupValues?.get(1)
                    cachedJwt = Regex(""""(?:proxypass|token)"\s*:\s*"(eyJ[^"]+)"""").find(trimmed)?.groupValues?.get(1)
                }
                trimmed.matches(Regex("""^[0-9a-fA-F]{64}$""")) -> {
                    sessionTokenHex = trimmed
                }
                trimmed.startsWith("eyJ") && trimmed.count { it == '.' } == 2 -> {
                    cachedJwt = trimmed
                }
                else -> {
                    oauthAccessToken = trimmed
                }
            }

            if (!forceRefresh && !cachedJwt.isNullOrBlank() && isJwtFresh(cachedJwt, 90)) {
                return cachedJwt
            }

            val client = buildClient(socksHost, socksPort, timeoutSec = 15, requirePrimary = true)

            val currentOAuth = oauthAccessToken
            if (!currentOAuth.isNullOrBlank()) {
                val jwt = runCatching { requestGuardianProxyPass(client, currentOAuth) }.getOrNull()
                if (!jwt.isNullOrBlank()) return jwt
            }

            val currentSession = sessionTokenHex
            if (!currentSession.isNullOrBlank()) {
                val mintedOAuth = runCatching { exchangeSessionTokenForOAuth(client, currentSession) }.getOrNull()
                if (!mintedOAuth.isNullOrBlank()) {
                    val jwt = runCatching { requestGuardianProxyPass(client, mintedOAuth) }.getOrNull()
                    if (!jwt.isNullOrBlank()) return jwt
                }
            }

            return cachedJwt?.takeIf { isJwtFresh(it, 10) }
        }

        /**
         * Called by FirefoxVpnDialog after WebView login or token paste.
         * Preserves the persistent 64-hex `sessionToken` (as `fxa:<sessionToken>:<oauth>:<jwt>` or `<sessionToken>`)
         * so that connecting later (or after the 10-minute ProxyPass JWT expires) always mints a fresh ProxyPass JWT
         * through Aether's Layer-1 tunnel!
         */
        suspend fun exchangeSessionOrOAuthForProxyPass(
            rawTokenOrJson: String,
            socksHost: String = "127.0.0.1",
            socksPort: Int = 2021
        ): Result<String> = withContext(Dispatchers.IO) {
            runCatching {
                val trimmed = rawTokenOrJson.trim()
                require(trimmed.isNotEmpty()) { "Extracted Firefox token is empty" }

                var sessionTokenHex: String? = null
                var oauthAccessToken: String? = null

                when {
                    trimmed.startsWith("fxa:", ignoreCase = true) -> {
                        val parts = trimmed.split(":")
                        sessionTokenHex = parts.getOrNull(1)?.takeIf { it.matches(Regex("""^[0-9a-fA-F]{64}$""")) }
                        oauthAccessToken = parts.getOrNull(2)?.takeIf { it.isNotBlank() }
                    }
                    trimmed.startsWith("{") -> {
                        sessionTokenHex = Regex(""""sessionToken"\s*:\s*"([0-9a-fA-F]{64})"""").find(trimmed)?.groupValues?.get(1)
                        oauthAccessToken = Regex(""""access_token"\s*:\s*"([^"]+)"""").find(trimmed)?.groupValues?.get(1)
                        val proxyMatch = Regex(""""(?:proxypass|token)"\s*:\s*"(eyJ[^"]+)"""").find(trimmed)
                        if (proxyMatch != null && sessionTokenHex.isNullOrBlank()) {
                            return@runCatching proxyMatch.groupValues[1]
                        }
                    }
                    trimmed.matches(Regex("""^[0-9a-fA-F]{64}$""")) -> {
                        sessionTokenHex = trimmed
                    }
                    trimmed.startsWith("eyJ") && trimmed.count { it == '.' } == 2 -> {
                        return@runCatching trimmed
                    }
                    else -> {
                        oauthAccessToken = trimmed.removePrefix("Bearer ").removePrefix("bearer ").trim()
                    }
                }

                val client = buildClient(socksHost, socksPort, timeoutSec = 15)

                val sessHex = sessionTokenHex
                if (oauthAccessToken.isNullOrBlank() && !sessHex.isNullOrBlank()) {
                    oauthAccessToken = runCatching { exchangeSessionTokenForOAuth(client, sessHex) }.getOrNull()
                }

                val oauthTok = oauthAccessToken
                val proxyPassJwt = if (!oauthTok.isNullOrBlank()) {
                    runCatching { requestGuardianProxyPass(client, oauthTok) }.getOrNull()
                } else null

                // Always preserve sessionTokenHex if available so FirefoxVpnExitTunnel.start() can mint/renew
                // 10-minute Guardian ProxyPass JWTs through Aether Layer-1 on every Connect!
                when {
                    !sessHex.isNullOrBlank() && !proxyPassJwt.isNullOrBlank() ->
                        "fxa:$sessHex:${oauthTok.orEmpty()}:$proxyPassJwt"
                    !sessHex.isNullOrBlank() && !oauthTok.isNullOrBlank() ->
                        "fxa:$sessHex:$oauthTok"
                    !sessHex.isNullOrBlank() ->
                        sessHex
                    !proxyPassJwt.isNullOrBlank() ->
                        proxyPassJwt
                    !oauthTok.isNullOrBlank() ->
                        oauthTok
                    else ->
                        throw IllegalStateException("Could not extract valid sessionToken or ProxyPass from Firefox login")
                }
            }
        }

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
                val verifyPayload = """{"code":"$cleanCode"}"""

                val hawkHeader = buildHawkHeader(
                    method = "POST",
                    host = "api.accounts.firefox.com",
                    port = 443,
                    path = "/v1/session/verify_code",
                    sessionTokenHex = sessionTokenHex,
                    body = verifyPayload
                )
                val verifyReq = Request.Builder()
                    .url("$FXA_API_BASE/session/verify_code")
                    .header("Authorization", hawkHeader)
                    .header("User-Agent", FIREFOX_DESKTOP_UA)
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

                val oauthToken = runCatching { exchangeSessionTokenForOAuth(client, sessionTokenHex) }.getOrNull()
                val proxyPass = oauthToken?.let { runCatching { requestGuardianProxyPass(client, it) }.getOrNull() }
                when {
                    !proxyPass.isNullOrBlank() -> "fxa:$sessionTokenHex:${oauthToken.orEmpty()}:$proxyPass"
                    !oauthToken.isNullOrBlank() -> "fxa:$sessionTokenHex:$oauthToken"
                    else -> sessionTokenHex
                }
            }
        }

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

                var sessionTokenHex: String? = null
                var isVerified = true
                var lastLoginErr = "Login failed"

                for (base in listOf(FXA_OAUTH_BASE, FXA_API_BASE)) {
                    val loginReq = Request.Builder()
                        .url("$base/account/login?keys=true")
                        .header("User-Agent", FIREFOX_DESKTOP_UA)
                        .post(loginPayload.toRequestBody(mediaJson))
                        .build()

                    val ok = runCatching {
                        client.newCall(loginReq).execute().use { resp ->
                            val bodyStr = resp.body?.string().orEmpty()
                            if (resp.isSuccessful) {
                                val obj = jsonParser.parseToJsonElement(bodyStr).jsonObject
                                sessionTokenHex = obj["sessionToken"]?.jsonPrimitive?.content
                                isVerified = obj["verified"]?.jsonPrimitive?.booleanOrNull ?: true
                                !sessionTokenHex.isNullOrBlank()
                            } else {
                                val errObj = runCatching { jsonParser.parseToJsonElement(bodyStr).jsonObject }.getOrNull()
                                val errno = errObj?.get("errno")?.jsonPrimitive?.intOrNull
                                val msg = errObj?.get("message")?.jsonPrimitive?.content ?: "HTTP ${resp.code}"
                                lastLoginErr = "$msg (errno=${errno ?: resp.code})"
                                false
                            }
                        }
                    }.getOrDefault(false)
                    if (ok) break
                }

                val sess = sessionTokenHex
                    ?: throw IllegalStateException("FxA sign-in failed: $lastLoginErr (Recommended: use In-App WebView Login)")

                if (!isVerified) {
                    throw FxaVerificationRequiredException(
                        sessionTokenHex = sess,
                        message = "Firefox sent a 6-digit verification code to your email ($cleanEmail). Enter it below to complete sign-in."
                    )
                }

                val oauthToken = runCatching { exchangeSessionTokenForOAuth(client, sess) }.getOrNull()
                val proxyPass = oauthToken?.let { runCatching { requestGuardianProxyPass(client, it) }.getOrNull() }
                when {
                    !proxyPass.isNullOrBlank() -> "fxa:$sess:${oauthToken.orEmpty()}:$proxyPass"
                    !oauthToken.isNullOrBlank() -> "fxa:$sess:$oauthToken"
                    else -> sess
                }
            }
        }

        /**
         * Exchanges a 64-hex `sessionToken` for a VPN-scoped OAuth `access_token` using:
         *  1. PKCE Authorization Code Grant (`POST /v1/oauth/authorization` -> `POST /v1/token` / `/v1/oauth/token`)
         *     across both `oauth.accounts.firefox.com` and `api.accounts.firefox.com` with Hawk + payload hash.
         *  2. Direct Hawk-signed `POST /v1/oauth/token` fallback on `oauth.accounts.firefox.com` and `api.accounts.firefox.com`.
         */
        private fun exchangeSessionTokenForOAuth(client: OkHttpClient, sessionTokenHex: String): String {
            val mediaJson = "application/json; charset=utf-8".toMediaType()
            var lastErr = "OAuth exchange failed"
            val hosts = listOf(
                "oauth.accounts.firefox.com" to FXA_OAUTH_BASE,
                "api.accounts.firefox.com" to FXA_API_BASE
            )

            // Flow A: PKCE Authorization Code Grant
            for (clientId in FXA_CLIENT_IDS) {
                val verifierBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
                val codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(verifierBytes)
                val challengeBytes = MessageDigest.getInstance("SHA-256").digest(codeVerifier.toByteArray(Charsets.UTF_8))
                val codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes)
                val state = UUID.randomUUID().toString().replace("-", "")

                val authPayload = """{"client_id":"$clientId","scope":"$FXA_SCOPE_VPN","state":"$state","response_type":"code","access_type":"offline","code_challenge":"$codeChallenge","code_challenge_method":"S256"}"""

                for ((hostName, baseUrl) in hosts) {
                    val hawkHeader = buildHawkHeader(
                        method = "POST",
                        host = hostName,
                        port = 443,
                        path = "/v1/oauth/authorization",
                        sessionTokenHex = sessionTokenHex,
                        body = authPayload
                    )
                    val authReq = Request.Builder()
                        .url("$baseUrl/oauth/authorization")
                        .header("Authorization", hawkHeader)
                        .header("User-Agent", FIREFOX_DESKTOP_UA)
                        .post(authPayload.toRequestBody(mediaJson))
                        .build()

                    val code = runCatching {
                        client.newCall(authReq).execute().use { resp ->
                            val bodyStr = resp.body?.string().orEmpty()
                            if (resp.isSuccessful) {
                                jsonParser.parseToJsonElement(bodyStr).jsonObject["code"]?.jsonPrimitive?.content
                            } else {
                                lastErr = "auth HTTP ${resp.code}: $bodyStr"
                                null
                            }
                        }
                    }.getOrNull()

                    if (!code.isNullOrBlank()) {
                        val redeemPayload = """{"client_id":"$clientId","grant_type":"authorization_code","code":"$code","code_verifier":"$codeVerifier"}"""
                        val redeemUrls = listOf(
                            "$FXA_OAUTH_BASE/token",
                            "$FXA_OAUTH_BASE/oauth/token",
                            "$FXA_API_BASE/oauth/token",
                            "$FXA_API_BASE/token"
                        )
                        for (rUrl in redeemUrls) {
                            val rReq = Request.Builder()
                                .url(rUrl)
                                .header("User-Agent", FIREFOX_DESKTOP_UA)
                                .post(redeemPayload.toRequestBody(mediaJson))
                                .build()
                            val accessToken = runCatching {
                                client.newCall(rReq).execute().use { resp ->
                                    val bodyStr = resp.body?.string().orEmpty()
                                    if (resp.isSuccessful) {
                                        jsonParser.parseToJsonElement(bodyStr).jsonObject["access_token"]?.jsonPrimitive?.content
                                    } else null
                                }
                            }.getOrNull()
                            if (!accessToken.isNullOrBlank()) return accessToken
                        }
                    }
                }
            }

            // Flow B: Direct Hawk-signed POST /v1/oauth/token with payload hash
            for (clientId in FXA_CLIENT_IDS) {
                val payloads = listOf(
                    """{"client_id":"$clientId","grant_type":"fxa-credentials","scope":"$FXA_SCOPE_VPN","access_type":"offline","ttl":3600}""",
                    """{"client_id":"$clientId","scope":"$FXA_SCOPE_VPN","ttl":3600}"""
                )
                for ((hostName, baseUrl) in hosts) {
                    for (oauthPayload in payloads) {
                        val hawkHeader = buildHawkHeader(
                            method = "POST",
                            host = hostName,
                            port = 443,
                            path = "/v1/oauth/token",
                            sessionTokenHex = sessionTokenHex,
                            body = oauthPayload
                        )
                        val oauthReq = Request.Builder()
                            .url("$baseUrl/oauth/token")
                            .header("Authorization", hawkHeader)
                            .header("User-Agent", FIREFOX_DESKTOP_UA)
                            .post(oauthPayload.toRequestBody(mediaJson))
                            .build()

                        val token = runCatching {
                            client.newCall(oauthReq).execute().use { resp ->
                                val bodyStr = resp.body?.string().orEmpty()
                                if (resp.isSuccessful) {
                                    jsonParser.parseToJsonElement(bodyStr).jsonObject["access_token"]?.jsonPrimitive?.content
                                } else {
                                    lastErr = "token HTTP ${resp.code}: $bodyStr"
                                    null
                                }
                            }
                        }.getOrNull()

                        if (!token.isNullOrBlank()) return token
                    }
                }
            }

            throw IllegalStateException("FxA OAuth token exchange failed ($lastErr)")
        }

        private fun requestGuardianProxyPass(client: OkHttpClient, fxaAccessToken: String): String? {
            val req = Request.Builder().url("$GUARDIAN_API_BASE/api/v1/fpn/token")
                .header("Authorization", "Bearer $fxaAccessToken").header("User-Agent", MOZILLA_VPN_UA)
                .header("Accept", "application/json").build()
            return client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) throw IllegalStateException("Firefox VPN authorization rejected (HTTP ${resp.code})")
                val obj = jsonParser.parseToJsonElement(resp.body?.string() ?: return@use null).jsonObject
                (obj["token"] ?: obj["proxypass"] ?: obj["proxy_pass"])?.jsonPrimitive?.content
            }
        }

        private fun buildClient(socksHost: String, socksPort: Int, timeoutSec: Long, requirePrimary: Boolean = false): OkHttpClient {
            val builder = OkHttpClient.Builder().callTimeout(timeoutSec, TimeUnit.SECONDS)
            // OkHttp uses an unresolved destination when the route is SOCKS. In a running chain,
            // never fall back to a direct account / discovery request when layer 1 disappears.
            if (requirePrimary || (socksPort > 0 && portListening(socksHost, socksPort))) {
                builder.proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort)))
            }
            return builder.build()
        }

        private fun deriveFxaAuthPw(email: String, password: String): String {
            // Official FxA quickStretchPW salt includes "PW"
            val salt = "identity.mozilla.com/picl/v1/quickStretchPW:$email".toByteArray(Charsets.UTF_8)
            val spec = PBEKeySpec(password.toCharArray(), salt, 1000, 256)
            val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
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
            sessionTokenHex: String,
            contentType: String = "application/json",
            body: String? = null
        ): String {
            val tokenBytes = sessionTokenHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val prk = hmacSha256(ByteArray(32), tokenBytes)
            val info = "identity.mozilla.com/picl/v1/sessionToken".toByteArray(Charsets.UTF_8)
            val t1 = hmacSha256(prk, info + byteArrayOf(0x01))
            val t2 = hmacSha256(prk, t1 + info + byteArrayOf(0x02))
            val derived = t1 + t2

            val tokenIdHex = derived.sliceArray(0 until 32).joinToString("") { "%02x".format(it) }
            val reqHmacKey = derived.sliceArray(32 until 64)

            val ts = System.currentTimeMillis() / 1000L
            val nonce = UUID.randomUUID().toString().replace("-", "").take(12)

            val payloadHash = if (!body.isNullOrEmpty()) {
                val payloadNorm = "hawk.1.payload\n${contentType.lowercase()}\n$body\n"
                val digest = MessageDigest.getInstance("SHA-256").digest(payloadNorm.toByteArray(Charsets.UTF_8))
                Base64.getEncoder().encodeToString(digest)
            } else ""

            val normalized = "hawk.1.header\n$ts\n$nonce\n${method.uppercase()}\n$path\n${host.lowercase()}\n$port\n$payloadHash\n\n"
            val macBytes = hmacSha256(reqHmacKey, normalized.toByteArray(Charsets.UTF_8))
            val macB64 = Base64.getEncoder().encodeToString(macBytes)

            return if (payloadHash.isNotEmpty()) {
                """Hawk id="$tokenIdHex", ts="$ts", nonce="$nonce", hash="$payloadHash", mac="$macB64""""
            } else {
                """Hawk id="$tokenIdHex", ts="$ts", nonce="$nonce", mac="$macB64""""
            }
        }

        private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            return mac.doFinal(data)
        }

        private fun isJwtFresh(jwt: String, minRemainingSec: Long): Boolean {
            val parts = jwt.trim().split(".")
            if (parts.size != 3) return false
            return try {
                val payloadJson = String(Base64.getUrlDecoder().decode(parts[1]), Charsets.UTF_8)
                val exp = Regex(""""exp"\s*:\s*(\d+)""").find(payloadJson)?.groupValues?.get(1)?.toLongOrNull()
                    ?: return true
                val nowSec = System.currentTimeMillis() / 1000L
                exp - nowSec > minRemainingSec
            } catch (_: Exception) {
                false
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
    }
}
