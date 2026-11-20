package io.github.immaghzbad.aetherst.shared.net

import okhttp3.internal.concurrent.TaskRunner
import okhttp3.internal.http2.ErrorCode
import okhttp3.internal.http2.Header
import okhttp3.internal.http2.Http2Connection
import okio.buffer
import okio.source
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.concurrent.TimeUnit
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

internal class ConnectRejected(val status: Int) : IOException("Firefox proxy rejected CONNECT (HTTP $status)")

internal class ConnectPipe(val input: InputStream, val output: OutputStream, val finishOutput: () -> Unit,
                           private val release: () -> Unit) : Closeable {
    override fun close() = release()
}

/** OkHttp's public Call API is not a bidirectional classic CONNECT (it adds :scheme and :path).
 * Keep the version-specific HTTP/2 codec adapter here; OkHttp 4.12 handles HPACK, window updates,
 * GOAWAY, and concurrent stream IDs. HTTP/1.1 requires one authenticated TLS connection per tunnel. */
internal class FirefoxConnectSession(
    private val edge: HostPort, private val primary: Proxy, private val tlsFactory: SSLSocketFactory,
    private val pass: () -> String
) : Closeable {
    private val lock = Any()
    @Volatile private var closed = false
    private val sockets = mutableSetOf<Socket>()
    private var spare: SSLSocket? = null
    private val h2: Http2Connection?
    val protocol: String

    init {
        val tls = dialTls(listOf("h2", "http/1.1"))
        try {
            protocol = runCatching { tls.applicationProtocol }.getOrNull().orEmpty().ifBlank { "http/1.1" }
            h2 = when (protocol) {
                "h2" -> Http2Connection.Builder(true, TaskRunner.INSTANCE).socket(tls, edge.host).build().apply { start() }
                "http/1.1" -> { spare = tls; null }
                else -> throw IOException("Unsupported proxy ALPN")
            }
        } catch (e: Exception) { discard(tls); throw e }
    }

    private fun dialTls(protocols: List<String>): SSLSocket {
        val raw = Socket(primary)
        try {
            raw.connect(InetSocketAddress.createUnresolved(edge.host, edge.port), 8_000)
            val ssl = tlsFactory.createSocket(raw, edge.host, edge.port, true) as SSLSocket
            ssl.sslParameters = ssl.sslParameters.apply {
                endpointIdentificationAlgorithm = "HTTPS"
                serverNames = listOf(SNIHostName(edge.host))
                // Android 8/9 do not expose the JDK ALPN API. Negotiate HTTP/1.1 on those devices.
                runCatching { applicationProtocols = protocols.toTypedArray() }
            }
            ssl.soTimeout = 8_000
            ssl.startHandshake()
            ssl.soTimeout = 0
            synchronized(lock) { check(!closed); sockets.add(ssl) }
            return ssl
        } catch (e: Exception) { raw.close(); throw e }
    }

    fun isAlive() = !closed && (h2?.isHealthy(System.nanoTime()) ?: true)

    fun open(host: String, port: Int): ConnectPipe {
        val authority = if (':' in host) "[$host]:$port" else "$host:$port"
        HostPort.parse(authority) // including CR/LF validation for the HTTP/1.1 request line
        val token = pass()
        check(token.isNotEmpty() && token.all { it.code in 33..126 }) { "Invalid proxy authorization" }
        val auth = "Bearer $token"
        val conn = h2
        if (conn != null) {
            val stream = conn.newStream(listOf(Header(":method", "CONNECT"), Header(":authority", authority),
                Header("proxy-authorization", auth)), true)
            try {
                stream.readTimeout().timeout(10, TimeUnit.SECONDS)
                stream.writeTimeout().timeout(30, TimeUnit.SECONDS)
                conn.flush() // No DATA until CONNECT has been accepted.
                val status = stream.takeHeaders()[":status"]?.toIntOrNull() ?: throw IOException("Missing CONNECT status")
                if (status !in 200..299) throw ConnectRejected(status)
                stream.readTimeout().clearTimeout()
                val output = stream.getSink().buffer().outputStream()
                return ConnectPipe(stream.getSource().buffer().inputStream(), output, { output.close() }) {
                    stream.closeLater(ErrorCode.CANCEL)
                }
            } catch (e: Exception) { stream.closeLater(ErrorCode.CANCEL); throw e }
        }
        val tls = synchronized(lock) { check(!closed); spare.also { spare = null } } ?: dialTls(listOf("http/1.1"))
        try {
            tls.soTimeout = 10_000
            val output = tls.outputStream
            output.write("CONNECT $authority HTTP/1.1\r\nHost: $authority\r\nProxy-Authorization: $auth\r\n\r\n".toByteArray(Charsets.US_ASCII))
            output.flush()
            val source = tls.source().buffer()
            val status = source.readUtf8LineStrict(4096).split(' ').let {
                if (it.first() in setOf("HTTP/1.0", "HTTP/1.1")) it.getOrNull(1)?.toIntOrNull() else null
            } ?: throw IOException("Invalid proxy response")
            if (status !in 200..299) throw ConnectRejected(status)
            var remaining = 65536L
            while (true) {
                val line = source.readUtf8LineStrict(remaining)
                if (line.isEmpty()) break
                remaining -= line.length + 2
                if (remaining <= 0) throw IOException("Proxy headers too large")
            }
            tls.soTimeout = 0
            return ConnectPipe(source.inputStream(), output, { tls.shutdownOutput() }, { discard(tls) })
        } catch (e: Exception) { discard(tls); throw e }
    }

    private fun discard(socket: Socket) {
        synchronized(lock) { sockets.remove(socket) }
        runCatching { socket.close() }
    }

    override fun close() {
        val open = synchronized(lock) { closed = true; spare = null; sockets.toList().also { sockets.clear() } }
        open.forEach { runCatching { it.close() } }
        runCatching { h2?.close() }
    }
}
