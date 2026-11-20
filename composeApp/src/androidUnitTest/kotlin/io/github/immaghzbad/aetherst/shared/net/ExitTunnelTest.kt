package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.util.WireGuardConfigParser
import kotlinx.serialization.json.*
import okhttp3.internal.concurrent.TaskRunner
import okhttp3.internal.http2.Header
import okhttp3.internal.http2.Http2Connection
import okhttp3.internal.http2.Http2Stream
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.buffer
import okio.source
import org.junit.Test
import java.io.Closeable
import java.io.DataInputStream
import java.net.*
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread
import kotlin.test.*

internal fun loopbackListener() = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
internal fun freePortPair(): Int {
    repeat(20) {
        loopbackListener().use { s ->
            if (runCatching { ServerSocket(s.localPort - 1, 1, s.inetAddress).close() }.isSuccess) return s.localPort
        }
    }
    error("No free consecutive ports")
}

class ExitTunnelTest {
    @Test fun wireGuardUsesOneUdpDetourAndTheImportedProfile() {
        val key = Base64.getEncoder().encodeToString(ByteArray(32) { it.toByte() })
        val cfg = WireGuardConfigParser.parse("""
            [Interface]
            PrivateKey = $key
            Address = 10.2.0.2/32, fd12::2/128
            DNS = 10.2.0.1
            [Peer]
            PublicKey = $key
            PresharedKey = $key
            Endpoint = wg.example.test:55123
            AllowedIPs = 0.0.0.0/0, ::/0
        """.trimIndent())
        val json = Json.parseToJsonElement(wireGuardExitConfig(cfg, "127.0.0.1", 3456, 10805, 3457)).jsonObject
        val (first, exit, dnsHop) = json.getValue("outbounds").jsonArray.map { it.jsonObject }
        assertEquals("socks", first.getValue("type").jsonPrimitive.content)
        assertEquals(3457, first.getValue("server_port").jsonPrimitive.int)
        assertEquals(3456, dnsHop.getValue("server_port").jsonPrimitive.int)
        assertEquals(first["tag"], exit["detour"])
        assertEquals(exit["tag"], json.getValue("route").jsonObject["final"])
        val peer = exit.getValue("peers").jsonArray.single().jsonObject
        assertEquals(55123, peer.getValue("server_port").jsonPrimitive.int)
        assertEquals(key, peer.getValue("pre_shared_key").jsonPrimitive.content)
        assertEquals(listOf("10.2.0.2/32", "fd12::2/128"), exit.getValue("local_address").jsonArray.map { it.jsonPrimitive.content })
        val dns = json.getValue("dns").jsonObject
        assertEquals("wg.example.test", dns.getValue("rules").jsonArray.single().jsonObject.getValue("domain").jsonPrimitive.content)
        assertFailsWith<IllegalArgumentException> { wireGuardExitConfig(cfg.copy(privateKey = "bad"), "127.0.0.1", 2021, 10805, 3457) }
        assertFailsWith<IllegalArgumentException> { wireGuardExitConfig(cfg, "127.0.0.1", 10804, 10805, 3457) }
        assertEquals(HostPort("2001:db8::1", 1234), HostPort.parse("[2001:db8::1]:1234"))
    }

    // Fake SOCKS5 first hop serving a TLS edge in-place. No DNS, provider accounts or external network.
    private class Edge(val alpn: String, val status: Int) : Closeable {
        val listener = loopbackListener()
        val primary = Proxy(Proxy.Type.SOCKS, InetSocketAddress(listener.inetAddress, listener.localPort))
        val cert = HeldCertificate.Builder().addSubjectAlternativeName("edge.test").build()
        val serverTls = HandshakeCertificates.Builder().heldCertificate(cert).build()
        val trust = HandshakeCertificates.Builder().addTrustedCertificate(cert.certificate).build()
        val opened = CopyOnWriteArrayList<String>()
        private val sockets = CopyOnWriteArrayList<Socket>()
        init {
            thread(isDaemon = true) {
                while (!listener.isClosed) {
                    val socket = runCatching { listener.accept() }.getOrNull() ?: break
                    sockets += socket
                    thread(isDaemon = true) { runCatching { accept(socket) }.onFailure { socket.close() } }
                }
            }
        }
        private fun accept(s: Socket) {
            val data = DataInputStream(s.inputStream)
            check(data.read() == 5); data.readFully(ByteArray(data.readUnsignedByte()))
            s.outputStream.write(byteArrayOf(5, 0))
            check(data.readInt() == 0x05010003)
            val host = ByteArray(data.readUnsignedByte()); data.readFully(host)
            check(host.decodeToString() == "edge.test" && data.readUnsignedShort() == 443)
            s.outputStream.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0, 0))
            val ssl = serverTls.sslSocketFactory().createSocket(s, "edge.test", 443, true) as SSLSocket
            ssl.useClientMode = false
            ssl.sslParameters = ssl.sslParameters.apply { applicationProtocols = if (alpn.isEmpty()) emptyArray() else arrayOf(alpn) }
            ssl.startHandshake()
            if (alpn == "h2") {
                Http2Connection.Builder(false, TaskRunner.INSTANCE).socket(ssl).listener(object : Http2Connection.Listener() {
                    override fun onStream(stream: Http2Stream) {
                        val h = stream.takeHeaders()
                        check(h[":method"] == "CONNECT" && h[":path"] == null && h["proxy-authorization"] == "Bearer fixture")
                        opened += h[":authority"].orEmpty()
                        stream.writeHeaders(listOf(Header(":status", "$status")), status != 200, true)
                        if (status == 200) stream.getSink().buffer().use { it.writeAll(stream.getSource()) }
                    }
                }).build().start()
            } else ssl.use {
                val source = ssl.source().buffer()
                val request = source.readUtf8LineStrict(); check(request.startsWith("CONNECT "))
                val headers = generateSequence { source.readUtf8LineStrict().takeIf(String::isNotEmpty) }.toList()
                check("Proxy-Authorization: Bearer fixture" in headers)
                opened += request.split(' ')[1]
                ssl.outputStream.write("HTTP/1.1 $status Test\r\n\r\n".toByteArray()); ssl.outputStream.flush()
                if (status == 200) source.inputStream().copyTo(ssl.outputStream)
            }
        }
        override fun close() { listener.close(); sockets.forEach { it.close() } }
    }

    private val payload = ByteArray(256 * 1024) { (it % 123).toByte() }
    private fun roundTrip(port: Int): String? = runCatching {
        Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port))).use { socket ->
            socket.soTimeout = 6_000
            socket.connect(InetSocketAddress.createUnresolved("origin.test", 443), 6_000)
            socket.outputStream.write(payload); socket.shutdownOutput()
            assertContentEquals(payload, socket.inputStream.readBytes())
        }
        "192.0.2.7"
    }.getOrNull()

    private fun exercise(protocol: String, status: Int, trusted: Boolean = true) {
        Edge(protocol, status).use { edge ->
            val port = freePortPair()
            val tunnel = FirefoxVpnExitTunnel(edge.primary, port, { "fixture" },
                { listOf(FirefoxVpnExitTunnel.EdgeEndpoint("edge.test", 443, "US")) }, ::roundTrip,
                (if (trusted) edge.trust else HandshakeCertificates.Builder().build()).sslSocketFactory())
            try {
                if (status == 200 && trusted) {
                    assertTrue(tunnel.start(), tunnel.lastErrorMessage); assertTrue(tunnel.isHealthy())
                    assertEquals("192.0.2.7", tunnel.verifiedExitIp)
                    assertNotNull(roundTrip(port)); assertEquals(listOf("origin.test:443", "origin.test:443"), edge.opened)
                    tunnel.stop(); assertNull(tunnel.verifiedExitIp)
                    assertTrue(tunnel.start(), "Could not rebind the same verified exit: ${tunnel.lastErrorMessage}")
                } else {
                    assertFalse(tunnel.start()); assertNull(tunnel.verifiedExitIp)
                    if (trusted) assertContains(tunnel.lastErrorMessage.orEmpty(), "$status") else assertTrue(edge.opened.isEmpty())
                }
            } finally { tunnel.stop() }
            assertFalse(portListening("127.0.0.1", port), "SOCKS port $port still open")
            assertFalse(portListening("127.0.0.1", port - 1), "HTTP port ${port-1} still open")
        }
    }
    @Test(timeout = 25000) fun firefoxH2RoundTripWhileStartIsWaiting() = exercise("h2", 200)
    @Test(timeout = 25000) fun firefoxH1RoundTripAndSecondSocket() = exercise("http/1.1", 200)
    @Test(timeout = 25000) fun noAlpnUsesClassicHttp11() = exercise("", 200)
    @Test(timeout = 15000) fun rejectedConnectIsNotReady() = exercise("h2", 407)
    @Test(timeout = 15000) fun untrustedEdgeNeverReceivesPass() = exercise("http/1.1", 200, trusted = false)
}
