package io.github.immaghzbad.aetherst.shared.net

import java.io.Closeable
import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Semaphore
import kotlin.concurrent.thread

/** Interop shim for the bundled sing v0.5.1 SOCKS client and Aether's RFC 1928 relay.
 * sing passes the WG peer to ClientHandshake5(UDP_ASSOCIATE). Aether's expected_udp_source()
 * correctly treats that field as the *client* IP and drops every datagram from 127.0.0.1.
 * Translate ONLY the TCP association request. The peer stays in the UDP packet headers; sing-box
 * exchanges encrypted datagrams directly with Aether's returned relay (no Kotlin packet pump).
 */
internal class WireGuardUdpControl(private val primary: InetSocketAddress) : Closeable {
    private val server = ServerSocket(0, 4, InetAddress.getByName("127.0.0.1"))
    val port = server.localPort
    private val slots = Semaphore(4)
    private val sockets = ConcurrentHashMap.newKeySet<Socket>()
    private val acceptor = thread(isDaemon = true, name = "WgExit-associate") {
        while (!server.isClosed) {
            val client = runCatching { server.accept() }.getOrNull() ?: break
            if (!slots.tryAcquire()) { client.close(); continue }
            val upstream = Socket(Proxy.NO_PROXY)
            sockets.add(client); sockets.add(upstream)
            thread(isDaemon = true, name = "WgExit-control") {
                try {
                    associate(client, upstream)
                } catch (_: Exception) {
                    // A rejected/closed control channel never enables a direct fallback.
                } finally {
                    upstream.close(); client.close()
                    sockets.remove(upstream); sockets.remove(client); slots.release()
                }
            }
        }
    }

    private fun associate(client: Socket, upstream: Socket) {
        client.soTimeout = 5000
        val input = DataInputStream(client.getInputStream())
        val reply = client.getOutputStream()
        require(input.readUnsignedByte() == 5)
        val methods = ByteArray(input.readUnsignedByte()).also(input::readFully)
        if (0.toByte() !in methods) { reply.write(byteArrayOf(5, -1)); return }
        reply.write(byteArrayOf(5, 0))
        require(input.readUnsignedByte() == 5)
        if (input.readUnsignedByte() != 3) { reply.write(byteArrayOf(5, 7, 0, 1, 0, 0, 0, 0, 0, 0)); return }
        require(input.readUnsignedByte() == 0)
        val size = when (input.readUnsignedByte()) { 1 -> 4; 4 -> 16; 3 -> input.readUnsignedByte(); else -> return }
        input.readFully(ByteArray(size + 2)) // Never advertise the remote peer as our client's source.

        upstream.connect(primary, 5000)
        upstream.soTimeout = 5000
        val control = DataInputStream(upstream.getInputStream())
        val request = upstream.getOutputStream()
        request.write(byteArrayOf(5, 1, 0))
        require(control.readUnsignedShort() == 0x0500)
        request.write(byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)) // unknown local UDP endpoint: RFC 1928 §7
        require(control.readUnsignedByte() == 5)
        val status = control.readUnsignedByte()
        if (status != 0) { reply.write(byteArrayOf(5, status.toByte(), 0, 1, 0, 0, 0, 0, 0, 0)); return }
        require(control.readUnsignedByte() == 0)
        val length = when (control.readUnsignedByte()) { 1 -> 4; 4 -> 16; else -> return }
        val bound = InetAddress.getByAddress(ByteArray(length).also(control::readFully))
        val relay = if (bound.isAnyLocalAddress) upstream.inetAddress else bound
        val relayPort = control.readUnsignedShort()
        require(relayPort > 0 && (relay.isLoopbackAddress || relay == upstream.inetAddress))
        reply.write(byteArrayOf(5, 0, 0, if (relay.address.size == 4) 1 else 4) + relay.address +
            byteArrayOf((relayPort ushr 8).toByte(), relayPort.toByte()))

        // RFC 1928: the association is scoped to the lifetime of both TCP control connections.
        client.soTimeout = 0; upstream.soTimeout = 0
        thread(isDaemon = true, name = "WgExit-primary-control") {
            try { control.read() } catch (_: Exception) {} finally { runCatching { client.close() } }
        }
        input.read()
    }

    override fun close() {
        server.close()
        try { acceptor.join(1000) } finally { sockets.forEach { runCatching { it.close() } } }
    }
}
