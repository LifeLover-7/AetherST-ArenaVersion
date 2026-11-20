package io.github.immaghzbad.aetherst.core

import java.io.DataInputStream
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket

internal enum class PrimarySignal { SCANNING, VALIDATING, SERVING, LOST, FATAL }

/** Aether binds before provisioning and serves *after* choosing the final stack. An
 * inner/outer validation line, a TCP accept backlog, or a Tor helper is not that stack. */
internal fun primarySignal(line: String, bind: String): PrimarySignal? {
    val text = line.lowercase().trim()
    return when {
        text.startsWith("error:") || "panicked at" in text || "[fatal]" in text -> PrimarySignal.FATAL
        "tunnel ended" in text || "tunnel closed" in text || "tunnel exited" in text ||
            "tunnel lost" in text || "all gateways failed" in text -> PrimarySignal.LOST
        text.endsWith("socks5 server listening on $bind") -> PrimarySignal.SERVING
        "scanning" in text || "hunting for" in text -> PrimarySignal.SCANNING
        "validating" in text || "tunnel validated" in text || "establishing" in text ||
            "gool ready:" in text || "masque-in-masque ready:" in text || "trying inner" in text ||
            "connect-ip established" in text || "connect-ip status: 200" in text -> PrimarySignal.VALIDATING
        else -> null
    }
}

internal fun primarySocksResponds(port: Int, timeoutMs: Int = 3000): Boolean = runCatching {
    Socket(Proxy.NO_PROXY).use { socket ->
        socket.connect(InetSocketAddress("127.0.0.1", port), timeoutMs)
        socket.soTimeout = timeoutMs
        socket.getOutputStream().write(byteArrayOf(5, 1, 0))
        DataInputStream(socket.getInputStream()).readUnsignedShort() == 0x0500
    }
}.getOrDefault(false)
