package io.github.immaghzbad.aetherst.shared.net

import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URI
import java.util.concurrent.TimeUnit

internal data class HostPort(val host: String, val port: Int) {
    companion object {
        fun parse(value: String): HostPort {
            val uri = runCatching { URI("socks://${value.trim()}") }.getOrNull()
            require(uri?.host != null && uri.port in 1..65535 && uri.userInfo == null &&
                uri.rawPath.isNullOrEmpty() && uri.query == null && uri.fragment == null) {
                "Expected a host:port or [IPv6]:port endpoint"
            }
            return HostPort(uri.host.removeSurrounding("[", "]"), uri.port)
        }
    }
}

internal fun isIpLiteral(value: String): Boolean = if (':' in value) {
    value.matches(Regex("[0-9a-fA-F:.]+")) && runCatching { InetAddress.getByName(value) }.isSuccess
} else {
    val parts = value.split('.')
    parts.size == 4 && parts.all { it.length in 1..3 && it.all { c -> c in '0'..'9' } && it.toInt() in 0..255 }
}

internal fun portListening(host: String, port: Int): Boolean = runCatching {
    Socket(Proxy.NO_PROXY).use { it.connect(InetSocketAddress(host, port), 300) }
}.isSuccess

/** A successful TLS-authenticated request through the *exit listener*, never a local bind or core log line. */
internal class ExitIpProbe(port: Int) {
    private val client = OkHttpClient.Builder()
        .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port)))
        .callTimeout(6, TimeUnit.SECONDS)
        .followRedirects(false)
        .build()

    fun check(): String? {
        for (url in listOf("https://1.1.1.1/cdn-cgi/trace", "https://api.ipify.org/")) {
            val ip = runCatching {
                client.newCall(Request.Builder().url(url).build()).execute().use { response ->
                    if (!response.isSuccessful) return@use null
                    val text = response.peekBody(4096).string()
                    val value = if (url.endsWith("/trace")) {
                        text.lineSequence().firstOrNull { it.startsWith("ip=") }?.removePrefix("ip=")
                    } else text
                    value?.trim()?.takeIf(::isIpLiteral)
                }
            }.getOrNull()
            if (ip != null) return ip
        }
        return null
    }
}
