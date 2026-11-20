package io.github.immaghzbad.aetherst.shared.model

import kotlinx.serialization.Serializable

@Serializable
data class CustomWireGuardConfig(
    val id: String = "",
    val name: String = "",
    val rawConfig: String = "",
    val privateKey: String = "",
    val addressV4: String = "",
    val addressV6: String = "",
    val dns: String = "1.1.1.1",
    val mtu: Int = 1280,
    val publicKey: String = "",
    val endpoint: String = "",
    val allowedIpsV4: String = "0.0.0.0/0",
    val allowedIpsV6: String = "::/0",
    val persistentKeepalive: Int = 25,
    val lastPingMs: Long = -1L,
    val preSharedKey: String = ""
) {
    fun isValid(): Boolean = privateKey.isNotBlank() && publicKey.isNotBlank() && endpoint.isNotBlank()
    val displayName: String get() = name.ifBlank { endpoint.ifBlank { "Proton WireGuard" } }
    val dnsServers: List<String> get() = dns.split(",").map { it.trim() }.filter { it.isNotEmpty() }
    fun filterForPrimarySupport(supportsIpv6: Boolean): CustomWireGuardConfig {
        return if (supportsIpv6) {
            this
        } else {
            copy(addressV6 = "", allowedIpsV6 = "")
        }
    }
}
