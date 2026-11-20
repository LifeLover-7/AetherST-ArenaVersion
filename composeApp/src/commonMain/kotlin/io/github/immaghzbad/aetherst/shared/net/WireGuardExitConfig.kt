package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.model.CustomWireGuardConfig
import kotlinx.serialization.json.*
import java.util.Base64

/** Outbound schema of the bundled sing-box (1.10.7). In particular, WG supports a SOCKS detour without GSO. */
internal fun wireGuardExitConfig(cfg: CustomWireGuardConfig, host: String, port: Int, listen: Int, udpControlPort: Int): String {
    val peer = HostPort.parse(cfg.endpoint)
    require(port in 1..65535 && udpControlPort in 1..65535 && listen in 2..65535 &&
        listOf(port, udpControlPort, listen, listen - 1).distinct().size == 4) { "Invalid or overlapping proxy ports" }
    fun key(value: String, label: String) = value.trim().also {
        require(runCatching { Base64.getDecoder().decode(it).size == 32 }.getOrDefault(false)) { "Invalid WireGuard $label" }
    }
    fun prefixes(v4: String, v6: String): List<String> = (v4.split(',') + v6.split(','))
        .map(String::trim).filter(String::isNotEmpty).map {
            val ip = it.substringBefore('/')
            val bits = if (':' in ip) 128 else 32
            val prefix = it.substringAfter('/', bits.toString()).toIntOrNull()
            require(isIpLiteral(ip) && prefix != null && prefix in 0..bits) { "Invalid WireGuard address or prefix" }
            "$ip/$prefix"
        }
    val addresses = prefixes(cfg.addressV4, cfg.addressV6)
    require(addresses.isNotEmpty()) { "WireGuard profile has no interface address" }
    val allowed = prefixes(cfg.allowedIpsV4, cfg.allowedIpsV6)
    require(allowed.isNotEmpty()) { "WireGuard peer has no AllowedIPs" }
    val resolver = cfg.dnsServers.firstOrNull(::isIpLiteral) ?: "1.1.1.1"
    return buildJsonObject {
        putJsonObject("log") { put("level", "warn") }
        putJsonArray("inbounds") {
            for ((type, bind) in listOf("socks" to listen, "http" to listen - 1)) addJsonObject {
                put("type", type); put("listen", "127.0.0.1"); put("listen_port", bind)
            }
        }
        putJsonArray("outbounds") {
            addJsonObject {
                put("type", "socks"); put("tag", "primary-udp"); put("version", "5")
                put("server", "127.0.0.1"); put("server_port", udpControlPort)
            }
            addJsonObject {
                put("type", "wireguard"); put("tag", "wg-exit"); put("detour", "primary-udp")
                put("private_key", key(cfg.privateKey, "private key"))
                putJsonArray("local_address") { addresses.forEach { add(it) } }
                put("mtu", cfg.mtu.coerceIn(576, WireGuardExitTunnel.INNER_WG_SAFE_MTU))
                putJsonArray("peers") {
                    addJsonObject {
                        put("server", peer.host); put("server_port", peer.port)
                        put("public_key", key(cfg.publicKey, "peer public key"))
                        if (cfg.preSharedKey.isNotBlank()) put("pre_shared_key", key(cfg.preSharedKey, "preshared key"))
                        putJsonArray("allowed_ips") { allowed.forEach { add(it) } }
                    }
                }
            }
            if (!isIpLiteral(peer.host)) addJsonObject {
                put("type", "socks"); put("tag", "primary-dns"); put("version", "5")
                put("server", host); put("server_port", port)
            }
        }
        putJsonObject("dns") {
            putJsonArray("servers") {
                addJsonObject {
                    put("tag", "inner-dns"); put("address", if (':' in resolver) "udp://[$resolver]" else "udp://$resolver")
                    put("detour", "wg-exit")
                }
                if (!isIpLiteral(peer.host)) addJsonObject {
                    put("tag", "bootstrap"); put("address", "tcp://1.1.1.1"); put("detour", "primary-dns")
                }
            }
            // A hostname peer cannot be bootstrapped using DNS *inside* that same not-yet-established peer.
            if (!isIpLiteral(peer.host)) putJsonArray("rules") {
                addJsonObject { put("domain", peer.host); put("server", "bootstrap") }
            }
            put("final", "inner-dns")
            if (cfg.addressV6.isBlank()) put("strategy", "prefer_ipv4")
        }
        putJsonObject("route") { put("final", "wg-exit") }
    }.toString()
}
