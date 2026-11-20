package io.github.immaghzbad.aetherst.core

import android.net.VpnService
import io.github.immaghzbad.aetherst.shared.model.AetherConfig
import io.github.immaghzbad.aetherst.shared.model.ExitNodeMode
import io.github.immaghzbad.aetherst.shared.model.TunnelEngine

/** Android's link and the userspace WG interface are different links. In particular the
 * 1120-byte MTU of WG-inside-WG must NOT be used on a device TUN carrying IPv6. */
internal class DeviceTun(config: AetherConfig) {
    private val ipv6 = config.ipv6Leak || (config.exitNodeMode == ExitNodeMode.CUSTOM_WG &&
        config.customWgConfig.allowedIpsV6.isNotBlank())
    val mtu = if (ipv6) 1280 else config.mtu.coerceIn(576, 1280)

    fun configure(builder: VpnService.Builder, engine: TunnelEngine) {
        builder.setMtu(mtu).addAddress("198.18.0.1", 24).addRoute("0.0.0.0", 0)
        if (ipv6) builder.addAddress("fd00::1", 120).addRoute("::", 0)
        if (engine == TunnelEngine.HEV_TUN2SOCKS) {
            builder.addDnsServer(HevTun2SocksConfig.MAP_DNS_ADDRESS)
        } else {
            builder.addDnsServer("1.1.1.1").addDnsServer("8.8.8.8")
            if (ipv6) builder.addDnsServer("2606:4700:4700::1111").addDnsServer("2001:4860:4860::8888")
        }
    }
}
