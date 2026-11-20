package io.github.immaghzbad.aetherst.shared.data

import io.github.immaghzbad.aetherst.shared.model.ExitNodeMode

object ActiveProxyProvider {
    @Volatile var psiphonProxyUrl: String? = null
    @Volatile var torProxyUrl: String? = null
    @Volatile var customWgPort: Int? = null
    @Volatile var firefoxVpnPort: Int? = null

    fun vpnExitPort(mode: ExitNodeMode): Int? = when (mode) {
        ExitNodeMode.CUSTOM_WG -> customWgPort
        ExitNodeMode.FIREFOX_VPN -> firefoxVpnPort
        else -> null
    }
}
