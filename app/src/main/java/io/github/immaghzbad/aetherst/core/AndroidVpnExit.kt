package io.github.immaghzbad.aetherst.core

import android.content.Context
import io.github.immaghzbad.aetherst.shared.data.ActiveProxyProvider
import io.github.immaghzbad.aetherst.shared.model.AetherConfig
import io.github.immaghzbad.aetherst.shared.model.ExitNodeMode
import io.github.immaghzbad.aetherst.shared.net.FirefoxVpnExitTunnel
import io.github.immaghzbad.aetherst.shared.net.WireGuardExitTunnel

/** Used by both the device TUN and proxy-only mode. Publish a port only after end-to-end verification. */
internal class AndroidVpnExit(private val context: Context) {
    private var wg: WireGuardExitTunnel? = null
    private var firefox: FirefoxVpnExitTunnel? = null

    @Synchronized
    fun start(config: AetherConfig, refresh: Boolean): Int {
        val primaryPort = config.socksPort.toIntOrNull() ?: 2021
        return when (config.exitNodeMode) {
            ExitNodeMode.CUSTOM_WG -> {
                wg?.let { if (!refresh && it.isHealthy()) return it.localListenPort }
                stop()
                val profile = if (config.customWgAutoSelect) WireGuardExitTunnel.selectFastestProfile(config.customWgProfiles, config.customWgConfig)
                    else config.customWgConfig
                val tunnel = WireGuardExitTunnel(profile, BinaryManager.prepareSingBoxBinary(context)?.absolutePath,
                    context.filesDir.absolutePath, primarySocksPort = primaryPort)
                check(tunnel.start()) { tunnel.lastErrorMessage ?: "WireGuard exit unavailable" }
                wg = tunnel
                tunnel.localListenPort.also { ActiveProxyProvider.customWgPort = it }
            }
            ExitNodeMode.FIREFOX_VPN -> {
                firefox?.let { if (!refresh && it.isHealthy()) return it.localListenPort }
                stop()
                val tunnel = FirefoxVpnExitTunnel(config.firefoxVpnToken, config.firefoxVpnCountry,
                    primarySocksPort = primaryPort, localListenPort = config.firefoxVpnPort)
                check(tunnel.start()) { tunnel.lastErrorMessage ?: "Firefox exit unavailable" }
                firefox = tunnel
                tunnel.localListenPort.also { ActiveProxyProvider.firefoxVpnPort = it }
            }
            else -> error("Not a VPN exit mode")
        }
    }

    @Synchronized
    fun stop() {
        wg?.let { ActiveProxyProvider.customWgPort = null; it.stop() }; wg = null
        firefox?.let { ActiveProxyProvider.firefoxVpnPort = null; it.stop() }; firefox = null
    }
}
