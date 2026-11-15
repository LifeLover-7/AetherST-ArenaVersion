package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.model.CustomWireGuardConfig
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Secondary WireGuard Exit Tunnel Manager.
 * WireGuard operates strictly over raw UDP (port 51820). Because censorship circumvention
 * tunnels (MASQUE / WARP) exit as local TCP SOCKS5 proxies, and the Iranian DPI filters
 * direct UDP packets to foreign WireGuard endpoints, raw WireGuard cannot establish handshakes
 * without a native UDP-in-TCP wrapper on the remote server.
 *
 * To prevent blackholing user traffic and presenting a deceptive fake connection,
 * this tunnel fails fast and allows the ConnectionController to cleanly route
 * through the working primary tunnel and advise the user to use Psiphon or SOCKS5.
 */
class WireGuardExitTunnel(
    private val config: CustomWireGuardConfig,
    private val binaryPath: String? = null,
    private val workingDir: String? = null,
    private val primarySocksHost: String = "127.0.0.1",
    private val primarySocksPort: Int = 2021,
    val localListenPort: Int = 10805
) {
    private val isRunning = AtomicBoolean(false)

    fun start(): Boolean {
        LogRepository.w(
            "[WgExit] WireGuard (UDP port 51820) cannot be chained over TCP SOCKS5 proxies without remote UDP-tunneling support. Falling back to primary tunnel to keep connection alive.",
            "WireGuard"
        )
        isRunning.set(false)
        return false
    }

    fun stop() {
        isRunning.set(false)
    }

    fun isConnected(): Boolean = false
}
