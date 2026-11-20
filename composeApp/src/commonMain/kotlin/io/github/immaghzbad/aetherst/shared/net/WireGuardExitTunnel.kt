package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.model.CustomWireGuardConfig
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** The only path is app -> this sing-box -> WireGuard peer, whose UDP socket is carried
 * by the already-running Aether SOCKS5 UDP ASSOCIATE. Never start a second WARP identity. */
class WireGuardExitTunnel(
    private val config: CustomWireGuardConfig,
    private val binaryPath: String? = null,
    private val workingDir: String? = null,
    private val primarySocksHost: String = "127.0.0.1",
    private val primarySocksPort: Int = 2021,
    val localListenPort: Int = 10805
) {
    @Volatile private var process: Process? = null
    @Volatile var verifiedExitIp: String? = null
        private set
    @Volatile var lastErrorMessage: String? = null
        private set

    @Synchronized
    fun start(): Boolean {
        if (isHealthy()) return true
        stop()
        lastErrorMessage = null
        return try {
            val json = wireGuardExitConfig(config, primarySocksHost, primarySocksPort, localListenPort)
            val binary = binaryPath?.let(::File)?.takeIf { it.isFile }
                ?: error("Bundled sing-box not found for this architecture")
            check(portListening(primarySocksHost, primarySocksPort)) { "Primary Aether SOCKS port is not listening" }
            check(!portListening("127.0.0.1", localListenPort) && !portListening("127.0.0.1", localListenPort - 1)) {
                "WireGuard exit listener port is already in use"
            }
            // sing-box 1.10.7 reads config from stdin until EOF. Do not persist private keys or log its IPC dump.
            val child = ProcessBuilder(binary.absolutePath, "run", "-c", "stdin")
                .directory(workingDir?.let(::File)).redirectErrorStream(true).start()
            process = child
            thread(isDaemon = true, name = "WgExit-log") {
                runCatching { child.inputStream.bufferedReader().useLines { lines -> lines.forEach { /* drain */ } } }
            }
            child.outputStream.bufferedWriter().use { it.write(json) }
            LogRepository.i("[WgExit] Starting WireGuard through primary SOCKS5 UDP on $primarySocksPort", "WgExit")
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8)
            while (child.isAlive && !portListening("127.0.0.1", localListenPort) && System.nanoTime() < deadline) {
                Thread.sleep(100)
            }
            check(child.isAlive) { "sing-box rejected the WireGuard configuration (exit ${child.exitValue()})" }
            check(portListening("127.0.0.1", localListenPort)) { "sing-box did not open its SOCKS listener" }
            val probe = ExitIpProbe(localListenPort)
            val ip = probe.check() ?: if (child.isAlive) probe.check() else null
            check(ip != null && child.isAlive) {
                "No data through the WireGuard exit. Check primary SOCKS5 UDP support and the configured peer/key."
            }
            verifiedExitIp = ip
            LogRepository.i("[WgExit] Verified traffic through the WireGuard exit: $ip", "WgExit")
            true
        } catch (e: Exception) {
            lastErrorMessage = e.message ?: "WireGuard exit startup failed"
            LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
            stop()
            false
        }
    }

    @Synchronized
    fun stop() {
        verifiedExitIp = null
        val child = process ?: return
        process = null
        runCatching {
            child.destroy()
            if (!child.waitFor(1500, TimeUnit.MILLISECONDS)) child.destroyForcibly()
        }
    }

    fun isConnected(): Boolean = process?.isAlive == true && verifiedExitIp != null
    fun isHealthy(): Boolean = isConnected() && portListening("127.0.0.1", localListenPort)

    companion object {
        const val INNER_WG_SAFE_MTU = 1120

        fun probeProfilesFast(
            profiles: List<CustomWireGuardConfig>,
            timeoutMs: Int = 1200
        ): List<CustomWireGuardConfig> {
            val valid = profiles.filter { it.isValid() }
            if (valid.isEmpty()) return profiles

            val executor = Executors.newFixedThreadPool(valid.size.coerceIn(1, 8))
            val updated = java.util.concurrent.ConcurrentHashMap<String, Long>()

            val futures = valid.map { cfg ->
                executor.submit {
                    val endpoint = cfg.endpoint.substringBefore(':').trim()
                    val port = cfg.endpoint.substringAfter(':', "51820").toIntOrNull() ?: 51820
                    val start = System.currentTimeMillis()
                    var ping = -1L
                    try {
                        Socket().use { s ->
                            s.connect(InetSocketAddress(endpoint, port), timeoutMs)
                            ping = System.currentTimeMillis() - start
                        }
                    } catch (_: Exception) {
                        val elapsed = System.currentTimeMillis() - start
                        if (elapsed in 10..timeoutMs) {
                            ping = elapsed
                        }
                    }
                    updated[cfg.id] = ping
                }
            }

            for (f in futures) {
                runCatching { f.get(timeoutMs.toLong() + 200, TimeUnit.MILLISECONDS) }
            }
            executor.shutdownNow()

            return profiles.map { p ->
                val newPing = updated[p.id]
                if (newPing != null && newPing > 0) p.copy(lastPingMs = newPing) else p
            }
        }

        fun selectFastestProfile(
            profiles: List<CustomWireGuardConfig>,
            fallback: CustomWireGuardConfig
        ): CustomWireGuardConfig {
            val valid = profiles.filter { it.isValid() }
            if (valid.isEmpty()) return fallback
            if (valid.size == 1) return valid.first()

            val sorted = valid.sortedBy { if (it.lastPingMs > 0) it.lastPingMs else Long.MAX_VALUE }
            return sorted.first()
        }
    }
}
