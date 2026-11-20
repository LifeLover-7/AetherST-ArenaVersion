package io.github.immaghzbad.aetherst.core

import android.content.Context
import android.net.VpnService
import io.github.immaghzbad.aetherst.platform.PlatformContext
import io.github.immaghzbad.aetherst.platform.getSettings
import io.github.immaghzbad.aetherst.shared.data.AetherConfigRepository
import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.data.PsiphonEgressRegistry
import io.github.immaghzbad.aetherst.shared.model.AetherConfig
import java.io.File
import java.lang.ref.WeakReference
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicLong

object PsiphonController {
    @Volatile private var psiphonPort: Int = 3080
    @Volatile private var running = false
    @Volatile private var connected = false
    @Volatile private var tunnelObj: Any? = null
    private val lastEventTime = AtomicLong(0L)
    @Volatile private var vpnServiceRef: WeakReference<VpnService>? = null

    fun setVpnService(service: VpnService) {
        vpnServiceRef = WeakReference(service)
    }

    fun isSupported(config: AetherConfig): Boolean = config.isPsiphonActive()

    fun getPort(): Int = psiphonPort

    fun getUpstreamProxy(): String = "socks5://127.0.0.1:$psiphonPort"

    private fun findFreePort(preferred: Int = 3080): Int {
        return try {
            ServerSocket(preferred).use { it.localPort }
        } catch (_: Exception) {
            try { ServerSocket(0).use { it.localPort } } catch (_: Exception) { preferred }
        }
    }

    fun start(context: Context, config: AetherConfig, upstream: String? = null): Boolean {
        if (!isSupported(config)) return false
        stop()

        return try {
            val dir = File(context.filesDir, "psiphon")
            if (!dir.exists()) dir.mkdirs()

            val requested = config.psiphonSocksPort.toIntOrNull() ?: 3080
            val port = if (requested.toString() == config.socksPort) findFreePort(3080) else requested
            psiphonPort = port

            val serverEntries = try {
                context.assets.open("server_entries.txt").bufferedReader().readText().trim()
            } catch (_: Exception) { "" }

            val clazz = Class.forName("ca.psiphon.PsiphonTunnel")
            val hostServiceClass = Class.forName("ca.psiphon.PsiphonTunnel\$HostService")
            val hostLoggerClass = Class.forName("ca.psiphon.PsiphonTunnel\$HostLogger")
            val hostLoaderClass = Class.forName("ca.psiphon.PsiphonTunnel\$HostLibraryLoader")

            val hostService = java.lang.reflect.Proxy.newProxyInstance(
                hostServiceClass.classLoader,
                arrayOf(hostServiceClass, hostLoggerClass, hostLoaderClass)
            ) { _, method, args ->
                when (method.name) {
                    "getContext" -> context
                    "getPsiphonConfig" -> buildPsiphonConfig(dir, port, config.psiphonEgressRegion, upstream)
                    "onListeningSocksProxyPort" -> {
                        val p = args?.get(0) as? Int ?: port
                        psiphonPort = p
                        LogRepository.i("[Psiphon] Listening on port $p", "Psiphon")
                        null
                    }
                    "onConnected" -> {
                        connected = true
                        lastEventTime.set(System.currentTimeMillis())
                        LogRepository.i("[Psiphon] Tunnel connected successfully! Egress ready.", "Psiphon")
                        null
                    }
                    "onConnecting" -> {
                        lastEventTime.set(System.currentTimeMillis())
                        null
                    }
                    "onAvailableEgressRegions" -> {
                        val list = (args?.get(0) as? List<*>)?.mapNotNull { it?.toString()?.trim()?.uppercase() }?.filter { it.matches(Regex("^[A-Z]{2}$")) } ?: emptyList()
                        if (list.isNotEmpty()) {
                            PsiphonEgressRegistry.setAvailableRegions(list)
                            runCatching { AetherConfigRepository.getInstance(getSettings(PlatformContext(context))).cacheEgressRegions(list) }
                            LogRepository.i("[Psiphon] Available regions: ${list.joinToString()}", "Psiphon")
                        }
                        null
                    }
                    "bindToDevice" -> {
                        val fd = (args?.get(0) as? Long)?.toInt() ?: (args?.get(0) as? Int) ?: -1
                        if (fd > 0) {
                            vpnServiceRef?.get()?.protect(fd) ?: false
                        } else {
                            false
                        }
                        null
                    }
                    else -> null
                }
            }

            val newTunnel = clazz.getMethod("newPsiphonTunnel", hostServiceClass).invoke(null, hostService)
            if (newTunnel != null) {
                val startMethod = clazz.getMethod("startTunneling", String::class.java)
                startMethod.invoke(newTunnel, serverEntries)
                val setVpnMode = try { clazz.getMethod("setVpnMode", Boolean::class.javaPrimitiveType) } catch (_: Exception) { null }
                setVpnMode?.invoke(newTunnel, false)
                tunnelObj = newTunnel
                running = true
                connected = false
                LogRepository.i("[Psiphon] Single core started on port $port with serverEntries (Egress=${config.psiphonEgressRegion.ifBlank { "Auto" }})", "Psiphon")
                true
            } else {
                running = false
                connected = false
                false
            }
        } catch (e: Exception) {
            val reason = e.message ?: "unknown error"
            LogRepository.w("[Psiphon] Library not found or start failed ($reason)", "Psiphon")
            running = false
            connected = false
            false
        }
    }

    private fun buildPsiphonConfig(dir: File, port: Int, egressRegion: String = "", upstream: String? = null): String {
        return try {
            val json = org.json.JSONObject()
            json.put("PropagationChannelId", "FFFFFFFFFFFFFFFF")
            json.put("SponsorId", "1111111111111111")
            if (egressRegion.isNotBlank()) json.put("EgressRegion", egressRegion)
            json.put("EstablishTunnelTimeoutSeconds", 300)
            json.put("DataRootDirectory", dir.absolutePath)
            json.put("ClientVersion", "1")
            json.put("TunnelProtocol", "")
            json.put("RemoteServerListURL", "")
            json.put("LocalSocksProxyPort", port)
            if (!upstream.isNullOrEmpty()) json.put("UpstreamProxyURL", upstream)
            json.put("RemoteServerListSignaturePublicKey", "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=")
            json.put("ServerEntrySignaturePublicKey", "sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA=")
            json.put("ExchangeObfuscationKey", "DpXzloJk1Hw6aSzmKKky0xcahsEHubch81Mi6K0XMlU=")
            json.put("EmitBytesTransferred", true)
            json.put("ConnectionWorkerPoolSize", 12)
            json.toString()
        } catch (_: Exception) {
            val safeDir = dir.absolutePath.replace("\\", "\\\\")
            "{\"LocalSocksProxyPort\":$port,\"DataRootDirectory\":\"$safeDir\",\"TunnelProtocol\":\"\"}"
        }
    }

    fun stop() {
        if (!running && tunnelObj == null) return
        try {
            tunnelObj?.let {
                val m = it.javaClass.getMethod("stop")
                m.invoke(it)
            }
        } catch (_: Exception) {}
        tunnelObj = null
        running = false
        connected = false
        vpnServiceRef?.clear()
        vpnServiceRef = null
        LogRepository.i("[Psiphon] Stopped", "Psiphon")
    }

    fun isRunning(): Boolean {
        if (!running) return false
        return try {
            tunnelObj?.let {
                val m = it.javaClass.getMethod("isRunning")
                (m.invoke(it) as? Boolean) == true
            } ?: running
        } catch (_: Exception) { running }
    }

    fun isConnected(): Boolean = connected && isRunning()

    fun stableFor(graceMs: Long): Boolean = isConnected() &&
            (System.currentTimeMillis() - lastEventTime.get()) >= graceMs
}
