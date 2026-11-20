package io.github.immaghzbad.aetherst

import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import io.github.immaghzbad.aetherst.core.ConnectionController
import io.github.immaghzbad.aetherst.core.primarySignal
import io.github.immaghzbad.aetherst.core.PrimarySignal
import io.github.immaghzbad.aetherst.core.primarySocksResponds
import io.github.immaghzbad.aetherst.platform.PlatformContext
import io.github.immaghzbad.aetherst.platform.getSettings
import io.github.immaghzbad.aetherst.service.AetherVpnService
import io.github.immaghzbad.aetherst.shared.data.*
import io.github.immaghzbad.aetherst.shared.model.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.net.ServerSocket

/** Goes through the app service, packaged Aether executable, selected exit, actual
 * VpnService.Builder and JNI HEV. The request originates from the shell UID, not
 * the VPN-excluded app UID; the private origin echoes which peer carried it. */
class DeviceRoutingTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val ctx = instrumentation.targetContext
    private fun shell(cmd: String): String = ParcelFileDescriptor.AutoCloseInputStream(
        instrumentation.uiAutomation.executeShellCommand(cmd)).bufferedReader().use { it.readText() }

    @Test fun primarySelection() {
        check(ctx.packageName.endsWith(".runtimecheck"))
        val repo = AetherConfigRepository.getInstance(getSettings(PlatformContext(ctx)))
        val old = AetherConfig(protocol = AetherProtocol.MASQUE, mimEnabled = true, mimOuter = "192.0.2.1:443",
            mimInner = "192.0.2.2:443", chainProvider = ChainProvider.PSIPHON, psiphonEnabled = true)
        repo.applyDetectedConfig(old)
        assertEquals(AetherProtocol.MIM, repo.config.value.primaryProtocol)
        assertFalse(old.selectExitNode(ExitNodeMode.DIRECT).isPsiphonActive())
        assertFalse(old.copy(chainProvider = ChainProvider.TOR, torEnabled = true).selectExitNode(ExitNodeMode.DIRECT).isTorActive())
        for ((preset, expected) in listOf("stealth" to AetherProtocol.MIM, "gaming" to AetherProtocol.GOOL,
                "ironclad" to AetherProtocol.WG, "turbo" to AetherProtocol.MASQUE)) {
            repo.applyPreset(preset)
            assertEquals(preset, expected, repo.config.value.primaryProtocol)
        }
        val classic = old.copy(protocol = AetherProtocol.GOOL, goolClassic = true, wiwOuter = "192.0.2.1:2408")
        assertEquals(listOf("--gool-classic", "--wiw-outer", "192.0.2.1:2408"), classic.primaryArguments())
        assertTrue("--wiw-scan" in classic.copy(wiwOuter = "").primaryArguments())
        assertFalse("--mim-scan" in old.primaryArguments())
        assertTrue("--mim-scan" in old.copy(mimOuter = "", mimInner = "").primaryArguments())
        assertTrue("--h3" in old.copy(httpVersion = MasqueHttpVersion.H3).primaryArguments())
    }

    @Test fun listenerEvidence() {
        val bind = "127.0.0.1:2021"
        assertEquals(PrimarySignal.VALIDATING, primarySignal("[+] gool ready: masque A carries wireguard B", bind))
        assertNotEquals(PrimarySignal.SERVING, primarySignal("[+] inner MASQUE tunnel established", bind))
        assertNull(primarySignal("[+] socks5 server listening on 127.0.0.1:49152", bind))
        assertEquals(PrimarySignal.SERVING, primarySignal("[+] socks5 server listening on $bind", bind))
        assertEquals(PrimarySignal.LOST, primarySignal("[-] masque-in-masque tunnel ended: eof; reconnecting", bind))
        ServerSocket(0).use { assertFalse(primarySocksResponds(it.localPort, 250)) }
    }

    @Test fun wgProton() = route(AetherProtocol.WG, ExitNodeMode.CUSTOM_WG, "wireguard")
    @Test fun wgFirefox() = route(AetherProtocol.WG, ExitNodeMode.FIREFOX_VPN, "firefox")
    @Test fun goolDirect() = route(AetherProtocol.GOOL, ExitNodeMode.DIRECT, "wireguard")
    @Test fun classicGoolDirect() = route(AetherProtocol.GOOL, ExitNodeMode.DIRECT, "wireguard", classic = true)
    @Test fun mimDirect() = route(AetherProtocol.MIM, ExitNodeMode.DIRECT, "masque")

    private fun route(proto: AetherProtocol, exit: ExitNodeMode, expected: String, classic: Boolean = false) {
        // Never touch a normal installation or its identities. Fixture assets are ephemeral.
        check(ctx.packageName.endsWith(".runtimecheck")) { "Run only on the disposable runtime-check build" }
        val assets = instrumentation.context.assets
        fun text(name: String) = assets.open(name).bufferedReader().use { it.readText() }
        val peers = JSONObject(text("peers.json"))
        fun identity(file: String, hop: String) {
            File(ctx.filesDir, file).writeText("""
                device_id = "emulator"
                access_token = "fixture"
                ipv4 = "10.70.0.2"
                ipv6 = "fd70::2"
                wg_private_key = "${peers.getString(hop + "Key")}"
                wg_peer_public_key = "${peers.getString(hop + "Pub")}"
                cert_pem = ${JSONObject.quote(text("leaf.pem")).replace("\\/", "/")}
                key_pem = ${JSONObject.quote(text("leaf.key")).replace("\\/", "/")}
                cert_issued_at = ${System.currentTimeMillis()/1000}
            """.trimIndent())
        }
        identity("aether.toml", "outer"); identity("aether-secondary.toml", "inner")
        identity("aether-masque.toml", "outer"); identity("aether-masque-gool.toml", "inner"); identity("aether-masque-secondary.toml", "inner")
        val wg = "10.0.2.2:${peers.getString("wgPort")}"; val masque = "10.0.2.2:${peers.getString("masquePort")}"
        val cfg = AetherConfig(protocol = proto, exitNodeMode = exit, connectionMode = ConnectionMode.TUNNEL,
            ipMode = AetherIpMode.IPV4, noise = AetherNoise.OFF, echEnabled = false, h2Fragment = false,
            mtu = 1240, ipv6Leak = true, quickReconnect = false, smartReconnect = false,
            wgPeer = wg, wiwOuter = if (classic) wg else masque, wiwInner = "10.70.0.1:2408", wiwScan = true,
            goolClassic = classic, goolNeighborEgress = false, mimEnabled = true, // stale on WG/GOOL
            mimOuter = masque, mimInner = "10.70.0.1:4443", mimScan = true, dnsEnabled = true, dnsList = "8.8.8.8",
            customWgConfig = CustomWireGuardConfig(privateKey = peers.getString("innerKey"), publicKey = peers.getString("innerPub"),
                endpoint = "10.70.0.1:2408", addressV4 = "10.70.0.2/32", allowedIpsV6 = ""),
            firefoxVpnToken = peers.getString("pass"), firefoxVpnCountry = "US")
        val repo = AetherConfigRepository.getInstance(getSettings(PlatformContext(ctx)))
        repo.applyDetectedConfig(cfg)
        assertNull("Grant ACTIVATE_VPN to the emulator test package", VpnService.prepare(ctx))
        val firstLog = LogRepository.logs.value.lastOrNull()?.id ?: 0L
        try {
            assertTrue(AetherVpnService.startVpn(ctx))
            runBlocking {
                withTimeout(90_000) {
                    while (ConnectionController.status.value != ConnectionStatus.RUNNING) {
                        val failure = LogRepository.logs.value.lastOrNull { it.id > firstLog &&
                            (it.message.startsWith("[Controller] Startup failed:") || it.message.startsWith("[VpnService] Rollback:")) }
                        check(failure == null) { failure!!.message }
                        delay(100)
                    }
                }
            }
            val nonce = System.nanoTime()
            // UiAutomation uses Runtime.exec(String); it splits whitespace and does not parse shell quoting.
            val reply = shell("sh /data/local/tmp/aether-runtime-probe.sh $nonce")
            assertTrue("Device TUN did not reach $expected: ${reply.take(160)}", reply.contains("via-$expected:/$nonce"))
            val lines = LogRepository.logs.value.filter { it.id > firstLog }.map { it.message }
            if (proto == AetherProtocol.GOOL && !classic) assertTrue("Unexpected classic fallback", lines.any { "gool ready:" in it })
            assertTrue(lines.any { "VPN tunnel active" in it || "Final SOCKS listener verified" in it })
        } catch (e: Throwable) {
            // Fixture-only run. No identity/config/credential files or request headers in CI output.
            val tail = LogRepository.logs.value.filter { it.id > firstLog }.takeLast(16).joinToString(" | ") { it.message.take(200) }
            throw AssertionError("$proto/$exit: ${e.message}: $tail", e)
        } finally {
            AetherVpnService.stopVpn(ctx)
            runBlocking { withTimeout(15_000) { while (ConnectionController.status.value != ConnectionStatus.STOPPED) delay(100) }; delay(700) }
        }
    }
}
