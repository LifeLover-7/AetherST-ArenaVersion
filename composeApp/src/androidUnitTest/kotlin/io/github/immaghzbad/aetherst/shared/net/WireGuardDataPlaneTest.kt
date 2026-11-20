package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.model.CustomWireGuardConfig
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.Assume.assumeNotNull
import org.junit.Test
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import kotlin.test.*

class WireGuardDataPlaneTest {
    @Test(timeout = 30000) fun encryptedRoundTripRequiresPrimaryUdpRelay() {
        val binary = System.getenv("AETHER_TEST_SING_BOX")
        val fixture = System.getenv("AETHER_TEST_WG_PEER")
        assumeNotNull(binary, fixture) // tools/exit-test/run.sh supplies both.
        val peer = ProcessBuilder(fixture).redirectError(ProcessBuilder.Redirect.INHERIT).start()
        try {
            val info = peer.inputStream.bufferedReader().readLine()?.split(' ') ?: error("Local test peer did not start")
            val peerPort = info[0].toInt()
            val primary = info[1].toInt()
            val blockedPrimary = info[2].toInt()
            val exit = freePortPair()
            val cfg = CustomWireGuardConfig(privateKey = info[3], publicKey = info[4], preSharedKey = info[5],
                endpoint = "127.0.0.2:1", addressV4 = "10.2.0.2/32")
            fun probe(port: Int): String? = runCatching {
                val client = OkHttpClient.Builder().proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port)))
                    .callTimeout(3, TimeUnit.SECONDS).build()
                client.newCall(Request.Builder().url("http://10.2.0.1/").build()).execute().use {
                    if (it.isSuccessful && it.body?.string() == "inside-the-test-peer") "10.2.0.1" else null
                }
            }.getOrNull()
            val tunnel = WireGuardExitTunnel(cfg, binary, null, "127.0.0.1", primary, exit, ::probe)
            try {
                assertTrue(tunnel.start(), tunnel.lastErrorMessage)
                assertEquals("10.2.0.1", tunnel.verifiedExitIp)
                assertEquals("10.2.0.1", probe(exit))
            } finally { tunnel.stop() }
            assertFalse(portListening("127.0.0.1", exit))
            // Give the real port to the exit, but have a SOCKS first hop which cannot transmit packets.
            // A hidden direct fallback would still reach the peer and incorrectly report success here.
            val blocked = WireGuardExitTunnel(cfg.copy(endpoint = "127.0.0.1:$peerPort"), binary, null,
                "127.0.0.1", blockedPrimary, exit, ::probe)
            try {
                assertFalse(blocked.start()); assertNull(blocked.verifiedExitIp)
                assertFalse(portListening("127.0.0.1", exit))
            } finally { blocked.stop() }
        } finally {
            peer.destroyForcibly(); peer.waitFor(2, TimeUnit.SECONDS)
        }
    }
}
