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
        val children = mutableListOf(peer)
        fun core(config: String, port: Int) {
            val p = ProcessBuilder(binary, "run", "-c", "stdin").redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.INHERIT).start()
            children.add(p)
            p.outputStream.bufferedWriter().use { it.write(config) }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(4)
            while (p.isAlive && !portListening("127.0.0.1", port) && System.nanoTime() < deadline) Thread.sleep(30)
            assertTrue(p.isAlive && portListening("127.0.0.1", port), "test core did not start")
        }
        try {
            val (peerPort, privateKey, publicKey) = peer.inputStream.bufferedReader().readLine().split(' ')
            val primary = freePortPair()
            core("""{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":$primary}],
                "outbounds":[{"type":"direct","override_address":"127.0.0.1","override_port":$peerPort}]}""", primary)
            val exit = freePortPair()
            val cfg = CustomWireGuardConfig(privateKey = privateKey, publicKey = publicKey, endpoint = "127.0.0.1:1", addressV4 = "10.2.0.2/32")
            core(wireGuardExitConfig(cfg, "127.0.0.1", primary, exit), exit)
            val client = OkHttpClient.Builder().proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", exit)))
                .callTimeout(8, TimeUnit.SECONDS).build()
            client.newCall(Request.Builder().url("http://10.2.0.1/").build()).execute().use {
                assertEquals(200, it.code); assertEquals("inside-the-test-peer", it.body?.string())
            }
        } finally {
            children.reversed().forEach { it.destroyForcibly(); it.waitFor(2, TimeUnit.SECONDS) }
        }
    }
}
