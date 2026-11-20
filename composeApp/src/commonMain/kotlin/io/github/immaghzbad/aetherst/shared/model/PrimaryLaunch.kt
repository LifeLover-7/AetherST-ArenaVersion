package io.github.immaghzbad.aetherst.shared.model

/** mimEnabled was originally a switch on MASQUE. A stale switch in an older profile
 * must never override an explicit WG/GOOL selection. */
val AetherConfig.primaryProtocol: AetherProtocol
    get() = if (protocol == AetherProtocol.MASQUE && mimEnabled) AetherProtocol.MIM else protocol

val AetherConfig.usesMasqueTransport: Boolean
    get() = primaryProtocol != AetherProtocol.WG && !(primaryProtocol == AetherProtocol.GOOL && goolClassic)

/** One source of truth for argv. These options must not also be synthesized in the environment. */
fun AetherConfig.primaryArguments(): List<String> = buildList {
    fun option(flag: String, value: String) { if (value.isNotBlank()) { add(flag); add(value.trim()) } }
    when (primaryProtocol) {
        AetherProtocol.WG -> {
            add("--wg")
            option("--wg-peer", wgPeer.ifBlank { peer })
        }
        AetherProtocol.GOOL -> {
            val outer = wiwOuter.ifBlank { peer }
            val inner = wiwInner.ifBlank { wgPeer }
            add(if (goolClassic) "--gool-classic" else "--gool")
            option(if (goolClassic) "--wiw-outer" else "--peer", outer)
            option(if (goolClassic) "--wiw-inner" else "--gool-peer", inner)
            if (goolClassic && wiwScan && outer.isBlank() && inner.isBlank()) add("--wiw-scan")
        }
        AetherProtocol.MIM -> {
            add("--mim")
            val outer = mimOuter.ifBlank { peer }
            option("--mim-outer", outer)
            option("--mim-inner", mimInner)
            if (mimScan && outer.isBlank() && mimInner.isBlank()) add("--mim-scan")
        }
        AetherProtocol.MASQUE, AetherProtocol.ZERO_TRUST -> {
            add("--masque")
            option("--peer", peer)
        }
    }
    if (usesMasqueTransport) {
        // Aether only implements CONNECT-IP over H2/H3. Old H1 profiles use the TCP transport.
        val h2 = effectiveHttpVersion() != MasqueHttpVersion.H3 ||
            (upstreamProxyEnabled && upstreamProxy.startsWith("http://", ignoreCase = true))
        add(if (h2) "--h2" else "--h3")
        if (echEnabled) option("--ech", "auto")
        if (h2 && h2Fragment) {
            add("--fragment")
            option("--fragment-size", fragmentSize.ifBlank { "30-60" })
            option("--fragment-delay", fragmentDelay.ifBlank { "5-15" })
        }
        option("--masque-sni", masqueSni)
    }
}
