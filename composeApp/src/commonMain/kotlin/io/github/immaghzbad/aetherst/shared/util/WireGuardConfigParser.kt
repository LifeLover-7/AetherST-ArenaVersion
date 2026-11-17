package io.github.immaghzbad.aetherst.shared.util

import io.github.immaghzbad.aetherst.shared.model.CustomWireGuardConfig
import java.util.UUID

object WireGuardConfigParser {

    /**
     * Parses a standard WireGuard INI-style configuration file (.conf)
     * e.g. Proton VPN, Mullvad, IVPN, or standard wg-quick configurations.
     * Extracts server name, country flag, keys, endpoint and enforces MTU=1280.
     */
    fun parse(rawText: String, fileName: String? = null): CustomWireGuardConfig {
        var privateKey = ""
        val addressV4List = mutableListOf<String>()
        val addressV6List = mutableListOf<String>()
        val dnsList = mutableListOf<String>()
        var mtu = 1280

        var publicKey = ""
        var endpoint = ""
        val allowedIpsV4List = mutableListOf<String>()
        val allowedIpsV6List = mutableListOf<String>()
        var keepalive = 25

        var currentSection = ""
        var extractedName = ""

        val lines = rawText.lines()
        for (rawLine in lines) {
            val trimmed = rawLine.trim()

            // Look for name/description in comments:
            // e.g. # Description: NL-FREE#123456, # Name: US-FREE#1, # NL-FREE#1
            if (trimmed.startsWith("#") || trimmed.startsWith(";")) {
                val commentContent = trimmed.substring(1).trim()
                if (commentContent.startsWith("Description:", ignoreCase = true)) {
                    val desc = commentContent.substringAfter(":").trim()
                    if (desc.isNotEmpty() && extractedName.isEmpty()) extractedName = desc
                } else if (commentContent.startsWith("Name:", ignoreCase = true)) {
                    val n = commentContent.substringAfter(":").trim()
                    if (n.isNotEmpty() && extractedName.isEmpty()) extractedName = n
                } else if (extractedName.isEmpty() && commentContent.matches(Regex("""^[A-Z]{2}[-#].+"""))) {
                    extractedName = commentContent
                }
                continue
            }

            val line = trimmed.substringBefore('#').substringBefore(';').trim()
            if (line.isEmpty()) continue

            if (line.startsWith("[") && line.endsWith("]")) {
                currentSection = line.substring(1, line.length - 1).trim().lowercase()
                continue
            }

            val eqIdx = line.indexOf('=')
            if (eqIdx == -1) continue

            val key = line.substring(0, eqIdx).trim().lowercase()
            val value = line.substring(eqIdx + 1).trim()

            when (currentSection) {
                "interface" -> {
                    when (key) {
                        "privatekey" -> privateKey = value
                        "address" -> {
                            val parts = value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                            for (p in parts) {
                                if (isIpv6Address(p)) {
                                    addressV6List.add(p)
                                } else {
                                    addressV4List.add(p)
                                }
                            }
                        }
                        "dns" -> {
                            val parts = value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                            dnsList.addAll(parts)
                        }
                        "mtu" -> {
                            // Enforce 1280 for WireGuard-in-WireGuard to prevent fragmentation
                            mtu = 1280
                        }
                    }
                }
                "peer" -> {
                    when (key) {
                        "publickey" -> publicKey = value
                        "endpoint" -> endpoint = value
                        "allowedips" -> {
                            val parts = value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                            for (p in parts) {
                                if (isIpv6Address(p)) {
                                    allowedIpsV6List.add(p)
                                } else {
                                    allowedIpsV4List.add(p)
                                }
                            }
                        }
                        "persistentkeepalive" -> {
                            keepalive = value.toIntOrNull()?.coerceAtLeast(0) ?: 25
                        }
                    }
                }
            }
        }

        // Determine server profile name with country flag
        val candidateName = when {
            extractedName.isNotBlank() -> extractedName
            !fileName.isNullOrBlank() -> fileName.removeSuffix(".conf").removeSuffix(".wg")
            endpoint.isNotBlank() -> "Proton ${endpoint.substringBefore(':')}"
            else -> "Proton WireGuard"
        }

        val formattedName = formatServerNameWithFlag(candidateName)

        return CustomWireGuardConfig(
            id = UUID.randomUUID().toString(),
            name = formattedName,
            rawConfig = rawText,
            privateKey = privateKey,
            addressV4 = addressV4List.joinToString(", "),
            addressV6 = addressV6List.joinToString(", "),
            dns = if (dnsList.isNotEmpty()) dnsList.joinToString(", ") else "1.1.1.1",
            mtu = 1280, // Always enforce 1280
            publicKey = publicKey,
            endpoint = endpoint,
            allowedIpsV4 = if (allowedIpsV4List.isNotEmpty()) allowedIpsV4List.joinToString(", ") else "0.0.0.0/0",
            allowedIpsV6 = if (allowedIpsV6List.isNotEmpty()) allowedIpsV6List.joinToString(", ") else "::/0",
            persistentKeepalive = keepalive,
            lastPingMs = -1L
        )
    }

    /**
     * Formats server name and prefixes with Country Flag emoji if country code is recognized.
     * e.g. "NL-FREE#123456" -> "🇳🇱 NL-FREE#123456"
     */
    fun formatServerNameWithFlag(rawName: String): String {
        val trimmed = rawName.trim()
        if (trimmed.isEmpty()) return "🌐 Proton WireGuard"

        // If it already has an emoji, return as is
        if (trimmed.codePoints().anyMatch { it > 0x1F000 }) {
            return trimmed
        }

        // Match 2-letter country code at start, e.g. "NL-FREE#1", "US#10", "JP-01"
        val match = Regex("""^([A-Za-z]{2})([-_#].*)?$""").find(trimmed)
        if (match != null) {
            val cc = match.groupValues[1].uppercase()
            val flag = countryCodeToEmoji(cc)
            return "$flag $trimmed"
        }

        return "🌐 $trimmed"
    }

    /**
     * Converts a 2-letter ISO country code (e.g. "NL", "US", "JP") to its emoji flag.
     */
    fun countryCodeToEmoji(countryCode: String): String {
        if (countryCode.length != 2) return "🌐"
        val upper = countryCode.uppercase()
        val c1 = upper[0]
        val c2 = upper[1]
        if (c1 !in 'A'..'Z' || c2 !in 'A'..'Z') return "🌐"

        val firstCodePoint = 0x1F1E6 + (c1 - 'A')
        val secondCodePoint = 0x1F1E6 + (c2 - 'A')
        return String(Character.toChars(firstCodePoint)) + String(Character.toChars(secondCodePoint))
    }

    /**
     * Determines whether an address or CIDR string represents an IPv6 address.
     */
    fun isIpv6Address(address: String): Boolean {
        val pure = address.substringBefore('/')
        return pure.contains(':')
    }

    /**
     * Filters IPv6 addresses and routes if the primary tunnel does not support IPv6,
     * preventing routing loops or gateway errors.
     */
    fun filterForPrimarySupport(config: CustomWireGuardConfig, supportsIpv6: Boolean): CustomWireGuardConfig {
        return if (!supportsIpv6) {
            config.copy(
                addressV6 = "",
                allowedIpsV6 = ""
            )
        } else {
            config
        }
    }
}
