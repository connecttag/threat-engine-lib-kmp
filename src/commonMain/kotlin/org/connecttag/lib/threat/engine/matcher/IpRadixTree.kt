package org.connecttag.lib.threat.engine.matcher

import org.connecttag.lib.threat.engine.model.ThreatMatchResult
import org.connecttag.lib.threat.engine.model.ThreatType
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger

/**
 * High-performance, bitwise Radix Tree (Patricia Tree) for IPv4 and IPv6 threat matching.
 *
 * Supports single IP addresses and arbitrary CIDR subnets (e.g. 192.168.1.0/24, 10.0.0.0/8, 2001:db8::/32).
 * Matching is O(32) for IPv4 and O(128) for IPv6, with ZERO heap allocations during lookup.
 */
public class IpRadixTree {

    private class RadixNode {
        @Volatile var zero: RadixNode? = null
        @Volatile var one: RadixNode? = null
        @Volatile var isTerminal: Boolean = false
        @Volatile var feedName: String? = null
        @Volatile var category: String? = null
    }

    private val ipv4Root = RadixNode()
    private val ipv6Root = RadixNode()
    private val ruleCount = AtomicInteger(0)

    public val size: Int
        get() = ruleCount.get()

    /**
     * Inserts an IP address or CIDR notation into the tree.
     * e.g., "198.51.100.1", "198.51.100.0/24", "2001:db8::/32"
     */
    public fun insert(rawIpOrCidr: String, feedName: String = "ThreatIntel", category: String = "Malicious IP") {
        val trimmed = rawIpOrCidr.trim()
        if (trimmed.isEmpty()) return

        val slashIdx = trimmed.indexOf('/')
        val ipStr = if (slashIdx >= 0) trimmed.substring(0, slashIdx).trim() else trimmed
        val prefixLenOverride = if (slashIdx >= 0) trimmed.substring(slashIdx + 1).trim().toIntOrNull() else null

        val inetAddr = try {
            InetAddress.getByName(ipStr)
        } catch (_: Exception) {
            return
        }

        when (inetAddr) {
            is Inet4Address -> {
                val prefix = prefixLenOverride?.coerceIn(0, 32) ?: 32
                insertIpv4(inetAddr.address, prefix, feedName, category)
            }
            is Inet6Address -> {
                val prefix = prefixLenOverride?.coerceIn(0, 128) ?: 128
                insertIpv6(inetAddr.address, prefix, feedName, category)
            }
            else -> return
        }
    }

    private fun insertIpv4(bytes: ByteArray, prefixLen: Int, feedName: String, category: String) {
        var current = ipv4Root
        val intVal = ((bytes[0].toInt() and 0xFF) shl 24) or
                ((bytes[1].toInt() and 0xFF) shl 16) or
                ((bytes[2].toInt() and 0xFF) shl 8) or
                (bytes[3].toInt() and 0xFF)

        for (i in 0 until prefixLen) {
            val bit = 31 - i
            val isOne = ((intVal ushr bit) and 1) == 1

            current = if (isOne) {
                current.one ?: RadixNode().also { current.one = it }
            } else {
                current.zero ?: RadixNode().also { current.zero = it }
            }
        }

        if (!current.isTerminal) {
            current.isTerminal = true
            current.feedName = feedName
            current.category = category
            ruleCount.incrementAndGet()
        }
    }

    private fun insertIpv6(bytes: ByteArray, prefixLen: Int, feedName: String, category: String) {
        var current = ipv6Root
        for (i in 0 until prefixLen) {
            val byteIndex = i / 8
            val bitIndex = 7 - (i % 8)
            val isOne = ((bytes[byteIndex].toInt() ushr bitIndex) and 1) == 1

            current = if (isOne) {
                current.one ?: RadixNode().also { current.one = it }
            } else {
                current.zero ?: RadixNode().also { current.zero = it }
            }
        }

        if (!current.isTerminal) {
            current.isTerminal = true
            current.feedName = feedName
            current.category = category
            ruleCount.incrementAndGet()
        }
    }

    /**
     * Matches an IP string (IPv4 or IPv6) against the radix tree.
     */
    public fun match(rawIp: String?): ThreatMatchResult? {
        if (rawIp.isNullOrBlank()) return null
        val trimmed = rawIp.trim()

        val inetAddr = try {
            InetAddress.getByName(trimmed)
        } catch (_: Exception) {
            return null
        }

        return match(inetAddr, trimmed)
    }

    /**
     * Matches an [InetAddress] against the radix tree with zero allocations.
     */
    public fun match(addr: InetAddress, originalIpStr: String = addr.hostAddress ?: ""): ThreatMatchResult? {
        return when (addr) {
            is Inet4Address -> matchIpv4(addr.address, originalIpStr)
            is Inet6Address -> matchIpv6(addr.address, originalIpStr)
            else -> null
        }
    }

    private fun matchIpv4(bytes: ByteArray, originalIpStr: String): ThreatMatchResult? {
        var current: RadixNode? = ipv4Root
        val intVal = ((bytes[0].toInt() and 0xFF) shl 24) or
                ((bytes[1].toInt() and 0xFF) shl 16) or
                ((bytes[2].toInt() and 0xFF) shl 8) or
                (bytes[3].toInt() and 0xFF)

        for (bit in 31 downTo 0) {
            if (current == null) return null
            if (current.isTerminal) {
                return ThreatMatchResult(
                    matched = true,
                    target = originalIpStr,
                    feedName = current.feedName ?: "ThreatIntel",
                    category = current.category ?: "Malicious IP",
                    threatType = ThreatType.IP
                )
            }

            val isOne = ((intVal ushr bit) and 1) == 1
            current = if (isOne) current.one else current.zero
        }

        if (current?.isTerminal == true) {
            return ThreatMatchResult(
                matched = true,
                target = originalIpStr,
                feedName = current.feedName ?: "ThreatIntel",
                category = current.category ?: "Malicious IP",
                threatType = ThreatType.IP
            )
        }

        return null
    }

    private fun matchIpv6(bytes: ByteArray, originalIpStr: String): ThreatMatchResult? {
        var current: RadixNode? = ipv6Root
        for (i in 0 until 128) {
            if (current == null) return null
            if (current.isTerminal) {
                return ThreatMatchResult(
                    matched = true,
                    target = originalIpStr,
                    feedName = current.feedName ?: "ThreatIntel",
                    category = current.category ?: "Malicious IP",
                    threatType = ThreatType.IP
                )
            }

            val byteIndex = i / 8
            val bitIndex = 7 - (i % 8)
            val isOne = ((bytes[byteIndex].toInt() ushr bitIndex) and 1) == 1
            current = if (isOne) current.one else current.zero
        }

        if (current?.isTerminal == true) {
            return ThreatMatchResult(
                matched = true,
                target = originalIpStr,
                feedName = current.feedName ?: "ThreatIntel",
                category = current.category ?: "Malicious IP",
                threatType = ThreatType.IP
            )
        }

        return null
    }

    /**
     * Clears all IP rules from the tree.
     */
    public fun clear() {
        ipv4Root.zero = null
        ipv4Root.one = null
        ipv4Root.isTerminal = false

        ipv6Root.zero = null
        ipv6Root.one = null
        ipv6Root.isTerminal = false

        ruleCount.set(0)
    }
}
