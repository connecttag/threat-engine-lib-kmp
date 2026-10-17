package org.connecttag.lib.threat.engine.matcher

import org.connecttag.lib.threat.engine.model.ThreatMatchResult
import org.connecttag.lib.threat.engine.model.ThreatType
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * High-performance, memory-efficient Domain Suffix Trie.
 *
 * Stores domain components in reverse order:
 * e.g., "malware.example.com" -> ["com", "example", "malware"].
 *
 * This allows O(k) matching of both exact domains and any arbitrary subdomains
 * (e.g. "sub.deep.malware.example.com" matches "malware.example.com")
 * without duplicating subdomains or bloating memory.
 */
public class DomainSuffixTrie {

    private class Node {
        val children = ConcurrentHashMap<String, Node>()
        @Volatile var isTerminal: Boolean = false
        @Volatile var feedName: String? = null
        @Volatile var category: String? = null
        @Volatile var matchedDomain: String? = null
    }

    private val root = Node()
    private val ruleCount = AtomicInteger(0)

    public val size: Int
        get() = ruleCount.get()

    /**
     * Normalizes a domain by trimming, lowercasing, stripping leading "www." and trailing dots.
     */
    public fun normalize(domain: String): String {
        var d = domain.trim().lowercase()
        while (d.endsWith(".")) {
            d = d.substring(0, d.length - 1)
        }
        if (d.startsWith("www.")) {
            d = d.substring(4)
        }
        return d
    }

    /**
     * Inserts a domain into the suffix trie.
     */
    public fun insert(rawDomain: String, feedName: String = "ThreatIntel", category: String = "Malware") {
        val normalized = normalize(rawDomain)
        if (normalized.isBlank()) return

        val parts = normalized.split('.')
        if (parts.isEmpty()) return

        var current = root
        for (i in parts.indices.reversed()) {
            val part = parts[i]
            if (part.isEmpty()) continue
            current = current.children.computeIfAbsent(part) { Node() }
        }

        if (!current.isTerminal) {
            current.isTerminal = true
            current.feedName = feedName
            current.category = category
            current.matchedDomain = normalized
            ruleCount.incrementAndGet()
        }
    }

    /**
     * Matches a query domain against the trie.
     * Returns a [ThreatMatchResult] if an exact domain or any parent domain matches.
     */
    public fun match(queryDomain: String?): ThreatMatchResult? {
        if (queryDomain.isNullOrBlank()) return null
        val normalized = normalize(queryDomain)
        if (normalized.isBlank()) return null

        val parts = normalized.split('.')
        if (parts.isEmpty()) return null

        var current = root
        for (i in parts.indices.reversed()) {
            val part = parts[i]
            val child = current.children[part] ?: return null
            current = child

            if (current.isTerminal) {
                return ThreatMatchResult(
                    matched = true,
                    target = current.matchedDomain ?: queryDomain,
                    feedName = current.feedName ?: "ThreatIntel",
                    category = current.category ?: "Malware",
                    threatType = ThreatType.DOMAIN
                )
            }
        }

        return null
    }

    /**
     * Returns true if the query domain or any of its parent domains is in the trie.
     */
    public fun contains(queryDomain: String?): Boolean {
        return match(queryDomain) != null
    }

    /**
     * Clears all entries from the trie.
     */
    public fun clear() {
        root.children.clear()
        ruleCount.set(0)
    }
}
