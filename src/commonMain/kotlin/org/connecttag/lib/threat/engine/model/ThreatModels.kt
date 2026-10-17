package org.connecttag.lib.threat.engine.model

import kotlinx.serialization.Serializable

/**
 * Type of threat intelligence indicator.
 */
@Serializable
public enum class ThreatType {
    DOMAIN,
    IP
}

/**
 * Result of threat intelligence matching against an IP or Domain.
 */
@Serializable
public data class ThreatMatchResult(
    val matched: Boolean,
    val target: String,
    val feedName: String,
    val category: String,
    val threatType: ThreatType,
    val timestamp: Long = 0L
)

/**
 * Descriptor for an automated threat intelligence feed.
 */
@Serializable
public data class ThreatFeedDescriptor(
    val id: String,
    val name: String,
    val nameAr: String,
    val type: ThreatType,
    val url: String,
    val localFileName: String,
    val category: String,
    val defaultEnabled: Boolean = true,
    var isEnabled: Boolean = true,
    var lastUpdated: Long = 0L,
    var etag: String? = null,
    var lastModifiedHeader: String? = null,
    var ruleCount: Int = 0
)

/**
 * Predefined catalog of high-value, public, zero-authentication Threat Intelligence Feeds.
 */
public object ThreatFeedCatalog {
    public const val FEED_ID_MALTRAIL: String = "maltrail"
    public const val FEED_ID_EMERGING_THREATS: String = "emerging_threats"
    public const val FEED_ID_DIGITALSIDE: String = "digitalside"

    public fun getDefaultFeeds(): List<ThreatFeedDescriptor> = listOf(
        ThreatFeedDescriptor(
            id = FEED_ID_MALTRAIL,
            name = "Maltrail Malware Domains",
            nameAr = "نطاقات البرمجيات الخبيثة والتصيد (Maltrail)",
            type = ThreatType.DOMAIN,
            url = "https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt",
            localFileName = "maltrail_domains.txt",
            category = "Malware / Phishing"
        ),
        ThreatFeedDescriptor(
            id = FEED_ID_EMERGING_THREATS,
            name = "Emerging Threats IP Blacklist",
            nameAr = "عناوين وشبكات البوتنت وخوادم الهجوم (Emerging Threats)",
            type = ThreatType.IP,
            url = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
            localFileName = "emerging_threats_ips.txt",
            category = "Botnet C2 / Attacker"
        ),
        ThreatFeedDescriptor(
            id = FEED_ID_DIGITALSIDE,
            name = "DigitalSide Threat-Intel IPs",
            nameAr = "خوادم القيادة والتحكم C2 (DigitalSide)",
            type = ThreatType.IP,
            url = "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestips.txt",
            localFileName = "digitalside_ips.txt",
            category = "C2 Server / Malware"
        )
    )
}
