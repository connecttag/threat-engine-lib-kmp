package org.connecttag.lib.threat.engine.model

import kotlinx.serialization.Serializable

/**
 * Standardized Risk Levels across SoorNet, Hazm, and Cloudflare Threat Intelligence (SSOT).
 */
@Serializable
public enum class RiskLevel {
    SAFE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

@Serializable
public enum class ThreatSeverity {
    SAFE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    public companion object {
        public fun fromString(value: String?): ThreatSeverity {
            if (value.isNullOrBlank()) return LOW
            return entries.firstOrNull { it.name.equals(value.trim(), ignoreCase = true) } ?: LOW
        }
    }
}

/**
 * Cyber Threat Classification Categories across network and application security.
 */
@Serializable
public enum class ThreatCategory {
    SAFE,
    PHISHING,
    MALWARE,
    MALWARE_SIGNATURE,
    BOTNET_C2,
    SPYWARE,
    BANKING_TROJAN,
    RANSOMWARE,
    ACCESSIBILITY_ABUSE,
    OVERLAY_HIJACK,
    SUSPICIOUS_SIDELOAD,
    SUSPICIOUS_HEURISTIC,
    MALICIOUS_APK_FILE,
    SCAM,
    ADWARE,
    SUSPICIOUS,
    TRACKER,
    UNKNOWN;

    public companion object {
        public fun fromString(value: String?): ThreatCategory {
            if (value.isNullOrBlank()) return UNKNOWN
            return entries.firstOrNull { it.name.equals(value.trim(), ignoreCase = true) } ?: UNKNOWN
        }
    }
}

/**
 * Unified Threat Report Model exchanged between Soor Suite apps and cloud services.
 */
@Serializable
public data class ThreatReport(
    val id: Long = 0L,
    val packageName: String? = null,
    val appName: String? = null,
    val filePath: String? = null,
    val fileHashSha256: String? = null,
    val severity: ThreatSeverity = ThreatSeverity.HIGH,
    val category: ThreatCategory = ThreatCategory.SUSPICIOUS,
    val title: String = "",
    val description: String = "",
    val detectedAt: Long = 0L,
    val isResolved: Boolean = false,
    val isInstalledApp: Boolean = true,
    val riskScore: Int = 0
)

/**
 * Cross-Platform OS Permission Model (Android, iOS, Windows)
 * Aligned with datacenter-threat-intel-db table `osPermissions`.
 */
@Serializable
public data class OsPermissionModel(
    val name: String,
    val platform: String = "ANDROID",
    val category: String = "GENERAL",
    val riskLevel: RiskLevel = RiskLevel.SAFE,
    val titleAr: String = "",
    val titleEn: String = "",
    val descriptionAr: String = "",
    val descriptionEn: String = "",
    val isDangerous: Boolean = false
)

/**
 * Anonymous Community Threat Report Request Payload (Zero-PII).
 * Sent to POST /threats/report on soor-api.
 */
@Serializable
public data class CommunityThreatReport(
    val target: String,
    val type: String = "DOMAIN",
    val category: String = "phishing",
    val reason: String = "",
    val riskLevel: String = "HIGH",
    val severityScore: Int = 75
)

/**
 * Result returned by the edge worker when a community report is accepted.
 */
@Serializable
public data class CommunityThreatReportResult(
    val id: Long? = null,
    val target: String,
    val normalizedValue: String = "",
    val type: String = "DOMAIN",
    val category: String = "phishing",
    val riskLevel: String = "HIGH",
    val isNew: Boolean = true,
    val status: String = "",
    val message: String = ""
)

/**
 * Result of checking an item (domain, IP, or package) against Threat Intel API.
 */
@Serializable
public data class RemoteThreatVerdict(
    val item: String,
    val target: String = "",
    val type: String = "",
    val isThreat: Boolean = false,
    val riskLevel: RiskLevel = RiskLevel.SAFE,
    val category: String = "",
    val description: String? = null,
    val source: String? = null
)

/**
 * Result of resolving a domain via the SoorNet Encrypted DoH Gateway.
 */
@Serializable
public data class DohResolutionVerdict(
    val status: Int = 0,
    val domain: String,
    val isBlocked: Boolean = false,
    val action: String = "RESOLVED",
    val resolvedIp: String? = null,
    val threatCategory: String? = null,
    val threatRisk: String? = null
)
