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
public enum class ThreatSeverity(public val levelScore: Int, public val displayNameAr: String) {
    SAFE(0, "آمن"),
    LOW(20, "منخفض الخطورة"),
    MEDIUM(50, "متوسط الخطورة"),
    HIGH(75, "عالي الخطورة"),
    CRITICAL(100, "تهديد حرج / خبيث");

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
public enum class ThreatCategory(public val displayNameAr: String, public val descriptionAr: String) {
    SAFE("آمن", "لا توجد أي شبهة أمنية"),
    PHISHING("تصيد احتيالي", "محاولة سرقة بيانات الاعتماد أو المعلومات الشخصية"),
    MALWARE("برمجية خبيثة", "برمجية ضارة تستهدف استغلال النظام وإلحاق الضرر"),
    MALWARE_SIGNATURE("برمجية خبيثة معروفة", "تطابق البصمة مع قاعدة بيانات الفيروسات والتروجانات المعروفة"),
    BOTNET_C2("شبكة روبوتات خبيثة", "اتصال بخوادم تحكم وسيطرة C2 مشبوهة"),
    SPYWARE("برمجية تجسس", "تطبيق يقوم بجمع البيانات والصوت والموقع والصور في الخلفية دون علم المستخدم"),
    BANKING_TROJAN("تروجان مصرفي", "تطبيق يحاول استهداف الحسابات البنكية والمحافظ المالية ومحاكاة شاشاتها"),
    RANSOMWARE("برمجية فدية", "محاولة تشفير أو قفل ملفات الهاتف وطلب فدية"),
    ACCESSIBILITY_ABUSE("إساءة استخدام إمكانية الوصول", "استغلال خدمات الوصول لمحاكاة النقرات وقراءة الشاشة خلسة"),
    OVERLAY_HIJACK("هجوم النوافذ العائمة", "الرسم فوق تطبيقات أخرى لخداع المستخدم وسرقة بيانات الدخول"),
    SUSPICIOUS_SIDELOAD("تطبيق خارجي مشبوه", "تثبيت من مصدر غير موثوق مع حزم أذونات حساسة مستهدفة"),
    SUSPICIOUS_HEURISTIC("سلوك مشبوه / مخاطر عالية", "نمط أذونات استثنائية يستوجب المراجعة والحذر"),
    MALICIOUS_APK_FILE("ملف APK خبيث بالتخزين", "حزمة تثبيت غير مثبتة موجودة بوحدة التخزين تحتوي على توقيع أو كود ضار"),
    SCAM("احتيال ونصب", "خداع المستخدم للحصول على أموال أو مكاسب غير مشروعة"),
    ADWARE("إعلانات مزعجة ومتطفلة", "عرض إعلانات قسرية واعتراض تجربة الاستخدام"),
    SUSPICIOUS("مشبوه", "سلوك غير اعتيادي يحتاج إلى تدقيق ومتابعة"),
    TRACKER("متتبع خصوصية", "مكتبة تتبع تجمع سلوك المستخدم ونشاطه"),
    UNKNOWN("غير محدد", "تصنيف غير معروف");

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
) {
    public companion object {
        public fun clean(packageName: String, appName: String): ThreatReport {
            return ThreatReport(
                packageName = packageName,
                appName = appName,
                filePath = null,
                fileHashSha256 = null,
                severity = ThreatSeverity.SAFE,
                category = ThreatCategory.SAFE,
                title = "تطبيق آمن",
                description = "لم يتم العثور على أي تهديدات أمنية أو سلوكيات مريبة.",
                isInstalledApp = true,
                riskScore = 0
            )
        }
    }
}

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
