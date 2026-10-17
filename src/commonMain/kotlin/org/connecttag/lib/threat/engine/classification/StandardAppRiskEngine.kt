package org.connecttag.lib.threat.engine.classification

import kotlinx.serialization.Serializable

/**
 * Standard Permission Risk Level (Pure Kotlin).
 */
@Serializable
public enum class StandardPermissionRisk {
    UNKNOWN,
    NONE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    public val isElevated: Boolean get() = this == HIGH || this == CRITICAL
}

/**
 * Standard Permission Assessment Descriptor.
 */
@Serializable
public data class StandardPermissionItem(
    val name: String,
    val risk: StandardPermissionRisk = StandardPermissionRisk.UNKNOWN,
    val isGranted: Boolean = true
)

/**
 * Reasons for security flags in static analysis.
 */
@Serializable
public enum class StandardAnalysisReason {
    MODIFIED_APP,
    USE_OFFICIAL_APP,
    SUSPICIOUS_APP,
    POSSIBLE_DATA_COLLECTION,
    CRITICAL_PERMISSION,
    HIGH_RISK_PERMISSIONS,
    UNVERIFIED_INSTALLER,
    ELEVATED_STATIC_RISK,
    LOW_STATIC_RISK,
    MANY_CRITICAL_PERMISSIONS,
    UNKNOWN_PERMISSIONS,
    POSSIBLE_APP_IMPERSONATION,
    UNEXPECTED_PERMISSIONS_FOR_CATEGORY
}

@Serializable
public data class StandardAnalysisFinding(
    val reason: StandardAnalysisReason,
    val permission: String? = null,
    val count: Int = 0
)

/**
 * Unified Result of Pure Static App Assessment.
 */
@Serializable
public data class StandardAppRiskVerdict(
    val packageName: String,
    val category: StandardAppCategory,
    val trust: StandardAppTrust,
    val riskScore: Int,
    val findings: List<StandardAnalysisFinding>,
    val isSpoofed: Boolean = false,
    val isSystemOrFamous: Boolean = false,
    val unexpectedPermissionCount: Int = 0
)

/**
 * Pure Kotlin Multiplatform Engine for evaluating context-aware application risk.
 * Shared between SoorNet and Hazm.
 */
public object StandardAppRiskEngine {

    public fun evaluate(
        packageName: String,
        appName: String? = null,
        isSystem: Boolean = false,
        installerPackage: String? = null,
        signatures: List<String> = emptyList(),
        permissions: List<StandardPermissionItem> = emptyList(),
        uid: Int = 10000
    ): StandardAppRiskVerdict {
        val category = AppClassificationPolicy.resolveCategory(
            packageName = packageName,
            appName = appName,
            isSystem = isSystem,
            uid = uid
        )

        // 1. Anti-Spoofing check
        val isSpoofed = AppClassificationPolicy.isPotentialAppImpersonation(
            packageName = packageName,
            installerPackage = installerPackage,
            isSystem = isSystem,
            signatures = signatures,
            appName = appName
        )

        if (isSpoofed) {
            val findings = listOf(
                StandardAnalysisFinding(StandardAnalysisReason.POSSIBLE_APP_IMPERSONATION),
                StandardAnalysisFinding(StandardAnalysisReason.SUSPICIOUS_APP),
                StandardAnalysisFinding(StandardAnalysisReason.USE_OFFICIAL_APP)
            )
            return StandardAppRiskVerdict(
                packageName = packageName,
                category = category,
                trust = StandardAppTrust.BLOCKED,
                riskScore = 90,
                findings = findings,
                isSpoofed = true,
                isSystemOrFamous = false
            )
        }

        // 2. Verified System or Globally Well-Known App
        val isSystemOrFamous = isSystem ||
            category == StandardAppCategory.SYSTEM ||
            category == StandardAppCategory.SYSTEM_CRITICAL ||
            category == StandardAppCategory.GOOGLE_SERVICES ||
            AppClassificationPolicy.isSystemOrWellKnownApp(
                packageName = packageName,
                isSystem = isSystem,
                appName = appName,
                installerPackage = installerPackage,
                signatures = signatures
            )

        if (isSystemOrFamous) {
            val findings = listOf(StandardAnalysisFinding(StandardAnalysisReason.LOW_STATIC_RISK))
            return StandardAppRiskVerdict(
                packageName = packageName,
                category = category,
                trust = StandardAppTrust.TRUSTED,
                riskScore = 0,
                findings = findings,
                isSpoofed = false,
                isSystemOrFamous = true
            )
        }

        // 3. Context-Aware Permission Evaluation for All Other Applications
        val unexpectedCritical = mutableListOf<String>()
        val unexpectedHigh = mutableListOf<String>()
        var expectedCriticalCount = 0
        var expectedHighCount = 0
        val unknown = permissions.count { it.risk == StandardPermissionRisk.UNKNOWN }

        permissions.forEach { perm ->
            val isExpected = AppClassificationPolicy.isPermissionExpectedForCategory(perm.name, category)
            when (perm.risk) {
                StandardPermissionRisk.CRITICAL -> {
                    if (isExpected) expectedCriticalCount++ else unexpectedCritical.add(perm.name)
                }
                StandardPermissionRisk.HIGH -> {
                    if (isExpected) expectedHighCount++ else unexpectedHigh.add(perm.name)
                }
                else -> Unit
            }
        }

        val base = when (category) {
            StandardAppCategory.SYSTEM_CRITICAL -> 0
            StandardAppCategory.SYSTEM -> 5
            StandardAppCategory.GOOGLE_SERVICES -> 10
            StandardAppCategory.MODIFIED_APPS -> 40
            StandardAppCategory.SUSPICIOUS -> 60
            StandardAppCategory.MALWARE -> 80
            else -> 20
        }
        val installerRisk = if (!isSystem && StandardInstallSourceTrust.fromInstaller(installerPackage) == StandardInstallSourceTrust.UNKNOWN) 15 else 0

        // Context-aware risk scoring:
        // Expected functional permissions have minimal overhead (+2 critical, +1 high)
        // Unexpected permissions (e.g. contacts in calculator/flashlight) trigger elevated risk (+20 critical, +10 high)
        val permissionRisk = (unexpectedCritical.size * 20) + (unexpectedHigh.size * 10) +
            (expectedCriticalCount * 2) + (expectedHighCount * 1)
        val risk = (base + permissionRisk + installerRisk).coerceIn(0, 100)
        val trust = StandardAppTrust.fromRiskScore(risk, category)

        val findings = buildList {
            if (category == StandardAppCategory.MODIFIED_APPS) {
                add(StandardAnalysisFinding(StandardAnalysisReason.MODIFIED_APP))
                add(StandardAnalysisFinding(StandardAnalysisReason.USE_OFFICIAL_APP))
            }
            if (category == StandardAppCategory.SUSPICIOUS) {
                add(StandardAnalysisFinding(StandardAnalysisReason.SUSPICIOUS_APP))
                add(StandardAnalysisFinding(StandardAnalysisReason.POSSIBLE_DATA_COLLECTION))
            }
            if (unexpectedCritical.isNotEmpty() || unexpectedHigh.isNotEmpty()) {
                add(
                    StandardAnalysisFinding(
                        StandardAnalysisReason.UNEXPECTED_PERMISSIONS_FOR_CATEGORY,
                        count = unexpectedCritical.size + unexpectedHigh.size
                    )
                )
            }
            unexpectedCritical.forEach {
                add(StandardAnalysisFinding(StandardAnalysisReason.CRITICAL_PERMISSION, permission = it))
            }
            if (unexpectedHigh.isNotEmpty()) {
                add(StandardAnalysisFinding(StandardAnalysisReason.HIGH_RISK_PERMISSIONS, count = unexpectedHigh.size))
            }
            if (installerRisk > 0) add(StandardAnalysisFinding(StandardAnalysisReason.UNVERIFIED_INSTALLER))
            if (unexpectedCritical.size > 2) add(StandardAnalysisFinding(StandardAnalysisReason.MANY_CRITICAL_PERMISSIONS, count = unexpectedCritical.size))
            if (unknown > 0) add(StandardAnalysisFinding(StandardAnalysisReason.UNKNOWN_PERMISSIONS, count = unknown))
            if (isEmpty()) add(
                StandardAnalysisFinding(
                    if (risk < 25) StandardAnalysisReason.LOW_STATIC_RISK else StandardAnalysisReason.ELEVATED_STATIC_RISK
                )
            )
        }

        return StandardAppRiskVerdict(
            packageName = packageName,
            category = category,
            trust = trust,
            riskScore = risk,
            findings = findings,
            isSpoofed = false,
            isSystemOrFamous = false,
            unexpectedPermissionCount = unexpectedCritical.size + unexpectedHigh.size
        )
    }
}
