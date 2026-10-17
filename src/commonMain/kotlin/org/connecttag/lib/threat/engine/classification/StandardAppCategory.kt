package org.connecttag.lib.threat.engine.classification

import kotlinx.serialization.Serializable

/**
 * Standardized App Categories across ConnectTag Suite (SoorNet, Hazm, SoorDefender).
 * Pure Kotlin Multiplatform model (SSOT).
 */
@Serializable
public enum class StandardAppCategory {
    SYSTEM,
    SYSTEM_CRITICAL,
    GOOGLE_SERVICES,
    SOCIAL_MEDIA,
    MESSAGING,
    BROWSER,
    EMAIL,
    MEDIA,
    GAME,
    BANKING,
    WALLET,
    SHOPPING,
    PRODUCTIVITY,
    UTILITY,
    NAVIGATION,
    SECURITY,
    VPN,
    DEVELOPER_TOOLS,
    CALLER_ID,
    MODIFIED_APPS,
    SUSPICIOUS,
    MALWARE,
    ADWARE,
    TRACKER,
    USER_APP,
    UNKNOWN
}

/**
 * Standard Trust Levels evaluated for applications.
 */
@Serializable
public enum class StandardAppTrust {
    TRUSTED,
    NORMAL,
    CAUTION,
    SUSPICIOUS,
    BLOCKED;

    public companion object {
        public fun fromRiskScore(score: Int, category: StandardAppCategory? = null): StandardAppTrust = when {
            category == StandardAppCategory.SYSTEM_CRITICAL ||
                category == StandardAppCategory.SYSTEM ||
                category == StandardAppCategory.GOOGLE_SERVICES ||
                score < 25 -> TRUSTED
            score < 50 -> NORMAL
            score < 75 -> CAUTION
            score < 90 -> SUSPICIOUS
            else -> BLOCKED
        }
    }
}

/**
 * Canonical Install Source Trust categorization.
 */
@Serializable
public enum class StandardInstallSourceTrust {
    UNKNOWN,
    PLAY_STORE,
    THIRD_PARTY_STORE;

    public companion object {
        private val playInstallers = setOf("com.android.vending", "com.google.android.feedback")
        private val otherStoreInstallers = setOf(
            "com.sec.android.app.samsungapps",
            "com.huawei.appmarket",
            "com.amazon.venezia",
            "org.fdroid.fdroid",
            "org.fdroid.fdroid.privileged",
            "com.xiaomi.mipicks"
        )

        public fun fromInstaller(packageName: String?): StandardInstallSourceTrust {
            val identity = packageName?.trim()?.lowercase() ?: return UNKNOWN
            return when (identity) {
                in playInstallers -> PLAY_STORE
                in otherStoreInstallers -> THIRD_PARTY_STORE
                else -> UNKNOWN
            }
        }
    }
}
