package org.connecttag.lib.threat.engine.contract

/**
 * Single Source of Truth (SSOT) for Inter-Process Communication (IPC) contracts,
 * Signature-protected broadcast actions, ContentProvider URIs, and Deep Link schemes
 * connecting SoorNet, Hazm, and SoorDefender.
 */
public object SecurityIpcContract {

    /** Signature-level IPC permission required to broadcast or query security data */
    public const val PERMISSION_SECURITY_IPC: String = "org.connecttag.soor.permission.SECURITY_IPC"

    /** Broadcast action sent when Hazm or SoorDefender detects a critical threat */
    public const val ACTION_THREAT_DETECTED: String = "org.connecttag.soor.action.THREAT_DETECTED"

    /** Broadcast action notifying status change in security engine */
    public const val ACTION_DEFENDER_STATUS_CHANGED: String = "org.connecttag.soor.action.DEFENDER_STATUS_CHANGED"

    /** Action requesting an on-demand scan */
    public const val ACTION_REQUEST_DEFENDER_SCAN: String = "org.connecttag.soor.action.REQUEST_DEFENDER_SCAN"

    /** Action to open deep app audit in Hazm */
    public const val ACTION_VIEW_APP_DETAIL: String = "org.connecttag.hazm.action.VIEW_APP_DETAIL"

    // ContentProvider Authorities & Paths
    public const val AUTHORITY_HAZM_PROVIDER: String = "org.connecttag.hazm.security.provider"
    public const val AUTHORITY_DEFENDER_PROVIDER: String = "org.connecttag.soordefender.security.provider"

    public const val PATH_THREATS: String = "threats"
    public const val PATH_SCAN_STATUS: String = "scan_status"
    public const val PATH_SYSTEM_STATS: String = "system_stats"

    public fun buildContentUri(authority: String, path: String): String = "content://$authority/$path"

    // Deep Link Schemes & URLs
    public const val SCHEME_SOORNET: String = "soornet"
    public const val SCHEME_HAZM: String = "hazm"
    public const val SOORNET_OFFICIAL_URL: String = "https://connecttag.org/company/projects/apps/soornet/"

    // Known Package Names
    public val SOORNET_PACKAGES: List<String> = listOf(
        "org.connecttag.soornet",
        "org.connecttag.soornet.play",
        "org.connecttag.soornet.debug",
        "org.connecttag.soornet.automation",
        "org.connecttag.soornet.certificates",
        "org.connecttag.soornet.internal"
    )

    public val HAZM_PACKAGES: List<String> = listOf(
        "org.connecttag.hazm",
        "org.connecttag.hazm.pro",
        "org.connecttag.hazm.debug",
        "org.connecttag.hazm.pro.debug"
    )

    public val SOORDEFENDER_PACKAGES: List<String> = listOf(
        "org.connecttag.soordefender",
        "org.connecttag.soordefender.debug"
    )

    // Deep Link URIs
    public fun buildSoorNetRulesUri(packageName: String): String = "$SCHEME_SOORNET://rules/$packageName"
    public fun buildSoorNetTrafficUri(packageName: String): String = "$SCHEME_SOORNET://traffic/$packageName"
    public fun buildHazmDetailUri(packageName: String): String = "$SCHEME_HAZM://app/detail/$packageName"

    /** Standard Routes for SoorNet Deep Linking */
    public object SoorNetRoutes {
        public const val ROUTE_RULES: String = "rules"
        public const val ROUTE_TRAFFIC: String = "traffic"
        public const val ROUTE_SETTINGS: String = "settings"
        public const val ROUTE_LOGS: String = "logs"
        public const val ROUTE_DNS: String = "dns"
        public const val ROUTE_APPS: String = "apps"
        public const val ROUTE_HOSTS: String = "hosts"
        public const val ROUTE_UPDATE: String = "update"

        public fun buildUri(route: String): String = "$SCHEME_SOORNET://$route"
    }

    /** Standard Columns for Threat Data Exchange */
    public object ThreatColumns {
        public const val COLUMN_ID: String = "_id"
        public const val COLUMN_PACKAGE_NAME: String = "package_name"
        public const val COLUMN_APP_NAME: String = "app_name"
        public const val COLUMN_FILE_PATH: String = "file_path"
        public const val COLUMN_FILE_HASH: String = "file_hash"
        public const val COLUMN_SEVERITY: String = "severity"
        public const val COLUMN_CATEGORY: String = "category"
        public const val COLUMN_TITLE: String = "title"
        public const val COLUMN_DESCRIPTION: String = "description"
        public const val COLUMN_DETECTED_AT: String = "detected_at"
        public const val COLUMN_IS_RESOLVED: String = "is_resolved"
        public const val COLUMN_IS_INSTALLED: String = "is_installed"
        public const val COLUMN_RISK_SCORE: String = "risk_score"
    }

    /** Standard Columns for Defender Engine Status */
    public object StatusColumns {
        public const val COLUMN_REALTIME_ENABLED: String = "is_realtime_enabled"
        public const val COLUMN_LAST_SCAN_TIME: String = "last_scan_time"
        public const val COLUMN_TOTAL_FILES_SCANNED: String = "total_files_scanned"
        public const val COLUMN_TOTAL_APPS_SCANNED: String = "total_apps_scanned"
        public const val COLUMN_ACTIVE_THREATS_COUNT: String = "active_threats_count"
        public const val COLUMN_DEFENDER_VERSION: String = "defender_version"
    }
}
