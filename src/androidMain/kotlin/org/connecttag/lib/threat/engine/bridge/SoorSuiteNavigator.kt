package org.connecttag.lib.threat.engine.bridge

import android.content.Context
import android.content.Intent
import android.net.Uri
import org.connecttag.lib.threat.engine.contract.SecurityIpcContract
import org.connecttag.lib.threat.engine.model.ThreatReport
import org.connecttag.lib.threat.engine.model.ThreatSeverity

/**
 * Android Companion Navigation and Automated Quarantine Broadcaster for the Soor Suite.
 * Connects SoorNet, Hazm, and SoorDefender via Intent Deep Links and Signature-level IPC broadcasts.
 */
public object SoorSuiteNavigator {

    public fun isPackageInstalled(context: Context, packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0) != null
        } catch (_: Exception) {
            false
        }
    }

    public fun getInstalledSoorNetPackage(context: Context): String? {
        return SecurityIpcContract.SOORNET_PACKAGES.firstOrNull { isPackageInstalled(context, it) }
    }

    public fun isSoorNetInstalled(context: Context): Boolean = getInstalledSoorNetPackage(context) != null

    public fun getInstalledHazmPackage(context: Context): String? {
        return SecurityIpcContract.HAZM_PACKAGES.firstOrNull { isPackageInstalled(context, it) }
    }

    public fun isHazmInstalled(context: Context): Boolean = getInstalledHazmPackage(context) != null

    public fun getInstalledDefenderPackage(context: Context): String? {
        return SecurityIpcContract.SOORDEFENDER_PACKAGES.firstOrNull { isPackageInstalled(context, it) }
    }

    public fun isSoorDefenderInstalled(context: Context): Boolean = getInstalledDefenderPackage(context) != null

    /**
     * Opens an official download/info web page for SoorNet.
     */
    public fun openSoorNetDownloadPage(context: Context): Boolean {
        return try {
            val webIntent = Intent(Intent.ACTION_VIEW, Uri.parse(SecurityIpcContract.SOORNET_OFFICIAL_URL)).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(webIntent)
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Opens SoorNet firewall rules editor for target package.
     */
    public fun openSoorNetFirewallRules(
        context: Context,
        targetPackageName: String,
        fallbackToDownload: Boolean = false
    ): Boolean {
        val installedPkg = getInstalledSoorNetPackage(context)
        if (installedPkg == null) {
            if (fallbackToDownload) openSoorNetDownloadPage(context)
            return false
        }
        return try {
            val deepLinkUri = Uri.parse(SecurityIpcContract.buildSoorNetRulesUri(targetPackageName))
            val intent = Intent(Intent.ACTION_VIEW, deepLinkUri).apply {
                `package` = installedPkg
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (intent.resolveActivity(context.packageManager) != null) {
                context.startActivity(intent)
                true
            } else {
                if (fallbackToDownload) openSoorNetDownloadPage(context)
                false
            }
        } catch (_: Exception) {
            if (fallbackToDownload) openSoorNetDownloadPage(context)
            false
        }
    }

    /**
     * Opens SoorNet live traffic and socket logs for target package.
     */
    public fun openSoorNetTrafficLogs(
        context: Context,
        targetPackageName: String,
        fallbackToDownload: Boolean = false
    ): Boolean {
        val installedPkg = getInstalledSoorNetPackage(context)
        if (installedPkg == null) {
            if (fallbackToDownload) openSoorNetDownloadPage(context)
            return false
        }
        return try {
            val deepLinkUri = Uri.parse(SecurityIpcContract.buildSoorNetTrafficUri(targetPackageName))
            val intent = Intent(Intent.ACTION_VIEW, deepLinkUri).apply {
                `package` = installedPkg
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (intent.resolveActivity(context.packageManager) != null) {
                context.startActivity(intent)
                true
            } else {
                if (fallbackToDownload) openSoorNetDownloadPage(context)
                false
            }
        } catch (_: Exception) {
            if (fallbackToDownload) openSoorNetDownloadPage(context)
            false
        }
    }

    /**
     * Opens a specific route inside SoorNet (e.g. settings, logs, dns, apps).
     */
    public fun openSoorNetRoute(context: Context, route: String): Boolean {
        val installedPkg = getInstalledSoorNetPackage(context) ?: return false
        return try {
            val deepLinkUri = Uri.parse(SecurityIpcContract.SoorNetRoutes.buildUri(route))
            val intent = Intent(Intent.ACTION_VIEW, deepLinkUri).apply {
                `package` = installedPkg
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (intent.resolveActivity(context.packageManager) != null) {
                context.startActivity(intent)
                true
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Opens deep APK audit and components in Hazm.
     */
    public fun openAppInHazm(context: Context, targetPackageName: String): Boolean {
        val installedPkg = getInstalledHazmPackage(context) ?: return false
        return try {
            val deepLinkUri = Uri.parse(SecurityIpcContract.buildHazmDetailUri(targetPackageName))
            val intent = Intent(SecurityIpcContract.ACTION_VIEW_APP_DETAIL).apply {
                `package` = installedPkg
                data = deepLinkUri
                putExtra("package_name", targetPackageName)
                putExtra("packageName", targetPackageName)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (intent.resolveActivity(context.packageManager) != null) {
                context.startActivity(intent)
                true
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Broadcasts a detected security threat to trigger Automated Security Quarantine in SoorNet.
     * Protected by signature-level permission `org.connecttag.soor.permission.SECURITY_IPC`.
     */
    public fun broadcastThreatDetected(context: Context, threat: ThreatReport): Boolean {
        val packageName = threat.packageName ?: return false
        if (threat.severity != ThreatSeverity.CRITICAL && threat.severity != ThreatSeverity.HIGH) {
            return false
        }

        return try {
            val intent = Intent(SecurityIpcContract.ACTION_THREAT_DETECTED).apply {
                putExtra(SecurityIpcContract.ThreatColumns.COLUMN_PACKAGE_NAME, packageName)
                putExtra(SecurityIpcContract.ThreatColumns.COLUMN_APP_NAME, threat.appName)
                putExtra(SecurityIpcContract.ThreatColumns.COLUMN_SEVERITY, threat.severity.name)
                putExtra(SecurityIpcContract.ThreatColumns.COLUMN_CATEGORY, threat.category.name)
                putExtra(SecurityIpcContract.ThreatColumns.COLUMN_TITLE, threat.title)
                putExtra(SecurityIpcContract.ThreatColumns.COLUMN_DESCRIPTION, threat.description)
                putExtra(SecurityIpcContract.ThreatColumns.COLUMN_RISK_SCORE, threat.riskScore)
            }
            context.sendBroadcast(intent, SecurityIpcContract.PERMISSION_SECURITY_IPC)
            true
        } catch (_: Exception) {
            false
        }
    }
}
