package org.connecttag.lib.threat.engine.report

import kotlinx.serialization.Serializable
import org.connecttag.lib.threat.engine.classification.FleetPrivacyHealth

public enum class SecurityReportFormat(public val extension: String, public val mimeType: String, public val displayNameAr: String) {
    HTML("html", "text/html", "تقرير تفاعلي شامل (HTML)"),
    MD("md", "text/markdown", "مستند ماركداون (Markdown - MD)"),
    JSON("json", "application/json", "بيانات منظمة (JSON)"),
    TXT("txt", "text/plain", "نص منسق (TXT)"),
    CSV("csv", "text/csv", "جدول بيانات (CSV)")
}

@Serializable
public data class AppSecurityExportItem(
    val packageName: String,
    val appName: String,
    val category: String,
    val riskScore: Int,
    val isSystem: Boolean,
    val isSideloaded: Boolean = false,
    val targetSdk: Int = 0,
    val findings: List<String> = emptyList(),
    val permissions: List<String> = emptyList()
)

/**
 * Unified pure Kotlin multiplatform engine for generating structured security,
 * privacy, and device audit reports across ConnectTag Suite.
 */
public object UnifiedSecurityReportExporter {

    public fun exportSingleApp(
        app: AppSecurityExportItem,
        format: SecurityReportFormat,
        isArabic: Boolean = true
    ): String {
        return when (format) {
            SecurityReportFormat.JSON -> exportAppJson(app)
            SecurityReportFormat.MD -> exportAppMarkdown(app, isArabic)
            SecurityReportFormat.TXT -> exportAppText(app, isArabic)
            SecurityReportFormat.CSV -> exportAppCsv(listOf(app))
            SecurityReportFormat.HTML -> exportAppHtml(app, isArabic)
        }
    }

    public fun exportFleetReport(
        fleet: FleetPrivacyHealth,
        apps: List<AppSecurityExportItem>,
        format: SecurityReportFormat,
        isArabic: Boolean = true
    ): String {
        return when (format) {
            SecurityReportFormat.JSON -> exportFleetJson(fleet, apps)
            SecurityReportFormat.MD -> exportFleetMarkdown(fleet, apps, isArabic)
            SecurityReportFormat.TXT -> exportFleetText(fleet, apps, isArabic)
            SecurityReportFormat.CSV -> exportAppCsv(apps)
            SecurityReportFormat.HTML -> exportFleetHtml(fleet, apps, isArabic)
        }
    }

    private fun exportAppJson(app: AppSecurityExportItem): String {
        val findingsArray = app.findings.joinToString(",") { "\"${escapeJson(it)}\"" }
        val permsArray = app.permissions.joinToString(",") { "\"${escapeJson(it)}\"" }
        return """
        {
          "packageName": "${escapeJson(app.packageName)}",
          "appName": "${escapeJson(app.appName)}",
          "category": "${escapeJson(app.category)}",
          "riskScore": ${app.riskScore},
          "isSystem": ${app.isSystem},
          "isSideloaded": ${app.isSideloaded},
          "targetSdk": ${app.targetSdk},
          "findings": [$findingsArray],
          "permissions": [$permsArray]
        }
        """.trimIndent()
    }

    private fun exportFleetJson(fleet: FleetPrivacyHealth, apps: List<AppSecurityExportItem>): String {
        val appsJson = apps.joinToString(",\n") { exportAppJson(it) }
        return """
        {
          "fleetHealth": {
            "overallHealthScore": ${fleet.overallHealthScore},
            "totalAppsAnalyzed": ${fleet.totalAppsAnalyzed},
            "criticalRiskCount": ${fleet.criticalRiskCount},
            "highRiskCount": ${fleet.highRiskCount},
            "mediumRiskCount": ${fleet.mediumRiskCount},
            "safeCount": ${fleet.safeCount},
            "averageRiskScore": ${fleet.averageRiskScore},
            "ratingAr": "${escapeJson(fleet.ratingAr)}",
            "ratingEn": "${escapeJson(fleet.ratingEn)}"
          },
          "apps": [
            $appsJson
          ]
        }
        """.trimIndent()
    }

    private fun exportAppMarkdown(app: AppSecurityExportItem, isArabic: Boolean): String = buildString {
        if (isArabic) {
            appendLine("# تقرير الفحص الأمني للتطبيق: ${app.appName}")
            appendLine("- **الحزمة**: `${app.packageName}`")
            appendLine("- **التصنيف**: ${app.category}")
            appendLine("- **درجة الخطورة**: ${app.riskScore}/100")
            appendLine("- **تطبيق نظام**: ${if (app.isSystem) "نعم" else "لا"}")
            appendLine()
            appendLine("## الملاحظات الأمنية")
            if (app.findings.isEmpty()) {
                appendLine("- لا توجد مخاطر أو ملاحظات مسجلة.")
            } else {
                app.findings.forEach { appendLine("- $it") }
            }
        } else {
            appendLine("# Security Assessment Report: ${app.appName}")
            appendLine("- **Package**: `${app.packageName}`")
            appendLine("- **Category**: ${app.category}")
            appendLine("- **Risk Score**: ${app.riskScore}/100")
            appendLine("- **System App**: ${if (app.isSystem) "Yes" else "No"}")
            appendLine()
            appendLine("## Security Findings")
            if (app.findings.isEmpty()) {
                appendLine("- No threats or anomalies detected.")
            } else {
                app.findings.forEach { appendLine("- $it") }
            }
        }
    }

    private fun exportFleetMarkdown(
        fleet: FleetPrivacyHealth,
        apps: List<AppSecurityExportItem>,
        isArabic: Boolean
    ): String = buildString {
        if (isArabic) {
            appendLine("# تقرير الفحص الأمني الشامل للجهاز")
            appendLine("- **المؤشر الأمني الكلي**: ${fleet.overallHealthScore}/100 (${fleet.ratingAr})")
            appendLine("- **إجمالي التطبيقات المفحوصة**: ${fleet.totalAppsAnalyzed}")
            appendLine("- **تطبيقات عالية الخطورة**: ${fleet.criticalRiskCount + fleet.highRiskCount}")
            appendLine()
            appendLine("| التطبيق | الحزمة | التصنيف | درجة الخطورة |")
            appendLine("| :--- | :--- | :--- | :--- |")
            apps.forEach { app ->
                appendLine("| ${app.appName} | `${app.packageName}` | ${app.category} | ${app.riskScore} |")
            }
        } else {
            appendLine("# Device Fleet Security & Privacy Report")
            appendLine("- **Overall Health Score**: ${fleet.overallHealthScore}/100 (${fleet.ratingEn})")
            appendLine("- **Total Apps Analyzed**: ${fleet.totalAppsAnalyzed}")
            appendLine("- **High/Critical Threats**: ${fleet.criticalRiskCount + fleet.highRiskCount}")
            appendLine()
            appendLine("| App Name | Package | Category | Risk Score |")
            appendLine("| :--- | :--- | :--- | :--- |")
            apps.forEach { app ->
                appendLine("| ${app.appName} | `${app.packageName}` | ${app.category} | ${app.riskScore} |")
            }
        }
    }

    private fun exportAppText(app: AppSecurityExportItem, isArabic: Boolean): String = buildString {
        if (isArabic) {
            appendLine("تقرير أمني: ${app.appName} (${app.packageName})")
            appendLine("التصنيف: ${app.category} | درجة الخطورة: ${app.riskScore}/100")
            appendLine("الملاحظات:")
            app.findings.forEach { appendLine(" - $it") }
        } else {
            appendLine("Security Report: ${app.appName} (${app.packageName})")
            appendLine("Category: ${app.category} | Risk Score: ${app.riskScore}/100")
            appendLine("Findings:")
            app.findings.forEach { appendLine(" - $it") }
        }
    }

    private fun exportFleetText(fleet: FleetPrivacyHealth, apps: List<AppSecurityExportItem>, isArabic: Boolean): String = buildString {
        if (isArabic) {
            appendLine("=== تقرير التدقيق الأمني للجهاز ===")
            appendLine("مؤشر الأمان: ${fleet.overallHealthScore}/100 (${fleet.ratingAr})")
            appendLine("التطبيقات المفحوصة: ${fleet.totalAppsAnalyzed}")
            appendLine("التهديدات: ${fleet.criticalRiskCount + fleet.highRiskCount}")
            appendLine("----------------------------------------")
            apps.forEach { appendLine("${it.appName} [${it.packageName}] -> خطورة: ${it.riskScore}") }
        } else {
            appendLine("=== Device Fleet Security Report ===")
            appendLine("Health Score: ${fleet.overallHealthScore}/100 (${fleet.ratingEn})")
            appendLine("Total Apps: ${fleet.totalAppsAnalyzed}")
            appendLine("Elevated Threats: ${fleet.criticalRiskCount + fleet.highRiskCount}")
            appendLine("----------------------------------------")
            apps.forEach { appendLine("${it.appName} [${it.packageName}] -> Risk: ${it.riskScore}") }
        }
    }

    private fun exportAppCsv(apps: List<AppSecurityExportItem>): String = buildString {
        appendLine("PackageName,AppName,Category,RiskScore,IsSystem,IsSideloaded,TargetSdk")
        apps.forEach { app ->
            appendLine("\"${escapeCsv(app.packageName)}\",\"${escapeCsv(app.appName)}\",\"${escapeCsv(app.category)}\",${app.riskScore},${app.isSystem},${app.isSideloaded},${app.targetSdk}")
        }
    }

    private fun exportAppHtml(app: AppSecurityExportItem, isArabic: Boolean): String {
        val dir = if (isArabic) "rtl" else "ltr"
        val lang = if (isArabic) "ar" else "en"
        return """
        <!DOCTYPE html>
        <html lang="$lang" dir="$dir">
        <head>
          <meta charset="UTF-8">
          <title>${app.appName}</title>
          <style>
            body { font-family: system-ui, -apple-system, sans-serif; margin: 2rem; background: #0f172a; color: #f8fafc; }
            .card { background: #1e293b; border-radius: 12px; padding: 2rem; border: 1px solid #334155; }
            .badge { display: inline-block; padding: 4px 12px; border-radius: 999px; background: #ef4444; color: white; font-weight: bold; }
          </style>
        </head>
        <body>
          <div class="card">
            <h1>${app.appName}</h1>
            <p><code>${app.packageName}</code></p>
            <p><strong>${if (isArabic) "التصنيف:" else "Category:"}</strong> ${app.category}</p>
            <p><strong>${if (isArabic) "درجة الخطورة:" else "Risk Score:"}</strong> <span class="badge">${app.riskScore}/100</span></p>
          </div>
        </body>
        </html>
        """.trimIndent()
    }

    private fun exportFleetHtml(fleet: FleetPrivacyHealth, apps: List<AppSecurityExportItem>, isArabic: Boolean): String {
        val dir = if (isArabic) "rtl" else "ltr"
        val lang = if (isArabic) "ar" else "en"
        val rows = apps.joinToString("\n") {
            "<tr><td>${it.appName}</td><td><code>${it.packageName}</code></td><td>${it.category}</td><td>${it.riskScore}</td></tr>"
        }
        return """
        <!DOCTYPE html>
        <html lang="$lang" dir="$dir">
        <head>
          <meta charset="UTF-8">
          <title>${if (isArabic) "تقرير أمان الجهاز" else "Device Security Report"}</title>
          <style>
            body { font-family: system-ui, -apple-system, sans-serif; margin: 2rem; background: #0f172a; color: #f8fafc; }
            .card { background: #1e293b; border-radius: 12px; padding: 1.5rem; border: 1px solid #334155; margin-bottom: 2rem; }
            table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
            th, td { text-align: ${if (isArabic) "right" else "left"}; padding: 12px; border-bottom: 1px solid #334155; }
            th { background: #0f172a; }
          </style>
        </head>
        <body>
          <div class="card">
            <h1>${if (isArabic) "مؤشر الحماية والأمان للجهاز" else "Device Security Health"}</h1>
            <h2>${fleet.overallHealthScore}/100 - ${if (isArabic) fleet.ratingAr else fleet.ratingEn}</h2>
            <p>${if (isArabic) "التطبيقات المفحوصة:" else "Analyzed Apps:"} ${fleet.totalAppsAnalyzed}</p>
          </div>
          <table>
            <thead>
              <tr>
                <th>${if (isArabic) "التطبيق" else "App"}</th>
                <th>${if (isArabic) "الحزمة" else "Package"}</th>
                <th>${if (isArabic) "التصنيف" else "Category"}</th>
                <th>${if (isArabic) "درجة الخطورة" else "Risk"}</th>
              </tr>
            </thead>
            <tbody>
              $rows
            </tbody>
          </table>
        </body>
        </html>
        """.trimIndent()
    }

    private fun escapeJson(value: String): String = value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
    private fun escapeCsv(value: String): String = value.replace("\"", "\"\"")
}
