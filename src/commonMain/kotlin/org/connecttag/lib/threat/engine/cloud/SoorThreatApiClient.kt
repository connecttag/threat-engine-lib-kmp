package org.connecttag.lib.threat.engine.cloud

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.connecttag.lib.threat.engine.model.CommunityThreatReport
import org.connecttag.lib.threat.engine.model.CommunityThreatReportResult
import org.connecttag.lib.threat.engine.model.DohResolutionVerdict
import org.connecttag.lib.threat.engine.model.OsPermissionModel
import org.connecttag.lib.threat.engine.model.RemoteThreatVerdict
import org.connecttag.lib.threat.engine.model.RiskLevel

/**
 * Interface for SoorNet Edge Threat Intelligence API Client.
 * Connects to Cloudflare Workers edge (https://api.soornet.connecttag.app).
 */
public interface ISoorThreatApiClient {
    public suspend fun checkDomain(domain: String): RemoteThreatVerdict?
    public suspend fun checkIp(ip: String): RemoteThreatVerdict?
    public suspend fun checkPackage(packageName: String): RemoteThreatVerdict?
    public suspend fun reportThreat(report: CommunityThreatReport): CommunityThreatReportResult?
    public suspend fun getOsPermissions(platform: String = "ANDROID"): List<OsPermissionModel>
    public suspend fun resolveDns(domain: String, type: String = "A"): DohResolutionVerdict?
}

/**
 * Functional HTTP transport contract to maintain 100% KMP purity without binding to a single HTTP client.
 */
public fun interface HttpTransport {
    public suspend fun execute(method: String, url: String, headers: Map<String, String>, body: String?): HttpResponse
}

public data class HttpResponse(
    val statusCode: Int,
    val headers: Map<String, String>,
    val body: String?
)

/**
 * Reference Implementation of SoorThreatApiClient.
 */
public class SoorThreatApiClient(
    private val transport: HttpTransport,
    private val baseUrl: String = DEFAULT_BASE_URL,
    private val json: Json = Json { ignoreUnknownKeys = true; isLenient = true }
) : ISoorThreatApiClient {

    public companion object {
        public const val DEFAULT_BASE_URL: String = "https://api.soornet.connecttag.app"
    }

    override suspend fun checkDomain(domain: String): RemoteThreatVerdict? {
        val cleanDomain = domain.trim().lowercase().removePrefix("https://").removePrefix("http://").substringBefore('/')
        val url = "$baseUrl/threats/domain/$cleanDomain"
        val res = transport.execute("GET", url, emptyMap(), null)
        if (res.statusCode != 200 || res.body.isNullOrBlank()) return null

        return parseThreatVerdict(cleanDomain, "DOMAIN", res.body)
    }

    override suspend fun checkIp(ip: String): RemoteThreatVerdict? {
        val cleanIp = ip.trim()
        val url = "$baseUrl/threats/ip/$cleanIp"
        val res = transport.execute("GET", url, emptyMap(), null)
        if (res.statusCode != 200 || res.body.isNullOrBlank()) return null

        return parseThreatVerdict(cleanIp, "IP", res.body)
    }

    override suspend fun checkPackage(packageName: String): RemoteThreatVerdict? {
        val cleanPkg = packageName.trim().lowercase()
        val url = "$baseUrl/threats/package/$cleanPkg"
        val res = transport.execute("GET", url, emptyMap(), null)
        if (res.statusCode != 200 || res.body.isNullOrBlank()) return null

        return parseThreatVerdict(cleanPkg, "PACKAGE", res.body)
    }

    override suspend fun reportThreat(report: CommunityThreatReport): CommunityThreatReportResult? {
        val url = "$baseUrl/threats/report"
        val headers = mapOf("Content-Type" to "application/json")
        val jsonBody = """
            {
                "target": "${report.target}",
                "type": "${report.type}",
                "category": "${report.category}",
                "reason": "${report.reason.replace("\"", "\\\"")}",
                "riskLevel": "${report.riskLevel}",
                "severityScore": ${report.severityScore}
            }
        """.trimIndent()

        val res = transport.execute("POST", url, headers, jsonBody)
        if (res.statusCode != 200 || res.body.isNullOrBlank()) return null

        return try {
            val root = json.parseToJsonElement(res.body).jsonObject
            val result = root["result"]?.jsonObject ?: return null

            CommunityThreatReportResult(
                id = result["id"]?.jsonPrimitive?.contentOrNull?.toLongOrNull(),
                target = result["target"]?.jsonPrimitive?.contentOrNull ?: report.target,
                normalizedValue = result["normalizedValue"]?.jsonPrimitive?.contentOrNull ?: "",
                type = result["type"]?.jsonPrimitive?.contentOrNull ?: report.type,
                category = result["category"]?.jsonPrimitive?.contentOrNull ?: report.category,
                riskLevel = result["riskLevel"]?.jsonPrimitive?.contentOrNull ?: report.riskLevel,
                isNew = result["isNew"]?.jsonPrimitive?.booleanOrNull ?: true,
                status = result["status"]?.jsonPrimitive?.contentOrNull ?: "ACCEPTED",
                message = result["message"]?.jsonPrimitive?.contentOrNull ?: ""
            )
        } catch (e: Exception) {
            null
        }
    }

    override suspend fun getOsPermissions(platform: String): List<OsPermissionModel> {
        val url = "$baseUrl/security/bundle?platform=${platform.uppercase()}"
        val res = transport.execute("GET", url, emptyMap(), null)
        if (res.statusCode != 200 || res.body.isNullOrBlank()) return emptyList()

        return try {
            val root = json.parseToJsonElement(res.body).jsonObject
            val result = root["result"]?.jsonObject
            val permArray = result?.get("permissions")?.jsonArray ?: return emptyList()

            permArray.mapNotNull { elem ->
                val obj = elem.jsonObject
                val name = obj["permissionName"]?.jsonPrimitive?.contentOrNull
                    ?: obj["name"]?.jsonPrimitive?.contentOrNull ?: return@mapNotNull null
                val plat = obj["platform"]?.jsonPrimitive?.contentOrNull ?: platform
                val cat = obj["category"]?.jsonPrimitive?.contentOrNull ?: "GENERAL"
                val riskStr = obj["riskLevel"]?.jsonPrimitive?.contentOrNull ?: "SAFE"
                val risk = runCatching { RiskLevel.valueOf(riskStr.uppercase()) }.getOrDefault(RiskLevel.SAFE)

                OsPermissionModel(
                    name = name,
                    platform = plat,
                    category = cat,
                    riskLevel = risk,
                    titleAr = obj["titleAr"]?.jsonPrimitive?.contentOrNull ?: "",
                    titleEn = obj["titleEn"]?.jsonPrimitive?.contentOrNull ?: "",
                    descriptionAr = obj["descriptionAr"]?.jsonPrimitive?.contentOrNull ?: "",
                    descriptionEn = obj["descriptionEn"]?.jsonPrimitive?.contentOrNull ?: "",
                    isDangerous = risk == RiskLevel.HIGH || risk == RiskLevel.CRITICAL
                )
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    override suspend fun resolveDns(domain: String, type: String): DohResolutionVerdict? {
        val cleanDomain = domain.trim().lowercase().removePrefix("https://").removePrefix("http://")
        val url = "$baseUrl/dns-query?name=$cleanDomain&type=$type"
        val headers = mapOf("Accept" to "application/dns-json")
        val res = transport.execute("GET", url, headers, null)
        if (res.statusCode != 200 || res.body.isNullOrBlank()) return null

        val action = res.headers["x-dns-action"] ?: res.headers["X-DNS-Action"] ?: "RESOLVED"
        val isBlocked = action.equals("BLOCKED", ignoreCase = true)

        return try {
            val root = json.parseToJsonElement(res.body).jsonObject
            val status = root["Status"]?.jsonPrimitive?.intOrNull ?: 0
            val answers = root["Answer"]?.jsonArray
            val firstIp = answers?.firstOrNull()?.jsonObject?.get("data")?.jsonPrimitive?.contentOrNull

            val soorNetObj = root["SoorNet"]?.jsonObject
            val cat = soorNetObj?.get("category")?.jsonPrimitive?.contentOrNull
                ?: res.headers["x-threat-category"]
            val threatRisk = soorNetObj?.get("riskLevel")?.jsonPrimitive?.contentOrNull
                ?: res.headers["x-threat-risk"]

            DohResolutionVerdict(
                status = status,
                domain = cleanDomain,
                isBlocked = isBlocked,
                action = action,
                resolvedIp = firstIp,
                threatCategory = cat,
                threatRisk = threatRisk
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun parseThreatVerdict(item: String, type: String, body: String): RemoteThreatVerdict? {
        return try {
            val root = json.parseToJsonElement(body).jsonObject
            val result = root["result"]?.jsonObject ?: return null

            val isThreat = result["isThreat"]?.jsonPrimitive?.booleanOrNull ?: false
            val riskStr = result["riskLevel"]?.jsonPrimitive?.contentOrNull ?: "SAFE"
            val risk = runCatching { RiskLevel.valueOf(riskStr.uppercase()) }.getOrDefault(RiskLevel.SAFE)
            val cat = result["category"]?.jsonPrimitive?.contentOrNull ?: ""

            val details = result["threatDetails"]?.jsonObject
            val desc = details?.get("description")?.jsonPrimitive?.contentOrNull
            val src = details?.get("source")?.jsonPrimitive?.contentOrNull

            RemoteThreatVerdict(
                item = item,
                target = item,
                type = type,
                isThreat = isThreat,
                riskLevel = risk,
                category = cat,
                description = desc,
                source = src
            )
        } catch (e: Exception) {
            null
        }
    }
}
