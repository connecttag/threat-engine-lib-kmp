package org.connecttag.lib.threat.engine.classification

/**
 * Single Source of Truth for App Classification Catalogs, Official Signatures,
 * Dangerous Permission Groups, and Anti-Spoofing logic across SoorNet and Hazm.
 * Pure Kotlin Multiplatform (Zero android.* dependencies).
 */
public object AppClassificationPolicy {

    // ==========================================
    // App Package Name Lists
    // ==========================================
    public val MESSAGING_APPS: List<String> = listOf(
        "com.discord", "com.facebook.mlite", "com.facebook.orca",
        "com.instagram.android", "com.Slack", "com.skype.raider",
        "com.snapchat.android", "com.whatsapp", "com.whatsapp.w4b",
        "com.telegram", "com.viber.voip", "com.tencent.mm",
        "org.thoughtcrime.securesms", "com.threema"
    )

    public val DOWNLOAD_APPS: List<String> = listOf(
        "com.google.android.youtube",
        "com.android.providers.downloads",
        "com.android.chrome",
        "org.mozilla.firefox",
        "com.utorrent.client",
        "com.torrent.client",
        "com.accuweather.android",
        "com.spotify.music"
    )

    public val SOCIAL_MEDIA_APPS: List<String> = listOf(
        "com.facebook.katana",
        "com.instagram.android",
        "com.twitter.android",
        "com.linkedin.android",
        "com.pinterest"
    )

    public val DEFAULT_BLACKLISTED_APPS: List<String> = listOf(
        "com.zhiliaoapp.musically",
        "com.ss.android.ugc.trill",
        "com.lenovo.anyshare.gps",
        "com.uc.browser.en",
        "com.cleanmaster.master",
        "com.duapps.cleaner",
        "com.cmcm.locker"
    )

    public val GAME_PACKAGE_PREFIXES: List<String> = listOf(
        "com.activision", "com.ea.", "com.gameloft.", "com.supercell",
        "com.epicgames", "com.riotgames", "com.ubisoft", "com.tencent.ig",
        "com.dts.freefireth", "com.pubg", "com.mojang.minecraftpe"
    )

    public val GAME_KEYWORDS: List<String> = listOf("game", "لعبة", "games", "ألعاب")

    public val NAVIGATION_APPS: List<String> = listOf(
        "com.google.android.apps.maps", "com.google.android.apps.mapslite",
        "com.waze", "com.here.app.maps", "com.yandex.yandexnavi",
        "cz.seznam.mapy", "com.mapswithme.maps.pro", "net.osmand", "net.osmand.plus"
    )

    public val NAVIGATION_KEYWORDS: List<String> = listOf("maps", "navigation", "gps", "ملاحة", "خرائط")

    public val FINANCIAL_KEYWORDS: List<String> = listOf(
        "bank", "wallet", "pay", "finance", "money", "credit", "cash",
        "بنك", "مصرف", "كريمي", "فلوس", "جيب", "ون كاش", "فلوسك", "محفظة"
    )

    public val CALLER_ID_KEYWORDS: List<String> = listOf(
        "هوية المتصل", "كاشف", "دليل", "يمن فون",
        "caller id", "whocalls", "truecaller", "numberbook"
    )

    public val MODIFIED_APP_KEYWORDS: List<String> = listOf(
        "واتساب الذهبي", "واتساب عمر", "واتس اب عمر", "واتس الذهبي",
        "gbwhatsapp", "yo_whatsapp", "fmwhatsapp", "whatsapp_plus", "ogwhatsapp", "instander"
    )

    public val DANGEROUS_PERMISSION_GROUPS: List<String> = listOf(
        "SMS", "CAMERA", "LOCATION", "CONTACTS", "PHONE",
        "MICROPHONE", "STORAGE", "RECORD_AUDIO", "CALL_PHONE"
    )

    public val KNOWN_TECH_PROVIDERS: List<String> = listOf(
        "Google", "Amazon", "AWS", "Microsoft", "Azure",
        "Facebook", "Cloudflare", "CloudFront", "Akamai", "Fastly"
    )

    // ==========================================
    // Globally Famous & Well-Known Applications
    // ==========================================
    public val GLOBALLY_FAMOUS_PACKAGES: Set<String> = setOf(
        // WhatsApp & Meta
        "com.whatsapp", "com.whatsapp.w4b",
        "com.facebook.katana", "com.facebook.lite", "com.facebook.orca", "com.facebook.mlite",
        "com.instagram.android", "com.instagram.lite", "com.instagram.barcelona",
        "com.facebook.services", "com.facebook.appmanager", "com.facebook.system",
        // Telegram & Signal
        "org.telegram.messenger", "org.telegram.messenger.web", "org.telegram.plus",
        "org.thoughtcrime.securesms", "com.threema",
        // Social Media
        "com.twitter.android", "com.twitter.android.lite",
        "com.snapchat.android",
        "com.zhiliaoapp.musically", "com.ss.android.ugc.trill",
        "com.reddit.frontpage", "com.discord", "com.Slack",
        "com.linkedin.android", "com.linkedin.android.lite",
        "com.pinterest", "com.tumblr",
        "com.viber.voip", "com.tencent.mm", "jp.naver.line.android",
        "us.zoom.videomeetings", "com.skype.raider", "com.skype.m2",
        "tv.twitch.android.app",
        // Browsers
        "com.android.chrome",
        "org.mozilla.firefox", "org.mozilla.firefox_beta", "org.mozilla.focus",
        "com.opera.browser", "com.opera.mini.native", "com.opera.touch", "com.opera.gx",
        "com.brave.browser", "com.microsoft.emmx", "com.sec.android.app.sbrowser",
        "com.duckduckgo.mobile.android", "com.vivaldi.browser", "org.torproject.torbrowser",
        // Media & Streaming
        "com.google.android.youtube", "com.google.android.apps.youtube.music", "com.google.android.apps.youtube.kids",
        "com.spotify.music", "com.spotify.lite",
        "com.netflix.mediaclient", "com.netflix.ninja",
        "com.amazon.avod.thirdpartyclient", "com.disney.disneyplus",
        "com.soundcloud.android", "com.shazam.android", "deezer.android.app", "com.anghami",
        // Productivity, Cloud & Tools
        "com.dropbox.android",
        "com.adobe.reader", "com.adobe.scan.android", "com.adobe.lrmobile", "com.adobe.psmobile",
        "com.canva.editor", "notion.id", "com.trello", "com.evernote",
        "com.duolingo", "org.wikipedia", "org.zwanoo.android.speedtest",
        "com.truecaller", "com.intsig.camscanner", "cn.wps.moffice_eng",
        "com.x8bit.bitwarden", "com.onepassword.android", "com.lastpass.lpandroid", "com.github.android",
        // Shopping, Travel, Payments
        "com.amazon.mShop.android.shopping", "com.alibaba.aliexpresshd", "com.ebay.mobile",
        "com.ubercab", "com.ubercab.eats", "com.booking", "com.airbnb.android",
        "com.paypal.android.p2pmobile"
    )

    public val GLOBALLY_FAMOUS_PACKAGE_PREFIXES: List<String> = listOf(
        "com.google.android.",
        "com.google.",
        "com.microsoft.",
        "com.android.",
        "org.telegram.",
        "com.facebook.",
        "com.whatsapp",
        "org.mozilla.",
        "com.spotify.",
        "com.netflix.",
        "com.amazon.",
        "com.adobe."
    )

    public val SYSTEM_PACKAGE_PREFIXES: List<String> = listOf(
        "android",
        "com.android.",
        "com.google.android.",
        "com.samsung.",
        "com.sec.android.",
        "com.miui.",
        "com.xiaomi.",
        "com.huawei.",
        "com.oppo.",
        "com.coloros.",
        "com.vivo.",
        "com.oneplus.",
        "com.transsion.",
        "com.motorola.",
        "com.lge.",
        "com.sony.",
        "com.asus.",
        "com.realme.",
        "com.hihonor.",
        "com.qualcomm.",
        "com.mediatek."
    )

    // ==========================================
    // Category Matchers
    // ==========================================
    public fun isGameApp(packageName: String, appName: String? = null, category: Int? = null): Boolean {
        if (category == 0) return true
        val lowerPkg = packageName.lowercase()
        if (GAME_PACKAGE_PREFIXES.any { lowerPkg.startsWith(it) }) return true
        if (GAME_KEYWORDS.any { lowerPkg.contains(it) }) return true
        if (!appName.isNullOrBlank() && GAME_KEYWORDS.any { appName.contains(it, ignoreCase = true) }) return true
        return false
    }

    public fun isMessagingApp(packageName: String, appName: String? = null): Boolean {
        val lowerPkg = packageName.lowercase()
        if (MESSAGING_APPS.any { lowerPkg.startsWith(it) }) return true
        val messagingKeywords = listOf("whatsapp", "telegram", "signal", "viber", "line", "discord", "slack")
        if (messagingKeywords.any { lowerPkg.contains(it) }) return true
        if (!appName.isNullOrBlank() && messagingKeywords.any { appName.contains(it, ignoreCase = true) }) return true
        return false
    }

    public fun isSocialMediaApp(packageName: String, appName: String? = null): Boolean {
        val lowerPkg = packageName.lowercase()
        if (SOCIAL_MEDIA_APPS.any { lowerPkg.startsWith(it) }) return true
        val socialKeywords = listOf("facebook", "instagram", "twitter", "snapchat", "tiktok", "linkedin")
        if (socialKeywords.any { lowerPkg.contains(it) }) return true
        if (!appName.isNullOrBlank() && socialKeywords.any { appName.contains(it, ignoreCase = true) }) return true
        return false
    }

    public fun isMediaApp(packageName: String, appName: String? = null): Boolean {
        val mediaKeywords = listOf("youtube", "netflix", "spotify", "soundcloud", "twitch")
        return mediaKeywords.any {
            packageName.contains(it, ignoreCase = true) ||
                appName?.contains(it, ignoreCase = true) == true
        }
    }

    public fun isDownloadApp(packageName: String): Boolean {
        val lowerPkg = packageName.lowercase()
        return DOWNLOAD_APPS.any { lowerPkg.startsWith(it) }
    }

    public fun isNavigationApp(packageName: String, appName: String? = null): Boolean {
        val lowerPkg = packageName.lowercase()
        if (NAVIGATION_APPS.any { lowerPkg.startsWith(it) }) return true
        if (NAVIGATION_KEYWORDS.any { lowerPkg.contains(it) }) return true
        if (!appName.isNullOrBlank() && NAVIGATION_KEYWORDS.any { appName.contains(it, ignoreCase = true) }) return true
        return false
    }

    public fun isModifiedApp(packageName: String, appName: String? = null): Boolean {
        val lowerPkg = packageName.lowercase()
        val lowerName = appName?.lowercase().orEmpty()
        if (MODIFIED_APP_KEYWORDS.any { lowerPkg.contains(it) || lowerName.contains(it) }) return true
        if (lowerPkg.contains("gbwhatsapp") || lowerPkg.contains("whatsappplus") || lowerPkg.contains("instander")) return true
        return false
    }

    public fun isWellKnownGlobalApp(packageName: String, appName: String? = null): Boolean {
        if (packageName.isBlank()) return false
        val lowerPkg = packageName.lowercase()
        if (isModifiedApp(lowerPkg, appName)) return false

        if (lowerPkg in GLOBALLY_FAMOUS_PACKAGES) return true
        if (GLOBALLY_FAMOUS_PACKAGE_PREFIXES.any { lowerPkg.startsWith(it) }) return true
        if (SYSTEM_PACKAGE_PREFIXES.any { lowerPkg.startsWith(it) }) return true

        return false
    }

    // ==========================================
    // Canonical Permission Groups for Context-Aware Evaluation
    // ==========================================
    public object PermissionGroups {
        public val CAMERA: Set<String> = setOf(
            "android.permission.CAMERA"
        )
        public val MICROPHONE: Set<String> = setOf(
            "android.permission.RECORD_AUDIO",
            "android.permission.CAPTURE_AUDIO_OUTPUT"
        )
        public val LOCATION: Set<String> = setOf(
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.ACCESS_MEDIA_LOCATION"
        )
        public val CONTACTS: Set<String> = setOf(
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.GET_ACCOUNTS"
        )
        public val PHONE_CALLS: Set<String> = setOf(
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.PROCESS_OUTGOING_CALLS"
        )
        public val SMS: Set<String> = setOf(
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.RECEIVE_MMS",
            "android.permission.RECEIVE_WAP_PUSH"
        )
        public val STORAGE: Set<String> = setOf(
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
            "android.permission.MANAGE_EXTERNAL_STORAGE"
        )
        public val SENSORS: Set<String> = setOf(
            "android.permission.BODY_SENSORS",
            "android.permission.BODY_SENSORS_BACKGROUND",
            "android.permission.ACTIVITY_RECOGNITION"
        )
    }

    /**
     * Determines whether a given permission is a legitimate, expected requirement for the given StandardAppCategory.
     */
    public fun isPermissionExpectedForCategory(permissionName: String, category: StandardAppCategory): Boolean {
        val perm = permissionName.trim()
        return when (category) {
            StandardAppCategory.MESSAGING -> {
                perm in PermissionGroups.CAMERA ||
                perm in PermissionGroups.MICROPHONE ||
                perm in PermissionGroups.CONTACTS ||
                perm in PermissionGroups.LOCATION ||
                perm in PermissionGroups.STORAGE ||
                perm == "android.permission.READ_PHONE_STATE" ||
                perm == "android.permission.CALL_PHONE" ||
                perm == "android.permission.VIBRATE" ||
                perm == "android.permission.POST_NOTIFICATIONS"
            }
            StandardAppCategory.SOCIAL_MEDIA -> {
                perm in PermissionGroups.CAMERA ||
                perm in PermissionGroups.MICROPHONE ||
                perm in PermissionGroups.CONTACTS ||
                perm in PermissionGroups.LOCATION ||
                perm in PermissionGroups.STORAGE ||
                perm == "android.permission.READ_PHONE_STATE" ||
                perm == "android.permission.POST_NOTIFICATIONS"
            }
            StandardAppCategory.NAVIGATION -> {
                perm in PermissionGroups.LOCATION ||
                perm in PermissionGroups.MICROPHONE ||
                perm in PermissionGroups.STORAGE ||
                perm == "android.permission.POST_NOTIFICATIONS"
            }
            StandardAppCategory.CALLER_ID -> {
                perm in PermissionGroups.CONTACTS ||
                perm in PermissionGroups.PHONE_CALLS ||
                perm == "android.permission.POST_NOTIFICATIONS"
            }
            StandardAppCategory.BROWSER -> {
                perm in PermissionGroups.CAMERA ||
                perm in PermissionGroups.MICROPHONE ||
                perm in PermissionGroups.LOCATION ||
                perm in PermissionGroups.STORAGE ||
                perm == "android.permission.POST_NOTIFICATIONS"
            }
            StandardAppCategory.MEDIA -> {
                perm in PermissionGroups.MICROPHONE ||
                perm in PermissionGroups.CAMERA ||
                perm in PermissionGroups.STORAGE ||
                perm == "android.permission.POST_NOTIFICATIONS"
            }
            StandardAppCategory.EMAIL -> {
                perm in PermissionGroups.CONTACTS ||
                perm in PermissionGroups.STORAGE ||
                perm == "android.permission.POST_NOTIFICATIONS"
            }
            StandardAppCategory.BANKING, StandardAppCategory.WALLET -> {
                perm in PermissionGroups.CAMERA ||
                perm in PermissionGroups.LOCATION ||
                perm in PermissionGroups.STORAGE ||
                perm == "android.permission.USE_BIOMETRIC" ||
                perm == "android.permission.USE_FINGERPRINT" ||
                perm == "android.permission.POST_NOTIFICATIONS"
            }
            StandardAppCategory.SYSTEM, StandardAppCategory.SYSTEM_CRITICAL, StandardAppCategory.GOOGLE_SERVICES -> true
            StandardAppCategory.GAME -> {
                perm in PermissionGroups.STORAGE ||
                perm in PermissionGroups.MICROPHONE ||
                perm == "android.permission.VIBRATE" ||
                perm == "android.permission.POST_NOTIFICATIONS"
            }
            StandardAppCategory.UTILITY, StandardAppCategory.PRODUCTIVITY, StandardAppCategory.USER_APP, StandardAppCategory.UNKNOWN -> {
                perm in PermissionGroups.STORAGE ||
                perm == "android.permission.VIBRATE" ||
                perm == "android.permission.POST_NOTIFICATIONS"
            }
            else -> false
        }
    }

    // ==========================================
    // Anti-Spoofing & Signature Integrity
    // ==========================================
    public val KNOWN_OFFICIAL_SIGNATURES: Map<String, Set<String>> = mapOf(
        // WhatsApp Official Signatures
        "com.whatsapp" to setOf(
            "38:91:8A:45:3D:07:10:E1:94:07:95:F9:6E:9E:C3:7E:8E:D6:55:04:84:DE:93:33:48:47:67:86:14:1D:64:1B",
            "D2:39:CA:73:96:FD:DE:E8:29:FE:48:E0:9E:A7:28:FE:84:86:52:13:B7:9B:EE:B4:85:2E:CD:9C:AE:34:64:9F"
        ),
        "com.whatsapp.w4b" to setOf(
            "38:91:8A:45:3D:07:10:E1:94:07:95:F9:6E:9E:C3:7E:8E:D6:55:04:84:DE:93:33:48:47:67:86:14:1D:64:1B",
            "D2:39:CA:73:96:FD:DE:E8:29:FE:48:E0:9E:A7:28:FE:84:86:52:13:B7:9B:EE:B4:85:2E:CD:9C:AE:34:64:9F"
        ),
        // Telegram Official Signatures
        "org.telegram.messenger" to setOf(
            "CA:BF:B4:05:8B:D0:6B:A9:6E:CE:6E:9A:C3:F8:78:E8:01:DF:7B:AE:65:FE:34:39:D7:A7:E9:57:37:B0:1B:32",
            "0C:E3:69:B3:60:E6:6A:00:A9:7D:6D:77:2C:B7:E9:9C:25:7C:F5:F4:56:F2:F2:C0:7E:C5:3C:90:7E:B7:2C:19"
        ),
        "org.telegram.plus" to setOf(
            "06:33:B1:32:0C:6D:FE:76:83:A0:6C:56:56:5F:C3:D9:C7:E4:05:BF:F0:4B:32:98:97:56:CE:B8:31:39:69:17"
        ),
        // Signal Official Signature
        "org.thoughtcrime.securesms" to setOf(
            "29:F3:4E:5F:27:F2:B1:7A:24:BF:CA:37:E6:85:8F:FF:83:A6:89:F4:7A:B4:92:C9:48:ED:E6:CD:4F:34:D0:21"
        )
    )

    public fun isPotentialAppImpersonation(
        packageName: String,
        installerPackage: String?,
        isSystem: Boolean,
        signatures: List<String> = emptyList(),
        appName: String? = null
    ): Boolean {
        if (isSystem) return false
        val lowerPkg = packageName.trim().lowercase()

        // 1. Any app showing modified keywords is considered modified / impersonated
        if (isModifiedApp(lowerPkg, appName)) return true

        // 2. Check if the package claims to be a globally famous app or system package
        val claimsFamousIdentity = lowerPkg in GLOBALLY_FAMOUS_PACKAGES ||
            GLOBALLY_FAMOUS_PACKAGE_PREFIXES.any { lowerPkg.startsWith(it) } ||
            SYSTEM_PACKAGE_PREFIXES.any { lowerPkg.startsWith(it) }

        if (!claimsFamousIdentity) return false

        // 3. Official installer check
        val installerTrust = StandardInstallSourceTrust.fromInstaller(installerPackage)
        val isFromOfficialStore = installerTrust == StandardInstallSourceTrust.PLAY_STORE ||
            installerTrust == StandardInstallSourceTrust.THIRD_PARTY_STORE

        // 4. Official signature verification if known
        val knownSignatures = KNOWN_OFFICIAL_SIGNATURES[lowerPkg]
        if (knownSignatures != null && signatures.isNotEmpty()) {
            val matchesSignature = signatures.any { sig ->
                val normalizedSig = sig.trim().uppercase()
                knownSignatures.any { it.equals(normalizedSig, ignoreCase = true) }
            }
            if (!matchesSignature) return true
        }

        // 5. If claiming a critical system/OEM prefix but installed as a non-system user app from untrusted source
        val claimsSystemPrefix = SYSTEM_PACKAGE_PREFIXES.any { lowerPkg.startsWith(it) }
        if (claimsSystemPrefix && !isSystem && !isFromOfficialStore) return true

        // 6. If claiming a top famous package but installed from untrusted source without matching known signature
        if (!isFromOfficialStore && knownSignatures == null && installerTrust == StandardInstallSourceTrust.UNKNOWN) {
            return true
        }

        return false
    }

    public fun isSystemOrWellKnownApp(
        packageName: String,
        isSystem: Boolean = false,
        appName: String? = null,
        installerPackage: String? = null,
        signatures: List<String> = emptyList()
    ): Boolean {
        if (isSystem) return true
        if (isPotentialAppImpersonation(packageName, installerPackage, isSystem, signatures, appName)) {
            return false
        }
        return isWellKnownGlobalApp(packageName, appName)
    }

    /**
     * Resolves the canonical StandardAppCategory based on package name and app label.
     */
    public fun resolveCategory(
        packageName: String,
        appName: String? = null,
        isSystem: Boolean = false,
        uid: Int = 10000
    ): StandardAppCategory {
        val lowerPkg = packageName.trim().lowercase()
        val lowerName = appName?.trim()?.lowercase().orEmpty()
        if (lowerPkg.isBlank() || uid < 0) return StandardAppCategory.UNKNOWN

        // 1. Critical System Applications (UID < 10000)
        if (uid % 100000 < 10000) {
            return when {
                lowerPkg == "android" -> StandardAppCategory.SYSTEM_CRITICAL
                lowerPkg.startsWith("com.android.phone") -> StandardAppCategory.SYSTEM_CRITICAL
                lowerPkg.startsWith("com.android.systemui") -> StandardAppCategory.SYSTEM_CRITICAL
                else -> StandardAppCategory.SYSTEM
            }
        }

        // 2. Google Services & OS Framework Apps
        if (lowerPkg.startsWith("com.google.") || lowerPkg.startsWith("com.android.")) {
            return when {
                lowerPkg.contains("gms") || lowerPkg.contains("gsf") -> StandardAppCategory.GOOGLE_SERVICES
                lowerPkg.contains("chrome") -> StandardAppCategory.BROWSER
                lowerPkg.contains("gmail") -> StandardAppCategory.EMAIL
                lowerPkg.contains("youtube") -> StandardAppCategory.MEDIA
                lowerPkg.contains("maps") -> StandardAppCategory.NAVIGATION
                else -> StandardAppCategory.GOOGLE_SERVICES
            }
        }

        // 3. Modified Apps (WhatsApp Gold, GBWhatsApp, Instander, etc.)
        if (isModifiedApp(lowerPkg, lowerName)) {
            return StandardAppCategory.MODIFIED_APPS
        }

        // 4. Caller ID / Number Book apps
        if (CALLER_ID_KEYWORDS.any { lowerName.contains(it) || lowerPkg.contains(it) }) {
            return StandardAppCategory.CALLER_ID
        }

        // 5. Banking & Wallets
        if (FINANCIAL_KEYWORDS.any { lowerName.contains(it) || lowerPkg.contains(it) }) {
            return StandardAppCategory.BANKING
        }

        // 6. Social Media & Messaging
        if (isSocialMediaApp(lowerPkg, lowerName)) return StandardAppCategory.SOCIAL_MEDIA
        if (isMessagingApp(lowerPkg, lowerName)) return StandardAppCategory.MESSAGING

        // 7. Browsers
        if (lowerPkg.contains("browser") || lowerPkg.contains("firefox") ||
            lowerPkg.contains("opera") || lowerPkg.contains("brave")) {
            return StandardAppCategory.BROWSER
        }

        // 8. Navigation & Maps
        if (isNavigationApp(lowerPkg, lowerName)) return StandardAppCategory.NAVIGATION

        // 9. Games & Media
        if (isGameApp(lowerPkg, lowerName)) return StandardAppCategory.GAME
        if (isMediaApp(lowerPkg, lowerName)) return StandardAppCategory.MEDIA

        // 10. VPN & Security
        if (lowerPkg.contains("vpn") || lowerPkg.contains("tunnel")) return StandardAppCategory.VPN
        if (lowerPkg.contains("security") || lowerPkg.contains("antivirus") || lowerPkg.contains("soornet")) {
            return StandardAppCategory.SECURITY
        }

        // 11. Known suspicious blacklisted packages
        if (DEFAULT_BLACKLISTED_APPS.contains(lowerPkg)) {
            return StandardAppCategory.SUSPICIOUS
        }

        // 12. Generic System vs User App
        if (isSystem) return StandardAppCategory.SYSTEM
        return if (lowerPkg.isNotBlank()) StandardAppCategory.USER_APP else StandardAppCategory.UNKNOWN
    }
}
