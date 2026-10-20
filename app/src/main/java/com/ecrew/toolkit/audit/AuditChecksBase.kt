package com.ecrew.toolkit.audit

import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * The 39 Base-tier checks (prompt Component 13, catalog frozen in the design note
 * 2026-10-19-2336-security-audit-design.md). Read-only, no privileged access.
 *
 * Rules:
 * - PASS is returned only on a value that was actually read.
 * - A null from [AuditEnv] means "not disclosed" and yields UNKNOWN, never PASS.
 * - Fixes are user actions: checks only attach a Settings intent for the UI to open.
 */
object AuditChecksBase {

    private const val ACTION_SECURITY = "android.settings.SECURITY_SETTINGS"
    private const val ACTION_ACCESSIBILITY = "android.settings.ACCESSIBILITY_SETTINGS"
    private const val ACTION_DEVICE_ADMIN = "android.settings.DEVICE_ADMIN_SETTINGS"
    private const val ACTION_DISPLAY = "android.settings.DISPLAY_SETTINGS"
    private const val ACTION_INPUT_METHODS = "android.settings.INPUT_METHOD_SETTINGS"
    private const val ACTION_NOTIFICATION_LISTENERS = "android.settings.NOTIFICATION_LISTENER_SETTINGS"
    private const val ACTION_WIFI = "android.settings.WIFI_SETTINGS"
    private const val ACTION_WIRELESS = "android.settings.WIRELESS_SETTINGS"
    private const val ACTION_BLUETOOTH = "android.settings.BLUETOOTH_SETTINGS"
    private const val ACTION_NFC = "android.settings.NFC_SETTINGS"
    private const val ACTION_VPN = "android.settings.VPN_SETTINGS"
    private const val ACTION_DEVELOPMENT = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS"
    private const val ACTION_APPS = "android.settings.APPLICATION_SETTINGS"
    private const val ACTION_SYSTEM_UPDATE = "android.settings.SYSTEM_UPDATE_SETTINGS"
    private const val ACTION_MOBILE_NETWORK = "android.settings.MOBILE_NETWORK_SETTINGS"

    private const val PERM_READ_SMS = "android.permission.READ_SMS"
    private const val PERM_RECEIVE_SMS = "android.permission.RECEIVE_SMS"
    private const val PERM_READ_CALL_LOG = "android.permission.READ_CALL_LOG"
    private const val PERM_READ_CONTACTS = "android.permission.READ_CONTACTS"
    private const val PERM_READ_PHONE_STATE = "android.permission.READ_PHONE_STATE"
    private const val PERM_FINE_LOCATION = "android.permission.ACCESS_FINE_LOCATION"
    private const val PERM_COARSE_LOCATION = "android.permission.ACCESS_COARSE_LOCATION"
    private const val PERM_CAMERA = "android.permission.CAMERA"
    private const val PERM_RECORD_AUDIO = "android.permission.RECORD_AUDIO"

    private val suPaths = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/system/app/Superuser.apk",
        "/system/app/Magisk.apk",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/magisk/.core"
    )

    private val catalog: List<AuditCheck> = listOf(
        // ---- Device integrity (11) ----
        def("INT-01", "Bootloader lock", AuditCategory.DEVICE_INTEGRITY, AuditSeverity.CRITICAL) { env ->
            val locked = env.prop("ro.boot.flash.locked")
            when (locked) {
                null -> unreadable("the bootloader lock state (ro.boot.flash.locked)")
                "1" -> ok("ro.boot.flash.locked=1", "The bootloader reports as locked.")
                else -> issue(
                    AuditStatus.FAIL,
                    "ro.boot.flash.locked=$locked",
                    "The bootloader reports as unlocked or in an unusual state; anyone with physical access can replace the system."
                )
            }
        },
        def("INT-02", "Verified boot", AuditCategory.DEVICE_INTEGRITY, AuditSeverity.CRITICAL) { env ->
            when (val state = env.prop("ro.boot.verifiedbootstate")) {
                null -> unreadable("the verified boot state (ro.boot.verifiedbootstate)")
                "green" -> ok("ro.boot.verifiedbootstate=green", "Verified boot is in the green state: the system image is fully verified.")
                "yellow" -> issue(
                    AuditStatus.WARN,
                    "ro.boot.verifiedbootstate=yellow",
                    "Verified boot is yellow: a custom key or modified boot image is in use."
                )
                "orange" -> issue(
                    AuditStatus.FAIL,
                    "ro.boot.verifiedbootstate=orange",
                    "Verified boot is orange: the bootloader is unlocked or a custom image is installed."
                )
                "red" -> issue(
                    AuditStatus.FAIL,
                    "ro.boot.verifiedbootstate=red",
                    "Verified boot is red: verification failed."
                )
                else -> issue(
                    AuditStatus.WARN,
                    "ro.boot.verifiedbootstate=$state",
                    "Unrecognized verified boot state; treated conservatively."
                )
            }
        },
        def("INT-03", "System security patch level", AuditCategory.DEVICE_INTEGRITY, AuditSeverity.CRITICAL) { env ->
            val patch = env.prop("ro.build.version.security_patch")
            val months = patchAgeMonths(patch, env.now())
            when {
                patch.isNullOrBlank() -> unreadable("the system security patch level")
                months == null -> unreadable("a parseable system security patch date (value: $patch)")
                months > 12 -> issue(
                    AuditStatus.FAIL,
                    "ro.build.version.security_patch=$patch (about $months months old)",
                    "The system security patch is more than 12 months old; known platform vulnerabilities are likely unpatched."
                )
                months > 6 -> issue(
                    AuditStatus.WARN,
                    "ro.build.version.security_patch=$patch (about $months months old)",
                    "The system security patch is more than 6 months old."
                )
                else -> ok(
                    "ro.build.version.security_patch=$patch (about $months months old)",
                    "The system security patch is reasonably current."
                )
            }
        },
        def("INT-04", "Vendor security patch level", AuditCategory.DEVICE_INTEGRITY, AuditSeverity.WARNING) { env ->
            val patch = env.prop("ro.vendor.build.security_patch")
            when {
                patch.isNullOrBlank() -> AuditResult(
                    AuditStatus.NA,
                    "ro.vendor.build.security_patch not exposed",
                    "This device does not publish a separate vendor patch level.",
                    null
                )
                else -> {
                    val months = patchAgeMonths(patch, env.now())
                    when {
                        months == null -> unreadable("a parseable vendor patch date (value: $patch)")
                        months > 12 -> issue(
                            AuditStatus.FAIL,
                            "ro.vendor.build.security_patch=$patch (about $months months old)",
                            "The vendor patch level is more than 12 months old."
                        )
                        months > 6 -> issue(
                            AuditStatus.WARN,
                            "ro.vendor.build.security_patch=$patch (about $months months old)",
                            "The vendor patch level is more than 6 months old."
                        )
                        else -> ok(
                            "ro.vendor.build.security_patch=$patch (about $months months old)",
                            "The vendor patch level is reasonably current."
                        )
                    }
                }
            }
        },
        def("INT-05", "Kernel version sanity", AuditCategory.DEVICE_INTEGRITY, AuditSeverity.NOTICE) { env ->
            val kernel = env.prop("os.version")
            when {
                kernel.isNullOrBlank() -> unreadable("the kernel version (os.version)")
                kernel.contains("eng", ignoreCase = true) || kernel.contains("test", ignoreCase = true) ->
                    issue(
                        AuditStatus.WARN,
                        "os.version=$kernel",
                        "The kernel identifies as an engineering or test build."
                    )
                else -> ok("os.version=$kernel", "The kernel version was read and looks like a production build.")
            }
        },
        def("INT-06", "Encryption at rest", AuditCategory.DEVICE_INTEGRITY, AuditSeverity.CRITICAL) { env ->
            val state = env.prop("ro.crypto.state")
            val type = env.prop("ro.crypto.type")
            when (state) {
                null -> unreadable("the encryption state (ro.crypto.state)")
                "encrypted" -> ok(
                    "ro.crypto.state=encrypted ro.crypto.type=${type ?: "unknown"}",
                    if (type == "file") "File-based encryption is active." else "Storage encryption is active."
                )
                "unencrypted" -> issue(
                    AuditStatus.FAIL,
                    "ro.crypto.state=unencrypted",
                    "Storage is not encrypted; data at rest can be read off the device."
                )
                else -> issue(AuditStatus.WARN, "ro.crypto.state=$state", "Unrecognized encryption state.")
            }
        },
        def("INT-07", "Root indicators", AuditCategory.DEVICE_INTEGRITY, AuditSeverity.CRITICAL) { env ->
            val present = suPaths.filter { env.pathExists(it) }
            val tags = env.prop("ro.build.tags")
            val debuggable = env.prop("ro.debuggable")
            val secure = env.prop("ro.secure")
            val props = ArrayList<String>()
            if (tags?.contains("test-keys") == true) props.add("ro.build.tags=$tags")
            if (debuggable == "1") props.add("ro.debuggable=1")
            if (secure == "0") props.add("ro.secure=0")
            val indicators = present + props
            if (indicators.isEmpty()) {
                ok("no su binaries, test-keys, ro.secure=0 or ro.debuggable=1", "No common root indicators were found.")
            } else {
                issue(
                    AuditStatus.FAIL,
                    joinCapped(indicators),
                    "Root indicators were found; the device may be rooted, which changes the threat model for stored evidence."
                )
            }
        },
        def("INT-08", "Developer options", AuditCategory.DEVICE_INTEGRITY, AuditSeverity.NOTICE) { env ->
            when (val v = env.global("development_settings_enabled")) {
                null -> unreadable("the developer options state")
                "0" -> ok("development_settings_enabled=0", "Developer options are disabled.")
                "1" -> issue(
                    AuditStatus.WARN,
                    "development_settings_enabled=1",
                    "Developer options are enabled; debugging features widen the attack surface.",
                    ACTION_DEVELOPMENT
                )
                else -> issue(AuditStatus.WARN, "development_settings_enabled=$v", "Unexpected developer options value.")
            }
        },
        def("INT-09", "USB debugging", AuditCategory.DEVICE_INTEGRITY, AuditSeverity.WARNING) { env ->
            when (val v = env.global("adb_enabled")) {
                null -> unreadable("the USB debugging state")
                "0" -> ok("adb_enabled=0", "USB debugging is disabled.")
                "1" -> issue(
                    AuditStatus.WARN,
                    "adb_enabled=1",
                    "USB debugging is enabled; any authorized computer can read app data over ADB.",
                    ACTION_DEVELOPMENT
                )
                else -> issue(AuditStatus.WARN, "adb_enabled=$v", "Unexpected USB debugging value.")
            }
        },
        def("INT-10", "System WebView", AuditCategory.DEVICE_INTEGRITY, AuditSeverity.WARNING) { env ->
            val candidates = listOf("com.google.android.webview", "com.android.webview")
            val found = candidates.firstOrNull { env.packageVersion(it) != null }
            if (found == null) {
                issue(
                    AuditStatus.WARN,
                    "no WebView package found (checked ${candidates.joinToString(", ")})",
                    "No system WebView package was found; apps embedding web content may be unpatched.",
                    ACTION_APPS
                )
            } else {
                ok(
                    "$found ${env.packageVersion(found)}",
                    "The system WebView package is present. Compare the version against the latest release when online."
                )
            }
        },
        def("INT-11", "Build type", AuditCategory.DEVICE_INTEGRITY, AuditSeverity.WARNING) { env ->
            when (val type = env.prop("ro.build.type")) {
                null -> unreadable("the build type (ro.build.type)")
                "user" -> ok("ro.build.type=user", "The build is a production user build.")
                "userdebug" -> issue(
                    AuditStatus.WARN,
                    "ro.build.type=userdebug",
                    "The build is userdebug: debugging and extra logging are available."
                )
                "eng" -> issue(
                    AuditStatus.FAIL,
                    "ro.build.type=eng",
                    "The build is an engineering build with debugging enabled."
                )
                else -> issue(AuditStatus.WARN, "ro.build.type=$type", "Unrecognized build type.")
            }
        },

        // ---- Access control (10) ----
        def("ACC-01", "Screen lock set", AuditCategory.ACCESS_CONTROL, AuditSeverity.CRITICAL) { env ->
            if (env.isDeviceSecure()) {
                ok("KeyguardManager.isDeviceSecure=true", "A screen lock is set.")
            } else {
                issue(
                    AuditStatus.FAIL,
                    "KeyguardManager.isDeviceSecure=false",
                    "No secure screen lock is set; anyone holding the device can read its data.",
                    ACTION_SECURITY
                )
            }
        },
        def("ACC-02", "Biometric unlock enrolled", AuditCategory.ACCESS_CONTROL, AuditSeverity.NOTICE) { env ->
            when (env.fingerprintsEnrolled()) {
                null -> unreadable("the biometric enrollment state")
                true -> ok("fingerprints enrolled", "A fingerprint is enrolled for unlock.")
                false -> issue(
                    AuditStatus.WARN,
                    "no fingerprints enrolled",
                    "No biometric unlock is enrolled; a long PIN is still fine, this is only a convenience or strength note.",
                    ACTION_SECURITY
                )
            }
        },
        def("ACC-03", "Device administrator apps", AuditCategory.ACCESS_CONTROL, AuditSeverity.WARNING) { env ->
            when (val admins = env.deviceAdmins()) {
                null -> unreadable("the active device administrators")
                else -> if (admins.isEmpty()) {
                    ok("no active device administrators", "No app holds device-administrator rights.")
                } else {
                    issue(
                        AuditStatus.WARN,
                        joinCapped(admins),
                        "Apps with device-administrator rights can wipe the device or lock it; review them.",
                        ACTION_DEVICE_ADMIN
                    )
                }
            }
        },
        def("ACC-04", "Accessibility services", AuditCategory.ACCESS_CONTROL, AuditSeverity.CRITICAL) { env ->
            when (val services = env.accessibilityServices()) {
                null -> unreadable("the enabled accessibility services")
                else -> if (services.isEmpty()) {
                    ok("no enabled accessibility services", "No accessibility service is enabled.")
                } else {
                    issue(
                        AuditStatus.FAIL,
                        joinCapped(services),
                        "Accessibility services can read screen content and act as the user; stalkerware commonly abuses them. Review every entry.",
                        ACTION_ACCESSIBILITY
                    )
                }
            }
        },
        def("ACC-05", "Notification listeners", AuditCategory.ACCESS_CONTROL, AuditSeverity.WARNING) { env ->
            when (val listeners = env.notificationListeners()) {
                null -> unreadable("the enabled notification listeners")
                else -> if (listeners.isEmpty()) {
                    ok("no enabled notification listeners", "No notification listener is enabled.")
                } else {
                    issue(
                        AuditStatus.WARN,
                        joinCapped(listeners),
                        "Notification listeners can read every notification; review them.",
                        ACTION_NOTIFICATION_LISTENERS
                    )
                }
            }
        },
        def("ACC-06", "Third-party keyboards", AuditCategory.ACCESS_CONTROL, AuditSeverity.WARNING) { env ->
            val packages = env.enabledInputMethodPackages()
            if (packages == null) {
                unreadable("the enabled input methods")
            } else {
                val systemPackages = env.installedApps().filter { it.system }.map { it.packageName }.toSet()
                val thirdParty = packages.filter { it.isNotBlank() && it !in systemPackages }
                if (thirdParty.isEmpty()) {
                    ok(joinCapped(packages), "Only system input methods are enabled.")
                } else {
                    issue(
                        AuditStatus.WARN,
                        joinCapped(thirdParty),
                        "A third-party keyboard is enabled; keyboards can observe everything typed.",
                        ACTION_INPUT_METHODS
                    )
                }
            }
        },
        def("ACC-07", "Screen-off timeout", AuditCategory.ACCESS_CONTROL, AuditSeverity.NOTICE) { env ->
            val value = env.systemSetting("screen_off_timeout")?.toLongOrNull()
            when {
                value == null -> unreadable("the screen-off timeout")
                value <= 300_000L -> ok(
                    "screen_off_timeout=${value}ms",
                    "The screen locks after at most 5 minutes."
                )
                else -> issue(
                    AuditStatus.WARN,
                    "screen_off_timeout=${value}ms",
                    "The screen stays on for more than 5 minutes, which widens physical-access exposure.",
                    ACTION_DISPLAY
                )
            }
        },
        def("ACC-08", "Lock-after-timeout delay", AuditCategory.ACCESS_CONTROL, AuditSeverity.NOTICE) { env ->
            val value = env.secure("lock_screen_lock_after_timeout")?.toLongOrNull()
            when {
                value == null -> unreadable("the lock-after-timeout delay")
                value <= 60_000L -> ok(
                    "lock_screen_lock_after_timeout=${value}ms",
                    "The screen locks quickly after the timeout."
                )
                else -> issue(
                    AuditStatus.WARN,
                    "lock_screen_lock_after_timeout=${value}ms",
                    "There is a delay of more than one minute between screen-off and lock.",
                    ACTION_SECURITY
                )
            }
        },
        def("ACC-09", "Unknown-sources install toggle", AuditCategory.ACCESS_CONTROL, AuditSeverity.WARNING) { env ->
            when (val v = env.secure("install_non_market_apps")) {
                null -> AuditResult(
                    AuditStatus.NA,
                    "install_non_market_apps not set",
                    "Android 8 replaced the global unknown-sources toggle with a per-app install permission; sideloaded apps are covered by APP-07.",
                    null
                )
                "0" -> ok("install_non_market_apps=0", "Installing apps from unknown sources is disabled.")
                else -> issue(
                    AuditStatus.WARN,
                    "install_non_market_apps=$v",
                    "Installing apps from unknown sources appears to be enabled.",
                    ACTION_SECURITY
                )
            }
        },
        def("ACC-10", "Device provisioned", AuditCategory.ACCESS_CONTROL, AuditSeverity.INFO) { env ->
            when (val v = env.global("device_provisioned")) {
                null -> unreadable("the device provisioning state")
                "1" -> ok("device_provisioned=1", "The device completed setup.")
                else -> issue(AuditStatus.WARN, "device_provisioned=$v", "The device reports as not fully provisioned.")
            }
        },

        // ---- Apps & permissions (8) ----
        def("APP-01", "Apps holding dangerous permissions", AuditCategory.APPS_PERMISSIONS, AuditSeverity.WARNING) { env ->
            val apps = env.installedApps()
            if (apps.isEmpty()) {
                unreadable("the installed app list")
            } else {
                var sawUnknownProtectionLevel = false
                val holders = ArrayList<InstalledApp>()
                for (app in apps) {
                    var dangerous = false
                    for (perm in app.grantedPermissions) {
                        when (env.isDangerousPermission(perm)) {
                            true -> dangerous = true
                            null -> sawUnknownProtectionLevel = true
                            false -> Unit
                        }
                    }
                    if (dangerous) holders.add(app)
                }
                when {
                    holders.isEmpty() && !sawUnknownProtectionLevel ->
                        ok("no app holds a dangerous permission", "No installed app holds a dangerous permission.")
                    holders.isEmpty() ->
                        unreadable("some permission protection levels")
                    holders.size <= 10 -> ok(
                        "${holders.size} app(s) hold dangerous permissions: ${joinCapped(holders.map { it.packageName })}",
                        "A small number of apps hold dangerous permissions."
                    )
                    else -> issue(
                        AuditStatus.WARN,
                        "${holders.size} apps hold dangerous permissions: ${joinCapped(holders.map { it.packageName })}",
                        "Many apps hold dangerous permissions; review camera, microphone, location, SMS and contacts grants.",
                        ACTION_APPS
                    )
                }
            }
        },
        def("APP-02", "Excessive permission combinations", AuditCategory.APPS_PERMISSIONS, AuditSeverity.WARNING) { env ->
            val apps = env.installedApps()
            if (apps.isEmpty()) {
                unreadable("the installed app list")
            } else {
                val risky = apps.filter { hasRiskyCombination(it) }
                if (risky.isEmpty()) {
                    ok("no app combines messaging, identity and surveillance permissions",
                        "No app combines SMS/call access with contacts or camera+microphone+location.")
                } else {
                    issue(
                        AuditStatus.WARN,
                        joinCapped(risky.map { it.packageName }),
                        "These apps combine permission sets typical of surveillance software; review them.",
                        ACTION_APPS
                    )
                }
            }
        },
        def("APP-03", "Apps targeting outdated SDKs", AuditCategory.APPS_PERMISSIONS, AuditSeverity.NOTICE) { env ->
            val apps = env.installedApps()
            if (apps.isEmpty()) {
                unreadable("the installed app list")
            } else {
                val outdated = apps.filter { it.targetSdk in 1 until 26 }
                if (outdated.isEmpty()) {
                    ok("no installed app targets an SDK below 26", "All installed apps target Android 8.0 or later.")
                } else {
                    issue(
                        AuditStatus.WARN,
                        joinCapped(outdated.map { "${it.packageName} (targetSdk ${it.targetSdk})" }),
                        "Apps targeting old SDK levels run without modern platform protections.",
                        ACTION_APPS
                    )
                }
            }
        },
        def("APP-04", "Debuggable apps", AuditCategory.APPS_PERMISSIONS, AuditSeverity.WARNING) { env ->
            val apps = env.installedApps()
            if (apps.isEmpty()) {
                unreadable("the installed app list")
            } else {
                val debuggable = apps.filter { it.debuggable }
                if (debuggable.isEmpty()) {
                    ok("no debuggable app installed", "No installed app is debuggable.")
                } else {
                    issue(
                        AuditStatus.WARN,
                        joinCapped(debuggable.map { it.packageName }),
                        "Debuggable apps allow app-private data extraction with a debugger or run-as.",
                        ACTION_APPS
                    )
                }
            }
        },
        def("APP-05", "Package verifier", AuditCategory.APPS_PERMISSIONS, AuditSeverity.NOTICE) { env ->
            when (val v = env.secure("package_verifier_enable")) {
                null -> unreadable("the package verifier state")
                "1" -> ok("package_verifier_enable=1", "Package verification is enabled.")
                else -> issue(
                    AuditStatus.WARN,
                    "package_verifier_enable=$v",
                    "Package verification appears disabled.",
                    ACTION_SECURITY
                )
            }
        },
        def("APP-06", "Play Protect verification", AuditCategory.APPS_PERMISSIONS, AuditSeverity.WARNING) { env ->
            val gms = env.packageVersion("com.google.android.gms")
            if (gms == null) {
                AuditResult(
                    AuditStatus.NA,
                    "com.google.android.gms not installed",
                    "Google Play services are not installed, so Play Protect verification does not apply.",
                    null
                )
            } else {
                when (val v = env.global("package_verifier_user_consent")) {
                    null -> unreadable("the verify-apps consent setting")
                    "1" -> ok("package_verifier_user_consent=1 (gms $gms)", "Verify apps is enabled.")
                    "-1" -> ok(
                        "package_verifier_user_consent=-1 (gms $gms)",
                        "Verify apps uses the platform default (enabled)."
                    )
                    else -> issue(
                        AuditStatus.WARN,
                        "package_verifier_user_consent=$v (gms $gms)",
                        "Verify apps is disabled or was declined.",
                        ACTION_SECURITY
                    )
                }
            }
        },
        def("APP-07", "Apps installed outside a store", AuditCategory.APPS_PERMISSIONS, AuditSeverity.NOTICE) { env ->
            val apps = env.installedApps()
            if (apps.isEmpty()) {
                unreadable("the installed app list")
            } else {
                val sideloaded = apps.filter { !it.system && it.installer.isNullOrBlank() }
                if (sideloaded.isEmpty()) {
                    ok("every user app has an installer", "No side-loaded user app was found.")
                } else {
                    issue(
                        AuditStatus.WARN,
                        joinCapped(sideloaded.map { it.packageName }),
                        "These user apps were installed without an app store; verify their origin.",
                        ACTION_APPS
                    )
                }
            }
        },
        def("APP-08", "Account inventory", AuditCategory.APPS_PERMISSIONS, AuditSeverity.INFO) { env ->
            when (val types = env.accountTypes()) {
                null -> unreadable("the account list")
                else -> {
                    val unusual = types.filter { !it.startsWith("com.google") && !it.startsWith("com.android") }
                    if (unusual.isEmpty()) {
                        ok(joinCapped(types), "Only platform or Google account types are present.")
                    } else {
                        issue(
                            AuditStatus.WARN,
                            joinCapped(types),
                            "Unusual account types are present: ${joinCapped(unusual)}."
                        )
                    }
                }
            }
        },

        // ---- Network & radios (10) ----
        def("NET-01", "2G connectivity", AuditCategory.NETWORK_RADIOS, AuditSeverity.CRITICAL) { env ->
            val type = env.networkType()
            val twoG = setOf(1, 2, 4, 7, 11, 16)
            when {
                type == null -> unreadable("the current mobile network type")
                type in twoG -> issue(
                    AuditStatus.FAIL,
                    "networkType=$type (2G generation)",
                    "The device is on a 2G network; 2G has no meaningful encryption and enables interception.",
                    ACTION_MOBILE_NETWORK
                )
                else -> ok("networkType=$type", "The current network type is not 2G.")
            }
        },
        def("NET-02", "Global HTTP proxy", AuditCategory.NETWORK_RADIOS, AuditSeverity.WARNING) { env ->
            when (val proxy = env.globalProxy()) {
                null -> unreadable("the global HTTP proxy setting")
                "", ":0" -> ok("no global HTTP proxy configured", "No global HTTP proxy is configured.")
                else -> issue(
                    AuditStatus.WARN,
                    "global http_proxy=$proxy",
                    "A global HTTP proxy is configured; all app traffic may be inspected or redirected.",
                    ACTION_WIFI
                )
            }
        },
        def("NET-03", "Active network proxy", AuditCategory.NETWORK_RADIOS, AuditSeverity.WARNING) { env ->
            when (val proxies = env.wifiProxies()) {
                null -> unreadable("the active network proxy configuration")
                else -> if (proxies.isEmpty()) {
                    ok("no proxy on the active network", "The active network does not use a proxy.")
                } else {
                    issue(
                        AuditStatus.WARN,
                        joinCapped(proxies),
                        "The active network routes through a proxy; traffic can be inspected or redirected.",
                        ACTION_WIFI
                    )
                }
            }
        },
        def("NET-04", "Private DNS", AuditCategory.NETWORK_RADIOS, AuditSeverity.NOTICE) { env ->
            if (env.sdkInt() < 28) {
                AuditResult(
                    AuditStatus.NA,
                    "sdkInt=${env.sdkInt()}",
                    "Private DNS arrived in Android 9 (API 28); it is not available on this build.",
                    null
                )
            } else {
                when (val mode = env.privateDnsMode()) {
                    null -> unreadable("the Private DNS mode")
                    "off" -> issue(
                        AuditStatus.WARN,
                        "Private DNS is off",
                        "Private DNS is disabled; DNS queries are not encrypted.",
                        ACTION_WIRELESS
                    )
                    else -> ok("Private DNS mode=$mode", "Private DNS is enabled.")
                }
            }
        },
        def("NET-05", "Always-on VPN", AuditCategory.NETWORK_RADIOS, AuditSeverity.NOTICE) { env ->
            when (env.vpnAlwaysOn()) {
                null -> unreadable("the always-on VPN state")
                true -> ok("always-on VPN configured", "An always-on VPN is configured.")
                false -> issue(
                    AuditStatus.WARN,
                    "no always-on VPN configured",
                    "No always-on VPN is configured; traffic can leave the device unencrypted.",
                    ACTION_VPN
                )
            }
        },
        def("NET-06", "Active VPN", AuditCategory.NETWORK_RADIOS, AuditSeverity.INFO) { env ->
            when (env.vpnActive()) {
                null -> unreadable("the VPN connection state")
                true -> ok("a VPN is active", "A VPN connection is active.")
                false -> ok("no active VPN", "No VPN connection is active.")
            }
        },
        def("NET-07", "Wi-Fi state", AuditCategory.NETWORK_RADIOS, AuditSeverity.INFO) { env ->
            when (env.wifiEnabled()) {
                null -> unreadable("the Wi-Fi state")
                true -> ok("Wi-Fi is on", "Wi-Fi is enabled.")
                false -> ok("Wi-Fi is off", "Wi-Fi is disabled.")
            }
        },
        def("NET-08", "Bluetooth state", AuditCategory.NETWORK_RADIOS, AuditSeverity.NOTICE) { env ->
            when (env.bluetoothEnabled()) {
                null -> AuditResult(
                    AuditStatus.NA,
                    "no Bluetooth adapter exposed",
                    "The system did not expose a Bluetooth adapter.",
                    null
                )
                true -> issue(
                    AuditStatus.WARN,
                    "Bluetooth is on",
                    "Bluetooth is enabled; it is a nearby attack surface. Turn it off when not in use.",
                    ACTION_BLUETOOTH
                )
                false -> ok("Bluetooth is off", "Bluetooth is disabled.")
            }
        },
        def("NET-09", "NFC state", AuditCategory.NETWORK_RADIOS, AuditSeverity.NOTICE) { env ->
            when (env.nfcEnabled()) {
                null -> AuditResult(
                    AuditStatus.NA,
                    "no NFC adapter exposed",
                    "The system did not expose an NFC adapter.",
                    null
                )
                true -> issue(
                    AuditStatus.WARN,
                    "NFC is on",
                    "NFC is enabled; it can be used for nearby skimming. Turn it off when not in use.",
                    ACTION_NFC
                )
                false -> ok("NFC is off", "NFC is disabled.")
            }
        },
        def("NET-10", "Cellular data state", AuditCategory.NETWORK_RADIOS, AuditSeverity.INFO) { env ->
            when (env.cellularDataEnabled()) {
                null -> unreadable("the cellular data state")
                true -> ok("cellular data is on", "Cellular data is enabled.")
                false -> ok("cellular data is off", "Cellular data is disabled.")
            }
        }
    )

    // ---- helpers ----

    /** All Base-tier checks (39, frozen catalog). */
    fun checks(): List<AuditCheck> = catalog

    /** Lookup by catalog id, used by the engine and the tests. */
    fun checkById(id: String): AuditCheck? = catalog.firstOrNull { it.id == id }

    private fun def(
        id: String,
        title: String,
        category: AuditCategory,
        severity: AuditSeverity,
        evaluate: (AuditEnv) -> AuditResult
    ) = AuditCheck(id, title, category, severity, AuditTier.BASE, evaluate)

    /** Informational pass with the read value as evidence. */
    private fun ok(evidence: String, explanation: String): AuditResult =
        AuditResult(AuditStatus.PASS, evidence, explanation)

    /** Finding. [action] is a Settings intent constant the UI can open, never automatic. */
    private fun issue(
        status: AuditStatus,
        evidence: String,
        explanation: String,
        action: String? = null
    ): AuditResult = AuditResult(
        status,
        evidence,
        explanation,
        action?.let { AuditRemediation("Open settings", it) }
    )

    /** The platform did not disclose a value; never a pass. */
    private fun unreadable(what: String): AuditResult = AuditResult(
        AuditStatus.UNKNOWN,
        "not readable",
        "The system did not disclose $what, so this check is UNKNOWN rather than a pass."
    )

    private fun joinCapped(items: List<String>, max: Int = 5): String {
        if (items.isEmpty()) return "none"
        val head = items.take(max).joinToString(", ")
        return if (items.size > max) "$head (+${items.size - max} more)" else head
    }

    /** Months between a `yyyy-MM-dd` patch date and now; null when unreadable/unparseable. */
    private fun patchAgeMonths(patch: String?, now: Long): Long? {
        if (patch.isNullOrBlank()) return null
        val parsed = try {
            SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(patch)
        } catch (e: ParseException) {
            null
        } ?: return null
        val monthMs = 30L * 24L * 60L * 60L * 1000L
        return (now - parsed.time) / monthMs
    }

    private fun hasRiskyCombination(app: InstalledApp): Boolean {
        val perms = app.grantedPermissions
        val messaging = perms.contains(PERM_READ_SMS) || perms.contains(PERM_RECEIVE_SMS) ||
            perms.contains(PERM_READ_CALL_LOG) || perms.contains(PERM_READ_PHONE_STATE)
        val identity = perms.contains(PERM_READ_CONTACTS) ||
            perms.contains(PERM_FINE_LOCATION) || perms.contains(PERM_COARSE_LOCATION)
        val surveillance = perms.contains(PERM_CAMERA) && perms.contains(PERM_RECORD_AUDIO) &&
            (perms.contains(PERM_FINE_LOCATION) || perms.contains(PERM_COARSE_LOCATION))
        return (messaging && identity) || surveillance
    }
}
