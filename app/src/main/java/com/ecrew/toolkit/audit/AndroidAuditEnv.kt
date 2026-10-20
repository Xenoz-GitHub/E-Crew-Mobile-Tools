package com.ecrew.toolkit.audit

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.nfc.NfcAdapter
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager
import android.view.accessibility.AccessibilityManager
import android.view.inputmethod.InputMethodManager
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.accounts.AccountManager
import android.net.wifi.WifiManager
import java.io.File

/**
 * Android implementation of [AuditEnv].
 *
 * Base-tier reads only: settings providers, PackageManager, ConnectivityManager, telephony,
 * radios, keyguard and a one-shot `getprop` dump (read-only, no permission). Every method
 * returns null when the platform refuses to disclose a value; the checks turn that into
 * UNKNOWN. No verdict logic lives here.
 *
 * The audit runs on a background dispatcher; this class is not thread-safe by itself but the
 * `getprop` cache is a lazy that may publish safely.
 */
class AndroidAuditEnv(
    private val context: Context,
    private val rootOptIn: () -> Boolean = { false }
) : AuditEnv {

    private val properties: Map<String, String> by lazy { readProperties() }

    override fun prop(name: String): String? = properties[name]

    override fun global(name: String): String? = try {
        Settings.Global.getString(context.contentResolver, name)
    } catch (e: SecurityException) {
        null
    }

    override fun secure(name: String): String? = try {
        Settings.Secure.getString(context.contentResolver, name)
    } catch (e: SecurityException) {
        null
    }

    override fun systemSetting(name: String): String? = try {
        Settings.System.getString(context.contentResolver, name)
    } catch (e: SecurityException) {
        null
    }

    override fun pathExists(path: String): Boolean = try {
        File(path).exists()
    } catch (e: SecurityException) {
        false
    }

    override fun packageVersion(packageName: String): String? = try {
        context.packageManager.getPackageInfo(packageName, 0).versionName
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    @Suppress("DEPRECATION") // getInstallerPackageName is the API 26-29 path
    override fun installedApps(): List<InstalledApp> {
        val pm = context.packageManager
        val packages = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (e: SecurityException) {
            return emptyList()
        }
        return packages.map { info ->
            val appInfo = info.applicationInfo
            val requested = info.requestedPermissions
            val flags = info.requestedPermissionsFlags
            val granted = LinkedHashSet<String>()
            if (requested != null && flags != null) {
                for (index in requested.indices) {
                    if (index < flags.size &&
                        (flags[index] and
                            android.content.pm.PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                    ) {
                        granted.add(requested[index])
                    }
                }
            }
            InstalledApp(
                packageName = info.packageName,
                system = appInfo != null &&
                    (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0,
                debuggable = appInfo != null &&
                    (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0,
                targetSdk = appInfo?.targetSdkVersion ?: 0,
                installer = try {
                    pm.getInstallerPackageName(info.packageName)
                } catch (e: IllegalArgumentException) {
                    null
                },
                grantedPermissions = granted
            )
        }.sortedBy { it.packageName }
    }

    @Suppress("DEPRECATION") // FingerprintManager is the API 26-27 path; no successor on 26
    override fun fingerprintsEnrolled(): Boolean? {
        if (context.checkPermission(Manifest.permission.USE_FINGERPRINT, android.os.Process.myPid(), android.os.Process.myUid()) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            return null
        }
        val manager =
            context.getSystemService(Context.FINGERPRINT_SERVICE) as?
                android.hardware.fingerprint.FingerprintManager
                ?: return null
        return try {
            manager.hasEnrolledFingerprints()
        } catch (e: SecurityException) {
            null
        }
    }

    override fun accessibilityServices(): List<String>? {
        val manager = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            ?: return null
        return try {
            manager.getEnabledAccessibilityServiceList(
                android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            ).map { it.id }.distinct()
        } catch (e: SecurityException) {
            null
        }
    }

    override fun notificationListeners(): List<String>? {
        val raw = try {
            Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners")
        } catch (e: SecurityException) {
            null
        } ?: return emptyList()
        if (raw.isBlank()) return emptyList()
        return raw.split(':')
            .mapNotNull { entry -> entry.substringBefore('/').ifBlank { null } }
            .distinct()
    }

    override fun enabledInputMethodPackages(): List<String>? {
        val manager = context.getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager
            ?: return null
        return try {
            manager.enabledInputMethodList.map { it.packageName }.distinct()
        } catch (e: SecurityException) {
            null
        }
    }

    override fun deviceAdmins(): List<String>? {
        val manager = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
            ?: return null
        return try {
            manager.activeAdmins?.map { it.packageName }?.distinct() ?: emptyList()
        } catch (e: SecurityException) {
            null
        }
    }

    override fun accountTypes(): List<String>? {
        val manager = context.getSystemService(Context.ACCOUNT_SERVICE) as? AccountManager
            ?: return null
        return try {
            // GET_ACCOUNTS is not requested by E-Crew; the platform refuses and the check
            // reports UNKNOWN rather than pretending the device has no accounts.
            manager.accounts.map { it.type }.distinct()
        } catch (e: SecurityException) {
            null
        }
    }

    override fun isDeviceSecure(): Boolean {
        val manager = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
            ?: return false
        return manager.isDeviceSecure
    }

    @Suppress("DEPRECATION") // NetworkType has no replacement on API 26
    override fun networkType(): Int? {
        val manager = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            ?: return null
        return try {
            manager.networkType
        } catch (e: SecurityException) {
            null
        }
    }

    override fun globalProxy(): String? = try {
        Settings.Global.getString(context.contentResolver, Settings.Global.HTTP_PROXY) ?: ""
    } catch (e: SecurityException) {
        null
    }

    @Suppress("DEPRECATION") // getDefaultProxy is the API 23-30 public path for this data
    override fun wifiProxies(): List<String>? {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return null
        return try {
            val proxy = manager.defaultProxy ?: return emptyList()
            val host = proxy.host
            if (host.isNullOrBlank()) {
                emptyList()
            } else {
                listOf("active network $host:${proxy.port}")
            }
        } catch (e: SecurityException) {
            null
        }
    }

    override fun privateDnsMode(): String? {
        if (Build.VERSION.SDK_INT < 28) return null
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return null
        return try {
            val network = manager.activeNetwork ?: return null
            val link = manager.getLinkProperties(network) ?: return null
            if (!link.isPrivateDnsActive) "off" else link.privateDnsServerName ?: "opportunistic"
        } catch (e: SecurityException) {
            null
        }
    }

    override fun vpnActive(): Boolean? {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return null
        val network = manager.activeNetwork ?: return false
        val capabilities = manager.getNetworkCapabilities(network) ?: return null
        return capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }

    override fun vpnAlwaysOn(): Boolean? = try {
        // The key is not a public API constant; it is read as a plain secure setting.
        val app = Settings.Secure.getString(context.contentResolver, "always_on_vpn_app")
        !app.isNullOrBlank()
    } catch (e: SecurityException) {
        null
    }

    override fun wifiEnabled(): Boolean? {
        val manager = context.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return null
        return try {
            manager.isWifiEnabled
        } catch (e: SecurityException) {
            null
        }
    }

    @Suppress("DEPRECATION") // getDefaultAdapter is the pre-31 path and still valid on 26
    override fun bluetoothEnabled(): Boolean? {
        val adapter = BluetoothAdapter.getDefaultAdapter() ?: return null
        return try {
            adapter.isEnabled
        } catch (e: SecurityException) {
            null
        }
    }

    @Suppress("DEPRECATION") // getDefaultAdapter is the pre-33 path and still valid on 26
    override fun nfcEnabled(): Boolean? {
        val adapter = NfcAdapter.getDefaultAdapter(context) ?: return null
        return try {
            adapter.isEnabled
        } catch (e: SecurityException) {
            null
        }
    }

    override fun cellularDataEnabled(): Boolean? {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return null
        val network = manager.activeNetwork ?: return false
        val capabilities = manager.getNetworkCapabilities(network) ?: return null
        return capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
    }

    @Suppress("DEPRECATION") // protectionLevel is the API 26-27 read path
    override fun isDangerousPermission(permission: String): Boolean? = try {
        val info = context.packageManager.getPermissionInfo(permission, 0)
        (info.protectionLevel and 0xF) ==
            android.content.pm.PermissionInfo.PROTECTION_DANGEROUS
    } catch (e: PackageManager.NameNotFoundException) {
        false
    } catch (e: SecurityException) {
        null
    }

    @Suppress("DEPRECATION") // SIM state has no permission-gated replacement on API 26
    override fun simState(): Int? {
        // No telephony hardware means no SIM; that is a fact, not a disclosure failure.
        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)) {
            return TelephonyManager.SIM_STATE_ABSENT
        }
        val manager = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            ?: return null
        return try {
            manager.simState
        } catch (e: SecurityException) {
            null
        }
    }

    override fun now(): Long = System.currentTimeMillis()

    override fun sdkInt(): Int = Build.VERSION.SDK_INT

    private val shellLock = Any()
    private var cachedShellSource: ShellTier = ShellTier.NONE
    private var cachedShell: AuditShell? = null

    /**
     * Root wins when the user opted in and the probe returned uid 0; Shizuku when it is
     * running and E-Crew is granted; otherwise the ADB shell when the one-time DUMP grant is
     * present. The state is re-evaluated on every call, so granting a tier while the Audit tab
     * is open takes effect on the next scan/recheck. A shell keeps its per-scan command cache
     * until the active tier changes.
     */
    override fun shell(): AuditShell? = synchronized(shellLock) {
        val source = when {
            rootOptIn() && AuditRoot.probe().state == RootState.READY -> ShellTier.ROOT
            AuditShizuku.state(context) == ShizukuState.READY -> ShellTier.SHIZUKU
            hasDumpGrant() -> ShellTier.ADB
            else -> ShellTier.NONE
        }
        if (source != cachedShellSource) {
            cachedShellSource = source
            cachedShell = when (source) {
                ShellTier.ROOT -> AuditRoot.shell()
                ShellTier.SHIZUKU -> ShizukuShell(context)
                ShellTier.ADB -> DumpShell()
                ShellTier.NONE -> null
            }
        }
        cachedShell
    }

    private fun hasDumpGrant(): Boolean = context.checkPermission(
        android.Manifest.permission.DUMP,
        android.os.Process.myPid(),
        android.os.Process.myUid()
    ) == PackageManager.PERMISSION_GRANTED

    /** One-shot read-only `getprop` dump; returns an empty map when unavailable. */
    private fun readProperties(): Map<String, String> {
        val output = try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop"))
            val text = process.inputStream.bufferedReader().use { it.readText() }
            process.waitFor()
            process.destroy()
            text
        } catch (e: Exception) {
            return emptyMap()
        }
        val map = HashMap<String, String>()
        val pattern = Regex("^\\[(.+?)]: \\[(.*)]$")
        for (line in output.lineSequence()) {
            val match = pattern.matchEntire(line.trim()) ?: continue
            map[match.groupValues[1]] = match.groupValues[2]
        }
        return map
    }
}
