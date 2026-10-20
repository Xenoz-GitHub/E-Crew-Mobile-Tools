package com.ecrew.toolkit.audit

/**
 * Security & Privacy Audit model (prompt Component 13).
 *
 * The audit is read-only: checks receive an [AuditEnv] (a thin, null-returning view over the
 * platform) and return an [AuditResult]. Every check is a pure function of the environment so
 * the whole Base tier is unit-testable on the JVM; the Android implementation of [AuditEnv]
 * only gathers facts and holds no verdict logic.
 *
 * Catalog: 54 checks across four privilege tiers (Base 39, ADB 8, Shizuku 3, Root 4). The
 * Base tier lives in [AuditChecksBase]; privileged tiers are registered as they activate.
 */

/** Result status of a single check. */
enum class AuditStatus {
    PASS,
    FAIL,
    WARN,
    UNKNOWN,
    NA,
    MUTED
}

/** Finding severity; the weight drives the 0-100 score. */
enum class AuditSeverity(val weight: Int) {
    CRITICAL(10),
    WARNING(5),
    NOTICE(2),
    INFO(0)
}

/** Privilege tier that is required before a check can run. */
enum class AuditTier {
    BASE,
    ADB,
    SHIZUKU,
    ROOT
}

/**
 * The privileged shell a scan actually ran through (design note sections 4, 9c and 9d).
 * [NONE] means the scan was Base-only; Shizuku subsumes the ADB checks, Root subsumes both.
 */
enum class ShellTier {
    NONE,
    ADB,
    SHIZUKU,
    ROOT
}

/** Report section. */
enum class AuditCategory(val label: String) {
    DEVICE_INTEGRITY("Device integrity"),
    ACCESS_CONTROL("Access control"),
    APPS_PERMISSIONS("Apps & permissions"),
    NETWORK_RADIOS("Network & radios")
}

/**
 * A Settings screen the user can open to act on a finding. The app never performs the fix
 * itself; it only navigates.
 */
data class AuditRemediation(val label: String, val intentAction: String)

/** Outcome of one check. [evidence] is the raw value read, shown verbatim. */
data class AuditResult(
    val status: AuditStatus,
    val evidence: String,
    val explanation: String,
    val remediation: AuditRemediation? = null
)

/** Definition + evaluator of a single check. */
class AuditCheck(
    val id: String,
    val title: String,
    val category: AuditCategory,
    val severity: AuditSeverity,
    val tier: AuditTier,
    private val evaluate: (AuditEnv) -> AuditResult
) {
    fun run(env: AuditEnv): AuditResult = evaluate(env)
}

/** One check paired with its result. */
data class AuditFinding(val check: AuditCheck, val result: AuditResult)

/** A completed scan. [mutedIds] is applied when scoring. */
data class AuditReport(val findings: List<AuditFinding>, val mutedIds: Set<String>) {
    fun score(): AuditScore = AuditScoring.compute(findings, mutedIds)
}

/** One installed app as the audit sees it (granted permissions only). */
data class InstalledApp(
    val packageName: String,
    val system: Boolean,
    val debuggable: Boolean,
    val targetSdk: Int,
    val installer: String?,
    val grantedPermissions: Set<String>
)

/**
 * Everything the Base-tier checks read. Null means "the platform did not disclose the value";
 * checks translate null into UNKNOWN, never PASS.
 */
interface AuditEnv {
    fun prop(name: String): String?
    fun global(name: String): String?
    fun secure(name: String): String?
    fun systemSetting(name: String): String?
    fun pathExists(path: String): Boolean
    fun packageVersion(packageName: String): String?
    fun installedApps(): List<InstalledApp>
    fun accessibilityServices(): List<String>?
    fun notificationListeners(): List<String>?
    fun enabledInputMethodPackages(): List<String>?
    fun deviceAdmins(): List<String>?
    fun accountTypes(): List<String>?
    fun isDeviceSecure(): Boolean
    fun fingerprintsEnrolled(): Boolean?
    fun networkType(): Int?
    /** null = unreadable; "" = readable and no proxy is configured. */
    fun globalProxy(): String?
    /** null = unreadable. */
    fun wifiProxies(): List<String>?
    fun privateDnsMode(): String?
    /** null = unreadable. */
    fun vpnActive(): Boolean?
    fun vpnAlwaysOn(): Boolean?
    fun wifiEnabled(): Boolean?
    fun bluetoothEnabled(): Boolean?
    fun nfcEnabled(): Boolean?
    fun cellularDataEnabled(): Boolean?
    fun isDangerousPermission(permission: String): Boolean?
    /** The privileged shell for this scan (Shizuku preferred, then ADB), or null. */
    fun shell(): AuditShell? = null
    /** `TelephonyManager.getSimState()`; null when telephony does not disclose it. */
    fun simState(): Int? = null
    fun now(): Long
    fun sdkInt(): Int
}
