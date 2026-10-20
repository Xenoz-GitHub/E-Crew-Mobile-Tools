package com.ecrew.toolkit.audit

/** Result of one fixed read-only command run through an [AuditShell]. */
data class ShellResult(
    val command: List<String>,
    val exitCode: Int,
    val stdout: String,
    val stderr: String
) {
    val ok: Boolean get() = exitCode == 0
}

/**
 * The frozen, read-only command tables for the privileged tiers (design note sections 4, 9b
 * and 9c).
 *
 * Every privileged tier executes commands exclusively through these lists. Adding a command
 * means updating the design note, this table and `AuditCommandTableTest` in the same change.
 * The tables are asserted to contain only read-only reads with no mutating verb, and each
 * [AuditShell] rejects anything outside its own table at runtime. User input never reaches a
 * command: all entries are compile-time constants.
 */
object AuditCommands {

    // ---- ADB tier (app uid + one-time DUMP/PACKAGE_USAGE_STATS grants) ----

    val TRUST = listOf("dumpsys", "trust")
    val APPOPS = listOf("dumpsys", "appops")
    val BATTERY_STATS = listOf("dumpsys", "batterystats", "--charged")
    val CONNECTIVITY = listOf("dumpsys", "connectivity")
    val NETSTATS = listOf("dumpsys", "netstats")

    // ---- Shizuku-only reads (design note 9c) ----

    val GETENFORCE = listOf("getenforce")
    val ALWAYS_ON_VPN_APP = listOf("settings", "get", "secure", "always_on_vpn_app")
    val VPN_LOCKDOWN = listOf("settings", "get", "secure", "always_on_vpn_lockdown")

    // ---- Root-only reads (design note 9d) ----

    /** Probe command; the transport runs it as uid 0 before any check. */
    val ROOT_PROBE = listOf("id")
    val ADB_KEYS = listOf("cat", "/data/misc/adb/adb_keys")
    val DATA_DIR = listOf("ls", "/data/data")
    val MAGISK_MODULES = listOf("ls", "/data/adb/modules")
    val MAGISK_SBIN = listOf("ls", "/sbin/.magisk")
    val SOCKETS_SS = listOf("ss", "-tulpn")
    val SOCKETS_NETSTAT = listOf("netstat", "-tulpn")

    /** The 5 reads the ADB tier (app uid) may run. */
    val adbTable: List<List<String>> =
        listOf(TRUST, APPOPS, BATTERY_STATS, CONNECTIVITY, NETSTATS)

    /** Everything the Shizuku tier may run: the ADB reads plus its own. */
    val shizukuTable: List<List<String>> =
        adbTable + listOf(GETENFORCE, ALWAYS_ON_VPN_APP, VPN_LOCKDOWN)

    /** The root-only reads. */
    val rootOnlyTable: List<List<String>> = listOf(
        ROOT_PROBE,
        ADB_KEYS,
        DATA_DIR,
        MAGISK_MODULES,
        MAGISK_SBIN,
        SOCKETS_SS,
        SOCKETS_NETSTAT
    )

    /** Everything the Root tier may run: the whole privileged union. */
    val rootTable: List<List<String>> = shizukuTable + rootOnlyTable

    /** The full privileged table; new code picks the table of the tier it speaks for. */
    val table: List<List<String>> get() = rootTable

    fun isAdbAllowed(command: List<String>): Boolean = adbTable.any { it == command }

    fun isShizukuAllowed(command: List<String>): Boolean = shizukuTable.any { it == command }

    fun isRootAllowed(command: List<String>): Boolean = rootTable.any { it == command }

    /** Backwards-compatible name used by the test doubles: the full privileged table. */
    fun isAllowed(command: List<String>): Boolean = isRootAllowed(command)

    /** The canonical, loggable form of a command. */
    fun canonical(command: List<String>): String = command.joinToString(" ")

    /** The tokens of a canonical command in the full table; null when outside the table. */
    fun parseCanonical(value: String): List<String>? =
        rootTable.firstOrNull { canonical(it) == value }
}

/** Executes only commands from its tier's table; anything else is a programming error. */
interface AuditShell {
    /** The privileged tier this shell speaks for. */
    val source: ShellTier
    fun exec(command: List<String>): ShellResult
}

/**
 * On-device ADB-tier [AuditShell]: runs the fixed `dumpsys` table as the app's own uid, which
 * requires the one-time DUMP/PACKAGE_USAGE_STATS grants (design note section 9). Results are
 * cached per session because the appops and batterystats dumps are large and several checks
 * share them.
 */
class DumpShell : AuditShell {

    override val source: ShellTier = ShellTier.ADB

    private val cache = HashMap<String, ShellResult>()

    override fun exec(command: List<String>): ShellResult {
        require(AuditCommands.isAdbAllowed(command)) {
            "command not in the read-only table (ADB): ${AuditCommands.canonical(command)}"
        }
        val key = AuditCommands.canonical(command)
        return cache.getOrPut(key) { run(command) }
    }

    private fun run(command: List<String>): ShellResult = try {
        val process = ProcessBuilder(command).redirectErrorStream(false).start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        val stderr = process.errorStream.bufferedReader().use { it.readText() }
        val exitCode = process.waitFor()
        ShellResult(command, exitCode, stdout, stderr)
    } catch (e: Exception) {
        ShellResult(command, -1, "", "${e.javaClass.simpleName}: ${e.message ?: "failed"}")
    }
}

/**
 * Some services print a refusal on stdout with exit code 0 (for example `dumpsys trust`
 * needs MANAGE_USERS for app uids). A refusal is never parsed as data.
 */
internal fun refusalReason(stdout: String): String? {
    val firstLine = stdout.lineSequence().map { it.trim() }.firstOrNull { it.isNotBlank() }
        ?: return null
    return when {
        firstLine.startsWith("Permission Denial", ignoreCase = true) ||
            firstLine.startsWith("Security exception", ignoreCase = true) ->
            firstLine.take(200)
        else -> null
    }
}
