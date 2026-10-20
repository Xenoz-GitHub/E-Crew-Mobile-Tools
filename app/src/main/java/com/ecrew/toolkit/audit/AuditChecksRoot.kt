package com.ecrew.toolkit.audit

import java.security.MessageDigest

/**
 * The 4 Root-tier checks (prompt Component 13, catalog frozen in the design note
 * 2026-10-19-2336-security-audit-design.md, section 9d).
 *
 * The tier is opt-in and runs through [RootShell] only. Every check is N/A when the active
 * shell is not ROOT, so a weaker tier can never produce a Root verdict. Evidence is the raw
 * read value; ACC-14 reports SHA-256 fingerprints of the authorized key lines instead of the
 * full keys (they are authorization material, and the fingerprint is enough to correlate a
 * key with the PC that owns it).
 *
 * API 26 limitations (stated in every affected explanation):
 * - There is no public API for per-app su grants; manager databases are private and are not
 *   parsed, so APP-13 reports active root plus installed root-manager packages.
 * - `ss`/`netstat` on Android 8 print process names, not UIDs; NET-14 maps exact or prefixed
 *   process names to installed non-system packages and ignores loopback-only listeners.
 */
object AuditChecksRoot {

    private const val ACTION_APPS = "android.settings.APPLICATION_SETTINGS"

    /** Known root managers; the name markers catch renamed/variant builds. */
    private val rootManagerPackages = setOf(
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.ramdroid.appquarantine"
    )

    private fun isRootManager(packageName: String): Boolean {
        val lower = packageName.lowercase()
        return packageName in rootManagerPackages ||
            lower.contains("superuser") ||
            lower.contains("supersu") ||
            lower.contains("magisk") ||
            lower.contains("kernelsu")
    }

    private val catalog: List<AuditCheck> = listOf(
        def("ACC-14", "Trusted computers / ADB keys", AuditCategory.ACCESS_CONTROL, AuditSeverity.WARNING) { env ->
            adbKeys(env)
        },
        def("APP-13", "Apps with root", AuditCategory.APPS_PERMISSIONS, AuditSeverity.CRITICAL) { env ->
            appsWithRoot(env)
        },
        def("APP-14", "Root modules", AuditCategory.APPS_PERMISSIONS, AuditSeverity.WARNING) { env ->
            rootModules(env)
        },
        def("NET-14", "Apps listening on network sockets", AuditCategory.NETWORK_RADIOS, AuditSeverity.WARNING) { env ->
            networkListeners(env)
        }
    )

    /** All Root-tier checks (4, frozen catalog). */
    fun checks(): List<AuditCheck> = catalog

    /** Lookup by catalog id, used by the tests. */
    fun checkById(id: String): AuditCheck? = catalog.firstOrNull { it.id == id }

    // ---- ACC-14 ----

    private fun adbKeys(env: AuditEnv): AuditResult {
        val (result, error) = raw(env, AuditCommands.ADB_KEYS)
        if (result == null) return error!!
        if (!result.ok) return failed(result)
        val keys = result.stdout.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        if (keys.isEmpty()) {
            return ok(
                "adb_keys: 0 authorized keys",
                "No computer is authorized to use ADB on this device. An empty or missing " +
                    "adb_keys file is the expected state."
            )
        }
        val prints = keys.take(5).map { fingerprint(it) }
        val suffix = if (keys.size > prints.size) " (+${keys.size - prints.size} more)" else ""
        return issue(
            AuditStatus.WARN,
            "adb_keys: ${keys.size} authorized key(s): ${prints.joinToString(", ")}$suffix",
            "Trusted ADB public keys can authorize a computer over USB or the network. Each " +
                "fingerprint above is the first 12 hex characters of the SHA-256 of one key " +
                "line; compare it with the comment on the owning PC's ~/.android/adbkey.pub. " +
                "Remove keys from a PC with adb; E-Crew never edits the file."
        )
    }

    private fun fingerprint(line: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(line.toByteArray(Charsets.UTF_8))
        return digest.take(6).joinToString("") { "%02x".format(it) }
    }

    // ---- APP-13 ----

    private fun appsWithRoot(env: AuditEnv): AuditResult {
        val (result, error) = raw(env, AuditCommands.DATA_DIR)
        if (result == null) return error!!
        if (!result.ok) return failed(result)
        val entries = result.stdout.lineSequence().count { it.isNotBlank() }
        val managers = env.installedApps()
            .filter { !it.system && isRootManager(it.packageName) }
            .map { it.packageName }
            .sorted()
        val managerEvidence = if (managers.isEmpty()) "none" else joinCapped(managers)
        val evidence = "root shell uid=0; /data/data entries=$entries; root managers: $managerEvidence"
        val explanation = if (managers.isEmpty()) {
            "Root access is active on this device (the tier probe returned uid=0), but no known " +
                "root-manager package is installed, so the grant path is not visible to " +
                "PackageManager. API 26 exposes no public per-app su grant list; the check " +
                "reports root presence rather than inventing an app list."
        } else {
            "Root access is active and a root-manager package is installed. API 26 exposes no " +
                "public per-app su grant list (manager databases are private and are not " +
                "parsed), so this finding names the managers rather than guessing which apps " +
                "hold grants. Review the manager's own app list."
        }
        return issue(
            AuditStatus.WARN,
            evidence,
            explanation,
            ACTION_APPS
        )
    }

    // ---- APP-14 ----

    private fun rootModules(env: AuditEnv): AuditResult {
        val (modulesResult, gate) = raw(env, AuditCommands.MAGISK_MODULES)
        if (modulesResult == null) return gate!!
        val (sbinResult, gate2) = raw(env, AuditCommands.MAGISK_SBIN)
        if (sbinResult == null) return gate2!!

        val modulesAbsent = missingPath(modulesResult)
        if (!modulesResult.ok && !modulesAbsent) {
            return AuditResult(
                AuditStatus.UNKNOWN,
                "modules dir unreadable: ${failureLine(modulesResult)}",
                "The root shell could not list /data/adb/modules, so this check is UNKNOWN " +
                    "rather than a pass."
            )
        }
        val modules = if (modulesResult.ok) {
            modulesResult.stdout.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        } else {
            emptyList()
        }
        if (modules.isNotEmpty()) {
            return issue(
                AuditStatus.WARN,
                "root modules: ${joinCapped(modules)}",
                "Root modules extend the boot image and run with system privileges; each one is " +
                    "part of the device's trusted computing base. Review them in the root " +
                    "manager. E-Crew only lists the module directory."
            )
        }
        val magiskCore = sbinResult.ok && sbinResult.stdout.isNotBlank()
        val evidence = buildString {
            append("root modules: none")
            append("; modules dir: ")
            append(if (modulesAbsent) "absent" else "empty")
            append("; magisk core: ")
            append(if (magiskCore) "present" else "absent")
        }
        return ok(
            evidence,
            "No module entries were found. The Magisk core directory is listed only as " +
                "context: its presence alone is not a module."
        )
    }

    // ---- NET-14 ----

    private fun networkListeners(env: AuditEnv): AuditResult {
        val (ssResult, gate) = raw(env, AuditCommands.SOCKETS_SS)
        if (ssResult == null) return gate!!
        var tool = "ss"
        var output = ssResult.stdout
        var listeners = if (ssResult.ok) parseListeners("ss", output) else null
        if (listeners == null) {
            val (netstatResult, gate2) = raw(env, AuditCommands.SOCKETS_NETSTAT)
            if (netstatResult == null) return gate2!!
            if (!netstatResult.ok || netstatResult.stdout.isBlank()) {
                return AuditResult(
                    AuditStatus.UNKNOWN,
                    "ss: ${failureLine(ssResult)}; netstat: ${failureLine(netstatResult)}",
                    "Neither socket listing could be read through the root shell, so this " +
                        "check is UNKNOWN rather than a pass."
                )
            }
            tool = "netstat"
            output = netstatResult.stdout
            listeners = parseListeners("netstat", output)
                ?: return unrecognized("an ss/netstat listener table")
        }
        val apps = env.installedApps()
        val nonLoopback = listeners.filter { !isLoopback(it.host) }
        if (nonLoopback.isEmpty()) {
            return ok(
                "$tool: no non-loopback listeners",
                "No socket is listening on a non-loopback address. Loopback-only listeners are " +
                    "excluded because they are not reachable from the network."
            )
        }
        val thirdParty = nonLoopback.filter { appFor(it, apps) != null }
        val system = nonLoopback.size - thirdParty.size
        if (thirdParty.isEmpty()) {
            return ok(
                "$tool: ${nonLoopback.size} non-loopback listener(s), none from third-party apps",
                "Every non-loopback listener belongs to a system component or a process that " +
                    "does not match an installed third-party package."
            )
        }
        val listed = thirdParty.take(5).joinToString(", ") {
            val name = it.process ?: "unknown process"
            "$name:${it.port}"
        }
        val suffix = if (thirdParty.size > 5) " (+${thirdParty.size - 5} more)" else ""
        return issue(
            AuditStatus.WARN,
            "$tool: ${thirdParty.size} third-party listener(s): $listed$suffix; system: $system",
            "These third-party processes accept connections on a non-loopback address and are " +
                "reachable from the local network. Android 8's ss/netstat print process names, " +
                "not UIDs, so the mapping uses exact or colon-prefixed package names; a " +
                "listener shown as a system process may still be an app's native helper."
        )
    }

    internal data class SocketListener(
        val protocol: String,
        val host: String,
        val port: Int,
        val process: String?
    )

    /**
     * Parses the two Android 8 listener formats. Returns null when the output does not look
     * like the requested tool's format (the caller may then try the fallback), and an empty
     * list for a valid header with no listeners.
     */
    internal fun parseListeners(tool: String, output: String): List<SocketListener>? {
        val lines = output.lineSequence().toList()
        val recognized = when (tool) {
            "ss" -> lines.any { it.contains("Netid") || it.contains("State") }
            "netstat" -> lines.any { it.contains("Active Internet connections") || it.contains("Proto Recv-Q") }
            else -> false
        }
        if (!recognized) return null
        val result = ArrayList<SocketListener>()
        for (line in lines) {
            val tokens = line.trim().split(Regex("\\s+"))
            if (tokens.size < 6) continue
            val proto = tokens[0].lowercase()
            if (proto != "tcp" && proto != "tcp6" && proto != "udp" && proto != "udp6") continue
            val isTcp = proto.startsWith("tcp")
            val parsed = if (tool == "ss") {
                if (isTcp && !tokens[1].equals("LISTEN", ignoreCase = true)) continue
                if (!isTcp && !tokens[1].equals("UNCONN", ignoreCase = true)) continue
                val local = tokens.getOrNull(4) ?: continue
                val process = Regex("users:\\(\\(\"([^\"]+)\"")
                    .find(line)?.groupValues?.get(1)
                hostPort(local)?.let { (host, port) -> SocketListener(proto, host, port, process) }
            } else {
                if (isTcp && (tokens.getOrNull(5) ?: "").uppercase() != "LISTEN") continue
                val isUdpEstablished = !isTcp && tokens.size >= 7 &&
                    tokens[5].uppercase() == "ESTABLISHED"
                if (isUdpEstablished) continue
                val local = tokens.getOrNull(3) ?: continue
                val rawProcess = if (isTcp) tokens.getOrNull(6) else tokens.getOrNull(5)
                val process = rawProcess?.substringAfterLast('/')?.takeIf { it.isNotBlank() }
                hostPort(local)?.let { (host, port) -> SocketListener(proto, host, port, process) }
            }
            if (parsed != null) result.add(parsed)
        }
        return result.distinct()
    }

    private fun hostPort(value: String): Pair<String, Int>? {
        val separator = value.lastIndexOf(':')
        if (separator <= 0) return null
        val host = value.substring(0, separator).removeSurrounding("[", "]")
        val port = value.substring(separator + 1).toIntOrNull() ?: return null
        if (host.isEmpty()) return null
        return host to port
    }

    private fun isLoopback(host: String): Boolean {
        val lower = host.lowercase()
        return lower == "::1" ||
            lower == "localhost" ||
            lower.startsWith("127.") ||
            lower.startsWith("::ffff:127.") ||
            lower == "::ffff:7f00:1"
    }

    private fun appFor(listener: SocketListener, apps: List<InstalledApp>): InstalledApp? {
        val process = listener.process ?: return null
        val base = process.substringBefore(':')
        return apps.firstOrNull { !it.system && it.packageName == base }
    }

    // ---- runner ----

    /** Runs one table command only through the ROOT shell; null result + gate otherwise. */
    private fun raw(env: AuditEnv, command: List<String>): Pair<ShellResult?, AuditResult?> {
        val gate = rootGate(env)
        if (gate != null) return null to gate
        val shell = env.shell() ?: return null to tierInactive()
        return shell.exec(command) to null
    }

    private fun rootGate(env: AuditEnv): AuditResult? {
        val shell = env.shell()
        return when {
            shell == null -> AuditResult(
                AuditStatus.NA,
                "Root tier inactive",
                "This check runs only through the Root tier. Opt in on the Audit tab and grant " +
                    "the root manager's prompt, then re-check."
            )
            shell.source != ShellTier.ROOT -> AuditResult(
                AuditStatus.NA,
                "Root tier inactive (${shell.source.name} shell active)",
                "This check runs only through the Root tier; it is N/A on the Shizuku/ADB/Base " +
                    "tier, so it never reports a verdict from a weaker read."
            )
            else -> null
        }
    }

    private fun tierInactive(): AuditResult = AuditResult(
        AuditStatus.NA,
        "Root tier inactive",
        "This check needs the Root tier; it is N/A until the opt-in is on and su returns uid 0."
    )

    private fun failed(result: ShellResult): AuditResult = AuditResult(
        AuditStatus.UNKNOWN,
        "${AuditCommands.canonical(result.command)} exited with ${result.exitCode}",
        "The read-only root command could not run (${failureLine(result)}), so this check is " +
            "UNKNOWN rather than a pass."
    )

    private fun missingPath(result: ShellResult): Boolean =
        !result.ok && result.stderr.contains("No such file or directory", ignoreCase = true)

    private fun failureLine(result: ShellResult): String {
        val text = result.stderr.trim().ifBlank { result.stdout.trim() }
        return text.lineSequence().map { it.trim() }.firstOrNull { it.isNotEmpty() }
            ?.take(160) ?: "no output (exit ${result.exitCode})"
    }

    private fun ok(evidence: String, explanation: String): AuditResult =
        AuditResult(AuditStatus.PASS, evidence, explanation)

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

    private fun unrecognized(what: String): AuditResult = AuditResult(
        AuditStatus.UNKNOWN,
        "unrecognized output format",
        "The command output did not contain $what on this device/version, so this check is " +
            "UNKNOWN rather than a pass."
    )

    private fun joinCapped(items: List<String>, max: Int = 5): String {
        if (items.isEmpty()) return "none"
        val head = items.take(max).joinToString(", ")
        return if (items.size > max) "$head (+${items.size - max} more)" else head
    }

    private fun def(
        id: String,
        title: String,
        category: AuditCategory,
        severity: AuditSeverity,
        evaluate: (AuditEnv) -> AuditResult
    ) = AuditCheck(id, title, category, severity, AuditTier.ROOT, evaluate)
}
