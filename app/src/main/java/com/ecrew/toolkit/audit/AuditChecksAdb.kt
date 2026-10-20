package com.ecrew.toolkit.audit

/**
 * The 8 ADB-tier checks (prompt Component 13, catalog frozen in the design note
 * 2026-10-19-2336-security-audit-design.md).
 *
 * Every check runs exactly one command from the frozen [AuditCommands] table through
 * [AuditEnv.shell]. Parsing is conservative: when the expected marker is missing (or the
 * command did not run), the result is UNKNOWN, never PASS. When the tier is inactive
 * (`env.shell() == null`, DUMP not granted) the result is N/A.
 *
 * The parsers are written against real `dumpsys` output captured on the AOSP API 26
 * emulator (see session note 2026-10-20-0030-security-audit-adb-tier.md); unrecognized
 * formats degrade to UNKNOWN rather than guessing.
 *
 * API 26 compromise (documented in the design note): Android 8 app-ops do not distinguish
 * foreground from background use, so APP-10/APP-11/APP-12 report third-party apps whose op
 * is explicitly allowed - the closest lawful read of the frozen catalog on API 26.
 */
object AuditChecksAdb {

    private const val ACTION_SECURITY = "android.settings.SECURITY_SETTINGS"
    private const val ACTION_USAGE_ACCESS = "android.settings.USAGE_ACCESS_SETTINGS"
    private const val ACTION_OVERLAY = "android.settings.action.MANAGE_OVERLAY_PERMISSION"
    private const val ACTION_INSTALL_SOURCES = "android.settings.MANAGE_UNKNOWN_APP_SOURCES"
    private const val ACTION_BATTERY_SAVER = "android.settings.BATTERY_SAVER_SETTINGS"
    private const val ACTION_APPS = "android.settings.APPLICATION_SETTINGS"

    /** App-op mode values as rendered by `dumpsys appops` on API 26. */
    private const val MODE_ALLOWED = 0

    private const val WAKE_LOCK_WARN_MS = 60L * 60L * 1000L

    private val specialAccessOps = listOf(
        "usage access" to "GET_USAGE_STATS",
        "draw over other apps" to "SYSTEM_ALERT_WINDOW",
        "install unknown apps" to "REQUEST_INSTALL_PACKAGES"
    )

    private val cameraOps = setOf("CAMERA")
    private val microphoneOps = setOf("RECORD_AUDIO")
    private val locationOps = setOf("COARSE_LOCATION", "FINE_LOCATION")

    private val catalog: List<AuditCheck> = listOf(
        def("ACC-11", "Smart Lock trust agents", AuditCategory.ACCESS_CONTROL, AuditSeverity.WARNING) { env ->
            run(env, AuditCommands.TRUST) { output ->
                val agents = trustAgents(output)
                when {
                    agents == null -> unrecognized("the 'Enabled agents' section of dumpsys trust")
                    agents.isEmpty() -> ok(
                        "Enabled agents: none",
                        "No Smart Lock (trust agent) unlock is enabled."
                    )
                    else -> issue(
                        AuditStatus.WARN,
                        "Enabled agents: ${joinCapped(agents)}",
                        "Smart Lock trust agents can keep the device unlocked in chosen situations; review them.",
                        ACTION_SECURITY
                    )
                }
            }
        },
        def("APP-09", "Special app access (system alerts, usage, overlay)", AuditCategory.APPS_PERMISSIONS, AuditSeverity.WARNING) { env ->
            opVerdict(
                env,
                specialAccessOps.map { it.second }.toSet(),
                "usage access, draw over other apps or unknown-source install",
                "special access allowances"
            ) { allowed ->
                val labels = specialAccessOps
                    .filter { (_, op) -> allowed.any { it.op == op } }
                    .joinToString("; ") { (label, op) ->
                        "$label: ${joinCapped(allowed.filter { it.op == op }.map { it.packageName }.distinct())}"
                    }
                labels to when {
                    allowed.any { it.op == "GET_USAGE_STATS" } -> ACTION_USAGE_ACCESS
                    allowed.any { it.op == "SYSTEM_ALERT_WINDOW" } -> ACTION_OVERLAY
                    else -> ACTION_INSTALL_SOURCES
                }
            }
        },
        def("APP-10", "Background camera use", AuditCategory.APPS_PERMISSIONS, AuditSeverity.CRITICAL) { env ->
            opVerdict(
                env, cameraOps, "the camera", "camera op allowed",
                note = "Android 8 app-ops cannot distinguish background use"
            ) { allowed -> opEvidence("camera", allowed) to ACTION_APPS }
        },
        def("APP-11", "Background microphone use", AuditCategory.APPS_PERMISSIONS, AuditSeverity.CRITICAL) { env ->
            opVerdict(
                env, microphoneOps, "the microphone", "microphone op allowed",
                note = "Android 8 app-ops cannot distinguish background use"
            ) { allowed -> opEvidence("microphone", allowed) to ACTION_APPS }
        },
        def("APP-12", "Background location use", AuditCategory.APPS_PERMISSIONS, AuditSeverity.WARNING) { env ->
            opVerdict(
                env, locationOps, "location", "location op allowed",
                note = "Android 8 app-ops cannot distinguish background use"
            ) { allowed -> opEvidence("location", allowed) to ACTION_APPS }
        },
        def("NET-11", "Battery drain in batterystats (limited)", AuditCategory.NETWORK_RADIOS, AuditSeverity.NOTICE) { env ->
            run(env, AuditCommands.BATTERY_STATS) { output ->
                val locks = kernelWakeLocks(output)
                when {
                    locks == null -> unrecognized("the 'All kernel wake locks' section of dumpsys batterystats --charged")
                    locks.isEmpty() -> ok(
                        "All kernel wake locks: none",
                        "No kernel wake lock was recorded since the last charge."
                    )
                    else -> {
                        val worst = locks.maxByOrNull { it.durationMs }!!
                        if (worst.durationMs >= WAKE_LOCK_WARN_MS) {
                            issue(
                                AuditStatus.WARN,
                                "worst kernel wake lock since charge: ${worst.name} ${worst.rendered}",
                                "A kernel wake lock was held for more than one hour since the last charge; a misbehaving driver or service can drain the battery.",
                                ACTION_BATTERY_SAVER
                            )
                        } else {
                            ok(
                                "worst kernel wake lock since charge: ${worst.name} ${worst.rendered}",
                                "No kernel wake lock exceeded one hour since the last charge."
                            )
                        }
                    }
                }
            }
        },
        def("NET-12", "Per-app proxy/network audit", AuditCategory.NETWORK_RADIOS, AuditSeverity.WARNING) { env ->
            run(env, AuditCommands.CONNECTIVITY) { output ->
                val proxies = connectivityProxies(output)
                when {
                    proxies == null -> unrecognized("the 'Current Networks' section of dumpsys connectivity")
                    proxies.isEmpty() -> ok(
                        "no HttpProxy in the parsed network state",
                        "No per-network HTTP proxy is configured in the connectivity state."
                    )
                    else -> issue(
                        AuditStatus.WARN,
                        "HttpProxy: ${joinCapped(proxies)}",
                        "The connectivity state carries an HTTP proxy; network traffic may be inspected or redirected."
                    )
                }
            }
        },
        def("NET-13", "Network usage stats anomalies", AuditCategory.NETWORK_RADIOS, AuditSeverity.NOTICE) { env ->
            run(env, AuditCommands.NETSTATS) { output ->
                val interfaces = netstatsInterfaces(output)
                if (interfaces == null) {
                    unrecognized("the 'Dev stats' section of dumpsys netstats")
                } else {
                    val negative = negativeCounter(output)
                    if (negative != null) {
                        issue(
                            AuditStatus.WARN,
                            "negative counter: $negative",
                            "A network stats counter is negative, which indicates a counter wrap or a corrupted stats entry."
                        )
                    } else {
                        ok(
                            "interfaces: ${if (interfaces.isEmpty()) "none listed" else interfaces.joinToString(", ")}; counters non-negative",
                            "The network stats counters parsed cleanly; no anomaly marker was found."
                        )
                    }
                }
            }
        }
    )

    // ---- runner ----

    private fun run(
        env: AuditEnv,
        command: List<String>,
        parse: (String) -> AuditResult
    ): AuditResult {
        val shell = env.shell() ?: return tierInactive()
        val result = shell.exec(command)
        if (!result.ok) {
            val detail = result.stderr.trim().lineSequence().firstOrNull()?.take(160) ?: "no stderr"
            return AuditResult(
                AuditStatus.UNKNOWN,
                "${command.joinToString(" ")} exited with ${result.exitCode}",
                "The read-only command could not run ($detail), so this check is UNKNOWN rather than a pass."
            )
        }
        val refusal = refusalReason(result.stdout)
        if (refusal != null) {
            return AuditResult(
                AuditStatus.UNKNOWN,
                "dump refused: $refusal",
                "The service refused this dump for the app uid. Some dumps need signature-level " +
                    "permissions that cannot be granted from a PC; the Shizuku tier runs the same " +
                    "read as the shell user, where it succeeds."
            )
        }
        return parse(result.stdout)
    }

    private fun tierInactive(): AuditResult = AuditResult(
        AuditStatus.NA,
        "privileged tier inactive",
        "This check needs the ADB tier (one-time DUMP grant from a PC) or the Shizuku tier; " +
            "it is N/A until one of them is active."
    )

    private fun unrecognized(what: String): AuditResult = AuditResult(
        AuditStatus.UNKNOWN,
        "unrecognized dump format",
        "The dump did not contain $what on this device/version, so this check is UNKNOWN rather than a pass."
    )

    // ---- app-ops checks ----

    /**
     * Shared verdict for the app-ops checks: third-party (non-system, installed) packages
     * whose op is explicitly allowed. [note] is appended to the finding explanation so the
     * API 26 limitation is always visible where it matters.
     */
    private fun opVerdict(
        env: AuditEnv,
        opNames: Set<String>,
        subject: String,
        passEvidence: String,
        note: String? = null,
        buildFinding: (List<OpEntry>) -> Pair<String, String>
    ): AuditResult = run(env, AuditCommands.APPOPS) { output ->
        val entries = appOpsEntries(output)
            ?: return@run unrecognized("the package/op blocks of dumpsys appops")
        val thirdParty = thirdPartyPackages(env)
            ?: return@run AuditResult(
                AuditStatus.UNKNOWN,
                "app inventory not readable",
                "Third-party packages cannot be separated from system apps, so this check is UNKNOWN rather than a pass."
            )
        val allowed = entries
            .filter { it.op in opNames && it.mode == MODE_ALLOWED && it.packageName in thirdParty }
            .distinctBy { it.packageName to it.op }
        if (allowed.isEmpty()) {
            ok("$passEvidence: none", "No third-party app is allowed to use $subject (op mode allow).")
        } else {
            val (evidence, action) = buildFinding(allowed)
            val explanation =
                "Third-party apps are allowed to use $subject; review them in the app settings." +
                    if (note == null) "" else " Note: $note."
            issue(AuditStatus.WARN, evidence, explanation, action)
        }
    }

    private fun opEvidence(label: String, allowed: List<OpEntry>): String {
        val packages = allowed.map { it.packageName }.distinct().sorted()
        return "$label op allowed: ${joinCapped(packages)}"
    }

    private data class OpEntry(val packageName: String, val op: String, val mode: Int)

    /**
     * Parses the per-package op lines of `dumpsys appops` (`NAME: mode=N; ...` inside
     * `Package <name>:` blocks under `Uid <n>:` headers). Returns null when no package
     * block was found at all (garbage or a different format).
     */
    private fun appOpsEntries(output: String): List<OpEntry>? {
        val packagePattern = Regex("^\\s*Package\\s+(\\S+):\\s*$")
        val opPattern = Regex("^\\s*([A-Z0-9_]+):\\s*mode=(\\d+)")
        val entries = ArrayList<OpEntry>()
        var currentPackage: String? = null
        var sawPackage = false
        for (line in output.lineSequence()) {
            val packageMatch = packagePattern.find(line)
            if (packageMatch != null) {
                val name = packageMatch.groupValues[1]
                currentPackage = if (isPlausiblePackage(name)) name else null
                if (currentPackage != null) sawPackage = true
                continue
            }
            val opMatch = opPattern.find(line) ?: continue
            val packageName = currentPackage ?: continue
            val mode = opMatch.groupValues[2].toIntOrNull() ?: continue
            entries.add(OpEntry(packageName, opMatch.groupValues[1], mode))
        }
        return if (sawPackage) entries else null
    }

    /** Guard against section headers such as `Package mode watchers:` matching the regex. */
    private fun isPlausiblePackage(name: String): Boolean =
        name == "android" || name == "root" || name.contains('.')

    /** Installed, non-system packages; null when the inventory itself is unreadable. */
    private fun thirdPartyPackages(env: AuditEnv): Set<String>? {
        val apps = env.installedApps()
        if (apps.isEmpty()) return null
        return apps.filter { !it.system }.map { it.packageName }.toSet()
    }

    // ---- dumpsys trust ----

    /** Trust agents listed under `Enabled agents:`; null when the section is absent. */
    private fun trustAgents(output: String): List<String>? {
        val lines = output.lineSequence().toList()
        if (lines.none { it.contains("Trust manager state") }) return null
        val headerIndex = lines.indexOfFirst { it.trim() == "Enabled agents:" }
        if (headerIndex < 0) return null
        if (lines.drop(headerIndex + 1).none { it.trim() == "Events:" }) return null
        val headerIndent = lines[headerIndex].takeWhile { it == ' ' }.length
        val agents = ArrayList<String>()
        for (index in headerIndex + 1 until lines.size) {
            val line = lines[index]
            if (line.isBlank()) continue
            if (line.takeWhile { it == ' ' }.length <= headerIndent) break
            agents.add(line.trim())
        }
        return agents.distinct()
    }

    // ---- dumpsys batterystats --charged ----

    private data class WakeLock(val name: String, val durationMs: Long, val rendered: String)

    /** Kernel wake locks under `All kernel wake locks:`; null when the section is absent. */
    private fun kernelWakeLocks(output: String): List<WakeLock>? {
        val lines = output.lineSequence().toList()
        val start = lines.indexOfFirst { it.trim() == "All kernel wake locks:" }
        if (start < 0) return null
        val pattern = Regex("^Kernel Wake lock (.+?)\\s*:\\s*(.+?)\\s*\\(\\d+ times\\)")
        val locks = ArrayList<WakeLock>()
        for (index in start + 1 until lines.size) {
            val line = lines[index].trim()
            if (line.isBlank()) continue
            if (!line.startsWith("Kernel Wake lock")) break
            val match = pattern.find(line) ?: continue
            val rendered = match.groupValues[2].trim()
            locks.add(WakeLock(match.groupValues[1].trim(), parseDuration(rendered), rendered))
        }
        return locks
    }

    /** Duration text such as "763ms", "2s 728ms", "6h 35m 14s 200ms" in milliseconds. */
    private fun parseDuration(text: String): Long {
        val pattern = Regex("(\\d+)\\s*(ms|h|m|s)")
        var total = 0L
        for (match in pattern.findAll(text)) {
            val value = match.groupValues[1].toLongOrNull() ?: continue
            total += when (match.groupValues[2]) {
                "h" -> value * 3_600_000L
                "m" -> value * 60_000L
                "s" -> value * 1_000L
                else -> value
            }
        }
        return total
    }

    // ---- dumpsys connectivity ----

    /** `HttpProxy:` entries of the current networks; null when the section is absent. */
    private fun connectivityProxies(output: String): List<String>? {
        if (!output.contains("Current Networks:")) return null
        val pattern = Regex("HttpProxy:\\s*\\[?ProxyInfo\\{([^}]*)\\}")
        val proxies = ArrayList<String>()
        for (line in output.lineSequence()) {
            val matches = pattern.findAll(line).toList()
            if (matches.isEmpty()) {
                if (line.contains("HttpProxy:")) proxies.add(line.trim().take(160))
                continue
            }
            for (match in matches) {
                val fields = match.groupValues[1].trim()
                proxies.add(if (fields.isBlank()) "ProxyInfo{}" else fields)
            }
        }
        return proxies.distinct()
    }

    // ---- dumpsys netstats ----

    /** Interface names under `Active interfaces:`; null when `Dev stats:` is absent. */
    private fun netstatsInterfaces(output: String): List<String>? {
        if (!output.contains("Dev stats:")) return null
        val lines = output.lineSequence().toList()
        val start = lines.indexOfFirst { it.trim() == "Active interfaces:" }
        if (start < 0) return emptyList()
        val pattern = Regex("^\\s*iface=(\\S+)")
        val interfaces = ArrayList<String>()
        for (index in start + 1 until lines.size) {
            val line = lines[index]
            if (line.isBlank()) break
            val match = pattern.find(line) ?: break
            interfaces.add(match.groupValues[1])
        }
        return interfaces.distinct()
    }

    /** First negative traffic counter (`rb/tb/rp/tp/op`), or null. `uid=-1` is normal. */
    private fun negativeCounter(output: String): String? =
        Regex("(?:rb|rp|tb|tp|op)=(-\\d+)").find(output)?.let { it.groupValues[0] }

    // ---- helpers ----

    /** All ADB-tier checks (8, frozen catalog). */
    fun checks(): List<AuditCheck> = catalog

    /** Lookup by catalog id, used by the tests. */
    fun checkById(id: String): AuditCheck? = catalog.firstOrNull { it.id == id }

    private fun def(
        id: String,
        title: String,
        category: AuditCategory,
        severity: AuditSeverity,
        evaluate: (AuditEnv) -> AuditResult
    ) = AuditCheck(id, title, category, severity, AuditTier.ADB, evaluate)

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

    private fun joinCapped(items: List<String>, max: Int = 5): String {
        if (items.isEmpty()) return "none"
        val head = items.take(max).joinToString(", ")
        return if (items.size > max) "$head (+${items.size - max} more)" else head
    }
}
