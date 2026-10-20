package com.ecrew.toolkit.audit

/**
 * The 3 Shizuku-tier checks (prompt Component 13, catalog frozen in the design note
 * 2026-10-19-2336-security-audit-design.md and implemented per section 9c).
 *
 * Every check requires the Shizuku or Root tier shell; with the ADB shell or no shell at all
 * the result is N/A. INT-12 and ACC-13 each run exactly one command from the frozen Shizuku
 * table; ACC-12 is the documented API 26 compromise: API 26 exposes no read-only SIM PIN
 * state after unlock, so it reads the public SIM state and never reports PASS from a READY
 * SIM. The Root tier runs the same reads through its own shell (design note 9d).
 */
object AuditChecksShizuku {

    private const val ACTION_SECURITY = "android.settings.SECURITY_SETTINGS"
    private const val ACTION_VPN = "android.settings.VPN_SETTINGS"

    // TelephonyManager SIM_STATE_* values (API 26).
    private const val SIM_STATE_ABSENT = 1
    private const val SIM_STATE_PIN_REQUIRED = 2
    private const val SIM_STATE_PUK_REQUIRED = 3

    private val catalog: List<AuditCheck> = listOf(
        def("INT-12", "SELinux mode", AuditCategory.DEVICE_INTEGRITY, AuditSeverity.CRITICAL) { env ->
            val (output, error) = read(env, AuditCommands.GETENFORCE)
            if (output == null) error!! else selinux(output)
        },
        def("ACC-12", "SIM PIN enabled", AuditCategory.ACCESS_CONTROL, AuditSeverity.WARNING) { env ->
            val gate = shizukuGate(env)
            if (gate != null) gate else simPin(env.simState())
        },
        def("ACC-13", "Always-on VPN lockdown", AuditCategory.ACCESS_CONTROL, AuditSeverity.WARNING) { env ->
            val gate = shizukuGate(env)
            if (gate != null) gate else vpnLockdown(env)
        }
    )

    /** All Shizuku-tier checks (3, frozen catalog). */
    fun checks(): List<AuditCheck> = catalog

    /** Lookup by catalog id, used by the tests. */
    fun checkById(id: String): AuditCheck? = catalog.firstOrNull { it.id == id }

    // ---- runner ----

    /**
     * Runs one table command through the Shizuku shell only; returns its stdout or the
     * UNKNOWN/N-A result explaining why not. The gate lives here so no check in this file can
     * accidentally read through a weaker shell.
     */
    private fun read(env: AuditEnv, command: List<String>): Pair<String?, AuditResult?> {
        val gate = shizukuGate(env)
        if (gate != null) return null to gate
        val shell = env.shell() ?: return null to tierInactive()
        val result = shell.exec(command)
        if (!result.ok) {
            val detail = result.stderr.trim().lineSequence().firstOrNull()?.take(160) ?: "no stderr"
            return null to AuditResult(
                AuditStatus.UNKNOWN,
                "${AuditCommands.canonical(command)} failed with ${result.exitCode}",
                "The read-only command could not run through Shizuku or Root ($detail), so this check " +
                    "is UNKNOWN rather than a pass."
            )
        }
        val refusal = refusalReason(result.stdout)
        if (refusal != null) {
            return null to AuditResult(
                AuditStatus.UNKNOWN,
                "refused: $refusal",
                "The served user was refused this read, so this check is UNKNOWN rather than a pass."
            )
        }
        return result.stdout to null
    }

    /**
     * The tier gate: every check in this file runs only through Shizuku or Root. When another
     * shell (or none) is active the result is N/A, never a verdict read through a weaker tier.
     */
    private fun shizukuGate(env: AuditEnv): AuditResult? {
        val shell = env.shell()
        return when {
            shell == null -> AuditResult(
                AuditStatus.NA,
                "Shizuku tier inactive",
                "This check runs only through the Shizuku or Root tier. Install and start " +
                    "Shizuku, grant E-Crew access in the Audit tab, then re-check."
            )
            shell.source != ShellTier.SHIZUKU && shell.source != ShellTier.ROOT -> AuditResult(
                AuditStatus.NA,
                "Shizuku tier inactive (${shell.source.name} shell active)",
                "This check runs only through the Shizuku or Root tier; it is N/A while only " +
                    "the ADB tier is active, so it never reports a verdict from a weaker read."
            )
            else -> null
        }
    }

    private fun tierInactive(): AuditResult = AuditResult(
        AuditStatus.NA,
        "Shizuku tier inactive",
        "This check needs the Shizuku or Root tier; it is N/A until one of them is active."
    )

    // ---- INT-12 ----

    private fun selinux(output: String): AuditResult {
        val mode = output.lineSequence().map { it.trim() }.firstOrNull { it.isNotEmpty() }
        return when {
            mode == null -> unrecognized("any getenforce output")
            mode.equals("Enforcing", ignoreCase = true) -> AuditResult(
                AuditStatus.PASS,
                "getenforce=$mode",
                "SELinux is enforcing: the kernel blocks policy violations instead of only logging them."
            )
            mode.equals("Permissive", ignoreCase = true) -> AuditResult(
                AuditStatus.FAIL,
                "getenforce=$mode",
                "SELinux is permissive: policy violations are logged but not blocked, so a " +
                    "compromised app can reach data it should not."
            )
            mode.equals("Disabled", ignoreCase = true) -> AuditResult(
                AuditStatus.FAIL,
                "getenforce=$mode",
                "SELinux is disabled on this build; no mandatory access control is active."
            )
            else -> unrecognized("an SELinux mode (read: ${mode.take(40)})")
        }
    }

    // ---- ACC-12 (API 26 compromise, see design note 9c) ----

    private fun simPin(state: Int?): AuditResult = when (state) {
        null -> AuditResult(
            AuditStatus.UNKNOWN,
            "SIM state not disclosed",
            "Telephony did not disclose the SIM state, so this check is UNKNOWN rather than a pass."
        )
        SIM_STATE_ABSENT -> AuditResult(
            AuditStatus.NA,
            "getSimState=ABSENT",
            "The device has no SIM, so there is no SIM PIN to audit."
        )
        SIM_STATE_PIN_REQUIRED -> AuditResult(
            AuditStatus.PASS,
            "getSimState=PIN_REQUIRED",
            "The SIM is PIN-locked right now, which proves a SIM PIN is enabled."
        )
        SIM_STATE_PUK_REQUIRED -> AuditResult(
            AuditStatus.WARN,
            "getSimState=PUK_REQUIRED",
            "The SIM is PUK-locked: a PIN was enabled and the card is blocked after too many " +
                "failed attempts. Unblock it in the SIM card lock settings.",
            remediation(ACTION_SECURITY)
        )
        else -> AuditResult(
            AuditStatus.UNKNOWN,
            "getSimState=${simStateName(state)}",
            "Android 8 does not expose whether a SIM PIN is enabled once the SIM is unlocked " +
                "(the telephony dump carries no PIN field), so this check is UNKNOWN rather " +
                "than a pass. Check Security > SIM card lock manually.",
            remediation(ACTION_SECURITY)
        )
    }

    private fun simStateName(state: Int): String = when (state) {
        0 -> "UNKNOWN(0)"
        4 -> "NETWORK_LOCKED(4)"
        5 -> "READY(5)"
        6 -> "NOT_READY(6)"
        7 -> "PERM_DISABLED(7)"
        8 -> "CARD_IO_ERROR(8)"
        9 -> "CARD_RESTRICTED(9)"
        else -> "STATE($state)"
    }

    // ---- ACC-13 ----

    private fun vpnLockdown(env: AuditEnv): AuditResult {
        val (appOutput, appError) = read(env, AuditCommands.ALWAYS_ON_VPN_APP)
        if (appOutput == null) return appError!!
        val app = settingValue(appOutput)
        if (app == null) {
            return AuditResult(
                AuditStatus.NA,
                "always_on_vpn_app=unset",
                "No always-on VPN is configured, so there is no tunnel to lock down; this " +
                    "check is N/A rather than a pass."
            )
        }
        val (lockdownOutput, lockdownError) = read(env, AuditCommands.VPN_LOCKDOWN)
        if (lockdownOutput == null) return lockdownError!!
        val lockdown = settingValue(lockdownOutput)
        val evidence = "always_on_vpn_app=$app; always_on_vpn_lockdown=${lockdown ?: "unset"}"
        return when (lockdown) {
            "1", "true" -> AuditResult(
                AuditStatus.PASS,
                "$evidence (locked down)",
                "The always-on VPN is in lockdown mode: apps cannot send traffic outside the tunnel."
            )
            "0", "false", null -> AuditResult(
                AuditStatus.FAIL,
                evidence,
                "An always-on VPN is configured without lockdown, so app traffic can leave the " +
                    "device outside the tunnel. Enable 'Block connections without VPN' in the VPN settings.",
                remediation(ACTION_VPN)
            )
            else -> unrecognized("always_on_vpn_lockdown=1/0 (read: ${lockdown.take(20)})")
        }
    }

    /** `settings get` prints the literal text `null` for an unset key. */
    private fun settingValue(raw: String): String? {
        val value = raw.lineSequence().map { it.trim() }.firstOrNull { it.isNotEmpty() }
            ?: return null
        return if (value == "null") null else value
    }

    // ---- helpers ----

    private fun def(
        id: String,
        title: String,
        category: AuditCategory,
        severity: AuditSeverity,
        evaluate: (AuditEnv) -> AuditResult
    ) = AuditCheck(id, title, category, severity, AuditTier.SHIZUKU, evaluate)

    private fun unrecognized(what: String): AuditResult = AuditResult(
        AuditStatus.UNKNOWN,
        "unrecognized output format",
        "The command output did not contain $what on this device/version, so this check is " +
            "UNKNOWN rather than a pass."
    )

    private fun remediation(action: String) = AuditRemediation("Open settings", action)
}
