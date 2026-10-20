package com.ecrew.toolkit.audit

/**
 * Read-only audit engine.
 *
 * Runs the registered checks sequentially against an [AuditEnv] and returns an [AuditReport].
 * A check that throws is reported as UNKNOWN with the exception class and message in the
 * evidence; the scan never aborts and nothing is swallowed silently.
 *
 * The default catalog is Base (39) + ADB (8) + Shizuku (3) + Root (4) = 54 checks. The tier
 * gating itself lives in the privileged tier code.
 */
class AuditEngine(private val checks: List<AuditCheck> = defaultCatalog()) {

    val checkCount: Int get() = checks.size

    fun evaluate(env: AuditEnv, mutedIds: Set<String> = emptySet()): AuditReport {
        val findings = ArrayList<AuditFinding>(checks.size)
        for (check in checks) {
            findings.add(AuditFinding(check, runCheck(check, env)))
        }
        return AuditReport(findings, mutedIds)
    }

    private fun runCheck(check: AuditCheck, env: AuditEnv): AuditResult = try {
        check.run(env)
    } catch (e: Exception) {
        AuditResult(
            AuditStatus.UNKNOWN,
            "check failed: ${e.javaClass.simpleName}: ${e.message ?: "no message"}",
            "The check could not complete on this device and is reported as UNKNOWN."
        )
    }

    companion object {
        /** Base (39) + ADB (8) + Shizuku (3) + Root (4). */
        fun defaultCatalog(): List<AuditCheck> =
            AuditChecksBase.checks() + AuditChecksAdb.checks() + AuditChecksShizuku.checks() +
                AuditChecksRoot.checks()
    }
}
