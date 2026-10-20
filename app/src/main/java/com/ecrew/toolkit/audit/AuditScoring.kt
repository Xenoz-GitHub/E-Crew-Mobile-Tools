package com.ecrew.toolkit.audit

/**
 * Score = passed weight / scored weight * 100.
 *
 * Weights: Critical 10, Warning 5, Notice 2, Info 0. UNKNOWN, N/A and MUTED are excluded from
 * the denominator. A single critical failure (FAIL or WARN on a CRITICAL check) caps the
 * score at 40. With no scored checks the report is "not scored" (score 0), never 100.
 */
data class AuditScore(
    val score: Int,
    val passedWeight: Int,
    val scoredWeight: Int,
    val criticalCapApplied: Boolean,
    val notScored: Boolean
) {
    /** True when the scan produced enough information to be meaningful. */
    val isScored: Boolean get() = !notScored
}

/** Minimal scoring input: mute application already happened, only weight + status remain. */
data class ScoredCheck(val severity: AuditSeverity, val status: AuditStatus)

object AuditScoring {

    const val CRITICAL_CAP = 40

    /** The one scoring algorithm; every other entry point funnels through here. */
    fun computeChecks(checks: List<ScoredCheck>): AuditScore {
        var passedWeight = 0
        var scoredWeight = 0
        var criticalFailure = false

        for (check in checks) {
            when (check.status) {
                AuditStatus.UNKNOWN, AuditStatus.NA, AuditStatus.MUTED -> Unit
                else -> {
                    val weight = check.severity.weight
                    scoredWeight += weight
                    if (check.status == AuditStatus.PASS) passedWeight += weight
                    if (check.severity == AuditSeverity.CRITICAL &&
                        (check.status == AuditStatus.FAIL || check.status == AuditStatus.WARN)
                    ) {
                        criticalFailure = true
                    }
                }
            }
        }

        if (scoredWeight == 0) {
            return AuditScore(
                score = 0,
                passedWeight = passedWeight,
                scoredWeight = scoredWeight,
                criticalCapApplied = false,
                notScored = true
            )
        }

        val raw = Math.round(100f * passedWeight / scoredWeight)
        val capped = raw > CRITICAL_CAP && criticalFailure
        return AuditScore(
            score = if (capped) CRITICAL_CAP else raw,
            passedWeight = passedWeight,
            scoredWeight = scoredWeight,
            criticalCapApplied = capped,
            notScored = false
        )
    }

    /** Scores a live [AuditReport]; [mutedIds] overrides the status of the matching checks. */
    fun compute(findings: List<AuditFinding>, mutedIds: Set<String> = emptySet()): AuditScore =
        computeChecks(
            findings.map { finding ->
                ScoredCheck(
                    finding.check.severity,
                    if (finding.check.id in mutedIds) AuditStatus.MUTED else finding.result.status
                )
            }
        )

    /** Scores export/display findings; used by the UI to reflect mute toggles immediately. */
    fun computeExport(
        findings: List<AuditExportFinding>,
        mutedIds: Set<String> = emptySet()
    ): AuditScore = computeChecks(
        findings.map { finding ->
            ScoredCheck(
                finding.severity,
                if (finding.id in mutedIds) AuditStatus.MUTED else finding.status
            )
        }
    )
}
