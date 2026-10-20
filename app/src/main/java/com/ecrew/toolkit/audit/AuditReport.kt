package com.ecrew.toolkit.audit

import com.ecrew.protocol.Json
import java.time.Instant

/**
 * Export/display models and the Markdown/JSON report renderer (design note section 8).
 *
 * [AuditExportSession] is pure data: the UI lists it, "hide personal details" rewrites its
 * evidence and explanation text, and the file writer serializes it. Nothing here touches the
 * platform, so the whole renderer is JVM-testable (`AuditReportTest`).
 */

/** One finding in export form: [AuditCheck] is replaced by plain fields. */
data class AuditExportFinding(
    val id: String,
    val title: String,
    val category: AuditCategory,
    val severity: AuditSeverity,
    val tier: AuditTier,
    val status: AuditStatus,
    val evidence: String,
    val explanation: String,
    val fixAction: String?
)

/** One finished session in export form. The JSON field order of [AuditRenderer.json] is frozen
 * so two scans diff cleanly; [findings] is in catalog order. */
data class AuditExportSession(
    val sessionId: String,
    val startedAt: Long,
    val finishedAt: Long,
    val sdkInt: Int,
    val privilegedTier: ShellTier,
    val score: Int,
    val scoredWeight: Int,
    val passedWeight: Int,
    val criticalCap: Boolean,
    val notScored: Boolean,
    val findings: List<AuditExportFinding>
) {

    companion object {

        /** Builds the export form of a live scan result. */
        fun from(result: AuditSessionResult): AuditExportSession = AuditExportSession(
            sessionId = result.sessionId,
            startedAt = result.startedAt,
            finishedAt = result.finishedAt,
            sdkInt = result.sdkInt,
            privilegedTier = result.privilegedTier,
            score = result.score.score,
            scoredWeight = result.score.scoredWeight,
            passedWeight = result.score.passedWeight,
            criticalCap = result.score.criticalCapApplied,
            notScored = result.score.notScored,
            findings = result.report.findings.map { finding ->
                AuditExportFinding(
                    id = finding.check.id,
                    title = finding.check.title,
                    category = finding.check.category,
                    severity = finding.check.severity,
                    tier = finding.check.tier,
                    status = finding.result.status,
                    evidence = finding.result.evidence,
                    explanation = finding.result.explanation,
                    fixAction = finding.result.remediation?.intentAction
                )
            }
        )

        /** Stored sessions map through here; a session without a score yet returns null. */
        fun from(row: AuditSessionRow, findings: List<AuditExportFinding>): AuditExportSession? {
            if (row.finishedAt == null || row.score == null ||
                row.scoredWeight == null || row.passedWeight == null
            ) {
                return null
            }
            return AuditExportSession(
                sessionId = row.id,
                startedAt = row.startedAt,
                finishedAt = row.finishedAt,
                sdkInt = row.sdkInt,
                privilegedTier = row.privilegedTier,
                score = row.score,
                scoredWeight = row.scoredWeight,
                passedWeight = row.passedWeight,
                criticalCap = row.criticalCap,
                notScored = row.notScored,
                findings = findings
            )
        }
    }
}

/** Renders export sessions to Markdown and to JSON with optional personal-detail redaction. */
object AuditRenderer {

    /** Export schema version; bump only together with a matching `AuditReportTest` update. */
    const val SCHEMA_VERSION = 2

    /** What a hidden value is replaced with. */
    const val HIDDEN = "[hidden]"

    // IPv4 with an optional port (both are hidden together).
    private val IPV4_PORT = Regex("""\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b""")

    // Colon-separated hex groups: IPv6 (full form) and MAC addresses.
    private val HEX_HOST = Regex("""\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){2,7}\b""")

    // ProxyInfo-style host field; the value is hidden, the key survives.
    private val HOST_FIELD = Regex("""(host=)('[^']*'|"[^"]*"|[^\s,;]+)""", RegexOption.IGNORE_CASE)

    // Hostname shapes: two or more dot-separated alphanumeric labels.
    private val HOSTNAME = Regex(
        """\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\b""",
        RegexOption.IGNORE_CASE
    )

    /**
     * Replaces personal details with [HIDDEN]: IPv4/IPv6/MAC addresses, proxy `host=` values,
     * and hostnames inside DNS-related text. Over-hiding is preferred over under-hiding.
     *
     * A colon-separated hex group is only treated as an address when it has at least three
     * colons or contains a hex letter, so clock values like `12:34:56` survive.
     */
    fun redact(text: String): String {
        var out = HOST_FIELD.replace(text) { match ->
            val value = match.groupValues[2].trim('\'', '"')
            if (value.isBlank()) match.value else match.groupValues[1] + HIDDEN
        }
        out = IPV4_PORT.replace(out) { HIDDEN }
        out = HEX_HOST.replace(out) { match ->
            val host = match.value
            val colonCount = host.count { it == ':' }
            val hasHexLetter = host.any { it in 'a'..'f' || it in 'A'..'F' }
            if (colonCount >= 3 || hasHexLetter) HIDDEN else host
        }
        if (out.contains("dns", ignoreCase = true)) {
            out = HOSTNAME.replace(out) { HIDDEN }
        }
        return out
    }

    /** Renders the Markdown report; [hidePersonal] applies [redact] to evidence/explanations. */
    fun markdown(session: AuditExportSession, hidePersonal: Boolean): String = buildString {
        append("# E-Crew Security and Privacy Audit\n\n")
        append("- Session: ${session.sessionId}\n")
        append("- Started: ${iso(session.startedAt)}\n")
        append("- Finished: ${iso(session.finishedAt)}\n")
        append("- Device API level: ${session.sdkInt}\n")
        append("- Privileged tier: ${session.privilegedTier.label()}\n")
        append("- Personal details: ${if (hidePersonal) "hidden" else "shown"}\n")
        append("- Score: ${scoreLine(session)}\n")
        append("- Weights: passed ${session.passedWeight} of ${session.scoredWeight}\n")
        append("\n## Status totals\n\n")
        val counts = statusCounts(session)
        append(
            AuditStatus.values().joinToString("  ") { "${it.label()}: ${counts.getValue(it)}" }
        )
        append("\n")
        for (category in AuditCategory.values()) {
            val section = session.findings.filter { it.category == category }
            if (section.isEmpty()) continue
            append("\n## ${category.label}\n")
            for (finding in section) {
                append("\n### ${finding.id} ${finding.title} [${finding.status.name}]\n\n")
                append("- Severity: ${finding.severity.name} (weight ${finding.severity.weight})\n")
                append("- Tier: ${finding.tier.name}\n")
                append("- Evidence: ${exportable(finding.evidence, hidePersonal)}\n")
                append("- Explanation: ${exportable(finding.explanation, hidePersonal)}\n")
                val fix = finding.fixAction
                if (fix != null) append("- Fix: open the Settings action $fix\n")
            }
        }
        append("\n## Notes\n\n")
        if (hidePersonal) {
            append(
                "- Personal details were hidden: IPv4/IPv6/MAC addresses, proxy host values " +
                    "and DNS hostnames were replaced with $HIDDEN.\n"
            )
        } else {
            append("- Personal details were exported verbatim; share this report carefully.\n")
        }
        append("- The audit is read-only: no setting was changed on this device.\n")
    }

    /**
     * Renders the JSON report. Field order is frozen: schema, session, tier state, score,
     * status counts, then checks in catalog order.
     */
    fun json(session: AuditExportSession, hidePersonal: Boolean): String {
        val checks = session.findings.map { finding ->
            linkedMapOf<String, Any?>(
                "id" to finding.id,
                "title" to finding.title,
                "category" to finding.category.name,
                "severity" to finding.severity.name,
                "tier" to finding.tier.name,
                "status" to finding.status.name,
                "evidence" to exportable(finding.evidence, hidePersonal),
                "explanation" to exportable(finding.explanation, hidePersonal),
                "fix" to finding.fixAction
            )
        }
        val counts = statusCounts(session)
        val countMap = linkedMapOf<String, Any?>()
        for (status in AuditStatus.values()) countMap[status.name] = counts.getValue(status)
        val root = linkedMapOf<String, Any?>(
            "schema" to SCHEMA_VERSION,
            "sessionId" to session.sessionId,
            "startedAt" to session.startedAt,
            "startedAtIso" to iso(session.startedAt),
            "finishedAt" to session.finishedAt,
            "finishedAtIso" to iso(session.finishedAt),
            "sdkInt" to session.sdkInt,
            "privilegedTier" to session.privilegedTier.name,
            "hidePersonal" to hidePersonal,
            "score" to session.score,
            "scoredWeight" to session.scoredWeight,
            "passedWeight" to session.passedWeight,
            "criticalCapApplied" to session.criticalCap,
            "notScored" to session.notScored,
            "counts" to countMap,
            "checks" to checks
        )
        return Json.encode(root) + "\n"
    }

    private fun scoreLine(session: AuditExportSession): String = when {
        session.notScored -> "not scored (no scored checks)"
        session.criticalCap -> "${session.score}/100, capped at 40 by a critical finding"
        else -> "${session.score}/100"
    }

    private fun statusCounts(session: AuditExportSession): Map<AuditStatus, Int> {
        val counts = LinkedHashMap<AuditStatus, Int>()
        for (status in AuditStatus.values()) counts[status] = 0
        for (finding in session.findings) {
            counts[finding.status] = counts.getValue(finding.status) + 1
        }
        return counts
    }

    private fun exportable(text: String, hidePersonal: Boolean): String =
        if (hidePersonal) redact(text) else text

    private fun iso(timestamp: Long): String = Instant.ofEpochMilli(timestamp).toString()

    private fun AuditStatus.label(): String =
        if (this == AuditStatus.NA) "N/A" else name

    private fun ShellTier.label(): String = when (this) {
        ShellTier.NONE -> "none (Base only)"
        ShellTier.ADB -> "ADB"
        ShellTier.SHIZUKU -> "Shizuku"
        ShellTier.ROOT -> "Root"
    }
}
