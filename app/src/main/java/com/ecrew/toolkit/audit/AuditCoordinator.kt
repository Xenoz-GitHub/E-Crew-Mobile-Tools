package com.ecrew.toolkit.audit

import android.content.Context
import java.util.UUID

/** Outcome of one scan session: the report plus the scored summary and its session id. */
data class AuditSessionResult(
    val sessionId: String,
    val report: AuditReport,
    val score: AuditScore,
    val startedAt: Long,
    val finishedAt: Long,
    val sdkInt: Int,
    val privilegedTier: ShellTier
)

/** Snapshot of the setup card's tier state after an explicit Recheck. */
data class AuditTierSnapshot(
    val tier: ShellTier,
    val shizuku: ShizukuState,
    val root: RootState
)

/**
 * Ties the environment, engine, `security_audit.db` store and the JSONL trail together for
 * one scan session. UI code never touches the store or the env directly.
 */
class AuditCoordinator(
    private val context: Context,
    private val store: AuditStore = AuditStore(context),
    private val engine: AuditEngine = AuditEngine(),
    private val env: AuditEnv = AndroidAuditEnv(context, rootOptIn = { store.rootOptIn() })
) {

    /** Runs a full scan: evaluate, persist, audit-log. Blocking; call from a background thread. */
    fun run(): Result<AuditSessionResult> = try {
        val sessionId = UUID.randomUUID().toString()
        val startedAt = System.currentTimeMillis()
        val muted = store.mutedIds()
        val tier = env.shell()?.source ?: ShellTier.NONE
        store.startSession(sessionId, env.sdkInt(), startedAt, tier)
        AuditAudit.append(
            context, sessionId, "session_start",
            linkedMapOf(
                "sdkInt" to env.sdkInt(),
                "checks" to engine.checkCount,
                "privilegedTier" to tier.name
            )
        )
        val report = engine.evaluate(env, muted)
        for (finding in report.findings) {
            AuditAudit.append(
                context, sessionId, "check",
                linkedMapOf(
                    "id" to finding.check.id,
                    "status" to finding.result.status.name,
                    "severity" to finding.check.severity.name,
                    "tier" to finding.check.tier.name,
                    "evidence" to finding.result.evidence
                )
            )
        }
        val score = report.score()
        val finishedAt = System.currentTimeMillis()
        store.recordFindings(sessionId, report.findings)
        store.finishSession(sessionId, score, report.findings.size, finishedAt)
        AuditAudit.append(
            context, sessionId, "session_end",
            linkedMapOf(
                "score" to score.score,
                "passedWeight" to score.passedWeight,
                "scoredWeight" to score.scoredWeight,
                "criticalCap" to score.criticalCapApplied,
                "notScored" to score.notScored,
                "checksRun" to report.findings.size
            )
        )
        Result.success(
            AuditSessionResult(
                sessionId = sessionId,
                report = report,
                score = score,
                startedAt = startedAt,
                finishedAt = finishedAt,
                sdkInt = env.sdkInt(),
                privilegedTier = tier
            )
        )
    } catch (e: Exception) {
        Result.failure(e)
    }

    /** Mutes or unmutes a check; the change is audit-logged in `mutes.jsonl`. */
    fun setMuted(checkId: String, muted: Boolean) {
        store.setMuted(checkId, muted)
        AuditAudit.append(
            context, AuditAudit.MUTES_FILE_ID,
            if (muted) "check_muted" else "check_unmuted",
            linkedMapOf("id" to checkId)
        )
    }

    fun clearMutes() {
        store.clearMutes()
        AuditAudit.append(context, AuditAudit.MUTES_FILE_ID, "mutes_cleared")
    }

    fun mutedIds(): Set<String> = store.mutedIds()

    /** The privileged tier usable right now (Root if opted in and ready, then Shizuku, then ADB). */
    fun privilegedTier(): ShellTier = env.shell()?.source ?: ShellTier.NONE

    /** Shizuku state for the setup card; never requests anything by itself. */
    fun shizukuState(): ShizukuState = AuditShizuku.state(context)

    /** Root opt-in state from `audit_settings` (design note 9d); off by default. */
    fun rootOptIn(): Boolean = store.rootOptIn()

    /**
     * Enables or disables the Root tier. Turning it off stops root reads immediately; turning
     * it on only allows the probe - the device's su manager still decides. Both are logged.
     */
    fun setRootOptIn(enabled: Boolean) {
        store.setRootOptIn(enabled)
        AuditRoot.reset()
        AuditAudit.append(
            context, AuditAudit.MUTES_FILE_ID,
            if (enabled) "root_opt_in" else "root_opt_out"
        )
    }

    /** Root state for the setup card; probes only when the opt-in is on. */
    fun rootState(): RootState =
        if (store.rootOptIn()) AuditRoot.probe().state else RootState.DISABLED

    /** Shows the Shizuku permission dialog; the UI calls this only from a user tap. */
    fun requestShizukuPermission(): Boolean = AuditShizuku.requestPermission()

    /**
     * Forgets the cached root probe, re-detects the tier and records a `tier_recheck` event.
     * Blocking (a root probe can run su); call from a background thread.
     */
    fun recheckTier(): AuditTierSnapshot {
        AuditRoot.reset()
        val tier = privilegedTier()
        val shizuku = shizukuState()
        val root = rootState()
        AuditAudit.append(
            context, AuditAudit.MUTES_FILE_ID, "tier_recheck",
            linkedMapOf(
                "tier" to tier.name,
                "shizuku" to shizuku.name,
                "root" to root.name,
                "active" to (tier != ShellTier.NONE)
            )
        )
        return AuditTierSnapshot(tier, shizuku, root)
    }

    /** Records the Shizuku permission answer; called from the permission listener. */
    fun logShizukuPermission(granted: Boolean) {
        AuditAudit.append(
            context, AuditAudit.MUTES_FILE_ID, "shizuku_permission",
            linkedMapOf("granted" to granted)
        )
    }

    /** Finished sessions, newest first. */
    fun history(limit: Int = 20): List<AuditSessionRow> =
        store.listSessions(limit).filter { it.finishedAt != null }

    /** Loads a stored session in export/display form, or null when missing or unfinished. */
    fun loadSession(sessionId: String): AuditExportSession? {
        val row = store.session(sessionId) ?: return null
        return AuditExportSession.from(row, store.loadFindings(sessionId))
    }

    /** "Hide personal details" export toggle; stored in `audit_settings`, default on. */
    fun hidePersonalDetails(): Boolean =
        store.getSetting(AuditStore.SETTING_HIDE_PERSONAL)?.toBooleanStrictOrNull() ?: true

    fun setHidePersonalDetails(hide: Boolean) {
        store.setSetting(AuditStore.SETTING_HIDE_PERSONAL, hide.toString())
    }

    /**
     * Renders and writes one session via [AuditExport] and appends an `export` event to the
     * session trail. Blocking; call from a background thread.
     */
    fun export(
        session: AuditExportSession,
        format: AuditExport.Format,
        hidePersonal: Boolean
    ): Result<String> {
        val result = AuditExport.write(context, session, format, hidePersonal)
        AuditAudit.append(
            context, session.sessionId, "export",
            linkedMapOf(
                "format" to format.name,
                "hidePersonal" to hidePersonal,
                "written" to result.isSuccess,
                "path" to result.getOrNull(),
                "error" to result.exceptionOrNull()?.message
            )
        )
        return result
    }
}
