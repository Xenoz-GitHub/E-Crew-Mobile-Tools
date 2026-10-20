package com.ecrew.toolkit.audit

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/** One scan session as stored in `security_audit.db` (plain SQLite, project convention). */
data class AuditSessionRow(
    val id: String,
    val startedAt: Long,
    val finishedAt: Long?,
    val sdkInt: Int,
    val privilegedTier: ShellTier,
    val score: Int?,
    val scoredWeight: Int?,
    val passedWeight: Int?,
    val criticalCap: Boolean,
    val notScored: Boolean,
    val checksRun: Int
)

/**
 * `security_audit.db`: sessions, findings, mutes and audit-specific settings.
 *
 * No Room, matching the WardriveDb/RemoteSessionDb/WpsAuditDb convention. Personal-detail
 * redaction applies to exported reports only; the stored evidence is the raw read value.
 */
class AuditStore(context: Context) :
    SQLiteOpenHelper(context, "security_audit.db", null, SCHEMA_VERSION) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE audit_sessions(
                id TEXT PRIMARY KEY,
                started_at INTEGER NOT NULL,
                finished_at INTEGER,
                sdk_int INTEGER NOT NULL,
                privileged_tier TEXT NOT NULL DEFAULT 'NONE',
                score INTEGER,
                scored_weight INTEGER,
                passed_weight INTEGER,
                critical_cap INTEGER NOT NULL DEFAULT 0,
                not_scored INTEGER NOT NULL DEFAULT 0,
                checks_run INTEGER NOT NULL DEFAULT 0
            )"""
        )
        db.execSQL(
            """CREATE TABLE audit_findings(
                session_id TEXT NOT NULL,
                check_id TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                tier TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                evidence TEXT NOT NULL,
                explanation TEXT NOT NULL,
                remediation_action TEXT,
                PRIMARY KEY(session_id, check_id)
            )"""
        )
        db.execSQL(
            """CREATE TABLE muted_checks(
                check_id TEXT PRIMARY KEY,
                muted_at INTEGER NOT NULL
            )"""
        )
        db.execSQL(
            """CREATE TABLE audit_settings(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )"""
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // v1 -> v2: the ADB tier state is now stored per session. Rows written before the
        // column existed default to inactive; sessions whose stored ADB findings carry a
        // real verdict are upgraded to active so history stays truthful.
        if (oldVersion < 2) {
            db.execSQL("ALTER TABLE audit_sessions ADD COLUMN adb_tier INTEGER NOT NULL DEFAULT 0")
            db.execSQL(
                """UPDATE audit_sessions SET adb_tier = 1 WHERE id IN (
                    SELECT DISTINCT session_id FROM audit_findings
                    WHERE tier = 'ADB' AND status != 'NA'
                )"""
            )
        }
        // v2 -> v3: the boolean ADB flag becomes the privileged tier a session actually ran
        // through (NONE/ADB/SHIZUKU). SQLite 3.18 (API 26) cannot drop a column in place, so
        // the table is recreated and the rows copied; findings/mutes/settings are untouched.
        if (oldVersion < 3) {
            db.execSQL(
                """CREATE TABLE audit_sessions_v3(
                    id TEXT PRIMARY KEY,
                    started_at INTEGER NOT NULL,
                    finished_at INTEGER,
                    sdk_int INTEGER NOT NULL,
                    privileged_tier TEXT NOT NULL DEFAULT 'NONE',
                    score INTEGER,
                    scored_weight INTEGER,
                    passed_weight INTEGER,
                    critical_cap INTEGER NOT NULL DEFAULT 0,
                    not_scored INTEGER NOT NULL DEFAULT 0,
                    checks_run INTEGER NOT NULL DEFAULT 0
                )"""
            )
            db.execSQL(
                """INSERT INTO audit_sessions_v3 (
                    id, started_at, finished_at, sdk_int, privileged_tier, score, scored_weight,
                    passed_weight, critical_cap, not_scored, checks_run
                ) SELECT id, started_at, finished_at, sdk_int,
                    CASE WHEN adb_tier = 1 THEN 'ADB' ELSE 'NONE' END, score, scored_weight,
                    passed_weight, critical_cap, not_scored, checks_run
                FROM audit_sessions"""
            )
            db.execSQL("DROP TABLE audit_sessions")
            db.execSQL("ALTER TABLE audit_sessions_v3 RENAME TO audit_sessions")
        }
    }

    fun startSession(id: String, sdkInt: Int, startedAt: Long, tier: ShellTier) {
        val values = ContentValues().apply {
            put("id", id)
            put("started_at", startedAt)
            put("sdk_int", sdkInt)
            put("privileged_tier", tier.name)
        }
        writableDatabase.insert("audit_sessions", null, values)
    }

    fun finishSession(id: String, score: AuditScore, checksRun: Int, finishedAt: Long) {
        val values = ContentValues().apply {
            put("finished_at", finishedAt)
            put("score", score.score)
            put("scored_weight", score.scoredWeight)
            put("passed_weight", score.passedWeight)
            put("critical_cap", if (score.criticalCapApplied) 1 else 0)
            put("not_scored", if (score.notScored) 1 else 0)
            put("checks_run", checksRun)
        }
        writableDatabase.update("audit_sessions", values, "id = ?", arrayOf(id))
    }

    fun recordFindings(sessionId: String, findings: List<AuditFinding>) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            for (finding in findings) {
                val values = ContentValues().apply {
                    put("session_id", sessionId)
                    put("check_id", finding.check.id)
                    put("status", finding.result.status.name)
                    put("severity", finding.check.severity.name)
                    put("tier", finding.check.tier.name)
                    put("category", finding.check.category.name)
                    put("title", finding.check.title)
                    put("evidence", finding.result.evidence)
                    put("explanation", finding.result.explanation)
                    put("remediation_action", finding.result.remediation?.intentAction)
                }
                db.insertWithOnConflict(
                    "audit_findings", null, values, SQLiteDatabase.CONFLICT_REPLACE
                )
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun listSessions(limit: Int = 20): List<AuditSessionRow> {
        val rows = ArrayList<AuditSessionRow>()
        readableDatabase.rawQuery(
            """SELECT id, started_at, finished_at, sdk_int, privileged_tier, score,
                      scored_weight, passed_weight, critical_cap, not_scored, checks_run
               FROM audit_sessions ORDER BY started_at DESC LIMIT ?""",
            arrayOf(limit.toString())
        ).use { cursor ->
            while (cursor.moveToNext()) rows.add(readSessionRow(cursor))
        }
        return rows
    }

    /** One session by id, or null when it was never stored. */
    fun session(id: String): AuditSessionRow? {
        readableDatabase.rawQuery(
            """SELECT id, started_at, finished_at, sdk_int, privileged_tier, score,
                      scored_weight, passed_weight, critical_cap, not_scored, checks_run
               FROM audit_sessions WHERE id = ?""",
            arrayOf(id)
        ).use { cursor ->
            return if (cursor.moveToFirst()) readSessionRow(cursor) else null
        }
    }

    /** The stored findings of one session, in catalog order (insertion order). */
    fun loadFindings(sessionId: String): List<AuditExportFinding> {
        val findings = ArrayList<AuditExportFinding>()
        readableDatabase.rawQuery(
            """SELECT check_id, status, severity, tier, category, title, evidence,
                      explanation, remediation_action
               FROM audit_findings WHERE session_id = ? ORDER BY rowid""",
            arrayOf(sessionId)
        ).use { cursor ->
            while (cursor.moveToNext()) {
                findings.add(
                    AuditExportFinding(
                        id = cursor.getString(0),
                        status = AuditStatus.valueOf(cursor.getString(1)),
                        severity = AuditSeverity.valueOf(cursor.getString(2)),
                        tier = AuditTier.valueOf(cursor.getString(3)),
                        category = AuditCategory.valueOf(cursor.getString(4)),
                        title = cursor.getString(5),
                        evidence = cursor.getString(6),
                        explanation = cursor.getString(7),
                        fixAction = if (cursor.isNull(8)) null else cursor.getString(8)
                    )
                )
            }
        }
        return findings
    }

    private fun readSessionRow(cursor: Cursor): AuditSessionRow = AuditSessionRow(
        id = cursor.getString(0),
        startedAt = cursor.getLong(1),
        finishedAt = if (cursor.isNull(2)) null else cursor.getLong(2),
        sdkInt = cursor.getInt(3),
        privilegedTier = runCatching { ShellTier.valueOf(cursor.getString(4)) }
            .getOrDefault(ShellTier.NONE),
        score = if (cursor.isNull(5)) null else cursor.getInt(5),
        scoredWeight = if (cursor.isNull(6)) null else cursor.getInt(6),
        passedWeight = if (cursor.isNull(7)) null else cursor.getInt(7),
        criticalCap = cursor.getInt(8) != 0,
        notScored = cursor.getInt(9) != 0,
        checksRun = cursor.getInt(10)
    )

    fun mutedIds(): Set<String> {
        val ids = LinkedHashSet<String>()
        readableDatabase.rawQuery("SELECT check_id FROM muted_checks", null).use { cursor ->
            while (cursor.moveToNext()) ids.add(cursor.getString(0))
        }
        return ids
    }

    fun setMuted(checkId: String, muted: Boolean) {
        if (muted) {
            val values = ContentValues().apply {
                put("check_id", checkId)
                put("muted_at", System.currentTimeMillis())
            }
            writableDatabase.insertWithOnConflict(
                "muted_checks", null, values, SQLiteDatabase.CONFLICT_REPLACE
            )
        } else {
            writableDatabase.delete("muted_checks", "check_id = ?", arrayOf(checkId))
        }
    }

    fun clearMutes() {
        writableDatabase.delete("muted_checks", null, null)
    }

    fun getSetting(key: String): String? {
        readableDatabase.rawQuery(
            "SELECT value FROM audit_settings WHERE key = ?", arrayOf(key)
        ).use { cursor ->
            return if (cursor.moveToFirst()) cursor.getString(0) else null
        }
    }

    fun setSetting(key: String, value: String) {
        val values = ContentValues().apply {
            put("key", key)
            put("value", value)
        }
        writableDatabase.insertWithOnConflict(
            "audit_settings", null, values, SQLiteDatabase.CONFLICT_REPLACE
        )
    }

    /** Root tier opt-in (design note 9d); off unless the user enabled it. */
    fun rootOptIn(): Boolean =
        getSetting(SETTING_ROOT_OPT_IN)?.toBooleanStrictOrNull() ?: false

    fun setRootOptIn(enabled: Boolean) {
        setSetting(SETTING_ROOT_OPT_IN, enabled.toString())
    }

    companion object {
        const val SCHEMA_VERSION = 3
        const val SETTING_HIDE_PERSONAL = "hide_personal_details"
        const val SETTING_ROOT_OPT_IN = "root_opt_in"
    }
}
