package com.ecrew.toolkit.apk

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.ecrew.toolkit.apk.fuzz.FuzzAuditRecord
import java.io.File
import java.io.FileOutputStream

/**
 * APK-specific audit storage: a dedicated SQLite database plus one JSONL file per analysis
 * session under filesDir/audit/apk. This database is owned by the APK workbench and is not
 * shared with audit, chat, GRIDSHOCK or any other module.
 */
class ApkAuditStore(context: Context) : SQLiteOpenHelper(
    context.applicationContext,
    DATABASE_NAME,
    null,
    DATABASE_VERSION
) {
    private val appContext = context.applicationContext

    override fun onCreate(database: SQLiteDatabase) {
        createAnalysisTable(database)
        createFuzzTable(database)
    }

    override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 1) createAnalysisTable(database)
        if (oldVersion < 2) createFuzzTable(database)
    }

    private fun createAnalysisTable(database: SQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS $TABLE (
                session_id TEXT PRIMARY KEY,
                started_at INTEGER NOT NULL,
                finished_at INTEGER NOT NULL,
                file_name TEXT NOT NULL,
                package_name TEXT,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                finding_count INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                medium_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                info_count INTEGER NOT NULL,
                truncated INTEGER NOT NULL,
                errors TEXT NOT NULL
            )
            """.trimIndent()
        )
    }

    private fun createFuzzTable(database: SQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS $FUZZ_TABLE (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                event_at INTEGER NOT NULL,
                target_package TEXT NOT NULL,
                component TEXT NOT NULL,
                component_type TEXT NOT NULL,
                payload_id TEXT NOT NULL,
                status TEXT NOT NULL,
                latency_ms INTEGER NOT NULL,
                crash_summary TEXT
            )
            """.trimIndent()
        )
    }

    fun record(record: ApkAuditRecord) {
        val values = ContentValues().apply {
            put("session_id", record.sessionId)
            put("started_at", record.startedAt)
            put("finished_at", record.finishedAt)
            put("file_name", record.fileName)
            put("package_name", record.packageName)
            put("sha256", record.sha256)
            put("size_bytes", record.sizeBytes)
            put("finding_count", record.findingCount)
            put("critical_count", record.criticalCount)
            put("high_count", record.highCount)
            put("medium_count", record.mediumCount)
            put("low_count", record.lowCount)
            put("info_count", record.infoCount)
            put("truncated", if (record.truncated) 1 else 0)
            put("errors", record.errors.joinToString("\n").take(MAX_ERRORS_CHARS))
        }
        writableDatabase.insertWithOnConflict(
            TABLE,
            null,
            values,
            SQLiteDatabase.CONFLICT_REPLACE
        )
        appendJsonl(record.sessionId, record.toJsonLine())
    }

    fun recordFuzz(record: FuzzAuditRecord) {
        val values = ContentValues().apply {
            put("session_id", record.sessionId)
            put("event_at", record.eventAt)
            put("target_package", record.targetPackage)
            put("component", record.component)
            put("component_type", record.componentType)
            put("payload_id", record.payloadId)
            put("status", record.status)
            put("latency_ms", record.latencyMs)
            put("crash_summary", record.crashSummary)
        }
        writableDatabase.insert(FUZZ_TABLE, null, values)
        appendJsonl(record.sessionId, record.toJsonLine())
    }

    private fun appendJsonl(sessionId: String, line: String) {
        val directory = File(appContext.filesDir, "audit/apk")
        if (!directory.isDirectory && !directory.mkdirs()) {
            throw IllegalStateException("cannot create the APK audit directory")
        }
        val target = File(directory, sessionId + ".jsonl")
        FileOutputStream(target, true).bufferedWriter().use { writer ->
            writer.write(line)
            writer.newLine()
        }
    }

    fun history(limit: Int = 50): List<ApkAuditRecord> {
        require(limit > 0) { "limit must be positive" }
        val result = ArrayList<ApkAuditRecord>()
        readableDatabase.query(
            TABLE,
            null,
            null,
            null,
            null,
            null,
            "finished_at DESC",
            limit.toString()
        ).use { cursor ->
            while (cursor.moveToNext()) {
                result.add(
                    ApkAuditRecord(
                        sessionId = cursor.getString(cursor.getColumnIndexOrThrow("session_id")),
                        startedAt = cursor.getLong(cursor.getColumnIndexOrThrow("started_at")),
                        finishedAt = cursor.getLong(cursor.getColumnIndexOrThrow("finished_at")),
                        fileName = cursor.getString(cursor.getColumnIndexOrThrow("file_name")),
                        packageName = cursor.getString(cursor.getColumnIndexOrThrow("package_name")),
                        sha256 = cursor.getString(cursor.getColumnIndexOrThrow("sha256")),
                        sizeBytes = cursor.getLong(cursor.getColumnIndexOrThrow("size_bytes")),
                        findingCount = cursor.getInt(cursor.getColumnIndexOrThrow("finding_count")),
                        criticalCount = cursor.getInt(cursor.getColumnIndexOrThrow("critical_count")),
                        highCount = cursor.getInt(cursor.getColumnIndexOrThrow("high_count")),
                        mediumCount = cursor.getInt(cursor.getColumnIndexOrThrow("medium_count")),
                        lowCount = cursor.getInt(cursor.getColumnIndexOrThrow("low_count")),
                        infoCount = cursor.getInt(cursor.getColumnIndexOrThrow("info_count")),
                        truncated = cursor.getInt(cursor.getColumnIndexOrThrow("truncated")) != 0,
                        errors = cursor.getString(cursor.getColumnIndexOrThrow("errors"))
                            .split('\n')
                            .filter { it.isNotEmpty() }
                    )
                )
            }
        }
        return result
    }

    private companion object {
        const val DATABASE_NAME = "apk_analysis.db"
        const val DATABASE_VERSION = 2
        const val TABLE = "apk_analysis_runs"
        const val FUZZ_TABLE = "apk_fuzz_events"
        const val MAX_ERRORS_CHARS = 16_000
    }
}
