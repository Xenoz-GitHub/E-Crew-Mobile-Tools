package com.ecrew.toolkit.remote

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteOpenHelper

/**
 * One row per remote-support session (recorded decision D1: plain SQLite on purpose -
 * no Room/kapt, matching the project-wide convention). The per-message record lives in
 * the JSONL audit files written by [RemoteAudit]; this table is the index surfaced on
 * the Audit screen and in exports.
 *
 * Column set recorded as F5 in the design note: session identity + endpoints + timing +
 * byte/frame counters + end reason (the exact Room column list from the spec was not
 * recoverable from the notes; these cover every field the spec's acceptance criteria name).
 */
class RemoteSessionDb(context: Context) :
    SQLiteOpenHelper(context, "remote.db", null, SCHEMA_VERSION) {

    override fun onCreate(db: android.database.sqlite.SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE remote_sessions(
                session_id TEXT PRIMARY KEY,
                peer TEXT NOT NULL,
                transport TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                ended_at INTEGER,
                bytes_in INTEGER NOT NULL DEFAULT 0,
                bytes_out INTEGER NOT NULL DEFAULT 0,
                frames_received INTEGER NOT NULL DEFAULT 0,
                end_reason TEXT
            )"""
        )
        db.execSQL("CREATE INDEX idx_remote_started ON remote_sessions(started_at)")
    }

    override fun onUpgrade(db: android.database.sqlite.SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // v1: nothing yet
    }

    fun insertStart(sessionId: String, peer: String, transport: String, startedAt: Long) {
        val values = ContentValues().apply {
            put("session_id", sessionId)
            put("peer", peer)
            put("transport", transport)
            put("started_at", startedAt)
        }
        writableDatabase.insertWithOnConflict(
            "remote_sessions", null, values, android.database.sqlite.SQLiteDatabase.CONFLICT_REPLACE
        )
    }

    fun finish(
        sessionId: String,
        endedAt: Long,
        bytesIn: Long,
        bytesOut: Long,
        framesReceived: Long,
        endReason: String
    ) {
        val values = ContentValues().apply {
            put("ended_at", endedAt)
            put("bytes_in", bytesIn)
            put("bytes_out", bytesOut)
            put("frames_received", framesReceived)
            put("end_reason", endReason)
        }
        writableDatabase.update("remote_sessions", values, "session_id = ?", arrayOf(sessionId))
    }

    data class Row(
        val sessionId: String,
        val peer: String,
        val transport: String,
        val startedAt: Long,
        val endedAt: Long?,
        val bytesIn: Long,
        val bytesOut: Long,
        val frames: Long,
        val endReason: String?
    )

    fun listRecent(limit: Int = 200): List<Row> {
        val rows = ArrayList<Row>()
        readableDatabase.rawQuery(
            "SELECT * FROM remote_sessions ORDER BY started_at DESC LIMIT ?",
            arrayOf(limit.toString())
        ).use { c ->
            while (c.moveToNext()) {
                rows.add(
                    Row(
                        sessionId = c.getString(c.getColumnIndexOrThrow("session_id")),
                        peer = c.getString(c.getColumnIndexOrThrow("peer")),
                        transport = c.getString(c.getColumnIndexOrThrow("transport")),
                        startedAt = c.getLong(c.getColumnIndexOrThrow("started_at")),
                        endedAt = if (c.isNull(c.getColumnIndexOrThrow("ended_at"))) null
                        else c.getLong(c.getColumnIndexOrThrow("ended_at")),
                        bytesIn = c.getLong(c.getColumnIndexOrThrow("bytes_in")),
                        bytesOut = c.getLong(c.getColumnIndexOrThrow("bytes_out")),
                        frames = c.getLong(c.getColumnIndexOrThrow("frames_received")),
                        endReason = c.getString(c.getColumnIndexOrThrow("end_reason"))
                    )
                )
            }
        }
        return rows
    }

    fun count(): Int =
        readableDatabase.rawQuery("SELECT COUNT(*) FROM remote_sessions", null).use { c ->
            if (c.moveToFirst()) c.getInt(0) else 0
        }

    companion object {
        const val SCHEMA_VERSION = 1
    }
}
