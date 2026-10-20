package com.ecrew.toolkit.wps

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * wps_audit table, one row per startWps attempt (plain SQLite, matching the
 * WardriveDb/RemoteSessionDb convention; no Room). Every row carries the consent text
 * that was on screen when the run started.
 */
class WpsAuditDb(context: Context) :
    SQLiteOpenHelper(context, "wps.db", null, SCHEMA_VERSION), WpsAuditSink {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE wps_audit(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                ssid TEXT,
                bssid TEXT NOT NULL,
                pin_tested TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                result TEXT NOT NULL,
                lockout_detected INTEGER NOT NULL,
                consent_text TEXT NOT NULL,
                note TEXT
            )"""
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // v1: nothing yet
    }

    override fun record(entry: WpsAuditEntry) {
        val values = ContentValues().apply {
            put("ts", System.currentTimeMillis())
            put("ssid", entry.ssid)
            put("bssid", entry.bssid)
            put("pin_tested", entry.pinTested)
            put("algorithm", entry.algorithm)
            put("result", entry.result)
            put("lockout_detected", if (entry.lockoutDetected) 1 else 0)
            put("consent_text", entry.consentText)
            put("note", entry.note)
        }
        writableDatabase.insert("wps_audit", null, values)
    }

    /** Number of recorded attempts (used by the instrumented test). */
    fun rowCount(): Int =
        readableDatabase.rawQuery("SELECT COUNT(*) FROM wps_audit", null).use { cursor ->
            if (cursor.moveToFirst()) cursor.getInt(0) else 0
        }

    companion object {
        const val SCHEMA_VERSION = 1
    }
}
