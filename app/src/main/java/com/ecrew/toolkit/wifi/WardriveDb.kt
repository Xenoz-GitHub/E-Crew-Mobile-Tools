package com.ecrew.toolkit.wifi

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.location.Location
import java.io.File
import java.io.FileWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Local SQLite store for wardriving observations (Wi-Fi scan correlated with
 * GPS). CSV export is written to app-scoped storage - no permissions needed.
 */
class WardriveDb(context: Context) :
    SQLiteOpenHelper(context, "wardrive.db", null, SCHEMA_VERSION) {

    companion object {
        const val SCHEMA_VERSION = 1
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE obs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                ssid TEXT, bssid TEXT,
                rssi INTEGER, freq INTEGER, channel INTEGER, sec TEXT,
                lat REAL, lon REAL, acc REAL, speed REAL
            )"""
        )
        db.execSQL("CREATE INDEX idx_obs_ts ON obs(ts)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // v1: nothing yet
    }

    /** Insert one observation per AP; returns rows written. */
    fun logScan(aps: List<ApInfo>, loc: Location?): Int {
        val db = writableDatabase
        val ts = System.currentTimeMillis()
        db.beginTransaction()
        try {
            for (ap in aps) {
                val cv = ContentValues().apply {
                    put("ts", ts)
                    put("ssid", ap.ssid)
                    put("bssid", ap.bssid)
                    put("rssi", ap.rssi)
                    put("freq", ap.frequency)
                    put("channel", ap.channel)
                    put("sec", ap.security)
                    if (loc != null) {
                        put("lat", loc.latitude)
                        put("lon", loc.longitude)
                        put("acc", loc.accuracy.toDouble())
                        put("speed", loc.speed.toDouble())
                    } else {
                        putNull("lat"); putNull("lon"); putNull("acc"); putNull("speed")
                    }
                }
                db.insert("obs", null, cv)
            }
            db.setTransactionSuccessful()
            return aps.size
        } finally {
            db.endTransaction()
        }
    }

    fun count(): Int =
        readableDatabase.rawQuery("SELECT COUNT(*) FROM obs", null).use { c ->
            if (c.moveToFirst()) c.getInt(0) else 0
        }

    /** WiGLE-style CSV export (local file, share via Files tab / adb). */
    fun exportCsv(context: Context): File? {
        val dir = context.getExternalFilesDir(null) ?: File(context.filesDir, "exports")
        val exportDir = File(dir, "exports").apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val file = File(exportDir, "wardrive_$stamp.csv")
        return try {
            val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).also {
                it.timeZone = java.util.TimeZone.getTimeZone("UTC")
            }
            FileWriter(file).use { w ->
                w.append("timestamp,ssid,bssid,rssi_dbm,frequency_mhz,channel,security,latitude,longitude,accuracy_m,speed_mps\n")
                readableDatabase.rawQuery("SELECT * FROM obs ORDER BY ts ASC", null).use { c ->
                    while (c.moveToNext()) {
                        val ts = sdf.format(Date(c.getLong(c.getColumnIndexOrThrow("ts"))))
                        fun optDouble(col: String): String =
                            if (c.isNull(c.getColumnIndexOrThrow(col))) "" else
                                c.getDouble(c.getColumnIndexOrThrow(col)).toString()
                        w.append(csv(ts)).append(',')
                            .append(csv(c.getString(c.getColumnIndexOrThrow("ssid")) ?: "")).append(',')
                            .append(csv(c.getString(c.getColumnIndexOrThrow("bssid")) ?: "")).append(',')
                            .append(c.getInt(c.getColumnIndexOrThrow("rssi")).toString()).append(',')
                            .append(c.getInt(c.getColumnIndexOrThrow("freq")).toString()).append(',')
                            .append(c.getInt(c.getColumnIndexOrThrow("channel")).toString()).append(',')
                            .append(csv(c.getString(c.getColumnIndexOrThrow("sec")) ?: "")).append(',')
                            .append(optDouble("lat")).append(',')
                            .append(optDouble("lon")).append(',')
                            .append(optDouble("acc")).append(',')
                            .append(optDouble("speed")).append('\n')
                    }
                }
            }
            file
        } catch (e: Exception) {
            null
        }
    }

    private fun csv(v: String): String =
        if (v.contains(',') || v.contains('"') || v.contains('\n'))
            "\"" + v.replace("\"", "\"\"") + "\"" else v
}

