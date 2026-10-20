package com.ecrew.toolkit.gridshock

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.nio.ByteBuffer

/**
 * GRIDSHOCK-only store. The schema mirrors the frozen design; this build uses
 * SQLiteOpenHelper because Room/kapt is not present in the project toolchain. No other
 * database is ever opened or referenced here.
 */
class GridshockStore(private val context: Context) :
    SQLiteOpenHelper(context, DB_NAME, null, SCHEMA_VERSION) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE scores(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mode TEXT NOT NULL,
                seed INTEGER NOT NULL,
                score INTEGER NOT NULL,
                moves INTEGER NOT NULL,
                lines INTEGER NOT NULL,
                best_combo INTEGER NOT NULL,
                perfects INTEGER NOT NULL,
                played_at INTEGER NOT NULL
            )"""
        )
        db.execSQL(
            """CREATE TABLE settings(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )"""
        )
        db.execSQL(
            """CREATE TABLE runs_in_progress(
                mode TEXT PRIMARY KEY,
                seed INTEGER NOT NULL,
                board_state BLOB NOT NULL,
                tray_state TEXT NOT NULL,
                score INTEGER NOT NULL,
                combo INTEGER NOT NULL,
                best_combo INTEGER NOT NULL,
                moves INTEGER NOT NULL,
                lines INTEGER NOT NULL,
                perfects INTEGER NOT NULL,
                overload INTEGER NOT NULL,
                overload_armed INTEGER NOT NULL,
                non_clearing INTEGER NOT NULL,
                allow_rotation INTEGER NOT NULL,
                corruption_state BLOB NOT NULL
            )"""
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // No released GRIDSHOCK schema has changed yet.
    }

    fun loadSettings(): GridshockSettings {
        val values = LinkedHashMap<String, String>()
        readableDatabase.rawQuery("SELECT key, value FROM settings", null).use { cursor ->
            while (cursor.moveToNext()) values[cursor.getString(0)] = cursor.getString(1)
        }
        return GridshockSettings(
            sound = values["sound"]?.toBooleanStrictOrNull() ?: true,
            haptics = values["haptics"]?.toBooleanStrictOrNull() ?: true,
            reduceMotion = values["reduce_motion"]?.toBooleanStrictOrNull() ?: false,
            allowRotation = values["allow_rotation"]?.toBooleanStrictOrNull() ?: false,
            lastMode = values["last_mode"]?.let { name ->
                Mode.entries.firstOrNull { it.name == name }
            } ?: Mode.CLASSIC
        )
    }

    fun saveSettings(settings: GridshockSettings) {
        putSetting("sound", settings.sound.toString())
        putSetting("haptics", settings.haptics.toString())
        putSetting("reduce_motion", settings.reduceMotion.toString())
        putSetting("allow_rotation", settings.allowRotation.toString())
        putSetting("last_mode", settings.lastMode.name)
    }

    fun putSetting(key: String, value: String) {
        val values = ContentValues().apply {
            put("key", key)
            put("value", value)
        }
        writableDatabase.insertWithOnConflict(
            "settings", null, values, SQLiteDatabase.CONFLICT_REPLACE
        )
    }

    fun recordScore(engine: GameEngine) {
        val values = ContentValues().apply {
            put("mode", engine.mode.name)
            put("seed", engine.seed)
            put("score", engine.score)
            put("moves", engine.moves)
            put("lines", engine.lines)
            put("best_combo", engine.bestCombo)
            put("perfects", engine.perfects)
            put("played_at", System.currentTimeMillis())
        }
        writableDatabase.insert("scores", null, values)
    }

    fun bestScore(mode: Mode): Int {
        readableDatabase.rawQuery(
            "SELECT MAX(score) FROM scores WHERE mode = ?", arrayOf(mode.name)
        ).use { cursor ->
            return if (cursor.moveToFirst() && !cursor.isNull(0)) cursor.getInt(0) else 0
        }
    }

    fun saveRun(engine: GameEngine) {
        val snapshot = engine.stateSnapshot()
        val values = ContentValues().apply {
            put("mode", snapshot.mode.name)
            put("seed", snapshot.seed)
            put("board_state", toBytes(snapshot.board))
            put("tray_state", snapshot.tray.joinToString(",") { it ?: "" })
            put("score", snapshot.score)
            put("combo", snapshot.combo)
            put("best_combo", snapshot.bestCombo)
            put("moves", snapshot.moves)
            put("lines", snapshot.lines)
            put("perfects", snapshot.perfects)
            put("overload", snapshot.overload)
            put("overload_armed", if (snapshot.overloadArmed) 1 else 0)
            put("non_clearing", snapshot.nonClearingMoves)
            put("allow_rotation", if (snapshot.allowRotation) 1 else 0)
            put("corruption_state", toBytes(snapshot.corruption))
        }
        writableDatabase.insertWithOnConflict(
            "runs_in_progress", null, values, SQLiteDatabase.CONFLICT_REPLACE
        )
    }

    fun loadRun(): GridshockSnapshot? {
        readableDatabase.rawQuery(
            "SELECT mode, seed, board_state, tray_state, score, combo, best_combo, moves, " +
                "lines, perfects, overload, overload_armed, non_clearing, allow_rotation, " +
                "corruption_state FROM runs_in_progress LIMIT 1",
            null
        ).use { cursor ->
            if (!cursor.moveToFirst()) return null
            val mode = Mode.entries.firstOrNull { it.name == cursor.getString(0) } ?: return null
            val board = fromBytes(cursor.getBlob(2))
            val corruption = fromBytes(cursor.getBlob(14))
            if (board.size != Board.CELL_COUNT || corruption.size != Board.CELL_COUNT) return null
            return GridshockSnapshot(
                mode = mode,
                seed = cursor.getLong(1),
                board = board,
                corruption = corruption,
                tray = cursor.getString(3).split(',').map { it.ifBlank { null } },
                score = cursor.getInt(4),
                combo = cursor.getInt(5),
                bestCombo = cursor.getInt(6),
                moves = cursor.getInt(7),
                lines = cursor.getInt(8),
                perfects = cursor.getInt(9),
                overload = cursor.getInt(10),
                overloadArmed = cursor.getInt(11) != 0,
                nonClearingMoves = cursor.getInt(12),
                allowRotation = cursor.getInt(13) != 0
            )
        }
    }

    fun clearRun() {
        writableDatabase.delete("runs_in_progress", null, null)
    }

    private fun toBytes(values: IntArray): ByteArray {
        val buffer = ByteBuffer.allocate(values.size * 4)
        values.forEach { buffer.putInt(it) }
        return buffer.array()
    }

    private fun fromBytes(bytes: ByteArray): IntArray {
        if (bytes.size % 4 != 0) return IntArray(0)
        val buffer = ByteBuffer.wrap(bytes)
        return IntArray(bytes.size / 4) { buffer.getInt() }
    }

    companion object {
        const val DB_NAME = "gridshock.db"
        const val SCHEMA_VERSION = 1
    }
}

data class GridshockSettings(
    val sound: Boolean,
    val haptics: Boolean,
    val reduceMotion: Boolean,
    val allowRotation: Boolean,
    val lastMode: Mode
)
