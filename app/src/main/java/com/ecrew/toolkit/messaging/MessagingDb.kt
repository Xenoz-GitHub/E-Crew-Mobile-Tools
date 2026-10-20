package com.ecrew.toolkit.messaging

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * messages.db (schema v2, design notes Components 11-12): peers, messages and the
 * Xairex assistant transcript (ai_messages). Plain SQLiteOpenHelper per the
 * project-wide convention (no Room/kapt).
 *
 * Schema extensions recorded in the implementation note: `read` (unread badges),
 * `last_attempt` (retry backoff) and `bt_address` (Bluetooth redelivery target).
 *
 * A single process-wide instance ([get]) is shared by the UI and the foreground service so
 * all writes serialize on one connection; WAL keeps readers unblocked.
 */
class MessagingDb internal constructor(context: Context, dbName: String) :
    SQLiteOpenHelper(context.applicationContext, dbName, null, SCHEMA_VERSION), MessageStore {

    constructor(context: Context) : this(context, DB_NAME)

    init {
        setWriteAheadLoggingEnabled(true)
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE peers(
                id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                verified INTEGER NOT NULL DEFAULT 0,
                blocked INTEGER NOT NULL DEFAULT 0,
                bt_address TEXT
            )"""
        )
        db.execSQL(
            """CREATE TABLE messages(
                id TEXT PRIMARY KEY,
                peer_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                body TEXT NOT NULL,
                ts INTEGER NOT NULL,
                state TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_attempt INTEGER NOT NULL DEFAULT 0,
                read INTEGER NOT NULL DEFAULT 1
            )"""
        )
        db.execSQL("CREATE INDEX idx_msg_peer_ts ON messages(peer_id, ts)")
        db.execSQL("CREATE INDEX idx_msg_state ON messages(state)")
        createAiMessages(db)
    }

    private fun createAiMessages(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE ai_messages(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role TEXT NOT NULL,
                body TEXT NOT NULL,
                ts INTEGER NOT NULL
            )"""
        )
        db.execSQL("CREATE INDEX idx_ai_ts ON ai_messages(ts)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // v1 -> v2: the Xairex assistant transcript (Component 12).
        if (oldVersion < 2) createAiMessages(db)
    }

    // ---------------------------------------------------------------- peers

    override fun upsertPeer(id: String, displayName: String, now: Long) {
        val insert = ContentValues().apply {
            put("id", id)
            put("display_name", displayName)
            put("first_seen", now)
            put("last_seen", now)
        }
        val inserted = writableDatabase.insertWithOnConflict(
            "peers", null, insert, SQLiteDatabase.CONFLICT_IGNORE
        )
        if (inserted == -1L) {
            val update = ContentValues().apply {
                put("display_name", displayName)
                put("last_seen", now)
            }
            writableDatabase.update("peers", update, "id = ?", arrayOf(id))
        }
    }

    override fun peer(id: String): PeerRow? =
        readableDatabase.rawQuery("SELECT * FROM peers WHERE id = ?", arrayOf(id)).use { c ->
            if (c.moveToFirst()) readPeer(c) else null
        }

    override fun setVerified(id: String, verified: Boolean) =
        setFlag(id, "verified", verified)

    override fun setBlocked(id: String, blocked: Boolean) =
        setFlag(id, "blocked", blocked)

    override fun setBtAddress(id: String, address: String) {
        val values = ContentValues().apply { put("bt_address", address) }
        writableDatabase.update("peers", values, "id = ?", arrayOf(id))
    }

    private fun setFlag(id: String, column: String, value: Boolean) {
        val values = ContentValues().apply { put(column, if (value) 1 else 0) }
        writableDatabase.update("peers", values, "id = ?", arrayOf(id))
    }

    private fun readPeer(c: android.database.Cursor): PeerRow = PeerRow(
        id = c.getString(c.getColumnIndexOrThrow("id")),
        displayName = c.getString(c.getColumnIndexOrThrow("display_name")),
        firstSeen = c.getLong(c.getColumnIndexOrThrow("first_seen")),
        lastSeen = c.getLong(c.getColumnIndexOrThrow("last_seen")),
        verified = c.getInt(c.getColumnIndexOrThrow("verified")) != 0,
        blocked = c.getInt(c.getColumnIndexOrThrow("blocked")) != 0,
        btAddress = if (c.isNull(c.getColumnIndexOrThrow("bt_address"))) null
        else c.getString(c.getColumnIndexOrThrow("bt_address"))
    )

    // ---------------------------------------------------------------- messages

    override fun insertMessage(row: MessageRow): Boolean {
        val values = ContentValues().apply {
            put("id", row.id)
            put("peer_id", row.peerId)
            put("direction", row.direction)
            put("body", row.body)
            put("ts", row.ts)
            put("state", row.state)
            put("attempts", row.attempts)
            put("last_attempt", row.lastAttempt)
            put("read", if (row.read) 1 else 0)
        }
        return writableDatabase.insertWithOnConflict(
            "messages", null, values, SQLiteDatabase.CONFLICT_IGNORE
        ) != -1L
    }

    override fun outgoingPending(peerId: String): List<MessageRow> {
        val rows = ArrayList<MessageRow>()
        readableDatabase.rawQuery(
            """SELECT * FROM messages
               WHERE peer_id = ? AND direction = 'out' AND state IN ('queued','sent')
               ORDER BY ts ASC LIMIT 80""",
            arrayOf(peerId)
        ).use { c ->
            while (c.moveToNext()) rows.add(readMessage(c))
        }
        return rows
    }

    override fun peersWithPending(): List<String> {
        val rows = ArrayList<String>()
        readableDatabase.rawQuery(
            "SELECT DISTINCT peer_id FROM messages WHERE direction = 'out' AND state IN ('queued','sent')",
            null
        ).use { c ->
            while (c.moveToNext()) rows.add(c.getString(0))
        }
        return rows
    }

    override fun markSent(id: String, now: Long) {
        writableDatabase.execSQL(
            "UPDATE messages SET state = 'sent', attempts = attempts + 1, last_attempt = ? WHERE id = ?",
            arrayOf<Any>(now, id)
        )
    }

    override fun markDelivered(id: String) {
        writableDatabase.execSQL(
            "UPDATE messages SET state = 'delivered' WHERE id = ?", arrayOf<Any>(id)
        )
    }

    override fun expireOutgoing(now: Long, expiryMs: Long): Int {
        val cutoff = now - expiryMs
        val values = ContentValues().apply { put("state", MsgState.FAILED) }
        return writableDatabase.update(
            "messages", values,
            "direction = 'out' AND state IN ('queued','sent') AND ts < ?",
            arrayOf(cutoff.toString())
        )
    }

    override fun conversation(peerId: String): List<MessageRow> {
        val rows = ArrayList<MessageRow>()
        readableDatabase.rawQuery(
            "SELECT * FROM messages WHERE peer_id = ? ORDER BY ts DESC LIMIT 400",
            arrayOf(peerId)
        ).use { c ->
            while (c.moveToNext()) rows.add(readMessage(c))
        }
        return rows.reversed()
    }

    override fun conversations(): List<Conversation> {
        val rows = ArrayList<Conversation>()
        readableDatabase.rawQuery(
            """SELECT p.*, m.body AS last_body, m.ts AS last_ts, m.direction AS last_dir,
                      (SELECT COUNT(*) FROM messages u
                       WHERE u.peer_id = p.id AND u.direction = 'in' AND u.read = 0) AS unread
               FROM peers p
               JOIN messages m ON m.id =
                   (SELECT m2.id FROM messages m2 WHERE m2.peer_id = p.id ORDER BY m2.ts DESC LIMIT 1)
               ORDER BY m.ts DESC LIMIT 200""",
            null
        ).use { c ->
            while (c.moveToNext()) {
                rows.add(
                    Conversation(
                        peer = readPeer(c),
                        lastBody = c.getString(c.getColumnIndexOrThrow("last_body")),
                        lastTs = c.getLong(c.getColumnIndexOrThrow("last_ts")),
                        lastOutgoing = c.getString(c.getColumnIndexOrThrow("last_dir")) == MsgDirection.OUT,
                        unread = c.getInt(c.getColumnIndexOrThrow("unread"))
                    )
                )
            }
        }
        return rows
    }

    override fun markRead(peerId: String) {
        writableDatabase.execSQL(
            "UPDATE messages SET read = 1 WHERE peer_id = ? AND direction = 'in' AND read = 0",
            arrayOf<Any>(peerId)
        )
    }

    // ------------------------------------------------------- assistant (Xairex)

    /** Oldest-first transcript window (the caller caps prompt history separately). */
    fun aiMessages(limit: Int = 400): List<AiMessageRow> {
        val rows = ArrayList<AiMessageRow>()
        readableDatabase.rawQuery(
            "SELECT * FROM ai_messages ORDER BY id DESC LIMIT ?",
            arrayOf(limit.toString())
        ).use { c ->
            while (c.moveToNext()) rows.add(readAiMessage(c))
        }
        return rows.reversed()
    }

    fun appendAiMessage(role: String, body: String, ts: Long): Long {
        val values = ContentValues().apply {
            put("role", role)
            put("body", body)
            put("ts", ts)
        }
        return writableDatabase.insert("ai_messages", null, values)
    }

    fun clearAiMessages() {
        writableDatabase.delete("ai_messages", null, null)
    }

    private fun readAiMessage(c: android.database.Cursor): AiMessageRow = AiMessageRow(
        id = c.getLong(c.getColumnIndexOrThrow("id")),
        role = c.getString(c.getColumnIndexOrThrow("role")),
        body = c.getString(c.getColumnIndexOrThrow("body")),
        ts = c.getLong(c.getColumnIndexOrThrow("ts"))
    )

    private fun readMessage(c: android.database.Cursor): MessageRow = MessageRow(
        id = c.getString(c.getColumnIndexOrThrow("id")),
        peerId = c.getString(c.getColumnIndexOrThrow("peer_id")),
        direction = c.getString(c.getColumnIndexOrThrow("direction")),
        body = c.getString(c.getColumnIndexOrThrow("body")),
        ts = c.getLong(c.getColumnIndexOrThrow("ts")),
        state = c.getString(c.getColumnIndexOrThrow("state")),
        attempts = c.getInt(c.getColumnIndexOrThrow("attempts")),
        lastAttempt = c.getLong(c.getColumnIndexOrThrow("last_attempt")),
        read = c.getInt(c.getColumnIndexOrThrow("read")) != 0
    )

    companion object {
        const val DB_NAME = "messages.db"
        const val SCHEMA_VERSION = 2

        @Volatile
        private var instance: MessagingDb? = null

        /** Process-wide instance shared by the UI and the messaging service. */
        fun get(context: Context): MessagingDb {
            instance?.let { return it }
            return synchronized(this) {
                instance ?: MessagingDb(context).also { instance = it }
            }
        }
    }
}
