package com.ecrew.agent

import android.content.Context
import com.ecrew.protocol.Json
import java.io.File

/**
 * JSONL audit trail: filesDir/audit/remote/<sessionId>.jsonl, one line per protocol event
 * (direction, type, timestamp, optional note). The controller keeps its own copy; the spec
 * requires every protocol message on both sides.
 */
object AuditLog {
    private val lock = Any()

    fun append(context: Context, sessionId: String, direction: String, type: String, note: String? = null) {
        val record = linkedMapOf<String, Any?>(
            "ts" to System.currentTimeMillis(),
            "dir" to direction,
            "type" to type
        )
        if (note != null) record["note"] = note
        val line = Json.encode(record) + "\n"
        synchronized(lock) {
            val directory = File(context.filesDir, "audit/remote")
            if (!directory.exists() && !directory.mkdirs()) return
            File(directory, "$sessionId.jsonl").appendText(line, Charsets.UTF_8)
        }
    }
}
