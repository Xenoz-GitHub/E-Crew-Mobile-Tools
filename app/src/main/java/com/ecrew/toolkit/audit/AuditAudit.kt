package com.ecrew.toolkit.audit

import android.content.Context
import com.ecrew.protocol.Json
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Per-session JSONL audit trail: `filesDir/audit/security/<sessionId>.jsonl`.
 *
 * Events: `session_start`, one `check` line per result, `session_end`, and (in the dedicated
 * `mutes.jsonl` trail) `check_muted` / `check_unmuted` / `mutes_cleared`. Local audit
 * evidence is stored raw; personal-detail redaction applies to exported reports only.
 */
object AuditAudit {

    const val MUTES_FILE_ID = "mutes"

    private val lock = Any()

    fun directory(context: Context): File = File(context.filesDir, "audit/security")

    fun sessionFile(context: Context, sessionId: String): File =
        File(directory(context), "$sessionId.jsonl")

    /** Appends one event; returns the short rendered line for in-session overlays. */
    fun append(
        context: Context,
        sessionId: String,
        type: String,
        fields: Map<String, Any?> = emptyMap()
    ): String {
        val ts = System.currentTimeMillis()
        val record = linkedMapOf<String, Any?>("ts" to ts, "type" to type)
        record.putAll(fields)
        synchronized(lock) {
            val dir = directory(context)
            if (dir.exists() || dir.mkdirs()) {
                sessionFile(context, sessionId)
                    .appendText(Json.encode(record) + "\n", Charsets.UTF_8)
            }
        }
        val time = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(ts))
        return "$time  $type"
    }
}
