package com.ecrew.toolkit.remote

import android.content.ContentValues
import android.content.Context
import android.media.MediaScannerConnection
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.annotation.RequiresApi
import com.ecrew.protocol.Json
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Controller-side audit trail.
 *
 * - Per-session JSONL files: filesDir/audit/remote/<sessionId>.jsonl, one line per protocol
 *   message in both directions (screen frames are recorded with size, not payload).
 * - Export: all sessions merged into a single JSONL (session header + messages) written to
 *   Downloads/E-Crew/audit via MediaStore on API 29+ (spec Component 8) and via the legacy
 *   public-Downloads path on 26-28, followed by a media scan so the file shows up in
 *   Files/USB immediately.
 */
object RemoteAudit {
    private val lock = Any()

    fun directory(context: Context): File = File(context.filesDir, "audit/remote")

    fun sessionFile(context: Context, sessionId: String): File = File(directory(context), "$sessionId.jsonl")

    /** Appends one record; returns the short line rendered in the in-session audit overlay. */
    fun append(context: Context, sessionId: String, direction: String, type: String, note: String? = null): String {
        val ts = System.currentTimeMillis()
        val record = linkedMapOf<String, Any?>(
            "ts" to ts,
            "dir" to direction,
            "type" to type
        )
        if (note != null) record["note"] = note
        synchronized(lock) {
            val dir = directory(context)
            if (dir.exists() || dir.mkdirs()) {
                sessionFile(context, sessionId).appendText(Json.encode(record) + "\n", Charsets.UTF_8)
            }
        }
        val time = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(ts))
        return if (note == null) "$time  $direction $type" else "$time  $direction $type  $note"
    }

    /** Removes the audit trail of a single session. */
    fun deleteSession(context: Context, sessionId: String) {
        synchronized(lock) {
            sessionFile(context, sessionId).delete()
        }
    }

    /** Merges every stored session into `ecrew-remote-audit_<stamp>.jsonl` in Downloads. */
    fun exportAll(context: Context, db: RemoteSessionDb): Result<String> {
        val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val fileName = "ecrew-remote-audit_$stamp.jsonl"
        val content = buildExportContent(context, db)
        return if (Build.VERSION.SDK_INT >= 29) {
            exportViaMediaStore(context, fileName, content)
        } else {
            exportLegacy(context, fileName, content)
        }
    }

    private fun buildExportContent(context: Context, db: RemoteSessionDb): String {
        val builder = StringBuilder()
        synchronized(lock) {
            for (row in db.listRecent(limit = 100_000).asReversed()) {
                val header = linkedMapOf<String, Any?>(
                    "type" to "session",
                    "sessionId" to row.sessionId,
                    "peer" to row.peer,
                    "transport" to row.transport,
                    "startedAt" to row.startedAt,
                    "endedAt" to row.endedAt,
                    "bytesIn" to row.bytesIn,
                    "bytesOut" to row.bytesOut,
                    "framesReceived" to row.frames,
                    "endReason" to row.endReason
                )
                builder.append(Json.encode(header)).append('\n')
                val file = sessionFile(context, row.sessionId)
                if (!file.exists()) continue
                for (rawLine in file.readLines()) {
                    if (rawLine.isBlank()) continue
                    builder.append(rawLine.trimEnd()).append('\n')
                }
            }
        }
        return builder.toString()
    }

    @RequiresApi(Build.VERSION_CODES.Q) // caller (exportAll) dispatches on Build.VERSION.SDK_INT
    private fun exportViaMediaStore(context: Context, fileName: String, content: String): Result<String> {
        val resolver = context.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, fileName)
            put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
            put(MediaStore.Downloads.RELATIVE_PATH, "Download/E-Crew/audit")
            put(MediaStore.Downloads.IS_PENDING, 1)
        }
        return try {
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: return Result.failure(IllegalStateException("MediaStore refused the export"))
            resolver.openOutputStream(uri)?.use { out ->
                out.write(content.toByteArray(Charsets.UTF_8))
            } ?: return Result.failure(IllegalStateException("cannot open export stream"))
            values.clear()
            values.put(MediaStore.Downloads.IS_PENDING, 0)
            resolver.update(uri, values, null, null)
            Result.success("Download/E-Crew/audit/$fileName")
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    @Suppress("DEPRECATION") // legacy public-Downloads path is only used on API 26-28
    private fun exportLegacy(context: Context, fileName: String, content: String): Result<String> {
        return try {
            val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val dir = File(downloads, "E-Crew/audit")
            if (!dir.exists() && !dir.mkdirs()) {
                return Result.failure(IllegalStateException("cannot create ${dir.absolutePath}"))
            }
            val file = File(dir, fileName)
            file.writeText(content, Charsets.UTF_8)
            MediaScannerConnection.scanFile(context, arrayOf(file.absolutePath), null, null)
            Result.success(file.absolutePath)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
