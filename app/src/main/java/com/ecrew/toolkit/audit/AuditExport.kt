package com.ecrew.toolkit.audit

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.annotation.RequiresApi
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Writes finished audit reports to `Downloads/E-Crew/audit/`.
 *
 * MediaStore on API 29+ (no storage permission needed); legacy external storage on API 26-28,
 * where the caller must hold WRITE_EXTERNAL_STORAGE (the UI requests it before exporting).
 * Blocking; call from a background thread.
 */
object AuditExport {

    enum class Format(val extension: String, val mimeType: String) {
        MARKDOWN("md", "text/markdown"),
        JSON("json", "application/json")
    }

    /** Folder below Downloads; shared with the other export paths of the app. */
    const val FOLDER = "E-Crew/audit"

    /** `audit-<yyyyMMdd-HHmmss>-<first 8 of the session id>.<ext>`, unique per export call. */
    fun fileName(session: AuditExportSession, format: Format, at: Long): String {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date(at))
        return "audit-$stamp-${session.sessionId.take(8)}.${format.extension}"
    }

    /** Renders and writes; returns the display path or the failure reason. Blocking. */
    fun write(
        context: Context,
        session: AuditExportSession,
        format: Format,
        hidePersonal: Boolean,
        at: Long = System.currentTimeMillis()
    ): Result<String> = try {
        val payload = when (format) {
            Format.MARKDOWN -> AuditRenderer.markdown(session, hidePersonal)
            Format.JSON -> AuditRenderer.json(session, hidePersonal)
        }
        val name = fileName(session, format, at)
        val path = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            writeMediaStore(context, name, format.mimeType, payload)
        } else {
            writeLegacy(context, name, payload)
        }
        Result.success(path)
    } catch (e: Exception) {
        Result.failure(e)
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun writeMediaStore(
        context: Context,
        name: String,
        mimeType: String,
        payload: String
    ): String {
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, name)
            put(MediaStore.Downloads.MIME_TYPE, mimeType)
            put(
                MediaStore.Downloads.RELATIVE_PATH,
                Environment.DIRECTORY_DOWNLOADS + "/" + FOLDER
            )
        }
        val uri = context.contentResolver
            .insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: throw IllegalStateException("MediaStore refused the export entry")
        val stream = context.contentResolver.openOutputStream(uri)
            ?: throw IllegalStateException("MediaStore did not open the export stream")
        stream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
        return "Download/$FOLDER/$name"
    }

    @Suppress("DEPRECATION") // the public Downloads directory is the API 26-28 contract
    private fun writeLegacy(context: Context, name: String, payload: String): String {
        val directError: Exception? = try {
            val dir = File(
                Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                FOLDER
            )
            if (!dir.exists() && !dir.mkdirs()) {
                throw IllegalStateException("could not create ${dir.absolutePath}")
            }
            val file = File(dir, name)
            file.writeText(payload, Charsets.UTF_8)
            return file.absolutePath
        } catch (e: Exception) {
            e
        }
        // Observed on the API 26 AVD: the emulated-storage layer denies app directory creation
        // in public Downloads even with the runtime grant. The app-specific external directory
        // is always writable, so the export stays on shared storage and the status line shows
        // the exact path it used.
        val fallbackRoot = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
            ?: throw IllegalStateException(
                "public Downloads failed (${directError?.message}); app-specific storage " +
                    "is not mounted"
            )
        val fallbackDir = File(fallbackRoot, FOLDER)
        if (!fallbackDir.exists() && !fallbackDir.mkdirs()) {
            throw IllegalStateException("could not create ${fallbackDir.absolutePath}")
        }
        val fallbackFile = File(fallbackDir, name)
        fallbackFile.writeText(payload, Charsets.UTF_8)
        return fallbackFile.absolutePath
    }
}
