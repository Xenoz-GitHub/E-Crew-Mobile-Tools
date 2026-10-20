package com.ecrew.toolkit.apk

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.io.File
import java.io.FileOutputStream

/**
 * Receives an APK content URI from a picker or a VIEW/SEND intent and copies it into the
 * app cache so the ZIP parsers have a stable, seekable file. The copy is capped and the
 * display name is reduced to a safe file name.
 */
object ApkFileIntake {
    var pendingUri by mutableStateOf<Uri?>(null)

    fun accept(intent: Intent?): Boolean {
        if (intent == null) return false
        val uri = when (intent.action) {
            Intent.ACTION_VIEW -> intent.data
            Intent.ACTION_SEND -> streamUri(intent)
            else -> null
        } ?: return false
        val type = intent.type ?: ""
        val looksLikeApk = type == "application/vnd.android.package-archive" ||
            type == "application/zip" ||
            type == "application/octet-stream" ||
            uri.lastPathSegment?.endsWith(".apk", ignoreCase = true) == true
        if (!looksLikeApk) return false
        pendingUri = uri
        return true
    }

    fun copyToCache(
        context: Context,
        uri: Uri,
        maxBytes: Long = 512L * 1024 * 1024
    ): File {
        val directory = File(context.cacheDir, "apk-intake")
        if (!directory.isDirectory && !directory.mkdirs()) {
            throw IllegalArgumentException("cannot create the APK cache directory")
        }
        val name = displayName(context, uri)
        val target = File(
            directory,
            System.currentTimeMillis().toString() + "-" + safeName(name)
        )
        val input = context.contentResolver.openInputStream(uri)
            ?: throw IllegalArgumentException("cannot open the selected APK")
        try {
            FileOutputStream(target).use { output ->
                input.use { source ->
                    val buffer = ByteArray(16 * 1024)
                    var total = 0L
                    while (true) {
                        val count = source.read(buffer)
                        if (count < 0) break
                        if (count == 0) continue
                        total += count
                        if (total > maxBytes) {
                            throw IllegalArgumentException(
                                "selected APK exceeds the ${maxBytes / (1024 * 1024)} MiB cap"
                            )
                        }
                        output.write(buffer, 0, count)
                    }
                }
            }
        } catch (error: Exception) {
            target.delete()
            throw error
        }
        return target
    }

    @Suppress("DEPRECATION")
    private fun streamUri(intent: Intent): Uri? =
        intent.getParcelableExtra(Intent.EXTRA_STREAM)

    private fun displayName(context: Context, uri: Uri): String {
        val projection = arrayOf(OpenableColumns.DISPLAY_NAME)
        return try {
            context.contentResolver.query(uri, projection, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (index >= 0) cursor.getString(index) else null
                } else {
                    null
                }
            } ?: uri.lastPathSegment ?: "picked.apk"
        } catch (_: RuntimeException) {
            uri.lastPathSegment ?: "picked.apk"
        }
    }

    private fun safeName(name: String): String {
        val cleaned = name.substringAfterLast('/')
            .substringAfterLast('\\')
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
            .take(96)
        return if (cleaned.isEmpty() || cleaned == "." || cleaned == "..") {
            "picked.apk"
        } else {
            cleaned
        }
    }
}
