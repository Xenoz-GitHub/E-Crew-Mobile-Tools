package com.ecrew.toolkit.apk

import java.util.Locale

/**
 * One completed APK analysis audit row. It deliberately contains no secret previews, URLs,
 * payloads or raw finding evidence; only counts and the APK hash are stored here.
 */
data class ApkAuditRecord(
    val sessionId: String,
    val startedAt: Long,
    val finishedAt: Long,
    val fileName: String,
    val packageName: String?,
    val sha256: String,
    val sizeBytes: Long,
    val findingCount: Int,
    val criticalCount: Int,
    val highCount: Int,
    val mediumCount: Int,
    val lowCount: Int,
    val infoCount: Int,
    val truncated: Boolean,
    val errors: List<String>
) {
    fun toJsonLine(): String = buildString {
        append('{')
        field("type", "analysis")
        append(',')
        field("sessionId", sessionId)
        append(',')
        field("startedAt", startedAt)
        append(',')
        field("finishedAt", finishedAt)
        append(',')
        field("fileName", fileName)
        append(',')
        field("packageName", packageName)
        append(',')
        field("sha256", sha256)
        append(',')
        field("sizeBytes", sizeBytes)
        append(',')
        field("findingCount", findingCount)
        append(',')
        field("criticalCount", criticalCount)
        append(',')
        field("highCount", highCount)
        append(',')
        field("mediumCount", mediumCount)
        append(',')
        field("lowCount", lowCount)
        append(',')
        field("infoCount", infoCount)
        append(',')
        field("truncated", truncated)
        append(',')
        append("\"errors\":[")
        errors.forEachIndexed { index, error ->
            if (index > 0) append(',')
            append(quote(error))
        }
        append(']')
        append('}')
    }

    private fun StringBuilder.field(name: String, value: String?) {
        append(quote(name))
        append(':')
        if (value == null) append("null") else append(quote(value))
    }

    private fun StringBuilder.field(name: String, value: Long) {
        append(quote(name))
        append(':')
        append(value)
    }

    private fun StringBuilder.field(name: String, value: Int) {
        append(quote(name))
        append(':')
        append(value)
    }

    private fun StringBuilder.field(name: String, value: Boolean) {
        append(quote(name))
        append(':')
        append(value)
    }

    companion object {
        fun quote(value: String): String = buildString {
            append('"')
            for (character in value) {
                when (character) {
                    '"' -> append("\\\"")
                    '\\' -> append("\\\\")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> {
                        if (character.code < 0x20) {
                            append(String.format(Locale.US, "\\u%04x", character.code))
                        } else {
                            append(character)
                        }
                    }
                }
            }
            append('"')
        }
    }
}
