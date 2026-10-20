package com.ecrew.toolkit.intercept

import android.content.Context
import com.ecrew.toolkit.audit.AuditStore
import java.io.File
import java.io.FileOutputStream
import java.util.UUID

/** JSONL trail for interception; proxy logs and header values are never written here. */
object InterceptionAudit {
    fun newSessionId(): String = UUID.randomUUID().toString()

    fun append(
        context: Context,
        sessionId: String,
        event: String,
        fields: Map<String, String> = emptyMap()
    ) {
        try {
            val directory = File(context.filesDir, "audit/interception")
            if (!directory.isDirectory && !directory.mkdirs()) return
            val target = File(directory, "$sessionId.jsonl")
            val line = buildString {
                append("{\"at\":").append(System.currentTimeMillis())
                append(",\"event\":").append(quote(event))
                fields.forEach { (key, value) ->
                    append(',').append(quote(key)).append(':').append(quote(value))
                }
                append("}\n")
            }
            FileOutputStream(target, true).bufferedWriter().use { it.write(line) }
        } catch (_: Exception) {
            // The UI still shows the state; a missing trail is never silently invented.
        }
    }

    private fun quote(value: String): String = buildString {
        append('"')
        value.forEach { character ->
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) {
                    append("\\u").append("%04x".format(character.code))
                } else {
                    append(character)
                }
            }
        }
        append('"')
    }
}

object InterceptionConsent {
    const val STATEMENT = "You are about to intercept encrypted traffic. This must only be " +
        "used on apps and devices you own or have explicit written authorization to analyze."

    fun confirmedAt(store: AuditStore): Long? =
        store.getSetting(SETTING_CONSENT)?.toLongOrNull()

    fun confirm(context: Context, store: AuditStore, sessionId: String): Long {
        val now = System.currentTimeMillis()
        store.setSetting(SETTING_CONSENT, now.toString())
        InterceptionAudit.append(
            context,
            sessionId,
            "consent_granted",
            mapOf("statement" to STATEMENT)
        )
        return now
    }

    fun revoke(store: AuditStore) {
        store.setSetting(SETTING_CONSENT, "")
    }

    const val SETTING_CONSENT = "intercept_consent_at"
}
