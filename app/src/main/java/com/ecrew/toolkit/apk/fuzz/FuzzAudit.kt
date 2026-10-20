package com.ecrew.toolkit.apk.fuzz

import com.ecrew.toolkit.apk.ApkAuditRecord

/** One dynamic fuzz event. Only the payload id is stored, never the payload value. */
data class FuzzAuditRecord(
    val sessionId: String,
    val eventAt: Long,
    val targetPackage: String,
    val component: String,
    val componentType: String,
    val payloadId: String,
    val status: String,
    val latencyMs: Long,
    val crashSummary: String?
) {
    fun toJsonLine(): String = buildString {
        append('{')
        field("type", "fuzz")
        append(',')
        field("sessionId", sessionId)
        append(',')
        field("eventAt", eventAt)
        append(',')
        field("targetPackage", targetPackage)
        append(',')
        field("component", component)
        append(',')
        field("componentType", componentType)
        append(',')
        field("payloadId", payloadId)
        append(',')
        field("status", status)
        append(',')
        field("latencyMs", latencyMs)
        append(',')
        field("crashSummary", crashSummary)
        append('}')
    }

    private fun StringBuilder.field(name: String, value: String?) {
        append(ApkAuditRecord.quote(name))
        append(':')
        if (value == null) append("null") else append(ApkAuditRecord.quote(value))
    }

    private fun StringBuilder.field(name: String, value: Long) {
        append(ApkAuditRecord.quote(name))
        append(':')
        append(value)
    }
}
