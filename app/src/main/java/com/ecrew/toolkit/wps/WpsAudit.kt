package com.ecrew.toolkit.wps

/** One audit row for the wps_audit table (one row per startWps attempt). */
data class WpsAuditEntry(
    val ssid: String,
    val bssid: String,
    val pinTested: String,
    val algorithm: String,
    val result: String,
    val lockoutDetected: Boolean,
    val consentText: String,
    val note: String?
) {
    companion object {
        const val RESULT_SUCCESS = "success"
        const val RESULT_FAILED = "failed"
        const val RESULT_TIMEOUT = "timeout"
    }
}

/**
 * Storage seam for the run controller: production writes go to [WpsAuditDb]; unit tests
 * record in memory.
 */
interface WpsAuditSink {
    fun record(entry: WpsAuditEntry)
}
