package com.ecrew.toolkit.capture

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** One line of live capture metadata (DNS / HTTP / TLS SNI / flows). */
data class CaptureEntry(
    val atMillis: Long,
    val kind: String,   // DNS | HTTP | TLS | TCP | PCAP | INFO | ERROR
    val text: String
) {
    fun display(): String {
        val t = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date(atMillis))
        return "$t  ${kind.padEnd(5)}  $text"
    }
}

/**
 * Process-wide capture state shared between PacketCaptureService (writer) and
 * the Compose UI (poller). Same-process singleton - no IPC, no network.
 */
object CaptureBus {
    const val MAX_ENTRIES = 500

    @Volatile
    var running: Boolean = false

    @Volatile
    var pcapPath: String = ""

    @Volatile
    var logPath: String = ""

    @Volatile
    var statsPackets: Int = 0

    @Volatile
    var statsBytes: Long = 0

    @Volatile
    var error: String = ""

    private val lock = Any()
    private val entries = ArrayList<CaptureEntry>(64)

    fun add(kind: String, text: String) {
        synchronized(lock) {
            entries.add(CaptureEntry(System.currentTimeMillis(), kind, text))
            while (entries.size > MAX_ENTRIES) entries.removeAt(0)
        }
        // persist alongside the pcap for evidence continuity
        try {
            if (logPath.isNotEmpty()) {
                java.io.File(logPath).appendText(
                    SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS", Locale.US)
                        .format(Date()) + "  $kind  $text\n"
                )
            }
        } catch (e: Exception) {
            // logging must never kill capture
        }
    }

    fun snapshot(): List<CaptureEntry> = synchronized(lock) { ArrayList(entries) }

    fun reset() {
        synchronized(lock) { entries.clear() }
        running = false
        pcapPath = ""
        logPath = ""
        statsPackets = 0
        statsBytes = 0
        error = ""
    }
}

