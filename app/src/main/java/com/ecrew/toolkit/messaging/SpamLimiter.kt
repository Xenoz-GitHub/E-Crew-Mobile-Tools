package com.ecrew.toolkit.messaging

import java.util.ArrayDeque

/**
 * Per-peer inbound message rate limiter (design: unverified 5/min + 50/hour, verified
 * 60/min). Sliding windows over event timestamps; pure JVM logic with an injectable clock.
 * Shared process-wide by all sessions so independent sessions cannot reset a peer's budget.
 */
class SpamLimiter(private val clock: () -> Long = System::currentTimeMillis) {

    private val windows = HashMap<String, ArrayDeque<Long>>()

    /** Returns true when the message is allowed; a rejected message is silently dropped. */
    @Synchronized
    fun allow(peerId: String, verified: Boolean): Boolean {
        val now = clock()
        if (windows.size > MAX_TRACKED_PEERS) windows.clear()
        val events = windows.getOrPut(peerId) { ArrayDeque() }
        while (events.isNotEmpty() && now - events.first() >= HOUR_MS) events.removeFirst()
        val minuteCount = events.count { now - it < MINUTE_MS }
        val hourCount = events.size
        val ok = if (verified) {
            minuteCount < MessagingProtocol.RATE_VERIFIED_PER_MIN
        } else {
            minuteCount < MessagingProtocol.RATE_UNVERIFIED_PER_MIN &&
                hourCount < MessagingProtocol.RATE_UNVERIFIED_PER_HOUR
        }
        if (ok) events.addLast(now)
        return ok
    }

    /** Test hook: clears all windows. */
    @Synchronized
    fun reset() {
        windows.clear()
    }

    private companion object {
        const val MINUTE_MS = 60_000L
        const val HOUR_MS = 60L * 60_000L
        const val MAX_TRACKED_PEERS = 2000
    }
}
