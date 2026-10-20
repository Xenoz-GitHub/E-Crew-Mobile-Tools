package com.ecrew.toolkit.messaging

/**
 * Outbox policy: which undelivered rows may be (re)sent, at what cadence, and when they
 * expire. Pure decisions over [MessageRow] snapshots - no storage here, so the pump and
 * the session share one rule set (DeliveryQueueTest).
 */
object Outbox {

    /**
     * Exponential retry backoff: 5 s, 10 s, 20 s ... capped at 5 min.
     * attempts is the number of sends already performed ([MessageRow.attempts]).
     */
    fun backoffMs(attempts: Int): Long {
        if (attempts <= 0) return 0L
        var delay = MessagingProtocol.RETRY_BASE_MS
        var remaining = attempts - 1
        while (remaining > 0) {
            if (delay >= MessagingProtocol.RETRY_MAX_MS) return MessagingProtocol.RETRY_MAX_MS
            delay *= 2
            remaining -= 1
        }
        return minOf(delay, MessagingProtocol.RETRY_MAX_MS)
    }

    /** A pending row is due when it was never attempted or the backoff window has passed. */
    fun isDue(row: MessageRow, now: Long): Boolean {
        if (row.state != MsgState.QUEUED && row.state != MsgState.SENT) return false
        if (row.attempts <= 0) return true
        return now - row.lastAttempt >= backoffMs(row.attempts)
    }

    /** The due subset of [rows], in queue order. */
    fun due(rows: List<MessageRow>, now: Long): List<MessageRow> =
        rows.filter { isDue(it, now) }

    fun isExpired(row: MessageRow, now: Long, expiryMs: Long = MessagingProtocol.OUTBOX_EXPIRY_MS): Boolean =
        row.ts < now - expiryMs
}
