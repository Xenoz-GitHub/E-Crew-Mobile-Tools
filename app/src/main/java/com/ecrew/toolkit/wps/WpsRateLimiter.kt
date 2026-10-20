package com.ecrew.toolkit.wps

/**
 * Attempt pacing for the WPS audit (non-negotiable safeguards, design note):
 *  - a minimum delay of [minDelayMs] (35 s in production) between attempt starts,
 *  - the run must stop after [MAX_FAILURES] consecutive failures,
 *  - restarting within [RESTART_WINDOW_MS] of a lockout stop doubles the gap
 *    (35 s -> 70 s -> 140 s ...), capped at [BACKOFF_CAP_MS] (5 minutes).
 *
 * The clock and the production delay are injectable so the unit tests run in fake time.
 */
class WpsRateLimiter(
    private val minDelayMs: Long = MIN_DELAY_MS,
    private val clock: () -> Long = System::currentTimeMillis
) {
    companion object {
        const val MIN_DELAY_MS = 35_000L
        const val MAX_FAILURES = 5
        const val BACKOFF_CAP_MS = 300_000L
        const val RESTART_WINDOW_MS = 600_000L

        /** Consecutive failures after which the audit flags lockout_detected. */
        const val LOCKOUT_HINT_FAILURES = 3

        private const val MAX_BACKOFF_LEVEL = 8
    }

    var consecutiveFailures = 0
        private set

    private var backoffLevel = 0
    private var lastAttemptAt: Long? = null
    private var lastLockoutStopAt: Long? = null

    /** Current gap between attempt starts. */
    val delayMs: Long get() = minOf(minDelayMs shl backoffLevel, BACKOFF_CAP_MS)

    /**
     * Prepares a new run. The failure streak always restarts at zero; the delay doubles
     * only when the previous run stopped on lockout within [RESTART_WINDOW_MS].
     */
    fun startRun(now: Long = clock()) {
        consecutiveFailures = 0
        val stoppedAt = lastLockoutStopAt
        backoffLevel = if (stoppedAt != null && now - stoppedAt <= RESTART_WINDOW_MS) {
            minOf(backoffLevel + 1, MAX_BACKOFF_LEVEL)
        } else {
            0
        }
    }

    /** Records the start of an attempt; the gap is measured from here. */
    fun recordAttempt(now: Long = clock()) {
        lastAttemptAt = now
    }

    /** Milliseconds until the next attempt may start (0 = allowed now). */
    fun delayRemainingMs(now: Long = clock()): Long {
        val last = lastAttemptAt ?: return 0L
        return (last + delayMs - now).coerceAtLeast(0L)
    }

    /** Records a failed attempt; returns true when the run must stop ([MAX_FAILURES]). */
    fun recordFailure(): Boolean {
        consecutiveFailures += 1
        return consecutiveFailures >= MAX_FAILURES
    }

    /** A successful attempt clears the streak and any accumulated backoff. */
    fun recordSuccess() {
        consecutiveFailures = 0
        backoffLevel = 0
        lastLockoutStopAt = null
    }

    /** The run ended on lockout; remember when so a quick restart doubles the delay. */
    fun stopRunLocked(now: Long = clock()) {
        lastLockoutStopAt = now
    }
}
