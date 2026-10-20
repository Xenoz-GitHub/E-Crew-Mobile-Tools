package com.ecrew.toolkit.wps

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.cancellation.CancellationException
import kotlin.coroutines.resume

/** UI-agnostic state emitted by [WpsRunController.run]. */
sealed interface WpsPhase {
    /** An attempt is in flight ([waiting] = false) or the run is waiting out the gap. */
    data class Testing(
        val pin: String,
        val algorithm: String,
        val attempt: Int,
        val total: Int,
        val waiting: Boolean,
        val waitRemainingMs: Long
    ) : WpsPhase

    /** The registrar accepted the PIN; the network is saved on the device. */
    object Success : WpsPhase

    /** The run ended without success; [message] is operator-facing. */
    data class Stopped(val message: String) : WpsPhase
}

/** Operator-facing strings, single source for UI and audit. */
object WpsText {
    const val CONSENT = "I own this network or have documented authorization to test it."
    const val BANNER = "This tool tests for known WPS PIN weaknesses. It cannot recover the Wi-Fi " +
        "password on a non-rooted device. Use only on networks you own or are authorized to test."
    const val LOCKED = "Router may be locked. Wait 2 minutes before retrying, or reboot the router."
    const val EXHAUSTED = "No candidate PIN worked for this network."
    const val NO_CANDIDATES = "No candidate PINs for this address."
    const val STOPPED = "Test stopped."
    const val SUCCESS = "Connected via WPS. The network is now saved on this device. To find the " +
        "password, check the router's admin panel or label."
    const val CAP_NOTE = "candidate cap reached"
}

/**
 * Orchestrates one rate-limited, audited PIN audit run: candidate order comes from
 * [generator], pacing and the 5-failure stop from [limiter], every attempt lands in the
 * audit, and the platform handshake goes through [engine].
 *
 * Cancellation contract: cancelling [run] during a countdown stops the run immediately;
 * cancelling while an attempt is in flight lets that attempt finish (NonCancellable) and
 * audits it before the run ends - "leaving the screen cancels after the current attempt".
 */
class WpsRunController(
    private val engine: WpsEngine,
    private val limiter: WpsRateLimiter,
    private val audit: WpsAuditSink,
    private val attemptTimeoutMs: Long = ATTEMPT_TIMEOUT_MS,
    private val sleeper: suspend (Long) -> Unit = { delay(it) },
    private val generator: (String) -> WpsCandidates = WpsPinGenerator::candidates
) {
    companion object {
        /** A startWps attempt that produces no callback within this window is a timeout. */
        const val ATTEMPT_TIMEOUT_MS = 30_000L

        /** UI countdown tick while waiting out the gap. */
        const val UI_TICK_MS = 500L
    }

    suspend fun run(ssid: String, bssid: String, onPhase: (WpsPhase) -> Unit) {
        try {
            orchestrate(ssid, bssid, onPhase)
        } catch (e: CancellationException) {
            // The owner left the screen or pressed Stop while the run was counting down.
            // When they left mid-attempt, the attempt above already ran NonCancellable and
            // its audit row was written before this point.
            onPhase(WpsPhase.Stopped(WpsText.STOPPED))
            throw e
        }
    }

    private suspend fun orchestrate(ssid: String, bssid: String, onPhase: (WpsPhase) -> Unit) {
        val generated = generator(bssid)
        val candidates = generated.list
        if (candidates.isEmpty()) {
            onPhase(WpsPhase.Stopped(WpsText.NO_CANDIDATES))
            return
        }
        limiter.startRun()
        val total = minOf(WpsRateLimiter.MAX_FAILURES, candidates.size)
        val capNoteIndex = if (generated.capReached) candidates.lastIndex else -1

        for ((index, candidate) in candidates.withIndex()) {
            val label = candidate.algorithms.joinToString("+")
            val attempt = index + 1

            // Wait out the enforced gap. Cancelling here stops the run before any further
            // startWps call is made.
            while (true) {
                val remaining = limiter.delayRemainingMs()
                if (remaining <= 0L) break
                onPhase(WpsPhase.Testing(candidate.pin, label, attempt, total, true, remaining))
                sleeper(minOf(remaining, UI_TICK_MS))
                currentCoroutineContext().ensureActive()
            }

            limiter.recordAttempt()
            onPhase(WpsPhase.Testing(candidate.pin, label, attempt, total, false, 0L))

            // The in-flight attempt always completes (NonCancellable) so its audit row is
            // written even when the owner left the screen; nothing new starts after it.
            val result = withContext(NonCancellable) { awaitAttempt(bssid, candidate.pin) }
            val capNote = if (index == capNoteIndex) WpsText.CAP_NOTE else null

            when (result) {
                is AttemptResult.Done -> when (val outcome = result.outcome) {
                    is WpsOutcome.Success -> {
                        limiter.recordSuccess()
                        writeAudit(
                            ssid, bssid, candidate.pin, label,
                            WpsAuditEntry.RESULT_SUCCESS, false, capNote
                        )
                        onPhase(WpsPhase.Success)
                        return
                    }

                    is WpsOutcome.Rejected -> {
                        writeAudit(
                            ssid, bssid, candidate.pin, label, WpsAuditEntry.RESULT_FAILED, false,
                            "startWps rejected (${outcome.detail})"
                        )
                        onPhase(WpsPhase.Stopped("This device refused to start WPS (${outcome.detail})."))
                        return
                    }

                    is WpsOutcome.Failure -> {
                        val stop = recordFailureAndAudit(
                            ssid, bssid, candidate.pin, label, WpsAuditEntry.RESULT_FAILED,
                            "registrar reason ${outcome.reason}", capNote, onPhase
                        )
                        if (stop) return
                    }
                }

                AttemptResult.Timeout -> {
                    val stop = recordFailureAndAudit(
                        ssid, bssid, candidate.pin, label, WpsAuditEntry.RESULT_TIMEOUT,
                        "no callback within ${attemptTimeoutMs} ms", capNote, onPhase
                    )
                    if (stop) return
                }
            }

            currentCoroutineContext().ensureActive()
        }

        val suffix = if (generated.capReached) " (${WpsText.CAP_NOTE})" else ""
        onPhase(WpsPhase.Stopped(WpsText.EXHAUSTED + suffix))
    }

    /** Records the failure, audits it, and returns true when the run must stop. */
    private suspend fun recordFailureAndAudit(
        ssid: String,
        bssid: String,
        pin: String,
        label: String,
        result: String,
        note: String,
        capNote: String?,
        onPhase: (WpsPhase) -> Unit
    ): Boolean {
        val capReached = limiter.recordFailure()
        val lockout = limiter.consecutiveFailures >= WpsRateLimiter.LOCKOUT_HINT_FAILURES
        val fullNote = if (capNote == null) note else "$note; $capNote"
        writeAudit(ssid, bssid, pin, label, result, lockout, fullNote)
        if (capReached) {
            limiter.stopRunLocked()
            onPhase(WpsPhase.Stopped(WpsText.LOCKED))
            return true
        }
        return false
    }

    private suspend fun writeAudit(
        ssid: String,
        bssid: String,
        pin: String,
        algorithm: String,
        result: String,
        lockoutDetected: Boolean,
        note: String?
    ) {
        // NonCancellable: the row for a completed attempt must land even when the owner
        // already left the screen.
        withContext(NonCancellable + Dispatchers.IO) {
            audit.record(
                WpsAuditEntry(
                    ssid = ssid,
                    bssid = bssid,
                    pinTested = pin,
                    algorithm = algorithm,
                    result = result,
                    lockoutDetected = lockoutDetected,
                    consentText = WpsText.CONSENT,
                    note = note
                )
            )
        }
    }

    private suspend fun awaitAttempt(bssid: String, pin: String): AttemptResult {
        val outcome = withTimeoutOrNull(attemptTimeoutMs) {
            suspendCancellableCoroutine { cont ->
                engine.start(bssid, pin) { result -> if (cont.isActive) cont.resume(result) }
                cont.invokeOnCancellation { engine.cancel() }
            }
        }
        return if (outcome != null) AttemptResult.Done(outcome) else AttemptResult.Timeout
    }

    private sealed interface AttemptResult {
        data class Done(val outcome: WpsOutcome) : AttemptResult
        object Timeout : AttemptResult
    }
}
