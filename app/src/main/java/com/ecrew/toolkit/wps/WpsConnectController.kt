package com.ecrew.toolkit.wps

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.cancellation.CancellationException
import kotlin.coroutines.resume

/**
 * One-shot WPS connection for an operator's own network. Supports the router's printed
 * PIN (keypad flow) and the physical WPS button (push-button flow). It never generates or
 * guesses PINs; the audit path remains the only generated-candidate flow.
 */
class WpsConnectController(
    private val engine: WpsEngine,
    private val audit: WpsAuditSink,
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS
) {
    companion object {
        /** Push-button mode needs time to find and associate with the registrar. */
        const val DEFAULT_TIMEOUT_MS = 120_000L
        private const val TAG = "E-Crew/WPS"
    }

    suspend fun connect(
        ssid: String,
        bssid: String,
        method: WpsMethod,
        onPhase: (WpsPhase) -> Unit
    ) {
        if (!WpsSupport.available) {
            onPhase(WpsPhase.Stopped(WpsSupport.REMOVED_MESSAGE, WpsPurpose.CONNECT))
            return
        }
        if (method is WpsMethod.Pin && !WpsPinGenerator.isValidPin(method.pin)) {
            onPhase(WpsPhase.Stopped(WpsText.INVALID_PIN, WpsPurpose.CONNECT))
            return
        }

        val pin = (method as? WpsMethod.Pin)?.pin.orEmpty()
        val algorithm = when (method) {
            is WpsMethod.Pin -> "Router PIN"
            WpsMethod.PushButton -> "Push button"
        }
        val displayPin = pin.ifEmpty { "PBC" }
        onPhase(
            WpsPhase.Testing(
                pin = displayPin,
                algorithm = algorithm,
                attempt = 1,
                total = 1,
                waiting = false,
                waitRemainingMs = 0L,
                purpose = WpsPurpose.CONNECT
            )
        )

        val outcome: WpsOutcome? = try {
            withTimeoutOrNull<WpsOutcome>(timeoutMs) {
                suspendCancellableCoroutine { cont ->
                    engine.start(bssid, method) { result ->
                        if (cont.isActive) cont.resume(result)
                    }
                    cont.invokeOnCancellation { engine.cancel() }
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "WPS connection failed", e)
            onPhase(
                WpsPhase.Stopped(
                    "WPS connection failed (${e.javaClass.simpleName}).",
                    WpsPurpose.CONNECT
                )
            )
            return
        }

        when (outcome) {
            null -> {
                writeAudit(ssid, bssid, displayPin, algorithm, WpsAuditEntry.RESULT_TIMEOUT, "no callback")
                onPhase(WpsPhase.Stopped(WpsText.NO_RESPONSE, WpsPurpose.CONNECT))
            }

            is WpsOutcome.Success -> {
                writeAudit(ssid, bssid, displayPin, algorithm, WpsAuditEntry.RESULT_SUCCESS, null)
                onPhase(WpsPhase.Success)
            }

            is WpsOutcome.Failure -> {
                writeAudit(
                    ssid, bssid, displayPin, algorithm, WpsAuditEntry.RESULT_FAILED,
                    "router reason ${outcome.reason}"
                )
                onPhase(
                    WpsPhase.Stopped(
                        "The router rejected the WPS attempt (code ${outcome.reason}). " +
                            "Check the PIN and the router's WPS window, then try again.",
                        WpsPurpose.CONNECT
                    )
                )
            }

            is WpsOutcome.Rejected -> {
                writeAudit(
                    ssid, bssid, displayPin, algorithm, WpsAuditEntry.RESULT_FAILED,
                    "startWps rejected (${outcome.detail})"
                )
                onPhase(
                    WpsPhase.Stopped(
                        "This device refused to start WPS (${outcome.detail}).",
                        WpsPurpose.CONNECT
                    )
                )
            }

            is WpsOutcome.Unsupported -> {
                onPhase(WpsPhase.Stopped(outcome.detail, WpsPurpose.CONNECT))
            }
        }
    }

    private suspend fun writeAudit(
        ssid: String,
        bssid: String,
        pin: String,
        algorithm: String,
        result: String,
        note: String?
    ) {
        withContext(NonCancellable + Dispatchers.IO) {
            try {
                audit.record(
                    WpsAuditEntry(
                        ssid = ssid,
                        bssid = bssid,
                        pinTested = pin,
                        algorithm = algorithm,
                        result = result,
                        lockoutDetected = false,
                        consentText = WpsText.CONSENT,
                        note = note
                    )
                )
            } catch (e: Exception) {
                Log.e(TAG, "Unable to write WPS connection audit row", e)
            }
        }
    }
}
