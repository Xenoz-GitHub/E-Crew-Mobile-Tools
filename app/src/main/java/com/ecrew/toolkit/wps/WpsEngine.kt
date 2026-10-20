package com.ecrew.toolkit.wps

import android.net.wifi.WifiManager
import android.net.wifi.WpsInfo

/** Outcome of one startWps attempt, as far as the audit needs to know it. */
sealed interface WpsOutcome {
    /** The registrar accepted the PIN; the network is saved on the device. */
    object Success : WpsOutcome

    /** The registrar rejected the PIN ([reason] is the callback error code). */
    data class Failure(val reason: Int) : WpsOutcome

    /** startWps refused to run (permissions/service), so no PIN verdict exists. */
    data class Rejected(val detail: String) : WpsOutcome
}

/**
 * Seam over WifiManager.startWps so the attempt loop, pacing and audit are testable with a
 * fake engine. Implementations must not throw: refusals are reported as
 * [WpsOutcome.Rejected].
 */
interface WpsEngine {
    fun start(bssid: String, pin: String, onResult: (WpsOutcome) -> Unit)
    fun cancel()
}

/**
 * Real engine for API 26 devices; any failure from the platform call is mapped into a
 * [WpsOutcome] so the audit row is always written and the app cannot crash on it.
 */
// WifiManager.startWps/cancelWps are deprecated in API 28; this module targets API 26 where
// the public API is still callable (verified against the installed SDK, see design note).
// OVERRIDE_DEPRECATION: the WpsCallback members themselves are deprecated in API 28.
@Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
class SystemWpsEngine(private val wifiManager: WifiManager) : WpsEngine {

    private var current: WifiManager.WpsCallback? = null

    override fun start(bssid: String, pin: String, onResult: (WpsOutcome) -> Unit) {
        val info = WpsInfo().apply {
            BSSID = bssid
            this.pin = pin
            setup = WpsInfo.KEYPAD
        }
        val deliver: (WpsOutcome) -> Unit = { outcome ->
            current = null
            onResult(outcome)
        }
        val callback = object : WifiManager.WpsCallback() {
            override fun onStarted(pin: String) = Unit
            override fun onSucceeded() = deliver(WpsOutcome.Success)
            override fun onFailed(reason: Int) = deliver(WpsOutcome.Failure(reason))
        }
        current = callback
        try {
            wifiManager.startWps(info, callback)
        } catch (e: RuntimeException) {
            // SecurityException, IllegalArgumentException or any other unchecked failure
            // from the framework must feed the audit, not crash the app.
            current = null
            onResult(WpsOutcome.Rejected(e.javaClass.simpleName))
        }
    }

    override fun cancel() {
        val callback = current ?: return
        current = null
        try {
            wifiManager.cancelWps(callback)
        } catch (_: SecurityException) {
            // The WPS session is already gone; there is nothing left to cancel.
        }
    }
}
