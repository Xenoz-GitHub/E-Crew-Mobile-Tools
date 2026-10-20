package com.ecrew.toolkit.wps

import android.net.wifi.WifiManager
import android.net.wifi.WpsInfo
import android.os.Build
import android.util.Log

/** Outcome of one startWps attempt, as far as the audit needs to know it. */
sealed interface WpsOutcome {
    /** The registrar accepted the PIN; the network is saved on the device. */
    object Success : WpsOutcome

    /** The registrar rejected the PIN ([reason] is the callback error code). */
    data class Failure(val reason: Int) : WpsOutcome

    /** startWps refused to run (permissions/service), so no PIN verdict exists. */
    data class Rejected(val detail: String) : WpsOutcome

    /** The Android client-mode WPS API is not present on this OS version. */
    data class Unsupported(val detail: String) : WpsOutcome
}

/** WPS client mode was removed from Android 9 (API 28). */
object WpsSupport {
    val available: Boolean
        get() = Build.VERSION.SDK_INT < Build.VERSION_CODES.P

    const val REMOVED_MESSAGE =
        "WPS client mode is not available on Android 9 or later. Use Wi-Fi settings or " +
            "Wi-Fi Easy Connect instead."
}

/**
 * Seam over WifiManager.startWps so the attempt loop, pacing and audit are testable with a
 * fake engine. Implementations must not throw: refusals are reported as
 * [WpsOutcome.Rejected].
 */
interface WpsEngine {
    fun start(bssid: String, method: WpsMethod, onResult: (WpsOutcome) -> Unit)
    fun cancel()
}

/**
 * Real engine for Android 8.x devices; any failure from the platform call is mapped into a
 * [WpsOutcome] so the audit row is always written and the app cannot crash on it.
 */
// WifiManager.startWps/cancelWps are deprecated in API 28; this module targets API 26/27
// where the public client-mode API is still functional.
// OVERRIDE_DEPRECATION: the WpsCallback members themselves are deprecated in API 28.
@Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
class SystemWpsEngine(private val wifiManager: WifiManager) : WpsEngine {

    private var current: WifiManager.WpsCallback? = null

    override fun start(bssid: String, method: WpsMethod, onResult: (WpsOutcome) -> Unit) {
        if (!WpsSupport.available) {
            onResult(WpsOutcome.Unsupported(WpsSupport.REMOVED_MESSAGE))
            return
        }

        val info = try {
            WpsInfo().apply {
                BSSID = bssid
                when (method) {
                    is WpsMethod.Pin -> {
                        pin = method.pin
                        setup = WpsInfo.KEYPAD
                    }

                    WpsMethod.PushButton -> {
                        pin = ""
                        setup = WpsInfo.PBC
                    }
                }
            }
        } catch (t: Throwable) {
            if (t is VirtualMachineError || t is ThreadDeath) throw t
            Log.e(TAG, "Unable to build WpsInfo", t)
            onResult(WpsOutcome.Rejected(t.javaClass.simpleName))
            return
        }

        var delivered = false
        val deliver: (WpsOutcome) -> Unit = { outcome ->
            if (!delivered) {
                delivered = true
                current = null
                try {
                    onResult(outcome)
                } catch (t: Throwable) {
                    logNonFatal(t, "WPS callback consumer failed")
                }
            }
        }
        val callback = object : WifiManager.WpsCallback() {
            // The framework passes a platform String here. Treat it as nullable so a
            // null from an OEM callback cannot raise a Kotlin NPE on a Binder thread.
            override fun onStarted(pin: String?) = Unit
            override fun onSucceeded() = deliver(WpsOutcome.Success)
            override fun onFailed(reason: Int) = deliver(WpsOutcome.Failure(reason))
        }
        current = callback
        try {
            wifiManager.startWps(info, callback)
        } catch (t: Throwable) {
            // Some OEM builds throw LinkageError when the removed framework symbol is
            // absent. Runtime exceptions cover permission and argument failures; both must
            // feed the audit instead of terminating the process.
            current = null
            if (t is VirtualMachineError || t is ThreadDeath) throw t
            Log.e(TAG, "startWps failed", t)
            try {
                onResult(WpsOutcome.Rejected(t.javaClass.simpleName))
            } catch (callbackError: Throwable) {
                logNonFatal(callbackError, "WPS error consumer failed")
            }
        }
    }

    override fun cancel() {
        val callback = current ?: return
        current = null
        try {
            wifiManager.cancelWps(callback)
        } catch (t: Throwable) {
            if (t is VirtualMachineError || t is ThreadDeath) throw t
            Log.w(TAG, "cancelWps failed", t)
        }
    }

    private fun logNonFatal(t: Throwable, message: String) {
        if (t is VirtualMachineError || t is ThreadDeath) throw t
        Log.e(TAG, message, t)
    }

    private companion object {
        const val TAG = "E-Crew/WPS"
    }
}
