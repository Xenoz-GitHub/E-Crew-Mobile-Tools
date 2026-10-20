package com.ecrew.agent

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.accessibilityservice.GestureDescription
import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.graphics.Path
import android.os.Bundle
import android.os.PowerManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityManager
import android.view.accessibility.AccessibilityNodeInfo
import com.ecrew.protocol.GlobalActions
import com.ecrew.protocol.InputNormalization

/**
 * Accessibility service doing exactly three things, and only while a consented session is
 * active: gestures (tap/swipe), text input into the focused node, and global navigation
 * actions. It never processes accessibility events (onAccessibilityEvent is a no-op) and
 * refuses to inject into its own package (self-control guard).
 *
 * Enablement is user-driven through system Settings; onServiceConnected re-checks the
 * recorded consent and disables itself when absent (defense in depth).
 */
class EcrewAccessibilityService : AccessibilityService() {

    override fun onServiceConnected() {
        super.onServiceConnected()
        if (!Prefs.consentGiven(this)) {
            disableSelf()
            return
        }
        instanceRef = this
        AgentRuntime.notifyChanged()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // No event processing by design: input injection is command-driven only.
    }

    override fun onInterrupt() = Unit

    override fun onUnbind(intent: Intent?): Boolean {
        if (instanceRef === this) instanceRef = null
        AgentRuntime.notifyChanged()
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        if (instanceRef === this) instanceRef = null
        AgentRuntime.notifyChanged()
        super.onDestroy()
    }

    // ------------------------------------------------------------- injection API

    fun tap(normalizedX: Double, normalizedY: Double, screenWidth: Int, screenHeight: Int): Boolean {
        if (!ownPackageSafe()) return false
        if (isScreenOff()) wakeForGesture()
        val path = Path().apply {
            moveTo(
                InputNormalization.denormalize(normalizedX, screenWidth).toFloat(),
                InputNormalization.denormalize(normalizedY, screenHeight).toFloat()
            )
        }
        return dispatch(path, TAP_DURATION_MS)
    }

    fun swipe(
        x1: Double, y1: Double, x2: Double, y2: Double,
        durationMs: Long, screenWidth: Int, screenHeight: Int
    ): Boolean {
        if (!ownPackageSafe()) return false
        if (isScreenOff()) wakeForGesture()
        val path = Path().apply {
            moveTo(
                InputNormalization.denormalize(x1, screenWidth).toFloat(),
                InputNormalization.denormalize(y1, screenHeight).toFloat()
            )
            lineTo(
                InputNormalization.denormalize(x2, screenWidth).toFloat(),
                InputNormalization.denormalize(y2, screenHeight).toFloat()
            )
        }
        return dispatch(path, durationMs.coerceIn(1L, 10_000L))
    }

    fun globalAction(action: String): Boolean {
        val actionId = when (action) {
            GlobalActions.BACK -> GLOBAL_ACTION_BACK
            GlobalActions.HOME -> GLOBAL_ACTION_HOME
            GlobalActions.RECENTS -> GLOBAL_ACTION_RECENTS
            GlobalActions.NOTIFICATIONS -> GLOBAL_ACTION_NOTIFICATIONS
            else -> return false
        }
        return performGlobalAction(actionId)
    }

    fun setFocusedText(text: String): Boolean {
        val root = rootInActiveWindow ?: return false
        if (root.packageName == packageName) return false
        val focused = root.findFocus(AccessibilityNodeInfo.FOCUS_INPUT) ?: return false
        val arguments = Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
        }
        return focused.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, arguments)
    }

    // ---------------------------------------------------------------- internals

    /** Never inject into our own package; content may not be readable for all windows. */
    private fun ownPackageSafe(): Boolean {
        val root = rootInActiveWindow ?: return true
        return root.packageName != packageName
    }

    private fun isScreenOff(): Boolean {
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        return !power.isInteractive
    }

    /**
     * Spec safeguard: if the screen is off, taps/swipes would do nothing. Wake for the
     * gesture only - a single ACQUIRE_CAUSES_WAKEUP wakelock with a 3 s timeout, never held
     * persistently.
     */
    @Suppress("DEPRECATION") // ACQUIRE_CAUSES_WAKEUP is the only public mechanism for this
    // ("PowerManager.wakeUp" needs the DEVICE_POWER permission); still functional on API 34.
    @SuppressLint("Wakelock") // intentional spec behaviour: wake with the gesture, never held, 3 s timeout
    private fun wakeForGesture() {
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        val wakeLock = power.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK or PowerManager.ACQUIRE_CAUSES_WAKEUP,
            "ecrew:gesture"
        )
        wakeLock.acquire(WAKE_TIMEOUT_MS)
    }

    private fun dispatch(path: Path, durationMs: Long): Boolean {
        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0L, durationMs))
            .build()
        return dispatchGesture(gesture, null, null)
    }

    companion object {
        @Volatile
        private var instanceRef: EcrewAccessibilityService? = null

        private const val TAP_DURATION_MS = 40L
        private const val WAKE_TIMEOUT_MS = 3000L

        fun instance(): EcrewAccessibilityService? = instanceRef

        /** True when this service is currently enabled in system Settings. */
        fun isEnabled(context: Context): Boolean {
            val manager = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
            val expectedId = "${context.packageName}/${EcrewAccessibilityService::class.java.name}"
            return manager
                .getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .any { it.id == expectedId }
        }
    }
}
