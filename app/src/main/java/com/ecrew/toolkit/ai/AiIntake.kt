package com.ecrew.toolkit.ai

import android.content.Context
import android.content.Intent
import com.ecrew.toolkit.MainActivity
import com.ecrew.toolkit.messaging.MessagingService

/** One text blob handed to Xairex by a result screen ("Ask Xairex"). */
data class AiContext(val title: String, val body: String)

/**
 * Cross-screen handoff for the Xairex assistant (same pattern as MessagingBus): a result
 * screen stores a context blob and asks MainActivity to open Chat -> Xairex. The context
 * is consumed by MessagingScreen when the assistant thread opens.
 */
object AiIntake {
    const val EXTRA_OPEN_XAIREX = "com.ecrew.toolkit.ai.OPEN_XAIREX"
    const val MAX_CONTEXT_CHARS = 1500
    private const val MAX_TITLE_CHARS = 120
    private const val TRUNCATION_MARK = "\n...(truncated)"

    /** Set when an open request is pending; consumed by MessagingScreen. */
    @Volatile
    var openRequested = false

    @Volatile
    private var pending: AiContext? = null

    /** Called from result screens; opens Chat -> Xairex with the text attached. */
    fun ask(context: Context, title: String, body: String) {
        pending = AiContext(title.trim().take(MAX_TITLE_CHARS), clip(body))
        openRequested = true
        val intent = Intent(context, MainActivity::class.java)
            .putExtra(MessagingService.EXTRA_OPEN_CHAT, true)
            .putExtra(EXTRA_OPEN_XAIREX, true)
            .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        context.startActivity(intent)
    }

    /** Returns and clears the pending context (if any). */
    fun consumePending(): AiContext? = pending.also { pending = null }

    /** Normalizes whitespace runs and bounds the size (unit-tested). */
    internal fun clip(body: String): String {
        val normalized = body.trim().replace(Regex("\n{3,}"), "\n\n")
        if (normalized.length <= MAX_CONTEXT_CHARS) return normalized
        return normalized.take(MAX_CONTEXT_CHARS - TRUNCATION_MARK.length) + TRUNCATION_MARK
    }
}
