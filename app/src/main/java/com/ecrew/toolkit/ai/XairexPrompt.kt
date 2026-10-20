package com.ecrew.toolkit.ai

import com.ecrew.toolkit.messaging.AiMessageRow

/**
 * Builds the chat message list handed to the engine. Pure Kotlin so it is unit-testable
 * on the JVM; the native layer applies the model's own chat template and injects the
 * system prompt.
 */
object XairexPrompt {
    const val MAX_HISTORY_MESSAGES = 10
    const val MAX_HISTORY_CHARS = 3000
    const val MAX_INPUT_CHARS = 2000

    const val SYSTEM_PROMPT =
        "You are Xairex, the offline assistant inside a cybersecurity and digital " +
            "forensics toolkit. You run entirely on this device with no network access. " +
            "Be concise and practical. You only see the text the user sends you."

    data class Msg(val role: String, val content: String)

    /**
     * Builds the prompt for a generation. [history] ends with the user message that is
     * about to be answered; older messages are trimmed to a tail window. A selected
     * result context is prepended to the last turn only - it is deliberately not part
     * of the stored conversation.
     */
    fun build(history: List<AiMessageRow>, context: AiContext?): List<Msg> {
        if (history.isEmpty()) return emptyList()
        val tail = ArrayList<AiMessageRow>()
        var chars = 0
        for (row in history.asReversed()) {
            if (tail.size >= MAX_HISTORY_MESSAGES) break
            if (tail.isNotEmpty() && chars + row.body.length > MAX_HISTORY_CHARS) break
            tail.add(row)
            chars += row.body.length
        }
        tail.reverse()
        return tail.mapIndexed { index, row ->
            val isLast = index == tail.size - 1
            if (isLast && context != null) {
                Msg(
                    row.role,
                    "Text from the app (" + context.title + "):\n" + context.body +
                        "\n\n" + row.body
                )
            } else {
                Msg(row.role, row.body)
            }
        }
    }
}
