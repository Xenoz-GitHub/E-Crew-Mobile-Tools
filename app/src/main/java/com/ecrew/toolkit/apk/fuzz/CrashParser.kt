package com.ecrew.toolkit.apk.fuzz

/**
 * Parses Android crash blocks without keeping full logs. Only the exception class, message and
 * first stack frames are retained. A block is accepted only when its `Process:` line names the
 * target package, so another app's crash is never attributed to the fuzz target.
 */
object CrashParser {
    private const val MAX_MESSAGE = 300
    private const val MAX_STACK_LINES = 5

    fun parseLogcat(text: String, packageName: String): List<CrashEvidence> =
        parseBlocks(text, packageName, "logcat")

    fun parseDropbox(text: String, packageName: String): List<CrashEvidence> =
        parseBlocks(text, packageName, "dropbox")

    private fun parseBlocks(text: String, packageName: String, source: String): List<CrashEvidence> {
        val lines = text.lineSequence().toList()
        val result = ArrayList<CrashEvidence>()
        var index = 0
        while (index < lines.size) {
            if (!lines[index].contains("FATAL EXCEPTION")) {
                index++
                continue
            }
            val end = (index + 80).coerceAtMost(lines.size)
            val block = lines.subList(index, end)
            val processLine = block.firstOrNull { payload(it).startsWith("Process:") }
            if (processLine == null || !processBelongsTo(processLine, packageName)) {
                index++
                continue
            }
            val processIndex = block.indexOf(processLine)
            val exceptionLine = block.drop(processIndex + 1).firstOrNull { looksLikeException(it) }
            if (exceptionLine != null) {
                val classAndMessage = payload(exceptionLine)
                val separator = classAndMessage.indexOf(':')
                val exceptionClass = if (separator > 0) {
                    classAndMessage.substring(0, separator)
                } else {
                    classAndMessage.substringBefore(' ')
                }
                val message = if (separator > 0) {
                    classAndMessage.substring(separator + 1).trim().take(MAX_MESSAGE)
                } else {
                    ""
                }
                val stackHead = block.drop(processIndex + 1)
                    .map { payload(it) }
                    .filter { it.startsWith("at ") }
                    .take(MAX_STACK_LINES)
                    .joinToString(" | ") { it.take(180) }
                result.add(CrashEvidence(exceptionClass, message, stackHead, source))
            }
            index++
        }
        return result.distinctBy { it.exceptionClass + "|" + it.stackHead }
            .take(MAX_CRASHES)
    }

    private fun processBelongsTo(line: String, packageName: String): Boolean {
        val process = payload(line).substringAfter("Process:", "")
            .substringBefore(',').trim()
        return process == packageName || process.startsWith("$packageName:")
    }

    private fun looksLikeException(line: String): Boolean {
        val value = payload(line)
        if (value.startsWith("Caused by:")) return false
        if (!value.contains('.')) return false
        return value.contains("Exception") || value.contains("Error") ||
            value.contains("Throwable")
    }

    /** Removes the logcat prefix; dropbox text is already in payload form. */
    private fun payload(line: String): String {
        val trimmed = line.trim()
        return if (trimmed.contains("AndroidRuntime:")) {
            trimmed.substringAfter("AndroidRuntime:").trim()
        } else {
            trimmed
        }
    }

    private const val MAX_CRASHES = 20
}
