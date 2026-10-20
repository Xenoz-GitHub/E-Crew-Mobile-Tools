package com.ecrew.toolkit.intercept

import java.security.MessageDigest

data class LoggedHeader(
    val name: String,
    val value: String,
    val sensitive: Boolean
)

data class ProxyLogEntry(
    val id: Long,
    val timestamp: Long,
    val method: String,
    val host: String,
    val path: String,
    val status: Int,
    val bytesUp: Long,
    val bytesDown: Long,
    val headers: List<LoggedHeader>,
    val note: String?
) {
    val hasSensitiveHeaders: Boolean get() = headers.any { it.sensitive }
}

/** Bounded, memory-only proxy log. Values of sensitive headers never enter the buffer. */
class ProxyLog(private val capacity: Int = 2_000) {
    private val entries = ArrayDeque<ProxyLogEntry>()
    private var nextId = 1L

    @Synchronized
    fun record(
        method: String,
        host: String,
        path: String,
        status: Int,
        bytesUp: Long,
        bytesDown: Long,
        headers: List<Pair<String, String>>,
        note: String? = null
    ): ProxyLogEntry {
        val logged = headers.map { (name, value) ->
            val sensitive = name.lowercase() in SENSITIVE_NAMES
            LoggedHeader(
                name = name,
                value = if (sensitive) redact(value) else value.take(MAX_VALUE_LENGTH),
                sensitive = sensitive
            )
        }
        val entry = ProxyLogEntry(
            id = nextId++,
            timestamp = System.currentTimeMillis(),
            method = method.take(16),
            host = host.take(255),
            path = path.take(2_048),
            status = status,
            bytesUp = bytesUp,
            bytesDown = bytesDown,
            headers = logged,
            note = note
        )
        entries.addLast(entry)
        while (entries.size > capacity) entries.removeFirst()
        return entry
    }

    @Synchronized
    fun snapshot(): List<ProxyLogEntry> = entries.toList()

    @Synchronized
    fun clear() {
        entries.clear()
    }

    @Synchronized
    fun size(): Int = entries.size

    private fun redact(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        return "[REDACTED len=${value.length} sha256=${digest.take(4)}]"
    }

    companion object {
        val SENSITIVE_NAMES = setOf(
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "x-auth-token",
            "token"
        )
        private const val MAX_VALUE_LENGTH = 512
    }
}
