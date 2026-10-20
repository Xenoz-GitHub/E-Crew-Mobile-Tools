package com.ecrew.protocol

/**
 * Minimal dependency-free JSON encoder/decoder used for protocol messages.
 *
 * Supported values: null, Boolean, String, Int, Long, Double, Map&lt;String, Any?&gt;, List&lt;Any?&gt;.
 * The root value for [parse] must be a JSON object (the protocol only uses object frames).
 * Numbers without a fraction/exponent are decoded as Long, otherwise as Double.
 *
 * Hand-rolled on purpose: the shared module must stay dependency-free (kotlin-stdlib only)
 * and the message schema is small and fixed.
 */
object Json {

    fun encode(value: Any?): String {
        val sb = StringBuilder(256)
        write(sb, value)
        return sb.toString()
    }

    fun parse(text: String): Map<String, Any?> {
        val parser = Parser(text)
        val value = parser.readValue()
        parser.expectEnd()
        if (value !is Map<*, *>) throw IllegalArgumentException("JSON root must be an object")
        @Suppress("UNCHECKED_CAST")
        return value as Map<String, Any?>
    }

    private fun write(sb: StringBuilder, value: Any?) {
        when (value) {
            null -> sb.append("null")
            is String -> writeString(sb, value)
            is Boolean -> sb.append(value)
            is Int -> sb.append(value)
            is Long -> sb.append(value)
            is Double -> {
                require(!value.isNaN() && !value.isInfinite()) { "unsupported non-finite number" }
                sb.append(value)
            }
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, v) in value) {
                    if (k !is String) throw IllegalArgumentException("object keys must be strings")
                    if (!first) sb.append(',')
                    first = false
                    writeString(sb, k)
                    sb.append(':')
                    write(sb, v)
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                for ((i, v) in value.withIndex()) {
                    if (i > 0) sb.append(',')
                    write(sb, v)
                }
                sb.append(']')
            }
            else -> throw IllegalArgumentException("unsupported JSON value: ${value::class.java.name}")
        }
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> if (c < ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
            }
        }
        sb.append('"')
    }

    private class Parser(private val text: String) {
        private var index = 0

        fun readValue(): Any? {
            skipWhitespace()
            if (index >= text.length) fail("unexpected end of input")
            return when (val c = text[index]) {
                '{' -> readObject()
                '[' -> readArray()
                '"' -> readString()
                't' -> { expectLiteral("true"); true }
                'f' -> { expectLiteral("false"); false }
                'n' -> { expectLiteral("null"); null }
                '-', in '0'..'9' -> readNumber()
                else -> fail("unexpected character '$c'")
            }
        }

        fun expectEnd() {
            skipWhitespace()
            if (index != text.length) fail("trailing content after JSON value")
        }

        private fun readObject(): Map<String, Any?> {
            index++ // consume '{'
            val map = LinkedHashMap<String, Any?>()
            skipWhitespace()
            if (peek() == '}') {
                index++
                return map
            }
            while (true) {
                skipWhitespace()
                if (peek() != '"') fail("expected string key")
                val key = readString()
                skipWhitespace()
                if (peek() != ':') fail("expected ':'")
                index++
                map[key] = readValue()
                skipWhitespace()
                when (peek()) {
                    ',' -> index++
                    '}' -> {
                        index++
                        return map
                    }
                    else -> fail("expected ',' or '}'")
                }
            }
        }

        private fun readArray(): List<Any?> {
            index++ // consume '['
            val list = ArrayList<Any?>()
            skipWhitespace()
            if (peek() == ']') {
                index++
                return list
            }
            while (true) {
                list.add(readValue())
                skipWhitespace()
                when (peek()) {
                    ',' -> index++
                    ']' -> {
                        index++
                        return list
                    }
                    else -> fail("expected ',' or ']'")
                }
            }
        }

        private fun readString(): String {
            index++ // consume opening quote
            val sb = StringBuilder()
            while (index < text.length) {
                val c = text[index++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        if (index >= text.length) fail("unterminated escape")
                        when (val e = text[index++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'u' -> {
                                if (index + 4 > text.length) fail("unterminated unicode escape")
                                val hex = text.substring(index, index + 4)
                                index += 4
                                sb.append(hex.toInt(16).toChar())
                            }
                            else -> fail("invalid escape '\\$e'")
                        }
                    }
                    else -> {
                        if (c < ' ') fail("unescaped control character")
                        sb.append(c)
                    }
                }
            }
            fail("unterminated string")
        }

        private fun readNumber(): Any {
            val start = index
            if (peek() == '-') index++
            while (index < text.length && (text[index].isDigit() || text[index] in ".eE+-")) index++
            val raw = text.substring(start, index)
            if (raw.isEmpty() || raw == "-") fail("invalid number")
            return if (raw.any { it == '.' || it == 'e' || it == 'E' }) {
                raw.toDoubleOrNull() ?: fail("invalid number '$raw'")
            } else {
                raw.toLongOrNull() ?: raw.toDoubleOrNull() ?: fail("invalid number '$raw'")
            }
        }

        private fun expectLiteral(literal: String) {
            if (!text.startsWith(literal, index)) fail("invalid literal")
            index += literal.length
        }

        private fun peek(): Char {
            if (index >= text.length) fail("unexpected end of input")
            return text[index]
        }

        private fun skipWhitespace() {
            while (index < text.length &&
                (text[index] == ' ' || text[index] == '\t' || text[index] == '\n' || text[index] == '\r')
            ) {
                index++
            }
        }

        private fun fail(message: String): Nothing =
            throw IllegalArgumentException("JSON error at offset $index: $message")
    }
}
