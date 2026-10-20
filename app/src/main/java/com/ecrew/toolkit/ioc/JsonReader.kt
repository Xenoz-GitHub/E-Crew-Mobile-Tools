package com.ecrew.toolkit.ioc

/** Minimal JSON reader used for STIX bundles; no Android or external dependency. */
internal object JsonReader {
    fun parse(text: String): Any? {
        val parser = Parser(text)
        val value = parser.value()
        parser.skipWhitespace()
        if (!parser.atEnd()) throw IocException("trailing JSON data at ${parser.position()}")
        return value
    }

    @Suppress("UNCHECKED_CAST")
    fun objectMap(value: Any?, what: String): Map<String, Any?> =
        value as? Map<String, Any?> ?: throw IocException("$what is not a JSON object")

    @Suppress("UNCHECKED_CAST")
    fun array(value: Any?, what: String): List<Any?> =
        value as? List<Any?> ?: throw IocException("$what is not a JSON array")

    private class Parser(private val text: String) {
        private var index = 0

        fun atEnd(): Boolean = index >= text.length
        fun position(): Int = index

        fun value(): Any? {
            skipWhitespace()
            if (atEnd()) throw IocException("unexpected end of JSON")
            return when (text[index]) {
                '{' -> objectValue()
                '[' -> arrayValue()
                '"' -> stringValue()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> numberValue()
            }
        }

        fun skipWhitespace() {
            while (!atEnd() && text[index].isWhitespace()) index++
        }

        private fun objectValue(): Map<String, Any?> {
            expect('{')
            val result = LinkedHashMap<String, Any?>()
            skipWhitespace()
            if (peek('}')) {
                index++
                return result
            }
            while (true) {
                skipWhitespace()
                if (!peek('"')) throw IocException("object key is not a string at $index")
                val key = stringValue()
                skipWhitespace()
                expect(':')
                result[key] = value()
                skipWhitespace()
                if (peek('}')) {
                    index++
                    return result
                }
                expect(',')
            }
        }

        private fun arrayValue(): List<Any?> {
            expect('[')
            val result = ArrayList<Any?>()
            skipWhitespace()
            if (peek(']')) {
                index++
                return result
            }
            while (true) {
                result.add(value())
                skipWhitespace()
                if (peek(']')) {
                    index++
                    return result
                }
                expect(',')
            }
        }

        private fun stringValue(): String {
            expect('"')
            val builder = StringBuilder()
            while (!atEnd()) {
                val character = text[index++]
                when (character) {
                    '"' -> return builder.toString()
                    '\\' -> {
                        if (atEnd()) throw IocException("unterminated escape")
                        when (val escaped = text[index++]) {
                            '"', '\\', '/' -> builder.append(escaped)
                            'b' -> builder.append('\b')
                            'f' -> builder.append('\u000C')
                            'n' -> builder.append('\n')
                            'r' -> builder.append('\r')
                            't' -> builder.append('\t')
                            'u' -> {
                                if (index + 4 > text.length) {
                                    throw IocException("short unicode escape")
                                }
                                val hex = text.substring(index, index + 4)
                                val code = hex.toIntOrNull(16)
                                    ?: throw IocException("invalid unicode escape")
                                builder.append(code.toChar())
                                index += 4
                            }
                            else -> throw IocException("unsupported escape \\$escaped")
                        }
                    }
                    else -> builder.append(character)
                }
            }
            throw IocException("unterminated string")
        }

        private fun numberValue(): Number {
            val start = index
            if (peek('-')) index++
            while (!atEnd() && (text[index].isDigit() || text[index] == '.' ||
                    text[index] == 'e' || text[index] == 'E' || text[index] == '+' ||
                    text[index] == '-')
            ) {
                index++
            }
            if (start == index) throw IocException("unexpected token at $index")
            val token = text.substring(start, index)
            return token.toLongOrNull() ?: token.toDoubleOrNull()
                ?: throw IocException("invalid number at $start")
        }

        private fun literal(token: String, value: Any?): Any? {
            if (!text.startsWith(token, index)) throw IocException("invalid literal at $index")
            index += token.length
            return value
        }

        private fun expect(character: Char) {
            if (atEnd() || text[index] != character) {
                throw IocException("expected '$character' at $index")
            }
            index++
        }

        private fun peek(character: Char): Boolean = !atEnd() && text[index] == character
    }
}
