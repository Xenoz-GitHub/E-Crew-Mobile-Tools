package com.ecrew.toolkit.acquisition

/** Small JSON string helper shared by acquisition modules. */
object QfJson {
    fun quote(value: String?): String {
        if (value == null) return "null"
        return buildString {
            append('"')
            value.forEach { character ->
                when (character) {
                    '"' -> append("\\\"")
                    '\\' -> append("\\\\")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> if (character.code < 0x20) {
                        append("\\u").append("%04x".format(character.code))
                    } else {
                        append(character)
                    }
                }
            }
            append('"')
        }
    }
}
