package com.ecrew.toolkit.apk

import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.Locale

data class PrintableStrings(
    val strings: List<String>,
    val truncated: Boolean,
    val bytesRead: Long,
    val sha256: String,
    val isElf: Boolean,
    val is64Bit: Boolean
)

/**
 * Streams a native file once to compute its SHA-256 and collect printable ASCII runs.
 * Caps are enforced while reading; a capped or oversized run is reported via [truncated],
 * never silently omitted.
 */
object PrintableStringsReader {
    fun read(
        input: InputStream,
        maxBytes: Int,
        maxStrings: Int,
        maxStringLength: Int = 4096,
        maxTotalChars: Int = 8 * 1024 * 1024
    ): PrintableStrings {
        require(maxBytes > 0) { "maxBytes must be positive" }
        require(maxStrings > 0) { "maxStrings must be positive" }
        require(maxStringLength >= 4) { "maxStringLength must be at least 4" }
        require(maxTotalChars > 0) { "maxTotalChars must be positive" }
        val digest = MessageDigest.getInstance("SHA-256")
        val strings = ArrayList<String>()
        val current = StringBuilder()
        val header = ByteArray(6)
        var headerBytes = 0
        var totalBytes = 0L
        var totalChars = 0
        var truncated = false
        var keepStrings = true
        var currentOverflow = false
        val buffer = ByteArray(8192)

        fun finishRun() {
            if (current.length >= 4) {
                if (keepStrings && strings.size >= maxStrings) {
                    truncated = true
                    keepStrings = false
                }
                if (keepStrings) {
                    if (totalChars + current.length > maxTotalChars) {
                        truncated = true
                        keepStrings = false
                    } else {
                        strings.add(current.toString())
                        totalChars += current.length
                    }
                }
            }
            current.setLength(0)
            currentOverflow = false
        }

        fun processByte(value: Int) {
            if (headerBytes < header.size) {
                header[headerBytes] = value.toByte()
                headerBytes++
            }
            if (value in 0x20..0x7E) {
                if (current.length < maxStringLength) {
                    current.append(value.toChar())
                } else {
                    currentOverflow = true
                    truncated = true
                }
            } else {
                if (currentOverflow) truncated = true
                finishRun()
            }
        }

        try {
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                var usable = count
                if (totalBytes + count > maxBytes) {
                    usable = (maxBytes - totalBytes).toInt()
                    truncated = true
                }
                if (usable > 0) {
                    digest.update(buffer, 0, usable)
                    for (index in 0 until usable) {
                        processByte(buffer[index].toInt() and 0xFF)
                    }
                    totalBytes += usable
                }
                if (usable < count) break
            }
        } catch (error: IOException) {
            throw ApkArchiveException(
                "cannot read native library: ${error.message ?: "I/O error"}",
                error
            )
        }
        if (currentOverflow) truncated = true
        finishRun()
        val isElf = headerBytes >= 4 &&
            header[0] == 0x7F.toByte() &&
            header[1] == 'E'.code.toByte() &&
            header[2] == 'L'.code.toByte() &&
            header[3] == 'F'.code.toByte()
        val is64Bit = isElf && headerBytes >= 5 && header[4] == 2.toByte()
        return PrintableStrings(
            strings = strings,
            truncated = truncated,
            bytesRead = totalBytes,
            sha256 = digest.digest().joinToString("") { byte ->
                String.format(Locale.US, "%02x", byte.toInt() and 0xFF)
            },
            isElf = isElf,
            is64Bit = is64Bit
        )
    }
}
