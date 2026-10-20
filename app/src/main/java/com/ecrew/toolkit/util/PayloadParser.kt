package com.ecrew.toolkit.util

import android.util.Base64
import java.net.URLDecoder

/** One decoded layer of a (possibly nested-encoded) payload. */
data class DecodeStep(
    val layer: Int,
    val encoding: String,
    val value: String,
    val isBinary: Boolean = false
)

data class UrlParts(
    val scheme: String?,
    val userInfo: String?,
    val host: String?,
    val port: Int?,
    val path: String?,
    val query: List<Pair<String, String>>,
    val fragment: String?
)

data class ParsedPayload(
    val original: String,
    val layers: List<DecodeStep>,
    val hexDump: String,
    val urlInfo: UrlParts?,
    val urls: List<String>,
    val iocs: IocSet,
    val yaraMatches: List<YaraMatch>,
    val blocklistHits: List<String>,
    val cborTree: String?
)

/**
 * Deep-inspects a QR payload: iterative nested decoding (URL-encoding, Base64,
 * hex) with cycle/depth guards, classic hex dump, URL decomposition, IOC
 * extraction, YARA-lite rule matching and blocklist matching.
 */
object PayloadParser {

    private const val MAX_LAYERS = 8

    fun parse(input: String): ParsedPayload {
        val layers = decodeLayers(input)
        val combinedText = (listOf(input) + layers.map { it.value }).joinToString("\n")

        val hexDump = hexDump(input.toByteArray(Charsets.UTF_8))
        val urlInfo = findUrl(combinedText)?.let { parseUrl(it) }
        val urls = IocExtractor.extractUrls(combinedText)
        val iocs = IocExtractor.extract(combinedText)
        val yaraMatches = YaraEngine.scanAssets(combinedText)
        val blocklistHits = Blocklist.check(iocs.domains + iocs.urls.mapNotNull { hostOf(it) })

        val cborTree = inspectCbor(input)

        return ParsedPayload(
            original = input,
            layers = layers,
            hexDump = hexDump,
            urlInfo = urlInfo,
            urls = urls,
            iocs = iocs,
            yaraMatches = yaraMatches,
            blocklistHits = blocklistHits,
            cborTree = cborTree
        )
    }

    /** Iteratively unwrap encodings until no further transform applies. */
    fun decodeLayers(input: String): List<DecodeStep> {
        val steps = mutableListOf<DecodeStep>()
        val seen = mutableSetOf(input)
        var current = input
        var layer = 0

        while (layer < MAX_LAYERS) {
            val next: Pair<String, String>? =
                urlDecodeStep(current) ?: base64Step(current) ?: hexStep(current)
                    ?: nestedQrStep(current)

            val (value, encoding) = next ?: break
            if (value == current || seen.contains(value)) break
            seen.add(value)
            layer++
            steps.add(DecodeStep(layer, encoding, value, isBinary = !isMostlyPrintable(value)))
            current = value
        }
        return steps
    }

    // ---------------------------------------------------------------- decoding

    private fun urlDecodeStep(s: String): Pair<String, String>? {
        if (!s.contains('%') && !s.contains('+')) return null
        return try {
            val decoded = URLDecoder.decode(s, "UTF-8")
            if (decoded != s && isMostlyPrintable(decoded)) decoded to "URL-encoding" else null
        } catch (e: Exception) {
            null
        }
    }

    private fun base64Step(s: String): Pair<String, String>? {
        val trimmed = s.trim()
        if (trimmed.length < 8) return null
        if (!trimmed.matches(Regex("^[A-Za-z0-9+/=\\s]+$"))) return null

        for (flags in intArrayOf(Base64.DEFAULT, Base64.URL_SAFE)) {
            try {
                val decoded = Base64.decode(trimmed, flags)
                if (decoded.isEmpty()) continue
                val text = String(decoded, Charsets.UTF_8)
                if (isMostlyPrintable(text) && text != s) {
                    return text to "Base64"
                }
                // Accept as binary layer only for long inputs (low false-positive rate).
                if (trimmed.length >= 16) {
                    val asHex = bytesToHexPreview(decoded)
                    return asHex to "Base64 -> binary (${decoded.size} bytes)"
                }
            } catch (e: Exception) {
                // try next flag
            }
        }
        return null
    }

    private fun hexStep(s: String): Pair<String, String>? {
        var body = s.trim()
        if (body.startsWith("0x") || body.startsWith("0X")) body = body.substring(2)
        if (body.length < 8 || body.length % 2 != 0) return null
        if (!body.matches(Regex("^[0-9a-fA-F]+$"))) return null

        return try {
            val decoded = hexToByteArray(body)
            val text = String(decoded, Charsets.UTF_8)
            when {
                isMostlyPrintable(text) && text != s -> text to "Hex"
                decoded.size >= 4 -> bytesToHexPreview(decoded) to "Hex -> binary (${decoded.size} bytes)"
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Structured-container unwrapping: QR-standard payloads whose fields are
     * themselves analysable (WIFI:..., vCard...).
     */
    private fun nestedQrStep(s: String): Pair<String, String>? {
        val trimmed = s.trim()
        if (trimmed.startsWith("WIFI:", ignoreCase = true)) {
            val fields = Regex("([A-Za-z]+):((?:[^;\\\\]|\\\\.)*);")
                .findAll(trimmed)
                .joinToString("\n") { "${it.groupValues[1]}=${unescape(it.groupValues[2])}" }
            return if (fields.isNotBlank()) fields to "WifiConfig fields" else null
        }
        if (trimmed.startsWith("BEGIN:VCARD", ignoreCase = true)) {
            val fields = trimmed.lines()
                .filter { it.isNotBlank() && !it.startsWith("BEGIN") && !it.startsWith("END") }
                .joinToString("\n")
            return fields to "vCard fields"
        }
        return null
    }

    private fun unescape(v: String) =
        v.replace("\\\\", "\\").replace("\\;", ";").replace("\\:", ":")

    // ---------------------------------------------------------------- display

    fun hexDump(data: ByteArray, maxBytes: Int = 4096): String {
        val len = minOf(data.size, maxBytes)
        val sb = StringBuilder()
        if (data.size > maxBytes) sb.append("(showing first $maxBytes of ${data.size} bytes)\n")
        var i = 0
        while (i < len) {
            sb.append("%08X  ".format(i.toLong()))
            val end = minOf(i + 16, len)
            var j = i
            while (j < i + 16) {
                if (j < end) sb.append("%02X ".format(data[j])) else sb.append("   ")
                if (j % 16 == 7) sb.append(' ')
                j++
            }
            sb.append(' ')
            j = i
            while (j < end) {
                val c = data[j].toInt() and 0xFF
                sb.append(if (c in 32..126) c.toChar() else '.')
                j++
            }
            sb.append('\n')
            i += 16
        }
        return sb.toString()
    }

    fun findUrl(text: String): String? {
        val m = Regex("https?://[^\\s\"'<>\\)]+").find(text) ?: return null
        return m.value.trimEnd('.', ',', ';', ':', '!', '?')
    }

    fun parseUrl(url: String): UrlParts? {
        return try {
            val m = Regex(
                "^(?<scheme>[a-zA-Z][a-zA-Z0-9+.-]*):" +
                    "(?://(?<userinfo>[^@/]+)@)?" +
                    "(?<host>[^/:?#]+)" +
                    "(?::(?<port>\\d+))?" +
                    "(?<path>/[^?#]*)?" +
                    "(?:\\?(?<query>[^#]*))?" +
                    "(?:#(?<fragment>.*))?$"
            ).find(url) ?: return null
            val g = m.groups
            val query = (g["query"]?.value ?: "").split('&')
                .filter { it.isNotEmpty() }
                .map {
                    val idx = it.indexOf('=')
                    if (idx >= 0) {
                        URLDecoder.decode(it.substring(0, idx), "UTF-8") to
                            URLDecoder.decode(it.substring(idx + 1), "UTF-8")
                    } else it to ""
                }
            UrlParts(
                scheme = g["scheme"]?.value,
                userInfo = g["userinfo"]?.value,
                host = g["host"]?.value,
                port = g["port"]?.value?.toIntOrNull(),
                path = g["path"]?.value,
                query = query,
                fragment = g["fragment"]?.value
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun hostOf(url: String): String? = parseUrl(url)?.host

    // ---------------------------------------------------------------- helpers

    fun isMostlyPrintable(s: String): Boolean {
        if (s.isEmpty()) return false
        var printable = 0
        for (c in s) {
            if (c == '\n' || c == '\r' || c == '\t' || c in ' '..'~') printable++
        }
        return printable.toDouble() / s.length >= 0.85
    }

    fun bytesToHexPreview(data: ByteArray, max: Int = 64): String {
        val len = minOf(data.size, max)
        val sb = StringBuilder()
        for (i in 0 until len) {
            if (i > 0) sb.append(' ')
            sb.append("%02X".format(data[i]))
        }
        if (data.size > max) sb.append(" ... (${data.size} bytes)")
        return sb.toString()
    }

    fun hexToByteArray(hex: String): ByteArray {
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(hex[i * 2], 16)
            val lo = Character.digit(hex[i * 2 + 1], 16)
            if (hi < 0 || lo < 0) throw IllegalArgumentException("invalid hex")
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    /** Try to render the payload (or an embedded hex blob) as a CBOR tree. */
    private fun inspectCbor(s: String): String? {
        CborInspector.decodeToTree(s.toByteArray(Charsets.UTF_8))?.let { return it }
        val trimmed = s.trim().removePrefix("0x").removePrefix("0X")
        if (trimmed.length >= 2 && trimmed.length % 2 == 0 &&
            trimmed.matches(Regex("^[0-9a-fA-F]+$"))
        ) {
            return try {
                CborInspector.decodeToTree(hexToByteArray(trimmed))
            } catch (e: Exception) {
                null
            }
        }
        return null
    }
}


