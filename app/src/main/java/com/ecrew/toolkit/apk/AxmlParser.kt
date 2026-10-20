package com.ecrew.toolkit.apk

import java.io.IOException
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.util.ArrayDeque
import java.util.Locale

/** Hard limits applied while decoding a binary XML resource. */
data class AxmlLimits(
    val maxChunks: Int = 200_000,
    val maxStringPoolEntries: Int = 1_000_000,
    val maxStringChars: Int = 1_048_576,
    val maxResourceIds: Int = 100_000,
    val maxAttributesPerElement: Int = 10_000,
    val maxDepth: Int = 512,
    val maxChunkBytes: Int = 32 * 1024 * 1024,
    val maxOutputChars: Int = 8 * 1024 * 1024
)

/** A malformed binary XML input; [offset] is the byte position of the failure. */
class AxmlParseException(message: String, val offset: Long) :
    Exception("$message (byte $offset)")

/**
 * Decodes the binary AndroidManifest.xml embedded in an APK into XML text.
 *
 * The parser is pure JVM code: no Android APIs, no external binaries and no whole-file
 * assumption. It validates every chunk length and string-pool offset against [AxmlLimits]
 * and reports failures as [AxmlParseException].
 */
object AxmlParser {
    private const val RES_XML_TYPE = 0x0003
    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_XML_RESOURCE_MAP_TYPE = 0x0180
    private const val RES_XML_START_NAMESPACE_TYPE = 0x0100
    private const val RES_XML_END_NAMESPACE_TYPE = 0x0101
    private const val RES_XML_START_ELEMENT_TYPE = 0x0102
    private const val RES_XML_END_ELEMENT_TYPE = 0x0103
    private const val RES_XML_CDATA_TYPE = 0x0104

    private const val NO_INDEX = 0xFFFFFFFFL
    private const val UTF8_FLAG = 1 shl 8

    private const val TYPE_NULL = 0x00
    private const val TYPE_REFERENCE = 0x01
    private const val TYPE_ATTRIBUTE = 0x02
    private const val TYPE_STRING = 0x03
    private const val TYPE_FLOAT = 0x04
    private const val TYPE_DIMENSION = 0x05
    private const val TYPE_FRACTION = 0x06
    private const val TYPE_DYNAMIC_REFERENCE = 0x07
    private const val TYPE_DYNAMIC_ATTRIBUTE = 0x08
    private const val TYPE_INT_DEC = 0x10
    private const val TYPE_INT_HEX = 0x11
    private const val TYPE_INT_BOOLEAN = 0x12
    private const val TYPE_INT_COLOR_ARGB8 = 0x1c
    private const val TYPE_INT_COLOR_RGB8 = 0x1d
    private const val TYPE_INT_COLOR_ARGB4 = 0x1e
    private const val TYPE_INT_COLOR_RGB4 = 0x1f

    fun parse(input: InputStream, limits: AxmlLimits = AxmlLimits()): String {
        require(limits.maxChunks > 0) { "maxChunks must be positive" }
        require(limits.maxStringPoolEntries > 0) { "maxStringPoolEntries must be positive" }
        require(limits.maxStringChars > 0) { "maxStringChars must be positive" }
        require(limits.maxResourceIds > 0) { "maxResourceIds must be positive" }
        require(limits.maxAttributesPerElement > 0) {
            "maxAttributesPerElement must be positive"
        }
        require(limits.maxDepth > 0) { "maxDepth must be positive" }
        require(limits.maxChunkBytes >= 8) { "maxChunkBytes must be at least 8" }
        require(limits.maxOutputChars > 0) { "maxOutputChars must be positive" }

        val reader = ChunkReader(input)
        val fileHeader = ByteArray(8)
        if (!reader.readHeader(fileHeader)) {
            throw AxmlParseException("empty input", 0)
        }
        val fileStart = 0L
        val fileType = u16(fileHeader, 0)
        if (fileType != RES_XML_TYPE) {
            throw AxmlParseException(
                "unexpected file chunk type 0x${hex4(fileType)}",
                fileStart
            )
        }
        checkChunkSize(fileHeader, fileStart, limits)

        val sink = XmlSink(limits.maxOutputChars)
        sink.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n", fileStart)

        var pool: StringPool? = null
        var resourceIds: List<Long> = emptyList()
        val namespaces = ArrayList<NamespaceDecl>()
        val pendingNamespaces = ArrayList<NamespaceDecl>()
        val generatedPrefixes = LinkedHashMap<String, String>()
        val stack = ArrayDeque<String>()
        var chunkCount = 1
        var elementCount = 0
        var generatedPrefixCount = 0
        var lastOffset = 0L

        while (true) {
            val header = ByteArray(8)
            if (!reader.readHeader(header)) break
            val chunkStart = reader.position - 8
            lastOffset = chunkStart
            val type = u16(header, 0)
            val size = checkChunkSize(header, chunkStart, limits)
            chunkCount++
            if (chunkCount > limits.maxChunks) {
                throw AxmlParseException(
                    "chunk count exceeds ${limits.maxChunks}",
                    chunkStart
                )
            }

            if (!isKnownChunk(type)) {
                reader.skip(size - 8, chunkStart)
                continue
            }
            if (size > Int.MAX_VALUE) {
                throw AxmlParseException("chunk too large", chunkStart)
            }
            val full = ByteArray(size.toInt())
            header.copyInto(full)
            reader.readFully(full, 8, full.size - 8, chunkStart)

            when (type) {
                RES_STRING_POOL_TYPE -> {
                    if (pool != null) {
                        throw AxmlParseException("duplicate string pool", chunkStart)
                    }
                    pool = parseStringPool(full, chunkStart, limits)
                }

                RES_XML_RESOURCE_MAP_TYPE -> {
                    val count = (full.size - 8) / 4
                    if (count > limits.maxResourceIds) {
                        throw AxmlParseException(
                            "resource map exceeds ${limits.maxResourceIds} ids",
                            chunkStart
                        )
                    }
                    val ids = ArrayList<Long>(count)
                    var at = 8
                    while (at + 4 <= full.size) {
                        ids.add(u32(full, at))
                        at += 4
                    }
                    resourceIds = ids
                }

                RES_XML_START_NAMESPACE_TYPE -> {
                    requireNodeHeader(full, chunkStart, 24)
                    val prefixIndex = u32(full, 16)
                    val uriIndex = u32(full, 20)
                    val currentPool = requirePool(pool, chunkStart)
                    val prefix = if (prefixIndex == NO_INDEX) {
                        ""
                    } else {
                        currentPool.get(prefixIndex, chunkStart + 16)
                    }
                    val uri = if (uriIndex == NO_INDEX) {
                        ""
                    } else {
                        currentPool.get(uriIndex, chunkStart + 20)
                    }
                    val declaration = NamespaceDecl(prefix, uri)
                    namespaces.add(declaration)
                    pendingNamespaces.add(declaration)
                }

                RES_XML_END_NAMESPACE_TYPE -> {
                    requireNodeHeader(full, chunkStart, 24)
                    val prefixIndex = u32(full, 16)
                    val uriIndex = u32(full, 20)
                    val currentPool = requirePool(pool, chunkStart)
                    val prefix = if (prefixIndex == NO_INDEX) {
                        ""
                    } else {
                        currentPool.get(prefixIndex, chunkStart + 16)
                    }
                    val uri = if (uriIndex == NO_INDEX) {
                        ""
                    } else {
                        currentPool.get(uriIndex, chunkStart + 20)
                    }
                    for (index in namespaces.indices.reversed()) {
                        val candidate = namespaces[index]
                        if (candidate.prefix == prefix && candidate.uri == uri) {
                            namespaces.removeAt(index)
                            break
                        }
                    }
                }

                RES_XML_START_ELEMENT_TYPE -> {
                    val currentPool = requirePool(pool, chunkStart)
                    val headerSize = u16(full, 2)
                    val attrsOffset = headerSize + 20
                    if (headerSize < 16 || attrsOffset > full.size) {
                        throw AxmlParseException("truncated start element", chunkStart)
                    }
                    val nameIndex = u32(full, headerSize + 4)
                    val tag = currentPool.get(nameIndex, chunkStart + headerSize + 4)
                    val attributeStart = u16(full, headerSize + 8)
                    val attributeSize = u16(full, headerSize + 10)
                    val attributeCount = u16(full, headerSize + 12)
                    if (attributeCount > limits.maxAttributesPerElement) {
                        throw AxmlParseException(
                            "attribute count exceeds ${limits.maxAttributesPerElement}",
                            chunkStart
                        )
                    }
                    if (attributeSize < 20) {
                        throw AxmlParseException(
                            "attribute record smaller than 20 bytes",
                            chunkStart
                        )
                    }
                    val attrBase = headerSize + attributeStart
                    val attrEnd = attrBase.toLong() + attributeCount.toLong() * attributeSize
                    if (attributeStart < 20 || attrBase < 0 || attrEnd > full.size) {
                        throw AxmlParseException("attribute table out of range", chunkStart)
                    }
                    if (stack.size >= limits.maxDepth) {
                        throw AxmlParseException(
                            "element depth exceeds ${limits.maxDepth}",
                            chunkStart
                        )
                    }

                    val attrs = StringBuilder()
                    for (declaration in pendingNamespaces) {
                        if (declaration.prefix.isEmpty()) {
                            attrs.append(" xmlns=\"").append(escape(declaration.uri))
                                .append('"')
                        } else {
                            attrs.append(" xmlns:").append(declaration.prefix)
                                .append("=\"").append(escape(declaration.uri)).append('"')
                        }
                    }
                    pendingNamespaces.clear()

                    var attrAt = attrBase
                    for (attributeIndex in 0 until attributeCount) {
                        val at = chunkStart + attrAt
                        val nsIndex = u32(full, attrAt)
                        val attrNameIndex = u32(full, attrAt + 4)
                        val rawIndex = u32(full, attrAt + 8)
                        val valueSize = u16(full, attrAt + 12)
                        val dataType = u8(full, attrAt + 15)
                        val data = u32(full, attrAt + 16)
                        if (valueSize < 8) {
                            throw AxmlParseException(
                                "typed value smaller than 8 bytes",
                                at
                            )
                        }
                        val name = if (attrNameIndex != NO_INDEX) {
                            currentPool.get(attrNameIndex, at + 4)
                        } else {
                            val id = resourceIds.getOrNull(attributeIndex)
                            if (id == null) "attr$attributeIndex" else {
                                String.format(Locale.US, "attr_0x%08x", id)
                            }
                        }
                        val prefix = if (nsIndex == NO_INDEX) {
                            ""
                        } else {
                            val uri = currentPool.get(nsIndex, at)
                            val active = namespaces.lastOrNull { it.uri == uri }
                            if (active != null) {
                                active.prefix
                            } else {
                                val existing = generatedPrefixes[uri]
                                if (existing != null) {
                                    existing
                                } else {
                                    val generated = "ns${generatedPrefixCount++}"
                                    generatedPrefixes[uri] = generated
                                    attrs.append(" xmlns:").append(generated)
                                        .append("=\"").append(escape(uri)).append('"')
                                    generated
                                }
                            }
                        }
                        val value = if (rawIndex != NO_INDEX) {
                            currentPool.get(rawIndex, at + 8)
                        } else {
                            formatTypedValue(currentPool, dataType, data, at + 12)
                        }
                        attrs.append(' ')
                        if (prefix.isNotEmpty()) attrs.append(prefix).append(':')
                        attrs.append(name).append("=\"").append(escape(value)).append('"')
                        attrAt += attributeSize
                    }

                    sink.append(
                        "  ".repeat(stack.size) + "<" + tag + attrs + ">\n",
                        chunkStart
                    )
                    stack.addLast(tag)
                    elementCount++
                }

                RES_XML_END_ELEMENT_TYPE -> {
                    val currentPool = requirePool(pool, chunkStart)
                    val headerSize = u16(full, 2)
                    if (headerSize < 16 || headerSize + 8 > full.size) {
                        throw AxmlParseException("truncated end element", chunkStart)
                    }
                    val nameIndex = u32(full, headerSize + 4)
                    val tag = currentPool.get(nameIndex, chunkStart + headerSize + 4)
                    if (stack.isEmpty()) {
                        throw AxmlParseException("unexpected end element $tag", chunkStart)
                    }
                    val open = stack.removeLast()
                    if (open != tag) {
                        throw AxmlParseException(
                            "end element $tag closes $open",
                            chunkStart
                        )
                    }
                    sink.append("  ".repeat(stack.size) + "</" + tag + ">\n", chunkStart)
                }

                RES_XML_CDATA_TYPE -> {
                    requireNodeHeader(full, chunkStart, 28)
                    val currentPool = requirePool(pool, chunkStart)
                    val dataIndex = u32(full, 16)
                    val text = currentPool.get(dataIndex, chunkStart + 16)
                    sink.append(escape(text), chunkStart)
                }
            }
        }

        if (pool == null) {
            throw AxmlParseException("no string pool", lastOffset)
        }
        if (!stack.isEmpty()) {
            throw AxmlParseException("unclosed element ${stack.last()}", lastOffset)
        }
        if (elementCount == 0) {
            throw AxmlParseException("no XML elements", lastOffset)
        }
        return sink.toString()
    }

    private fun requirePool(pool: StringPool?, offset: Long): StringPool =
        pool ?: throw AxmlParseException("string reference before string pool", offset)

    private fun requireNodeHeader(full: ByteArray, chunkStart: Long, minimum: Int) {
        val headerSize = u16(full, 2)
        if (headerSize < 16 || headerSize + minimum - 16 > full.size) {
            throw AxmlParseException("truncated XML node chunk", chunkStart)
        }
    }

    private fun isKnownChunk(type: Int): Boolean = when (type) {
        RES_STRING_POOL_TYPE,
        RES_XML_RESOURCE_MAP_TYPE,
        RES_XML_START_NAMESPACE_TYPE,
        RES_XML_END_NAMESPACE_TYPE,
        RES_XML_START_ELEMENT_TYPE,
        RES_XML_END_ELEMENT_TYPE,
        RES_XML_CDATA_TYPE -> true
        else -> false
    }

    private fun checkChunkSize(header: ByteArray, chunkStart: Long, limits: AxmlLimits): Long {
        val headerSize = u16(header, 2)
        val size = u32(header, 4)
        if (headerSize < 8) {
            throw AxmlParseException("chunk header size $headerSize is too small", chunkStart)
        }
        if (size < 8) {
            throw AxmlParseException("chunk size $size is too small", chunkStart)
        }
        if (headerSize > size) {
            throw AxmlParseException(
                "chunk header size $headerSize exceeds chunk size $size",
                chunkStart
            )
        }
        if (size > limits.maxChunkBytes) {
            throw AxmlParseException(
                "chunk size $size exceeds ${limits.maxChunkBytes}",
                chunkStart
            )
        }
        return size
    }

    private fun parseStringPool(
        full: ByteArray,
        chunkStart: Long,
        limits: AxmlLimits
    ): StringPool {
        if (full.size < 28) {
            throw AxmlParseException("truncated string pool", chunkStart)
        }
        val headerSize = u16(full, 2)
        if (headerSize < 28 || headerSize > full.size) {
            throw AxmlParseException("invalid string pool header size", chunkStart)
        }
        val stringCount = u32(full, 8)
        val styleCount = u32(full, 12)
        val flags = u32(full, 16)
        val stringsStart = u32(full, 20)
        val stylesStart = u32(full, 24)
        if (stringCount > limits.maxStringPoolEntries) {
            throw AxmlParseException(
                "string pool count $stringCount exceeds ${limits.maxStringPoolEntries}",
                chunkStart
            )
        }
        if (styleCount > limits.maxStringPoolEntries) {
            throw AxmlParseException(
                "style pool count $styleCount exceeds ${limits.maxStringPoolEntries}",
                chunkStart
            )
        }
        val offsetsEnd = headerSize.toLong() + stringCount * 4L
        if (offsetsEnd > full.size) {
            throw AxmlParseException("string pool offset table out of range", chunkStart)
        }
        if (stringCount > 0) {
            if (stringsStart < headerSize.toLong() || stringsStart > full.size) {
                throw AxmlParseException("string pool data offset out of range", chunkStart)
            }
        }
        if (stylesStart != 0L && (stylesStart < headerSize.toLong() || stylesStart > full.size)) {
            throw AxmlParseException("string pool style offset out of range", chunkStart)
        }
        val utf8 = (flags.toInt() and UTF8_FLAG) != 0
        val strings = ArrayList<String>(stringCount.toInt())
        for (index in 0 until stringCount.toInt()) {
            val relative = u32(full, headerSize + index * 4)
            val at = stringsStart + relative
            if (at < 0 || at >= full.size) {
                throw AxmlParseException(
                    "string $index offset $at is out of range",
                    chunkStart
                )
            }
            strings.add(decodeString(full, at.toInt(), utf8, chunkStart, limits))
        }
        return StringPool(strings)
    }

    private fun decodeString(
        full: ByteArray,
        start: Int,
        utf8: Boolean,
        chunkStart: Long,
        limits: AxmlLimits
    ): String {
        if (start >= full.size) {
            throw AxmlParseException("string starts outside the pool", chunkStart + start)
        }
        if (utf8) {
            var at = start
            val charLengthResult = readUtf8Length(full, at, chunkStart)
            at = charLengthResult.second
            val byteLengthResult = readUtf8Length(full, at, chunkStart)
            at = byteLengthResult.second
            val charLength = charLengthResult.first
            val byteLength = byteLengthResult.first
            if (charLength > limits.maxStringChars) {
                throw AxmlParseException(
                    "string length $charLength exceeds ${limits.maxStringChars}",
                    chunkStart + start
                )
            }
            if (byteLength > limits.maxStringChars * 4L || at + byteLength > full.size) {
                throw AxmlParseException("string bytes are out of range", chunkStart + start)
            }
            return String(full, at, byteLength.toInt(), StandardCharsets.UTF_8)
        }
        var at = start
        if (at + 2 > full.size) {
            throw AxmlParseException("truncated UTF-16 string length", chunkStart + at)
        }
        var length = u16(full, at)
        at += 2
        if ((length and 0x8000) != 0) {
            if (at + 2 > full.size) {
                throw AxmlParseException("truncated UTF-16 string length", chunkStart + at)
            }
            length = ((length and 0x7fff) shl 16) or u16(full, at)
            at += 2
        }
        if (length > limits.maxStringChars) {
            throw AxmlParseException(
                "string length $length exceeds ${limits.maxStringChars}",
                chunkStart + start
            )
        }
        if (at.toLong() + length * 2L > full.size) {
            throw AxmlParseException("string bytes are out of range", chunkStart + start)
        }
        return String(full, at, length * 2, StandardCharsets.UTF_16LE)
    }

    private fun readUtf8Length(full: ByteArray, at: Int, chunkStart: Long): Pair<Int, Int> {
        if (at + 1 > full.size) {
            throw AxmlParseException("truncated UTF-8 string length", chunkStart + at)
        }
        val first = u8(full, at)
        if ((first and 0x80) == 0) {
            return Pair(first, at + 1)
        }
        if (at + 2 > full.size) {
            throw AxmlParseException("truncated UTF-8 string length", chunkStart + at)
        }
        val value = ((first and 0x7f) shl 8) or u8(full, at + 1)
        return Pair(value, at + 2)
    }

    private fun formatTypedValue(
        pool: StringPool,
        dataType: Int,
        data: Long,
        at: Long
    ): String = when (dataType) {
        TYPE_NULL -> ""
        TYPE_REFERENCE, TYPE_DYNAMIC_REFERENCE ->
            String.format(Locale.US, "@0x%08x", data.toInt())
        TYPE_ATTRIBUTE, TYPE_DYNAMIC_ATTRIBUTE ->
            String.format(Locale.US, "?0x%08x", data.toInt())
        TYPE_STRING -> pool.get(data, at + 4)
        TYPE_FLOAT -> java.lang.Float.intBitsToFloat(data.toInt()).toString()
        TYPE_DIMENSION -> formatComplex(data, isFraction = false)
        TYPE_FRACTION -> formatComplex(data, isFraction = true)
        TYPE_INT_DEC -> data.toString()
        TYPE_INT_HEX -> String.format(Locale.US, "0x%08x", data.toInt())
        TYPE_INT_BOOLEAN -> (data != 0L).toString()
        TYPE_INT_COLOR_ARGB8 -> String.format(Locale.US, "#%08x", data.toInt())
        TYPE_INT_COLOR_RGB8 -> String.format(Locale.US, "#%06x", data.toInt() and 0xFFFFFF)
        TYPE_INT_COLOR_ARGB4 -> String.format(Locale.US, "#%04x", data.toInt() and 0xFFFF)
        TYPE_INT_COLOR_RGB4 -> String.format(Locale.US, "#%03x", data.toInt() and 0xFFF)
        else -> String.format(Locale.US, "0x%08x", data.toInt())
    }

    private fun formatComplex(data: Long, isFraction: Boolean): String {
        val complex = data.toInt()
        val mantissa = complex and 0xFFFFFF00.toInt()
        val radix = (complex shr 4) and 0x3
        val multiplier = when (radix) {
            0 -> 1.0f / (1 shl 0)
            1 -> 1.0f / (1 shl 7)
            2 -> 1.0f / (1 shl 15)
            else -> 1.0f / (1 shl 23)
        }
        val value = mantissa * multiplier
        val unit = complex and 0xF
        if (isFraction) {
            val suffix = if (unit == 1) "%p" else "%"
            return formatDecimal(value) + suffix
        }
        val suffix = when (unit) {
            0 -> "px"
            1 -> "dp"
            2 -> "sp"
            3 -> "pt"
            4 -> "in"
            5 -> "mm"
            else -> ""
        }
        return formatDecimal(value) + suffix
    }

    private fun formatDecimal(value: Float): String {
        val text = value.toString()
        return if (text.endsWith(".0")) text.dropLast(2) else text
    }

    private fun escape(value: String): String {
        val out = StringBuilder(value.length + 8)
        for (ch in value) {
            when (ch) {
                '&' -> out.append("&amp;")
                '<' -> out.append("&lt;")
                '>' -> out.append("&gt;")
                '"' -> out.append("&quot;")
                '\'' -> out.append("&apos;")
                '\t', '\n', '\r' -> out.append(ch)
                else -> if (ch < ' ') out.append('\uFFFD') else out.append(ch)
            }
        }
        return out.toString()
    }

    private fun u8(data: ByteArray, at: Int): Int = data[at].toInt() and 0xFF

    private fun u16(data: ByteArray, at: Int): Int {
        if (at < 0 || at + 2 > data.size) {
            throw AxmlParseException("read outside chunk", at.toLong())
        }
        return (data[at].toInt() and 0xFF) or
            ((data[at + 1].toInt() and 0xFF) shl 8)
    }

    private fun u32(data: ByteArray, at: Int): Long {
        if (at < 0 || at + 4 > data.size) {
            throw AxmlParseException("read outside chunk", at.toLong())
        }
        return (data[at].toLong() and 0xFF) or
            ((data[at + 1].toLong() and 0xFF) shl 8) or
            ((data[at + 2].toLong() and 0xFF) shl 16) or
            ((data[at + 3].toLong() and 0xFF) shl 24)
    }

    private fun hex4(value: Int): String = Integer.toHexString(value and 0xFFFF)

    private class StringPool(private val strings: List<String>) {
        fun get(index: Long, at: Long): String {
            if (index == NO_INDEX || index < 0 || index >= strings.size) {
                throw AxmlParseException(
                    "string index $index out of range (${strings.size} entries)",
                    at
                )
            }
            return strings[index.toInt()]
        }
    }

    private data class NamespaceDecl(val prefix: String, val uri: String)

    private class XmlSink(private val maxChars: Int) {
        private val builder = StringBuilder()

        fun append(text: String, at: Long) {
            if (text.length > maxChars - builder.length) {
                throw AxmlParseException(
                    "XML output exceeds $maxChars characters",
                    at
                )
            }
            builder.append(text)
        }

        override fun toString(): String = builder.toString()
    }

    private class ChunkReader(private val input: InputStream) {
        var position: Long = 0
            private set

        fun readHeader(buffer: ByteArray): Boolean {
            var read = 0
            while (read < buffer.size) {
                val count = try {
                    input.read(buffer, read, buffer.size - read)
                } catch (error: IOException) {
                    throw AxmlParseException(
                        "read failed: ${error.message ?: "I/O error"}",
                        position
                    )
                }
                if (count < 0) break
                if (count == 0) continue
                read += count
                position += count
            }
            if (read == 0) return false
            if (read < buffer.size) {
                throw AxmlParseException("truncated chunk header", position - read)
            }
            return true
        }

        fun readFully(buffer: ByteArray, offset: Int, length: Int, at: Long) {
            var read = 0
            while (read < length) {
                val count = try {
                    input.read(buffer, offset + read, length - read)
                } catch (error: IOException) {
                    throw AxmlParseException(
                        "read failed: ${error.message ?: "I/O error"}",
                        at + read
                    )
                }
                if (count < 0) {
                    throw AxmlParseException(
                        "truncated chunk: needed $length bytes, got $read",
                        at
                    )
                }
                if (count == 0) continue
                read += count
                position += count
            }
        }

        fun skip(length: Long, at: Long) {
            var remaining = length
            val buffer = ByteArray(8192)
            while (remaining > 0) {
                val wanted = minOf(remaining, buffer.size.toLong()).toInt()
                val count = try {
                    input.read(buffer, 0, wanted)
                } catch (error: IOException) {
                    throw AxmlParseException(
                        "read failed: ${error.message ?: "I/O error"}",
                        at + length - remaining
                    )
                }
                if (count < 0) {
                    throw AxmlParseException("truncated chunk", at)
                }
                if (count == 0) continue
                remaining -= count
                position += count
            }
        }
    }
}
