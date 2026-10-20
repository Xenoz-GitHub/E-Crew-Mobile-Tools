package com.ecrew.toolkit.apk

import java.io.IOException
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.util.Locale

/** Hard limits applied while decoding resources.arsc. */
data class ArscLimits(
    val maxPackages: Int = 256,
    val maxTypeChunks: Int = 100_000,
    val maxStringPoolEntries: Int = 1_000_000,
    val maxStringChars: Int = 1_048_576,
    val maxEntries: Int = 1_000_000,
    val maxChunkBytes: Int = 64 * 1024 * 1024,
    val maxPackageBytes: Int = 64 * 1024 * 1024,
    val maxReferenceDepth: Int = 8
)

/** A malformed resources.arsc table. */
class ArscParseException(message: String, val offset: Long) :
    Exception("$message (byte $offset)")

/** A flattened, resolved resource table entry. */
data class ArscResource(
    val id: Int,
    val typeName: String,
    val name: String,
    val value: String
)

/**
 * Decodes resources.arsc enough to resolve manifest labels and resource IDs.
 *
 * Only scalar values are flattened. Style, array and other complex entries are skipped because
 * the workbench never needs to render them; callers get null from [resolve] for those ids.
 * Packages are processed one at a time, and all chunk and entry counts are capped.
 */
class ArscDecoder private constructor(
    private val resources: Map<Int, ArscResource>
) {
    val entries: List<ArscResource>
        get() = resources.values.toList()

    fun resolve(id: Int): ArscResource? = resources[id]

    companion object {
        private const val RES_TABLE_TYPE = 0x0002
        private const val RES_STRING_POOL_TYPE = 0x0001
        private const val RES_TABLE_PACKAGE_TYPE = 0x0200
        private const val RES_TABLE_TYPE_TYPE = 0x0201
        private const val RES_TABLE_TYPE_SPEC_TYPE = 0x0202

        private const val NO_ENTRY = 0xFFFFFFFFL
        private const val UTF8_FLAG = 1 shl 8
        private const val FLAG_COMPLEX = 0x0001

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

        fun parse(input: InputStream, limits: ArscLimits = ArscLimits()): ArscDecoder {
            require(limits.maxPackages > 0) { "maxPackages must be positive" }
            require(limits.maxTypeChunks > 0) { "maxTypeChunks must be positive" }
            require(limits.maxStringPoolEntries > 0) {
                "maxStringPoolEntries must be positive"
            }
            require(limits.maxStringChars > 0) { "maxStringChars must be positive" }
            require(limits.maxEntries > 0) { "maxEntries must be positive" }
            require(limits.maxChunkBytes >= 8) { "maxChunkBytes must be at least 8" }
            require(limits.maxPackageBytes >= 8) { "maxPackageBytes must be at least 8" }
            require(limits.maxReferenceDepth > 0) { "maxReferenceDepth must be positive" }

            val reader = TableReader(input)
            val fileHeader = ByteArray(12)
            val headerRead = reader.readUpTo(fileHeader)
            if (headerRead == 0) {
                throw ArscParseException("empty resource table", 0)
            }
            if (headerRead < fileHeader.size) {
                throw ArscParseException("truncated resource table header", 0)
            }
            if (u16(fileHeader, 0) != RES_TABLE_TYPE) {
                throw ArscParseException("not a resource table", 0)
            }
            val fileHeaderSize = u16(fileHeader, 2)
            if (fileHeaderSize < 12) {
                throw ArscParseException(
                    "resource table header size $fileHeaderSize is too small",
                    0
                )
            }
            val fileSize = u32(fileHeader, 4)
            if (fileSize < 12) {
                throw ArscParseException("resource table size $fileSize is too small", 0)
            }
            val packageCount = u32(fileHeader, 8)
            if (packageCount > limits.maxPackages) {
                throw ArscParseException(
                    "package count $packageCount exceeds ${limits.maxPackages}",
                    0
                )
            }

            var pool: StringPool? = null
            val rawResources = LinkedHashMap<Int, RawResource>()
            val seenPackages = HashSet<Int>()
            var packageChunks = 0
            var chunkCount = 0

            while (true) {
                val header = ByteArray(8)
                if (!reader.readHeader(header)) break
                val chunkStart = reader.position - 8
                val type = u16(header, 0)
                val size = checkedSize(header, chunkStart, limits.maxChunkBytes)
                chunkCount++
                if (type != RES_STRING_POOL_TYPE && type != RES_TABLE_PACKAGE_TYPE) {
                    reader.skip(size - 8, chunkStart)
                    continue
                }
                if (size > Int.MAX_VALUE) {
                    throw ArscParseException("chunk too large", chunkStart)
                }
                val full = ByteArray(size.toInt())
                header.copyInto(full)
                reader.readFully(full, 8, full.size - 8, chunkStart)
                when (type) {
                    RES_STRING_POOL_TYPE -> {
                        if (pool != null) {
                            throw ArscParseException("duplicate global string pool", chunkStart)
                        }
                        pool = parseStringPool(full, 0, chunkStart, limits)
                    }

                    RES_TABLE_PACKAGE_TYPE -> {
                        if (size > limits.maxPackageBytes) {
                            throw ArscParseException(
                                "package chunk exceeds ${limits.maxPackageBytes} bytes",
                                chunkStart
                            )
                        }
                        packageChunks++
                        if (packageChunks > limits.maxPackages) {
                            throw ArscParseException(
                                "package count exceeds ${limits.maxPackages}",
                                chunkStart
                            )
                        }
                        val packageId = parsePackage(
                            full = full,
                            packageStart = chunkStart,
                            rawResources = rawResources,
                            limits = limits
                        )
                        if (!seenPackages.add(packageId)) {
                            throw ArscParseException(
                                "duplicate package id 0x${hex2(packageId)}",
                                chunkStart
                            )
                        }
                    }
                }
            }

            if (chunkCount == 0) {
                throw ArscParseException("no resource chunks", 12)
            }
            val resolved = LinkedHashMap<Int, ArscResource>(rawResources.size)
            for ((id, raw) in rawResources) {
                val value = resolveRaw(
                    raw = raw,
                    pool = pool,
                    rawResources = rawResources,
                    depth = 0,
                    seen = HashSet(),
                    maxDepth = limits.maxReferenceDepth
                )
                resolved[id] = ArscResource(
                    id = id,
                    typeName = raw.typeName,
                    name = raw.name,
                    value = value
                )
            }
            return ArscDecoder(resolved)
        }

        private fun parsePackage(
            full: ByteArray,
            packageStart: Long,
            rawResources: MutableMap<Int, RawResource>,
            limits: ArscLimits
        ): Int {
            val headerSize = u16(full, 2)
            if (headerSize < 284 || headerSize > full.size) {
                throw ArscParseException("invalid package header size", packageStart)
            }
            val packageId = (u32(full, 8).toInt() and 0xFF)
            if (packageId == 0) {
                throw ArscParseException("package id 0 is invalid", packageStart + 8)
            }
            val typeStringsOffset = u32(full, 268)
            val keyStringsOffset = u32(full, 276)
            val typePool = parseStringPoolAt(
                full = full,
                base = typeStringsOffset,
                fileOffset = packageStart,
                limits = limits
            )
            val keyPool = parseStringPoolAt(
                full = full,
                base = keyStringsOffset,
                fileOffset = packageStart,
                limits = limits
            )
            val typeIdOffset = if (headerSize >= 288) u32(full, 284).toInt() else 0

            var offset = headerSize
            var typeChunks = 0
            var totalEntries = 0
            while (offset + 8 <= full.size) {
                val chunkType = u16(full, offset)
                val chunkSize = u32(full, offset + 4)
                if (chunkSize < 8 || offset.toLong() + chunkSize > full.size) {
                    throw ArscParseException(
                        "package chunk size $chunkSize is out of range",
                        packageStart + offset
                    )
                }
                if (chunkType == RES_TABLE_TYPE_TYPE) {
                    typeChunks++
                    if (typeChunks > limits.maxTypeChunks) {
                        throw ArscParseException(
                            "type chunk count exceeds ${limits.maxTypeChunks}",
                            packageStart + offset
                        )
                    }
                    totalEntries += parseTypeChunk(
                        full = full,
                        chunkOffset = offset,
                        chunkSize = chunkSize.toInt(),
                        packageStart = packageStart,
                        packageId = packageId,
                        typeIdOffset = typeIdOffset,
                        typePool = typePool,
                        keyPool = keyPool,
                        rawResources = rawResources,
                        remainingEntries = limits.maxEntries - totalEntries
                    )
                    if (totalEntries > limits.maxEntries) {
                        throw ArscParseException(
                            "resource entries exceed ${limits.maxEntries}",
                            packageStart + offset
                        )
                    }
                } else if (chunkType == RES_TABLE_TYPE_SPEC_TYPE) {
                    // A type spec only declares configuration flags; nothing to flatten here.
                }
                offset += chunkSize.toInt()
            }
            return packageId
        }

        private fun parseTypeChunk(
            full: ByteArray,
            chunkOffset: Int,
            chunkSize: Int,
            packageStart: Long,
            packageId: Int,
            typeIdOffset: Int,
            typePool: StringPool,
            keyPool: StringPool,
            rawResources: MutableMap<Int, RawResource>,
            remainingEntries: Int
        ): Int {
            if (chunkSize < 20) {
                throw ArscParseException(
                    "type chunk is too small",
                    packageStart + chunkOffset
                )
            }
            val headerSize = u16(full, chunkOffset + 2)
            if (headerSize < 20 || headerSize > chunkSize) {
                throw ArscParseException(
                    "invalid type chunk header size",
                    packageStart + chunkOffset
                )
            }
            val rawTypeId = u8(full, chunkOffset + 8)
            val typeId = rawTypeId + typeIdOffset
            if (typeId <= 0 || typeId > 255) {
                throw ArscParseException(
                    "invalid type id $typeId",
                    packageStart + chunkOffset + 8
                )
            }
            val entryCount = u32(full, chunkOffset + 12)
            if (entryCount > remainingEntries) {
                throw ArscParseException(
                    "type entry count $entryCount exceeds the entry cap",
                    packageStart + chunkOffset + 12
                )
            }
            val entriesStart = u32(full, chunkOffset + 16)
            val offsetsStart = chunkOffset.toLong() + headerSize
            val offsetsEnd = offsetsStart + entryCount * 4L
            if (offsetsEnd > chunkOffset.toLong() + chunkSize) {
                throw ArscParseException(
                    "type entry offset table is out of range",
                    packageStart + chunkOffset
                )
            }
            val typeName = typePool.get((rawTypeId - 1).toLong(), packageStart + chunkOffset)
            val chunkEnd = chunkOffset.toLong() + chunkSize
            for (index in 0 until entryCount.toInt()) {
                val entryOffset = u32(full, offsetsStart.toInt() + index * 4)
                if (entryOffset == NO_ENTRY) continue
                val entryAt = chunkOffset.toLong() + entriesStart + entryOffset
                if (entryAt + 8 > chunkEnd) {
                    throw ArscParseException(
                        "entry $index is out of range",
                        packageStart + entryAt
                    )
                }
                val entryAtInt = entryAt.toInt()
                val entrySize = u16(full, entryAtInt)
                val flags = u16(full, entryAtInt + 2)
                if (entrySize < 8) {
                    throw ArscParseException(
                        "entry $index header is too small",
                        packageStart + entryAt
                    )
                }
                if ((flags and FLAG_COMPLEX) != 0) {
                    continue
                }
                val keyIndex = u32(full, entryAtInt + 4)
                val valueAt = entryAt + entrySize
                if (valueAt + 8 > chunkEnd) {
                    throw ArscParseException(
                        "entry $index value is out of range",
                        packageStart + entryAt
                    )
                }
                val valueAtInt = valueAt.toInt()
                val valueSize = u16(full, valueAtInt)
                if (valueSize < 8) {
                    throw ArscParseException(
                        "entry $index value size is too small",
                        packageStart + valueAt
                    )
                }
                val dataType = u8(full, valueAtInt + 3)
                val data = u32(full, valueAtInt + 4)
                val keyName = keyPool.get(keyIndex, packageStart + entryAt + 4)
                val id = (packageId shl 24) or (typeId shl 16) or index
                if (!rawResources.containsKey(id)) {
                    rawResources[id] = RawResource(
                        id = id,
                        typeName = typeName,
                        name = keyName,
                        dataType = dataType,
                        data = data,
                        at = packageStart + entryAt
                    )
                }
            }
            return entryCount.toInt()
        }

        private fun parseStringPoolAt(
            full: ByteArray,
            base: Long,
            fileOffset: Long,
            limits: ArscLimits
        ): StringPool {
            if (base < 0 || base + 8 > full.size) {
                throw ArscParseException(
                    "string pool offset $base is out of range",
                    fileOffset + base
                )
            }
            val baseInt = base.toInt()
            val type = u16(full, baseInt)
            if (type != RES_STRING_POOL_TYPE) {
                throw ArscParseException(
                    "expected a string pool at $base",
                    fileOffset + base
                )
            }
            val size = u32(full, baseInt + 4)
            if (size < 28 || base + size > full.size) {
                throw ArscParseException(
                    "string pool size $size is out of range",
                    fileOffset + base
                )
            }
            val slice = full.copyOfRange(baseInt, baseInt + size.toInt())
            return parseStringPool(slice, 0, fileOffset + base, limits)
        }

        private fun parseStringPool(
            full: ByteArray,
            chunkStart: Long,
            fileStart: Long,
            limits: ArscLimits
        ): StringPool {
            if (full.size < 28) {
                throw ArscParseException("truncated string pool", fileStart + chunkStart)
            }
            val headerSize = u16(full, 2)
            if (headerSize < 28 || headerSize > full.size) {
                throw ArscParseException(
                    "invalid string pool header size",
                    fileStart + chunkStart
                )
            }
            val stringCount = u32(full, 8)
            val styleCount = u32(full, 12)
            val flags = u32(full, 16)
            val stringsStart = u32(full, 20)
            if (stringCount > limits.maxStringPoolEntries) {
                throw ArscParseException(
                    "string count $stringCount exceeds ${limits.maxStringPoolEntries}",
                    fileStart + chunkStart
                )
            }
            if (styleCount > limits.maxStringPoolEntries) {
                throw ArscParseException(
                    "style count $styleCount exceeds ${limits.maxStringPoolEntries}",
                    fileStart + chunkStart
                )
            }
            val offsetsEnd = headerSize.toLong() + stringCount * 4L
            if (offsetsEnd > full.size) {
                throw ArscParseException(
                    "string offset table is out of range",
                    fileStart + chunkStart
                )
            }
            if (stringCount > 0 &&
                (stringsStart < headerSize.toLong() || stringsStart > full.size)
            ) {
                throw ArscParseException(
                    "string data offset is out of range",
                    fileStart + chunkStart
                )
            }
            val utf8 = (flags.toInt() and UTF8_FLAG) != 0
            val strings = ArrayList<String>(stringCount.toInt())
            for (index in 0 until stringCount.toInt()) {
                val relative = u32(full, headerSize + index * 4)
                val at = stringsStart + relative
                if (at < 0 || at >= full.size) {
                    throw ArscParseException(
                        "string $index offset is out of range",
                        fileStart + chunkStart
                    )
                }
                strings.add(
                    decodeString(
                        full,
                        at.toInt(),
                        utf8,
                        fileStart + chunkStart,
                        limits
                    )
                )
            }
            return StringPool(strings)
        }

        private fun decodeString(
            full: ByteArray,
            start: Int,
            utf8: Boolean,
            fileStart: Long,
            limits: ArscLimits
        ): String {
            if (utf8) {
                var at = start
                val first = readUtf8Length(full, at, fileStart)
                at = first.second
                val second = readUtf8Length(full, at, fileStart)
                at = second.second
                if (first.first > limits.maxStringChars ||
                    second.first > limits.maxStringChars * 4L ||
                    at + second.first > full.size
                ) {
                    throw ArscParseException(
                        "UTF-8 string is out of range",
                        fileStart + start
                    )
                }
                return String(full, at, second.first.toInt(), StandardCharsets.UTF_8)
            }
            var at = start
            if (at + 2 > full.size) {
                throw ArscParseException("truncated UTF-16 length", fileStart + at)
            }
            var length = u16(full, at)
            at += 2
            if ((length and 0x8000) != 0) {
                if (at + 2 > full.size) {
                    throw ArscParseException("truncated UTF-16 length", fileStart + at)
                }
                length = ((length and 0x7fff) shl 16) or u16(full, at)
                at += 2
            }
            if (length > limits.maxStringChars || at.toLong() + length * 2L > full.size) {
                throw ArscParseException("UTF-16 string is out of range", fileStart + start)
            }
            return String(full, at, length * 2, StandardCharsets.UTF_16LE)
        }

        private fun readUtf8Length(
            full: ByteArray,
            at: Int,
            fileStart: Long
        ): Pair<Long, Int> {
            if (at + 1 > full.size) {
                throw ArscParseException("truncated UTF-8 length", fileStart + at)
            }
            val first = u8(full, at)
            if ((first and 0x80) == 0) {
                return Pair(first.toLong(), at + 1)
            }
            if (at + 2 > full.size) {
                throw ArscParseException("truncated UTF-8 length", fileStart + at)
            }
            val value = ((first and 0x7f) shl 8) or u8(full, at + 1)
            return Pair(value.toLong(), at + 2)
        }

        private fun resolveRaw(
            raw: RawResource,
            pool: StringPool?,
            rawResources: Map<Int, RawResource>,
            depth: Int,
            seen: MutableSet<Int>,
            maxDepth: Int
        ): String {
            if (!seen.add(raw.id)) {
                return String.format(Locale.US, "@0x%08x", raw.id)
            }
            if (depth >= maxDepth) {
                return String.format(Locale.US, "@0x%08x", raw.id)
            }
            val value = when (raw.dataType) {
                TYPE_NULL -> ""
                TYPE_STRING -> {
                    val strings = pool ?: throw ArscParseException(
                        "string value without a global string pool",
                        raw.at
                    )
                    strings.get(raw.data, raw.at)
                }

                TYPE_REFERENCE, TYPE_DYNAMIC_REFERENCE -> {
                    val target = raw.data.toInt()
                    val targetRaw = rawResources[target]
                    if (targetRaw == null) {
                        String.format(Locale.US, "@0x%08x", target)
                    } else {
                        resolveRaw(
                            targetRaw,
                            pool,
                            rawResources,
                            depth + 1,
                            seen,
                            maxDepth
                        )
                    }
                }

                TYPE_ATTRIBUTE, TYPE_DYNAMIC_ATTRIBUTE ->
                    String.format(Locale.US, "?0x%08x", raw.data.toInt())
                TYPE_FLOAT -> java.lang.Float.intBitsToFloat(raw.data.toInt()).toString()
                TYPE_DIMENSION -> formatComplex(raw.data, isFraction = false)
                TYPE_FRACTION -> formatComplex(raw.data, isFraction = true)
                TYPE_INT_DEC -> raw.data.toString()
                TYPE_INT_HEX -> String.format(Locale.US, "0x%08x", raw.data.toInt())
                TYPE_INT_BOOLEAN -> (raw.data != 0L).toString()
                TYPE_INT_COLOR_ARGB8 -> String.format(Locale.US, "#%08x", raw.data.toInt())
                TYPE_INT_COLOR_RGB8 -> String.format(
                    Locale.US,
                    "#%06x",
                    raw.data.toInt() and 0xFFFFFF
                )
                TYPE_INT_COLOR_ARGB4 -> String.format(
                    Locale.US,
                    "#%04x",
                    raw.data.toInt() and 0xFFFF
                )
                TYPE_INT_COLOR_RGB4 -> String.format(
                    Locale.US,
                    "#%03x",
                    raw.data.toInt() and 0xFFF
                )
                else -> String.format(Locale.US, "0x%08x", raw.data.toInt())
            }
            seen.remove(raw.id)
            return value
        }

        private fun formatComplex(data: Long, isFraction: Boolean): String {
            val complex = data.toInt()
            val mantissa = complex and 0xFFFFFF00.toInt()
            val radix = (complex shr 4) and 0x3
            val multiplier = when (radix) {
                0 -> 1.0f
                1 -> 1.0f / (1 shl 7)
                2 -> 1.0f / (1 shl 15)
                else -> 1.0f / (1 shl 23)
            }
            val value = mantissa * multiplier
            val unit = complex and 0xF
            if (isFraction) {
                return formatDecimal(value) + if (unit == 1) "%p" else "%"
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

        private fun checkedSize(header: ByteArray, chunkStart: Long, cap: Int): Long {
            val headerSize = u16(header, 2)
            val size = u32(header, 4)
            if (headerSize < 8) {
                throw ArscParseException(
                    "chunk header size $headerSize is too small",
                    chunkStart
                )
            }
            if (size < 8) {
                throw ArscParseException("chunk size $size is too small", chunkStart)
            }
            if (headerSize > size) {
                throw ArscParseException(
                    "chunk header size $headerSize exceeds chunk size $size",
                    chunkStart
                )
            }
            if (size > cap) {
                throw ArscParseException(
                    "chunk size $size exceeds $cap",
                    chunkStart
                )
            }
            return size
        }

        private fun u8(data: ByteArray, at: Int): Int {
            if (at < 0 || at >= data.size) {
                throw ArscParseException("read outside chunk", at.toLong())
            }
            return data[at].toInt() and 0xFF
        }

        private fun u16(data: ByteArray, at: Int): Int {
            if (at < 0 || at + 2 > data.size) {
                throw ArscParseException("read outside chunk", at.toLong())
            }
            return (data[at].toInt() and 0xFF) or
                ((data[at + 1].toInt() and 0xFF) shl 8)
        }

        private fun u32(data: ByteArray, at: Int): Long {
            if (at < 0 || at + 4 > data.size) {
                throw ArscParseException("read outside chunk", at.toLong())
            }
            return (data[at].toLong() and 0xFF) or
                ((data[at + 1].toLong() and 0xFF) shl 8) or
                ((data[at + 2].toLong() and 0xFF) shl 16) or
                ((data[at + 3].toLong() and 0xFF) shl 24)
        }

        private fun hex2(value: Int): String = String.format(Locale.US, "%02x", value)

        private data class RawResource(
            val id: Int,
            val typeName: String,
            val name: String,
            val dataType: Int,
            val data: Long,
            val at: Long
        )

        private class StringPool(private val strings: List<String>) {
            fun get(index: Long, at: Long): String {
                if (index < 0 || index >= strings.size) {
                    throw ArscParseException(
                        "string index $index out of range (${strings.size} entries)",
                        at
                    )
                }
                return strings[index.toInt()]
            }
        }

        private class TableReader(private val input: InputStream) {
            var position: Long = 0
                private set

            fun readUpTo(buffer: ByteArray): Int {
                var read = 0
                while (read < buffer.size) {
                    val count = try {
                        input.read(buffer, read, buffer.size - read)
                    } catch (error: IOException) {
                        throw ArscParseException(
                            "read failed: ${error.message ?: "I/O error"}",
                            position
                        )
                    }
                    if (count < 0) break
                    if (count == 0) continue
                    read += count
                    position += count
                }
                return read
            }

            fun readHeader(buffer: ByteArray): Boolean {
                val read = readUpTo(buffer)
                if (read == 0) return false
                if (read < buffer.size) {
                    throw ArscParseException("truncated chunk header", position - read)
                }
                return true
            }

            fun readFully(buffer: ByteArray, offset: Int, length: Int, at: Long) {
                var read = 0
                while (read < length) {
                    val count = try {
                        input.read(buffer, offset + read, length - read)
                    } catch (error: IOException) {
                        throw ArscParseException(
                            "read failed: ${error.message ?: "I/O error"}",
                            at + read
                        )
                    }
                    if (count < 0) {
                        throw ArscParseException(
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
                        throw ArscParseException(
                            "read failed: ${error.message ?: "I/O error"}",
                            at + length - remaining
                        )
                    }
                    if (count < 0) {
                        throw ArscParseException("truncated chunk", at)
                    }
                    if (count == 0) continue
                    remaining -= count
                    position += count
                }
            }
        }
    }
}
