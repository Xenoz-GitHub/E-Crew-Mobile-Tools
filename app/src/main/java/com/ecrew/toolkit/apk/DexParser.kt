package com.ecrew.toolkit.apk

import java.io.IOException
import java.io.InputStream
import java.util.zip.Adler32

/** Hard limits applied while decoding a DEX file. */
data class DexLimits(
    val maxDexBytes: Int = 64 * 1024 * 1024,
    val maxMapItems: Int = 4096,
    val maxStrings: Int = 5_000_000,
    val maxStringChars: Int = 1_048_576,
    val maxClasses: Int = 500_000,
    val maxMethodRefs: Int = 2_000_000,
    val maxFieldRefs: Int = 2_000_000,
    val maxMethodsPerClass: Int = 200_000,
    val maxInterfaces: Int = 65_535
)

/** A malformed DEX file. */
class DexParseException(message: String, val offset: Long) :
    Exception("$message (byte $offset)")

data class DexMethod(
    val name: String,
    val accessFlags: Int,
    val codeOffset: Long
)

data class DexClass(
    val name: String,
    val descriptor: String,
    val accessFlags: Int,
    val superName: String?,
    val interfaces: List<String>,
    val sourceFile: String?,
    val methods: List<DexMethod>,
    val fieldCount: Int
)

/**
 * Reads one classes*.dex file: validates the header checksum/size, walks the map list, decodes
 * MUTF-8 strings, and enumerates classes, superclasses, interfaces, methods and fields.
 *
 * DEX offsets are random access, so the input is buffered up to [DexLimits.maxDexBytes]. This
 * is the only parser that holds the complete input; the cap keeps it bounded. All references
 * are checked against the file size before use.
 */
class DexParser private constructor(
    val strings: List<String>,
    val classes: List<DexClass>,
    val methodReferenceCount: Int,
    val fieldReferenceCount: Int
) {
    fun findClass(name: String): DexClass? = classes.firstOrNull { it.name == name }

    companion object {
        private const val HEADER_SIZE = 0x70
        private const val ENDIAN_TAG = 0x12345678L
        private const val NO_INDEX = 0xFFFFFFFFL

        fun parse(
            input: InputStream,
            limits: DexLimits = DexLimits(),
            label: String = "classes.dex"
        ): DexParser {
            require(limits.maxDexBytes > 0) { "maxDexBytes must be positive" }
            require(limits.maxMapItems > 0) { "maxMapItems must be positive" }
            require(limits.maxStrings > 0) { "maxStrings must be positive" }
            require(limits.maxStringChars > 0) { "maxStringChars must be positive" }
            require(limits.maxClasses > 0) { "maxClasses must be positive" }
            require(limits.maxMethodRefs > 0) { "maxMethodRefs must be positive" }
            require(limits.maxFieldRefs > 0) { "maxFieldRefs must be positive" }
            require(limits.maxMethodsPerClass > 0) { "maxMethodsPerClass must be positive" }
            require(limits.maxInterfaces > 0) { "maxInterfaces must be positive" }

            val bytes = readCapped(input, limits.maxDexBytes, label)
            if (bytes.size < HEADER_SIZE) {
                throw DexParseException("DEX is shorter than its header", 0)
            }
            validateMagic(bytes)
            val fileSize = u32(bytes, 32)
            if (fileSize != bytes.size.toLong()) {
                throw DexParseException(
                    "header file_size $fileSize does not match ${bytes.size} bytes",
                    32
                )
            }
            if (u32(bytes, 36) != HEADER_SIZE.toLong()) {
                throw DexParseException("unsupported header size", 36)
            }
            if (u32(bytes, 40) != ENDIAN_TAG) {
                throw DexParseException("unsupported endian tag", 40)
            }
            val checksum = u32(bytes, 8)
            val adler = Adler32()
            adler.update(bytes, 12, bytes.size - 12)
            if (expectedChecksum(adler.value) != checksum) {
                throw DexParseException("checksum mismatch", 8)
            }

            val mapOffset = checkedOffset(bytes, 52, "map")
            val mapCount = u32(bytes, mapOffset.toInt())
            if (mapCount > limits.maxMapItems) {
                throw DexParseException(
                    "map count $mapCount exceeds ${limits.maxMapItems}",
                    mapOffset
                )
            }
            val mapItems = mapOffset + 4
            if (mapItems + mapCount * 12L > bytes.size) {
                throw DexParseException("map list is out of range", mapItems)
            }
            for (index in 0 until mapCount.toInt()) {
                val item = mapItems + index * 12L
                val type = u16(bytes, item.toInt())
                val size = u32(bytes, (item + 4).toInt())
                val offset = u32(bytes, (item + 8).toInt())
                if (size > 0 && offset >= bytes.size.toLong()) {
                    throw DexParseException(
                        "map item $index (type 0x${Integer.toHexString(type)}) " +
                            "offset is out of range",
                        item
                    )
                }
            }

            val stringCount = checkedCount(bytes, 56, limits.maxStrings, "string")
            val stringIds = if (stringCount == 0L) {
                0L
            } else {
                checkedOffset(bytes, 60, "string ids")
            }
            if (stringCount > 0 && stringIds + stringCount * 4L > bytes.size) {
                throw DexParseException("string ids are out of range", stringIds)
            }
            val strings = ArrayList<String>(stringCount.toInt())
            for (index in 0 until stringCount.toInt()) {
                val dataOffset = u32(bytes, (stringIds + index * 4L).toInt())
                if (dataOffset < HEADER_SIZE || dataOffset >= bytes.size.toLong()) {
                    throw DexParseException(
                        "string data offset is out of range",
                        stringIds + index * 4L
                    )
                }
                val decoded = decodeMutf8(bytes, dataOffset.toInt(), limits)
                strings.add(decoded.first)
            }

            val typeCount = checkedCount(bytes, 64, limits.maxStrings, "type")
            val typeIds = if (typeCount == 0L) {
                0L
            } else {
                checkedOffset(bytes, 68, "type ids")
            }
            if (typeCount > 0 && typeIds + typeCount * 4L > bytes.size) {
                throw DexParseException("type ids are out of range", typeIds)
            }
            val types = ArrayList<String>(typeCount.toInt())
            for (index in 0 until typeCount.toInt()) {
                val stringIndex = u32(bytes, (typeIds + index * 4L).toInt())
                types.add(stringAt(strings, stringIndex, typeIds + index * 4L))
            }

            val fieldCount = checkedCount(bytes, 80, limits.maxFieldRefs, "field ref")
            val fieldIds = if (fieldCount == 0L) {
                0L
            } else {
                checkedOffset(bytes, 84, "field ids")
            }
            if (fieldCount > 0 && fieldIds + fieldCount * 8L > bytes.size) {
                throw DexParseException("field ids are out of range", fieldIds)
            }
            val methodCount = checkedCount(bytes, 88, limits.maxMethodRefs, "method ref")
            val methodIds = if (methodCount == 0L) {
                0L
            } else {
                checkedOffset(bytes, 92, "method ids")
            }
            if (methodCount > 0 && methodIds + methodCount * 8L > bytes.size) {
                throw DexParseException("method ids are out of range", methodIds)
            }

            val classCount = checkedCount(bytes, 96, limits.maxClasses, "class")
            val classDefs = if (classCount == 0L) {
                0L
            } else {
                checkedOffset(bytes, 100, "class defs")
            }
            if (classCount > 0 && classDefs + classCount * 32L > bytes.size) {
                throw DexParseException("class definitions are out of range", classDefs)
            }

            val classes = ArrayList<DexClass>(classCount.toInt())
            for (index in 0 until classCount.toInt()) {
                val base = classDefs + index * 32L
                val classIdx = u32(bytes, base.toInt())
                val accessFlags = u32(bytes, (base + 4).toInt()).toInt()
                val superIdx = u32(bytes, (base + 8).toInt())
                val interfacesOff = u32(bytes, (base + 12).toInt())
                val sourceFileIdx = u32(bytes, (base + 16).toInt())
                val classDataOff = u32(bytes, (base + 24).toInt())
                val descriptor = typeAt(types, classIdx, base)
                val superName = if (superIdx == NO_INDEX) {
                    null
                } else {
                    descriptorToName(typeAt(types, superIdx, base + 8))
                }
                val interfaces = parseInterfaces(
                    bytes,
                    interfacesOff,
                    types,
                    limits,
                    base + 12
                )
                val sourceFile = if (sourceFileIdx == NO_INDEX) {
                    null
                } else {
                    stringAt(strings, sourceFileIdx, base + 16)
                }
                val data = parseClassData(
                    bytes = bytes,
                    classDataOff = classDataOff,
                    methodIds = methodIds,
                    methodCount = methodCount,
                    strings = strings,
                    limits = limits,
                    at = base + 24
                )
                classes.add(
                    DexClass(
                        name = descriptorToName(descriptor),
                        descriptor = descriptor,
                        accessFlags = accessFlags,
                        superName = superName,
                        interfaces = interfaces,
                        sourceFile = sourceFile,
                        methods = data.methods,
                        fieldCount = data.fieldCount
                    )
                )
            }
            return DexParser(
                strings = strings,
                classes = classes,
                methodReferenceCount = methodCount.toInt(),
                fieldReferenceCount = fieldCount.toInt()
            )
        }

        private fun validateMagic(bytes: ByteArray) {
            if (bytes[0] != 'd'.code.toByte() ||
                bytes[1] != 'e'.code.toByte() ||
                bytes[2] != 'x'.code.toByte() ||
                bytes[3] != '\n'.code.toByte() ||
                bytes[7] != 0.toByte()
            ) {
                throw DexParseException("not a DEX file", 0)
            }
            if (bytes[4] != '0'.code.toByte() ||
                bytes[5] != '3'.code.toByte() ||
                bytes[6] < '5'.code.toByte() ||
                bytes[6] > '9'.code.toByte()
            ) {
                throw DexParseException("unsupported DEX version", 4)
            }
        }

        private fun expectedChecksum(adlerValue: Long): Long = adlerValue and 0xFFFFFFFFL

        private fun parseInterfaces(
            bytes: ByteArray,
            offset: Long,
            types: List<String>,
            limits: DexLimits,
            at: Long
        ): List<String> {
            if (offset == 0L) return emptyList()
            if (offset + 4 > bytes.size) {
                throw DexParseException("interface list is out of range", at)
            }
            val count = u32(bytes, offset.toInt())
            if (count > limits.maxInterfaces) {
                throw DexParseException(
                    "interface count $count exceeds ${limits.maxInterfaces}",
                    at
                )
            }
            if (offset + 4 + count * 2L > bytes.size) {
                throw DexParseException("interface list is out of range", at)
            }
            val names = ArrayList<String>(count.toInt())
            for (index in 0 until count.toInt()) {
                val typeIndex = u16(bytes, (offset + 4 + index * 2L).toInt()).toLong()
                names.add(descriptorToName(typeAt(types, typeIndex, at)))
            }
            return names
        }

        private fun parseClassData(
            bytes: ByteArray,
            classDataOff: Long,
            methodIds: Long,
            methodCount: Long,
            strings: List<String>,
            limits: DexLimits,
            at: Long
        ): ClassData {
            if (classDataOff == 0L) return ClassData(emptyList(), 0)
            if (classDataOff >= bytes.size.toLong()) {
                throw DexParseException("class data offset is out of range", at)
            }
            var offset = classDataOff.toInt()
            val staticFields = readUleb128(bytes, offset, at + 40)
            offset = staticFields.second
            val instanceFields = readUleb128(bytes, offset, at + 41)
            offset = instanceFields.second
            val directMethods = readUleb128(bytes, offset, at + 42)
            offset = directMethods.second
            val virtualMethods = readUleb128(bytes, offset, at + 43)
            offset = virtualMethods.second
            val fieldTotal = staticFields.first.toLong() + instanceFields.first.toLong()
            if (fieldTotal > limits.maxMethodsPerClass) {
                throw DexParseException(
                    "field count $fieldTotal exceeds ${limits.maxMethodsPerClass}",
                    at
                )
            }
            var fieldCounter = 0L
            while (fieldCounter < staticFields.first) {
                val diff = readUleb128(bytes, offset, at)
                offset = diff.second
                val flags = readUleb128(bytes, offset, at)
                offset = flags.second
                fieldCounter++
            }
            fieldCounter = 0L
            while (fieldCounter < instanceFields.first) {
                val diff = readUleb128(bytes, offset, at)
                offset = diff.second
                val flags = readUleb128(bytes, offset, at)
                offset = flags.second
                fieldCounter++
            }
            val methodTotal = directMethods.first.toLong() + virtualMethods.first.toLong()
            if (methodTotal > limits.maxMethodsPerClass) {
                throw DexParseException(
                    "method count $methodTotal exceeds ${limits.maxMethodsPerClass}",
                    at
                )
            }
            val methods = ArrayList<DexMethod>(methodTotal.toInt())
            var methodIndex = 0L
            var methodCounter = 0L
            while (methodCounter < directMethods.first) {
                val diff = readUleb128(bytes, offset, at)
                methodIndex += diff.first.toLong()
                offset = diff.second
                val flags = readUleb128(bytes, offset, at)
                offset = flags.second
                val codeOffset = readUleb128(bytes, offset, at)
                offset = codeOffset.second
                if (methodIndex >= methodCount) {
                    throw DexParseException(
                        "method index $methodIndex is out of range",
                        at
                    )
                }
                val methodId = methodIds + methodIndex * 8L
                if (methodId + 8 > bytes.size) {
                    throw DexParseException("method id is out of range", methodId)
                }
                val nameIndex = u32(bytes, (methodId + 4).toInt())
                val name = stringAt(strings, nameIndex, methodId + 4)
                methods.add(
                    DexMethod(
                        name = name,
                        accessFlags = flags.first,
                        codeOffset = codeOffset.first.toLong()
                    )
                )
                methodCounter++
            }
            methodIndex = 0L
            methodCounter = 0L
            while (methodCounter < virtualMethods.first) {
                val diff = readUleb128(bytes, offset, at)
                methodIndex += diff.first.toLong()
                offset = diff.second
                val flags = readUleb128(bytes, offset, at)
                offset = flags.second
                val codeOffset = readUleb128(bytes, offset, at)
                offset = codeOffset.second
                if (methodIndex >= methodCount) {
                    throw DexParseException(
                        "method index $methodIndex is out of range",
                        at
                    )
                }
                val methodId = methodIds + methodIndex * 8L
                if (methodId + 8 > bytes.size) {
                    throw DexParseException("method id is out of range", methodId)
                }
                val nameIndex = u32(bytes, (methodId + 4).toInt())
                val name = stringAt(strings, nameIndex, methodId + 4)
                methods.add(
                    DexMethod(
                        name = name,
                        accessFlags = flags.first,
                        codeOffset = codeOffset.first.toLong()
                    )
                )
                methodCounter++
            }
            return ClassData(methods, fieldTotal.toInt())
        }

        private fun readUleb128(bytes: ByteArray, start: Int, at: Long): Pair<Int, Int> {
            var result = 0
            var shift = 0
            var offset = start
            while (true) {
                if (offset >= bytes.size) {
                    throw DexParseException("truncated uleb128", at)
                }
                val value = bytes[offset].toInt() and 0xFF
                offset++
                result = result or ((value and 0x7F) shl shift)
                if ((value and 0x80) == 0) break
                shift += 7
                if (shift >= 35) {
                    throw DexParseException("uleb128 is too long", at)
                }
            }
            return Pair(result, offset)
        }

        private fun decodeMutf8(
            bytes: ByteArray,
            start: Int,
            limits: DexLimits
        ): Pair<String, Int> {
            val length = readUleb128(bytes, start, start.toLong())
            var offset = length.second
            if (length.first > limits.maxStringChars) {
                throw DexParseException(
                    "MUTF-8 string length ${length.first} exceeds ${limits.maxStringChars}",
                    start.toLong()
                )
            }
            val out = StringBuilder(minOf(length.first, 1024))
            var units = 0
            while (true) {
                if (offset >= bytes.size) {
                    throw DexParseException("unterminated MUTF-8 string", start.toLong())
                }
                val first = bytes[offset].toInt() and 0xFF
                if (first == 0) {
                    offset++
                    break
                }
                val code: Int
                if (first and 0x80 == 0) {
                    code = first
                    offset++
                } else if (first and 0xE0 == 0xC0) {
                    if (offset + 1 >= bytes.size) {
                        throw DexParseException("truncated MUTF-8 string", start.toLong())
                    }
                    val second = bytes[offset + 1].toInt() and 0xFF
                    if (second and 0xC0 != 0x80) {
                        throw DexParseException("bad MUTF-8 continuation", offset.toLong())
                    }
                    code = ((first and 0x1F) shl 6) or (second and 0x3F)
                    offset += 2
                } else if (first and 0xF0 == 0xE0) {
                    if (offset + 2 >= bytes.size) {
                        throw DexParseException("truncated MUTF-8 string", start.toLong())
                    }
                    val second = bytes[offset + 1].toInt() and 0xFF
                    val third = bytes[offset + 2].toInt() and 0xFF
                    if (second and 0xC0 != 0x80 || third and 0xC0 != 0x80) {
                        throw DexParseException("bad MUTF-8 continuation", offset.toLong())
                    }
                    code = ((first and 0x0F) shl 12) or
                        ((second and 0x3F) shl 6) or
                        (third and 0x3F)
                    offset += 3
                } else {
                    throw DexParseException("unsupported MUTF-8 byte", offset.toLong())
                }
                out.append(code.toChar())
                units++
                if (units > limits.maxStringChars) {
                    throw DexParseException(
                        "MUTF-8 string exceeds ${limits.maxStringChars} units",
                        start.toLong()
                    )
                }
            }
            if (units != length.first) {
                throw DexParseException(
                    "MUTF-8 length ${length.first} does not match $units units",
                    start.toLong()
                )
            }
            return Pair(out.toString(), offset)
        }

        private fun descriptorToName(descriptor: String): String {
            if (descriptor.length >= 2 && descriptor.startsWith("L") &&
                descriptor.endsWith(";")
            ) {
                return descriptor.substring(1, descriptor.length - 1).replace('/', '.')
            }
            return descriptor
        }

        private fun stringAt(strings: List<String>, index: Long, at: Long): String {
            if (index < 0 || index >= strings.size.toLong()) {
                throw DexParseException("string index $index is out of range", at)
            }
            return strings[index.toInt()]
        }

        private fun typeAt(types: List<String>, index: Long, at: Long): String {
            if (index < 0 || index >= types.size.toLong()) {
                throw DexParseException("type index $index is out of range", at)
            }
            return types[index.toInt()]
        }

        private fun checkedCount(
            bytes: ByteArray,
            offset: Int,
            cap: Int,
            label: String
        ): Long {
            val count = u32(bytes, offset)
            if (count > cap) {
                throw DexParseException("$label count $count exceeds $cap", offset.toLong())
            }
            return count
        }

        private fun checkedOffset(bytes: ByteArray, offset: Int, label: String): Long {
            val value = u32(bytes, offset)
            if (value < HEADER_SIZE || value >= bytes.size.toLong()) {
                throw DexParseException("$label offset $value is out of range", offset.toLong())
            }
            return value
        }

        private fun readCapped(input: InputStream, cap: Int, label: String): ByteArray {
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            var total = 0
            while (true) {
                val count = try {
                    input.read(buffer)
                } catch (error: IOException) {
                    throw DexParseException(
                        "cannot read $label: ${error.message ?: "I/O error"}",
                        0
                    )
                }
                if (count < 0) break
                if (count == 0) continue
                total += count
                if (total > cap) {
                    throw DexParseException("$label exceeds the $cap byte cap", 0)
                }
                output.write(buffer, 0, count)
            }
            return output.toByteArray()
        }

        private fun u16(data: ByteArray, at: Int): Int {
            if (at < 0 || at + 2 > data.size) {
                throw DexParseException("read outside DEX", at.toLong())
            }
            return (data[at].toInt() and 0xFF) or
                ((data[at + 1].toInt() and 0xFF) shl 8)
        }

        private fun u32(data: ByteArray, at: Int): Long {
            if (at < 0 || at + 4 > data.size) {
                throw DexParseException("read outside DEX", at.toLong())
            }
            return (data[at].toLong() and 0xFF) or
                ((data[at + 1].toLong() and 0xFF) shl 8) or
                ((data[at + 2].toLong() and 0xFF) shl 16) or
                ((data[at + 3].toLong() and 0xFF) shl 24)
        }

        private data class ClassData(val methods: List<DexMethod>, val fieldCount: Int)
    }
}
