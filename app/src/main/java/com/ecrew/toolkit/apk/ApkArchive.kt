package com.ecrew.toolkit.apk

import java.io.Closeable
import java.io.File
import java.io.FileInputStream
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipFile

/** A malformed, oversized or unreadable APK archive. */
class ApkArchiveException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** Size and count caps applied to an APK archive. */
data class ApkLimits(
    val maxEntries: Int = 200_000,
    val maxEntryBytes: Int = 64 * 1024 * 1024,
    val maxTotalUncompressedBytes: Long = 1024L * 1024 * 1024
)

/** Metadata for one file entry in an APK. */
data class ApkEntryInfo(
    val name: String,
    val compressedSize: Long,
    val uncompressedSize: Long,
    val crc32: Long,
    val method: Int
)

/**
 * Read-only APK/ZIP access with streamed hashing and hard caps.
 *
 * The archive is opened with [ZipFile] (random access, no whole-file copy). Callers own the
 * returned streams. Entry reads are capped while streaming, so a lying ZIP header cannot make
 * a parser allocate or read without bound.
 */
class ApkArchive private constructor(
    private val file: File,
    private val zip: ZipFile,
    private val limits: ApkLimits,
    val entries: List<ApkEntryInfo>
) : Closeable {
    val path: String
        get() = file.absolutePath

    val sizeBytes: Long
        get() = file.length()

    fun contains(name: String): Boolean = zip.getEntry(name)?.isDirectory == false

    fun openEntry(name: String, maxBytes: Int = limits.maxEntryBytes): InputStream {
        if (maxBytes <= 0) {
            throw ApkArchiveException("maxBytes must be positive")
        }
        val entry = zip.getEntry(name)
            ?: throw ApkArchiveException("entry $name is missing")
        if (entry.isDirectory) {
            throw ApkArchiveException("entry $name is a directory")
        }
        return try {
            BoundedInputStream(zip.getInputStream(entry), maxBytes, name)
        } catch (error: IOException) {
            throw ApkArchiveException("cannot open entry $name: ${error.message}", error)
        }
    }

    fun readEntry(name: String, maxBytes: Int = limits.maxEntryBytes): ByteArray {
        val stream = openEntry(name, maxBytes)
        return stream.use { input ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = try {
                    input.read(buffer)
                } catch (error: IOException) {
                    throw ApkArchiveException("cannot read entry $name: ${error.message}", error)
                }
                if (count < 0) break
                if (count == 0) continue
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
    }

    fun hashEntry(name: String, algorithm: String = "SHA-256"): String {
        val digest = MessageDigest.getInstance(algorithm)
        openEntry(name).use { input ->
            val buffer = ByteArray(8192)
            while (true) {
                val count = try {
                    input.read(buffer)
                } catch (error: IOException) {
                    throw ApkArchiveException("cannot read entry $name: ${error.message}", error)
                }
                if (count < 0) break
                if (count == 0) continue
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().toHex()
    }

    override fun close() {
        try {
            zip.close()
        } catch (_: IOException) {
        }
    }

    private class BoundedInputStream(
        input: InputStream,
        private val maxBytes: Int,
        private val entryName: String
    ) : FilterInputStream(input) {
        private var readSoFar = 0L

        override fun read(): Int {
            val value = super.read()
            if (value >= 0) {
                readSoFar++
                checkCap()
            }
            return value
        }

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            val count = super.read(buffer, offset, length)
            if (count > 0) {
                readSoFar += count
                checkCap()
            }
            return count
        }

        private fun checkCap() {
            if (readSoFar > maxBytes) {
                throw ApkArchiveException(
                    "entry $entryName exceeds the $maxBytes byte read cap"
                )
            }
        }
    }

    companion object {
        fun open(file: File, limits: ApkLimits = ApkLimits()): ApkArchive {
            require(limits.maxEntries > 0) { "maxEntries must be positive" }
            require(limits.maxEntryBytes > 0) { "maxEntryBytes must be positive" }
            require(limits.maxTotalUncompressedBytes > 0) {
                "maxTotalUncompressedBytes must be positive"
            }
            if (!file.isFile) {
                throw ApkArchiveException("not a file: ${file.absolutePath}")
            }
            val zip = try {
                ZipFile(file)
            } catch (error: IOException) {
                throw ApkArchiveException(
                    "not a readable ZIP/APK: ${error.message}",
                    error
                )
            }
            try {
                val entries = ArrayList<ApkEntryInfo>()
                val names = HashSet<String>()
                var totalUncompressed = 0L
                val enumeration = zip.entries()
                while (enumeration.hasMoreElements()) {
                    val entry = enumeration.nextElement()
                    if (entries.size >= limits.maxEntries) {
                        throw ApkArchiveException(
                            "archive exceeds ${limits.maxEntries} entries"
                        )
                    }
                    if (entry.isDirectory) continue
                    if (entry.name.isEmpty()) {
                        throw ApkArchiveException("archive contains an empty entry name")
                    }
                    if (!names.add(entry.name)) {
                        throw ApkArchiveException("duplicate archive entry: ${entry.name}")
                    }
                    if (entry.size >= 0) {
                        // Entry metadata is admitted even when a single asset is larger than
                        // the read cap. Reads are capped by BoundedInputStream, so an oversized
                        // asset can never be loaded; rejecting the whole archive here would make
                        // common APKs with large model/media assets impossible to analyze.
                        totalUncompressed += entry.size
                        if (totalUncompressed > limits.maxTotalUncompressedBytes) {
                            throw ApkArchiveException(
                                "archive exceeds the total uncompressed size cap"
                            )
                        }
                    }
                    entries.add(
                        ApkEntryInfo(
                            name = entry.name,
                            compressedSize = entry.compressedSize,
                            uncompressedSize = entry.size,
                            crc32 = entry.crc,
                            method = entry.method
                        )
                    )
                }
                entries.sortBy { it.name }
                return ApkArchive(file, zip, limits, entries)
            } catch (error: Throwable) {
                try {
                    zip.close()
                } catch (_: IOException) {
                }
                if (error is ApkArchiveException) throw error
                throw ApkArchiveException("cannot enumerate archive: ${error.message}", error)
            }
        }

        fun hashFile(file: File, algorithm: String = "SHA-256"): String {
            val digest = MessageDigest.getInstance(algorithm)
            FileInputStream(file).use { input ->
                val buffer = ByteArray(8192)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (count == 0) continue
                    digest.update(buffer, 0, count)
                }
            }
            return digest.digest().toHex()
        }

        private fun ByteArray.toHex(): String = joinToString("") {
            String.format("%02x", it.toInt() and 0xFF)
        }
    }
}
