package com.ecrew.toolkit.acquisition

import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Writes an AndroidQF-compatible directory and ZIP. Artifact paths are relative and
 * traversal-free; sizes and file counts are bounded. `hashes.csv` is calculated over every
 * artifact written before it and never includes itself.
 */
class AndroidQfWriter(
    private val directory: File,
    private val cacheDirectory: File
) {
    private val artifacts = LinkedHashMap<String, File>()
    private var totalBytes = 0L

    init {
        if (!directory.isDirectory && !directory.mkdirs()) {
            throw AcquisitionException("cannot create the acquisition directory")
        }
    }

    fun add(relativePath: String, bytes: ByteArray): String {
        val safe = safePath(relativePath)
        if (artifacts.size >= MAX_FILES) throw AcquisitionException("artifact count cap reached")
        if (bytes.size > MAX_ARTIFACT_BYTES) {
            throw AcquisitionException("artifact exceeds the per-file cap: $safe")
        }
        totalBytes += bytes.size
        if (totalBytes > MAX_TOTAL_BYTES) {
            throw AcquisitionException("artifact byte cap reached")
        }
        val target = File(directory, safe)
        val parent = target.parentFile
        if (parent != null && !parent.isDirectory && !parent.mkdirs()) {
            throw AcquisitionException("cannot create artifact directory")
        }
        FileOutputStream(target).use { it.write(bytes) }
        artifacts[safe] = target
        return safe
    }

    fun addText(relativePath: String, text: String): String =
        add(relativePath, text.toByteArray(Charsets.UTF_8))

    fun finish(
        sessionId: String,
        startedAt: Long,
        finishedAt: Long,
        modules: List<AcquisitionModuleResult>
    ): AcquisitionSession {
        val acquisitionJson = buildAcquisitionJson(sessionId, startedAt, finishedAt, modules)
        addText(ACQUISITION_JSON, acquisitionJson)
        val hashRows = ArrayList<Triple<String, String, Long>>()
        for ((path, file) in artifacts.toSortedMap()) {
            hashRows.add(Triple(path, sha256(file), file.length()))
        }
        val hashes = StringBuilder()
        hashes.append("path,sha256,bytes\n")
        hashRows.forEach { (path, digest, size) ->
            hashes.append(csv(path)).append(',').append(digest).append(',').append(size).append('\n')
        }
        val hashesFile = File(directory, HASHES_CSV)
        hashesFile.writeText(hashes.toString(), Charsets.UTF_8)
        val archive = File(cacheDirectory, "androidqf-$sessionId.zip")
        val entryNames = artifacts.keys.toSortedSet()
        ZipOutputStream(FileOutputStream(archive)).use { zip ->
            for (name in entryNames) {
                val file = artifacts.getValue(name)
                val entry = ZipEntry(name).apply {
                    time = 0L
                    size = file.length()
                }
                zip.putNextEntry(entry)
                file.inputStream().use { it.copyTo(zip, COPY_BUFFER) }
                zip.closeEntry()
            }
            val hashesEntry = ZipEntry(HASHES_CSV).apply { time = 0L }
            zip.putNextEntry(hashesEntry)
            zip.write(hashesFile.readBytes())
            zip.closeEntry()
        }
        val artifactList = hashRows.map { (path, digest, size) ->
            AcquisitionArtifact(path, size, digest)
        }
        return AcquisitionSession(
            id = sessionId,
            startedAt = startedAt,
            finishedAt = finishedAt,
            directory = directory,
            archive = archive,
            modules = modules,
            artifacts = artifactList,
            ioc = null
        )
    }

    private fun buildAcquisitionJson(
        sessionId: String,
        startedAt: Long,
        finishedAt: Long,
        modules: List<AcquisitionModuleResult>
    ): String = buildString {
        append("{\n")
        append("  \"schema\": \"ecrew-androidqf-1\",\n")
        append("  \"session_id\": ").append(quote(sessionId)).append(",\n")
        append("  \"started_at\": ").append(startedAt).append(",\n")
        append("  \"finished_at\": ").append(finishedAt).append(",\n")
        append("  \"platform\": \"android\",\n")
        append("  \"modules\": [\n")
        modules.forEachIndexed { index, module ->
            append("    {\n")
            append("      \"id\": ").append(quote(module.id)).append(",\n")
            append("      \"label\": ").append(quote(module.label)).append(",\n")
            append("      \"status\": ").append(quote(module.status.name.lowercase())).append(",\n")
            append("      \"started_at\": ").append(module.startedAt).append(",\n")
            append("      \"finished_at\": ").append(module.finishedAt).append(",\n")
            append("      \"artifacts\": [")
            module.artifacts.forEachIndexed { artifactIndex, path ->
                if (artifactIndex > 0) append(", ")
                append(quote(path))
            }
            append("],\n")
            append("      \"error\": ")
            if (module.error == null) append("null") else append(quote(module.error))
            append("\n    }")
            if (index < modules.lastIndex) append(',')
            append('\n')
        }
        append("  ],\n")
        append("  \"artifacts\": [")
        val names = artifacts.keys.toSortedSet()
        names.forEachIndexed { index, name ->
            if (index > 0) append(", ")
            append(quote(name))
        }
        append("],\n")
        append("  \"notes\": \"E-Crew public-tier extension; AndroidQF consumers ignore unknown keys\"\n")
        append("}\n")
    }

    private fun safePath(path: String): String {
        val normalized = path.replace('\\', '/')
        if (normalized.isBlank() || normalized.startsWith('/')) {
            throw AcquisitionException("artifact path must be relative")
        }
        if (normalized.split('/').any { it == ".." || it.isEmpty() }) {
            throw AcquisitionException("artifact path contains an unsafe segment")
        }
        return normalized
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(8 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun csv(value: String): String {
        if (value.indexOf(',') < 0 && value.indexOf('"') < 0) return value
        return "\"" + value.replace("\"", "\"\"") + "\""
    }

    private fun quote(value: String): String = buildString {
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

    companion object {
        const val ACQUISITION_JSON = "acquisition.json"
        const val HASHES_CSV = "hashes.csv"
        private const val MAX_FILES = 500
        private const val MAX_ARTIFACT_BYTES = 64L * 1024 * 1024
        private const val MAX_TOTAL_BYTES = 320L * 1024 * 1024
        private const val COPY_BUFFER = 8 * 1024
    }
}
