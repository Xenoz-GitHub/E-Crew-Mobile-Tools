package com.ecrew.toolkit.apk

import jadx.api.JadxArgs
import jadx.api.JadxDecompiler
import jadx.api.JavaClass
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.io.File
import kotlin.coroutines.coroutineContext

class JadxException(message: String, cause: Throwable? = null) : Exception(message, cause)

data class JadxClassInfo(
    val fullName: String,
    val packageName: String,
    val name: String,
    val inner: Boolean
)

/**
 * One in-process jadx 1.4.7 load. The session owns the decompiler and must be closed by the
 * caller. jadx loads classes lazily for source; [source] synchronizes access because the
 * decompiler is not designed for concurrent class requests.
 */
class JadxSession internal constructor(
    private val decompiler: JadxDecompiler,
    private val javaClasses: List<JavaClass>
) : Closeable {
    val classes: List<JadxClassInfo> = javaClasses
        .map { javaClass ->
            JadxClassInfo(
                fullName = javaClass.fullName,
                packageName = javaClass.`package` ?: "",
                name = javaClass.name,
                inner = javaClass.isInner
            )
        }
        .sortedWith(compareBy({ it.packageName }, { it.fullName }))

    val errorCount: Int = decompiler.errorsCount
    val warningCount: Int = decompiler.warnsCount
    val issues: List<String> = buildList {
        if (errorCount > 0) add("jadx reported $errorCount decompilation error(s)")
        if (warningCount > 0) add("jadx reported $warningCount warning(s)")
    }

    private val byName: Map<String, JavaClass> = javaClasses.associateBy { it.fullName }

    @Synchronized
    fun source(fullName: String): String {
        val javaClass = byName[fullName]
            ?: throw JadxException("unknown class: $fullName")
        if (javaClass.isNoCode) return ""
        return try {
            javaClass.code ?: ""
        } catch (error: Exception) {
            throw JadxException("cannot decompile $fullName: ${error.message ?: error.javaClass.simpleName}", error)
        }
    }

    @Synchronized
    fun smali(fullName: String): String {
        val javaClass = byName[fullName]
            ?: throw JadxException("unknown class: $fullName")
        return try {
            javaClass.smali ?: ""
        } catch (error: Exception) {
            throw JadxException("cannot read smali $fullName: ${error.message ?: error.javaClass.simpleName}", error)
        }
    }

    override fun close() {
        decompiler.close()
    }
}

/**
 * Loads an APK into jadx without writing sources to disk and without any external binary.
 * Resource decoding is skipped; only DEX classes and Java source are exposed. Cancellation is
 * observed before and after [JadxDecompiler.load]; the decompiler is always closed on failure
 * or cancellation so a cancelled load cannot keep its worker pool alive.
 */
class JadxService {
    suspend fun open(file: File): JadxSession = withContext(Dispatchers.IO) {
        coroutineContext.ensureActive()
        val dexBytes = if (file.isFile) {
            try {
                java.util.zip.ZipFile(file).use { zip ->
                    zip.entries().asSequence()
                        .filter { entry ->
                            !entry.isDirectory &&
                                entry.name.startsWith("classes") &&
                                entry.name.endsWith(".dex")
                        }
                        .sumOf { entry -> entry.size.coerceAtLeast(0L) }
                }
            } catch (_: Exception) {
                0L
            }
        } else {
            0L
        }
        if (dexBytes > MAX_DEX_BYTES) {
            throw JadxException(
                "DEX input is ${dexBytes / (1024 * 1024)} MiB; in-process jadx is capped at " +
                    "${MAX_DEX_BYTES / (1024 * 1024)} MiB to protect the app from running out of memory"
            )
        }
        val arguments = JadxArgs().apply {
            setInputFile(file)
            setSkipResources(true)
            setSkipSources(false)
            setThreadsCount(1)
            setShowInconsistentCode(true)
            setDeobfuscationOn(false)
            setUseImports(true)
        }
        val decompiler = JadxDecompiler(arguments)
        var keepOpen = false
        try {
            decompiler.load()
            coroutineContext.ensureActive()
            val classes = decompiler.classesWithInners
            coroutineContext.ensureActive()
            keepOpen = true
            JadxSession(decompiler, classes)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            throw JadxException(
                "jadx load failed: ${error.message ?: error.javaClass.simpleName}",
                error
            )
        } finally {
            if (!keepOpen) decompiler.close()
        }
    }

    private companion object {
        const val MAX_DEX_BYTES: Long = 32L * 1024 * 1024
    }
}
