package com.ecrew.toolkit.terminal

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit
import java.util.zip.ZipInputStream

/**
 * Extracts the bundled Termux bootstrap on first launch.
 *
 * `libtermux-bootstrap.so` is exactly how Termux ships it (Cody/Termux
 * pattern): an ELF whose .rodata embeds the complete bootstrap zip
 * (incbin'ed by termux-bootstrap-zip.S). We locate the zip payload inside the
 * ELF, stream it with ZipInputStream into filesDir/usr (staging + rename),
 * recreate SYMLINKS.txt links and REWRITE `#!/data/data/com.termux/...`
 * shebangs to our own prefix - the bootstrap scripts hardcode the com.termux
 * app id, which would not exist on this device.
 */
object BootstrapManager {

    private const val TAG = "Bootstrapper"
    private const val LIB_NAME = "libtermux-bootstrap.so"
    private const val MARKER = ".bootstrapped"

    // Literal on purpose: the legacy Termux bootstrap prefix must match byte-for-byte when
    // migrating old installs to the app-scoped prefix; nothing is read from this path.
    @Suppress("SdCardPath")
    private const val OLD_PREFIX = "/data/data/com.termux"

    fun prefixDir(ctx: Context) = File(ctx.filesDir, "usr")

    fun homeDir(ctx: Context) = File(ctx.filesDir, "home").also { it.mkdirs() }

    fun tmpDir(ctx: Context) = File(ctx.filesDir, "tmp").also { it.mkdirs() }

    fun isBootstrapped(ctx: Context): Boolean =
        File(prefixDir(ctx), MARKER).exists() && File(prefixDir(ctx), "bin/bash").exists()

    data class Result(val ok: Boolean, val message: String)

    @Synchronized
    fun ensureBootstrapped(ctx: Context): Result {
        if (isBootstrapped(ctx)) return Result(true, "bootstrap present")
        return try {
            val bytes = loadLibBytes(ctx)
                ?: return Result(
                    false,
                    "libtermux-bootstrap.so not found for ${Build.SUPPORTED_ABIS.joinToString()}"
                )
            val offset = findZipOffset(bytes)
                ?: return Result(false, "zip payload not found inside libtermux-bootstrap.so")

            val staging = File(ctx.filesDir, "usr.staging")
            if (staging.exists()) staging.deleteRecursively()
            staging.mkdirs()

            var entries = 0
            var shebangs = 0
            val symlinks = ArrayList<Pair<String, String>>(64)
            val filesDirPath = ctx.filesDir.absolutePath // replaces /data/data/com.termux/files

            ZipInputStream(ByteArrayInputStream(bytes, offset, bytes.size - offset)).use { zin ->
                var entry = zin.nextEntry
                while (entry != null) {
                    val name = entry.name
                    if (name == "SYMLINKS.txt") {
                        BufferedReader(InputStreamReader(zin, Charsets.UTF_8)).use { reader ->
                            var line = reader.readLine()
                            while (line != null) {
                                val parts = line.split("←")
                                if (parts.size == 2) symlinks.add(parts[0] to parts[1])
                                line = reader.readLine()
                            }
                        }
                    } else {
                        val target = File(staging, name)
                        if (entry.isDirectory) {
                            target.mkdirs()
                        } else {
                            target.parentFile?.mkdirs()
                            target.outputStream().use { out -> zin.copyTo(out) }
                            if (rewriteShebang(target, filesDirPath)) shebangs++
                            if (name.startsWith("bin/") || name.startsWith("libexec") ||
                                name.startsWith("lib/apt/apt-helper") ||
                                name.startsWith("lib/apt/methods")
                            ) {
                                target.setExecutable(true, false)
                            }
                        }
                        entries++
                    }
                    entry = zin.nextEntry
                }
            }

            if (entries == 0) return Result(false, "bootstrap zip contained no entries")

            var linksCreated = 0
            for ((oldPath, newRelPath) in symlinks) {
                val link = File(staging, newRelPath)
                link.parentFile?.mkdirs()
                try {
                    java.nio.file.Files.createSymbolicLink(
                        link.toPath(), java.nio.file.Paths.get(oldPath)
                    )
                    linksCreated++
                } catch (e: Exception) {
                    // best effort: some link targets may not resolve in app sandbox
                }
            }

            val prefix = prefixDir(ctx)
            if (prefix.exists()) prefix.deleteRecursively()
            if (!staging.renameTo(prefix)) {
                return Result(false, "could not move staging prefix into place")
            }
            File(prefix, MARKER).writeText(System.currentTimeMillis().toString())
            Result(
                true,
                "extracted $entries entries, $linksCreated symlinks, $shebangs shebangs rewritten"
            )
        } catch (e: Exception) {
            Log.e(TAG, "bootstrap extraction failed", e)
            Result(false, "error: ${e.message}")
        }
    }

    // ------------------------------------------------- payload location helpers

    /** #!.../com.termux... -> #!<our filesDir>... (app-id portable scripts). */
    private fun rewriteShebang(file: File, filesDirPath: String): Boolean {
        return try {
            if (!file.isFile || file.length() > 4_000_000) return false
            val head = ByteArray(2)
            file.inputStream().use { it.read(head) }
            if (head[0] != '#'.code.toByte() || head[1] != '!'.code.toByte()) return false
            val text = file.readText(Charsets.UTF_8)
            if (!text.contains(OLD_PREFIX)) return false
            file.writeText(text.replace(OLD_PREFIX, filesDirPath), Charsets.UTF_8)
            true
        } catch (e: Exception) {
            false
        }
    }

    /** The zip blob sits at a `PK\x03\x04` local header inside the ELF .rodata,
     *  identified by its first entry name SYMLINKS.txt (Termux layout). */
    private fun findZipOffset(bytes: ByteArray): Int? {
        val sig = byteArrayOf(0x50, 0x4B, 0x03, 0x04)
        var from = 0
        while (from <= bytes.size - 4) {
            var i = from
            var found = -1
            while (i <= bytes.size - 4) {
                if (bytes[i] == sig[0] && bytes[i + 1] == sig[1] &&
                    bytes[i + 2] == sig[2] && bytes[i + 3] == sig[3]
                ) { found = i; break }
                i++
            }
            if (found < 0) return null
            if (found + 32 < bytes.size) {
                val nameLen = (bytes[found + 26].toInt() and 0xFF) or
                    ((bytes[found + 27].toInt() and 0xFF) shl 8)
                if (nameLen in 1..255 && found + 30 + nameLen <= bytes.size) {
                    val name = String(bytes, found + 30, nameLen, Charsets.US_ASCII)
                    if (name == "SYMLINKS.txt") return found
                }
            }
            from = found + 4
        }
        return null
    }

    /** Read the bootstrap ELF: nativeLibraryDir first, then our own APK entry
     *  (covers installs where native libs stay uncompressed inside the APK). */
    private fun loadLibBytes(ctx: Context): ByteArray? {
        val direct = File(ctx.applicationInfo.nativeLibraryDir, LIB_NAME)
        if (direct.exists() && direct.canRead()) return direct.readBytes()

        val apk = ctx.applicationInfo.sourceDir ?: return null
        return try {
            val zip = java.util.zip.ZipFile(apk)
            try {
                for (abi in Build.SUPPORTED_ABIS) {
                    val entry = zip.getEntry("lib/$abi/$LIB_NAME") ?: continue
                    zip.getInputStream(entry).use { return it.readBytes() }
                }
                val all = zip.entries()
                while (all.hasMoreElements()) {
                    val en = all.nextElement()
                    if (en.name.endsWith("/$LIB_NAME")) {
                        zip.getInputStream(en).use { return it.readBytes() }
                    }
                }
                null
            } finally {
                zip.close()
            }
        } catch (e: Exception) {
            Log.e(TAG, "reading $LIB_NAME from apk failed", e)
            null
        }
    }

    // ------------------------------------------------- shell environment

    /** Prefer the extracted bootstrap bash; fall back to the system mksh. */
    fun shellPath(ctx: Context): String {
        val bash = File(prefixDir(ctx), "bin/bash")
        return if (bash.exists() && bash.canExecute()) bash.absolutePath else "/system/bin/sh"
    }

    fun sessionEnv(ctx: Context): Array<String> {
        val prefix = prefixDir(ctx).absolutePath
        val home = homeDir(ctx).absolutePath
        val tmp = tmpDir(ctx).absolutePath
        return arrayOf(
            "HOME=$home",
            "PREFIX=$prefix",
            "TMPDIR=$tmp",
            "TMP=$tmp",
            "TEMP=$tmp",
            "PATH=$prefix/bin:$prefix/bin/applets:/system/xbin:/system/bin",
            // RUNPATHs inside the bootstrap point at /data/data/com.termux - the
            // loader checks LD_LIBRARY_PATH before RUNPATH, so ours wins.
            "LD_LIBRARY_PATH=$prefix/lib",
            "TERM=xterm-256color",
            "LANG=en_US.UTF-8",
            "COLORTERM=truecolor",
            "SHELL=$prefix/bin/bash",
            "EXTERNAL_STORAGE=/sdcard",
            "ANDROID_DATA=/data"
        )
    }

    /** Run Termux's second-stage script (post-extract fixes). Non-fatal. */
    fun runSecondStage(ctx: Context): String {
        val script = File(prefixDir(ctx), "etc/termux/bootstrap/termux-bootstrap-second-stage.sh")
        if (!script.exists()) return "second stage: script absent (skipped)"
        return try {
            script.setExecutable(true, false)
            val pb = ProcessBuilder(script.absolutePath)
                .directory(homeDir(ctx))
                .redirectErrorStream(true)
            val env = pb.environment()
            sessionEnv(ctx).forEach { kv ->
                val idx = kv.indexOf('=')
                if (idx > 0) env[kv.substring(0, idx)] = kv.substring(idx + 1)
            }
            val proc = pb.start()
            val output = StringBuilder()
            proc.inputStream.bufferedReader().use { r ->
                var line = r.readLine()
                while (line != null && output.length < 4096) {
                    output.append(line).append('\n')
                    line = r.readLine()
                }
            }
            val finished = proc.waitFor(60, TimeUnit.SECONDS)
            if (!finished) proc.destroy() else proc.waitFor()
            val rc = if (finished) proc.exitValue() else -1
            "second stage: exit=$rc ${if (rc != 0) output.toString().take(300) else ""}"
        } catch (e: Exception) {
            Log.e(TAG, "second stage failed", e)
            "second stage failed: ${e.message}"
        }
    }
}
