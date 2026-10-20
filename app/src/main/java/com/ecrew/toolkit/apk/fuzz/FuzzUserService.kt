package com.ecrew.toolkit.apk.fuzz

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.concurrent.TimeUnit

/**
 * Shizuku user service used only by the APK fuzzing tab. Unlike AuditUserService it accepts a
 * small integer mode, never a command string, and can therefore capture crashes without opening
 * a general shell. Modes and binaries are compile-time constants.
 */
class FuzzUserService : IFuzzShellService.Stub() {
    private val lock = Any()
    private var stdout = ByteArray(0)
    private var stderr = ""
    private var exit = -1

    override fun capture(mode: Int): Int {
        val command = when (mode) {
            0 -> listOf(
                "/system/bin/logcat", "-d", "-b", "crash", "-v", "brief", "-t", "400"
            )
            1 -> listOf("/system/bin/dumpsys", "dropbox", "--print", "data_app_crash")
            2 -> listOf("/system/bin/dumpsys", "dropbox", "--print", "system_app_crash")
            3 -> listOf("/system/bin/logcat", "-d", "-v", "brief", "-t", "400")
            else -> return fail(ERROR_MODE, "unsupported capture mode")
        }
        val process = try {
            ProcessBuilder(command).redirectErrorStream(false).start()
        } catch (error: Exception) {
            return fail(ERROR_START, "cannot start ${command.first()}")
        }
        val collector = Collector()
        val outThread = Thread {
            collector.drain(process.inputStream, collector.out, OUT_LIMIT) {
                collector.truncated = true
            }
        }
        val errThread = Thread {
            collector.drain(process.errorStream, collector.err, ERR_LIMIT) {}
        }
        outThread.start()
        errThread.start()
        val finished = try {
            process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!finished) {
            process.destroy()
            outThread.join(1_000)
            errThread.join(1_000)
            return fail(ERROR_TIMEOUT, "crash capture timed out")
        }
        outThread.join(5_000)
        errThread.join(5_000)
        val bytes = collector.out.toByteArray()
        synchronized(lock) {
            stdout = bytes
            stderr = collector.err.toByteArray().toString(Charsets.UTF_8)
            exit = process.exitValue()
        }
        return bytes.size
    }

    override fun exitCode(): Int = synchronized(lock) { exit }

    override fun stderr(): String = synchronized(lock) { stderr }

    override fun read(offset: Int, length: Int): ByteArray = synchronized(lock) {
        if (offset < 0 || length <= 0 || offset >= stdout.size) ByteArray(0) else {
            stdout.copyOfRange(offset, minOf(stdout.size, offset + length))
        }
    }

    override fun exit() {
        System.exit(0)
    }

    override fun destroy() {
        exit()
    }

    private fun fail(code: Int, message: String): Int {
        synchronized(lock) {
            stdout = ByteArray(0)
            stderr = message
            exit = code
        }
        return code
    }

    private class Collector {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        @Volatile
        var truncated = false

        fun drain(input: InputStream, target: ByteArrayOutputStream, cap: Int, onTruncate: () -> Unit) {
            val buffer = ByteArray(8 * 1024)
            try {
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    val room = cap - target.size()
                    if (read <= room) {
                        target.write(buffer, 0, read)
                    } else {
                        if (room > 0) target.write(buffer, 0, room)
                        onTruncate()
                    }
                }
            } catch (_: Exception) {
                // The process is gone after a timeout; the timeout is reported separately.
            } finally {
                try {
                    input.close()
                } catch (_: Exception) {
                    // Nothing left to close.
                }
            }
        }
    }

    private companion object {
        const val TIMEOUT_SECONDS = 15L
        const val OUT_LIMIT = 1024 * 1024
        const val ERR_LIMIT = 64 * 1024
        const val ERROR_MODE = -4
        const val ERROR_TIMEOUT = -5
        const val ERROR_START = -6
    }
}
