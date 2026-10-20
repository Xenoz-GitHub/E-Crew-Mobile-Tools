package com.ecrew.toolkit.audit

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.concurrent.TimeUnit

/**
 * The Shizuku audit user service (design note 9c).
 *
 * Shizuku loads this class into an `app_process` running as the served user; it is not an
 * Android Service and has no manifest entry. It executes only commands from
 * [AuditCommands.shizukuTable] and never mutates the device. The output is captured with
 * hard caps and served to the app in chunks via [IAuditShellService], because a single
 * binder transaction is limited to about 1 MB.
 */
class AuditUserService : IAuditShellService.Stub() {

    private val lock = Any()
    private var stdout = ByteArray(0)
    private var stderr = ""
    private var exit = -1

    override fun execute(command: String): Int {
        val tokens = AuditCommands.parseCanonical(command)
            ?: return fail(ERROR_NOT_ALLOWED, "command not in the read-only table: $command")
        val process = try {
            ProcessBuilder(executable(tokens))
                .redirectErrorStream(false)
                .start()
        } catch (e: Exception) {
            return fail(
                ERROR_START,
                "cannot start ${tokens.first()}: ${e.javaClass.simpleName}: ${e.message ?: "failed"}"
            )
        }
        val collector = StreamCollector()
        val stdoutThread = Thread({ collector.drain(process.inputStream, collector.out, STDOUT_LIMIT) { collector.stdoutTruncated = true } })
        val stderrThread = Thread({ collector.drain(process.errorStream, collector.err, STDERR_LIMIT) {} })
        stdoutThread.start()
        stderrThread.start()
        val finished = try {
            process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!finished) {
            process.destroy()
            stdoutThread.join(1_000)
            stderrThread.join(1_000)
            return fail(
                ERROR_TIMEOUT,
                "the command did not finish within $TIMEOUT_SECONDS s and was stopped"
            )
        }
        stdoutThread.join(5_000)
        stderrThread.join(5_000)
        if (collector.stdoutTruncated) {
            return fail(
                ERROR_TRUNCATED,
                "stdout exceeded the $STDOUT_LIMIT-byte cap; a truncated dump is never parsed"
            )
        }
        val output = collector.out.toByteArray()
        synchronized(lock) {
            stdout = output
            stderr = collector.err.toByteArray().toString(Charsets.UTF_8)
            exit = process.exitValue()
        }
        return output.size
    }

    override fun exitCode(): Int = synchronized(lock) { exit }

    override fun stderr(): String = synchronized(lock) { stderr }

    override fun read(offset: Int, length: Int): ByteArray = synchronized(lock) {
        if (offset < 0 || length <= 0 || offset >= stdout.size) return ByteArray(0)
        val end = minOf(stdout.size, offset + length)
        stdout.copyOfRange(offset, end)
    }

    override fun exit() {
        System.exit(0)
    }

    override fun destroy() {
        exit()
    }

    /**
     * The service process may not inherit a usable PATH; the frozen table only names
     * /system/bin binaries, so the mapping is deterministic.
     */
    private fun executable(tokens: List<String>): List<String> =
        listOf("/system/bin/" + tokens.first()) + tokens.drop(1)

    private fun fail(code: Int, message: String): Int {
        synchronized(lock) {
            stdout = ByteArray(0)
            stderr = message
            exit = code
        }
        return code
    }

    /** Reads a stream to the cap while still draining it, so the child never blocks. */
    private class StreamCollector {

        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        @Volatile
        var stdoutTruncated = false

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
            } catch (e: Exception) {
                // The process was destroyed on timeout; the timeout reason is reported instead.
            } finally {
                try {
                    input.close()
                } catch (e: Exception) {
                    // The stream is already gone; nothing to flush.
                }
            }
        }
    }

    private companion object {
        const val TIMEOUT_SECONDS = 20L
        const val STDOUT_LIMIT = 8 * 1024 * 1024
        const val STDERR_LIMIT = 64 * 1024

        const val ERROR_NOT_ALLOWED = -4
        const val ERROR_TIMEOUT = -5
        const val ERROR_START = -6
        const val ERROR_TRUNCATED = -7
    }
}
