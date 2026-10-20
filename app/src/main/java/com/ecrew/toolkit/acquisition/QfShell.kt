package com.ecrew.toolkit.acquisition

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.concurrent.TimeUnit

data class QfShellOutput(
    val command: String,
    val exitCode: Int,
    val text: String,
    val truncated: Boolean,
    val error: String?
)

/**
 * Fixed, read-only privileged table for acquisition. The only privileged inputs are the
 * compile-time topic names below; no operator text is ever interpolated into a command.
 */
object QfCommands {
    val dumpsysTopics = listOf(
        "package",
        "activity",
        "accessibility",
        "device_policy",
        "batterystats"
    )

    val table: List<List<String>> = buildList {
        add(listOf("/system/bin/getprop"))
        add(listOf("/system/bin/ps", "-A"))
        add(listOf("/system/bin/service", "list"))
        add(listOf("/system/bin/logcat", "-d", "-v", "brief", "-t", "2000"))
        add(listOf("/system/bin/ss", "-tulpn"))
        add(listOf("/system/bin/netstat", "-tulpn"))
        dumpsysTopics.forEach { topic ->
            add(listOf("/system/bin/dumpsys", topic))
        }
    }
}

class QfShell(private val context: Context) {
    val available: Boolean
        get() = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.DUMP
        ) == PackageManager.PERMISSION_GRANTED

    fun run(tokens: List<String>): QfShellOutput {
        if (tokens !in QfCommands.table) {
            return QfShellOutput(tokens.joinToString(" "), -1, "", false, "command not allowed")
        }
        val process = try {
            ProcessBuilder(tokens).redirectErrorStream(true).start()
        } catch (error: Exception) {
            return QfShellOutput(
                tokens.joinToString(" "),
                -1,
                "",
                false,
                error.javaClass.simpleName
            )
        }
        val collector = Collector()
        val reader = Thread {
            collector.drain(process.inputStream)
        }
        reader.start()
        val finished = try {
            process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!finished) {
            process.destroy()
            reader.join(2_000)
            return QfShellOutput(
                tokens.joinToString(" "),
                -1,
                collector.text(),
                collector.truncated,
                "command timed out"
            )
        }
        reader.join(3_000)
        return QfShellOutput(
            tokens.joinToString(" "),
            process.exitValue(),
            collector.text(),
            collector.truncated,
            null
        )
    }

    private class Collector {
        private val output = ByteArrayOutputStream()
        @Volatile
        var truncated = false

        fun drain(input: InputStream) {
            val buffer = ByteArray(8 * 1024)
            try {
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    val room = MAX_BYTES - output.size()
                    if (read <= room) output.write(buffer, 0, read) else {
                        if (room > 0) output.write(buffer, 0, room)
                        truncated = true
                    }
                }
            } catch (_: Exception) {
                // The process is gone; the caller reports the timeout separately.
            } finally {
                try {
                    input.close()
                } catch (_: Exception) {
                    // Nothing left to close.
                }
            }
        }

        fun text(): String = output.toByteArray().toString(Charsets.UTF_8)
    }

    private companion object {
        const val TIMEOUT_SECONDS = 25L
        const val MAX_BYTES = 8 * 1024 * 1024
    }
}
