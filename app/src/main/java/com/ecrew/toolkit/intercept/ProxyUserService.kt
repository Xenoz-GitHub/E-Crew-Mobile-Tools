package com.ecrew.toolkit.intercept

import java.io.ByteArrayOutputStream
import java.util.concurrent.TimeUnit

/**
 * Shizuku user service. It runs as the shell UID and exposes only the proxy get/set/clear/
 * restore operations. Host text is validated and passed as a single ProcessBuilder argument;
 * no shell is involved. `settings` is the only mutating command.
 */
class ProxyUserService : IProxyShellService.Stub() {
    override fun getProxy(): String =
        run(listOf("/system/bin/settings", "get", "global", "http_proxy")).output

    override fun setProxy(host: String, port: Int): Int {
        if (!validHost(host) || port !in 1..65535) return ERROR_INVALID
        return run(
            listOf(
                "/system/bin/settings", "put", "global", "http_proxy", "$host:$port"
            )
        ).exitCode
    }

    override fun clearProxy(): Int = run(
        listOf("/system/bin/settings", "delete", "global", "http_proxy")
    ).exitCode

    override fun restoreProxy(value: String): Int {
        val trimmed = value.trim()
        if (trimmed == "null" || trimmed.isEmpty() || trimmed == ":0" || trimmed == "0") {
            return clearProxy()
        }
        val host = trimmed.substringBefore(':')
        val port = trimmed.substringAfter(':', "").toIntOrNull() ?: return ERROR_INVALID
        if (!validHost(host) || port !in 1..65535) return ERROR_INVALID
        return run(
            listOf("/system/bin/settings", "put", "global", "http_proxy", "$host:$port")
        ).exitCode
    }

    override fun exit() {
        System.exit(0)
    }

    override fun destroy() {
        exit()
    }

    private data class CommandResult(val exitCode: Int, val output: String)

    /**
     * Runs only absolute /system/bin/settings commands. The exit code is returned
     * separately: `settings put` prints nothing on success, which previously made a
     * successful write look like a failure.
     */
    private fun run(command: List<String>): CommandResult {
        val process = try {
            ProcessBuilder(command).redirectErrorStream(true).start()
        } catch (_: Exception) {
            return CommandResult(ERROR_FAILED, "")
        }
        val output = ByteArrayOutputStream()
        val reader = Thread {
            try {
                process.inputStream.use { input ->
                    val buffer = ByteArray(8 * 1024)
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        if (output.size() + read <= MAX_OUTPUT) {
                            output.write(buffer, 0, read)
                        }
                    }
                }
            } catch (_: Exception) {
                // Report the exit code below.
            }
        }
        reader.start()
        val finished = try {
            process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!finished) {
            process.destroy()
            return CommandResult(ERROR_TIMEOUT, "")
        }
        reader.join(2_000)
        val text = output.toByteArray().toString(Charsets.UTF_8).trim()
        return CommandResult(process.exitValue(), text)
    }

    private fun validHost(host: String): Boolean =
        host.length in 1..253 && host.all {
            it.isLetterOrDigit() || it == '.' || it == '-' || it == '_'
        }

    private companion object {
        const val ERROR_INVALID = -2
        const val ERROR_FAILED = -1
        const val ERROR_TIMEOUT = -3
        const val TIMEOUT_SECONDS = 15L
        const val MAX_OUTPUT = 4 * 1024
    }
}
