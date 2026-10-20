package com.ecrew.toolkit.audit

import java.io.InputStream
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Root tier transport (design note section 9d). E-Crew runs only the frozen read-only argv
 * table through the platform's `su`; it never bundles, downloads or auto-grants a su binary.
 *
 * Two su grammars exist on Android 8: AOSP userdebug images use `su <uid> <command...>`,
 * while Magisk/KernelSU-style managers use `su -c "<command>"`. The probe tries the AOSP form
 * first and keeps the first variant that reports uid=0. A failure is cached so a scan cannot
 * trigger repeated root prompts; the Tier card's Recheck resets the cache.
 */
enum class RootState {
    /** Opt-in off: su was never executed. */
    DISABLED,
    /** No su reachable by the app, or the binary refuses app UIDs. */
    NOT_AVAILABLE,
    /** su ran but did not return uid 0. */
    DENIED,
    /** The probe returned uid 0. */
    READY
}

/** Which su grammar answered the probe. */
enum class SuVariant { AOSP_UID, COMMAND }

/** Outcome of the opt-in root probe, including the raw first failure line. */
data class RootProbeResult(
    val state: RootState,
    val variant: SuVariant?,
    val evidence: String
)

internal const val ROOT_TIMEOUT_MS = 20_000L
internal const val ROOT_STDOUT_CAP = 1 shl 20
internal const val ROOT_STDERR_CAP = 64 * 1024

object AuditRoot {

    @Volatile
    private var cached: RootProbeResult? = null

    /** Probes once per process until [reset] is called. Blocking: call from a background thread. */
    fun probe(): RootProbeResult {
        cached?.let { return it }
        synchronized(this) {
            cached?.let { return it }
            val result = runProbe()
            cached = result
            return result
        }
    }

    /** Forgets the cached probe; the Tier card calls this on an explicit Recheck. */
    fun reset() {
        cached = null
    }

    /** The root shell when the probe is READY, otherwise null. */
    fun shell(): RootShell? {
        val result = probe()
        val variant = result.variant ?: return null
        return if (result.state == RootState.READY) RootShell(variant) else null
    }

    private fun runProbe(): RootProbeResult {
        val aosp = executeRootCommand(
            listOf("su", "0", "id"), AuditCommands.ROOT_PROBE, ROOT_TIMEOUT_MS
        )
        if (isUidZero(aosp.stdout)) {
            return RootProbeResult(RootState.READY, SuVariant.AOSP_UID, "su 0 id: uid=0")
        }
        val commandStyle = executeRootCommand(
            listOf("su", "-c", "id"), AuditCommands.ROOT_PROBE, ROOT_TIMEOUT_MS
        )
        if (isUidZero(commandStyle.stdout)) {
            return RootProbeResult(RootState.READY, SuVariant.COMMAND, "su -c id: uid=0")
        }
        return decideRootProbe(aosp, commandStyle)
    }
}

/**
 * Classifies two failed probe attempts. Kept pure so the JVM tests can pin the rule: both
 * "not usable" errors mean the app has no usable su (NOT_AVAILABLE); anything else means su
 * answered but refused to become root (DENIED).
 */
internal fun decideRootProbe(aosp: ShellResult, commandStyle: ShellResult): RootProbeResult {
    val aospReason = probeFailureLine(aosp)
    val commandReason = probeFailureLine(commandStyle)
    val noSu = isNoSuError(aospReason) && isNoSuError(commandReason)
    return RootProbeResult(
        if (noSu) RootState.NOT_AVAILABLE else RootState.DENIED,
        null,
        "su 0 id: $aospReason; su -c id: $commandReason"
    )
}

internal fun isUidZero(stdout: String): Boolean =
    Regex("(^|\\s)uid=0\\b").containsMatchIn(stdout)

private fun probeFailureLine(result: ShellResult): String {
    val text = result.stderr.trim().ifBlank { result.stdout.trim() }
    val line = text.lineSequence().map { it.trim() }.firstOrNull { it.isNotEmpty() }
    return line?.take(160) ?: "no output (exit ${result.exitCode})"
}

private fun isNoSuError(line: String): Boolean {
    val lower = line.lowercase()
    return lower.contains("permission denied") ||
        lower.contains("not found") ||
        lower.contains("no such file") ||
        lower.contains("error=13") ||
        lower.contains("not executable") ||
        lower.contains("operation not permitted")
}

/**
 * Root-tier [AuditShell]. The command tokens come from the frozen table; the transport only
 * chooses the su grammar. No shell string uses user input.
 */
class RootShell(private val variant: SuVariant) : AuditShell {

    override val source: ShellTier = ShellTier.ROOT

    override fun exec(command: List<String>): ShellResult {
        require(AuditCommands.isRootAllowed(command)) {
            "command not in the read-only table (ROOT): ${AuditCommands.canonical(command)}"
        }
        val argv = when (variant) {
            SuVariant.AOSP_UID -> listOf("su", "0") + command
            SuVariant.COMMAND -> listOf("su", "-c", AuditCommands.canonical(command))
        }
        return executeRootCommand(argv, command, ROOT_TIMEOUT_MS)
    }
}

/**
 * Runs one fixed argv with a timeout and hard output caps. Timeout or over-cap output is an
 * error result, so the check reports UNKNOWN instead of parsing a partial read.
 */
internal fun executeRootCommand(
    argv: List<String>,
    logical: List<String>,
    timeoutMs: Long
): ShellResult {
    val process = try {
        ProcessBuilder(argv).redirectErrorStream(false).start()
    } catch (e: Exception) {
        return ShellResult(
            logical,
            -1,
            "",
            "${e.javaClass.simpleName}: ${e.message ?: "failed"}"
        )
    }
    val out = StringBuilder()
    val err = StringBuilder()
    val outTruncated = AtomicBoolean(false)
    val errTruncated = AtomicBoolean(false)
    val outThread = Thread({
        outTruncated.set(drain(process.inputStream, out, ROOT_STDOUT_CAP))
    }, "audit-root-stdout").apply { isDaemon = true }
    val errThread = Thread({
        errTruncated.set(drain(process.errorStream, err, ROOT_STDERR_CAP))
    }, "audit-root-stderr").apply { isDaemon = true }
    outThread.start()
    errThread.start()
    val finished = try {
        process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
    } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        false
    }
    if (!finished) {
        process.destroyForcibly()
        process.waitFor()
        outThread.join(1000)
        errThread.join(1000)
        return ShellResult(
            logical,
            -1,
            "",
            "timed out after $timeoutMs ms; output discarded"
        )
    }
    outThread.join(2000)
    errThread.join(2000)
    if (outTruncated.get() || errTruncated.get()) {
        return ShellResult(
            logical,
            -1,
            "",
            "output exceeded the ${ROOT_STDOUT_CAP} character cap; not parsed"
        )
    }
    return ShellResult(logical, process.exitValue(), out.toString(), err.toString())
}

/** Reads to EOF, keeps at most [cap] characters and reports whether anything was dropped. */
private fun drain(input: InputStream, sink: StringBuilder, cap: Int): Boolean {
    val buffer = CharArray(8192)
    var truncated = false
    input.bufferedReader().use { reader ->
        while (true) {
            val read = try {
                reader.read(buffer)
            } catch (e: Exception) {
                return true
            }
            if (read < 0) break
            val room = cap - sink.length
            if (room > 0) {
                val keep = minOf(read, room)
                sink.append(buffer, 0, keep)
                if (keep < read) truncated = true
            } else {
                truncated = true
            }
        }
    }
    return truncated
}
