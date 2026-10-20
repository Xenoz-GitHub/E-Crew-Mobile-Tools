package com.ecrew.toolkit.apk.fuzz

data class CrashSnapshot(
    val events: List<CrashEvidence>,
    val degraded: Boolean,
    val errors: List<String>
)

/**
 * Captures crash buffers through the fuzz Shizuku service. The service is optional; when it is
 * not ready the fuzz runner still sends payloads and labels every crash-capture result degraded.
 */
class CrashWatcher(private val gateway: FuzzShizukuGateway) {
    val ready: Boolean get() = gateway.ready

    fun snapshot(packageName: String): CrashSnapshot {
        if (!gateway.ready) {
            return CrashSnapshot(emptyList(), true, listOf("Shizuku is not ready; crash capture degraded"))
        }
        val events = ArrayList<CrashEvidence>()
        val errors = ArrayList<String>()
        var degraded = false
        for (mode in listOf(0, 3)) {
            val logcat = gateway.capture(mode)
            if (logcat.degraded) {
                degraded = true
                logcat.error?.let { errors.add(it) }
            } else {
                events.addAll(CrashParser.parseLogcat(logcat.stdout, packageName))
            }
        }
        for (mode in listOf(1, 2)) {
            val dropbox = gateway.capture(mode)
            if (dropbox.degraded) {
                degraded = true
                dropbox.error?.let { errors.add(it) }
            } else {
                events.addAll(CrashParser.parseDropbox(dropbox.stdout, packageName))
            }
        }
        return CrashSnapshot(
            events = events.distinctBy { it.exceptionClass + "|" + it.stackHead }.take(20),
            degraded = degraded,
            errors = errors.distinct()
        )
    }
}
