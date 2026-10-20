package com.ecrew.toolkit.apk.fuzz

import com.ecrew.toolkit.apk.ComponentFacts
import com.ecrew.toolkit.apk.ComponentKind

/** One exported component selected for dynamic testing. */
data class FuzzTarget(
    val packageName: String,
    val component: ComponentFacts
) {
    val name: String get() = component.name
    val kind: ComponentKind get() = component.kind
    val permission: String? get() = component.permission
}

enum class FuzzStatus {
    SENT,
    BLOCKED,
    TIMEOUT,
    ERROR,
    CRASH,
    SKIPPED
}

data class CrashEvidence(
    val exceptionClass: String,
    val message: String,
    val stackHead: String,
    val source: String
) {
    fun summary(): String = buildString {
        append(exceptionClass)
        if (message.isNotEmpty()) append(": ").append(message)
        if (stackHead.isNotEmpty()) append(" | ").append(stackHead)
    }.take(MAX_SUMMARY_CHARS)

    private companion object {
        const val MAX_SUMMARY_CHARS = 600
    }
}

data class FuzzResult(
    val target: FuzzTarget,
    val payloadId: String,
    val status: FuzzStatus,
    val latencyMs: Long,
    val detail: String,
    val crash: CrashEvidence? = null
)

data class FuzzSessionReport(
    val results: List<FuzzResult>,
    val targets: List<FuzzTarget>,
    val startedAt: Long,
    val finishedAt: Long,
    val crashCaptureDegraded: Boolean,
    val errors: List<String>
) {
    val crashCount: Int get() = results.count { it.status == FuzzStatus.CRASH }
    val sentCount: Int get() = results.count { it.status == FuzzStatus.SENT }
    val blockedCount: Int get() = results.count { it.status == FuzzStatus.BLOCKED }
    val timeoutCount: Int get() = results.count { it.status == FuzzStatus.TIMEOUT }
    val errorCount: Int get() = results.count { it.status == FuzzStatus.ERROR }
}

object FuzzTargets {
    fun exported(manifest: com.ecrew.toolkit.apk.ApkManifestFacts): List<FuzzTarget> =
        manifest.components
            .filter { it.exported && it.enabled }
            .sortedWith(compareBy({ it.kind.ordinal }, { it.name }))
            .map { FuzzTarget(manifest.packageName, it) }
}
