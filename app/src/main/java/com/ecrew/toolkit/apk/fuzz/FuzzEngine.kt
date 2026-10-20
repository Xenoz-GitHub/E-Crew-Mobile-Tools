package com.ecrew.toolkit.apk.fuzz

import android.content.ComponentName
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import com.ecrew.toolkit.apk.ComponentKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.coroutineContext

class FuzzException(message: String) : Exception(message)

/** Sends one explicit intent; used by both the fuzzer and the one-tap activity launcher. */
class ActivityLauncher(private val context: Context) {
    fun launch(
        target: FuzzTarget,
        extraKey: String = "",
        extraValue: String = "",
        data: String = ""
    ): FuzzResult {
        val startedAt = System.currentTimeMillis()
        return try {
            val intent = Intent().apply {
                component = ComponentName(target.packageName, target.name)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                if (extraKey.isNotBlank()) putExtra(extraKey, extraValue)
                if (data.isNotBlank()) this.data = Uri.parse(data)
            }
            context.startActivity(intent)
            FuzzResult(
                target,
                "launch",
                FuzzStatus.SENT,
                System.currentTimeMillis() - startedAt,
                "explicit activity launch sent"
            )
        } catch (error: Exception) {
            FuzzResult(
                target,
                "launch",
                classifyFuzzError(error),
                System.currentTimeMillis() - startedAt,
                fuzzErrorDetail(error)
            )
        }
    }
}

/**
 * Runs the exported-component payload set. Payload values are never passed to the audit sink;
 * only the payload id and a short outcome are emitted. Crash capture is attempted after each
 * target through Shizuku and is marked degraded when that service is not ready.
 */
class FuzzEngine(
    private val context: Context,
    private val crashWatcher: CrashWatcher,
    private val crashCaptureRequired: Boolean = true
) {
    private val stopped = AtomicBoolean(false)

    fun stop() {
        stopped.set(true)
    }

    suspend fun run(
        targets: List<FuzzTarget>,
        consentConfirmed: Boolean,
        audit: (FuzzResult) -> Unit = {}
    ): FuzzSessionReport {
        if (!consentConfirmed) throw FuzzException("written-authorization attestation is required")
        if (targets.isEmpty()) throw FuzzException("no exported components to fuzz")
        if (targets.any { it.packageName == context.packageName }) {
            throw FuzzException("E-Crew does not fuzz its own package")
        }
        if (crashCaptureRequired && !crashWatcher.ready) {
            throw FuzzException("dynamic fuzzing requires Shizuku for crash capture")
        }
        val startedAt = System.currentTimeMillis()
        val results = ArrayList<FuzzResult>()
        val errors = ArrayList<String>()
        var degraded = !crashWatcher.ready
        stopped.set(false)
        for (target in targets) {
            coroutineContext.ensureActive()
            if (stopped.get()) break
            val targetResults = ArrayList<FuzzResult>()
            try {
                when (target.kind) {
                    ComponentKind.ACTIVITY, ComponentKind.SERVICE ->
                        targetResults.addAll(runIntentTarget(target))
                    ComponentKind.PROVIDER ->
                        targetResults.addAll(runProviderTarget(target))
                    ComponentKind.RECEIVER ->
                        targetResults.addAll(runBroadcastTarget(target))
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                errors.add("${target.name}: ${fuzzErrorDetail(error)}")
            }
            delay(350)
            val snapshot = crashWatcher.snapshot(target.packageName)
            if (snapshot.degraded) degraded = true
            errors.addAll(snapshot.errors)
            if (snapshot.events.isNotEmpty()) {
                val last = targetResults.lastOrNull()
                if (last != null && last.status != FuzzStatus.ERROR) {
                    targetResults[targetResults.lastIndex] = last.copy(
                        status = FuzzStatus.CRASH,
                        crash = snapshot.events.first(),
                        detail = "crash after ${last.payloadId}: ${snapshot.events.first().summary()}"
                    )
                } else {
                    targetResults.add(
                        FuzzResult(
                            target,
                            "crash",
                            FuzzStatus.CRASH,
                            last?.latencyMs ?: 0L,
                            snapshot.events.first().summary(),
                            snapshot.events.first()
                        )
                    )
                }
            }
            for (result in targetResults) {
                results.add(result)
                try {
                    audit(result)
                } catch (error: Exception) {
                    errors.add("audit: ${fuzzErrorDetail(error)}")
                }
            }
        }
        return FuzzSessionReport(
            results = results,
            targets = targets,
            startedAt = startedAt,
            finishedAt = System.currentTimeMillis(),
            crashCaptureDegraded = degraded,
            errors = errors.distinct()
        )
    }

    private suspend fun runIntentTarget(target: FuzzTarget): List<FuzzResult> {
        val results = ArrayList<FuzzResult>()
        val payloads = FuzzPayloads.intentPayloads +
            FuzzPayloads.actionPayloads +
            FuzzPayloads.dataPayloads
        for (payload in payloads) {
            if (stopped.get()) break
            val started = System.currentTimeMillis()
            val outcome = withTimeoutOrNull(SEND_TIMEOUT_MS) {
                withContext(Dispatchers.IO) {
                    try {
                        val intent = intentFor(target, payload)
                        when (target.kind) {
                            ComponentKind.ACTIVITY -> context.startActivity(intent)
                            ComponentKind.SERVICE -> context.startService(intent)
                            else -> context.sendBroadcast(intent)
                        }
                        FuzzStatus.SENT to "sent ${payload.id}"
                    } catch (error: Exception) {
                        classifyFuzzError(error) to fuzzErrorDetail(error)
                    }
                }
            } ?: (FuzzStatus.TIMEOUT to "binder call exceeded ${SEND_TIMEOUT_MS} ms")
            results.add(
                FuzzResult(
                    target,
                    payload.id,
                    outcome.first,
                    System.currentTimeMillis() - started,
                    outcome.second
                )
            )
        }
        return results
    }

    private suspend fun runBroadcastTarget(target: FuzzTarget): List<FuzzResult> {
        val results = ArrayList<FuzzResult>()
        for (payload in FuzzPayloads.broadcastPayloads) {
            if (stopped.get()) break
            val started = System.currentTimeMillis()
            val outcome = withTimeoutOrNull(SEND_TIMEOUT_MS) {
                withContext(Dispatchers.IO) {
                    try {
                        val action = payload.value.take(200)
                        val intent = Intent(action).apply {
                            component = ComponentName(target.packageName, target.name)
                            putExtra(EXTRA_KEY, payload.id)
                        }
                        context.sendBroadcast(intent)
                        FuzzStatus.SENT to "broadcast ${payload.id} sent"
                    } catch (error: Exception) {
                        classifyFuzzError(error) to fuzzErrorDetail(error)
                    }
                }
            } ?: (FuzzStatus.TIMEOUT to "broadcast exceeded ${SEND_TIMEOUT_MS} ms")
            results.add(
                FuzzResult(
                    target,
                    payload.id,
                    outcome.first,
                    System.currentTimeMillis() - started,
                    outcome.second
                )
            )
        }
        return results
    }

    private suspend fun runProviderTarget(target: FuzzTarget): List<FuzzResult> {
        val authority = target.component.authorities.firstOrNull()
            ?: return listOf(
                FuzzResult(
                    target,
                    "provider_authority",
                    FuzzStatus.SKIPPED,
                    0L,
                    "no provider authority"
                )
            )
        val base = Uri.parse("content://$authority/")
        val results = ArrayList<FuzzResult>()
        for (payload in FuzzPayloads.providerQueryPayloads) {
            if (stopped.get()) break
            val started = System.currentTimeMillis()
            val outcome = withTimeoutOrNull(PROVIDER_TIMEOUT_MS) {
                withContext(Dispatchers.IO) {
                    try {
                        val traversal = payload.id == "provider_traversal"
                        val queryUri = if (traversal) {
                            Uri.parse("content://$authority/../../../../etc/passwd")
                        } else {
                            base
                        }
                        val projection = if (traversal) {
                            null
                        } else if (payload.channel == FuzzChannel.PROVIDER_PROJECTION) {
                            arrayOf(payload.value.take(200))
                        } else {
                            null
                        }
                        val selection = if (payload.channel == FuzzChannel.PROVIDER_SELECTION) {
                            payload.value.take(200)
                        } else {
                            null
                        }
                        context.contentResolver.query(queryUri, projection, selection, null, null)
                            ?.use { cursor ->
                                val rows = minOf(cursor.count, 5)
                                FuzzStatus.SENT to "query returned $rows row(s)"
                            } ?: (FuzzStatus.SENT to "query returned no cursor")
                    } catch (error: Exception) {
                        classifyFuzzError(error) to fuzzErrorDetail(error)
                    }
                }
            } ?: (FuzzStatus.TIMEOUT to "provider query exceeded ${PROVIDER_TIMEOUT_MS} ms")
            results.add(
                FuzzResult(
                    target,
                    payload.id,
                    outcome.first,
                    System.currentTimeMillis() - started,
                    outcome.second
                )
            )
        }
        for (payload in FuzzPayloads.providerInsertPayloads) {
            if (stopped.get()) break
            val started = System.currentTimeMillis()
            val outcome = withTimeoutOrNull(PROVIDER_TIMEOUT_MS) {
                withContext(Dispatchers.IO) {
                    try {
                        val values = ContentValues().apply {
                            put("ecrew_fuzz_probe", payload.value.take(1024))
                        }
                        val inserted = context.contentResolver.insert(base, values)
                        if (inserted == null) {
                            FuzzStatus.SENT to "provider returned a null insert URI"
                        } else {
                            FuzzStatus.SENT to "provider accepted an insert"
                        }
                    } catch (error: Exception) {
                        classifyFuzzError(error) to fuzzErrorDetail(error)
                    }
                }
            } ?: (FuzzStatus.TIMEOUT to "provider insert exceeded ${PROVIDER_TIMEOUT_MS} ms")
            results.add(
                FuzzResult(
                    target,
                    payload.id,
                    outcome.first,
                    System.currentTimeMillis() - started,
                    outcome.second
                )
            )
        }
        return results
    }

    private fun intentFor(target: FuzzTarget, payload: FuzzPayload): Intent {
        val intent = Intent().apply {
            component = ComponentName(target.packageName, target.name)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        when (payload.channel) {
            FuzzChannel.INTENT_EXTRA ->
                intent.putExtra(EXTRA_KEY, payload.value)
            FuzzChannel.INTENT_ACTION ->
                intent.action = payload.value
            FuzzChannel.INTENT_DATA ->
                intent.data = Uri.parse(payload.value)
            else -> intent.putExtra(EXTRA_KEY, payload.value)
        }
        return intent
    }

    private companion object {
        const val EXTRA_KEY = "ecrew_fuzz_input"
        const val SEND_TIMEOUT_MS = 2_000L
        const val PROVIDER_TIMEOUT_MS = 3_000L
    }
}

private fun classifyFuzzError(error: Exception): FuzzStatus = when (error) {
    is SecurityException -> FuzzStatus.BLOCKED
    is android.os.TransactionTooLargeException -> FuzzStatus.ERROR
    else -> FuzzStatus.ERROR
}

private fun fuzzErrorDetail(error: Exception): String {
    val message = error.message ?: ""
    return (error.javaClass.simpleName + if (message.isBlank()) "" else ": $message")
        .replace('\n', ' ')
        .take(300)
}

