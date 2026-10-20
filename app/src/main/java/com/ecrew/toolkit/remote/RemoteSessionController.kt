package com.ecrew.toolkit.remote

import android.content.Context
import android.graphics.BitmapFactory
import android.os.Build
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.graphics.asImageBitmap
import com.ecrew.protocol.AppInventory
import com.ecrew.protocol.GlobalActions
import com.ecrew.protocol.HandshakeClient
import com.ecrew.protocol.Messages
import com.ecrew.protocol.Msg
import com.ecrew.protocol.Session
import com.ecrew.protocol.StreamSession
import com.ecrew.protocol.Transport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.util.ArrayDeque
import java.util.Base64
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Owns one controller-side remote session end to end: transport connect, handshake,
 * the encrypted receive loop, keepalive, input forwarding, per-session audit (SQLite row +
 * JSONL), and clean teardown. The UI observes [state] and never touches sockets directly.
 *
 * Threading: connects and the reader run on the internal IO scope / a dedicated thread;
 * UI-initiated sends are queued onto a single writer thread (no socket I/O on the caller
 * thread, FIFO order preserved), and endSession flushes session_end before teardown.
 */
class RemoteSessionController(private val context: Context) {

    val state = mutableStateOf(RemoteUiState())
    val model: String = Build.MODEL ?: "Android"

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val db = RemoteSessionDb(context)
    private val auditRing = ArrayDeque<String>()
    private val finishLock = Any()

    /**
     * Single outbound writer. Every UI-initiated message is queued here so no socket
     * write ever runs on the caller (usually main) thread, and writes stay FIFO-ordered.
     */
    private val outbound = Executors.newSingleThreadExecutor { r ->
        Thread(r, "ecrew-remote-send").apply { isDaemon = true }
    }

    @Volatile
    private var session: Session? = null

    @Volatile
    private var transport: Transport? = null

    @Volatile
    private var abandoned = false

    @Volatile
    private var finished = false

    @Volatile
    private var lastPongAt = 0L

    @Volatile
    private var lastPingSentAt = 0L

    private var tickerJob: Job? = null
    private var appsTimeoutJob: Job? = null

    // ---------------------------------------------------------------- lifecycle

    fun start(target: RemoteTarget, code: String) {
        val phase = state.value.phase
        if (phase == RemotePhase.CONNECTING || phase == RemotePhase.ACTIVE) return
        abandoned = false
        finished = false
        synchronized(auditRing) { auditRing.clear() }
        state.value = RemoteUiState(phase = RemotePhase.CONNECTING, peer = target.label)
        scope.launch {
            val opened = openTransport(target, code)
            val openedSession = opened.getOrNull()
            if (openedSession == null) {
                if (!abandoned) {
                    state.value = state.value.copy(phase = RemotePhase.IDLE, error = friendly(opened.exceptionOrNull()))
                }
                return@launch
            }
            if (abandoned) {
                runCatching { openedSession.close() }
                return@launch
            }
            afterOpen(target, openedSession)
        }
    }

    /** Aborts an in-flight connect attempt; closing the transport unblocks the I/O. */
    fun cancelConnect() {
        if (state.value.phase != RemotePhase.CONNECTING) return
        abandoned = true
        runCatching { transport?.close() }
        state.value = state.value.copy(phase = RemotePhase.IDLE)
    }

    /** Clears the ended-session view so the feature returns to its tabs. */
    fun reset() {
        if (state.value.phase == RemotePhase.ACTIVE || state.value.phase == RemotePhase.CONNECTING) return
        state.value = RemoteUiState()
    }

    fun dispose() {
        runCatching { session?.close() }
        runCatching { transport?.close() }
        session = null
        transport = null
        appsTimeoutJob?.cancel()
        appsTimeoutJob = null
        outbound.shutdownNow()
        scope.cancel()
    }

    private suspend fun openTransport(target: RemoteTarget, code: String): Result<Session> = when (target) {
        is RemoteTarget.Lan -> LanTransport(target.host, target.port, code, model)
            .also { transport = it }.open()
        is RemoteTarget.Bluetooth -> {
            val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE)
                as? android.bluetooth.BluetoothManager)?.adapter
            if (adapter == null || !adapter.isEnabled) {
                Result.failure(IllegalStateException("Bluetooth is disabled"))
            } else {
                BluetoothTransport(adapter, target.address, code, model)
                    .also { transport = it }.open()
            }
        }
    }

    private fun afterOpen(target: RemoteTarget, opened: Session) {
        session = opened
        val sessionId = (opened as? StreamSession)?.sessionId ?: "local-${System.currentTimeMillis()}"
        val startedAt = System.currentTimeMillis()
        lastPongAt = startedAt
        lastPingSentAt = 0L
        runCatching { db.insertStart(sessionId, target.label, opened.transportName, startedAt) }
        state.value = state.value.copy(
            phase = RemotePhase.ACTIVE,
            sessionId = sessionId,
            transport = opened.transportName,
            peer = target.label
        )
        appendAudit(sessionId, "in", Msg.AUTH_OK, null)
        // Spec flow: streaming is requested right away; the agent asks its user
        // for the system capture consent on every stream_start.
        requestStreaming(true)
        Thread({ readerLoop(sessionId) }, "ecrew-remote-read").apply { isDaemon = true }.start()
        tickerJob = scope.launch { tickerLoop(opened) }
    }

    // ---------------------------------------------------------------- loops

    private fun readerLoop(sessionId: String) {
        val live = session ?: return
        try {
            while (true) {
                val message = live.receive(RECEIVE_TIMEOUT_MS) ?: continue
                val type = Messages.type(message) ?: continue
                when (type) {
                    Msg.SCREEN_FRAME -> {
                        onFrame(message)
                        val width = Messages.long(message, "w") ?: 0L
                        val height = Messages.long(message, "h") ?: 0L
                        appendAudit(sessionId, "in", type, "${width}x${height} frame")
                    }
                    Msg.PING -> {
                        lastPongAt = System.currentTimeMillis()
                        live.send(Messages.pong(Messages.long(message, "ts") ?: 0L))
                    }
                    Msg.PONG -> lastPongAt = System.currentTimeMillis()
                    Msg.SESSION_END -> {
                        finishSession(sessionId, "agent ended: " + (Messages.string(message, "reason") ?: "session_end"))
                        return
                    }
                    Msg.AUDIT_MARKER -> {
                        val note = Messages.string(message, "note")
                        appendAudit(sessionId, "in", type, note)
                        if (note != null && (note.contains("declined") || note.startsWith("screen capture stopped"))) {
                            state.value = state.value.copy(streaming = false, streamNotice = note)
                        }
                    }
                    Msg.APP_LIST -> onAppInventory(sessionId, message)
                    Msg.AUTH_OK -> appendAudit(sessionId, "in", type, null)
                    else -> appendAudit(sessionId, "in", type, Messages.string(message, "reason"))
                }
            }
        } catch (e: Exception) {
            if (!finished) {
                finishSession(sessionId, "connection lost" + (e.message?.let { ": $it" } ?: ""))
            }
        }
    }

    private suspend fun tickerLoop(live: Session) {
        while (true) {
            delay(TICK_MS)
            val now = System.currentTimeMillis()
            state.value = state.value.copy(bytesIn = live.bytesIn, bytesOut = live.bytesOut)
            if (now - lastPongAt > LIVENESS_TIMEOUT_MS) {
                finishSession(state.value.sessionId ?: "unknown", "timeout: peer stopped responding")
                return
            }
            if (now - lastPingSentAt >= PING_INTERVAL_MS) {
                live.send(Messages.ping(now))
                lastPingSentAt = now
            }
        }
    }

    private fun onFrame(message: Map<String, Any?>) {
        val jpegB64 = Messages.string(message, "jpeg") ?: return
        val width = Messages.long(message, "w")?.toInt() ?: 0
        val height = Messages.long(message, "h")?.toInt() ?: 0
        val bytes = try {
            Base64.getDecoder().decode(jpegB64)
        } catch (_: IllegalArgumentException) {
            null
        } ?: return
        val bitmap = try {
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
        } catch (_: Exception) {
            null
        } ?: return
        val current = state.value
        state.value = current.copy(
            frame = bitmap.asImageBitmap(),
            frameWidth = width,
            frameHeight = height,
            frames = current.frames + 1,
            streaming = true,
            lastFrameAt = System.currentTimeMillis(),
            streamNotice = null
        )
    }

    private fun finishSession(sessionId: String, reason: String) {
        synchronized(finishLock) {
            if (finished) return
            finished = true
        }
        tickerJob?.cancel()
        tickerJob = null
        appsTimeoutJob?.cancel()
        appsTimeoutJob = null
        val live = session
        val current = state.value
        val bytesIn = live?.bytesIn ?: current.bytesIn
        val bytesOut = live?.bytesOut ?: current.bytesOut
        runCatching { live?.close() }
        session = null
        runCatching { transport?.close() }
        transport = null
        runCatching {
            db.finish(sessionId, System.currentTimeMillis(), bytesIn, bytesOut, current.frames, reason)
        }
        appendAudit(sessionId, "local", Msg.SESSION_END, reason)
        state.value = current.copy(
            phase = RemotePhase.ENDED,
            streaming = false,
            endReason = reason,
            appsLoading = false
        )
    }

    // ---------------------------------------------------------------- sending

    fun requestStreaming(on: Boolean) {
        if (state.value.phase != RemotePhase.ACTIVE) return
        if (on) {
            send(Messages.streamStart())
            state.value = state.value.copy(
                streaming = false,
                streamNotice = "waiting for the device owner to accept the capture dialog"
            )
        } else {
            send(Messages.streamStop())
            state.value = state.value.copy(streaming = false, streamNotice = null)
        }
    }

    fun sendTap(normalizedX: Double, normalizedY: Double) {
        send(Messages.tap(normalizedX, normalizedY))
    }

    fun sendSwipe(x1: Double, y1: Double, x2: Double, y2: Double, durationMs: Long) {
        send(Messages.swipe(x1, y1, x2, y2, durationMs.coerceIn(1L, 10_000L)))
    }

    fun sendGlobalAction(action: String) {
        if (action in GlobalActions.ALL) send(Messages.globalAction(action))
    }

    fun sendText(text: String) {
        if (text.isNotEmpty()) send(Messages.textInput(text))
    }

    /**
     * Requests the agent's installed-app inventory. The agent answers only inside an
     * authenticated session; the response is validated/capped by [AppInventory.parse].
     */
    fun requestAppInventory() {
        if (state.value.phase != RemotePhase.ACTIVE || state.value.appsLoading) return
        appsTimeoutJob?.cancel()
        state.value = state.value.copy(appsLoading = true, appsError = null)
        send(Messages.appListRequest())
        appsTimeoutJob = scope.launch {
            delay(APP_LIST_TIMEOUT_MS)
            if (state.value.appsLoading) {
                state.value = state.value.copy(
                    appsLoading = false,
                    appsError = "No inventory response from the agent (timed out)."
                )
            }
        }
    }

    private fun onAppInventory(sessionId: String, message: Map<String, Any?>) {
        if (!state.value.appsLoading) {
            appendAudit(sessionId, "in", Msg.APP_LIST, "unsolicited response ignored")
            return
        }
        appsTimeoutJob?.cancel()
        appsTimeoutJob = null
        val snapshot = AppInventory.parse(message)
        if (snapshot == null) {
            appendAudit(sessionId, "in", Msg.APP_LIST, "unreadable response")
            state.value = state.value.copy(
                appsLoading = false,
                appsError = "The agent sent an unreadable app inventory."
            )
            return
        }
        val apps = AppInventory.sortedForDisplay(snapshot.entries)
        state.value = state.value.copy(
            apps = apps,
            appsTotal = snapshot.total,
            appsTruncated = snapshot.truncated,
            appsLoading = false,
            appsError = null,
            appsReceivedAt = System.currentTimeMillis()
        )
        appendAudit(sessionId, "in", Msg.APP_LIST, "${apps.size} of ${snapshot.total} apps")
    }

    fun endSession(reason: String = "user-ended") {
        val sessionId = state.value.sessionId ?: "unknown"
        if (finished) return
        if (state.value.phase == RemotePhase.ACTIVE) {
            // Flush the farewell message through the writer before the transport closes.
            sendAndWait(Messages.sessionEnd(reason))
        }
        finishSession(sessionId, reason)
    }

    private fun send(message: Map<String, Any?>) {
        val live = session ?: return
        val type = Messages.type(message) ?: return
        outbound.execute { deliver(live, message, type) }
    }

    /** Queues [message] and waits (bounded) for the writer to flush it - session-end path. */
    private fun sendAndWait(message: Map<String, Any?>): Boolean {
        val live = session ?: return false
        val type = Messages.type(message) ?: return false
        return try {
            outbound.submit(Callable { deliver(live, message, type) }).get(1, TimeUnit.SECONDS)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Runs on the writer thread: sends with a couple of cheap retries so a concurrent
     * ping/pong (writer lock held momentarily) cannot silently drop a user input.
     */
    private fun deliver(live: Session, message: Map<String, Any?>, type: String): Boolean {
        var sent = false
        var attempts = 0
        while (!sent && attempts < 3) {
            sent = runCatching { live.send(message) }.getOrDefault(false)
            if (!sent) {
                attempts += 1
                if (attempts < 3) Thread.sleep(BACKPRESSURE_RETRY_MS)
            }
        }
        if (sent) appendAudit(state.value.sessionId ?: "unknown", "out", type, null)
        return sent
    }

    // ---------------------------------------------------------------- audit helpers

    private fun appendAudit(sessionId: String, direction: String, type: String, note: String?) {
        val line = RemoteAudit.append(context, sessionId, direction, type, note)
        val snapshot: List<String>
        synchronized(auditRing) {
            auditRing.addLast(line)
            while (auditRing.size > AUDIT_RING_MAX) auditRing.removeFirst()
            snapshot = auditRing.toList()
        }
        state.value = state.value.copy(auditLines = snapshot)
    }

    private fun friendly(error: Throwable?): String = when (error) {
        null -> "connection failed"
        is HandshakeClient.HandshakeFailedException ->
            "pairing rejected: " + (error.message ?: "invalid code")
        is SocketTimeoutException ->
            "connection timed out"
        is ConnectException ->
            "agent not reachable (" + (error.message ?: "refused") + ")"
        is java.io.IOException ->
            error.message ?: "I/O error"
        else -> error.message ?: error.javaClass.simpleName
    }

    private companion object {
        const val RECEIVE_TIMEOUT_MS = 1_000L
        const val PING_INTERVAL_MS = 5_000L
        const val LIVENESS_TIMEOUT_MS = 15_000L
        const val TICK_MS = 1_000L
        const val AUDIT_RING_MAX = 120
        const val BACKPRESSURE_RETRY_MS = 15L
        const val APP_LIST_TIMEOUT_MS = 12_000L
    }
}
