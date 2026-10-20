package com.ecrew.agent

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.provider.Settings
import android.util.DisplayMetrics
import android.view.WindowManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.ecrew.protocol.AppInventory
import com.ecrew.protocol.Frames
import com.ecrew.protocol.HandshakeOutcome
import com.ecrew.protocol.HandshakeServer
import com.ecrew.protocol.Messages
import com.ecrew.protocol.Msg
import com.ecrew.protocol.ProtocolConstants
import com.ecrew.protocol.SecureFrameCodec
import com.ecrew.protocol.StreamSession
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Foreground service owning the whole remote-support lifecycle on the agent side:
 * LAN + Bluetooth listeners, handshake, the encrypted session loop, screen capture, and
 * the MANDATORY persistent notification (the transparency contract).
 *
 * Session model: one session at a time; the accept thread runs the session inline.
 * The session ends (cleanly or not) -> capture stops, the pairing code rotates, the
 * foreground service stops. The user re-arms listening from the status activity (F3).
 */
class RemoteAgentService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private var lanListener: LanListener? = null
    private var btListener: BtListener? = null
    private var handshakeServer: HandshakeServer? = null
    private var captureEngine: ScreenCaptureEngine? = null

    @Volatile
    private var activeSession: StreamSession? = null

    @Volatile
    private var activeSessionId: String? = null

    @Volatile
    private var lastPongAt = 0L

    @Volatile
    private var lastPingSentAt = 0L

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startListening()
            ACTION_STOP -> {
                stopEverything()
                stopSelf()
            }
            ACTION_END_SESSION -> endSessionByUser()
            ACTION_NEW_CODE -> rotateCode(burned = false)
            ACTION_CAPTURE_RESULT -> {
                // Process-local handoff (see deliverCaptureResult): avoids the deprecated
                // parcelable read API; activity and service share one process.
                val data = pendingCaptureData
                pendingCaptureData = null
                onCaptureResult(intent.getIntExtra(EXTRA_RESULT_CODE, Activity.RESULT_CANCELED), data)
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopEverything()
        scope.cancel()
        super.onDestroy()
    }

    // ------------------------------------------------------------------ listening

    private fun startListening() {
        if (lanListener != null) return

        if (Prefs.adbHardening(this) && isAdbEnabled()) {
            AgentRuntime.lastNotice = getString(R.string.status_adb_refused)
            AgentRuntime.notifyChanged()
            stopSelf()
            return
        }

        AgentRuntime.operatorName = Prefs.operatorName(this)
        AgentRuntime.lastNotice = null
        handshakeServer = HandshakeServer(Prefs.ensurePairingCode(this))

        startForeground(NOTIFICATION_ID, buildNotification(waiting = true))

        val lan = LanListener(this, ::onLanClient)
        if (lan.start()) {
            lanListener = lan
            AgentRuntime.lanEndpoint = lan.localAddress?.let { "$it:${lan.port}" }
        }
        val bt = BtListener(this, ::onBtClient)
        if (bt.canListen() && bt.start()) {
            btListener = bt
        }

        AgentRuntime.listening = true
        AgentRuntime.notifyChanged()
    }

    private fun onLanClient(socket: Socket) {
        try {
            socket.soTimeout = HANDSHAKE_TIMEOUT_MS.toInt()
            val input = DataInputStream(BufferedInputStream(socket.getInputStream()))
            val output = DataOutputStream(BufferedOutputStream(socket.getOutputStream()))
            runSession("lan", socket.inetAddress?.hostAddress ?: "lan", input, output, socket::close)
        } catch (_: Exception) {
            runCatching { socket.close() }
        }
    }

    private fun onBtClient(socket: BluetoothSocket) {
        try {
            val input = DataInputStream(BufferedInputStream(socket.inputStream))
            val output = DataOutputStream(BufferedOutputStream(socket.outputStream))
            runSession("bluetooth", socket.remoteDevice?.address ?: "bluetooth", input, output, socket::close)
        } catch (_: Exception) {
            runCatching { socket.close() }
        }
    }

    // ------------------------------------------------------------------ session

    private fun runSession(
        transport: String,
        remote: String,
        input: DataInputStream,
        output: DataOutputStream,
        closeSocket: () -> Unit
    ) {
        val server = handshakeServer ?: run {
            closeSocket()
            return
        }
        // Handshake watchdog: Bluetooth sockets have no read timeout, so a silent peer must
        // not be able to park the accept thread forever.
        val handshakeDone = AtomicBoolean(false)
        val watchdog = scope.launch {
            delay(HANDSHAKE_TIMEOUT_MS)
            if (!handshakeDone.get()) closeSocket()
        }
        var session: StreamSession? = null
        try {
            val hello = Frames.readPlain(input, ProtocolConstants.MAX_HANDSHAKE_BYTES)
            if (Messages.type(hello) != Msg.HELLO) {
                runCatching { Frames.writePlain(output, Messages.authFail("expected hello")) }
                return
            }
            when (val outcome = server.onHello(hello)) {
                is HandshakeOutcome.RateLimited -> {
                    runCatching { Frames.writePlain(output, Messages.authFail("rate limited")) }
                }
                is HandshakeOutcome.RejectedRetryable -> {
                    runCatching { Frames.writePlain(output, Messages.authFail(outcome.reason)) }
                }
                is HandshakeOutcome.RejectedFatal -> {
                    runCatching { Frames.writePlain(output, Messages.authFail(outcome.reason)) }
                    rotateCode(burned = true)
                }
                is HandshakeOutcome.Accepted -> {
                    val sessionId = UUID.randomUUID().toString()
                    val codec = SecureFrameCodec(outcome.sessionKey)
                    val streamSession = StreamSession(input, output, codec, transport, remote, sessionId)
                    session = streamSession
                    Frames.writePlain(output, Messages.authOk(sessionId))
                    handshakeDone.set(true)
                    // Post-handshake reads may block or time out depending on the
                    // transport; keepalive/liveness are driven by the ticker coroutine
                    // in runActiveSession, so the read loop is timeout-agnostic.
                    runActiveSession(streamSession, sessionId)
                }
            }
        } catch (_: Exception) {
            // Handshake/IO failure: the socket closes below; nothing else to clean.
        } finally {
            handshakeDone.set(true)
            watchdog.cancel()
            session?.close()
            runCatching { closeSocket() }
        }
    }

    private fun runActiveSession(session: StreamSession, sessionId: String) {
        activeSession = session
        activeSessionId = sessionId
        lastPongAt = System.currentTimeMillis()
        lastPingSentAt = 0L
        AuditLog.append(this, sessionId, "in", Msg.HELLO)
        AuditLog.append(this, sessionId, "out", Msg.AUTH_OK)
        AgentRuntime.sessionActive = true
        AgentRuntime.notifyChanged()
        updateNotification(waiting = false)

        val reader = Thread({ readLoop(session, sessionId) }, "ecrew-session-read")
        reader.start()

        val ticker = scope.launch {
            while (isActive) {
                delay(TICK_MS)
                val current = activeSession ?: break
                val now = System.currentTimeMillis()
                if (now - lastPongAt > ProtocolConstants.PING_INTERVAL_MS * ProtocolConstants.MAX_MISSED_PONGS) {
                    current.close()
                    break
                }
                if (now - lastPingSentAt >= ProtocolConstants.PING_INTERVAL_MS) {
                    current.send(Messages.ping(now))
                    lastPingSentAt = now
                }
            }
        }

        try {
            reader.join()
        } catch (_: InterruptedException) {
        }
        ticker.cancel()
        finishSession(sessionId)
    }

    private fun readLoop(session: StreamSession, sessionId: String) {
        try {
            while (true) {
                val message = session.receive(0L) ?: continue
                val type = Messages.type(message) ?: continue
                AuditLog.append(this, sessionId, "in", type, Messages.string(message, "note"))
                when (type) {
                    Msg.PING -> {
                        lastPongAt = System.currentTimeMillis()
                        session.send(Messages.pong(Messages.long(message, "ts") ?: 0L))
                    }
                    Msg.PONG -> lastPongAt = System.currentTimeMillis()
                    Msg.TAP -> dispatchTap(message)
                    Msg.SWIPE -> dispatchSwipe(message)
                    Msg.GLOBAL_ACTION -> dispatchGlobalAction(message)
                    Msg.TEXT_INPUT -> dispatchText(message)
                    Msg.STREAM_START -> requestScreenCapture()
                    Msg.STREAM_STOP -> stopScreenCapture()
                    Msg.APP_LIST_REQ -> sendAppInventory(session, sessionId)
                    Msg.SESSION_END -> return
                    Msg.HELLO -> {
                        // Protocol violation: hello is only legal before auth_ok.
                        runCatching { session.send(Messages.sessionEnd("hello-after-auth")) }
                        return
                    }
                    else -> Unit // screen_frame never arrives agent-bound; audit_marker logged above
                }
            }
        } catch (_: Exception) {
            // Socket closed, tampered frame, or replay attempt: the session ends.
        }
    }

    private fun finishSession(sessionId: String) {
        stopScreenCapture()
        activeSession = null
        activeSessionId = null
        AgentRuntime.sessionActive = false
        AgentRuntime.screenStreaming = false
        AgentRuntime.notifyChanged()
        AuditLog.append(this, sessionId, "out", Msg.SESSION_END)
        // Fresh secret for the next session (recorded decision F2).
        Prefs.regeneratePairingCode(this)
        stopEverything()
        stopSelf()
    }

    private fun endSessionByUser() {
        val session = activeSession
        if (session == null) {
            stopEverything()
            stopSelf()
            return
        }
        val sessionId = activeSessionId ?: "unknown"
        AuditLog.append(this, sessionId, "out", Msg.SESSION_END, "user-ended")
        runCatching { session.send(Messages.sessionEnd("user-ended")) }
        session.close()
    }

    // ------------------------------------------------------------------ injection dispatch

    private fun dispatchTap(message: Map<String, Any?>) {
        val service = EcrewAccessibilityService.instance() ?: return
        val x = Messages.double(message, "x") ?: return
        val y = Messages.double(message, "y") ?: return
        val (width, height) = screenMetrics()
        service.tap(x, y, width, height)
    }

    private fun dispatchSwipe(message: Map<String, Any?>) {
        val service = EcrewAccessibilityService.instance() ?: return
        val x1 = Messages.double(message, "x1") ?: return
        val y1 = Messages.double(message, "y1") ?: return
        val x2 = Messages.double(message, "x2") ?: return
        val y2 = Messages.double(message, "y2") ?: return
        val duration = Messages.long(message, "durationMs") ?: 200L
        val (width, height) = screenMetrics()
        service.swipe(x1, y1, x2, y2, duration, width, height)
    }

    private fun dispatchGlobalAction(message: Map<String, Any?>) {
        val service = EcrewAccessibilityService.instance() ?: return
        val action = Messages.string(message, "action") ?: return
        service.globalAction(action)
    }

    private fun dispatchText(message: Map<String, Any?>) {
        val service = EcrewAccessibilityService.instance() ?: return
        val text = Messages.string(message, "text") ?: return
        service.setFocusedText(text)
    }

    // ------------------------------------------------------------------ app inventory

    /**
     * Answers one explicit `app_list_req`. The request is only handled here, inside the
     * authenticated session read loop; the response is capped and audit-logged with counts
     * (never the app names). The inventory is not stored on the agent.
     */
    private fun sendAppInventory(session: StreamSession, sessionId: String) {
        val all = AppInventoryCollector.collect(this)
        val entries = all.take(AppInventory.MAX_ENTRIES)
        val snapshot = AppInventory.Snapshot(
            entries = entries,
            total = all.size,
            truncated = all.size > entries.size
        )
        val sent = runCatching { session.send(AppInventory.toMessage(snapshot)) }.getOrDefault(false)
        AuditLog.append(
            this,
            sessionId,
            "out",
            Msg.APP_LIST,
            "${entries.size} of ${all.size} apps" + if (sent) "" else " (send failed)"
        )
    }

    // ------------------------------------------------------------------ capture

    private fun requestScreenCapture() {
        val intent = Intent(this, AgentStatusActivity::class.java)
            .setAction(AgentStatusActivity.ACTION_REQUEST_CAPTURE)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        runCatching { startActivity(intent) }
    }

    private fun onCaptureResult(resultCode: Int, data: Intent?) {
        val session = activeSession ?: return
        val sessionId = activeSessionId ?: return
        if (resultCode == Activity.RESULT_OK && data != null) {
            captureEngine?.stop()
            val engine = ScreenCaptureEngine(
                context = this,
                frameSink = { jpeg, width, height ->
                    session.send(
                        Messages.screenFrame(
                            Base64.getEncoder().encodeToString(jpeg),
                            width.toLong(),
                            height.toLong(),
                            System.currentTimeMillis()
                        )
                    )
                },
                onStopped = { reason ->
                    captureEngine = null
                    AgentRuntime.screenStreaming = false
                    AgentRuntime.notifyChanged()
                    AuditLog.append(this, sessionId, "out", Msg.AUDIT_MARKER, "screen capture stopped: $reason")
                    runCatching { session.send(Messages.auditMarker("screen capture stopped: $reason")) }
                }
            )
            captureEngine = engine
            engine.start(resultCode, data)
            AgentRuntime.screenStreaming = true
            AgentRuntime.notifyChanged()
        } else {
            // Spec: decline is recorded, streaming is not started.
            AuditLog.append(this, sessionId, "out", Msg.AUDIT_MARKER, "user declined screen capture")
            runCatching { session.send(Messages.auditMarker("user declined screen capture")) }
        }
    }

    private fun stopScreenCapture() {
        captureEngine?.stop()
        captureEngine = null
        AgentRuntime.screenStreaming = false
    }

    // ------------------------------------------------------------------ lifecycle helpers

    private fun rotateCode(burned: Boolean) {
        val newCode = Prefs.regeneratePairingCode(this)
        handshakeServer = HandshakeServer(newCode)
        if (burned) {
            AgentRuntime.lastNotice = getString(R.string.status_code_burned)
        }
        if (AgentRuntime.listening) {
            updateNotification(waiting = true)
        }
        AgentRuntime.notifyChanged()
    }

    private fun stopEverything() {
        stopScreenCapture()
        activeSession?.close()
        activeSession = null
        activeSessionId = null
        lanListener?.stop()
        lanListener = null
        btListener?.stop()
        btListener = null
        handshakeServer = null
        AgentRuntime.listening = false
        AgentRuntime.sessionActive = false
        AgentRuntime.screenStreaming = false
        AgentRuntime.lanEndpoint = null
        AgentRuntime.bluetoothListening = false
        AgentRuntime.notifyChanged()
        stopForeground(Service.STOP_FOREGROUND_REMOVE)
    }

    private fun isAdbEnabled(): Boolean =
        Settings.Global.getInt(contentResolver, Settings.Global.ADB_ENABLED, 0) == 1

    @Suppress("DEPRECATION") // defaultDisplay.getRealMetrics: correct for the target-28 legacy model
    private fun screenMetrics(): Pair<Int, Int> {
        val windowManager = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val metrics = DisplayMetrics()
        windowManager.defaultDisplay.getRealMetrics(metrics)
        return metrics.widthPixels to metrics.heightPixels
    }

    // ------------------------------------------------------------------ notification

    private fun createChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        )
        channel.description = getString(R.string.notification_channel_description)
        manager.createNotificationChannel(channel)
    }

    private fun updateNotification(waiting: Boolean) {
        try {
            NotificationManagerCompat.from(this).notify(NOTIFICATION_ID, buildNotification(waiting))
        } catch (_: SecurityException) {
            // POST_NOTIFICATIONS missing on 33+: the foreground service still runs and the
            // platform enforces the notification requirement itself.
        }
    }

    private fun buildNotification(waiting: Boolean): Notification {
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, AgentStatusActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val endIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, RemoteAgentService::class.java).setAction(ACTION_END_SESSION),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_agent_notify)
            .setOngoing(true)
            .setShowWhen(false)
            .setOnlyAlertOnce(true)
            .setContentIntent(contentIntent)
            .addAction(0, getString(R.string.notification_end_session), endIntent)
        if (waiting) {
            builder.setContentTitle(getString(R.string.notification_waiting_title))
            builder.setContentText(getString(R.string.notification_waiting_text, Prefs.pairingCode(this)))
        } else {
            builder.setContentTitle(getString(R.string.notification_active_title))
            builder.setContentText(getString(R.string.notification_active_text, AgentRuntime.operatorName))
        }
        return builder.build()
    }

    companion object {
        const val ACTION_START = "com.ecrew.agent.action.START"
        const val ACTION_STOP = "com.ecrew.agent.action.STOP"
        const val ACTION_END_SESSION = "com.ecrew.agent.action.END_SESSION"
        const val ACTION_NEW_CODE = "com.ecrew.agent.action.NEW_CODE"
        const val ACTION_CAPTURE_RESULT = "com.ecrew.agent.action.CAPTURE_RESULT"
        const val EXTRA_RESULT_CODE = "result_code"

        private const val CHANNEL_ID = "ecrew_remote"
        private const val NOTIFICATION_ID = 41
        private const val HANDSHAKE_TIMEOUT_MS = 10_000L
        private const val TICK_MS = 1000L

        /** Process-local handoff of the MediaProjection consent result (same process). */
        @Volatile
        private var pendingCaptureData: Intent? = null

        fun start(context: Context) {
            ContextCompat.startForegroundService(
                context,
                Intent(context, RemoteAgentService::class.java).setAction(ACTION_START)
            )
        }

        fun stop(context: Context) {
            runCatching {
                context.startService(Intent(context, RemoteAgentService::class.java).setAction(ACTION_STOP))
            }
        }

        fun endSession(context: Context) {
            runCatching {
                context.startService(Intent(context, RemoteAgentService::class.java).setAction(ACTION_END_SESSION))
            }
        }

        fun newCode(context: Context) {
            runCatching {
                context.startService(Intent(context, RemoteAgentService::class.java).setAction(ACTION_NEW_CODE))
            }
        }

        fun deliverCaptureResult(context: Context, resultCode: Int, data: Intent?) {
            pendingCaptureData = data
            val intent = Intent(context, RemoteAgentService::class.java)
                .setAction(ACTION_CAPTURE_RESULT)
                .putExtra(EXTRA_RESULT_CODE, resultCode)
            runCatching { context.startService(intent) }
        }
    }
}
