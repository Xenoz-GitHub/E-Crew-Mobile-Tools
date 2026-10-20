package com.ecrew.toolkit.intercept

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import com.ecrew.toolkit.MainActivity
import com.ecrew.toolkit.audit.AuditStore

/** In-memory state shared by the foreground service and the Intercept tab. */
object InterceptionBus {
    val log = ProxyLog()
    @Volatile
    var running = false
    @Volatile
    var boundPort = 0
    @Volatile
    var upstream: String? = null
    @Volatile
    var error: String? = null
    @Volatile
    var globalProxyApplied = false
    @Volatile
    var globalProxyPrevious: String? = null
    @Volatile
    var sessionId: String = ""
}

class InterceptionProxyService : Service() {
    private var server: LocalProxyServer? = null
    private var stopping = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopEverything()
            return START_NOT_STICKY
        }
        startForeground(NOTIF_ID, notification("Interception proxy listening on 127.0.0.1"))
        if (server != null) return START_STICKY
        val store = AuditStore(this)
        val consented = try {
            InterceptionConsent.confirmedAt(store) != null
        } finally {
            store.close()
        }
        if (!consented) {
            InterceptionBus.error = "Interception consent has not been recorded. Nothing started."
            stopSelf()
            return START_NOT_STICKY
        }
        val requestedPort = intent?.getIntExtra(EXTRA_PORT, DEFAULT_PORT) ?: DEFAULT_PORT
        if (requestedPort !in 1024..65535) {
            InterceptionBus.error = "Proxy port must be 1024-65535."
            stopSelf()
            return START_NOT_STICKY
        }
        val upstreamText = intent?.getStringExtra(EXTRA_UPSTREAM)
        val upstream = try {
            upstreamText?.takeIf { it.isNotBlank() }?.let { UpstreamConfig.parse(it).endpoint }
        } catch (error: Exception) {
            InterceptionBus.error = error.message ?: "Invalid upstream."
            stopSelf()
            return START_NOT_STICKY
        }
        val sessionId = intent?.getStringExtra(EXTRA_SESSION) ?: InterceptionAudit.newSessionId()
        InterceptionBus.sessionId = sessionId
        val proxy = LocalProxyServer(port = requestedPort, upstream = upstream, log = InterceptionBus.log)
        return try {
            proxy.start()
            server = proxy
            InterceptionBus.running = true
            InterceptionBus.boundPort = proxy.boundPort
            InterceptionBus.upstream = upstreamText?.takeIf { it.isNotBlank() }
            InterceptionBus.error = null
            InterceptionAudit.append(
                this,
                sessionId,
                "proxy_start",
                mapOf(
                    "bind" to "127.0.0.1:${proxy.boundPort}",
                    "upstream" to (InterceptionBus.upstream ?: "direct (no upstream)")
                )
            )
            notifyUpdate()
            START_STICKY
        } catch (error: Exception) {
            InterceptionBus.error = error.message ?: "Proxy start failed."
            InterceptionBus.running = false
            stopSelf()
            START_NOT_STICKY
        }
    }

    override fun onDestroy() {
        stopEverything()
        super.onDestroy()
    }

    private fun stopEverything() {
        if (stopping) return
        stopping = true
        try {
            server?.stop()
        } catch (_: Exception) {
            // The listener may already be closed.
        }
        server = null
        InterceptionBus.running = false
        val session = InterceptionBus.sessionId
        val needsRestore = InterceptionBus.globalProxyApplied
        val previous = InterceptionBus.globalProxyPrevious
        val logEntries = InterceptionBus.log.size()
        // Shizuku binding may take seconds; keep it off the service main thread. The
        // foreground notification stays until the restore attempt finishes or times out.
        Thread({
            if (needsRestore) {
                try {
                    val controller = ShizukuProxyController(this)
                    try {
                        val result = controller.restore(previous)
                        InterceptionAudit.append(
                            this,
                            session,
                            "global_proxy_restore",
                            mapOf(
                                "success" to result.success.toString(),
                                "previous" to (previous ?: "null"),
                                "error" to (result.error ?: "")
                            )
                        )
                        if (result.success) {
                            InterceptionBus.globalProxyApplied = false
                            InterceptionBus.globalProxyPrevious = null
                        } else {
                            InterceptionBus.error = result.error
                        }
                    } finally {
                        controller.close()
                    }
                } catch (error: Exception) {
                    InterceptionBus.error = "Global proxy restore failed: " +
                        (error.message ?: error.javaClass.simpleName)
                }
            }
            InterceptionAudit.append(
                this,
                session,
                "proxy_stop",
                mapOf("log_entries" to logEntries.toString())
            )
            Handler(Looper.getMainLooper()).post {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }, "ecrew-proxy-restore").start()
    }

    private fun createChannel() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Interception proxy",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Loopback HTTP CONNECT proxy status and stop action"
        }
        manager.createNotificationChannel(channel)
    }

    @Suppress("DEPRECATION")
    private fun notification(text: String): Notification {
        val stop = Intent(this, InterceptionProxyService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPending = PendingIntent.getService(
            this,
            2,
            stop,
            PendingIntent.FLAG_UPDATE_CURRENT
        )
        val open = PendingIntent.getActivity(
            this,
            3,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("E-Crew interception proxy")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentIntent(open)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", stopPending)
            .setOngoing(true)
            .build()
    }

    private fun notifyUpdate() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(
            NOTIF_ID,
            notification(
                "Listening on 127.0.0.1:${InterceptionBus.boundPort}; TLS is not terminated"
            )
        )
    }

    companion object {
        const val ACTION_STOP = "com.ecrew.toolkit.intercept.STOP"
        const val EXTRA_PORT = "port"
        const val EXTRA_UPSTREAM = "upstream"
        const val EXTRA_SESSION = "session"
        const val DEFAULT_PORT = 8877
        private const val CHANNEL_ID = "interception_proxy"
        private const val NOTIF_ID = 0x1EC7

        fun start(context: Context, port: Int, upstream: String?, sessionId: String) {
            val intent = Intent(context, InterceptionProxyService::class.java).apply {
                putExtra(EXTRA_PORT, port)
                putExtra(EXTRA_UPSTREAM, upstream)
                putExtra(EXTRA_SESSION, sessionId)
            }
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, InterceptionProxyService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}
