package com.ecrew.toolkit.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.ecrew.toolkit.MainActivity
import com.ecrew.toolkit.capture.CaptureBus
import com.ecrew.toolkit.capture.CaptureEngine
import java.io.File
import java.io.RandomAccessFile
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Local loopback VPN (no external VPN server): routes device IPv4 traffic
 * through a user-space forwarder that records every packet to a PCAP file and
 * extracts DNS/HTTP/TLS metadata. IPv6 is not routed (bypasses untouched).
 */
class PacketCaptureService : VpnService() {

    private var engine: CaptureEngine? = null
    private var pcap: RandomAccessFile? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopCapture()
                stopForeground(android.app.Service.STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                // Foreground notification immediately (5s budget on API 26+)
                startForeground(NOTIF_ID, buildNotification("starting capture…"))
                startCapture()
            }
        }
        return START_STICKY
    }

    private fun startCapture() {
        if (engine != null) return
        try {
            // Read pre-VPN DNS servers BEFORE establish() (afterwards they are ours).
            val dns = originalDns()
            val builder = Builder()
                .setSession("ForensicCapture")
                .setMtu(1500)
                .addAddress("10.111.222.1", 32)
                .addRoute("0.0.0.0", 0)
            for (d in dns) builder.addDnsServer(d)
            if (dns.isEmpty()) builder.addDnsServer("8.8.8.8") // last resort

            val tun = builder.establish()
            if (tun == null) {
                CaptureBus.add("ERROR", "VpnService.establish() returned null")
                CaptureBus.running = false
                stopSelf()
                return
            }

            val base = getExternalFilesDir(null) ?: filesDir
            val dir = File(base, "captures").apply { mkdirs() }
            val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val file = File(dir, "capture_$stamp.pcap")
            val raf = RandomAccessFile(file, "rw")
            CaptureEngine.writePcapHeader(raf)

            CaptureBus.reset()
            CaptureBus.pcapPath = file.absolutePath
            CaptureBus.logPath = file.absolutePath.removeSuffix(".pcap") + ".log.txt"
            CaptureBus.running = true
            CaptureBus.add("INFO", "capture started (dns=${dns.joinToString()})")

            val eng = CaptureEngine(this, tun, raf)
            eng.start()
            engine = eng
            pcap = raf
            notifyUpdate()
        } catch (e: Exception) {
            CaptureBus.add("ERROR", "start: ${e.message}")
            CaptureBus.running = false
            stopSelf()
        }
    }

    private fun stopCapture() {
        engine?.stop()
        engine = null
        try { pcap?.fd?.sync() } catch (e: Exception) {}
        try { pcap?.close() } catch (e: Exception) {}
        pcap = null
        if (CaptureBus.running) CaptureBus.add("INFO", "capture stopped")
        CaptureBus.running = false
    }

    override fun onDestroy() {
        stopCapture()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopCapture()
        stopForeground(android.app.Service.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    @Suppress("DEPRECATION") // ConnectivityManager.allNetworks: no replacement before API 31;
    // the pre-VPN DNS read must enumerate every active network (declared before establish()).
    private fun originalDns(): List<String> = try {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        val out = LinkedHashSet<String>()
        for (net in cm.allNetworks) {
            cm.getLinkProperties(net)?.dnsServers?.forEach { a -> a.hostAddress?.let { out.add(it) } }
            if (out.isNotEmpty()) break
        }
        out.toList()
    } catch (e: Exception) {
        emptyList()
    }

    private fun notifyUpdate() {
        try {
            getSystemService(NotificationManager::class.java)
                .notify(NOTIF_ID, buildNotification(CaptureBus.pcapPath.substringAfterLast('/')))
        } catch (e: Exception) {
        }
    }

    private fun buildNotification(text: String): Notification {
        val channelId = "packet_capture"
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(channelId) == null) {
            nm.createNotificationChannel(
                NotificationChannel(
                    channelId, "Packet capture", NotificationManager.IMPORTANCE_LOW
                )
            )
        }
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, channelId)
            .setContentTitle("Forensic packet capture")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_manage)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_STOP = "com.ecrew.toolkit.action.STOP_CAPTURE"
        private const val NOTIF_ID = 41

        fun start(context: Context) {
            context.startForegroundService(
                Intent(context, PacketCaptureService::class.java)
            )
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, PacketCaptureService::class.java).setAction(ACTION_STOP)
            )
        }
    }
}


