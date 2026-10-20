package com.ecrew.toolkit.messaging

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothSocket
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import com.ecrew.toolkit.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * Foreground-service core of peer messaging (design note, "Transports" + "Delivery
 * engine"). Owns everything socket-shaped: the LAN listener + discovery, the Bluetooth
 * RFCOMM server, outbound delivery sessions and the outbox pump. The UI only writes to
 * the database and observes [MessagingBus].
 *
 * Modes: visibility ON = foreground + beaconing + listening; screen open = listening only
 * (no beacon, no foreground). Sessions are short-lived and re-established on demand.
 */
class MessagingService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val stateLock = Any()

    private lateinit var db: MessagingDb
    private lateinit var prefs: MessagingPrefs
    private lateinit var identity: MessagingIdentity
    private lateinit var bt: BluetoothLink
    private val limiter = SpamLimiter()

    @Volatile
    private var beaconing = false

    @Volatile
    private var foregroundNow = false

    @Volatile
    private var btServing = false

    private var lan: LanDiscovery? = null
    private var lanServer: ServerSocket? = null
    private var pumpJob: Job? = null
    private var scanReceiver: BroadcastReceiver? = null
    private var bondReceiver: BroadcastReceiver? = null

    private var lastLanRaw: List<LanDiscovery.LanePeer> = emptyList()
    private var lanPeers: List<NearbyPeer> = emptyList()
    private val btKnown = LinkedHashMap<String, NearbyPeer>()
    private val activePeers = HashSet<String>()
    private val connectFails = HashMap<String, Pair<Int, Long>>()
    private var inboundSessions = 0

    override fun onCreate() {
        super.onCreate()
        db = MessagingDb.get(this)
        prefs = MessagingPrefs(this)
        identity = IdentityStore.load(this)
        bt = BluetoothLink(this)
        MessagingBus.visible = prefs.visible
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_ENABLE_VISIBLE -> {
                prefs.visible = true
                ensureRunning(beacon = true)
            }
            ACTION_LISTEN -> ensureRunning(beacon = prefs.visible)
            ACTION_DISABLE -> {
                prefs.visible = false
                stopEverything()
                stopSelf()
            }
            ACTION_SCREEN_CLOSED -> if (!prefs.visible) {
                stopEverything()
                stopSelf()
            }
            ACTION_REFRESH -> remapLanPeers()
            ACTION_BT_SCAN -> startBtScan()
            ACTION_BT_PAIR -> pairBt(intent.getStringExtra(EXTRA_ADDRESS))
            ACTION_PROBE_BT -> probeBt(intent.getStringExtra(EXTRA_ADDRESS))
            ACTION_IDENTIFY_LAN -> identifyLan(
                intent.getStringExtra(EXTRA_HOST),
                intent.getIntExtra(EXTRA_PORT, 0)
            )
            else -> ensureRunning(beacon = prefs.visible)
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopEverything()
        super.onDestroy()
    }

    // ---------------------------------------------------------------- modes

    private fun ensureRunning(beacon: Boolean) {
        if (!beacon && foregroundNow) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            foregroundNow = false
        }
        if (beacon && !foregroundNow) {
            startForeground(NOTIF_VISIBLE, buildVisibleNotification())
            foregroundNow = true
        }
        if (beaconing != beacon || lan == null) {
            beaconing = beacon
            lan?.stop()
            val discovery = LanDiscovery(this)
            discovery.start(
                beacon = if (beacon) {
                    LanDiscovery.BeaconProfile(prefs.displayName, identity.fingerprint, MessagingProtocol.TCP_PORT)
                } else {
                    null
                },
                onChanged = { peers -> onLanPeers(peers) }
            )
            lan = discovery
        }
        startLanServer()
        if (!btServing) btServing = bt.startServer { socket -> acceptBluetooth(socket) }
        registerBondReceiver()
        startPump()
        MessagingBus.visible = beacon
    }

    private fun stopEverything() {
        pumpJob?.cancel()
        pumpJob = null
        runCatching { lanServer?.close() }
        lanServer = null
        lan?.stop()
        lan = null
        if (btServing) {
            bt.stopServer()
            btServing = false
        }
        stopBtScan()
        unregisterBondReceiver()
        synchronized(stateLock) {
            lastLanRaw = emptyList()
            lanPeers = emptyList()
            btKnown.clear()
            activePeers.clear()
            connectFails.clear()
        }
        MessagingBus.nearby = emptyList()
        MessagingBus.btDiscovered = emptyList()
        MessagingBus.btScanning = false
        MessagingBus.btBusyAddress = null
    }

    // ---------------------------------------------------------------- LAN

    private fun onLanPeers(peers: List<LanDiscovery.LanePeer>) {
        synchronized(stateLock) { lastLanRaw = peers }
        remapLanPeers()
    }

    private fun remapLanPeers() {
        scope.launch {
            val raw = synchronized(stateLock) { lastLanRaw }
            val mapped = raw.mapNotNull { peer ->
                val fingerprint = peer.fingerprint
                val row = fingerprint?.let { db.peer(it) }
                if (row?.blocked == true) return@mapNotNull null
                NearbyPeer(
                    id = fingerprint ?: ("lan:" + peer.host + ":" + peer.port),
                    fingerprint = fingerprint,
                    name = row?.displayName ?: peer.name,
                    transport = MsgTransport.WIFI,
                    host = peer.host,
                    port = peer.port,
                    verified = row?.verified == true
                )
            }
            synchronized(stateLock) { lanPeers = mapped }
            publishNearby()
        }
    }

    private fun publishNearby() {
        val merged = ArrayList<NearbyPeer>()
        val seen = HashSet<String>()
        synchronized(stateLock) {
            for (peer in lanPeers) if (seen.add(peer.id)) merged.add(peer)
            for (peer in btKnown.values) if (seen.add(peer.id)) merged.add(peer)
        }
        MessagingBus.nearby = merged
    }

    private fun startLanServer() {
        if (lanServer != null) return
        val server = try {
            ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(MessagingProtocol.TCP_PORT))
            }
        } catch (_: Exception) {
            return
        }
        lanServer = server
        scope.launch {
            while (isActive) {
                val socket = try {
                    withContext(Dispatchers.IO) { server.accept() }
                } catch (_: Exception) {
                    if (!isActive) return@launch
                    delay(500)
                    continue
                }
                try {
                    socket.tcpNoDelay = true
                    socket.soTimeout = MessagingProtocol.HANDSHAKE_TIMEOUT_MS.toInt()
                    acceptLan(socket)
                } catch (_: Exception) {
                    runCatching { socket.close() }
                }
            }
        }
    }

    private fun acceptLan(socket: Socket) {
        if (!acquireInbound()) {
            runCatching { socket.close() }
            return
        }
        scope.launch {
            try {
                handleInbound(socket.getInputStream(), socket.getOutputStream(), socket, "lan", null)
            } finally {
                releaseInbound()
            }
        }
    }

    // ---------------------------------------------------------------- Bluetooth

    private fun acceptBluetooth(socket: BluetoothSocket) {
        if (!acquireInbound()) {
            runCatching { socket.close() }
            return
        }
        val address = try {
            socket.remoteDevice?.address
        } catch (_: Exception) {
            null
        }
        scope.launch {
            try {
                handleInbound(socket.inputStream, socket.outputStream, socket, "bluetooth", address)
            } catch (_: Exception) {
                runCatching { socket.close() }
            } finally {
                releaseInbound()
            }
        }
    }

    private fun startBtScan() {
        if (MessagingBus.btScanning) return
        scanReceiver?.let { bt.stopDiscovery(it) }
        MessagingBus.btDiscovered = emptyList()
        val receiver = bt.watchDiscovery(
            onFound = { device -> onBtDeviceFound(device) },
            onFinished = { stopBtScan() },
            onBondStateChanged = { device, state -> onBondStateChanged(device, state) }
        )
        if (receiver == null) {
            MessagingBus.setStatus("Bluetooth scan unavailable (radio off or permission missing)")
            return
        }
        scanReceiver = receiver
        MessagingBus.btScanning = true
        MessagingBus.setStatus("Scanning for Bluetooth devices...")
    }

    private fun stopBtScan() {
        scanReceiver?.let { bt.stopDiscovery(it) }
        scanReceiver = null
        MessagingBus.btScanning = false
    }

    @SuppressLint("MissingPermission") // legacy BT permissions (targetSdk 28), guarded by try/catch
    private fun onBtDeviceFound(device: BluetoothDevice) {
        val address = try {
            device.address
        } catch (_: Exception) {
            return
        }
        if (address.isBlank()) return
        val bonded = try {
            device.bondState == BluetoothDevice.BOND_BONDED
        } catch (_: Exception) {
            false
        }
        val name = try {
            device.name?.takeIf { it.isNotBlank() } ?: "Unnamed device"
        } catch (_: Exception) {
            "Unnamed device"
        }
        val current = MessagingBus.btDiscovered
        if (current.any { it.address == address }) return
        MessagingBus.btDiscovered = current + BtDeviceInfo(
            name = name,
            address = address,
            bonded = bonded,
            busy = address == MessagingBus.btBusyAddress
        )
    }

    @SuppressLint("MissingPermission") // legacy BT permissions (targetSdk 28), guarded by try/catch
    private fun onBondStateChanged(device: BluetoothDevice, state: Int) {
        val address = try {
            device.address
        } catch (_: Exception) {
            return
        }
        val name = try {
            device.name ?: address
        } catch (_: Exception) {
            address
        }
        when (state) {
            BluetoothDevice.BOND_BONDED -> MessagingBus.setStatus("Paired with $name - tap Connect")
            BluetoothDevice.BOND_NONE -> MessagingBus.setStatus("Pairing with $name was cancelled or failed")
        }
        // Refresh the bonded flag in the discovered list.
        MessagingBus.btDiscovered = MessagingBus.btDiscovered.map { info ->
            if (info.address == address) {
                info.copy(bonded = state == BluetoothDevice.BOND_BONDED)
            } else {
                info
            }
        }
    }

    private fun pairBt(address: String?) {
        if (address.isNullOrBlank()) return
        val ok = bt.createBond(address)
        MessagingBus.setStatus(
            if (ok) "Pairing with ${bt.deviceName(address)} - confirm the system dialog"
            else "Pairing could not be started for ${bt.deviceName(address)}"
        )
    }

    private fun probeBt(address: String?) {
        if (address.isNullOrBlank()) return
        if (MessagingBus.btBusyAddress != null) return
        MessagingBus.btBusyAddress = address
        val name = bt.deviceName(address)
        MessagingBus.setStatus("Connecting to $name...")
        scope.launch {
            try {
                val connected = runInitiatorSession(Endpoint.Bt(address))
                MessagingBus.setStatus(
                    if (connected) "Connected to $name"
                    else "Could not reach $name - is E-Crew Chat open on that device?"
                )
            } finally {
                MessagingBus.btBusyAddress = null
                MessagingBus.btDiscovered = MessagingBus.btDiscovered.map { info ->
                    if (info.address == address) info.copy(busy = false) else info
                }
            }
        }
    }

    private fun identifyLan(host: String?, port: Int) {
        if (host.isNullOrBlank() || port !in 1..65535) return
        MessagingBus.setStatus("Connecting to $host:$port...")
        scope.launch {
            val connected = runInitiatorSession(Endpoint.Lan(host, port))
            MessagingBus.setStatus(
                if (connected) "Connected to the E-Crew user at $host" else "Could not reach $host:$port"
            )
        }
    }

    // ---------------------------------------------------------------- sessions

    private val sessionEvents = object : PeerSession.Events {
        override fun onStoreChanged() {
            MessagingBus.bump()
        }

        override fun onIncomingStored(peer: PeerRow, row: MessageRow) {
            MessagingBus.bump()
            notifyIncoming(peer, row)
        }
    }

    private sealed class Endpoint {
        class Lan(val host: String, val port: Int) : Endpoint()
        class Bt(val address: String) : Endpoint()
    }

    private fun sessionFor(
        input: InputStream,
        output: OutputStream,
        closeable: Closeable,
        transport: String
    ): PeerSession = PeerSession(
        rawInput = input,
        rawOutput = output,
        closeable = closeable,
        transportName = transport,
        identity = identity,
        displayName = prefs.displayName,
        store = db,
        limiter = limiter,
        clock = System::currentTimeMillis,
        events = sessionEvents
    )

    /** Accepted (responder) session; returns when the session ends. */
    private fun handleInbound(
        input: InputStream,
        output: OutputStream,
        closeable: Closeable,
        transport: String,
        btAddress: String?
    ) {
        val session = sessionFor(input, output, closeable, transport)
        try {
            val peer = session.handshake(initiator = false)
            if (btAddress != null) rememberBtPeer(peer, btAddress)
            MessagingBus.bump()
            session.run()
        } catch (_: Exception) {
            // Session errors are contained to this connection.
        } finally {
            session.close()
        }
    }

    /** Outbound (initiator) session; returns true when the handshake succeeded. */
    private suspend fun runInitiatorSession(endpoint: Endpoint): Boolean = withContext(Dispatchers.IO) {
        var connected = false
        var session: PeerSession? = null
        try {
            session = when (endpoint) {
                is Endpoint.Lan -> {
                    val socket = Socket()
                    socket.tcpNoDelay = true
                    socket.connect(
                        InetSocketAddress(endpoint.host, endpoint.port),
                        LAN_CONNECT_TIMEOUT_MS.toInt()
                    )
                    socket.soTimeout = MessagingProtocol.HANDSHAKE_TIMEOUT_MS.toInt()
                    sessionFor(socket.getInputStream(), socket.getOutputStream(), socket, "lan")
                }
                is Endpoint.Bt -> {
                    val socket = bt.connect(endpoint.address).getOrElse { throw it }
                    sessionFor(socket.inputStream, socket.outputStream, socket, "bluetooth")
                }
            }
            val peer = session.handshake(initiator = true)
            connected = true
            if (endpoint is Endpoint.Bt) rememberBtPeer(peer, endpoint.address)
            MessagingBus.bump()
            session.run()
        } catch (_: Exception) {
            // Delivery failures surface through queue state and the pump backoff.
        } finally {
            session?.close()
        }
        connected
    }

    private fun rememberBtPeer(peer: PeerRow, address: String) {
        if (peer.btAddress != address) db.setBtAddress(peer.id, address)
        val updated = db.peer(peer.id) ?: peer
        synchronized(stateLock) {
            btKnown[peer.id] = NearbyPeer(
                id = peer.id,
                fingerprint = peer.id,
                name = updated.displayName,
                transport = MsgTransport.BLUETOOTH,
                address = address,
                verified = updated.verified
            )
        }
        publishNearby()
        MessagingBus.setStatus("Connected to ${updated.displayName} over Bluetooth")
    }

    private fun acquireInbound(): Boolean = synchronized(stateLock) {
        if (inboundSessions >= MessagingProtocol.MAX_INBOUND_SESSIONS) return false
        inboundSessions += 1
        true
    }

    private fun releaseInbound() {
        synchronized(stateLock) { if (inboundSessions > 0) inboundSessions -= 1 }
    }

    // ---------------------------------------------------------------- outbox pump

    private fun startPump() {
        if (pumpJob != null) return
        pumpJob = scope.launch {
            var tick = 0
            while (isActive) {
                tick += 1
                runCatching { pumpOnce(tick) }
                delay(PUMP_TICK_MS)
            }
        }
    }

    private fun pumpOnce(tick: Int) {
        val now = System.currentTimeMillis()
        if (tick % EXPIRY_EVERY_TICKS == 0) {
            val expired = db.expireOutgoing(now, MessagingProtocol.OUTBOX_EXPIRY_MS)
            if (expired > 0) MessagingBus.bump()
        }
        for (peerId in db.peersWithPending()) {
            if (db.peer(peerId)?.blocked == true) continue
            if (!acquireOutbound(peerId)) continue
            val pending = db.outgoingPending(peerId)
            if (Outbox.due(pending, now).isEmpty()) {
                releaseOutbound(peerId)
                continue
            }
            val endpoint = endpointFor(peerId)
            if (endpoint == null || connectBackoffActive(peerId, now)) {
                releaseOutbound(peerId)
                continue
            }
            scope.launch {
                var connected = false
                try {
                    connected = runInitiatorSession(endpoint)
                } finally {
                    if (connected) markConnectSuccess(peerId) else markConnectFailure(peerId)
                    releaseOutbound(peerId)
                }
            }
        }
    }

    private fun endpointFor(peerId: String): Endpoint? {
        val lan = synchronized(stateLock) { lanPeers.firstOrNull { it.fingerprint == peerId } }
        if (lan?.host != null && lan.port > 0) return Endpoint.Lan(lan.host, lan.port)
        val btAddress = db.peer(peerId)?.btAddress
        if (btAddress != null && bt.isEnabled() && bt.isBonded(btAddress)) return Endpoint.Bt(btAddress)
        return null
    }

    private fun acquireOutbound(peerId: String): Boolean =
        synchronized(stateLock) { activePeers.add(peerId) }

    private fun releaseOutbound(peerId: String) {
        synchronized(stateLock) { activePeers.remove(peerId) }
    }

    private fun connectBackoffActive(peerId: String, now: Long): Boolean =
        synchronized(stateLock) {
            val state = connectFails[peerId] ?: return false
            now - state.second < Outbox.backoffMs(state.first)
        }

    private fun markConnectFailure(peerId: String) {
        synchronized(stateLock) {
            val previous = connectFails[peerId]?.first ?: 0
            connectFails[peerId] = Pair(previous + 1, System.currentTimeMillis())
        }
    }

    private fun markConnectSuccess(peerId: String) {
        synchronized(stateLock) { connectFails.remove(peerId) }
    }

    // ---------------------------------------------------------------- notifications

    private fun notifyIncoming(peer: PeerRow, row: MessageRow) {
        if (MessagingBus.screenActive) return
        val channelId = "ecrew_messages"
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(channelId) == null) {
            nm.createNotificationChannel(
                NotificationChannel(channelId, "Messages", NotificationManager.IMPORTANCE_DEFAULT)
            )
        }
        val preview = row.body.replace('\n', ' ').take(PREVIEW_CHARS)
        val notification = Notification.Builder(this, channelId)
            .setContentTitle(peer.displayName)
            .setContentText(preview)
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentIntent(chatPendingIntent())
            .setAutoCancel(true)
            .build()
        runCatching { nm.notify(peer.id.hashCode(), notification) }
    }

    private fun buildVisibleNotification(): Notification {
        val channelId = "ecrew_visibility"
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(channelId) == null) {
            nm.createNotificationChannel(
                NotificationChannel(channelId, "Chat visibility", NotificationManager.IMPORTANCE_LOW)
            )
        }
        return Notification.Builder(this, channelId)
            .setContentTitle("Visible to nearby users")
            .setContentText("Chatting as ${prefs.displayName} on Wi-Fi and Bluetooth")
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setContentIntent(chatPendingIntent())
            .setOngoing(true)
            .build()
    }

    private fun chatPendingIntent(): PendingIntent {
        val intent = Intent(this, MainActivity::class.java)
            .putExtra(EXTRA_OPEN_CHAT, true)
            .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        return PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    private fun registerBondReceiver() {
        if (bondReceiver != null) return
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action != BluetoothDevice.ACTION_BOND_STATE_CHANGED) return
                @Suppress("DEPRECATION") // getParcelableExtra(String, Class) needs API 33, minSdk 26
                val device = intent.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE)
                val state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.ERROR)
                if (device != null && state != BluetoothDevice.ERROR) onBondStateChanged(device, state)
            }
        }
        runCatching {
            registerReceiver(receiver, IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED))
            bondReceiver = receiver
        }
    }

    private fun unregisterBondReceiver() {
        bondReceiver?.let { runCatching { unregisterReceiver(it) } }
        bondReceiver = null
    }

    companion object {
        const val EXTRA_OPEN_CHAT = "com.ecrew.toolkit.messaging.OPEN_CHAT"
        const val ACTION_ENABLE_VISIBLE = "com.ecrew.toolkit.messaging.ENABLE_VISIBLE"
        const val ACTION_LISTEN = "com.ecrew.toolkit.messaging.LISTEN"
        const val ACTION_DISABLE = "com.ecrew.toolkit.messaging.DISABLE"
        const val ACTION_SCREEN_CLOSED = "com.ecrew.toolkit.messaging.SCREEN_CLOSED"
        const val ACTION_REFRESH = "com.ecrew.toolkit.messaging.REFRESH"
        const val ACTION_BT_SCAN = "com.ecrew.toolkit.messaging.BT_SCAN"
        const val ACTION_BT_PAIR = "com.ecrew.toolkit.messaging.BT_PAIR"
        const val ACTION_PROBE_BT = "com.ecrew.toolkit.messaging.PROBE_BT"
        const val ACTION_IDENTIFY_LAN = "com.ecrew.toolkit.messaging.IDENTIFY_LAN"

        private const val EXTRA_ADDRESS = "address"
        private const val EXTRA_HOST = "host"
        private const val EXTRA_PORT = "port"
        private const val NOTIF_VISIBLE = 42
        private const val PREVIEW_CHARS = 120
        private const val PUMP_TICK_MS = 2_000L
        private const val EXPIRY_EVERY_TICKS = 15
        private const val LAN_CONNECT_TIMEOUT_MS = 5_000L
        private const val SCREEN_CLOSE_DEBOUNCE_MS = 1_500L

        private val mainHandler = Handler(Looper.getMainLooper())
        private var pendingScreenClose: Runnable? = null

        fun enableVisible(context: Context) {
            cancelPendingScreenClose()
            context.startForegroundService(intent(context, ACTION_ENABLE_VISIBLE))
        }

        fun listen(context: Context) {
            cancelPendingScreenClose()
            runCatching { context.startService(intent(context, ACTION_LISTEN)) }
        }

        /** Debounced so a configuration change does not tear the listener down mid-session. */
        fun screenClosed(context: Context) {
            cancelPendingScreenClose()
            val appContext = context.applicationContext
            val runnable = Runnable {
                pendingScreenClose = null
                if (!MessagingBus.screenActive) {
                    runCatching { appContext.startService(intent(appContext, ACTION_SCREEN_CLOSED)) }
                }
            }
            pendingScreenClose = runnable
            mainHandler.postDelayed(runnable, SCREEN_CLOSE_DEBOUNCE_MS)
        }

        fun disable(context: Context) {
            cancelPendingScreenClose()
            runCatching { context.startService(intent(context, ACTION_DISABLE)) }
        }

        fun refresh(context: Context) {
            runCatching { context.startService(intent(context, ACTION_REFRESH)) }
        }

        fun scanBt(context: Context) {
            runCatching { context.startService(intent(context, ACTION_BT_SCAN)) }
        }

        fun pairBt(context: Context, address: String) {
            runCatching {
                context.startService(intent(context, ACTION_BT_PAIR).putExtra(EXTRA_ADDRESS, address))
            }
        }

        fun probeBt(context: Context, address: String) {
            runCatching {
                context.startService(intent(context, ACTION_PROBE_BT).putExtra(EXTRA_ADDRESS, address))
            }
        }

        fun identifyLan(context: Context, host: String, port: Int) {
            runCatching {
                context.startService(
                    intent(context, ACTION_IDENTIFY_LAN)
                        .putExtra(EXTRA_HOST, host)
                        .putExtra(EXTRA_PORT, port)
                )
            }
        }

        private fun intent(context: Context, action: String): Intent =
            Intent(context, MessagingService::class.java).setAction(action)

        private fun cancelPendingScreenClose() {
            pendingScreenClose?.let { mainHandler.removeCallbacks(it) }
            pendingScreenClose = null
        }
    }
}
