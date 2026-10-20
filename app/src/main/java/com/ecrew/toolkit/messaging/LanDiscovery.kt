package com.ecrew.toolkit.messaging

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import com.ecrew.protocol.Json
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * LAN presence (design note, "Transports"): NSD service `_ecrewmsg._tcp` plus a UDP
 * broadcast beacon on :47821 for networks that drop multicast. Beacons are only sent while
 * the visibility toggle is on; discovery always listens while running.
 *
 * A beacon exposes display name + fingerprint to the local segment (documented trade-off
 * of the user-chosen open discovery model). Duplicate identities are deduplicated by
 * fingerprint; mDNS-only entries (identity not yet learned) appear until the first session.
 */
class LanDiscovery(private val context: Context) {

    data class LanePeer(
        val fingerprint: String?,
        val name: String,
        val host: String,
        val port: Int,
        val lastSeen: Long
    )

    data class BeaconProfile(val name: String, val fingerprint: String, val port: Int)

    private val appContext = context.applicationContext
    private val nsd: NsdManager by lazy {
        appContext.getSystemService(Context.NSD_SERVICE) as NsdManager
    }

    @Volatile
    private var running = false

    private val lock = Any()
    private val entries = LinkedHashMap<String, LanePeer>()
    private var onChanged: ((List<LanePeer>) -> Unit)? = null
    private var ownFingerprint: String = ""

    private var discoveryListener: NsdManager.DiscoveryListener? = null
    private var registeredInfo: NsdServiceInfo? = null
    private var multicastLock: WifiManager.MulticastLock? = null

    private var receiverSocket: DatagramSocket? = null
    private var senderSocket: DatagramSocket? = null
    private var receiverThread: Thread? = null
    private var senderThread: Thread? = null

    private var resolveQueue = ArrayDeque<NsdServiceInfo>()
    private var resolving = false

    /**
     * Starts discovery; when [beacon] is non-null this device also announces itself
     * (visibility toggle on). [onChanged] fires with the merged peer list.
     */
    fun start(beacon: BeaconProfile?, onChanged: (List<LanePeer>) -> Unit) {
        if (running) {
            onChanged(snapshot())
            return
        }
        this.onChanged = onChanged
        ownFingerprint = beacon?.fingerprint ?: ""
        running = true
        acquireMulticastLock()
        if (beacon != null) registerBeaconService(beacon)
        startNsdDiscovery()
        startUdp(beacon)
        onChanged(snapshot())
    }

    fun stop() {
        if (!running) return
        running = false
        discoveryListener?.let { listener -> runCatching { nsd.stopServiceDiscovery(listener) } }
        discoveryListener = null
        registeredInfo?.let { runCatching { nsd.unregisterService(registrationListener) } }
        registeredInfo = null
        runCatching { receiverSocket?.close() }
        runCatching { senderSocket?.close() }
        receiverSocket = null
        senderSocket = null
        receiverThread = null
        senderThread = null
        resolveQueue = ArrayDeque()
        resolving = false
        synchronized(lock) { entries.clear() }
        releaseMulticastLock()
    }

    fun snapshot(): List<LanePeer> = synchronized(lock) { entries.values.toList() }

    // ---------------------------------------------------------------- NSD

    private val registrationListener = object : NsdManager.RegistrationListener {
        override fun onServiceRegistered(serviceInfo: NsdServiceInfo) = Unit
        override fun onRegistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) = Unit
        override fun onServiceUnregistered(serviceInfo: NsdServiceInfo) = Unit
        override fun onUnregistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) = Unit
    }

    private fun registerBeaconService(beacon: BeaconProfile) {
        val serviceInfo = NsdServiceInfo().apply {
            serviceName = "ecrewmsg-" + beacon.fingerprint.takeLast(4)
            serviceType = MessagingProtocol.NSD_SERVICE_TYPE
            port = beacon.port
        }
        runCatching { nsd.registerService(serviceInfo, NsdManager.PROTOCOL_DNS_SD, registrationListener) }
            .onSuccess { registeredInfo = serviceInfo }
    }

    private fun startNsdDiscovery() {
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) = Unit
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) = Unit
            override fun onDiscoveryStopped(serviceType: String) = Unit
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = Unit

            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                if (!serviceInfo.serviceType.contains(NSD_TAG)) return
                if (serviceInfo.serviceName.endsWith("ecrewmsg-${ownFingerprint.takeLast(4)}") &&
                    ownFingerprint.isNotEmpty()
                ) {
                    return
                }
                resolveQueue.addLast(serviceInfo)
                pumpResolve()
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                synchronized(lock) { entries.remove(nsdKey(serviceInfo.serviceName)) }
                notifyChanged()
            }
        }
        discoveryListener = listener
        runCatching {
            nsd.discoverServices(MessagingProtocol.NSD_SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
        }
    }

    @Suppress("DEPRECATION") // NsdManager.resolveService: registerServiceInfoCallback needs API 34, minSdk 26
    private fun pumpResolve() {
        if (!running || resolving) return
        val next = resolveQueue.removeFirstOrNull() ?: return
        resolving = true
        val listener = object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                resolving = false
                pumpResolve()
            }

            override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                resolving = false
                val host = hostOf(serviceInfo)
                if (host != null && serviceInfo.port > 0) {
                    update(nsdKey(serviceInfo.serviceName)) {
                        LanePeer(
                            fingerprint = null,
                            name = "E-Crew user",
                            host = host,
                            port = serviceInfo.port,
                            lastSeen = System.currentTimeMillis()
                        )
                    }
                }
                pumpResolve()
            }
        }
        runCatching { nsd.resolveService(next, listener) }.onFailure {
            resolving = false
            pumpResolve()
        }
    }

    @Suppress("DEPRECATION") // NsdServiceInfo.getHost(): getHostAddresses() needs API 34, minSdk 26
    private fun hostOf(serviceInfo: NsdServiceInfo): String? = serviceInfo.host?.hostAddress

    // ---------------------------------------------------------------- UDP beacon

    private fun startUdp(beacon: BeaconProfile?) {
        val receiver = try {
            DatagramSocket(null).apply {
                reuseAddress = true
                bind(InetSocketAddress(MessagingProtocol.BEACON_PORT))
                soTimeout = 1000
            }
        } catch (_: Exception) {
            null
        }
        receiverSocket = receiver
        if (receiver != null) {
            val thread = Thread({ receiveLoop(receiver, beacon?.fingerprint ?: "") }, "ecrew-msg-beacon-rx")
            thread.isDaemon = true
            receiverThread = thread
            thread.start()
        }

        if (beacon != null) {
            val sender = try {
                DatagramSocket().apply { broadcast = true }
            } catch (_: Exception) {
                null
            }
            senderSocket = sender
            if (sender != null) {
                val thread = Thread({ sendLoop(sender, beacon) }, "ecrew-msg-beacon-tx")
                thread.isDaemon = true
                senderThread = thread
                thread.start()
            }
        }
    }

    private fun sendLoop(socket: DatagramSocket, beacon: BeaconProfile) {
        val payload = Json.encode(
            mapOf(
                "t" to "beacon",
                "v" to MessagingProtocol.VERSION,
                "name" to beacon.name,
                "fp" to beacon.fingerprint,
                "port" to beacon.port
            )
        ).toByteArray(Charsets.UTF_8)
        while (running) {
            for (address in broadcastAddresses()) {
                runCatching {
                    socket.send(
                        DatagramPacket(payload, payload.size, address, MessagingProtocol.BEACON_PORT)
                    )
                }
            }
            try {
                Thread.sleep(MessagingProtocol.BEACON_INTERVAL_MS)
            } catch (_: InterruptedException) {
                return
            }
        }
    }

    private fun receiveLoop(socket: DatagramSocket, ownFp: String) {
        val buffer = ByteArray(MAX_BEACON_BYTES)
        while (running) {
            val packet = DatagramPacket(buffer, buffer.size)
            val received = try {
                socket.receive(packet)
                packet
            } catch (_: Exception) {
                if (!running) return
                continue
            }
            val host = received.address?.hostAddress ?: continue
            val text = String(received.data, received.offset, received.length, Charsets.UTF_8)
            val map = try {
                Json.parse(text)
            } catch (_: Exception) {
                continue
            }
            if (map["t"] != "beacon" || map["v"] != MessagingProtocol.VERSION) continue
            val fingerprint = (map["fp"] as? String)?.lowercase() ?: continue
            if (!Fingerprints.isHex(fingerprint)) continue
            if (fingerprint == ownFp) continue
            val port = (map["port"] as? Number)?.toInt() ?: continue
            if (port !in 1..65535) continue
            val name = (map["name"] as? String)
                ?.trim()
                ?.take(MessagingProtocol.MAX_NAME_CHARS)
                ?.ifBlank { null }
                ?: "E-Crew user"
            update("fp:$fingerprint") {
                LanePeer(
                    fingerprint = fingerprint,
                    name = name,
                    host = host,
                    port = port,
                    lastSeen = System.currentTimeMillis()
                )
            }
        }
    }

    @Suppress("DEPRECATION") // WifiManager.connectionInfo/dhcpInfo: no replacement before API 31
    private fun broadcastAddresses(): List<InetAddress> {
        val out = LinkedHashSet<InetAddress>()
        runCatching { out.add(InetAddress.getByName("255.255.255.255")) }
        try {
            val wifi = appContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            val ip = wifi?.connectionInfo?.ipAddress ?: 0
            val mask = wifi?.dhcpInfo?.netmask ?: 0
            if (ip != 0 && mask != 0) {
                val directed = (ip and mask) or mask.inv()
                val bytes = byteArrayOf(
                    (directed and 0xFF).toByte(),
                    (directed ushr 8 and 0xFF).toByte(),
                    (directed ushr 16 and 0xFF).toByte(),
                    (directed ushr 24 and 0xFF).toByte()
                )
                runCatching { out.add(InetAddress.getByAddress(bytes)) }
            }
        } catch (_: Exception) {
        }
        return out.toList()
    }

    // ---------------------------------------------------------------- bookkeeping

    private fun nsdKey(serviceName: String): String = "nsd:$serviceName"

    private fun update(key: String, build: () -> LanePeer) {
        synchronized(lock) {
            entries[key] = build()
            expireLocked()
        }
        notifyChanged()
    }

    private fun expireLocked() {
        val cutoff = System.currentTimeMillis() - MessagingProtocol.BEACON_EXPIRY_MS
        entries.entries.removeAll { (key, peer) -> key.startsWith("fp:") && peer.lastSeen < cutoff }
        // mDNS-only entries whose endpoint is already covered by a beacon identity.
        val covered = entries.values.filter { it.fingerprint != null }.map { it.host + ":" + it.port }.toSet()
        entries.entries.removeAll { (key, peer) ->
            key.startsWith("nsd:") && (peer.host + ":" + peer.port) in covered
        }
    }

    private fun notifyChanged() {
        val callback = onChanged ?: return
        callback(snapshot())
    }

    private fun acquireMulticastLock() {
        val wifi = appContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return
        val lock = wifi.createMulticastLock("ecrew-msg-nsd")
        lock.setReferenceCounted(true)
        runCatching { lock.acquire() }
        multicastLock = lock
    }

    private fun releaseMulticastLock() {
        multicastLock?.let { lock -> runCatching { if (lock.isHeld) lock.release() } }
        multicastLock = null
    }

    private companion object {
        const val NSD_TAG = "ecrewmsg"
        const val MAX_BEACON_BYTES = 1024
    }
}
