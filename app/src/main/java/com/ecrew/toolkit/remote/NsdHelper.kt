package com.ecrew.toolkit.remote

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import com.ecrew.protocol.ProtocolConstants

/**
 * mDNS discovery for `_ecrew-remote._tcp` agents (spec Component 6, LAN half).
 *
 * Services are resolved serially (one at a time) because some devices reject concurrent
 * resolves; a multicast lock is held for the duration of discovery so mDNS packets are not
 * filtered while the Wi-Fi radio is in power save.
 */
class NsdHelper(private val context: Context) {

    data class Discovered(val name: String, val host: String, val port: Int)

    private val nsd: NsdManager by lazy {
        context.getSystemService(Context.NSD_SERVICE) as NsdManager
    }

    @Volatile
    private var running = false

    private var discoveryListener: NsdManager.DiscoveryListener? = null
    private var multicastLock: WifiManager.MulticastLock? = null
    private val found = LinkedHashMap<String, Discovered>()
    private val resolveQueue = ArrayDeque<NsdServiceInfo>()
    private var resolving = false
    private var onChanged: ((List<Discovered>) -> Unit)? = null
    private var onError: ((String) -> Unit)? = null

    fun snapshot(): List<Discovered> = found.values.toList()

    fun start(onChanged: (List<Discovered>) -> Unit, onError: (String) -> Unit) {
        this.onChanged = onChanged
        this.onError = onError
        if (running) {
            onChanged(found.values.toList())
            return
        }
        acquireMulticastLock()
        running = true
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) = Unit

            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                running = false
                releaseMulticastLock()
                onError("mDNS discovery failed (code $errorCode)")
            }

            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                if (serviceInfo.serviceType.contains(SERVICE_TAG)) {
                    resolveQueue.addLast(serviceInfo)
                    pumpResolve()
                }
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                found.remove(serviceInfo.serviceName)
                onChanged(found.values.toList())
            }

            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = Unit

            override fun onDiscoveryStopped(serviceType: String) = Unit
        }
        discoveryListener = listener
        try {
            nsd.discoverServices(ProtocolConstants.MDNS_SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            running = false
            releaseMulticastLock()
            onError("mDNS discovery unavailable")
        }
    }

    fun stop() {
        running = false
        discoveryListener?.let { listener -> runCatching { nsd.stopServiceDiscovery(listener) } }
        discoveryListener = null
        resolveQueue.clear()
        resolving = false
        releaseMulticastLock()
    }

    @Suppress("DEPRECATION") // NsdManager.resolveService: registerServiceInfoCallback needs API 34, minSdk is 26
    private fun pumpResolve() {
        if (resolving) return
        val next = resolveQueue.removeFirstOrNull() ?: return
        if (found.containsKey(next.serviceName)) {
            pumpResolve()
            return
        }
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
                    found[serviceInfo.serviceName] = Discovered(serviceInfo.serviceName, host, serviceInfo.port)
                    onChanged?.invoke(found.values.toList())
                }
                pumpResolve()
            }
        }
        try {
            nsd.resolveService(next, listener)
        } catch (e: Exception) {
            // Resolve already in flight (some vendors): drop this one, keep the queue moving.
            resolving = false
            pumpResolve()
        }
    }

    @Suppress("DEPRECATION") // NsdServiceInfo.getHost(): getHostAddresses() requires API 34, minSdk is 26
    private fun hostOf(serviceInfo: NsdServiceInfo): String? =
        serviceInfo.host?.hostAddress

    private fun acquireMulticastLock() {
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return
        val lock = wifi.createMulticastLock("ecrew-remote-nsd")
        lock.setReferenceCounted(true)
        runCatching { lock.acquire() }
        multicastLock = lock
    }

    private fun releaseMulticastLock() {
        multicastLock?.let { lock ->
            runCatching { if (lock.isHeld) lock.release() }
        }
        multicastLock = null
    }

    private companion object {
        const val SERVICE_TAG = "ecrew-remote"
    }
}
