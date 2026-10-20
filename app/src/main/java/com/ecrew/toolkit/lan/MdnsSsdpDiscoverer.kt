package com.ecrew.toolkit.lan

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.MulticastSocket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*

/**
 * mDNS (Bonjour/Avahi) and SSDP (UPnP) discovery for local network services.
 */
class MdnsSsdpDiscoverer(private val context: Context) {

    data class DiscoveredService(
        val name: String,
        val type: String,
        val address: String,
        val port: Int,
        val protocol: String, // "mDNS" or "SSDP"
        val details: Map<String, String> = emptyMap()
    )

    private val discoveredServices = mutableListOf<DiscoveredService>()
    private var nsdManager: NsdManager? = null
    private var discoveryListener: NsdManager.DiscoveryListener? = null

    /**
     * Start mDNS discovery for common service types.
     */
    fun startMdnsDiscovery(): List<DiscoveredService> {
        discoveredServices.clear()
        
        nsdManager = context.getSystemService(Context.NSD_SERVICE) as NsdManager
        
        discoveryListener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(regType: String) {
                // Discovery started
            }

            // NsdManager.resolveService and NsdServiceInfo.host are deprecated on API 34
            // (registerServiceInfoCallback / getHostAddresses replace them); this module
            // supports API 26+, so the legacy API stays.
            @Suppress("DEPRECATION")
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                nsdManager?.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                    override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                        val service = DiscoveredService(
                            name = serviceInfo.serviceName,
                            type = serviceInfo.serviceType,
                            address = serviceInfo.host?.hostAddress ?: "unknown",
                            port = serviceInfo.port,
                            protocol = "mDNS",
                            details = mapOf(
                                "hostname" to (serviceInfo.host?.hostName ?: ""),
                                "serviceType" to serviceInfo.serviceType
                            )
                        )
                        synchronized(discoveredServices) {
                            discoveredServices.add(service)
                        }
                    }

                    override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                        // Service found but couldn't resolve
                    }
                })
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                // Service disappeared
            }

            override fun onDiscoveryStopped(serviceType: String) {
                // Discovery stopped
            }

            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                // Failed to start discovery
            }

            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
                // Failed to stop discovery
            }
        }

        // Common mDNS service types
        val serviceTypes = listOf(
            "_http._tcp.",          // Web servers
            "_https._tcp.",         // HTTPS servers
            "_ssh._tcp.",           // SSH servers
            "_ftp._tcp.",           // FTP servers
            "_sftp-ssh._tcp.",      // SFTP servers
            "_smb._tcp.",           // SMB file sharing
            "_afpovertcp._tcp.",    // Apple Filing Protocol
            "_raop._tcp.",          // AirPlay
            "_airplay._tcp.",       // AirPlay
            "_home-sharing._tcp.",  // iTunes Home Sharing
            "_googlecast._tcp.",    // Google Cast
            "_printer._tcp.",       // Printers
            "_ipp._tcp.",           // Internet Printing Protocol
            "_pdl-datastream._tcp.", // Printer
            "_scanner._tcp.",       // Scanners
            "_device-info._tcp.",   // Device info
            "_workstation._tcp.",   // Workstations
            "_nfs._tcp.",           // Network File System
            "_apple-mobdev2._tcp.", // Apple Mobile Device
            "_companion-link._tcp." // Companion Link
        )

        serviceTypes.forEach { type ->
            try {
                nsdManager?.discoverServices(type, NsdManager.PROTOCOL_DNS_SD, discoveryListener)
            } catch (e: Exception) {
                // Some service types may fail
            }
        }

        // Run discovery for 10 seconds, then close this window. A fresh
        // executor per call keeps this safe after discoverSsdp() shuts one down.
        val executor = Executors.newSingleThreadExecutor()
        executor.submit {
            Thread.sleep(10000)
            stopMdnsDiscovery()
            executor.shutdown()
        }

        return synchronized(discoveredServices) { discoveredServices.toList() }
    }

    /**
     * Stop mDNS discovery.
     */
    fun stopMdnsDiscovery() {
        try {
            discoveryListener?.let { nsdManager?.stopServiceDiscovery(it) }
        } catch (e: Exception) {
            // Ignore
        }
        discoveryListener = null
        nsdManager = null
    }

    /**
     * Perform SSDP (UPnP) discovery.
     */
    fun discoverSsdp(timeoutMillis: Long = 5000): List<DiscoveredService> {
        val ssdpServices = mutableListOf<DiscoveredService>()
        val executor = Executors.newSingleThreadExecutor()
        
        executor.submit {
            try {
                val multicast = MulticastSocket(1900)
                multicast.soTimeout = timeoutMillis.toInt()
                multicast.joinGroup(InetAddress.getByName("239.255.255.250"))
                
                // Send M-SEARCH request
                val searchRequest = """
                    M-SEARCH * HTTP/1.1
                    Host: 239.255.255.250:1900
                    Man: "ssdp:discover"
                    MX: 3
                    ST: ssdp:all
                    
                """.trimIndent().replace("\n", "\r\n")
                
                val requestData = searchRequest.toByteArray()
                val packet = DatagramPacket(
                    requestData, requestData.size,
                    InetAddress.getByName("239.255.255.250"), 1900
                )
                multicast.send(packet)
                
                // Listen for responses
                val buffer = ByteArray(4096)
                val startTime = System.currentTimeMillis()
                
                while (System.currentTimeMillis() - startTime < timeoutMillis) {
                    try {
                        val responsePacket = DatagramPacket(buffer, buffer.size)
                        multicast.receive(responsePacket)
                        
                        val response = String(responsePacket.data, 0, responsePacket.length)
                        val service = parseSsdpResponse(response, responsePacket.address.hostAddress ?: "unknown")
                        if (service != null) {
                            synchronized(ssdpServices) { ssdpServices.add(service) }
                        }
                    } catch (e: java.net.SocketTimeoutException) {
                        break
                    } catch (e: Exception) {
                        // Continue listening
                    }
                }
                
                multicast.leaveGroup(InetAddress.getByName("239.255.255.250"))
                multicast.close()
            } catch (e: Exception) {
                // SSDP may not be available
            }
        }
        
        executor.shutdown()
        executor.awaitTermination(timeoutMillis + 1000, TimeUnit.MILLISECONDS)
        
        return ssdpServices
    }

    /**
     * Parse SSDP response into DiscoveredService.
     */
    private fun parseSsdpResponse(response: String, address: String): DiscoveredService? {
        val lines = response.lines()
        if (lines.isEmpty() || !lines[0].contains("HTTP/1.1 200")) {
            return null
        }
        
        val headers = mutableMapOf<String, String>()
        lines.forEach { line ->
            val colonIndex = line.indexOf(':')
            if (colonIndex > 0) {
                val key = line.substring(0, colonIndex).trim()
                val value = line.substring(colonIndex + 1).trim()
                headers[key] = value
            }
        }
        
        val location = headers["LOCATION"] ?: ""
        val server = headers["SERVER"] ?: ""
        val usn = headers["USN"] ?: ""
        val st = headers["ST"] ?: ""
        
        // Extract port from location if possible
        var port = 80
        try {
            val urlMatch = Regex("http://[^:]+:(\\d+)").find(location)
            port = urlMatch?.groupValues?.get(1)?.toInt() ?: 80
        } catch (e: Exception) {
            // Keep default port
        }
        
        return DiscoveredService(
            name = usn.split("::")[0],
            type = st,
            address = address,
            port = port,
            protocol = "SSDP",
            details = mapOf(
                "location" to location,
                "server" to server,
                "usn" to usn
            )
        )
    }

    /**
     * Get all discovered services.
     */
    fun getDiscoveredServices(): List<DiscoveredService> = synchronized(discoveredServices) {
        discoveredServices.toList()
    }

    /**
     * Clear discovered services.
     */
    fun clear() {
        synchronized(discoveredServices) {
            discoveredServices.clear()
        }
    }
}