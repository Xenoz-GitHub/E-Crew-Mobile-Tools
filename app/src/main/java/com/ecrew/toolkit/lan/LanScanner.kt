package com.ecrew.toolkit.lan

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.min

/**
 * LAN reconnaissance module (root-free):
 *  - Local network discovery via /proc/net/arp
 *  - TCP port scanning (common service ports)
 *  - Banner grabbing for open ports
 *  - mDNS/SSDP discovery for local services
 *  - OUI vendor lookup for MAC addresses
 */
object LanScanner {

    data class Host(
        val ip: String,
        val mac: String? = null,
        val hostname: String? = null,
        val vendor: String? = null,
        val openPorts: List<OpenPort> = emptyList()
    )

    data class OpenPort(
        val port: Int,
        val service: String,
        val banner: String? = null,
        val protocol: String = "TCP"
    )

    data class ScanResult(
        val network: String,
        val hosts: List<Host>,
        val scanTime: Long,
        val totalPortsScanned: Int
    )

    private val COMMON_PORTS = listOf(
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
        445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    )

    /**
     * Get local network information (IP range, gateway).
     */
    fun getLocalNetwork(context: Context): String? {
        return try {
            val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = connectivity.activeNetwork ?: return null
            val caps = connectivity.getNetworkCapabilities(network) ?: return null
            
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                return null
            }

            // Get local IP from network interfaces
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                if (!iface.isUp || iface.isLoopback) continue

                val addresses = iface.inetAddresses
                while (addresses.hasMoreElements()) {
                    val addr = addresses.nextElement()
                    val address = addr.hostAddress
                    if (address != null && address.contains('.') && !addr.isLoopbackAddress) {
                        val parts = address.split('.')
                        if (parts.size == 4) {
                            return "${parts[0]}.${parts[1]}.${parts[2]}.0/24"
                        }
                    }
                }
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Read the kernel ARP table at /proc/net/arp (readable to apps on the
     * supported platform versions; MAC vendors resolved via OuiLookup).
     */
    fun readArpTable(): List<Host> {
        val hosts = mutableListOf<Host>()
        try {
            val reader = java.io.File("/proc/net/arp").bufferedReader()
            reader.readLine() // Skip header
            
            reader.lineSequence().forEach { line ->
                val parts = line.trim().split("\\s+".toRegex())
                if (parts.size >= 6) {
                    val ip = parts[0]
                    val mac = if (parts[3] != "00:00:00:00:00:00") parts[3] else null
                    if (mac != null) {
                        val vendor = OuiLookup.getVendor(mac)
                        hosts.add(Host(ip = ip, mac = mac, vendor = vendor))
                    }
                }
            }
            reader.close()
        } catch (e: Exception) {
            // ARP table may not be accessible without root
        }
        return hosts
    }

    /**
     * Perform TCP port scan on a single host.
     */
    fun scanHostPorts(host: String, ports: List<Int> = COMMON_PORTS): List<OpenPort> {
        val openPorts = mutableListOf<OpenPort>()
        val executor = Executors.newFixedThreadPool(min(ports.size, 16))
        val latch = java.util.concurrent.CountDownLatch(ports.size)
        
        ports.forEach { port ->
            executor.submit {
                try {
                    val socket = Socket()
                    socket.connect(InetSocketAddress(host, port), 1500)
                    socket.close()
                    
                    // Try to grab banner if port is open
                    val banner = try {
                        val bannerSocket = Socket()
                        bannerSocket.connect(InetSocketAddress(host, port), 1000)
                        bannerSocket.soTimeout = 2000
                        bannerSocket.getInputStream().bufferedReader().readLine()?.take(100)
                            ?: "No banner"
                    } catch (e: Exception) {
                        null
                    }
                    
                    val service = getServiceName(port)
                    openPorts.add(OpenPort(port, service, banner))
                } catch (e: Exception) {
                    // Port is closed or filtered
                } finally {
                    latch.countDown()
                }
            }
        }
        
        latch.await(10, TimeUnit.SECONDS)
        executor.shutdown()
        return openPorts
    }

    /**
     * Perform network sweep (ping + ARP + port scan). Initializes the OUI
     * database (no-op after the first call) so ARP results carry vendors.
     */
    fun scanNetwork(context: Context, subnet: String = "192.168.1.0/24"): ScanResult {
        OuiLookup.init(context)
        val startTime = System.currentTimeMillis()
        val hosts = mutableListOf<Host>()
        val totalScanned = AtomicInteger(0)
        
        // Parse subnet
        val parts = subnet.removeSuffix("/24").split('.')
        if (parts.size != 3) return ScanResult(subnet, emptyList(), 0, 0)
        
        // Ping sweep (ICMP echo, limited on Android without root)
        val executor = Executors.newFixedThreadPool(32)
        val latch = java.util.concurrent.CountDownLatch(254)
        
        for (i in 1..254) {
            val ip = "${parts[0]}.${parts[1]}.${parts[2]}.$i"
            executor.submit {
                totalScanned.incrementAndGet()
                if (isHostAlive(ip)) {
                    val arpEntry = readArpTable().find { it.ip == ip }
                    val ports = if (arpEntry != null) scanHostPorts(ip) else emptyList()
                    
                    val host = Host(
                        ip = ip,
                        mac = arpEntry?.mac,
                        vendor = arpEntry?.vendor,
                        openPorts = ports
                    )
                    synchronized(hosts) { hosts.add(host) }
                }
                latch.countDown()
            }
        }
        
        latch.await(30, TimeUnit.SECONDS)
        executor.shutdown()
        
        return ScanResult(
            network = subnet,
            hosts = hosts,
            scanTime = System.currentTimeMillis() - startTime,
            totalPortsScanned = totalScanned.get()
        )
    }

    /**
     * Simple ICMP ping (works on some Android versions without root).
     */
    private fun isHostAlive(ip: String): Boolean {
        return try {
            val address = InetAddress.getByName(ip)
            address.isReachable(1000)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get service name for common ports.
     */
    private fun getServiceName(port: Int): String = when (port) {
        21 -> "FTP"
        22 -> "SSH"
        23 -> "Telnet"
        25 -> "SMTP"
        53 -> "DNS"
        80 -> "HTTP"
        110 -> "POP3"
        111 -> "RPC"
        135 -> "MSRPC"
        139 -> "NetBIOS"
        143 -> "IMAP"
        443 -> "HTTPS"
        445 -> "SMB"
        993 -> "IMAPS"
        995 -> "POP3S"
        1723 -> "PPTP"
        3306 -> "MySQL"
        3389 -> "RDP"
        5900 -> "VNC"
        8080 -> "HTTP-ALT"
        8443 -> "HTTPS-ALT"
        else -> "Unknown"
    }
}