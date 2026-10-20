package com.ecrew.agent

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import com.ecrew.protocol.ProtocolConstants
import java.io.IOException
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket

/**
 * LAN transport listener: TCP server on an ephemeral port, advertised via mDNS
 * (_ecrew-remote._tcp) with model/version TXT attributes only.
 *
 * Recorded deviation D3: the feature spec asked for the 6-digit pairing code in the TXT
 * record. That would publish the session secret to every LAN peer (the handshake key is
 * derived from code + plaintext salt), so the code never leaves the device screen.
 *
 * The accept loop hands each socket to the session runner and is intentionally blocked for
 * the duration of a session: exactly one session at a time, others wait in the backlog.
 */
class LanListener(
    private val context: Context,
    private val onClient: (socket: Socket) -> Unit
) {
    private var serverSocket: ServerSocket? = null
    private var nsdManager: NsdManager? = null
    private var registrationListener: NsdManager.RegistrationListener? = null

    @Volatile
    private var running = false

    var port: Int = 0
        private set

    var localAddress: String? = null
        private set

    fun start(): Boolean {
        if (running) return true
        val server = try {
            ServerSocket(0)
        } catch (_: IOException) {
            return false
        }
        serverSocket = server
        port = server.localPort
        localAddress = findLocalIpv4()
        running = true

        val model = Build.MODEL ?: "Android"
        val serviceInfo = NsdServiceInfo().apply {
            serviceName = "E-Crew Agent $model"
            serviceType = ProtocolConstants.MDNS_SERVICE_TYPE
            setPort(port)
            setAttribute("model", model)
            setAttribute("ver", ProtocolConstants.VERSION)
        }
        val nsd = context.getSystemService(Context.NSD_SERVICE) as NsdManager
        nsdManager = nsd
        val listener = object : NsdManager.RegistrationListener {
            override fun onServiceRegistered(serviceInfo: NsdServiceInfo) {
                AgentRuntime.notifyChanged()
            }

            override fun onRegistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                // Discovery failed; the controller can still connect by IP:port shown on screen.
            }

            override fun onServiceUnregistered(serviceInfo: NsdServiceInfo) = Unit

            override fun onUnregistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) = Unit
        }
        registrationListener = listener
        runCatching { nsd.registerService(serviceInfo, NsdManager.PROTOCOL_DNS_SD, listener) }

        Thread({
            while (running) {
                val client = try {
                    server.accept()
                } catch (_: IOException) {
                    if (!running) break else continue
                }
                try {
                    onClient(client)
                } catch (_: Exception) {
                    runCatching { client.close() }
                }
            }
        }, "ecrew-lan-accept").apply { isDaemon = true }.start()
        return true
    }

    fun stop() {
        running = false
        registrationListener?.let { listener ->
            runCatching { nsdManager?.unregisterService(listener) }
        }
        registrationListener = null
        runCatching { serverSocket?.close() }
        serverSocket = null
        AgentRuntime.notifyChanged()
    }

    private fun findLocalIpv4(): String? {
        try {
            for (nif in NetworkInterface.getNetworkInterfaces()) {
                if (!nif.isUp || nif.isLoopback) continue
                for (address in nif.inetAddresses) {
                    if (address is Inet4Address && !address.isLoopbackAddress && address.isSiteLocalAddress) {
                        return address.hostAddress
                    }
                }
            }
        } catch (_: Exception) {
            // No network: LAN transport simply stays undiscoverable.
        }
        return null
    }
}
