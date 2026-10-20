package com.ecrew.agent

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat
import com.ecrew.protocol.ProtocolConstants
import java.io.IOException
import java.util.UUID

/**
 * Bluetooth RFCOMM fallback transport: listens on the fixed service UUID (spec Component
 * 3B). The UUID is obscurity only - the AES-GCM session layer is the security boundary.
 *
 * Runtime BLUETOOTH_CONNECT is required on API 31+; on API 26-30 the legacy BLUETOOTH
 * permissions (targetSdk 28) apply. When Bluetooth is unavailable or denied, the LAN
 * transport is unaffected.
 */
class BtListener(
    private val context: Context,
    private val onClient: (socket: BluetoothSocket) -> Unit
) {
    private var serverSocket: BluetoothServerSocket? = null

    @Volatile
    private var running = false

    fun canListen(): Boolean {
        val adapter = adapter() ?: return false
        if (!hasConnectPermission()) return false
        return adapter.isEnabled
    }

    // targetSdk 28 keeps the legacy Bluetooth permission model: BLUETOOTH/BLUETOOTH_ADMIN are
    // install-time granted and the API 31 runtime pair is not enforced for legacy apps, so no
    // checkSelfPermission guard applies; availability is re-checked in hasConnectPermission().
    @SuppressLint("MissingPermission")
    fun start(): Boolean {
        if (running) return true
        val adapter = adapter() ?: return false
        if (!hasConnectPermission() || !adapter.isEnabled) return false
        val socket = try {
            adapter.listenUsingRfcommWithServiceRecord(
                "E-Crew Remote",
                UUID.fromString(ProtocolConstants.BT_SERVICE_UUID)
            )
        } catch (_: Exception) {
            return false
        }
        serverSocket = socket
        running = true
        AgentRuntime.bluetoothListening = true
        AgentRuntime.notifyChanged()

        Thread({
            while (running) {
                val client = try {
                    socket.accept()
                } catch (_: IOException) {
                    if (!running) break else continue
                }
                try {
                    onClient(client)
                } catch (_: Exception) {
                    runCatching { client.close() }
                }
            }
        }, "ecrew-bt-accept").apply { isDaemon = true }.start()
        return true
    }

    fun stop() {
        running = false
        runCatching { serverSocket?.close() }
        serverSocket = null
        AgentRuntime.bluetoothListening = false
        AgentRuntime.notifyChanged()
    }

    private fun adapter(): BluetoothAdapter? =
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter

    private fun hasConnectPermission(): Boolean =
        Build.VERSION.SDK_INT < 31 ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) ==
            PackageManager.PERMISSION_GRANTED
}
