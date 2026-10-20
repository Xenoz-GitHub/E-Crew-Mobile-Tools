package com.ecrew.toolkit.messaging

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.util.UUID

/**
 * Bluetooth classic glue for messaging: an RFCOMM server on the fixed messaging UUID
 * (accept loop), outbound connects to a device address, bonded-device listing, discovery
 * with a broadcast receiver, and the "make discoverable" system intent.
 *
 * targetSdk 28 keeps the legacy Bluetooth permission model (install-time BLUETOOTH /
 * BLUETOOTH_ADMIN); the API 31 runtime pair is not enforced for legacy apps, so members
 * are suppressed for missing-permission lint and failures are surfaced as exceptions.
 */
class BluetoothLink(private val context: Context) {

    private val appContext = context.applicationContext

    @Volatile
    private var serverSocket: BluetoothServerSocket? = null

    @Volatile
    private var serving = false

    private var acceptThread: Thread? = null

    @SuppressLint("MissingPermission")
    fun adapter(): BluetoothAdapter? = try {
        (appContext.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
    } catch (_: Exception) {
        null
    }

    fun isEnabled(): Boolean = adapter()?.isEnabled == true

    @SuppressLint("MissingPermission")
    fun bondedDevices(): List<BluetoothDevice> {
        val adapter = adapter() ?: return emptyList()
        if (!adapter.isEnabled) return emptyList()
        return try {
            adapter.bondedDevices
                .sortedBy { (it.name ?: "\uFFFF").lowercase() }
        } catch (_: Exception) {
            emptyList()
        }
    }

    @SuppressLint("MissingPermission")
    fun deviceName(address: String): String = try {
        adapter()?.getRemoteDevice(address)?.name?.takeIf { it.isNotBlank() } ?: address
    } catch (_: Exception) {
        address
    }

    fun isBonded(address: String): Boolean = bondedDevices().any { it.address == address }

    // ---------------------------------------------------------------- server

    /** Starts the RFCOMM accept loop; each accepted socket is handed to [onSocket]. */
    @SuppressLint("MissingPermission")
    fun startServer(onSocket: (BluetoothSocket) -> Unit): Boolean {
        if (serving) return true
        val adapter = adapter() ?: return false
        if (!adapter.isEnabled) return false
        val server = try {
            adapter.listenUsingRfcommWithServiceRecord(
                MessagingProtocol.BT_SERVICE_NAME,
                UUID.fromString(MessagingProtocol.BT_SERVICE_UUID)
            )
        } catch (_: Exception) {
            return false
        }
        serverSocket = server
        serving = true
        val thread = Thread({
            while (serving) {
                val socket = try {
                    server.accept()
                } catch (_: Exception) {
                    if (!serving) return@Thread
                    try {
                        Thread.sleep(ACCEPT_ERROR_PAUSE_MS)
                    } catch (_: InterruptedException) {
                        return@Thread
                    }
                    continue
                }
                if (socket != null) {
                    try {
                        onSocket(socket)
                    } catch (_: Exception) {
                        runCatching { socket.close() }
                    }
                }
            }
        }, "ecrew-msg-bt-accept")
        thread.isDaemon = true
        acceptThread = thread
        thread.start()
        return true
    }

    fun stopServer() {
        serving = false
        runCatching { serverSocket?.close() }
        serverSocket = null
        acceptThread = null
    }

    // ---------------------------------------------------------------- client

    /**
     * RFCOMM connect with a hard deadline. The blocking connect runs on a worker; on
     * timeout the socket is closed, which unblocks (and discards) the worker.
     */
    @SuppressLint("MissingPermission")
    suspend fun connect(address: String, timeoutMs: Long = PROBE_TIMEOUT_MS): Result<BluetoothSocket> =
        withContext(Dispatchers.IO) {
            val adapter = adapter() ?: return@withContext fail("Bluetooth unavailable")
            if (!adapter.isEnabled) return@withContext fail("Bluetooth is off")
            val device = try {
                adapter.getRemoteDevice(address)
            } catch (e: Exception) {
                return@withContext Result.failure(e)
            }
            runCatching { adapter.cancelDiscovery() }
            val socket = try {
                device.createRfcommSocketToServiceRecord(
                    UUID.fromString(MessagingProtocol.BT_SERVICE_UUID)
                )
            } catch (e: Exception) {
                return@withContext Result.failure(e)
            }
            val connected = CompletableDeferred<Unit>()
            val worker = Thread({
                try {
                    socket.connect()
                    connected.complete(Unit)
                } catch (e: Exception) {
                    connected.completeExceptionally(e)
                }
            }, "ecrew-msg-bt-connect")
            worker.isDaemon = true
            worker.start()
            try {
                withTimeout(timeoutMs) { connected.await() }
                Result.success(socket)
            } catch (e: Exception) {
                runCatching { socket.close() }
                Result.failure(e)
            }
        }

    private fun fail(reason: String): Result<BluetoothSocket> =
        Result.failure(IllegalStateException(reason))

    // ---------------------------------------------------------------- bonding + discovery

    @SuppressLint("MissingPermission")
    fun createBond(address: String): Boolean = try {
        adapter()?.getRemoteDevice(address)?.createBond() ?: false
    } catch (_: Exception) {
        false
    }

    // ---------------------------------------------------------------- bonding + discovery

    /**
     * Registers a receiver for discovery + bond-state events and starts discovery.
     * Returns the receiver so the caller can unregister (and stop discovery) later.
     */
    @SuppressLint("MissingPermission")
    fun watchDiscovery(
        onFound: (BluetoothDevice) -> Unit,
        onFinished: () -> Unit,
        onBondStateChanged: (BluetoothDevice, Int) -> Unit
    ): BroadcastReceiver? {
        val adapter = adapter() ?: return null
        if (!adapter.isEnabled) return null
        val receiver = object : BroadcastReceiver() {
            @Suppress("DEPRECATION") // getParcelableExtra(String, Class) requires API 33, minSdk 26
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    BluetoothDevice.ACTION_FOUND -> {
                        val device = intent.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE)
                        if (device != null) onFound(device)
                    }
                    BluetoothAdapter.ACTION_DISCOVERY_FINISHED -> onFinished()
                    BluetoothDevice.ACTION_BOND_STATE_CHANGED -> {
                        val device = intent.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE)
                        val state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.ERROR)
                        if (device != null && state != BluetoothDevice.ERROR) onBondStateChanged(device, state)
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(BluetoothDevice.ACTION_FOUND)
            addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
            addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED)
        }
        return try {
            appContext.registerReceiver(receiver, filter)
            if (!adapter.startDiscovery()) {
                appContext.unregisterReceiver(receiver)
                null
            } else {
                receiver
            }
        } catch (_: Exception) {
            null
        }
    }

    @SuppressLint("MissingPermission")
    fun stopDiscovery(receiver: BroadcastReceiver?) {
        runCatching { adapter()?.cancelDiscovery() }
        receiver?.let { runCatching { appContext.unregisterReceiver(it) } }
    }

    companion object {
        const val PROBE_TIMEOUT_MS = 15_000L
        const val DISCOVERABLE_SECONDS = 120
        private const val ACCEPT_ERROR_PAUSE_MS = 500L

        /** ACTION_REQUEST_DISCOVERABLE intent with the 2-minute window (design decision). */
        fun makeDiscoverableIntent(durationSeconds: Int = DISCOVERABLE_SECONDS): Intent =
            Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE)
                .putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, durationSeconds)
    }
}
