package com.ecrew.toolkit.remote

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import com.ecrew.protocol.HandshakeClient
import com.ecrew.protocol.ProtocolConstants
import com.ecrew.protocol.SecureFrameCodec
import com.ecrew.protocol.Session
import com.ecrew.protocol.StreamSession
import com.ecrew.protocol.Transport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.UUID

/**
 * Controller-side Bluetooth transport: RFCOMM connect to the fixed service UUID + plaintext
 * handshake + [StreamSession]. The RFCOMM UUID is obscurity only; AES-GCM is the boundary.
 */
class BluetoothTransport(
    private val adapter: BluetoothAdapter,
    private val address: String,
    private val code: String,
    private val model: String
) : Transport {

    @Volatile
    private var socket: android.bluetooth.BluetoothSocket? = null

    // targetSdk 28 keeps the legacy Bluetooth permission model: BLUETOOTH/BLUETOOTH_ADMIN
    // are install-time granted, and the API 31 runtime pair is neither required nor granted
    // for legacy apps - a checkSelfPermission guard would wrongly block working devices.
    // Failures (SecurityException included) surface through the catch below.
    @SuppressLint("MissingPermission")
    override suspend fun open(): Result<Session> = withContext(Dispatchers.IO) {
        try {
            val device = adapter.getRemoteDevice(address)
            val s = device.createRfcommSocketToServiceRecord(
                UUID.fromString(ProtocolConstants.BT_SERVICE_UUID)
            )
            socket = s
            runCatching { adapter.cancelDiscovery() }
            s.connect()
            val input = DataInputStream(BufferedInputStream(s.inputStream))
            val output = DataOutputStream(BufferedOutputStream(s.outputStream))
            val result = HandshakeClient.perform(input, output, code, model)
            val session = StreamSession(
                input, output,
                SecureFrameCodec(result.sessionKey),
                "bluetooth",
                address,
                result.sessionId
            )
            Result.success(session)
        } catch (e: Exception) {
            runCatching { socket?.close() }
            Result.failure(e)
        }
    }

    override fun close() {
        runCatching { socket?.close() }
    }
}
