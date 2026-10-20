package com.ecrew.toolkit.remote

import com.ecrew.protocol.HandshakeClient
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
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Controller-side LAN transport: TCP connect + plaintext handshake + [StreamSession].
 * A 10 s read timeout covers the handshake so a stalled peer cannot hang the connecting
 * coroutine forever; after `auth_ok` the reader loop tolerates the periodic timeouts.
 */
class LanTransport(
    private val host: String,
    private val port: Int,
    private val code: String,
    private val model: String
) : Transport {

    @Volatile
    private var socket: Socket? = null

    override suspend fun open(): Result<Session> = withContext(Dispatchers.IO) {
        try {
            val s = Socket()
            s.tcpNoDelay = true
            s.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS.toInt())
            s.soTimeout = HANDSHAKE_TIMEOUT_MS.toInt()
            socket = s
            val input = DataInputStream(BufferedInputStream(s.getInputStream()))
            val output = DataOutputStream(BufferedOutputStream(s.getOutputStream()))
            val result = HandshakeClient.perform(input, output, code, model)
            val session = StreamSession(
                input, output,
                SecureFrameCodec(result.sessionKey),
                "lan",
                "$host:$port",
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

    private companion object {
        const val CONNECT_TIMEOUT_MS = 10_000L
        const val HANDSHAKE_TIMEOUT_MS = 10_000L
    }
}
