package com.ecrew.protocol

import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.concurrent.locks.ReentrantLock

/**
 * Wire framing helpers.
 *
 * Every frame on a stream transport is `writeInt(size)` (big-endian) followed by `size`
 * bytes. Handshake frames carry plaintext JSON; post-handshake frames carry
 * `nonce || ciphertext || tag` (see [SecureFrameCodec]).
 */
object Frames {

    fun writePlain(output: DataOutputStream, message: Map<String, Any?>) {
        val bytes = Json.encode(message).toByteArray(Charsets.UTF_8)
        if (bytes.size > ProtocolConstants.MAX_HANDSHAKE_BYTES) throw IOException("handshake frame too large")
        output.writeInt(bytes.size)
        output.write(bytes)
        output.flush()
    }

    fun readPlain(input: DataInputStream, maxBytes: Int): Map<String, Any?> {
        val size = input.readInt()
        if (size <= 0 || size > maxBytes) throw IOException("invalid frame size: $size")
        val bytes = ByteArray(size)
        input.readFully(bytes)
        return Json.parse(String(bytes, Charsets.UTF_8))
    }
}

/**
 * A live, authenticated session over a stream pair (LAN socket or Bluetooth RFCOMM socket).
 */
interface Session : Closeable {
    val transportName: String

    /**
     * Sends one encrypted message. Returns false when a previous send is still in flight
     * (backpressure: the agent's frame pump skips the current frame instead of blocking).
     */
    fun send(message: Map<String, Any?>): Boolean

    /**
     * Receives the next encrypted message, or null on read timeout.
     * Throws on tampered/replayed frames or a closed stream.
     */
    fun receive(timeoutMs: Long): Map<String, Any?>?

    val bytesIn: Long
    val bytesOut: Long
}

/**
 * Unified transport abstraction (spec Component 3). Implementations (LAN TCP, Bluetooth
 * RFCOMM) live in the Android modules; both are expected to reuse [StreamSession] after
 * completing the handshake so there is exactly one frame codec implementation.
 */
interface Transport {
    suspend fun open(): Result<Session>
    fun close()
}

/**
 * Generic [Session] over any stream pair. All framing/crypto goes through the shared
 * [SecureFrameCodec], so LAN and Bluetooth sessions share one code path.
 *
 * Threading model: one writer (guarded by a try-lock for backpressure) and one reader
 * (callers must not call [receive] concurrently from multiple threads).
 */
class StreamSession(
    private val input: DataInputStream,
    private val output: DataOutputStream,
    private val codec: SecureFrameCodec,
    override val transportName: String,
    private val remote: String,
    /** Agent-assigned session id from `auth_ok`; null until assigned (controller side). */
    val sessionId: String? = null
) : Session {

    private val writeLock = ReentrantLock()
    @Volatile
    private var closed = false
    private var bytesInCount = 0L
    private var bytesOutCount = 0L

    override val bytesIn: Long get() = bytesInCount
    override val bytesOut: Long get() = bytesOutCount

    /** Human-readable description of the peer (shown in the session/audit UI). */
    val remoteDescription: String get() = remote

    override fun send(message: Map<String, Any?>): Boolean {
        if (closed) return false
        if (!writeLock.tryLock()) return false
        try {
            val sealed = codec.seal(Json.encode(message).toByteArray(Charsets.UTF_8))
            if (sealed.size > ProtocolConstants.MAX_FRAME_BYTES) throw IOException("frame too large")
            output.writeInt(sealed.size)
            output.write(sealed)
            output.flush()
            bytesOutCount += sealed.size + 4
            return true
        } finally {
            writeLock.unlock()
        }
    }

    override fun receive(timeoutMs: Long): Map<String, Any?>? {
        val size = try {
            input.readInt()
        } catch (e: SocketTimeoutException) {
            return null
        }
        if (size <= SecureFrameCodec.NONCE_BYTES + SecureFrameCodec.TAG_BYTES) {
            if (size == -1 || size == 0) throw IOException("session closed by peer")
            throw IOException("invalid frame size: $size")
        }
        if (size > ProtocolConstants.MAX_FRAME_BYTES) throw IOException("frame too large: $size")
        val frame = ByteArray(size)
        try {
            input.readFully(frame)
        } catch (e: SocketTimeoutException) {
            throw IOException("truncated frame after timeout", e)
        }
        bytesInCount += size + 4
        return Json.parse(String(codec.open(frame), Charsets.UTF_8))
    }

    /** Best effort: closes both streams (and therefore the underlying socket). */
    override fun close() {
        if (closed) return
        closed = true
        try {
            input.close()
        } catch (_: IOException) {
        }
        try {
            output.close()
        } catch (_: IOException) {
        }
        codec.close()
    }
}
