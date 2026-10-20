package com.ecrew.toolkit.messaging

import com.ecrew.protocol.Json
import com.ecrew.protocol.SecureFrameCodec
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** A session-level abort that is contained to one session (peer blocked mid-session, flood). */
class SessionAbortException(message: String) : Exception(message)

/**
 * One authenticated messaging session over any byte stream (LAN TCP or Bluetooth RFCOMM).
 *
 * Lifecycle: construct -> [handshake] (hello exchange + TOFU checks, plaintext frames) ->
 * [run] (sealed frames: flush the outbox, ACK inbound messages, idle deadline) -> closed.
 *
 * Threading: [run] owns a dedicated reader thread that decodes sealed frames into a queue;
 * all writes (acks, outbox flushes) happen on the [run] caller's thread, so the frame
 * writer needs no lock. Blocking by design: callers run sessions on IO threads.
 */
class PeerSession(
    private val rawInput: InputStream,
    private val rawOutput: OutputStream,
    private val closeable: Closeable?,
    private val transportName: String,
    private val identity: MessagingIdentity,
    private val displayName: String,
    private val store: MessageStore,
    private val limiter: SpamLimiter,
    private val clock: () -> Long = System::currentTimeMillis,
    private val events: Events = SilentEvents
) : AutoCloseable {

    /** Session callbacks; all fire on the session thread. */
    interface Events {
        /** Sticky/transient data changed (messages, peers); the UI should reload. */
        fun onStoreChanged() {}

        /** An inbound message was persisted (notification hook). */
        fun onIncomingStored(peer: PeerRow, row: MessageRow) {}
    }

    private sealed class Frame {
        class Incoming(val message: Map<String, Any?>) : Frame()
        class Closed(val cause: Exception?) : Frame()
    }

    private var input: DataInputStream? = null
    private var output: DataOutputStream? = null
    private var codec: SecureFrameCodec? = null
    private val queue = LinkedBlockingQueue<Frame>(QUEUE_CAPACITY)
    private val sessionSendsPerMessage = HashMap<String, Int>()
    private var drops = 0
    private var peerFingerprint: String = ""
    private var peerDisplayName: String = ""
    private var closed = false

    val peerFp: String get() = peerFingerprint
    val peerName: String get() = peerDisplayName
    val transport: String get() = transportName

    /** Exchanges hellos and establishes the sealed session. Throws on any trust failure. */
    fun handshake(initiator: Boolean): PeerRow {
        val deadlinePassed = arrayOf(false)
        val watchdog = Thread {
            try {
                Thread.sleep(MessagingProtocol.HANDSHAKE_TIMEOUT_MS)
                deadlinePassed[0] = true
                close()
            } catch (_: InterruptedException) {
            }
        }
        watchdog.isDaemon = true
        watchdog.start()
        try {
            val inputStream = DataInputStream(BufferedInputStream(rawInput))
            val outputStream = DataOutputStream(BufferedOutputStream(rawOutput))
            input = inputStream
            output = outputStream
            val outcome = PeerHandshake.perform(
                input = inputStream,
                output = outputStream,
                identity = identity,
                displayName = displayName,
                initiator = initiator,
                clock = clock
            )
            val existing = store.peer(outcome.peerFingerprint)
            if (existing?.blocked == true) throw BlockedPeerException()
            store.upsertPeer(outcome.peerFingerprint, outcome.peerName, clock())
            peerFingerprint = outcome.peerFingerprint
            peerDisplayName = outcome.peerName
            codec = SecureFrameCodec(outcome.sessionKey)
            return store.peer(peerFingerprint) ?: PeerRow(
                id = peerFingerprint,
                displayName = peerDisplayName,
                firstSeen = clock(),
                lastSeen = clock(),
                verified = false,
                blocked = false,
                btAddress = null
            )
        } finally {
            watchdog.interrupt()
        }
    }

    /**
     * Runs the session until the peer goes quiet for [idleTimeoutMs], the reader fails, or
     * an abort condition trips. Always closes the session (the peer reconnects for more).
     */
    fun run(idleTimeoutMs: Long = MessagingProtocol.SESSION_IDLE_TIMEOUT_MS) {
        if (codec == null) return
        val reader = Thread({ readerLoop() }, "ecrew-msg-read")
        reader.isDaemon = true
        reader.start()
        var lastActivity = clock()
        var ticks = 0
        try {
            flushPending(clock())
            while (true) {
                val frame = queue.poll(MessagingProtocol.RECEIVE_TICK_MS, TimeUnit.MILLISECONDS)
                val now = clock()
                when (frame) {
                    is Frame.Incoming -> {
                        handleIncoming(frame.message)
                        lastActivity = now
                    }
                    is Frame.Closed -> return
                    null -> {
                        if (now - lastActivity >= idleTimeoutMs) return
                        ticks += 1
                        if (ticks % FLUSH_EVERY_TICKS == 0) flushPending(now)
                    }
                }
                if (now - lastActivity >= idleTimeoutMs) return
            }
        } catch (_: Exception) {
            // Session errors are contained to this connection (malformed frames, flood,
            // socket failures); the outbox retries on the next rediscovery.
        } finally {
            close()
        }
    }

    /** Sends one chat message inside an established session. Used by tests and the UI flow. */
    fun sendText(uuid: String, body: String, ts: Long): Boolean =
        writeFrame(MessageCodec.text(uuid, body, ts))

    override fun close() {
        if (closed) return
        closed = true
        codec?.let { runCatching { it.close() } }
        codec = null
        runCatching { input?.close() }
        runCatching { output?.close() }
        runCatching { closeable?.close() }
    }

    // ---------------------------------------------------------------- receive path

    private fun readerLoop() {
        val input = this.input
        val codec = this.codec
        if (input == null || codec == null) {
            queue.put(Frame.Closed(null))
            return
        }
        try {
            while (true) {
                val size = input.readInt()
                if (size <= 0 || size > MessagingProtocol.MAX_FRAME_BYTES) {
                    throw SessionAbortException("invalid frame size")
                }
                val sealed = ByteArray(size)
                input.readFully(sealed)
                val message = Json.parse(String(codec.open(sealed), Charsets.UTF_8))
                queue.put(Frame.Incoming(message))
            }
        } catch (e: Exception) {
            queue.put(Frame.Closed(e))
        }
    }

    private fun handleIncoming(message: Map<String, Any?>) {
        when (message["t"] as? String) {
            MsgType.MESSAGE -> onTextFrame(message)
            MsgType.ACK -> onAckFrame(message)
            else -> Unit // unknown frame type: ignore (forward compatibility)
        }
    }

    private fun onAckFrame(message: Map<String, Any?>) {
        val uuid = MessageCodec.parseAck(message) ?: return
        store.markDelivered(uuid)
        events.onStoreChanged()
    }

    private fun onTextFrame(message: Map<String, Any?>) {
        // Blocked peers are enforced silently at session time too (block can change mid-session).
        if (store.peer(peerFingerprint)?.blocked == true) throw BlockedPeerException()
        val text = MessageCodec.parseText(message) ?: return
        val verified = store.peer(peerFingerprint)?.verified == true
        if (!limiter.allow(peerFingerprint, verified)) {
            drops += 1
            if (drops >= MessagingProtocol.RATE_DROP_CLOSE_THRESHOLD) {
                throw SessionAbortException("inbound rate limit exceeded")
            }
            return
        }
        val row = MessageRow(
            id = text.uuid,
            peerId = peerFingerprint,
            direction = MsgDirection.IN,
            body = text.body,
            ts = clock(),
            state = MsgState.RECEIVED,
            attempts = 0,
            lastAttempt = 0L,
            read = false
        )
        val inserted = store.insertMessage(row)
        // ACK even for duplicates: the sender may not have received the first ack.
        writeFrame(MessageCodec.ack(text.uuid))
        if (inserted) {
            val peer = store.peer(peerFingerprint)
            if (peer != null) events.onIncomingStored(peer, row) else events.onStoreChanged()
        }
    }

    // ---------------------------------------------------------------- send path

    private fun flushPending(now: Long) {
        var sent = 0
        for (row in store.outgoingPending(peerFingerprint)) {
            if (sent >= MessagingProtocol.MAX_SENDS_PER_FLUSH) return
            if (!Outbox.isDue(row, now)) continue
            val sessionSends = sessionSendsPerMessage[row.id] ?: 0
            if (sessionSends >= MessagingProtocol.MAX_SESSION_SENDS_PER_MESSAGE) continue
            if (!writeFrame(MessageCodec.text(row.id, row.body, row.ts))) return
            sessionSendsPerMessage[row.id] = sessionSends + 1
            store.markSent(row.id, now)
            sent += 1
            events.onStoreChanged()
        }
    }

    private fun writeFrame(message: Map<String, Any?>): Boolean {
        val output = this.output ?: return false
        val codec = this.codec ?: return false
        return try {
            val sealed = codec.seal(Json.encode(message).toByteArray(Charsets.UTF_8))
            if (sealed.size > MessagingProtocol.MAX_FRAME_BYTES) return false
            output.writeInt(sealed.size)
            output.write(sealed)
            output.flush()
            true
        } catch (_: Exception) {
            false
        }
    }

    private companion object {
        const val QUEUE_CAPACITY = 256
        const val FLUSH_EVERY_TICKS = 2
    }
}

/** No-op session events; used by tests and short identification sessions. */
private object SilentEvents : PeerSession.Events
