package com.ecrew.toolkit.messaging

/**
 * Storage seam for the messaging engine. Implemented by [MessagingDb] on Android and by an
 * in-memory store in unit tests, so PeerSession / Outbox logic is pure JVM-testable.
 *
 * Thread-safety: implementations must be safe for concurrent use (sessions run on IO
 * threads while the UI writes from the main thread).
 */
interface MessageStore {

    /** Inserts the peer or refreshes name/last-seen; verified/blocked/bt flags are preserved. */
    fun upsertPeer(id: String, displayName: String, now: Long)

    fun peer(id: String): PeerRow?

    fun setVerified(id: String, verified: Boolean)

    fun setBlocked(id: String, blocked: Boolean)

    /** Sticky Bluetooth address of a peer (learned from a successful RFCOMM session). */
    fun setBtAddress(id: String, address: String)

    /** Inserts a message unless the uuid already exists. Returns true when inserted. */
    fun insertMessage(row: MessageRow): Boolean

    /**
     * Outgoing rows that still need delivery for [peerId] (states queued and sent),
     * oldest first. Callers apply the retry backoff via [Outbox.isDue].
     */
    fun outgoingPending(peerId: String): List<MessageRow>

    /** Peer ids that have any undelivered outgoing rows (pump scan). */
    fun peersWithPending(): List<String>

    /** Marks an outgoing row as transmitted (sent, attempts + 1, last attempt timestamp). */
    fun markSent(id: String, now: Long)

    fun markDelivered(id: String)

    /** Marks rows older than [expiryMs] as failed. Returns the number of rows expired. */
    fun expireOutgoing(now: Long, expiryMs: Long): Int

    /** Messages of one conversation in ascending timestamp order (bounded window). */
    fun conversation(peerId: String): List<MessageRow>

    /** Conversations with a last-message preview and unread count, newest first. */
    fun conversations(): List<Conversation>

    fun markRead(peerId: String)
}
