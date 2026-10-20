package com.ecrew.toolkit.messaging

/** Transport a nearby peer was discovered on. */
enum class MsgTransport(val label: String) {
    WIFI("Wi-Fi"),
    BLUETOOTH("Bluetooth")
}

/**
 * A peer currently reachable (LAN beacon/NSD result, or a Bluetooth device whose
 * handshake already succeeded). [fingerprint] is null for LAN mDNS-only entries whose
 * identity has not been learned yet (the first session reveals it).
 */
data class NearbyPeer(
    val id: String,
    val fingerprint: String?,
    val name: String,
    val transport: MsgTransport,
    val host: String? = null,
    val port: Int = 0,
    val address: String? = null,
    val verified: Boolean = false
)

/** One row of the Bluetooth device list (bonded or freshly discovered). */
data class BtDeviceInfo(
    val name: String,
    val address: String,
    val bonded: Boolean,
    val busy: Boolean
)

/** peers table row. */
data class PeerRow(
    val id: String,
    val displayName: String,
    val firstSeen: Long,
    val lastSeen: Long,
    val verified: Boolean,
    val blocked: Boolean,
    val btAddress: String?
)

/** messages table row. */
data class MessageRow(
    val id: String,
    val peerId: String,
    val direction: String,
    val body: String,
    val ts: Long,
    val state: String,
    val attempts: Int,
    val lastAttempt: Long,
    val read: Boolean
)

/** Aggregated conversation row for the list screen. */
data class Conversation(
    val peer: PeerRow,
    val lastBody: String,
    val lastTs: Long,
    val lastOutgoing: Boolean,
    val unread: Int
)

/** Direction values for [MessageRow.direction]. */
object MsgDirection {
    const val OUT = "out"
    const val IN = "in"
}

/**
 * State values for [MessageRow.state]. Outgoing rows move queued -> sent -> delivered
 * (or failed on expiry); incoming rows are stored as "received".
 */
object MsgState {
    const val QUEUED = "queued"
    const val SENT = "sent"
    const val DELIVERED = "delivered"
    const val FAILED = "failed"
    const val RECEIVED = "received"
}

/** ai_messages table row (Component 12, the Xairex assistant transcript). */
data class AiMessageRow(
    val id: Long,
    val role: String,
    val body: String,
    val ts: Long
)

/** Role values for [AiMessageRow.role]. */
object AiRole {
    const val USER = "user"
    const val ASSISTANT = "assistant"
}
