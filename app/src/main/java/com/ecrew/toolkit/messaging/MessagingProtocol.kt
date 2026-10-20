package com.ecrew.toolkit.messaging

/**
 * Wire + policy constants for peer messaging (Component 11, design note
 * notes/2026-10-19-1021-peer-messaging-design.md). All limits here are enforced on both
 * encode and decode paths (never trust the peer to respect them).
 */
object MessagingProtocol {
    /** Protocol version carried in the plaintext hello frame. */
    const val VERSION = "1.0"

    /** Fixed RFCOMM service UUID; distinct from the Remote Support UUID (design decision 5). */
    const val BT_SERVICE_UUID = "6f2a1c34-9d5e-4b7a-8c1d-2e3f4a5b6c7d"

    /** SDP record name shown by Bluetooth discovery when this device is listening. */
    const val BT_SERVICE_NAME = "E-Crew Messaging"

    /** NSD service type for LAN presence. */
    const val NSD_SERVICE_TYPE = "_ecrewmsg._tcp"

    /** UDP beacon port (broadcast fallback for networks that block multicast). */
    const val BEACON_PORT = 47821

    /** TCP session port (also the port advertised over NSD/beacon). */
    const val TCP_PORT = 47822

    /** Hard cap for any single sealed frame on the messaging wire. */
    const val MAX_FRAME_BYTES = 8 * 1024

    /** Hard cap for plaintext handshake frames (hello only, keep it small). */
    const val MAX_HANDSHAKE_BYTES = 4096

    /** Message body cap: 2000 characters (UTF-16 units, UI-enforced). */
    const val MAX_MESSAGE_CHARS = 2000

    /** UTF-8 byte guard so a max-length body still fits MAX_FRAME_BYTES after sealing. */
    const val MAX_MESSAGE_BYTES = 7800

    /** Display name length cap (both directions). */
    const val MAX_NAME_CHARS = 64

    /** Presence beacon cadence while the visibility toggle is on. */
    const val BEACON_INTERVAL_MS = 8_000L

    /** A peer we have not heard from for this long is dropped from the nearby list. */
    const val BEACON_EXPIRY_MS = 30_000L

    /** Handshake deadline; enforced with socket timeouts where supported and a watchdog. */
    const val HANDSHAKE_TIMEOUT_MS = 10_000L

    /** Session loop tick: how often pending outbox rows and the idle deadline are checked. */
    const val RECEIVE_TICK_MS = 1_000L

    /** A session with no frame activity for this long closes (peer will reconnect). */
    const val SESSION_IDLE_TIMEOUT_MS = 45_000L

    /** Outbox rows older than this are marked "failed" (shown as "Not delivered"). */
    const val OUTBOX_EXPIRY_MS = 7L * 24 * 60 * 60 * 1000

    /** Retry backoff for unacknowledged rows: 5 s, doubling, capped at 5 min. */
    const val RETRY_BASE_MS = 5_000L
    const val RETRY_MAX_MS = 300_000L

    /** Spam limits (design: unverified 5/min + 50/hour; verified 60/min). */
    const val RATE_UNVERIFIED_PER_MIN = 5
    const val RATE_UNVERIFIED_PER_HOUR = 50
    const val RATE_VERIFIED_PER_MIN = 60

    /** Consecutive dropped frames after which a flooding session is closed. */
    const val RATE_DROP_CLOSE_THRESHOLD = 10

    /** Max frames one flush may send (per session, per tick). */
    const val MAX_SENDS_PER_FLUSH = 30

    /** Max re-sends of the same message inside one session before waiting for a new one. */
    const val MAX_SESSION_SENDS_PER_MESSAGE = 3

    /** Fingerprint: 32 lowercase hex characters (first 16 bytes of SHA-256), 8 display groups. */
    const val FP_HEX_CHARS = 32
    const val FP_GROUPS = 8

    /** Cap on concurrently handled accepted sessions (thread-exhaustion guard). */
    const val MAX_INBOUND_SESSIONS = 4
}

/** Message type tags for the messaging protocol (`t` field). */
object MsgType {
    const val HELLO = "hello"
    const val MESSAGE = "msg"
    const val ACK = "ack"
}

/** Fingerprint display helpers (8 groups of 4 hex chars, and a compact form). */
object Fingerprints {

    fun isHex(value: String?): Boolean {
        if (value == null || value.length != MessagingProtocol.FP_HEX_CHARS) return false
        return value.all { it in '0'..'9' || it in 'a'..'f' }
    }

    /** "ab12cd34..." to "ab12 cd34 ef56 7890 ab12 cd34 ef56 7890" (8 groups). */
    fun group(fingerprint: String): String {
        if (!isHex(fingerprint)) return fingerprint
        return fingerprint.chunked(4).joinToString(" ")
    }

    /** Compact form for list rows: "ab12..7890" (first + last group). */
    fun short(fingerprint: String?): String {
        if (!isHex(fingerprint)) return ""
        val fp = fingerprint!!
        return fp.take(4) + ".." + fp.takeLast(4)
    }
}
