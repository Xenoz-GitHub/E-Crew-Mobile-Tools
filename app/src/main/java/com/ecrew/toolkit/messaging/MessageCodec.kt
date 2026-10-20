package com.ecrew.toolkit.messaging

import com.ecrew.protocol.Json
import java.security.PublicKey

/**
 * JSON codec for the messaging protocol frames (shared dependency-free [Json] encoder).
 *
 * Plaintext frames (handshake): hello. Sealed frames (session): msg + ack. Everything that
 * arrives is validated here; malformed input yields null and the session drops the frame
 * (or the handshake fails) instead of trusting it.
 */
object MessageCodec {

    /** Validated hello payload. */
    class HelloInfo(
        val displayName: String,
        val fingerprint: String,
        val publicKey: PublicKey,
        val publicKeyB64: String,
        val ecdhKey: PublicKey,
        val ecdhB64: String,
        val signature: ByteArray
    )

    /** Validated chat message payload. */
    class TextInfo(val uuid: String, val body: String, val ts: Long)

    // ---------------------------------------------------------------- builders

    fun hello(
        version: String,
        displayName: String,
        fingerprint: String,
        publicKeyB64: String,
        ecdhB64: String,
        signatureB64: String,
        ts: Long
    ): Map<String, Any?> = mapOf(
        "t" to MsgType.HELLO,
        "v" to version,
        "name" to displayName,
        "fp" to fingerprint,
        "pub" to publicKeyB64,
        "ecdh" to ecdhB64,
        "sig" to signatureB64,
        "ts" to ts
    )

    fun text(uuid: String, body: String, ts: Long): Map<String, Any?> = mapOf(
        "t" to MsgType.MESSAGE,
        "uuid" to uuid,
        "body" to body,
        "ts" to ts
    )

    fun ack(uuid: String): Map<String, Any?> = mapOf(
        "t" to MsgType.ACK,
        "uuid" to uuid
    )

    // ---------------------------------------------------------------- parsers

    /**
     * Validates a hello frame: version, fingerprint format, public key parse, the
     * fingerprint <-> public key binding (SHA-256), ephemeral key parse and signature
     * presence. The signature is verified by the handshake, not here (context is role-aware).
     */
    fun parseHello(message: Map<String, Any?>): HelloInfo? {
        if (message["t"] != MsgType.HELLO) return null
        if (message["v"] != MessagingProtocol.VERSION) return null
        val fingerprint = (message["fp"] as? String)?.lowercase()
        if (!Fingerprints.isHex(fingerprint)) return null
        val publicKeyB64 = (message["pub"] as? String)?.takeIf { it.length in 40..512 } ?: return null
        val publicKey = MessagingCrypto.parseEcPublic(publicKeyB64) ?: return null
        if (fingerprintOf(publicKey) != fingerprint) return null
        val ecdhB64 = (message["ecdh"] as? String)?.takeIf { it.length in 40..512 } ?: return null
        val ecdhKey = MessagingCrypto.parseEcPublic(ecdhB64) ?: return null
        val signature = (message["sig"] as? String)?.let { MessagingCrypto.unb64(it) } ?: return null
        if (signature.isEmpty() || signature.size > 256) return null
        val name = (message["name"] as? String)
            ?.trim()
            ?.take(MessagingProtocol.MAX_NAME_CHARS)
            ?.ifBlank { null }
            ?: "E-Crew user"
        return HelloInfo(name, fingerprint, publicKey, publicKeyB64, ecdhKey, ecdhB64, signature)
    }

    fun parseText(message: Map<String, Any?>): TextInfo? {
        if (message["t"] != MsgType.MESSAGE) return null
        val uuid = (message["uuid"] as? String)?.takeIf { isUuid(it) } ?: return null
        val body = message["body"] as? String ?: return null
        if (body.isEmpty()) return null
        if (body.length > MessagingProtocol.MAX_MESSAGE_CHARS) return null
        if (body.toByteArray(Charsets.UTF_8).size > MessagingProtocol.MAX_MESSAGE_BYTES) return null
        val ts = (message["ts"] as? Number)?.toLong() ?: 0L
        return TextInfo(uuid, body, ts)
    }

    fun parseAck(message: Map<String, Any?>): String? {
        if (message["t"] != MsgType.ACK) return null
        return (message["uuid"] as? String)?.takeIf { isUuid(it) }
    }

    /** SHA-256(X.509 public key) truncated to 16 bytes, hex - the shared fingerprint rule. */
    fun fingerprintOf(publicKey: PublicKey): String {
        val digest = MessagingCrypto.sha256(publicKey.encoded)
        val sb = StringBuilder(MessagingProtocol.FP_HEX_CHARS)
        for (i in 0 until MessagingProtocol.FP_HEX_CHARS / 2) {
            val b = digest[i].toInt() and 0xFF
            sb.append("0123456789abcdef"[b ushr 4])
            sb.append("0123456789abcdef"[b and 0x0F])
        }
        return sb.toString()
    }

    fun isUuid(value: String): Boolean {
        if (value.length != 36) return false
        for (i in value.indices) {
            val c = value[i]
            when (i) {
                8, 13, 18, 23 -> if (c != '-') return false
                else -> if (!(c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F')) return false
            }
        }
        return true
    }

    /** Compact helper for tests and debug paths. */
    fun encode(message: Map<String, Any?>): String = Json.encode(message)
}
