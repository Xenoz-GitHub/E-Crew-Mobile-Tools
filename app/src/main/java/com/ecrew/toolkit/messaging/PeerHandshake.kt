package com.ecrew.toolkit.messaging

import com.ecrew.protocol.Frames
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.KeyPair

/** Raised when the peer's hello cannot be trusted; the session is closed without a reply. */
class HandshakeException(message: String) : Exception(message)

/** Raised when the peer is on the local block list (silent close, no feedback to the peer). */
class BlockedPeerException : Exception("blocked peer")

/**
 * Messaging handshake (design note, "Handshake"): both sides exchange a hello carrying the
 * protocol version, display name, identity public key, a fresh ephemeral ECDH key and an
 * ECDSA signature over (role | fingerprint | ephemeral key). The session key is
 * HKDF-SHA-256 over the ephemeral ECDH secret with a transcript salt binding both
 * identities and both ephemeral keys.
 *
 * TOFU limit (documented): an active man-in-the-middle on the very first contact can relay
 * two sessions; out-of-band fingerprint comparison is the mitigation.
 */
object PeerHandshake {

    class Outcome(
        val peerFingerprint: String,
        val peerName: String,
        val sessionKey: ByteArray
    )

    /** Initiator is the side that opened the TCP/RFCOMM connection. */
    fun perform(
        input: DataInputStream,
        output: DataOutputStream,
        identity: MessagingIdentity,
        displayName: String,
        initiator: Boolean,
        clock: () -> Long = System::currentTimeMillis
    ): Outcome {
        val ephemeral: KeyPair = MessagingCrypto.generateEcKeyPair()
        val ecdhB64 = MessagingCrypto.encodePublicB64(ephemeral.public)
        val role = if (initiator) ROLE_INITIATOR else ROLE_RESPONDER
        val signature = identity.sign(signatureContext(role, identity.fingerprint, ecdhB64))
        val hello = MessageCodec.hello(
            version = MessagingProtocol.VERSION,
            displayName = displayName.take(MessagingProtocol.MAX_NAME_CHARS),
            fingerprint = identity.fingerprint,
            publicKeyB64 = identity.publicKeyB64,
            ecdhB64 = ecdhB64,
            signatureB64 = MessagingCrypto.b64(signature),
            ts = clock()
        )

        val peerHello: Map<String, Any?>
        if (initiator) {
            Frames.writePlain(output, hello)
            peerHello = Frames.readPlain(input, MessagingProtocol.MAX_HANDSHAKE_BYTES)
        } else {
            peerHello = Frames.readPlain(input, MessagingProtocol.MAX_HANDSHAKE_BYTES)
            Frames.writePlain(output, hello)
        }

        val parsed = MessageCodec.parseHello(peerHello)
            ?: throw HandshakeException("malformed hello")
        val peerRole = if (initiator) ROLE_RESPONDER else ROLE_INITIATOR
        val context = signatureContext(peerRole, parsed.fingerprint, parsed.ecdhB64)
        if (!MessagingCrypto.verify(parsed.publicKey, context, parsed.signature)) {
            throw HandshakeException("hello signature verification failed")
        }

        val shared = try {
            MessagingCrypto.ecdhSharedSecret(ephemeral.private, parsed.ecdhKey)
        } catch (_: Exception) {
            throw HandshakeException("key agreement failed")
        }
        val initiatorFp = if (initiator) identity.fingerprint else parsed.fingerprint
        val responderFp = if (initiator) parsed.fingerprint else identity.fingerprint
        val initiatorEcdh = if (initiator) ecdhB64 else parsed.ecdhB64
        val responderEcdh = if (initiator) parsed.ecdhB64 else ecdhB64
        val salt = MessagingCrypto.sha256(
            ("$SALT_CONTEXT|$initiatorFp|$responderFp|$initiatorEcdh|$responderEcdh")
                .toByteArray(Charsets.UTF_8)
        )
        val sessionKey = try {
            MessagingCrypto.hkdfSha256(
                ikm = shared,
                salt = salt,
                info = INFO,
                length = MessagingCrypto.SESSION_KEY_BYTES
            )
        } finally {
            MessagingCrypto.wipe(shared)
        }
        return Outcome(parsed.fingerprint, parsed.displayName, sessionKey)
    }

    fun signatureContext(role: String, fingerprint: String, ecdhB64: String): ByteArray =
        "$SIGN_CONTEXT|$role|$fingerprint|$ecdhB64".toByteArray(Charsets.UTF_8)

    const val ROLE_INITIATOR = "initiator"
    const val ROLE_RESPONDER = "responder"

    private const val SIGN_CONTEXT = "ecrew-msg-v1"
    private const val SALT_CONTEXT = "ecrew-msg-v1-salt"
    private val INFO = "ecrew-msg-v1 session".toByteArray(Charsets.UTF_8)
}
