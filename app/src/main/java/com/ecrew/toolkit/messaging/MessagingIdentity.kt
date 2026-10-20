package com.ecrew.toolkit.messaging

import java.security.KeyPair

/**
 * This install's messaging identity: a persistent ECDSA P-256 keypair. The fingerprint is
 * the first 16 bytes of SHA-256 over the X.509 public key encoding, shown as 32 lowercase
 * hex characters (8 groups of 4 in the UI). Fingerprint == peer id everywhere.
 */
class MessagingIdentity(val keyPair: KeyPair) {

    /** 32 lowercase hex chars; deterministic over the public key. */
    val fingerprint: String by lazy {
        val digest = MessagingCrypto.sha256(keyPair.public.encoded)
        buildString(32) {
            for (i in 0 until 16) {
                val b = digest[i].toInt() and 0xFF
                append(HEX[b ushr 4])
                append(HEX[b and 0x0F])
            }
        }
    }

    val publicKeyB64: String by lazy { MessagingCrypto.encodePublicB64(keyPair.public) }

    fun sign(data: ByteArray): ByteArray =
        MessagingCrypto.sign(keyPair.private, data)

    companion object {
        fun generate(): MessagingIdentity =
            MessagingIdentity(MessagingCrypto.generateEcKeyPair())

        private const val HEX = "0123456789abcdef"
    }
}
