package com.ecrew.protocol

import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * PBKDF2-HMAC-SHA256 key derivation for session keys.
 *
 * Non-negotiable parameters (feature spec, Component 7):
 *  - 200,000 iterations
 *  - 16-byte random salt (exchanged in the plaintext handshake)
 *  - 256-bit derived key
 */
object KeyDerivation {
    const val ITERATIONS = 200_000
    const val SALT_BYTES = 16
    const val KEY_BITS = 256
    const val KEY_BYTES = KEY_BITS / 8

    fun deriveKey(code: String, salt: ByteArray): ByteArray {
        require(code.isNotEmpty()) { "code must not be empty" }
        require(salt.size == SALT_BYTES) { "salt must be $SALT_BYTES bytes" }
        val spec = PBEKeySpec(code.toCharArray(), salt, ITERATIONS, KEY_BITS)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    fun randomSalt(random: SecureRandom = SecureRandom()): ByteArray =
        ByteArray(SALT_BYTES).also { random.nextBytes(it) }

    /** Best-effort key wipe: zero the derived key bytes in place. */
    fun wipe(keyBytes: ByteArray) {
        Arrays.fill(keyBytes, 0.toByte())
    }
}
