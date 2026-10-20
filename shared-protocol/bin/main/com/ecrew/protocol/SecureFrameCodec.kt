package com.ecrew.protocol

import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Raised for any authentication / replay / lifecycle failure on a sealed frame. */
class SecureFrameException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * AES-256-GCM frame codec for one direction pair of a session.
 *
 * Wire format of a sealed frame: `nonce(12) || ciphertext || tag(16)`.
 *
 * Nonce layout: `counter_low32(4, big-endian) || random(8)`.
 * The sender keeps a logical 64-bit monotonic counter starting at 1. Only the low 32 bits
 * travel on the wire; the receiver reconstructs the full counter against its last accepted
 * value (recorded deviation D5: a 64-bit counter cannot fit a 4-byte nonce prefix).
 * Sessions abort after 2^32 frames, which is unreachable in practice (8 fps => ~17 years).
 *
 * Replay protection: a frame is accepted only when its reconstructed counter is strictly
 * greater than the last accepted counter, and only after the AEAD tag verifies (the counter
 * never advances for tampered frames). Rejections raise [SecureFrameException].
 *
 * KEY HANDLING - HARD-WON LESSON (do not "optimize" this away):
 * `key` MUST be handed to JCE via a standard [SecretKeySpec]. SunJCE's GaloisCounterMode
 * assumes `Key.getEncoded()` returns a fresh, disposable array and ZEROES it in two places
 * (after decrypt-init, and for the previous key array on every new encrypt-init - see
 * com.sun.crypto.provider.GaloisCounterMode.init in the JDK sources). A custom Key whose
 * `getEncoded()` returned the live backing array caused the SECOND sealed frame to be
 * encrypted under an all-zero key (reproduced + root-caused on JDK 17; guarded by
 * SecureFrameCodecTest). SecretKeySpec clones on construction and on every getEncoded()
 * call, which makes both JDK zeroing paths harmless.
 *
 * Thread-safety: all operations are synchronized; use one codec per session, both directions.
 * The caller-provided key array is zeroed by [close] (security requirement: keys are wiped
 * on session end). Do not reuse the array after constructing the codec.
 */
class SecureFrameCodec(
    key: ByteArray,
    private val random: SecureRandom = SecureRandom()
) : AutoCloseable {

    /** The caller's derived key. Wiped in place by [close]; not used for crypto directly. */
    private val callerKeyRef: ByteArray

    private val keySpec: SecretKeySpec
    private val encryptCipher: Cipher
    private val decryptCipher: Cipher
    private var sendCounter = 0L
    private var lastAccepted = -1L
    private var closed = false

    init {
        require(key.size == KeyDerivation.KEY_BYTES) { "key must be ${KeyDerivation.KEY_BYTES} bytes" }
        callerKeyRef = key
        keySpec = SecretKeySpec(key, "AES")
        encryptCipher = Cipher.getInstance("AES/GCM/NoPadding")
        decryptCipher = Cipher.getInstance("AES/GCM/NoPadding")
    }

    /** Seals [plaintext] into `nonce || ciphertext || tag`. */
    @Synchronized
    fun seal(plaintext: ByteArray): ByteArray {
        checkOpen()
        sendCounter += 1
        require(sendCounter <= 0xFFFFFFFFL) { "session frame budget exhausted" }
        val nonce = nonceFor(sendCounter)
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(TAG_BYTES * 8, nonce))
        val sealed = encryptCipher.doFinal(plaintext)
        return nonce + sealed
    }

    /** Opens a sealed frame, enforcing uniqueness + monotonic counter (replay protection). */
    @Synchronized
    fun open(frame: ByteArray): ByteArray {
        checkOpen()
        if (frame.size < NONCE_BYTES + TAG_BYTES) throw SecureFrameException("frame too short")
        val nonce = frame.copyOfRange(0, NONCE_BYTES)
        val seq = reconstructCounter(low32Of(nonce))
        val ciphertext = frame.copyOfRange(NONCE_BYTES, frame.size)
        val plaintext = try {
            decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(TAG_BYTES * 8, nonce))
            decryptCipher.doFinal(ciphertext)
        } catch (e: Exception) {
            // AEADBadTagException and friends: authentication failed. Do NOT advance counter.
            throw SecureFrameException("authentication failed", e)
        }
        lastAccepted = seq
        return plaintext
    }

    /** Number of frames sealed so far (monotonic). */
    @get:Synchronized
    val framesSealed: Long
        get() = sendCounter

    @Synchronized
    override fun close() {
        if (!closed) {
            closed = true
            // Security requirement: wipe the derived key bytes on session end.
            Arrays.fill(callerKeyRef, 0.toByte())
            // Residual (accepted): SecretKeySpec's internal clone cannot be reached from here.
        }
    }

    // ---------------------------------------------------------------- internals

    private fun checkOpen() {
        if (closed) throw SecureFrameException("codec is closed")
    }

    private fun nonceFor(counter: Long): ByteArray {
        val nonce = ByteArray(NONCE_BYTES)
        nonce[0] = (counter ushr 24 and 0xFF).toByte()
        nonce[1] = (counter ushr 16 and 0xFF).toByte()
        nonce[2] = (counter ushr 8 and 0xFF).toByte()
        nonce[3] = (counter and 0xFF).toByte()
        val randomBytes = ByteArray(NONCE_BYTES - 4)
        random.nextBytes(randomBytes)
        System.arraycopy(randomBytes, 0, nonce, 4, randomBytes.size)
        return nonce
    }

    private fun low32Of(nonce: ByteArray): Long =
        ((nonce[0].toLong() and 0xFF) shl 24) or
            ((nonce[1].toLong() and 0xFF) shl 16) or
            ((nonce[2].toLong() and 0xFF) shl 8) or
            (nonce[3].toLong() and 0xFF)

    private fun reconstructCounter(low32: Long): Long {
        val last = lastAccepted
        if (last < 0) return low32 // first frame of the session
        var candidate = (last and -0x1_0000_0000L) or low32
        if (candidate <= last) {
            candidate += 1L shl 32
        }
        val delta = candidate - last
        if (delta <= 0 || delta > 0x7FFF_FFFFL) throw SecureFrameException("replay rejected")
        return candidate
    }

    companion object {
        const val NONCE_BYTES = 12
        const val TAG_BYTES = 16
    }
}
