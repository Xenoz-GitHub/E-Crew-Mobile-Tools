package com.ecrew.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.AEADBadTagException

/**
 * Security tests for [SecureFrameCodec]:
 * round-trip, tampered-tag rejection, replay rejection, nonce uniqueness over 100,000
 * frames, and key wiping on close.
 */
class SecureFrameCodecTest {

    private fun newKey(): ByteArray = CACHED_KEY.copyOf()

    @Test
    fun roundTrip() {
        val key = newKey()
        val sender = SecureFrameCodec(key)
        val receiver = SecureFrameCodec(key.copyOf())

        val message = "hello world".toByteArray()
        val frame = sender.seal(message)
        assertArrayEquals(message, receiver.open(frame))

        // A second frame through the same pair also round-trips.
        val frame2 = sender.seal(ByteArray(0))
        assertArrayEquals(ByteArray(0), receiver.open(frame2))
    }

    @Test
    fun tamperedTagRejected() {
        val key = newKey()
        val sender = SecureFrameCodec(key)
        val receiver = SecureFrameCodec(key.copyOf())

        val frame = sender.seal("top secret".toByteArray())
        frame[frame.size - 1] = (frame[frame.size - 1].toInt() xor 0x01).toByte()

        val failure = assertThrows(SecureFrameException::class.java) { receiver.open(frame) }
        assertTrue(failure.cause is AEADBadTagException || failure.cause != null)
    }

    @Test
    fun tamperedCiphertextRejected() {
        val key = newKey()
        val sender = SecureFrameCodec(key)
        val receiver = SecureFrameCodec(key.copyOf())

        val frame = sender.seal("top secret".toByteArray())
        frame[SecureFrameCodec.NONCE_BYTES + 1] = (frame[SecureFrameCodec.NONCE_BYTES + 1].toInt() xor 0x40).toByte()

        assertThrows(SecureFrameException::class.java) { receiver.open(frame) }
    }

    @Test
    fun replayRejected() {
        val key = newKey()
        val sender = SecureFrameCodec(key)
        val receiver = SecureFrameCodec(key.copyOf())

        val frame = sender.seal("once".toByteArray())
        assertArrayEquals("once".toByteArray(), receiver.open(frame))

        // Replaying the exact same frame must fail (counter <= last accepted).
        assertThrows(SecureFrameException::class.java) { receiver.open(frame) }
    }

    @Test
    fun reorderedFramesRejected() {
        val key = newKey()
        val sender = SecureFrameCodec(key)
        val receiver = SecureFrameCodec(key.copyOf())

        val frame1 = sender.seal("first".toByteArray())
        val frame2 = sender.seal("second".toByteArray())

        assertArrayEquals("second".toByteArray(), receiver.open(frame2))
        // The older frame is now a replay; must be rejected.
        assertThrows(SecureFrameException::class.java) { receiver.open(frame1) }
    }

    @Test
    fun nonceUniquenessOver100kFrames() {
        val key = newKey()
        val codecA = SecureFrameCodec(key)
        val codecB = SecureFrameCodec(key.copyOf())
        val seen = HashSet<String>(200_000)
        val payload = byteArrayOf(0x42)

        var previousCounterA = 0L
        var previousCounterB = 0L
        repeat(100_000) { i ->
            val fromA = i % 2 == 0
            val codec = if (fromA) codecA else codecB
            val frame = codec.seal(payload)
            val nonce = frame.copyOfRange(0, SecureFrameCodec.NONCE_BYTES)
            assertTrue("nonce collision at iteration $i", seen.add(hex(nonce)))

            // The counter prefix (first 4 bytes, big-endian) must advance by exactly one.
            val counter = ((nonce[0].toLong() and 0xFF) shl 24) or
                ((nonce[1].toLong() and 0xFF) shl 16) or
                ((nonce[2].toLong() and 0xFF) shl 8) or
                (nonce[3].toLong() and 0xFF)
            if (fromA) {
                assertEquals(previousCounterA + 1, counter)
                previousCounterA = counter
            } else {
                assertEquals(previousCounterB + 1, counter)
                previousCounterB = counter
            }
        }
        assertEquals(100_000, seen.size)
    }

    @Test
    fun closeWipesKeyBytesInPlace() {
        val key = newKey()
        val codec = SecureFrameCodec(key)
        codec.seal("x".toByteArray())
        codec.close()
        assertArrayEquals(ByteArray(KeyDerivation.KEY_BYTES), key)
        assertThrows(SecureFrameException::class.java) { codec.seal("y".toByteArray()) }
    }

    private fun hex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) sb.append("%02x".format(b.toInt() and 0xFF))
        return sb.toString()
    }

    private companion object {
        /**
         * Shared derived key; tests always operate on copies so wiping in one test cannot
         * leak into another. Derived once per suite (~150 ms) to keep the suite fast.
         */
        val CACHED_KEY: ByteArray by lazy {
            KeyDerivation.deriveKey("123456", ByteArray(KeyDerivation.SALT_BYTES) { it.toByte() })
        }
    }
}
