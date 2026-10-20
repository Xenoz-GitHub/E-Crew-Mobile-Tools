package com.ecrew.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * Frame sizing test: a 1024x768 frame -> base64 -> JSON -> encrypted frame -> back to the
 * original bytes must be byte-identical.
 *
 * NOTE (recorded decision D7): this is a pure JVM test with no Android image codecs, so the
 * "JPEG" is a synthetic payload carrying real JPEG SOI/EOI markers with deterministic filler.
 * What the test proves is byte-identity through the full wire pipeline at realistic sizes;
 * on-device JPEG encode/decode is exercised by the manual emulator smoke test.
 */
class FrameSizingTest {

    private fun newKey(): ByteArray =
        KeyDerivation.deriveKey("654321", ByteArray(KeyDerivation.SALT_BYTES) { it.toByte() })

    @Test
    fun jpegRoundTripThroughFullPipeline() {
        val key = newKey()
        val sender = SecureFrameCodec(key)
        val receiver = SecureFrameCodec(key.copyOf())

        val width = 1024L
        val height = 768L
        val jpeg = syntheticJpeg(64 * 1024)

        val b64 = Base64.getEncoder().encodeToString(jpeg)
        val message = Messages.screenFrame(b64, width, height, ts = 1_776_500_000_000)

        val frame = sender.seal(Json.encode(message).toByteArray(Charsets.UTF_8))
        assertTrue("frame must fit the wire cap", frame.size <= ProtocolConstants.MAX_FRAME_BYTES)

        val decoded = Json.parse(String(receiver.open(frame), Charsets.UTF_8))
        assertEquals(Msg.SCREEN_FRAME, Messages.type(decoded))
        assertEquals(width, Messages.long(decoded, "w"))
        assertEquals(height, Messages.long(decoded, "h"))

        val jpegOut = Base64.getDecoder().decode(Messages.string(decoded, "jpeg")!!)
        assertArrayEquals("JPEG bytes must be identical after the full pipeline", jpeg, jpegOut)
    }

    @Test
    fun jsonRoundTripPreservesMessageFields() {
        val swipe = Messages.swipe(0.25, 0.5, 0.75, 0.9, 240)
        val decoded = Json.parse(Json.encode(swipe))
        assertEquals(Msg.SWIPE, Messages.type(decoded))
        assertEquals(0.25, Messages.double(decoded, "x1")!!, 0.0)
        assertEquals(0.9, Messages.double(decoded, "y2")!!, 0.0)
        assertEquals(240L, Messages.long(decoded, "durationMs"))
    }

    /** Deterministic pseudo-JPEG: SOI + APP0 header, LCG filler, EOI tail. */
    private fun syntheticJpeg(size: Int): ByteArray {
        require(size > 32) { "size too small" }
        val bytes = ByteArray(size)
        bytes[0] = 0xFF.toByte(); bytes[1] = 0xD8.toByte(); bytes[2] = 0xFF.toByte(); bytes[3] = 0xE0.toByte()
        bytes[4] = 0x00; bytes[5] = 0x10; bytes[6] = 0x4A; bytes[7] = 0x46; bytes[8] = 0x49; bytes[9] = 0x46
        var state = 0x12345678L
        for (i in 10 until size - 2) {
            state = (state * 6364136223846793005L + 1442695040888963407L)
            bytes[i] = (state ushr 33).toByte()
        }
        bytes[size - 2] = 0xFF.toByte(); bytes[size - 1] = 0xD9.toByte()
        return bytes
    }
}
