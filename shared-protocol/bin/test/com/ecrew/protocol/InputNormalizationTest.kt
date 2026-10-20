package com.ecrew.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.abs

/**
 * Input normalization tests: tap coordinates must round-trip within +/-1 pixel for the
 * common resolutions (480x800, 720x1280, 1080x1920, 1080x2340), including cross-resolution
 * (controller -> agent display) mapping.
 */
class InputNormalizationTest {

    private val resolutions = listOf(
        480 to 800,
        720 to 1280,
        1080 to 1920,
        1080 to 2340
    )

    @Test
    fun sameResolutionRoundTripWithinOnePixel() {
        for ((w, h) in resolutions) {
            for (px in samplePixels(w)) {
                val normalized = InputNormalization.normalize(px, w)
                val back = InputNormalization.denormalize(normalized, w)
                assertTrue("x $px on width $w -> $back", abs(back - px) <= 1)
            }
            for (py in samplePixels(h)) {
                val normalized = InputNormalization.normalize(py, h)
                val back = InputNormalization.denormalize(normalized, h)
                assertTrue("y $py on height $h -> $back", abs(back - py) <= 1)
            }
        }
    }

    @Test
    fun crossResolutionMappingWithinOnePixel() {
        val (controllerW, controllerH) = 1080 to 2340
        for ((agentW, agentH) in resolutions) {
            for (px in samplePixels(controllerW)) {
                val onAgent = InputNormalization.roundTrip(px, controllerW, agentW)
                val expected = px.toDouble() * agentW / controllerW
                assertTrue(
                    "controller x $px -> agent $onAgent, expected ~$expected",
                    abs(onAgent - expected) <= 1.0
                )
            }
            for (py in samplePixels(controllerH)) {
                val onAgent = InputNormalization.roundTrip(py, controllerH, agentH)
                val expected = py.toDouble() * agentH / controllerH
                assertTrue(
                    "controller y $py -> agent $onAgent, expected ~$expected",
                    abs(onAgent - expected) <= 1.0
                )
            }
        }
    }

    @Test
    fun normalizedValuesStayInUnitRange() {
        for ((w, _) in resolutions) {
            assertEquals(0.0, InputNormalization.normalize(0, w), 0.0)
            assertTrue(InputNormalization.normalize(w - 1, w) < 1.0)
            assertTrue(InputNormalization.normalize(w + 500, w) <= 1.0)
            assertEquals(0.0, InputNormalization.normalize(-10, w), 0.0)
        }
    }

    @Test
    fun denormalizeClampsToDisplayBounds() {
        for ((w, _) in resolutions) {
            assertEquals(w - 1, InputNormalization.denormalize(1.0, w))
            assertEquals(0, InputNormalization.denormalize(0.0, w))
            assertEquals(0, InputNormalization.denormalize(-0.5, w))
            assertEquals(w - 1, InputNormalization.denormalize(1.5, w))
        }
    }

    /** Corners, edges, center, and quarter points. */
    private fun samplePixels(extent: Int): List<Int> {
        val candidates = listOf(
            0,
            1,
            2,
            extent / 4,
            extent / 2,
            extent / 2 + 1,
            extent * 3 / 4,
            extent - 3,
            extent - 2,
            extent - 1
        )
        return candidates.filter { it in 0 until extent }.distinct()
    }
}
