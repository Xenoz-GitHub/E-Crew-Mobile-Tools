package com.ecrew.protocol

import kotlin.math.roundToInt

/**
 * Tap/swipe coordinate normalization shared by the controller (sender) and the agent
 * (receiver). Coordinates travel as doubles in [0.0, 1.0] so the agent side is independent
 * of the controller display resolution.
 */
object InputNormalization {

    /** Pixel -> normalized. clamps into [0,1]. */
    fun normalize(pixel: Int, extent: Int): Double {
        require(extent > 0) { "extent must be positive" }
        return (pixel.toDouble() / extent.toDouble()).coerceIn(0.0, 1.0)
    }

    /** Normalized -> pixel on a target display of [extent]; clamps to [0, extent-1]. */
    fun denormalize(normalized: Double, extent: Int): Int {
        require(extent > 0) { "extent must be positive" }
        return (normalized * extent).roundToInt().coerceIn(0, extent - 1)
    }

    /** Round-trips a pixel coordinate through normalize/denormalize for a target display. */
    fun roundTrip(pixel: Int, fromExtent: Int, toExtent: Int): Int =
        denormalize(normalize(pixel, fromExtent), toExtent)
}
