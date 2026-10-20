package com.ecrew.toolkit.gridblocks

/**
 * Fixed VFX catalog from the frozen design note. The view maps each event to one of these
 * effect names; the budget test pins the count at 14 and the Reduce Motion policy.
 */
object EffectKinds {
    const val NEON_BLOOM = "NEON_BLOOM"
    const val SCANLINES = "SCANLINES"
    const val CRT_VIGNETTE = "CRT_VIGNETTE"
    const val GLITCH_SLICE = "GLITCH_SLICE"
    const val SCREEN_SHAKE = "SCREEN_SHAKE"
    const val CORRUPTION_FILL = "CORRUPTION_FILL"
    const val SHARD_BURST = "SHARD_BURST"
    const val COMBO_POPUP = "COMBO_POPUP"
    const val GRID_PULSE = "GRID_PULSE"
    const val DRAG_GHOST_TRAIL = "DRAG_GHOST_TRAIL"
    const val OVERLOAD_CHARGE_GLOW = "OVERLOAD_CHARGE_GLOW"
    const val OVERLOAD_DETONATION = "OVERLOAD_DETONATION"
    const val CELL_PLACEMENT_POP = "CELL_PLACEMENT_POP"
    const val INVALID_DROP = "INVALID_DROP"

    val ALL: List<String> = listOf(
        NEON_BLOOM,
        SCANLINES,
        CRT_VIGNETTE,
        GLITCH_SLICE,
        SCREEN_SHAKE,
        CORRUPTION_FILL,
        SHARD_BURST,
        COMBO_POPUP,
        GRID_PULSE,
        DRAG_GHOST_TRAIL,
        OVERLOAD_CHARGE_GLOW,
        OVERLOAD_DETONATION,
        CELL_PLACEMENT_POP,
        INVALID_DROP
    )

    /** Effects disabled by Reduce Motion (design section 7). */
    val REDUCE_MOTION_DISABLED: Set<String> = setOf(
        GLITCH_SLICE,
        SCREEN_SHAKE,
        SHARD_BURST,
        GRID_PULSE,
        OVERLOAD_DETONATION,
        CELL_PLACEMENT_POP,
        INVALID_DROP
    )

    val LOW_TIER_DISABLED: Set<String> = setOf(
        SCANLINES,
        GLITCH_SLICE,
        GRID_PULSE
    )

    fun enabled(effect: String, reduceMotion: Boolean, tier: QualityTier): Boolean {
        if (effect !in ALL) return false
        if (reduceMotion && effect in REDUCE_MOTION_DISABLED) return false
        if (tier == QualityTier.LOW && effect in LOW_TIER_DISABLED) return false
        return true
    }
}

enum class QualityTier { HIGH, LOW }

/** Rolling frame-time window that degrades to LOW above 22 ms mean and recovers under 18 ms. */
class QualityGovernor(
    private val windowFrames: Int = 120,
    private val recoveryFrames: Int = 300
) {
    private val frameTimes = LongArray(windowFrames)
    private var cursor = 0
    private var samples = 0
    private var recovery = 0
    var tier: QualityTier = QualityTier.HIGH
        private set

    fun frame(frameNanos: Long) {
        frameTimes[cursor] = frameNanos
        cursor = (cursor + 1) % windowFrames
        if (samples < windowFrames) samples++
        if (samples < windowFrames) return
        val averageMs = frameTimes.sum() / samples / 1_000_000.0
        if (averageMs > 22.0 && tier == QualityTier.HIGH) {
            tier = QualityTier.LOW
            recovery = 0
        } else if (averageMs < 18.0 && tier == QualityTier.LOW) {
            recovery++
            if (recovery >= recoveryFrames) {
                tier = QualityTier.HIGH
                recovery = 0
            }
        } else if (averageMs >= 18.0) {
            recovery = 0
        }
    }

    fun particleCap(): Int = if (tier == QualityTier.LOW) LOW_PARTICLE_CAP else HIGH_PARTICLE_CAP

    companion object {
        const val HIGH_PARTICLE_CAP = 240
        const val LOW_PARTICLE_CAP = 120
    }
}

/** Fixed-capacity particle data, no allocation after construction. */
class ParticlePool(private val capacity: Int) {
    val x = FloatArray(capacity)
    val y = FloatArray(capacity)
    val vx = FloatArray(capacity)
    val vy = FloatArray(capacity)
    val bornAt = LongArray(capacity)
    val lifeMs = IntArray(capacity)
    val color = IntArray(capacity)
    private val random = java.util.Random(0x9E3779B9L)
    var activeCapacity: Int = capacity

    fun spawn(
        count: Int,
        originX: Float,
        originY: Float,
        colorValue: Int,
        now: Long
    ) {
        repeat(count) {
            val slot = findFree(now) ?: return
            val angle = random.nextDouble() * Math.PI * 2
            val speed = 260.0 + random.nextDouble() * 340.0
            x[slot] = originX
            y[slot] = originY
            vx[slot] = (Math.cos(angle) * speed).toFloat()
            vy[slot] = (Math.sin(angle) * speed).toFloat()
            bornAt[slot] = now
            lifeMs[slot] = 450 + random.nextInt(250)
            color[slot] = colorValue
        }
    }

    fun activeCount(now: Long): Int {
        var count = 0
        for (index in 0 until capacity) {
            if (lifeMs[index] > 0 && now - bornAt[index] < lifeMs[index]) count++
        }
        return count
    }

    fun clear() {
        lifeMs.fill(0)
        bornAt.fill(0)
    }

    private fun findFree(now: Long): Int? {
        for (index in 0 until activeCapacity) {
            if (lifeMs[index] == 0 || now - bornAt[index] >= lifeMs[index]) {
                return index
            }
        }
        return null
    }
}
