package com.ecrew.toolkit.gridblocks

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.SoundPool
import android.view.HapticFeedbackConstants
import android.view.View
import com.ecrew.toolkit.R

/** SoundPool wrapper for the eight build-time synthesized WAVs. */
class GridBlocksAudio(private val context: Context) {
    private val pool: SoundPool
    private val ids = HashMap<String, Int>()
    private var loaded = 0
    private var muted = false

    val ready: Boolean get() = loaded >= FILES.size
    val loadedCount: Int get() = loaded

    init {
        val attributes = AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_GAME)
            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
            .build()
        pool = SoundPool.Builder()
            .setMaxStreams(8)
            .setAudioAttributes(attributes)
            .build()
        pool.setOnLoadCompleteListener { _, _, status ->
            if (status == 0) loaded++
        }
        FILES.forEach { (name, resource) ->
            ids[name] = pool.load(context, resource, 1)
        }
    }

    fun setMuted(value: Boolean) {
        muted = value
    }

    fun play(name: String, rate: Float = 1f, volume: Float = 0.6f) {
        if (muted) return
        val ringer = (context.getSystemService(Context.AUDIO_SERVICE) as AudioManager)
            .ringerMode
        if (ringer == AudioManager.RINGER_MODE_SILENT) return
        val id = ids[name] ?: return
        pool.play(id, volume, volume, 1, 0, rate.coerceIn(0.5f, 2f))
    }

    fun release() {
        pool.release()
    }

    companion object {
        val FILES: List<Pair<String, Int>> = listOf(
            "place" to R.raw.place,
            "clear" to R.raw.clear,
            "combo" to R.raw.combo,
            "overload" to R.raw.overload,
            "perfect" to R.raw.perfect,
            "corrupt" to R.raw.corrupt,
            "gameover" to R.raw.gameover,
            "ui_tap" to R.raw.ui_tap
        )
    }
}

/**
 * Haptics through View.performHapticFeedback, which uses the system haptic channel and
 * requires no VIBRATE permission. Custom waveform amplitudes from the design are therefore
 * not available; the closest lawful API 26-safe feedback constants are used instead.
 */
class GridBlocksHaptics {
    var enabled = true
    private var view: View? = null

    fun attach(target: View) {
        view = target
    }

    fun place() = feedback(HapticFeedbackConstants.KEYBOARD_TAP)
    fun clear() = feedback(HapticFeedbackConstants.CLOCK_TICK)
    fun combo() = feedback(HapticFeedbackConstants.LONG_PRESS)
    fun gameOver() = feedback(HapticFeedbackConstants.LONG_PRESS)

    private fun feedback(constant: Int) {
        if (!enabled) return
        try {
            view?.performHapticFeedback(constant)
        } catch (_: SecurityException) {
            // Haptics are optional and the system may disable them.
        }
    }
}
