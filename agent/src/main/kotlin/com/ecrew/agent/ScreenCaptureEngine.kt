package com.ecrew.agent

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Handler
import android.os.HandlerThread
import android.util.DisplayMetrics
import android.view.WindowManager
import com.ecrew.protocol.ProtocolConstants
import java.io.ByteArrayOutputStream

/**
 * MediaProjection screen capture: JPEG frames at <= 8 fps (CAPTURE_MAX_FPS), quality 55,
 * longest edge <= 1024 px.
 *
 * Backpressure (spec Component 5): the ImageReader holds at most 2 images and
 * acquireLatestImage() drops stale ones while the session socket write is in flight. The
 * frameSink callback is invoked on the capture thread; StreamSession.send is non-blocking
 * (try-lock), so a busy socket drops the current frame instead of queuing it.
 */
class ScreenCaptureEngine(
    private val context: Context,
    private val frameSink: (jpeg: ByteArray, width: Int, height: Int) -> Unit,
    private val onStopped: (reason: String) -> Unit
) {
    private var projection: MediaProjection? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var imageReader: ImageReader? = null
    private var thread: HandlerThread? = null

    @Volatile
    private var lastFrameAt = 0L

    @Volatile
    private var stopped = false

    fun start(resultCode: Int, resultData: Intent) {
        stop()
        stopped = false
        val manager = context.getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        val newProjection = manager.getMediaProjection(resultCode, resultData)
        if (newProjection == null) {
            onStopped("projection-unavailable")
            return
        }
        val metrics = realMetrics()
        val longestEdge = maxOf(metrics.widthPixels, metrics.heightPixels)
        val scale = minOf(1.0, ProtocolConstants.MAX_STREAM_EDGE.toDouble() / longestEdge.toDouble())
        val width = (metrics.widthPixels * scale).toInt().coerceAtLeast(2)
        val height = (metrics.heightPixels * scale).toInt().coerceAtLeast(2)

        val captureThread = HandlerThread("ecrew-capture")
        captureThread.start()
        val handler = Handler(captureThread.looper)

        val reader = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 2)
        reader.setOnImageAvailableListener({ activeReader -> onImageAvailable(activeReader) }, handler)

        val display = newProjection.createVirtualDisplay(
            "ecrew-capture",
            width,
            height,
            metrics.densityDpi,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            reader.surface,
            null,
            handler
        )
        newProjection.registerCallback(object : MediaProjection.Callback() {
            override fun onStop() {
                if (!stopped) onStopped("projection-stopped-by-user")
                stop()
            }
        }, handler)

        projection = newProjection
        imageReader = reader
        virtualDisplay = display
        thread = captureThread
    }

    private fun onImageAvailable(reader: ImageReader) {
        val image = reader.acquireLatestImage() ?: return
        try {
            val now = System.currentTimeMillis()
            if (now - lastFrameAt < FRAME_INTERVAL_MS) return // fps cap
            lastFrameAt = now

            val plane = image.planes[0]
            val pixelStride = plane.pixelStride
            val rowStride = plane.rowStride
            val width = image.width
            val height = image.height
            val rowPadding = rowStride - pixelStride * width
            val paddedWidth = width + rowPadding / pixelStride

            val padded = Bitmap.createBitmap(paddedWidth, height, Bitmap.Config.ARGB_8888)
            padded.copyPixelsFromBuffer(plane.buffer)
            val cropped = if (paddedWidth != width) {
                Bitmap.createBitmap(padded, 0, 0, width, height)
            } else {
                padded
            }
            val output = ByteArrayOutputStream(64 * 1024)
            cropped.compress(Bitmap.CompressFormat.JPEG, ProtocolConstants.JPEG_QUALITY, output)
            if (cropped !== padded) cropped.recycle()
            padded.recycle()
            frameSink(output.toByteArray(), width, height)
        } catch (_: Exception) {
            // A dropped frame must never kill the capture loop.
        } finally {
            image.close()
        }
    }

    fun stop() {
        stopped = true
        virtualDisplay?.release()
        virtualDisplay = null
        imageReader?.close()
        imageReader = null
        projection?.stop()
        projection = null
        thread?.quitSafely()
        thread = null
    }

    @Suppress("DEPRECATION") // defaultDisplay.getRealMetrics: correct for the target-28 legacy model
    private fun realMetrics(): DisplayMetrics {
        val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val metrics = DisplayMetrics()
        windowManager.defaultDisplay.getRealMetrics(metrics)
        return metrics
    }

    private companion object {
        val FRAME_INTERVAL_MS = 1000L / ProtocolConstants.CAPTURE_MAX_FPS
    }
}
