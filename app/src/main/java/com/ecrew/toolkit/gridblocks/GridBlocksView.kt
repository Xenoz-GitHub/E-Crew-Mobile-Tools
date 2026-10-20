package com.ecrew.toolkit.gridblocks

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.BitmapShader
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.PorterDuff
import android.graphics.PorterDuffXfermode
import android.graphics.RadialGradient
import android.graphics.Rect
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.Typeface
import android.os.SystemClock
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View
import com.ecrew.toolkit.R
import java.util.ArrayDeque
import java.util.Random
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.roundToInt
import kotlin.math.sin

/**
 * Canvas-only GridBlocks board.
 *
 * The drag interaction deliberately lifts the piece above the finger. A translucent
 * finger ring stays under the touch point while the piece and its placement preview
 * float above it, so the hand never hides the target cells.
 */
class GridBlocksView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : View(context, attrs) {
    var engine: GameEngine? = null
        private set
    var settings: GridBlocksSettings = GridBlocksSettings(true, true, false, false, Mode.CLASSIC)
        private set

    fun updateSettings(newSettings: GridBlocksSettings) {
        settings = newSettings
        reduceMotion = newSettings.reduceMotion
        engine?.allowRotation = newSettings.allowRotation
        audio?.setMuted(!newSettings.sound)
        haptics?.enabled = newSettings.haptics
        invalidate()
    }

    var audio: GridBlocksAudio? = null
    var haptics: GridBlocksHaptics? = null
    var onChanged: (() -> Unit)? = null
    var onGameOver: ((GameEngine) -> Unit)? = null

    private val density = resources.displayMetrics.density
    private val backgroundPaint = Paint().apply { color = Color.rgb(5, 9, 15) }
    private val backgroundGradientPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val backgroundGlowPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val auroraPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(54f)
        strokeCap = Paint.Cap.ROUND
    }
    private val starPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val fireworkPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(2f)
        xfermode = PorterDuffXfermode(PorterDuff.Mode.ADD)
    }
    private val fireworkCorePaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val fireworkRingPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(1.2f)
    }
    private val fingerPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val fingerRingPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(1.5f)
    }
    private val boardPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.rgb(12, 21, 31) }
    private val boardEdgePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(1f)
        color = Color.argb(90, 90, 190, 230)
    }
    private val socketPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.rgb(13, 24, 34) }
    private val socketBorderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(0.8f)
        color = Color.argb(55, 104, 151, 181)
    }
    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(0.7f)
    }
    private val gridNodePaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val borderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(2f)
        color = Color.rgb(0, 229, 255)
    }
    private val cellPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val blockPaint = Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG)
    private val blockShadowPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.argb(120, 0, 0, 0)
    }
    private val blockRimPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(0.9f)
    }
    private val blockHighlightPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(1.1f)
    }
    private val targetFillPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val targetStrokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(2f)
    }
    private val rainbowPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(2.2f)
    }
    private val rainbowFillPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.rgb(184, 203, 214)
        textSize = dp(11f)
    }
    private val titlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textSize = dp(20f)
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        letterSpacing = 0.08f
    }
    private val flashPaint = Paint().apply { color = Color.argb(90, 255, 80, 80) }
    private val clearFlashPaint = Paint().apply { color = Color.argb(80, 180, 250, 255) }
    private val meterTrackPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.rgb(25, 40, 52) }
    private val corruptionPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.argb(180, 0, 229, 255)
        strokeWidth = dp(2f)
    }
    private val corruptionLinePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.argb(220, 255, 70, 70)
    }
    private val overlayPaint = Paint().apply { color = Color.argb(225, 3, 7, 13) }
    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG).apply {
        xfermode = PorterDuffXfermode(PorterDuff.Mode.ADD)
        alpha = 58
    }
    private val particlePaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val pulsePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(2f)
        color = Color.rgb(0, 229, 255)
    }
    private val detonationPaint = Paint().apply { color = Color.argb(160, 130, 230, 255) }
    private val glowBitmap64: Bitmap? = BitmapFactory.decodeResource(resources, R.drawable.glow_64)
    private val glowBitmap128: Bitmap? = BitmapFactory.decodeResource(resources, R.drawable.glow_128)
    private val glowBitmap256: Bitmap? = BitmapFactory.decodeResource(resources, R.drawable.glow_256)
    private val vignetteBitmap: Bitmap? =
        BitmapFactory.decodeResource(resources, R.drawable.vignette_256)
    private val scanlineBitmap: Bitmap? =
        BitmapFactory.decodeResource(resources, R.drawable.scanline_4h)
    private val blockAtlas: Bitmap? = decodeBlockAtlas()
    private val scanlinePaint: Paint = Paint().apply {
        val tile = scanlineBitmap
        if (tile != null) shader = BitmapShader(tile, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT)
        alpha = 15
    }
    private val vignettePaint = Paint(Paint.FILTER_BITMAP_FLAG)
    private val tempRect = RectF()
    private val shadowRect = RectF()
    private val pulseRect = RectF()
    private val blockSrc = Rect()
    private val frameRandom = Random(0xC0FFEEL)
    private val particles = ParticlePool(QualityGovernor.HIGH_PARTICLE_CAP)
    private val governor = QualityGovernor()
    private val fireworks = ArrayDeque<Firework>()
    private val auroraPaths = Array(3) { Path() }
    private val starX = FloatArray(STAR_COUNT)
    private val starY = FloatArray(STAR_COUNT)
    private val starPhase = FloatArray(STAR_COUNT)
    private val starSize = FloatArray(STAR_COUNT)
    private val hsv = FloatArray(3)
    private var reduceMotion = false
    private var lastFrameAt = 0L
    private var comboPopupUntil = 0L
    private var comboPopupText = ""
    private var perfectPulseUntil = 0L
    private var glitchUntil = 0L
    private var shakeUntil = 0L
    private var detonationUntil = 0L
    private var placementPopUntil = 0L
    private var clearGlowUntil = 0L
    private var rippleUntil = 0L
    private var rippleX = 0f
    private var rippleY = 0f
    private var placedMarks = IntArray(Board.CELL_COUNT)
    private val clearedMask = BooleanArray(Board.CELL_COUNT)
    private var lastRows = IntArray(0)
    private var lastCols = IntArray(0)
    private val boardRect = RectF()
    private val trayRect = RectF()
    private val overloadRect = RectF()
    private val cellRect = RectF()
    private var cellSize = 0f
    private var dragIndex = -1
    private var dragX = 0f
    private var dragY = 0f
    private var dragStartX = 0f
    private var dragStartY = 0f
    private var dragLift = 0f
    private var dragMoved = false
    private var rotation = 0
    private var lastTapAt = 0L
    private var lastDragParticleAt = 0L
    private var invalidUntil = 0L
    private var clearUntil = 0L
    private var gameOverReported = false
    private var traySlotWidth = 0f
    private var trayTop = 0f
    private var titleGradient: Shader? = null

    init {
        isFocusable = true
        isClickable = true
    }

    fun start(
        newEngine: GameEngine,
        newSettings: GridBlocksSettings,
        newAudio: GridBlocksAudio?,
        newHaptics: GridBlocksHaptics?,
        restored: GridBlocksSnapshot? = null
    ) {
        engine = newEngine
        settings = newSettings
        reduceMotion = newSettings.reduceMotion
        particles.activeCapacity = governor.particleCap()
        audio = newAudio
        haptics = newHaptics
        newHaptics?.attach(this)
        if (restored != null) {
            try {
                newEngine.restore(restored)
            } catch (_: Exception) {
                // A mismatched save is ignored rather than corrupting the run.
            }
        }
        gameOverReported = false
        dragIndex = -1
        dragLift = 0f
        rotation = 0
        fireworks.clear()
        contentDescription = describe(newEngine)
        invalidate()
        notifyChanged()
    }

    fun saveRun() {
        engine?.let { current ->
            if (!current.gameOver) {
                val store = GridBlocksStore(context)
                try {
                    store.saveRun(current)
                } catch (_: Exception) {
                    // Saving is best effort; the in-memory run is still valid.
                } finally {
                    store.close()
                }
            }
        }
    }

    fun overload() {
        val current = engine ?: return
        if (current.armOverload()) {
            audio?.play("ui_tap")
            invalidate()
        }
    }

    fun rotateFirstTray() {
        val current = engine ?: return
        val index = current.tray.indexOfFirst { it != null }
        if (index < 0) return
        if (current.rotateTray(index)) {
            audio?.play("ui_tap", 1.2f)
            haptics?.place()
            contentDescription = describe(current)
            notifyChanged()
            invalidate()
        }
    }

    override fun onSizeChanged(width: Int, height: Int, oldWidth: Int, oldHeight: Int) {
        super.onSizeChanged(width, height, oldWidth, oldHeight)
        val horizontalPadding = dp(8f)
        val top = dp(92f)
        val trayHeight = dp(98f)
        val availableHeight = height - top - trayHeight - dp(10f)
        val size = min(width - horizontalPadding * 2, min(availableHeight, dp(620f)))
            .coerceAtLeast(dp(120f))
        val left = (width - size) / 2f
        boardRect.set(left, top, left + size, top + size)
        cellSize = size / Board.SIZE
        trayTop = boardRect.bottom + dp(8f)
        trayRect.set(horizontalPadding, trayTop, width - horizontalPadding, trayTop + trayHeight)
        traySlotWidth = trayRect.width() / 3f
        overloadRect.set(width - dp(132f), dp(43f), width - dp(10f), dp(74f))
        dragLift = (cellSize * 1.45f).coerceIn(dp(48f), dp(112f))

        backgroundGradientPaint.shader = LinearGradient(
            0f, 0f, 0f, height.toFloat(),
            intArrayOf(
                Color.rgb(4, 8, 16),
                Color.rgb(9, 21, 35),
                Color.rgb(3, 8, 15)
            ),
            floatArrayOf(0f, 0.52f, 1f),
            Shader.TileMode.CLAMP
        )
        backgroundGlowPaint.shader = RadialGradient(
            width * 0.24f,
            height * 0.2f,
            maxOf(width, height) * 0.75f,
            intArrayOf(Color.argb(48, 30, 160, 210), Color.argb(0, 0, 0, 0)),
            null,
            Shader.TileMode.CLAMP
        )
        auroraPaint.shader = LinearGradient(
            0f, 0f, width.toFloat(), 0f,
            intArrayOf(
                Color.argb(0, 0, 229, 255),
                Color.argb(95, 0, 229, 255),
                Color.argb(85, 255, 80, 180),
                Color.argb(0, 255, 80, 180)
            ),
            null,
            Shader.TileMode.CLAMP
        )
        titleGradient = LinearGradient(
            0f, 0f, dp(230f), 0f,
            intArrayOf(Color.rgb(100, 245, 255), Color.rgb(100, 170, 255), Color.rgb(255, 115, 210)),
            null,
            Shader.TileMode.CLAMP
        )
        titlePaint.shader = titleGradient
        initBackground(width, height)
    }

    private fun initBackground(width: Int, height: Int) {
        val random = Random(0xB10C5L)
        for (index in starX.indices) {
            starX[index] = random.nextFloat() * width
            starY[index] = random.nextFloat() * height
            starPhase[index] = random.nextFloat() * 6.28f
            starSize[index] = dp(0.6f + random.nextFloat() * 1.3f)
        }
        for (index in auroraPaths.indices) {
            val path = auroraPaths[index]
            path.reset()
            val baseY = height * (0.18f + index * 0.15f)
            path.moveTo(-width * 0.25f, baseY)
            path.cubicTo(
                width * 0.18f, baseY - height * 0.13f,
                width * 0.55f, baseY + height * 0.11f,
                width * 1.25f, baseY - height * 0.03f
            )
        }
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val now = SystemClock.uptimeMillis()
        if (lastFrameAt != 0L) governor.frame((now - lastFrameAt) * 1_000_000L)
        lastFrameAt = now
        particles.activeCapacity = governor.particleCap()

        drawBackground(canvas, now)
        drawHud(canvas, now)

        var shakeX = 0f
        var shakeY = 0f
        if (!reduceMotion && now < shakeUntil) {
            val remaining = (shakeUntil - now) / 200f
            val magnitude = dp(8f) * remaining.coerceIn(0f, 1f)
            shakeX = (frameRandom.nextFloat() - 0.5f) * magnitude
            shakeY = (frameRandom.nextFloat() - 0.5f) * magnitude
        }

        canvas.save()
        canvas.translate(shakeX, shakeY)
        canvas.drawRoundRect(boardRect, dp(9f), dp(9f), boardPaint)
        drawSockets(canvas)
        drawGlow(canvas, now)
        drawCells(canvas, now)
        drawFireworks(canvas, now)
        drawClearHighlights(canvas, now)
        drawGrid(canvas, now)
        drawPlacementGuide(canvas, now)
        drawParticles(canvas, now)
        drawRipple(canvas, now)
        drawScanlines(canvas)
        drawVignette(canvas)
        drawComboPopup(canvas, now)
        drawPulse(canvas, now)
        drawTray(canvas)
        drawDrag(canvas)
        canvas.restore()

        if (now < clearUntil) canvas.drawRect(boardRect, clearFlashPaint)
        if (now < detonationUntil) canvas.drawRect(boardRect, detonationPaint)
        if (!reduceMotion && now < glitchUntil) drawGlitch(canvas, now)
        if (now < invalidUntil) canvas.drawRoundRect(boardRect, dp(9f), dp(9f), flashPaint)
        drawOverlay(canvas)

        if (
            now < invalidUntil || now < clearUntil || now < detonationUntil ||
            now < glitchUntil || now < perfectPulseUntil || now < comboPopupUntil ||
            now < placementPopUntil || now < clearGlowUntil || now < rippleUntil ||
            dragIndex >= 0 || fireworks.isNotEmpty()
        ) {
            postInvalidateOnAnimation()
        }
    }

    private fun drawBackground(canvas: Canvas, now: Long) {
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), backgroundPaint)
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), backgroundGradientPaint)
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), backgroundGlowPaint)

        if (!reduceMotion) {
            val drift = sin(now / 4200f) * dp(26f)
            for (index in auroraPaths.indices) {
                auroraPaint.alpha = (38 - index * 7).coerceAtLeast(12)
                canvas.save()
                canvas.translate(drift * (index - 1), sin(now / 3600f + index) * dp(8f))
                canvas.drawPath(auroraPaths[index], auroraPaint)
                canvas.restore()
            }
        }

        if (!reduceMotion && now < clearGlowUntil) {
            val energy = (clearGlowUntil - now) / CLEAR_GLOW_MS.toFloat()
            hsv[0] = ((now / 4) % 360).toFloat()
            hsv[1] = 0.7f
            hsv[2] = 1f
            particlePaint.color = Color.HSVToColor((26 * energy).toInt(), hsv)
            canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), particlePaint)
        }

        val starLimit = if (governor.tier == QualityTier.LOW) STAR_COUNT / 2 else STAR_COUNT
        for (index in 0 until starLimit) {
            val twinkle = if (reduceMotion) 0.55f else {
                0.35f + 0.35f * (sin(now / 900f + starPhase[index]) * 0.5f + 0.5f)
            }
            starPaint.color = Color.argb(
                (255 * twinkle).toInt().coerceIn(0, 255),
                if (index % 3 == 0) 255 else 130,
                if (index % 3 == 0) 225 else 210,
                255
            )
            canvas.drawCircle(starX[index], starY[index], starSize[index], starPaint)
        }
    }

    private fun drawFireworks(canvas: Canvas, now: Long) {
        if (reduceMotion || fireworks.isEmpty()) return
        val iterator = fireworks.iterator()
        while (iterator.hasNext()) {
            val firework = iterator.next()
            val progress = (now - firework.start) / FIREWORK_MS.toFloat()
            if (progress >= 1f) {
                iterator.remove()
                continue
            }
            if (progress < 0f) continue
            val fade = (1f - progress).coerceIn(0f, 1f)
            val radius = dp(8f) + progress * dp(130f) * firework.scale
            hsv[0] = firework.hue
            hsv[1] = 0.8f
            hsv[2] = 1f
            val color = Color.HSVToColor((235 * fade).toInt(), hsv)
            fireworkPaint.color = color
            fireworkPaint.strokeWidth = dp(1.4f + 2.2f * fade)
            fireworkCorePaint.color = Color.HSVToColor((26 * fade).toInt(), hsv)
            canvas.drawCircle(firework.x, firework.y, radius * 0.58f, fireworkCorePaint)
            for (ray in 0 until 12) {
                val angle = firework.seed + ray * (Math.PI * 2 / 12)
                val inner = radius * 0.22f
                val outer = radius * (0.72f + 0.22f * (ray % 3) / 2f)
                canvas.drawLine(
                    firework.x + cos(angle).toFloat() * inner,
                    firework.y + sin(angle).toFloat() * inner,
                    firework.x + cos(angle).toFloat() * outer,
                    firework.y + sin(angle).toFloat() * outer,
                    fireworkPaint
                )
                fireworkCorePaint.color = Color.HSVToColor((190 * fade).toInt(), hsv)
                canvas.drawCircle(
                    firework.x + cos(angle).toFloat() * outer,
                    firework.y + sin(angle).toFloat() * outer,
                    dp(1.6f + 1.3f * fade),
                    fireworkCorePaint
                )
            }
            fireworkCorePaint.color = Color.argb((90 * fade).toInt(), 255, 255, 255)
            canvas.drawCircle(firework.x, firework.y, dp(3f) + radius * 0.08f, fireworkCorePaint)
            hsv[1] = 0.55f
            fireworkRingPaint.color = Color.HSVToColor((110 * fade).toInt(), hsv)
            fireworkRingPaint.strokeWidth = dp(1.2f + 1.4f * fade)
            canvas.drawCircle(firework.x, firework.y, radius * 0.9f, fireworkRingPaint)
        }
    }

    private fun drawSockets(canvas: Canvas) {
        for (row in 0 until Board.SIZE) {
            for (col in 0 until Board.SIZE) {
                cellRect.set(
                    boardRect.left + col * cellSize + dp(2.2f),
                    boardRect.top + row * cellSize + dp(2.2f),
                    boardRect.left + (col + 1) * cellSize - dp(2.2f),
                    boardRect.top + (row + 1) * cellSize - dp(2.2f)
                )
                canvas.drawRoundRect(cellRect, dp(5f), dp(5f), socketPaint)
                canvas.drawRoundRect(cellRect, dp(5f), dp(5f), socketBorderPaint)
            }
        }
    }

    private fun drawGlow(canvas: Canvas, now: Long) {
        if (!EffectKinds.enabled(EffectKinds.NEON_BLOOM, reduceMotion, governor.tier)) return
        val glow = when {
            cellSize >= dp(48f) -> glowBitmap256
            cellSize >= dp(24f) -> glowBitmap128
            else -> glowBitmap64
        } ?: return
        val current = engine ?: return
        val halo = cellSize * 1.45f
        for (row in 0 until Board.SIZE) {
            for (col in 0 until Board.SIZE) {
                if (!current.board.isFilled(col, row)) continue
                val index = Board.index(col, row)
                val stored = current.board.cells[index]
                val colorIndex = colorIndexFor(stored, col, row)
                glowPaint.color = PieceCatalog.cellColors[colorIndex]
                tempRect.set(
                    boardRect.left + col * cellSize - (halo - cellSize) / 2f,
                    boardRect.top + row * cellSize - (halo - cellSize) / 2f,
                    boardRect.left + (col + 1) * cellSize + (halo - cellSize) / 2f,
                    boardRect.top + (row + 1) * cellSize + (halo - cellSize) / 2f
                )
                canvas.drawBitmap(glow, null, tempRect, glowPaint)
            }
        }
        val placedRemaining = (placementPopUntil - now) / 120f
        if (placedRemaining > 0f) {
            particlePaint.color = Color.argb((120 * placedRemaining).toInt(), 255, 255, 255)
            for (index in placedMarks.indices) {
                if (placedMarks[index] == 0) continue
                val col = index % Board.SIZE
                val row = index / Board.SIZE
                canvas.drawRoundRect(
                    boardRect.left + col * cellSize + dp(2f),
                    boardRect.top + row * cellSize + dp(2f),
                    boardRect.left + (col + 1) * cellSize - dp(2f),
                    boardRect.top + (row + 1) * cellSize - dp(2f),
                    dp(5f), dp(5f), particlePaint
                )
            }
        }
    }

    private fun drawCells(canvas: Canvas, now: Long) {
        val current = engine ?: return
        val rainbowActive = now < clearGlowUntil
        for (row in 0 until Board.SIZE) {
            for (col in 0 until Board.SIZE) {
                if (!current.board.isFilled(col, row)) continue
                val index = Board.index(col, row)
                val colorIndex = colorIndexFor(current.board.cells[index], col, row)
                cellRect.set(
                    boardRect.left + col * cellSize + dp(2f),
                    boardRect.top + row * cellSize + dp(2f),
                    boardRect.left + (col + 1) * cellSize - dp(2f),
                    boardRect.top + (row + 1) * cellSize - dp(2f)
                )
                drawBlock(canvas, cellRect, colorIndex, 255, true)

                val depth = current.board.corruptionDepth[index]
                if (depth > 0) {
                    val stripeStep = cellRect.height() / 4f
                    for (stripeIndex in 1..3) {
                        val y = cellRect.top + stripeStep * stripeIndex
                        canvas.drawLine(
                            cellRect.left + dp(3f), y, cellRect.right - dp(3f), y,
                            corruptionPaint
                        )
                    }
                    canvas.drawLine(
                        cellRect.left + dp(4f),
                        cellRect.centerY(),
                        cellRect.right - dp(4f),
                        cellRect.centerY(),
                        corruptionLinePaint
                    )
                }

                if (rainbowActive && clearedMask[index]) {
                    hsv[0] = ((now / 4 + index * 29) % 360).toFloat()
                    hsv[1] = 0.75f
                    hsv[2] = 1f
                    rainbowFillPaint.color = Color.HSVToColor(45, hsv)
                    rainbowPaint.color = Color.HSVToColor(235, hsv)
                    canvas.drawRoundRect(cellRect, dp(5f), dp(5f), rainbowFillPaint)
                    canvas.drawRoundRect(cellRect, dp(5f), dp(5f), rainbowPaint)
                }
            }
        }
    }

    private fun drawClearHighlights(canvas: Canvas, now: Long) {
        if (now >= clearGlowUntil) return
        val remaining = (clearGlowUntil - now) / CLEAR_GLOW_MS.toFloat()
        hsv[0] = ((now / 5) % 360).toFloat()
        hsv[1] = 0.7f
        hsv[2] = 1f
        rainbowPaint.color = Color.HSVToColor((220 * remaining).toInt(), hsv)
        rainbowFillPaint.color = Color.HSVToColor((45 * remaining).toInt(), hsv)
        lastRows.forEach { row ->
            val y = boardRect.top + (row + 0.5f) * cellSize
            val top = boardRect.top + row * cellSize
            canvas.drawRect(
                boardRect.left,
                top,
                boardRect.right,
                top + cellSize,
                rainbowFillPaint
            )
            canvas.drawLine(
                boardRect.left + dp(2f),
                y,
                boardRect.left + (1f - remaining) * (boardRect.width() - dp(4f)) + dp(2f),
                y,
                rainbowPaint
            )
        }
        lastCols.forEach { col ->
            val x = boardRect.left + (col + 0.5f) * cellSize
            val left = boardRect.left + col * cellSize
            canvas.drawRect(
                left,
                boardRect.top,
                left + cellSize,
                boardRect.bottom,
                rainbowFillPaint
            )
            canvas.drawLine(
                x,
                boardRect.top + dp(2f),
                x,
                boardRect.top + (1f - remaining) * (boardRect.height() - dp(4f)) + dp(2f),
                rainbowPaint
            )
        }
    }

    private fun drawGrid(canvas: Canvas, now: Long) {
        val energy = when {
            dragIndex >= 0 -> 1f
            now < comboPopupUntil -> 0.65f
            else -> 0.2f
        }
        hsv[0] = ((now / 30) % 360).toFloat()
        hsv[1] = 0.45f + energy * 0.2f
        hsv[2] = 0.9f
        gridPaint.color = Color.HSVToColor((32 + 32 * energy).toInt(), hsv)
        gridPaint.strokeWidth = dp(0.65f + 0.55f * energy)
        for (index in 0..Board.SIZE) {
            val x = boardRect.left + index * cellSize
            val y = boardRect.top + index * cellSize
            canvas.drawLine(x, boardRect.top, x, boardRect.bottom, gridPaint)
            canvas.drawLine(boardRect.left, y, boardRect.right, y, gridPaint)
        }
        if (dragIndex >= 0) {
            gridNodePaint.color = Color.HSVToColor(130, hsv)
            for (row in 0..Board.SIZE) {
                for (col in 0..Board.SIZE) {
                    canvas.drawCircle(
                        boardRect.left + col * cellSize,
                        boardRect.top + row * cellSize,
                        dp(1.4f),
                        gridNodePaint
                    )
                }
            }
        }
        borderPaint.color = when {
            engine?.overloadArmed == true -> Color.rgb(255, 90, 110)
            (engine?.overloadMeter ?: 0) >= 100 -> Color.rgb(255, 190, 60)
            else -> Color.HSVToColor(180, floatArrayOf(185f, 0.75f, 1f))
        }
        borderPaint.strokeWidth = dp(2f + 3f * (engine?.overloadMeter ?: 0) / 100f)
        canvas.drawRoundRect(boardRect, dp(9f), dp(9f), borderPaint)
        canvas.drawRoundRect(boardRect, dp(9f), dp(9f), boardEdgePaint)
    }

    private fun drawPlacementGuide(canvas: Canvas, now: Long) {
        if (dragIndex < 0) return
        val current = engine ?: return
        val piece = current.tray.getOrNull(dragIndex) ?: return
        val rotated = rotate(piece, rotation)
        val target = targetFor(rotated)
        if (!target.valid) {
            targetStrokePaint.color = Color.argb(120, 255, 80, 90)
            targetFillPaint.color = Color.argb(20, 255, 80, 90)
        } else {
            // Keep the valid-placement cue in the green/cyan band. A fully cycling
            // hue occasionally lands on red, which reads as an invalid drop.
            hsv[0] = 168f + 28f * sin(now / 260f)
            hsv[1] = 0.72f
            hsv[2] = 1f
            targetStrokePaint.color = Color.HSVToColor(235, hsv)
            targetFillPaint.color = Color.HSVToColor(38, hsv)
        }
        for (cell in rotated.cells) {
            val col = target.col + cell.col
            val row = target.row + cell.row
            if (col !in 0 until Board.SIZE || row !in 0 until Board.SIZE) continue
            cellRect.set(
                boardRect.left + col * cellSize + dp(2f),
                boardRect.top + row * cellSize + dp(2f),
                boardRect.left + (col + 1) * cellSize - dp(2f),
                boardRect.top + (row + 1) * cellSize - dp(2f)
            )
            canvas.drawRoundRect(cellRect, dp(5f), dp(5f), targetFillPaint)
            canvas.drawRoundRect(cellRect, dp(5f), dp(5f), targetStrokePaint)
        }
    }

    private fun drawParticles(canvas: Canvas, now: Long) {
        for (index in 0 until particles.activeCapacity) {
            if (particles.lifeMs[index] <= 0) continue
            val age = now - particles.bornAt[index]
            if (age < 0 || age >= particles.lifeMs[index]) continue
            val seconds = age / 1000f
            val fade = 1f - age.toFloat() / particles.lifeMs[index]
            val x = particles.x[index] + particles.vx[index] * seconds
            val y = particles.y[index] + particles.vy[index] * seconds + 300f * seconds * seconds
            particlePaint.color = particles.color[index]
            particlePaint.alpha = (255 * fade).toInt().coerceIn(0, 255)
            canvas.drawCircle(x, y, dp(1.6f + 2.4f * fade), particlePaint)
        }
    }

    private fun drawRipple(canvas: Canvas, now: Long) {
        if (now >= rippleUntil) return
        val progress = 1f - (rippleUntil - now) / RIPPLE_MS.toFloat()
        val radius = dp(8f) + progress * dp(58f)
        hsv[0] = ((now / 5) % 360).toFloat()
        hsv[1] = 0.65f
        hsv[2] = 1f
        fingerRingPaint.color = Color.HSVToColor(((1f - progress) * 160).toInt(), hsv)
        canvas.drawCircle(rippleX, rippleY, radius, fingerRingPaint)
    }

    private fun drawScanlines(canvas: Canvas) {
        if (!EffectKinds.enabled(EffectKinds.SCANLINES, reduceMotion, governor.tier)) return
        if (scanlineBitmap == null) return
        canvas.drawRect(boardRect, scanlinePaint)
    }

    private fun drawVignette(canvas: Canvas) {
        if (!EffectKinds.enabled(EffectKinds.CRT_VIGNETTE, reduceMotion, governor.tier)) return
        val vignette = vignetteBitmap ?: return
        canvas.drawBitmap(vignette, null, boardRect, vignettePaint)
    }

    private fun drawComboPopup(canvas: Canvas, now: Long) {
        if (now >= comboPopupUntil || comboPopupText.isEmpty()) return
        val remaining = (comboPopupUntil - now) / 700f
        val rise = dp(40f) * (1f - remaining)
        textPaint.color = Color.rgb(0, 229, 255)
        textPaint.textSize = dp(24f)
        textPaint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        canvas.drawText(
            comboPopupText,
            boardRect.centerX() - dp(18f) + dp(2f),
            boardRect.centerY() - rise + dp(2f),
            textPaint
        )
        textPaint.color = Color.WHITE
        canvas.drawText(
            comboPopupText,
            boardRect.centerX() - dp(18f),
            boardRect.centerY() - rise,
            textPaint
        )
        textPaint.typeface = Typeface.DEFAULT
    }

    private fun drawPulse(canvas: Canvas, now: Long) {
        if (!EffectKinds.enabled(EffectKinds.GRID_PULSE, reduceMotion, governor.tier)) return
        if (now >= perfectPulseUntil) return
        val remaining = (perfectPulseUntil - now) / 500f
        val inflate = dp(10f) * (1f - remaining)
        pulsePaint.alpha = (255 * remaining).toInt().coerceIn(0, 255)
        pulsePaint.style = Paint.Style.STROKE
        pulseRect.set(
            boardRect.left - inflate,
            boardRect.top - inflate,
            boardRect.right + inflate,
            boardRect.bottom + inflate
        )
        canvas.drawRoundRect(pulseRect, dp(9f), dp(9f), pulsePaint)
    }

    private fun drawGlitch(canvas: Canvas, now: Long) {
        val remaining = (glitchUntil - now) / 150f
        val height = boardRect.height() / 5f
        for (slice in 0 until 5) {
            val dx = (frameRandom.nextFloat() - 0.5f) * dp(6f) * remaining
            val top = boardRect.top + slice * height
            val tint = if (slice % 2 == 0) {
                Color.argb((40 * remaining).toInt(), 255, 60, 90)
            } else {
                Color.argb((40 * remaining).toInt(), 60, 220, 255)
            }
            particlePaint.color = tint
            canvas.drawRect(
                boardRect.left + dx, top, boardRect.right + dx, top + height, particlePaint
            )
        }
    }

    private fun drawHud(canvas: Canvas, now: Long) {
        val current = engine ?: return
        titlePaint.textSize = dp(20f)
        canvas.drawText("GRIDBLOCKS", dp(10f), dp(29f), titlePaint)
        textPaint.textSize = dp(9f)
        textPaint.color = Color.rgb(135, 168, 186)
        canvas.drawText("${current.mode.name}  ·  SEED ${current.seed}", dp(10f), dp(41f), textPaint)
        textPaint.textSize = dp(13f)
        textPaint.color = Color.rgb(196, 224, 234)
        canvas.drawText("SCORE ${current.score}", dp(10f), dp(63f), textPaint)
        textPaint.color = Color.rgb(120, 230, 255)
        canvas.drawText("COMBO x${current.combo}", dp(10f), dp(80f), textPaint)

        val meterWidth = dp(150f)
        val meterLeft = width - meterWidth - dp(10f)
        val meterTop = dp(8f)
        canvas.drawRoundRect(
            meterLeft, meterTop, meterLeft + meterWidth, meterTop + dp(8f),
            dp(4f), dp(4f), meterTrackPaint
        )
        cellPaint.color = if (current.overloadArmed) {
            Color.rgb(255, 90, 110)
        } else {
            Color.rgb(0, 229, 255)
        }
        canvas.drawRoundRect(
            meterLeft,
            meterTop,
            meterLeft + meterWidth * current.overloadMeter / 100f,
            meterTop + dp(8f),
            dp(4f), dp(4f), cellPaint
        )
        textPaint.textSize = dp(9f)
        textPaint.color = if (now < comboPopupUntil) Color.WHITE else Color.rgb(170, 199, 211)
        val overloadText = when {
            current.overloadArmed -> "ARMED"
            current.overloadMeter >= 100 -> "OVERLOAD READY"
            else -> "OVERLOAD ${current.overloadMeter}%"
        }
        canvas.drawText(
            overloadText,
            overloadRect.left + dp(3f),
            overloadRect.centerY() + dp(3f),
            textPaint
        )
    }

    private fun drawTray(canvas: Canvas) {
        val current = engine ?: return
        for (slot in 0..2) {
            val left = trayRect.left + slot * traySlotWidth
            cellRect.set(
                left + dp(2f), trayRect.top + dp(2f),
                left + traySlotWidth - dp(2f), trayRect.bottom - dp(2f)
            )
            cellPaint.color = if (slot == dragIndex) Color.argb(160, 18, 36, 51) else Color.argb(210, 13, 25, 37)
            canvas.drawRoundRect(cellRect, dp(10f), dp(10f), cellPaint)
            socketBorderPaint.color = Color.argb(70, 80, 150, 180)
            canvas.drawRoundRect(cellRect, dp(10f), dp(10f), socketBorderPaint)
            if (slot == dragIndex) continue
            val piece = current.tray[slot] ?: continue
            val pieceCell = min(traySlotWidth, trayRect.height()) / 6.2f
            val offsetX = left + (traySlotWidth - piece.width * pieceCell) / 2f
            val offsetY = trayRect.top + (trayRect.height() - piece.height * pieceCell) / 2f
            drawMiniPiece(canvas, piece, offsetX, offsetY, pieceCell, 1f)
        }
    }

    private fun drawDrag(canvas: Canvas) {
        if (dragIndex < 0) return
        val piece = engine?.tray?.getOrNull(dragIndex) ?: return
        val rotated = rotate(piece, rotation)
        val target = targetFor(rotated)
        val originX: Float
        val originY: Float
        if (target.valid) {
            // Snap the lifted piece to the cell where it will land so the preview and
            // the piece never disagree by half a cell.
            originX = boardRect.left + target.col * cellSize
            originY = boardRect.top + target.row * cellSize
        } else {
            originX = dragX - rotated.width * cellSize / 2f
            originY = (dragY - dragLift) - rotated.height * cellSize / 2f
        }
        val pieceCenterX = originX + rotated.width * cellSize / 2f
        val pieceCenterY = originY + rotated.height * cellSize / 2f

        fingerPaint.color = Color.argb(42, 0, 229, 255)
        canvas.drawCircle(dragX, dragY, dp(18f), fingerPaint)
        fingerRingPaint.color = Color.argb(150, 100, 240, 255)
        canvas.drawCircle(dragX, dragY, dp(18f), fingerRingPaint)
        fingerPaint.color = Color.argb(120, 150, 245, 255)
        canvas.drawLine(dragX, dragY - dp(16f), pieceCenterX, pieceCenterY, fingerPaint)

        cellPaint.color = Color.argb(45, 0, 0, 0)
        canvas.drawRoundRect(
            originX + dp(5f), originY + dp(8f),
            originX + rotated.width * cellSize + dp(5f),
            originY + rotated.height * cellSize + dp(8f),
            dp(8f), dp(8f), cellPaint
        )
        drawMiniPiece(canvas, rotated, originX, originY, cellSize, 0.96f)
    }

    private fun drawMiniPiece(
        canvas: Canvas,
        piece: Piece,
        originX: Float,
        originY: Float,
        cell: Float,
        alpha: Float
    ) {
        for (offset in piece.cells) {
            cellRect.set(
                originX + offset.col * cell + dp(1.2f),
                originY + offset.row * cell + dp(1.2f),
                originX + (offset.col + 1) * cell - dp(1.2f),
                originY + (offset.row + 1) * cell - dp(1.2f)
            )
            drawBlock(canvas, cellRect, piece.colorIndex, (255 * alpha).toInt(), true)
        }
    }

    private fun drawBlock(
        canvas: Canvas,
        rect: RectF,
        colorIndex: Int,
        alpha: Int,
        shadow: Boolean
    ) {
        val atlas = blockAtlas
        if (shadow) {
            shadowRect.set(rect)
            shadowRect.offset(dp(1.5f), dp(3.5f))
            blockShadowPaint.alpha = (140 * alpha / 255).coerceIn(0, 255)
            canvas.drawRoundRect(shadowRect, dp(5f), dp(5f), blockShadowPaint)
        }
        if (atlas != null) {
            val cellWidth = atlas.width / 4
            val cellHeight = atlas.height / 2
            val index = colorIndex.coerceIn(0, 7)
            val left = (index % 4) * cellWidth
            val top = (index / 4) * cellHeight
            blockSrc.set(left, top, left + cellWidth, top + cellHeight)
            blockPaint.alpha = alpha.coerceIn(0, 255)
            canvas.drawBitmap(atlas, blockSrc, rect, blockPaint)
        } else {
            cellPaint.color = PieceCatalog.cellColors[colorIndex % PieceCatalog.cellColors.size]
            cellPaint.alpha = alpha.coerceIn(0, 255)
            canvas.drawRoundRect(rect, dp(5f), dp(5f), cellPaint)
        }
        blockRimPaint.color = Color.argb((alpha * 0.34f).toInt(), 235, 252, 255)
        canvas.drawRoundRect(rect, dp(5f), dp(5f), blockRimPaint)
        blockHighlightPaint.color = Color.argb((alpha * 0.22f).toInt(), 255, 255, 255)
        canvas.drawLine(
            rect.left + dp(4f),
            rect.top + dp(3.5f),
            rect.right - dp(4f),
            rect.top + dp(3.5f),
            blockHighlightPaint
        )
    }

    private fun colorIndexFor(stored: Int, col: Int, row: Int): Int {
        if (stored > 1) return (stored - 1) % PieceCatalog.cellColors.size
        // Saves written before block colours were stored used 1 for every cell.
        return (col * 3 + row * 5) % PieceCatalog.cellColors.size
    }

    private fun drawOverlay(canvas: Canvas) {
        val current = engine ?: return
        if (!current.gameOver) return
        canvas.drawRect(boardRect, overlayPaint)
        textPaint.textAlign = Paint.Align.CENTER
        textPaint.textSize = dp(22f)
        textPaint.color = Color.rgb(255, 107, 127)
        textPaint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        canvas.drawText("RUN ENDED", boardRect.centerX(), boardRect.centerY() - dp(18f), textPaint)
        textPaint.textSize = dp(12f)
        textPaint.color = Color.rgb(200, 230, 240)
        canvas.drawText(
            "SCORE ${current.score}",
            boardRect.centerX(),
            boardRect.centerY() + dp(12f),
            textPaint
        )
        canvas.drawText(
            "SEED ${current.seed}",
            boardRect.centerX(),
            boardRect.centerY() + dp(30f),
            textPaint
        )
        textPaint.textAlign = Paint.Align.LEFT
        textPaint.typeface = Typeface.DEFAULT
    }

    override fun performClick(): Boolean {
        super.performClick()
        return true
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        val current = engine ?: return false
        if (current.gameOver) return false
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                if (overloadRect.contains(event.x, event.y)) {
                    overload()
                    return true
                }
                lastTapAt = SystemClock.uptimeMillis()
                val slot = traySlotAt(event.x, event.y)
                if (slot >= 0 && current.tray[slot] != null) {
                    dragIndex = slot
                    dragX = event.x
                    dragY = event.y
                    dragStartX = event.x
                    dragStartY = event.y
                    dragLift = liftFor(current.tray[slot]!!)
                    dragMoved = false
                    lastDragParticleAt = 0L
                    rotation = 0
                    invalidate()
                    return true
                }
                if (boardRect.contains(event.x, event.y)) {
                    rippleX = event.x
                    rippleY = event.y
                    rippleUntil = SystemClock.uptimeMillis() + RIPPLE_MS
                    invalidate()
                    return true
                }
            }

            MotionEvent.ACTION_MOVE -> if (dragIndex >= 0) {
                dragX = event.x
                dragY = event.y
                if (abs(event.x - dragStartX) > dp(8f) || abs(event.y - dragStartY) > dp(8f)) {
                    dragMoved = true
                }
                val now = SystemClock.uptimeMillis()
                if (!reduceMotion && now - lastDragParticleAt > 55L) {
                    lastDragParticleAt = now
                    repeat(2) {
                        particles.spawn(
                            1,
                            dragX + (frameRandom.nextFloat() - 0.5f) * dp(40f),
                            dragY - dragLift + (frameRandom.nextFloat() - 0.5f) * dp(30f),
                            PieceCatalog.cellColors[
                                frameRandom.nextInt(PieceCatalog.cellColors.size)
                            ],
                            now
                        )
                    }
                }
                invalidate()
                return true
            }

            MotionEvent.ACTION_UP -> if (dragIndex >= 0) {
                performClick()
                dragX = event.x
                dragY = event.y
                if (!dragMoved && settings.allowRotation) {
                    if (current.rotateTray(dragIndex)) {
                        audio?.play("ui_tap", 1.2f)
                        haptics?.place()
                        contentDescription = describe(current)
                        notifyChanged()
                    }
                    dragIndex = -1
                    dragLift = 0f
                    invalidate()
                    return true
                }
                drop(event.x, event.y)
                return true
            }

            MotionEvent.ACTION_CANCEL -> {
                dragIndex = -1
                dragLift = 0f
                invalidate()
                return true
            }
        }
        return true
    }

    private fun drop(x: Float, y: Float) {
        val current = engine ?: return
        val piece = current.tray.getOrNull(dragIndex) ?: return
        val rotated = rotate(piece, rotation)
        val col = ((x - boardRect.left) / cellSize - rotated.width / 2f).roundToInt()
        val row = (((y - dragLift) - boardRect.top) / cellSize - rotated.height / 2f).roundToInt()
        val result = current.place(dragIndex, col, row, rotation)
        if (result == null) {
            invalidUntil = SystemClock.uptimeMillis() + 180L
            dragIndex = -1
            dragLift = 0f
            audio?.play("ui_tap", 0.8f)
            haptics?.let { if (it.enabled) it.place() }
            contentDescription = describe(current)
            invalidate()
            return
        }
        dragIndex = -1
        dragLift = 0f
        val now = SystemClock.uptimeMillis()
        if (!reduceMotion) {
            placedMarks.fill(0)
            result.placedIndices.forEach { index -> placedMarks[index] = 1 }
            placementPopUntil = now + 120L
        }
        clearedMask.fill(false)
        lastRows = IntArray(0)
        lastCols = IntArray(0)
        if (result.clearedCells > 0) {
            clearUntil = now + 180L
            clearGlowUntil = now + CLEAR_GLOW_MS
            lastRows = result.clearedRows.toIntArray()
            lastCols = result.clearedColumns.toIntArray()
            result.clearedIndices.forEach { index -> clearedMask[index] = true }
            audio?.play("clear")
            haptics?.clear()
            if (result.combo >= 2) {
                audio?.play("combo", (1f + 0.08f * (result.combo - 1)).coerceAtMost(1.6f))
                haptics?.combo()
                comboPopupText = "x${result.combo}"
                comboPopupUntil = now + 700L
            }
            if (result.perfect) {
                audio?.play("perfect")
                perfectPulseUntil = now + 500L
            }
            spawnClearEffects(current, result, now)
        } else {
            audio?.play("place")
            haptics?.place()
        }
        if (result.overloadUsed) {
            audio?.play("overload")
            haptics?.clear()
            clearUntil = maxOf(clearUntil, now + 220L)
            if (!reduceMotion) {
                detonationUntil = now + 160L
                shakeUntil = now + 220L
                glitchUntil = now + 150L
                addFirework(boardRect.centerX(), boardRect.centerY(), now, 190f, 1.35f)
                for (index in 0 until 48) {
                    particles.spawn(
                        1,
                        boardRect.centerX(),
                        boardRect.centerY(),
                        PieceCatalog.cellColors[index % PieceCatalog.cellColors.size],
                        now
                    )
                }
            }
        }
        contentDescription = describe(current)
        notifyChanged()
        invalidate()
        if (current.gameOver && !gameOverReported) {
            gameOverReported = true
            audio?.play("gameover")
            haptics?.gameOver()
            onGameOver?.invoke(current)
        }
    }

    private fun spawnClearEffects(current: GameEngine, result: MoveResult, now: Long) {
        if (reduceMotion) return
        for (index in result.clearedIndices) {
            val col = index % Board.SIZE
            val row = index / Board.SIZE
            particles.spawn(
                4,
                boardRect.left + (col + 0.5f) * cellSize,
                boardRect.top + (row + 0.5f) * cellSize,
                PieceCatalog.cellColors[colorIndexFor(current.board.cells[index], col, row)],
                now
            )
        }
        val bursts = (2 + result.combo).coerceAtMost(7)
        repeat(bursts) { burst ->
            hsv[0] = ((now / 3 + burst * 47) % 360).toFloat()
            hsv[1] = 0.78f
            hsv[2] = 1f
            addFirework(
                boardRect.left + boardRect.width() * (0.12f + 0.76f * (burst + 0.5f) / bursts),
                boardRect.top + boardRect.height() * (0.18f + 0.12f * (burst % 3)),
                now + burst * 45L,
                hsv[0],
                0.7f + result.combo * 0.10f
            )
        }
        if (result.combo >= 3) shakeUntil = now + 200L
    }

    private fun addFirework(
        x: Float,
        y: Float,
        start: Long,
        hue: Float,
        scale: Float
    ) {
        if (reduceMotion) return
        while (fireworks.size >= MAX_FIREWORKS) fireworks.removeFirst()
        fireworks.addLast(
            Firework(
                x = x,
                y = y,
                start = start,
                hue = hue,
                scale = scale,
                seed = frameRandom.nextFloat() * 6.28f
            )
        )
    }

    private fun describe(current: GameEngine): String =
        "GridBlocks board. ${current.board.filledCount()} cells filled of 64. " +
            "Score ${current.score}. Combo x${current.combo}."

    private fun notifyChanged() {
        onChanged?.invoke()
    }

    private fun traySlotAt(x: Float, y: Float): Int {
        if (!trayRect.contains(x, y)) return -1
        return ((x - trayRect.left) / traySlotWidth).toInt().coerceIn(0, 2)
    }

    private fun liftFor(piece: Piece): Float =
        maxOf(
            cellSize * 1.45f,
            piece.height * cellSize / 2f + dp(28f)
        ).coerceIn(dp(48f), dp(168f))

    private fun targetFor(piece: Piece): Target {
        val col = ((dragX - boardRect.left) / cellSize - piece.width / 2f).roundToInt()
        val row = (((dragY - dragLift) - boardRect.top) / cellSize - piece.height / 2f)
            .roundToInt()
        val valid = engine?.board?.canPlace(piece, col, row) == true
        return Target(col, row, valid)
    }

    private fun rotate(piece: Piece, times: Int): Piece {
        var result = piece
        repeat(((times % 4) + 4) % 4) { result = result.rotatedClockwise() }
        return result
    }

    private fun decodeBlockAtlas(): Bitmap? = try {
        val options = BitmapFactory.Options().apply {
            inScaled = false
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        BitmapFactory.decodeResource(resources, R.drawable.gridblocks_glass, options)
    } catch (_: Throwable) {
        null
    }

    private data class Target(val col: Int, val row: Int, val valid: Boolean)

    private data class Firework(
        val x: Float,
        val y: Float,
        val start: Long,
        val hue: Float,
        val scale: Float,
        val seed: Float
    )

    private fun dp(value: Float): Float = value * density

    private companion object {
        const val STAR_COUNT = 62
        const val MAX_FIREWORKS = 10
        const val FIREWORK_MS = 1_100L
        const val CLEAR_GLOW_MS = 620L
        const val RIPPLE_MS = 420L
    }
}
