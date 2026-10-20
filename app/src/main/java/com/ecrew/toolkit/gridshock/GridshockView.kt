package com.ecrew.toolkit.gridshock

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.BitmapShader
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.PorterDuff
import android.graphics.PorterDuffXfermode
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.Typeface
import android.os.SystemClock
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View
import com.ecrew.toolkit.R
import kotlin.math.abs
import kotlin.math.min
import kotlin.math.roundToInt

/**
 * Canvas-only GRIDSHOCK board. A single finger drags a tray piece onto the nearest valid
 * anchor. Animations are short and redraws stop when the board is static.
 */
class GridshockView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : View(context, attrs) {
    var engine: GameEngine? = null
        private set
    var settings: GridshockSettings = GridshockSettings(true, true, false, false, Mode.CLASSIC)
        private set

    fun updateSettings(newSettings: GridshockSettings) {
        settings = newSettings
        reduceMotion = newSettings.reduceMotion
        engine?.allowRotation = newSettings.allowRotation
        audio?.setMuted(!newSettings.sound)
        haptics?.enabled = newSettings.haptics
        invalidate()
    }
    var audio: GridshockAudio? = null
    var haptics: GridshockHaptics? = null
    var onChanged: (() -> Unit)? = null
    var onGameOver: ((GameEngine) -> Unit)? = null

    private val density = resources.displayMetrics.density
    private val backgroundPaint = Paint().apply { color = Color.rgb(8, 13, 18) }
    private val boardPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.rgb(16, 24, 31) }
    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.argb(55, 126, 179, 213)
        style = Paint.Style.STROKE
        strokeWidth = dp(0.7f)
    }
    private val borderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(2f)
        color = Color.rgb(0, 229, 255)
    }
    private val cellPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val markerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.argb(160, 255, 255, 255)
        style = Paint.Style.STROKE
        strokeWidth = dp(1.5f)
    }
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.rgb(176, 190, 197)
        textSize = dp(11f)
    }
    private val titlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.rgb(0, 229, 255)
        textSize = dp(18f)
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
    }
    private val flashPaint = Paint().apply { color = Color.argb(120, 255, 80, 80) }
    private val clearFlashPaint = Paint().apply { color = Color.argb(100, 255, 255, 255) }
    private val meterTrackPaint = Paint().apply { color = Color.rgb(30, 45, 55) }
    private val corruptionPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.argb(180, 0, 229, 255)
        strokeWidth = dp(2f)
    }
    private val corruptionLinePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.argb(220, 255, 70, 70)
    }
    private val overlayPaint = Paint().apply { color = Color.argb(215, 4, 8, 12) }
    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG).apply {
        xfermode = PorterDuffXfermode(PorterDuff.Mode.ADD)
        alpha = 46
    }
    private val particlePaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val pulsePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(2f)
        color = Color.rgb(0, 229, 255)
    }
    private val ghostPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(2f)
        color = Color.argb(90, 0, 229, 255)
    }
    private val detonationPaint = Paint().apply { color = Color.argb(204, 255, 255, 255) }
    private val glowBitmap64: Bitmap? = BitmapFactory.decodeResource(resources, R.drawable.glow_64)
    private val glowBitmap128: Bitmap? = BitmapFactory.decodeResource(resources, R.drawable.glow_128)
    private val glowBitmap256: Bitmap? = BitmapFactory.decodeResource(resources, R.drawable.glow_256)
    private val vignetteBitmap: Bitmap? =
        BitmapFactory.decodeResource(resources, R.drawable.vignette_256)
    private val scanlineBitmap: Bitmap? =
        BitmapFactory.decodeResource(resources, R.drawable.scanline_4h)
    private val scanlinePaint: Paint = Paint().apply {
        val tile = scanlineBitmap
        if (tile != null) shader = BitmapShader(tile, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT)
        alpha = 15
    }
    private val vignettePaint = Paint(Paint.FILTER_BITMAP_FLAG)
    private val tempRect = RectF()
    private val pulseRect = RectF()
    private val frameRandom = java.util.Random(0xC0FFEEL)
    private val particles = ParticlePool(QualityGovernor.HIGH_PARTICLE_CAP)
    private val governor = QualityGovernor()
    private var reduceMotion = false
    private var lastFrameAt = 0L
    private var comboPopupUntil = 0L
    private var comboPopupText = ""
    private var perfectPulseUntil = 0L
    private var glitchUntil = 0L
    private var shakeUntil = 0L
    private var detonationUntil = 0L
    private var placementPopUntil = 0L
    private val placedMarks = IntArray(Board.CELL_COUNT)
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
    private var dragMoved = false
    private var rotation = 0
    private var lastTapAt = 0L
    private var invalidUntil = 0L
    private var clearUntil = 0L
    private var gameOverReported = false
    private var traySlotWidth = 0f
    private var trayTop = 0f

    fun start(
        newEngine: GameEngine,
        newSettings: GridshockSettings,
        newAudio: GridshockAudio?,
        newHaptics: GridshockHaptics?,
        restored: GridshockSnapshot? = null
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
        rotation = 0
        invalidate()
        notifyChanged()
    }

    fun saveRun() {
        engine?.let { current ->
            if (!current.gameOver) {
                val store = GridshockStore(context)
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
        val trayHeight = dp(92f)
        val availableHeight = height - top - trayHeight - dp(10f)
        val size = min(width - horizontalPadding * 2, min(availableHeight, dp(600f)))
            .coerceAtLeast(dp(120f))
        val left = (width - size) / 2f
        boardRect.set(left, top, left + size, top + size)
        cellSize = size / Board.SIZE
        trayTop = boardRect.bottom + dp(8f)
        trayRect.set(horizontalPadding, trayTop, width - horizontalPadding, trayTop + trayHeight)
        traySlotWidth = trayRect.width() / 3f
        overloadRect.set(width - dp(122f), dp(44f), width - dp(10f), dp(72f))
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val now = SystemClock.uptimeMillis()
        if (lastFrameAt != 0L) governor.frame((now - lastFrameAt) * 1_000_000L)
        lastFrameAt = now
        particles.activeCapacity = governor.particleCap()
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), backgroundPaint)
        drawHud(canvas)
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
        canvas.drawRoundRect(boardRect, dp(6f), dp(6f), boardPaint)
        drawGlow(canvas, now)
        drawCells(canvas)
        drawGhostTrail(canvas)
        drawGrid(canvas)
        drawParticles(canvas, now)
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
        if (now < invalidUntil) canvas.drawRoundRect(boardRect, dp(6f), dp(6f), flashPaint)
        if (now < invalidUntil || now < clearUntil || now < detonationUntil ||
            now < glitchUntil || now < perfectPulseUntil || now < comboPopupUntil ||
            now < placementPopUntil || particles.activeCount(now) > 0
        ) {
            postInvalidateOnAnimation()
        }
        drawOverlay(canvas)
    }

    private fun drawGlow(canvas: Canvas, now: Long) {
        val glow = when {
            cellSize >= dp(48f) -> glowBitmap256
            cellSize >= dp(24f) -> glowBitmap128
            else -> glowBitmap64
        } ?: return
        val current = engine ?: return
        val halo = cellSize * 1.4f
        for (row in 0 until Board.SIZE) {
            for (col in 0 until Board.SIZE) {
                if (!current.board.isFilled(col, row)) continue
                glowPaint.color = PieceCatalog.cellColors[
                    (col * 3 + row * 5) % PieceCatalog.cellColors.size
                ]
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
                    boardRect.left + col * cellSize,
                    boardRect.top + row * cellSize,
                    boardRect.left + (col + 1) * cellSize,
                    boardRect.top + (row + 1) * cellSize,
                    dp(4f), dp(4f), particlePaint
                )
            }
        }
    }

    private fun drawGhostTrail(canvas: Canvas) {
        if (dragIndex < 0 || reduceMotion) return
        val current = engine ?: return
        val piece = current.tray.getOrNull(dragIndex) ?: return
        for (col in 0..Board.SIZE - piece.width) {
            for (row in 0..Board.SIZE - piece.height) {
                if (!current.board.canPlace(piece, col, row)) continue
                piece.cells.forEach { cell ->
                    canvas.drawRect(
                        boardRect.left + (col + cell.col) * cellSize + dp(2f),
                        boardRect.top + (row + cell.row) * cellSize + dp(2f),
                        boardRect.left + (col + cell.col + 1) * cellSize - dp(2f),
                        boardRect.top + (row + cell.row + 1) * cellSize - dp(2f),
                        ghostPaint
                    )
                }
            }
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
            canvas.drawRect(x, y, x + dp(3f), y + dp(3f), particlePaint)
        }
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
        textPaint.textSize = dp(22f)
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
    }

    private fun drawPulse(canvas: Canvas, now: Long) {
        if (!EffectKinds.enabled(EffectKinds.GRID_PULSE, reduceMotion, governor.tier)) return
        if (now >= perfectPulseUntil) return
        val remaining = (perfectPulseUntil - now) / 400f
        val inflate = dp(8f) * (1f - remaining)
        pulsePaint.alpha = (255 * remaining).toInt().coerceIn(0, 255)
        pulsePaint.style = Paint.Style.STROKE
        pulseRect.set(
            boardRect.left - inflate,
            boardRect.top - inflate,
            boardRect.right + inflate,
            boardRect.bottom + inflate
        )
        canvas.drawRoundRect(pulseRect, dp(6f), dp(6f), pulsePaint)
    }

    private fun drawGlitch(canvas: Canvas, now: Long) {
        val remaining = (glitchUntil - now) / 150f
        val height = boardRect.height() / 5f
        for (slice in 0 until 5) {
            val dx = (Math.random().toFloat() - 0.5f) * dp(6f) * remaining
            val top = boardRect.top + slice * height
            val tint = if (slice % 2 == 0) {
                Color.argb((40 * remaining).toInt(), 255, 60, 60)
            } else {
                Color.argb((40 * remaining).toInt(), 60, 220, 255)
            }
            particlePaint.color = tint
            canvas.drawRect(
                boardRect.left + dx, top, boardRect.right + dx, top + height, particlePaint
            )
        }
    }

    private fun drawHud(canvas: Canvas) {
        val current = engine ?: return
        canvas.drawText("GRIDSHOCK", dp(10f), dp(28f), titlePaint)
        textPaint.textSize = dp(10f)
        canvas.drawText("${current.mode.name}  SEED ${current.seed}", dp(10f), dp(40f), textPaint)
        textPaint.textSize = dp(13f)
        canvas.drawText("SCORE ${current.score}", dp(10f), dp(62f), textPaint)
        canvas.drawText("COMBO x${current.combo}", dp(10f), dp(79f), textPaint)
        val meterWidth = dp(150f)
        val meterLeft = width - meterWidth - dp(10f)
        val meterTop = dp(8f)
        canvas.drawRect(
            meterLeft, meterTop, meterLeft + meterWidth, meterTop + dp(8f), meterTrackPaint
        )
        cellPaint.color = if (current.overloadArmed) {
            Color.rgb(255, 90, 90)
        } else {
            Color.rgb(0, 229, 255)
        }
        canvas.drawRect(
            meterLeft,
            meterTop,
            meterLeft + meterWidth * current.overloadMeter / 100f,
            meterTop + dp(8f),
            cellPaint
        )
        textPaint.textSize = dp(9f)
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
        borderPaint.color = when {
            current.overloadArmed -> Color.rgb(255, 90, 90)
            current.overloadMeter >= 100 -> Color.rgb(255, 190, 60)
            else -> Color.rgb(0, 229, 255)
        }
        borderPaint.strokeWidth = dp(2f + 3f * current.overloadMeter / 100f)
        canvas.drawRoundRect(boardRect, dp(6f), dp(6f), borderPaint)
    }

    private fun drawCells(canvas: Canvas) {
        val current = engine ?: return
        for (row in 0 until Board.SIZE) {
            for (col in 0 until Board.SIZE) {
                if (!current.board.isFilled(col, row)) continue
                cellRect.set(
                    boardRect.left + col * cellSize + dp(2f),
                    boardRect.top + row * cellSize + dp(2f),
                    boardRect.left + (col + 1) * cellSize - dp(2f),
                    boardRect.top + (row + 1) * cellSize - dp(2f)
                )
                cellPaint.color = PieceCatalog.cellColors[
                    (col * 3 + row * 5) % PieceCatalog.cellColors.size
                ]
                canvas.drawRoundRect(cellRect, dp(4f), dp(4f), cellPaint)
                val depth = current.board.corruptionDepth[Board.index(col, row)]
                if (depth > 0) {
                    val stripeStep = cellRect.height() / 4f
                    for (stripeIndex in 1..3) {
                        val y = cellRect.top + stripeStep * stripeIndex
                        canvas.drawLine(
                            cellRect.left + dp(2f), y, cellRect.right - dp(2f), y,
                            corruptionPaint
                        )
                    }
                    canvas.drawLine(
                        cellRect.left + dp(3f),
                        cellRect.centerY(),
                        cellRect.right - dp(3f),
                        cellRect.centerY(),
                        corruptionLinePaint
                    )
                }
                drawMarker(canvas, "DOT", cellRect)
            }
        }
    }

    private fun drawGrid(canvas: Canvas) {
        for (index in 0..Board.SIZE) {
            val x = boardRect.left + index * cellSize
            val y = boardRect.top + index * cellSize
            canvas.drawLine(x, boardRect.top, x, boardRect.bottom, gridPaint)
            canvas.drawLine(boardRect.left, y, boardRect.right, y, gridPaint)
        }
    }

    private fun drawTray(canvas: Canvas) {
        val current = engine ?: return
        for (slot in 0..2) {
            val left = trayRect.left + slot * traySlotWidth
            canvas.drawRoundRect(
                left + dp(2f), trayRect.top + dp(2f),
                left + traySlotWidth - dp(2f), trayRect.bottom - dp(2f),
                dp(5f), dp(5f), gridPaint
            )
            val piece = current.tray[slot] ?: continue
            val pieceCell = min(traySlotWidth, trayRect.height()) / 6f
            val offsetX = left + (traySlotWidth - piece.width * pieceCell) / 2f
            val offsetY = trayRect.top + (trayRect.height() - piece.height * pieceCell) / 2f
            drawMiniPiece(canvas, piece, offsetX, offsetY, pieceCell, 1f)
        }
    }

    private fun drawDrag(canvas: Canvas) {
        if (dragIndex < 0) return
        val piece = engine?.tray?.getOrNull(dragIndex) ?: return
        var rotated = piece
        repeat(rotation) { rotated = rotated.rotatedClockwise() }
        val originX = dragX - rotated.width * cellSize / 2f
        val originY = dragY - rotated.height * cellSize / 2f
        drawMiniPiece(canvas, rotated, originX, originY, cellSize, 0.85f)
    }

    private fun drawMiniPiece(
        canvas: Canvas,
        piece: Piece,
        originX: Float,
        originY: Float,
        cell: Float,
        alpha: Float
    ) {
        val color = PieceCatalog.cellColors[piece.colorIndex]
        cellPaint.color = Color.argb((255 * alpha).toInt(), Color.red(color), Color.green(color), Color.blue(color))
        for (offset in piece.cells) {
            cellRect.set(
                originX + offset.col * cell + dp(1f),
                originY + offset.row * cell + dp(1f),
                originX + (offset.col + 1) * cell - dp(1f),
                originY + (offset.row + 1) * cell - dp(1f)
            )
            canvas.drawRoundRect(cellRect, dp(3f), dp(3f), cellPaint)
            drawMarker(canvas, piece.id, cellRect)
        }
    }

    private fun drawMarker(canvas: Canvas, pieceId: String, rect: RectF) {
        val cx = rect.centerX()
        val cy = rect.centerY()
        when {
            pieceId == "DOT" -> canvas.drawCircle(cx, cy, dp(2f), markerPaint)
            pieceId.startsWith("LINE") -> {
                if (rect.width() > rect.height()) {
                    canvas.drawLine(rect.left + dp(2f), cy, rect.right - dp(2f), cy, markerPaint)
                } else {
                    canvas.drawLine(cx, rect.top + dp(2f), cx, rect.bottom - dp(2f), markerPaint)
                }
            }
            pieceId.startsWith("SQUARE") -> canvas.drawRect(
                rect.left + dp(3f), rect.top + dp(3f),
                rect.right - dp(3f), rect.bottom - dp(3f), markerPaint
            )
            pieceId.startsWith("T4") -> {
                canvas.drawLine(rect.left + dp(2f), cy, rect.right - dp(2f), cy, markerPaint)
                canvas.drawLine(cx, rect.top + dp(2f), cx, rect.bottom - dp(2f), markerPaint)
            }
            pieceId.startsWith("S4") || pieceId.startsWith("Z4") -> {
                canvas.drawLine(rect.left + dp(2f), rect.bottom - dp(2f), rect.right - dp(2f), rect.top + dp(2f), markerPaint)
            }
            pieceId.startsWith("L") || pieceId.startsWith("J") -> {
                canvas.drawLine(rect.left + dp(2f), rect.top + dp(2f), rect.left + dp(2f), rect.bottom - dp(2f), markerPaint)
                canvas.drawLine(rect.left + dp(2f), rect.bottom - dp(2f), rect.right - dp(2f), rect.bottom - dp(2f), markerPaint)
            }
            else -> canvas.drawCircle(cx, cy, dp(1.5f), markerPaint)
        }
    }

    private fun drawOverlay(canvas: Canvas) {
        val current = engine ?: return
        if (!current.gameOver) return
        canvas.drawRect(boardRect, overlayPaint)
        textPaint.textSize = dp(20f)
        textPaint.color = Color.rgb(255, 107, 107)
        canvas.drawText("GAME OVER", boardRect.centerX() - dp(55f), boardRect.centerY() - dp(10f), textPaint)
        textPaint.textSize = dp(11f)
        textPaint.color = Color.rgb(176, 190, 197)
        canvas.drawText("SCORE ${current.score}", boardRect.centerX() - dp(35f), boardRect.centerY() + dp(14f), textPaint)
        canvas.drawText("SEED ${current.seed}", boardRect.centerX() - dp(35f), boardRect.centerY() + dp(30f), textPaint)
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
                    dragMoved = false
                    rotation = 0
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
                invalidate()
                return true
            }
            MotionEvent.ACTION_UP -> if (dragIndex >= 0) {
                performClick()
                if (!dragMoved && settings.allowRotation) {
                    if (current.rotateTray(dragIndex)) {
                        audio?.play("ui_tap", 1.2f)
                        haptics?.place()
                        contentDescription = describe(current)
                        notifyChanged()
                    }
                    dragIndex = -1
                    invalidate()
                    return true
                }
                drop(event.x, event.y)
                return true
            }
            MotionEvent.ACTION_CANCEL -> {
                dragIndex = -1
                invalidate()
                return true
            }
        }
        return true
    }

    private fun drop(x: Float, y: Float) {
        val current = engine ?: return
        val piece = current.tray.getOrNull(dragIndex) ?: return
        var rotated = piece
        repeat(rotation) { rotated = rotated.rotatedClockwise() }
        val col = ((x - boardRect.left) / cellSize - rotated.width / 2f).roundToInt()
        val row = ((y - boardRect.top) / cellSize - rotated.height / 2f).roundToInt()
        val result = current.place(dragIndex, col, row, rotation)
        if (result == null) {
            invalidUntil = SystemClock.uptimeMillis() + 180L
            dragIndex = -1
            audio?.play("ui_tap", 0.8f)
            haptics?.let { if (it.enabled) it.place() }
            contentDescription = describe(current)
            invalidate()
            return
        }
        dragIndex = -1
        val now = SystemClock.uptimeMillis()
        if (!reduceMotion) {
            placedMarks.fill(0)
            result.placedIndices.forEach { index -> placedMarks[index] = 1 }
            placementPopUntil = now + 120L
        }
        if (result.clearedCells > 0) {
            clearUntil = now + 120L
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
                perfectPulseUntil = now + 400L
            }
            if (!reduceMotion) {
                for (index in result.clearedIndices) {
                    val burstCol = index % Board.SIZE
                    val burstRow = index / Board.SIZE
                    particles.spawn(
                        4,
                        boardRect.left + (burstCol + 0.5f) * cellSize,
                        boardRect.top + (burstRow + 0.5f) * cellSize,
                        PieceCatalog.cellColors[
                            (burstCol + burstRow) % PieceCatalog.cellColors.size
                        ],
                        now
                    )
                }
                glitchUntil = now + 150L
                if (result.combo >= 3) shakeUntil = now + 200L
            }
        } else {
            audio?.play("place")
            haptics?.place()
        }
        if (result.overloadUsed) {
            audio?.play("overload")
            haptics?.clear()
            clearUntil = maxOf(clearUntil, now + 160L)
            if (!reduceMotion) {
                detonationUntil = now + 120L
                shakeUntil = now + 200L
                glitchUntil = now + 150L
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

    private fun describe(current: GameEngine): String =
        "GRIDSHOCK board. ${current.board.filledCount()} cells filled of 64. " +
            "Score ${current.score}. Combo x${current.combo}."

    private fun notifyChanged() {
        onChanged?.invoke()
    }

    private fun traySlotAt(x: Float, y: Float): Int {
        if (!trayRect.contains(x, y)) return -1
        return ((x - trayRect.left) / traySlotWidth).toInt().coerceIn(0, 2)
    }

    private fun dp(value: Float): Float = value * density
}
