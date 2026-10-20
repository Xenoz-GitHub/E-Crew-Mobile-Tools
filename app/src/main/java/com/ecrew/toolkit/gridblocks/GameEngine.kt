package com.ecrew.toolkit.gridblocks

import java.util.ArrayDeque
import java.util.Random

/** Weighted, deterministic and deliberately blind to the board. */
class PieceBag(seed: Long) {
    private val random = Random(seed)
    private val recent = ArrayDeque<String>()

    fun next(): Piece {
        var candidate: Piece? = null
        for (attempt in 0 until RETRIES + 1) {
            val roll = random.nextInt(PieceCatalog.totalWeight)
            var accumulated = 0
            for (piece in PieceCatalog.pieces) {
                accumulated += piece.weight
                if (roll < accumulated) {
                    candidate = piece
                    break
                }
            }
            val chosen = candidate ?: PieceCatalog.pieces.last()
            candidate = chosen
            if (chosen.id !in recent || attempt == RETRIES) break
        }
        val accepted = candidate ?: PieceCatalog.pieces.last()
        recent.addLast(accepted.id)
        while (recent.size > RECENT_CAPACITY) recent.removeFirst()
        return accepted
    }

    companion object {
        const val RECENT_CAPACITY = 8
        const val RETRIES = 3
    }
}

object Scoring {
    fun lineScore(
        mode: Mode,
        placedCells: Int,
        clearedCells: Int,
        combo: Int,
        perfect: Boolean
    ): Int {
        val base = if (mode == Mode.BREACH) {
            clearedCells * 10 * combo * 3 / 2
        } else {
            clearedCells * 10 * combo
        }
        return placedCells + base + if (perfect) 1000 else 0
    }

    fun blockScore(mode: Mode, clearedCells: Int, combo: Int): Int =
        if (mode == Mode.BREACH) clearedCells * 10 * combo * 3 / 2
        else clearedCells * 10 * combo

    fun nextCombo(current: Int, hadClear: Boolean): Int =
        if (hadClear) (current + 1).coerceAtMost(MAX_COMBO) else current

    const val MAX_COMBO = 5
}

enum class Mode { CLASSIC, BREACH, ZEN }

data class MoveResult(
    val scoreDelta: Int,
    val placedCells: Int,
    val clearedCells: Int,
    val combo: Int,
    val perfect: Boolean,
    val overloadUsed: Boolean,
    val gameOver: Boolean,
    val clearedIndices: List<Int>,
    val clearedRows: List<Int>,
    val clearedColumns: List<Int>,
    val placedIndices: List<Int>
)

class GameEngine(
    val seed: Long,
    val mode: Mode,
    var allowRotation: Boolean = false
) {
    val board = Board()
    private val bag = PieceBag(seed)
    val tray = mutableListOf<Piece?>(null, null, null)
    var score = 0
        private set
    var combo = 1
        private set
    var bestCombo = 1
        private set
    var moves = 0
        private set
    var lines = 0
        private set
    var perfects = 0
        private set
    var overloadMeter = 0
        private set
    var overloadArmed = false
        private set
    var gameOver = false
        private set
    private var nonClearingMoves = 0
    private val placementRandom = Random(seed xor 0x5EED5EEDL)

    init {
        if (mode == Mode.BREACH) board.seedCorruption(2, placementRandom)
        refill()
        checkGameOver()
    }

    fun refill() {
        tray[0] = bag.next()
        tray[1] = bag.next()
        tray[2] = bag.next()
        if (mode == Mode.ZEN && !board.canPlaceAny(tray)) {
            tray[0] = bag.next()
            tray[1] = bag.next()
            tray[2] = bag.next()
        }
    }

    fun canPlace(trayIndex: Int, col: Int, row: Int, rotation: Int = 0): Boolean {
        if (gameOver || trayIndex !in tray.indices) return false
        val piece = tray[trayIndex] ?: return false
        val rotated = rotate(piece, rotation)
        return board.canPlace(rotated, col, row)
    }

    fun place(
        trayIndex: Int,
        col: Int,
        row: Int,
        rotation: Int = 0
    ): MoveResult? {
        if (gameOver || trayIndex !in tray.indices) return null
        val original = tray[trayIndex] ?: return null
        if (rotation != 0 && !allowRotation) return null
        val piece = rotate(original, rotation)
        if (!board.place(piece, col, row)) return null
        val placedIndices = piece.cells.map { cell ->
            Board.index(col + cell.col, row + cell.row)
        }
        tray[trayIndex] = null
        moves++
        val placedCells = piece.cells.size
        val outcome = board.clearLines()
        val scoreCombo = combo
        var delta = Scoring.lineScore(
            mode,
            placedCells,
            outcome.clearedCells,
            scoreCombo,
            outcome.perfect
        )
        var overloadUsed = false
        var blockCleared = 0
        if (overloadArmed) {
            val centerCol = col + piece.width / 2
            val centerRow = row + piece.height / 2
            blockCleared = board.clear3x3(centerCol, centerRow)
            delta += Scoring.blockScore(mode, blockCleared, scoreCombo)
            overloadMeter = 0
            overloadArmed = false
            overloadUsed = true
        } else {
            overloadMeter = (overloadMeter + outcome.clearedCells).coerceAtMost(100)
        }
        if (outcome.hadClear) {
            combo = Scoring.nextCombo(combo, true)
            nonClearingMoves = 0
            if (outcome.perfect) perfects++
        } else {
            nonClearingMoves++
            if (nonClearingMoves >= 2) {
                combo = 1
                nonClearingMoves = 0
            }
        }
        bestCombo = maxOf(bestCombo, combo)
        lines += outcome.rows.size + outcome.columns.size
        score += delta
        if (mode == Mode.BREACH && moves % 10 == 0) {
            val count = board.corruptionCount()
            if (count > 6 && count < 12) board.spreadCorruption(placementRandom)
        }
        if (tray.all { it == null }) refill()
        checkGameOver()
        return MoveResult(
            scoreDelta = delta,
            placedCells = placedCells,
            clearedCells = outcome.clearedCells + blockCleared,
            combo = combo,
            perfect = outcome.perfect,
            overloadUsed = overloadUsed,
            gameOver = gameOver,
            clearedIndices = outcome.indices,
            clearedRows = outcome.rows,
            clearedColumns = outcome.columns,
            placedIndices = placedIndices
        )
    }

    /** Rotates a tray piece in place; used before dragging when rotation is enabled. */
    fun rotateTray(trayIndex: Int): Boolean {
        if (!allowRotation || gameOver || trayIndex !in tray.indices) return false
        val piece = tray[trayIndex] ?: return false
        tray[trayIndex] = piece.rotatedClockwise()
        return true
    }

    fun armOverload(): Boolean {
        if (mode == Mode.ZEN || overloadArmed || overloadMeter < 100) return false
        overloadArmed = true
        return true
    }

    fun disarmOverload() {
        overloadArmed = false
    }

    fun stateSnapshot(): GridBlocksSnapshot = GridBlocksSnapshot(
        mode = mode,
        seed = seed,
        board = board.copyCells(),
        corruption = board.copyCorruption(),
        tray = tray.map { it?.id },
        score = score,
        combo = combo,
        bestCombo = bestCombo,
        moves = moves,
        lines = lines,
        perfects = perfects,
        overload = overloadMeter,
        overloadArmed = overloadArmed,
        nonClearingMoves = nonClearingMoves,
        allowRotation = allowRotation
    )

    fun restore(snapshot: GridBlocksSnapshot) {
        require(snapshot.mode == mode && snapshot.seed == seed)
        board.restore(snapshot.board, snapshot.corruption)
        snapshot.tray.forEachIndexed { index, id ->
            tray[index] = id?.let { PieceCatalog.byId[it] }
        }
        score = snapshot.score
        combo = snapshot.combo
        bestCombo = snapshot.bestCombo
        moves = snapshot.moves
        lines = snapshot.lines
        perfects = snapshot.perfects
        overloadMeter = snapshot.overload
        overloadArmed = snapshot.overloadArmed
        nonClearingMoves = snapshot.nonClearingMoves
        allowRotation = snapshot.allowRotation
        gameOver = mode != Mode.ZEN && !board.canPlaceAny(tray)
    }

    private fun rotate(piece: Piece, times: Int): Piece {
        var result = piece
        repeat(((times % 4) + 4) % 4) { result = result.rotatedClockwise() }
        return result
    }

    private fun checkGameOver() {
        if (mode == Mode.ZEN) return
        if (tray.any { it != null } && !board.canPlaceAny(tray)) {
            gameOver = true
        }
    }
}

data class GridBlocksSnapshot(
    val mode: Mode,
    val seed: Long,
    val board: IntArray,
    val corruption: IntArray,
    val tray: List<String?>,
    val score: Int,
    val combo: Int,
    val bestCombo: Int,
    val moves: Int,
    val lines: Int,
    val perfects: Int,
    val overload: Int,
    val overloadArmed: Boolean,
    val nonClearingMoves: Int,
    val allowRotation: Boolean
)
