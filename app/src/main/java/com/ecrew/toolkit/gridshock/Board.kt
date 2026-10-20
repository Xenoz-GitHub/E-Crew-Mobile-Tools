package com.ecrew.toolkit.gridshock

import java.util.Random

data class ClearOutcome(
    val rows: List<Int>,
    val columns: List<Int>,
    val clearedCells: Int,
    val perfect: Boolean,
    val indices: List<Int>
) {
    val hadClear: Boolean get() = clearedCells > 0
}

class Board {
    val cells = IntArray(SIZE * SIZE)
    val corruptionDepth = IntArray(SIZE * SIZE)

    fun isOpen(col: Int, row: Int): Boolean =
        col in 0 until SIZE && row in 0 until SIZE && cells[index(col, row)] == 0

    fun isFilled(col: Int, row: Int): Boolean =
        col in 0 until SIZE && row in 0 until SIZE && cells[index(col, row)] != 0

    fun filledCount(): Int = cells.count { it != 0 }

    fun corruptionCount(): Int = corruptionDepth.count { it > 0 }

    fun canPlace(piece: Piece, col: Int, row: Int): Boolean =
        piece.cells.all { isOpen(col + it.col, row + it.row) }

    fun place(piece: Piece, col: Int, row: Int): Boolean {
        if (!canPlace(piece, col, row)) return false
        piece.cells.forEach { cell -> cells[index(col + cell.col, row + cell.row)] = 1 }
        return true
    }

    fun clearLines(): ClearOutcome {
        val rows = (0 until SIZE).filter { row ->
            (0 until SIZE).all { col -> cells[index(col, row)] != 0 }
        }
        val columns = (0 until SIZE).filter { col ->
            (0 until SIZE).all { row -> cells[index(col, row)] != 0 }
        }
        val targets = LinkedHashSet<Int>()
        rows.forEach { row ->
            (0 until SIZE).forEach { col -> targets.add(index(col, row)) }
        }
        columns.forEach { col ->
            (0 until SIZE).forEach { row -> targets.add(index(col, row)) }
        }
        targets.forEach { index ->
            when (corruptionDepth[index]) {
                2 -> corruptionDepth[index] = 1
                1 -> {
                    corruptionDepth[index] = 0
                    cells[index] = 0
                }
                else -> cells[index] = 0
            }
        }
        val perfect = targets.isNotEmpty() && cells.all { it == 0 }
        return ClearOutcome(rows, columns, targets.size, perfect, targets.toList())
    }

    /**
     * Clears a 3x3 block centered on the placed piece's bounding-box centre. Corruption is
     * handled by the same first-clear-second-remove rule as a line clear.
     */
    fun clear3x3(centerCol: Int, centerRow: Int): Int {
        var cleared = 0
        for (row in centerRow - 1..centerRow + 1) {
            for (col in centerCol - 1..centerCol + 1) {
                if (col !in 0 until SIZE || row !in 0 until SIZE) continue
                val index = index(col, row)
                if (cells[index] == 0) continue
                cleared++
                when (corruptionDepth[index]) {
                    2 -> corruptionDepth[index] = 1
                    1 -> {
                        corruptionDepth[index] = 0
                        cells[index] = 0
                    }
                    else -> cells[index] = 0
                }
            }
        }
        return cleared
    }

    fun canPlaceAny(tray: List<Piece?>): Boolean =
        tray.filterNotNull().any { piece ->
            (0..SIZE - piece.width).any { col ->
                (0..SIZE - piece.height).any { row -> canPlace(piece, col, row) }
            }
        }

    fun seedCorruption(count: Int, random: Random): Int {
        val empty = (0 until SIZE * SIZE).filter {
            cells[it] == 0 && corruptionDepth[it] == 0
        }.shuffled(random)
        var added = 0
        for (index in empty) {
            if (added >= count) break
            corruptionDepth[index] = 2
            added++
        }
        return added
    }

    fun spreadCorruption(random: Random): Boolean {
        val candidates = (0 until SIZE * SIZE).filter {
            cells[it] == 0 && corruptionDepth[it] == 0
        }
        if (candidates.isEmpty()) return false
        corruptionDepth[candidates[random.nextInt(candidates.size)]] = 2
        return true
    }

    fun copyCells(): IntArray = cells.copyOf()

    fun copyCorruption(): IntArray = corruptionDepth.copyOf()

    fun restore(cellsValue: IntArray, corruption: IntArray) {
        require(cellsValue.size == cells.size && corruption.size == corruption.size)
        cellsValue.copyInto(cells)
        corruption.copyInto(corruptionDepth)
    }

    companion object {
        const val SIZE = 8
        const val CELL_COUNT = SIZE * SIZE

        fun index(col: Int, row: Int): Int = row * SIZE + col
    }
}
