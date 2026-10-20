package com.ecrew.toolkit.gridshock

import kotlin.math.abs

data class Cell(val col: Int, val row: Int)

data class Piece(
    val id: String,
    val cells: List<Cell>,
    val weight: Int
) {
    val width: Int = cells.maxOfOrNull { it.col }?.plus(1) ?: 0
    val height: Int = cells.maxOfOrNull { it.row }?.plus(1) ?: 0
    val colorIndex: Int = abs(id.hashCode()) % 6

    init {
        require(cells.isNotEmpty()) { "piece $id has no cells" }
        require(cells.minOf { it.col } == 0) { "piece $id is not normalized horizontally" }
        require(cells.minOf { it.row } == 0) { "piece $id is not normalized vertically" }
        require(cells.distinct().size == cells.size) { "piece $id has duplicate cells" }
    }

    fun rotatedClockwise(): Piece {
        val rotated = cells.map { Cell(height - 1 - it.row, it.col) }
            .distinct()
            .sortedWith(compareBy<Cell> { it.row }.thenBy { it.col })
        val minCol = rotated.minOf { it.col }
        val minRow = rotated.minOf { it.row }
        return copy(
            id = id,
            cells = rotated.map { Cell(it.col - minCol, it.row - minRow) }
        )
    }

    fun canFit(board: Board, col: Int, row: Int): Boolean =
        cells.all { board.isOpen(col + it.col, row + it.row) }
}

object PieceCatalog {
    private fun piece(id: String, weight: Int, vararg cells: Pair<Int, Int>) =
        Piece(id, cells.map { Cell(it.first, it.second) }, weight)

    val pieces: List<Piece> = listOf(
        piece("DOT", 2, 0 to 0),
        piece("LINE2_H", 3, 0 to 0, 1 to 0),
        piece("LINE2_V", 3, 0 to 0, 0 to 1),
        piece("LINE3_H", 3, 0 to 0, 1 to 0, 2 to 0),
        piece("LINE3_V", 3, 0 to 0, 0 to 1, 0 to 2),
        piece("LINE4_H", 2, 0 to 0, 1 to 0, 2 to 0, 3 to 0),
        piece("LINE4_V", 2, 0 to 0, 0 to 1, 0 to 2, 0 to 3),
        piece("LINE5_H", 1, 0 to 0, 1 to 0, 2 to 0, 3 to 0, 4 to 0),
        piece("LINE5_V", 1, 0 to 0, 0 to 1, 0 to 2, 0 to 3, 0 to 4),
        piece("SQUARE2", 4, 0 to 0, 1 to 0, 0 to 1, 1 to 1),
        piece(
            "SQUARE3", 1,
            0 to 0, 1 to 0, 2 to 0, 0 to 1, 1 to 1, 2 to 1, 0 to 2, 1 to 2, 2 to 2
        ),
        piece("RECT_3x2", 1, 0 to 0, 1 to 0, 2 to 0, 0 to 1, 1 to 1, 2 to 1),
        piece("RECT_2x3", 1, 0 to 0, 1 to 0, 0 to 1, 1 to 1, 0 to 2, 1 to 2),
        piece("L3_R0", 2, 0 to 0, 0 to 1, 1 to 1),
        piece("L3_R1", 2, 0 to 0, 1 to 0, 0 to 1),
        piece("L3_R2", 2, 0 to 0, 1 to 0, 1 to 1),
        piece("L3_R3", 2, 1 to 0, 0 to 1, 1 to 1),
        piece("L4_R0", 1, 0 to 0, 0 to 1, 0 to 2, 1 to 2),
        piece("L4_R1", 1, 0 to 0, 1 to 0, 2 to 0, 2 to 1),
        piece("L4_R2", 1, 0 to 0, 1 to 0, 1 to 1, 1 to 2),
        piece("L4_R3", 1, 0 to 0, 0 to 1, 1 to 0, 2 to 0),
        piece("J4_R0", 1, 1 to 0, 1 to 1, 1 to 2, 0 to 2),
        piece("J4_R1", 1, 0 to 0, 0 to 1, 1 to 1, 2 to 1),
        piece("J4_R2", 1, 0 to 0, 0 to 1, 0 to 2, 1 to 0),
        piece("J4_R3", 1, 0 to 1, 1 to 1, 2 to 1, 2 to 0),
        piece("T4_R0", 1, 0 to 0, 1 to 0, 2 to 0, 1 to 1),
        piece("T4_R1", 1, 0 to 0, 0 to 1, 0 to 2, 1 to 1),
        piece("T4_R2", 1, 0 to 1, 1 to 1, 2 to 1, 1 to 0),
        piece("T4_R3", 1, 1 to 0, 1 to 1, 1 to 2, 0 to 1),
        piece("S4_R0", 1, 1 to 0, 2 to 0, 0 to 1, 1 to 1),
        piece("S4_R1", 1, 0 to 0, 0 to 1, 1 to 1, 1 to 2),
        piece("Z4_R0", 1, 0 to 0, 1 to 0, 1 to 1, 2 to 1),
        piece("Z4_R1", 1, 1 to 0, 0 to 1, 1 to 1, 0 to 2)
    )

    val byId: Map<String, Piece> = pieces.associateBy { it.id }
    val totalWeight: Int = pieces.sumOf { it.weight }
    val cellColors: List<Int> = listOf(
        0xFF00E5FF.toInt(),
        0xFF58D68D.toInt(),
        0xFFF4D03F.toInt(),
        0xFF9B59B6.toInt(),
        0xFFFF6FAE.toInt(),
        0xFFFF6B6B.toInt()
    )

    init {
        require(pieces.size == 33) { "GRIDSHOCK needs exactly 33 catalog pieces" }
        require(pieces.map { it.id }.distinct().size == pieces.size) { "duplicate piece id" }
        require(totalWeight == 51) { "piece weights must total 51" }
    }
}
