package com.ecrew.toolkit.gridblocks

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BoardTest {
    private val dot = Piece("dot", listOf(Cell(0, 0)), 1)

    @Test
    fun placeStoresPieceColourOnEachCell() {
        val board = Board()
        assertTrue(board.place(dot, 3, 4))
        assertEquals(dot.colorIndex + 1, board.cells[Board.index(3, 4)])
    }

    @Test
    fun lineClearUsesStoredCellValues() {
        val board = Board()
        for (col in 0 until Board.SIZE) {
            board.cells[Board.index(col, 0)] = 4
        }
        board.cells[Board.index(0, 1)] = 2

        val outcome = board.clearLines()

        assertTrue(outcome.hadClear)
        assertEquals(listOf(0), outcome.rows)
        assertFalse(outcome.columns.isNotEmpty())
        assertEquals(0, board.cells[Board.index(0, 0)])
        assertEquals(2, board.cells[Board.index(0, 1)])
    }

    @Test
    fun restoreRejectsWrongCorruptionLength() {
        val board = Board()
        try {
            board.restore(IntArray(Board.CELL_COUNT), IntArray(2))
            throw AssertionError("Expected restore to reject a short corruption array")
        } catch (_: IllegalArgumentException) {
            // Expected.
        }
    }
}
