"""Tests for ``seedsigner.stealth.tetris.TetrisGame``."""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def _install_hw_mocks():
    for mod in ["RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
                "smartcard", "smartcard.System", "pygame", "periphery"]:
        sys.modules.setdefault(mod, MagicMock())


_install_hw_mocks()


def _game():
    from seedsigner.stealth.tetris import TetrisGame
    g = TetrisGame()
    g.reset(100, 180)  # 10x18 grid, cell ~10
    return g


class TestTetris(unittest.TestCase):
    def test_rotate_keeps_four_cells_and_normalises(self):
        from seedsigner.stealth.tetris import TetrisGame
        rotated = TetrisGame._rotate([(0, 0), (0, 1), (0, 2), (1, 1)])  # T
        self.assertEqual(len(rotated), 4)
        self.assertEqual(min(r for r, _ in rotated), 0)
        self.assertEqual(min(c for _, c in rotated), 0)

    def test_collides_with_walls_floor_and_blocks(self):
        from seedsigner.stealth.tetris import COLS, ROWS
        g = _game()
        self.assertTrue(g._collides([(0, 0)], 0, -1))      # left wall
        self.assertTrue(g._collides([(0, 0)], 0, COLS))    # right wall
        self.assertTrue(g._collides([(0, 0)], ROWS, 0))    # floor
        g._grid[5][3] = (1, 1, 1)
        self.assertTrue(g._collides([(0, 0)], 5, 3))       # occupied cell
        self.assertFalse(g._collides([(0, 0)], 4, 3))      # free cell

    def test_clear_lines(self):
        from seedsigner.stealth.tetris import COLS, ROWS
        g = _game()
        g._grid = [[0] * COLS for _ in range(ROWS)]
        g._grid[ROWS - 1] = [(1, 1, 1)] * COLS  # full bottom row
        cleared = g._clear_lines()
        self.assertEqual(cleared, 1)
        self.assertTrue(all(v == 0 for row in g._grid for v in row))
        self.assertEqual(len(g._grid), ROWS)

    def test_lock_completes_row_and_scores(self):
        from seedsigner.stealth.tetris import COLS, ROWS
        g = _game()
        g._grid = [[0] * COLS for _ in range(ROWS)]
        g._grid[ROWS - 1] = [(9, 9, 9)] * COLS
        g._grid[ROWS - 1][3] = 0           # single gap
        g._shape = [(0, 0)]
        g._color = (5, 5, 5)
        g._pr = ROWS - 1
        g._pc = 3
        g._lock()
        self.assertEqual(g._lines, 1)
        self.assertEqual(g.score, 100)
        self.assertTrue(g.alive)            # a new piece was spawned

    def test_spawn_into_full_top_is_game_over(self):
        from seedsigner.stealth.tetris import COLS
        g = _game()
        for r in range(2):
            g._grid[r] = [(9, 9, 9)] * COLS
        g._spawn()
        self.assertFalse(g.alive)

    def test_handle_key_moves_horizontally(self):
        g = _game()
        btn = MagicMock()
        btn.KEY_LEFT = "KEY_LEFT"
        btn.KEY_RIGHT = "KEY_RIGHT"
        btn.KEY_UP = "KEY_UP"
        btn.KEY_DOWN = "KEY_DOWN"
        btn.KEY_PRESS = "KEY_PRESS"
        g._shape = [(0, 0)]
        g._pr = 0
        g._pc = 5
        self.assertTrue(g.handle_key("KEY_LEFT", btn))
        self.assertEqual(g._pc, 4)
        self.assertTrue(g.handle_key("KEY_RIGHT", btn))
        self.assertEqual(g._pc, 5)


if __name__ == "__main__":
    unittest.main()
