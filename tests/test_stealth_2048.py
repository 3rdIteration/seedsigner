"""Tests for ``seedsigner.stealth.game_2048.Game2048`` (turn-based)."""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def _btn():
    b = MagicMock()
    b.KEY_LEFT = "KEY_LEFT"
    b.KEY_RIGHT = "KEY_RIGHT"
    b.KEY_UP = "KEY_UP"
    b.KEY_DOWN = "KEY_DOWN"
    return b


def _game():
    from seedsigner.stealth.game_2048 import Game2048
    g = Game2048()
    g._cell = 10
    g._origin_x = 0
    g._origin_y = 0
    return g


class TestGame2048(unittest.TestCase):
    def test_compress_merge(self):
        g = _game()
        self.assertEqual(g._compress_merge([2, 2, 0, 0]), ([4, 0, 0, 0], 4))
        self.assertEqual(g._compress_merge([2, 2, 2, 2]), ([4, 4, 0, 0], 8))
        self.assertEqual(g._compress_merge([2, 0, 2, 4]), ([4, 4, 0, 0], 4))
        self.assertEqual(g._compress_merge([0, 0, 0, 0]), ([0, 0, 0, 0], 0))

    def test_slide_left_merges_and_reports_gain(self):
        g = _game()
        g._board = [
            [2, 2, 0, 0],
            [0, 0, 0, 0],
            [4, 0, 4, 0],
            [0, 0, 0, 0],
        ]
        changed, gain = g._slide("L")
        self.assertTrue(changed)
        self.assertEqual(g._board[0], [4, 0, 0, 0])
        self.assertEqual(g._board[2], [8, 0, 0, 0])
        self.assertEqual(gain, 4 + 8)

    def test_slide_down_on_column(self):
        g = _game()
        g._board = [
            [2, 0, 0, 0],
            [2, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
        ]
        changed, gain = g._slide("D")
        self.assertTrue(changed)
        self.assertEqual([g._board[r][0] for r in range(4)], [0, 0, 0, 4])
        self.assertEqual(gain, 4)

    def test_no_op_move_does_not_spawn(self):
        g = _game()
        # A board already fully slid left: LEFT changes nothing.
        g._board = [
            [2, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
        ]
        btn = _btn()
        self.assertFalse(g.handle_key("KEY_LEFT", btn))
        zeros = sum(row.count(0) for row in g._board)
        self.assertEqual(zeros, 15)  # unchanged, no new tile

    def test_changing_move_spawns_one_tile(self):
        g = _game()
        g._board = [
            [0, 2, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
        ]
        btn = _btn()
        self.assertTrue(g.handle_key("KEY_LEFT", btn))
        nonzero = sum(1 for row in g._board for v in row if v)
        self.assertEqual(nonzero, 2)  # moved tile + one spawn

    def test_has_moves(self):
        g = _game()
        # Full checkerboard: no empties, no equal neighbours -> no moves.
        g._board = [
            [2, 4, 2, 4],
            [4, 2, 4, 2],
            [2, 4, 2, 4],
            [4, 2, 4, 2],
        ]
        self.assertFalse(g._has_moves())
        g._board[0][0] = 4  # now a horizontal pair exists
        self.assertTrue(g._has_moves())

    def test_handle_key_ends_game_when_no_moves_remain(self):
        g = _game()
        g._board = [
            [0, 2, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
        ]
        btn = _btn()
        with patch.object(g, "_spawn"), \
             patch.object(g, "_has_moves", return_value=False):
            self.assertTrue(g.handle_key("KEY_LEFT", btn))
        self.assertFalse(g.alive)


if __name__ == "__main__":
    unittest.main()
