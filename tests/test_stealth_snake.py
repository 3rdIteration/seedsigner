"""Tests for ``seedsigner.stealth.snake.SnakeGame``.

The shared input thread / unlock buffer / panic exit now live in
``StealthConsole`` (see ``tests/test_stealth_console.py``); these tests
exercise the Snake state machine directly, no rendering involved.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def _install_hw_mocks():
    for mod in [
        "RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
        "smartcard", "smartcard.System", "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
        "periphery",
    ]:
        sys.modules.setdefault(mod, MagicMock())


_install_hw_mocks()


class TestSnakeStateMachine(unittest.TestCase):
    """Direct tests of the internal state machine, no rendering involved."""

    def _make_game(self):
        from seedsigner.stealth.snake import SnakeGame
        return SnakeGame()

    def test_advance_eats_food_and_grows(self):
        from seedsigner.stealth.snake import _GameState
        game = self._make_game()
        # Place the snake so the next step lands on the food cell.
        state = _GameState(width=10, height=10,
                           snake=[(2, 5), (1, 5), (0, 5)],
                           food=(3, 5),
                           direction=(1, 0))
        game._cell = 10
        game._origin_x = 0
        game._origin_y = 0
        game._grid_cols = state.width
        game._grid_rows = state.height
        starting_len = len(state.snake)
        game._advance(state)
        self.assertTrue(state.alive)
        self.assertEqual(state.score, 1)
        self.assertEqual(len(state.snake), starting_len + 1)
        self.assertEqual(state.head, (3, 5))
        self.assertNotEqual(state.food, (3, 5))  # food respawned

    def test_advance_wraps_at_wall(self):
        from seedsigner.stealth.snake import _GameState
        game = self._make_game()
        # Head at the right edge moving right -> wraps to the left edge,
        # and the snake stays alive (no wall death any more).
        state = _GameState(width=10, height=10,
                           snake=[(9, 5), (8, 5), (7, 5)],
                           food=(0, 0),
                           direction=(1, 0))
        game._grid_cols = state.width
        game._grid_rows = state.height
        game._advance(state)
        self.assertTrue(state.alive)
        self.assertEqual(state.head, (0, 5))

    def test_advance_wraps_at_top(self):
        from seedsigner.stealth.snake import _GameState
        game = self._make_game()
        state = _GameState(width=10, height=10,
                           snake=[(5, 0), (5, 1), (5, 2)],
                           food=(0, 0),
                           direction=(0, -1))
        game._grid_cols = state.width
        game._grid_rows = state.height
        game._advance(state)
        self.assertTrue(state.alive)
        self.assertEqual(state.head, (5, 9))

    def test_advance_dies_on_self(self):
        from seedsigner.stealth.snake import _GameState
        game = self._make_game()
        # Snake 4 long, doubled back so head will hit body.
        state = _GameState(
            width=10, height=10,
            snake=[(2, 5), (2, 6), (3, 6), (3, 5)],
            food=(0, 0),
            direction=(0, 1),
        )
        game._grid_cols = state.width
        game._grid_rows = state.height
        game._advance(state)
        self.assertFalse(state.alive)

    def test_apply_input_blocks_180_reverse(self):
        from seedsigner.stealth.snake import _GameState
        game = self._make_game()
        state = _GameState(width=10, height=10,
                           snake=[(5, 5), (4, 5), (3, 5)],
                           food=(9, 9),
                           direction=(1, 0))
        btn = MagicMock()
        btn.KEY_UP = "KEY_UP"
        btn.KEY_DOWN = "KEY_DOWN"
        btn.KEY_LEFT = "KEY_LEFT"
        btn.KEY_RIGHT = "KEY_RIGHT"
        self.assertFalse(game._apply_input(state, "KEY_LEFT", btn))
        self.assertEqual(state.direction, (1, 0))  # blocked
        self.assertTrue(game._apply_input(state, "KEY_UP", btn))
        self.assertEqual(state.direction, (0, -1))


if __name__ == "__main__":
    unittest.main()
