"""Tests for ``seedsigner.stealth.snake.SnakeGame``.

We exercise the game with mocked Renderer and HardwareButtons singletons
so the test suite stays headless. The button singleton is fed a script
of presses; the renderer's ``show_image`` is a no-op MagicMock that
never blocks.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch


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


class _ButtonScript:
    """Stub HardwareButtons that hands back a scripted list of keys.

    ``wait_for`` blocks until either there's a key in the queue or the
    test stops the game; behaves like the real one for the input thread.
    """

    def __init__(self, keys):
        self.q: "queue.Queue[str]" = queue.Queue()
        for k in keys:
            self.q.put(k)
        self._gpio_pins = {}  # empty -> panic-exit will never trigger

    def wait_for(self, _keys):
        try:
            return self.q.get(timeout=2.0)
        except queue.Empty:
            # Block forever (until the input thread is signalled to stop).
            time.sleep(60)
            return None


class _FakeRenderer:
    def __init__(self):
        self.canvas_width = 240
        self.canvas_height = 240
        self.lock = threading.RLock()
        self.frames = []

    def show_image(self, img, *args, **kwargs):
        # Don't keep the PIL Image; just count.
        self.frames.append(True)


class TestSnakeGame(unittest.TestCase):
    def test_run_returns_when_unlock_sequence_matched(self):
        from seedsigner.stealth.snake import SnakeGame

        renderer = _FakeRenderer()
        # 5 KEY_UP -> matches default unlock combo immediately.
        buttons = _ButtonScript(["KEY_UP"] * 5)

        with patch(
            "seedsigner.gui.renderer.Renderer.get_instance",
            return_value=renderer,
        ), patch(
            "seedsigner.hardware.buttons.HardwareButtons.get_instance",
            return_value=buttons,
        ):
            game = SnakeGame(unlock_sequence_csv="KEY_UP,KEY_UP,KEY_UP,KEY_UP,KEY_UP")
            # Run with a watchdog: if the game doesn't return quickly the
            # test fails clearly rather than hanging the suite.
            done = threading.Event()
            err = []

            def _runner():
                try:
                    game.run()
                finally:
                    done.set()

            t = threading.Thread(target=_runner, daemon=True)
            t.start()
            self.assertTrue(done.wait(timeout=5.0),
                            "SnakeGame.run() did not return on unlock combo")
            self.assertIsNone(err[0]) if err else None

    def test_run_handles_custom_sequence(self):
        from seedsigner.stealth.snake import SnakeGame

        renderer = _FakeRenderer()
        buttons = _ButtonScript([
            "KEY_LEFT", "KEY_RIGHT", "KEY_PRESS",
        ])

        with patch(
            "seedsigner.gui.renderer.Renderer.get_instance",
            return_value=renderer,
        ), patch(
            "seedsigner.hardware.buttons.HardwareButtons.get_instance",
            return_value=buttons,
        ):
            game = SnakeGame(
                unlock_sequence_csv="KEY_LEFT,KEY_RIGHT,KEY_PRESS",
            )
            done = threading.Event()

            def _runner():
                try:
                    game.run()
                finally:
                    done.set()

            t = threading.Thread(target=_runner, daemon=True)
            t.start()
            self.assertTrue(done.wait(timeout=5.0),
                            "SnakeGame.run() did not return on custom combo")

    def test_invalid_sequence_raises_at_construction(self):
        from seedsigner.stealth.snake import SnakeGame
        from seedsigner.stealth.unlock import InvalidSequenceError

        with self.assertRaises(InvalidSequenceError):
            SnakeGame(unlock_sequence_csv="KEY_UP,KEY_BANANA,KEY_UP")


class TestSnakeStateMachine(unittest.TestCase):
    """Direct tests of the internal state machine, no rendering involved."""

    def _make_game(self):
        from seedsigner.stealth.snake import SnakeGame
        return SnakeGame(unlock_sequence_csv="KEY_UP,KEY_UP,KEY_UP,KEY_UP,KEY_UP")

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

    def test_advance_dies_on_wall(self):
        from seedsigner.stealth.snake import _GameState
        game = self._make_game()
        state = _GameState(width=10, height=10,
                           snake=[(9, 5), (8, 5), (7, 5)],
                           food=(0, 0),
                           direction=(1, 0))
        game._grid_cols = state.width
        game._grid_rows = state.height
        game._advance(state)
        self.assertFalse(state.alive)

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
        game._apply_input(state, "KEY_LEFT", btn)
        self.assertEqual(state.direction, (1, 0))  # blocked
        game._apply_input(state, "KEY_UP", btn)
        self.assertEqual(state.direction, (0, -1))


if __name__ == "__main__":
    unittest.main()
