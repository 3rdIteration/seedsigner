"""Tests for ``seedsigner.stealth.console.StealthConsole``.

These drive ``_run_menu`` / ``_play`` directly with a pre-filled input
queue (no input thread, no real hardware) so they stay deterministic.
"""

from __future__ import annotations

import os
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def _install_hw_mocks():
    for mod in ["RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
                "smartcard", "smartcard.System", "pygame", "periphery"]:
        sys.modules.setdefault(mod, MagicMock())


_install_hw_mocks()


class _Btn:
    KEY_UP = "KEY_UP"
    KEY_DOWN = "KEY_DOWN"
    KEY_LEFT = "KEY_LEFT"
    KEY_RIGHT = "KEY_RIGHT"
    KEY_PRESS = "KEY_PRESS"
    KEY1 = "KEY1"
    KEY2 = "KEY2"
    KEY3 = "KEY3"
    ALL_KEYS = [KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY_PRESS,
                KEY1, KEY2, KEY3]


class _FakeRenderer:
    def __init__(self):
        self.canvas_width = 240
        self.canvas_height = 240
        self.lock = threading.RLock()

    def show_image(self, img, *args, **kwargs):
        pass


def _no_panic_buttons():
    """A HardwareButtons stub whose empty ``_gpio_pins`` disables panic."""
    b = MagicMock()
    b._gpio_pins = {}
    return b


def _patch_buttons(buttons):
    return patch(
        "seedsigner.hardware.buttons.HardwareButtons.get_instance",
        return_value=buttons,
    )


class TestMenu(unittest.TestCase):
    def test_menu_down_then_select_returns_second_game(self):
        from seedsigner.stealth.console import StealthConsole
        from seedsigner.stealth.game_2048 import Game2048
        console = StealthConsole(unlock_sequence_csv="KEY1,KEY2,KEY3")
        console._input_q.put("KEY_DOWN")
        console._input_q.put("KEY_PRESS")
        with _patch_buttons(_no_panic_buttons()):
            chosen = console._run_menu(_FakeRenderer(), _Btn)
        self.assertIs(chosen, Game2048)

    def test_unlock_combo_from_menu_exits(self):
        from seedsigner.stealth.console import StealthConsole, StealthGameExit
        console = StealthConsole(unlock_sequence_csv="KEY_DOWN,KEY_DOWN,KEY_DOWN")
        for _ in range(3):
            console._input_q.put("KEY_DOWN")
        with _patch_buttons(_no_panic_buttons()):
            with self.assertRaises(StealthGameExit):
                console._run_menu(_FakeRenderer(), _Btn)


class TestPlay(unittest.TestCase):
    def _game(self):
        from seedsigner.stealth.game_2048 import Game2048
        g = Game2048()
        g.reset(240, 240)
        return g

    def test_unlock_combo_from_game_exits(self):
        from seedsigner.stealth.console import StealthConsole, StealthGameExit
        console = StealthConsole(unlock_sequence_csv="KEY_LEFT,KEY_LEFT,KEY_LEFT")
        game = self._game()
        for _ in range(3):
            console._input_q.put("KEY_LEFT")
        with _patch_buttons(_no_panic_buttons()):
            with self.assertRaises(StealthGameExit):
                console._play(_FakeRenderer(), game, _Btn)

    def test_key1_returns_to_menu_without_exit(self):
        from seedsigner.stealth.console import StealthConsole
        console = StealthConsole(unlock_sequence_csv="KEY_UP,KEY_UP,KEY_UP")
        game = self._game()
        console._input_q.put("KEY1")
        with _patch_buttons(_no_panic_buttons()):
            result = console._play(_FakeRenderer(), game, _Btn)
        self.assertIsNone(result)
        self.assertTrue(game.alive)


class _RecordingGame:
    """Minimal game stub: records every key it is asked to handle.

    Turn-based (``tick_ms is None``) so ``_play`` never auto-steps; lets us
    assert exactly which keys reached the game after de-flooding.
    """

    name = "Rec"
    menu_accent = (1, 2, 3)

    def __init__(self):
        self.alive = True
        self.score = 0
        self.keys = []

    def reset(self, w, h):
        self.alive = True

    @property
    def tick_ms(self):
        return None

    def step(self):
        pass

    def handle_key(self, key, btn):
        self.keys.append(key)
        return True

    def render(self, renderer):
        pass

    def render_game_over(self, renderer):
        pass


class TestInputThrottle(unittest.TestCase):
    def test_held_flood_collapses_to_one_action(self):
        """A held button (30 identical repeats in one batch) acts once."""
        from seedsigner.stealth.console import StealthConsole
        console = StealthConsole(unlock_sequence_csv="KEY1,KEY2,KEY3")
        game = _RecordingGame()
        for _ in range(30):
            console._input_q.put("KEY_DOWN")
        console._input_q.put("KEY1")  # return to menu, ends _play
        with _patch_buttons(_no_panic_buttons()):
            console._play(_FakeRenderer(), game, _Btn)
        self.assertEqual(game.keys, ["KEY_DOWN"])

    def test_distinct_keys_in_batch_all_apply(self):
        """De-flooding gates only repeats — distinct keys all get through."""
        from seedsigner.stealth.console import StealthConsole
        console = StealthConsole(unlock_sequence_csv="KEY1,KEY2,KEY3")
        game = _RecordingGame()
        for key in ("KEY_LEFT", "KEY_DOWN", "KEY1"):
            console._input_q.put(key)
        with _patch_buttons(_no_panic_buttons()):
            console._play(_FakeRenderer(), game, _Btn)
        self.assertEqual(game.keys, ["KEY_LEFT", "KEY_DOWN"])

    def test_unlock_buffer_sees_every_raw_key_despite_throttle(self):
        """Repeated-key unlock combos still fire — _consume runs on each key."""
        from seedsigner.stealth.console import StealthConsole, StealthGameExit
        console = StealthConsole(unlock_sequence_csv="KEY_DOWN,KEY_DOWN,KEY_DOWN")
        game = _RecordingGame()
        for _ in range(3):
            console._input_q.put("KEY_DOWN")
        with _patch_buttons(_no_panic_buttons()):
            with self.assertRaises(StealthGameExit):
                console._play(_FakeRenderer(), game, _Btn)

    def test_flush_queue_drops_pending(self):
        from seedsigner.stealth.console import StealthConsole
        console = StealthConsole(unlock_sequence_csv="KEY1,KEY2,KEY3")
        for _ in range(5):
            console._input_q.put("KEY_DOWN")
        console._flush_queue()
        self.assertTrue(console._input_q.empty())


class TestMenuRender(unittest.TestCase):
    def test_render_menu_each_index_does_not_raise(self):
        from seedsigner.stealth.console import StealthConsole
        console = StealthConsole(unlock_sequence_csv="KEY1,KEY2,KEY3")
        renderer = _FakeRenderer()
        for i in range(len(console._games)):
            console._render_menu(renderer, i)  # styled path must not raise

    def test_render_menu_fallback_does_not_raise(self):
        from seedsigner.stealth.console import StealthConsole
        console = StealthConsole(unlock_sequence_csv="KEY1,KEY2,KEY3")
        canvas = console._draw_menu_fallback(_FakeRenderer(), 0)
        self.assertIsNotNone(canvas)


class TestConstruction(unittest.TestCase):
    def test_invalid_sequence_raises(self):
        from seedsigner.stealth.console import StealthConsole
        from seedsigner.stealth.unlock import InvalidSequenceError
        with self.assertRaises(InvalidSequenceError):
            StealthConsole(unlock_sequence_csv="KEY_UP,KEY_BANANA,KEY_UP")


class TestPanic(unittest.TestCase):
    def test_holding_three_keys_disables_stealth_and_exits(self):
        from seedsigner.stealth.console import StealthConsole, StealthGameExit
        from seedsigner.hardware.buttons import HardwareButtonsConstants as HBC
        from seedsigner.models.settings import Settings
        from seedsigner.models.settings_definition import SettingsConstants

        class _Pin:
            def read(self):
                return 0  # active-low: held

        gpio = {HBC.KEY1: _Pin(), HBC.KEY2: _Pin(), HBC.KEY3: _Pin()}
        buttons = MagicMock()
        buttons._gpio_pins = gpio

        console = StealthConsole(unlock_sequence_csv="KEY_UP,KEY_UP,KEY_UP")
        settings = MagicMock()
        with _patch_buttons(buttons), \
             patch.object(Settings, "get_instance", return_value=settings):
            console._track_panic(1_000, _Btn)          # arm the latch
            with self.assertRaises(StealthGameExit):
                console._track_panic(1_000 + 11_000, _Btn)  # 11 s held -> panic

        settings.set_value.assert_called_with(
            SettingsConstants.SETTING__STEALTH_BOOT,
            SettingsConstants.OPTION__DISABLED,
        )


if __name__ == "__main__":
    unittest.main()
