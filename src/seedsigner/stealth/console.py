"""Stealth-boot games console.

When stealth boot is enabled, ``Controller.start()`` runs
``StealthConsole().run()`` before the firmware splash. The console shows a
game-select menu and dispatches to a mini-game; on game-over it returns to
the menu. To a casual observer the device just boots into a little handheld
games console.

The console owns the three things shared by every game:

* the **input thread**, which forwards button presses onto a queue;
* the **unlock buffer** (``stealth.unlock``), fed every key pressed anywhere
  — in the menu *or* in any game — so the configured secret combo always
  exits the console straight into the firmware (suffix match, no progress
  shown); and
* the **panic exit**: holding ``KEY1 + KEY2 + KEY3`` for 10 s disables
  stealth boot and continues into the firmware.

A single **KEY1** press inside a game returns to the console menu (the
handheld "menu" button); it is still fed to the unlock buffer first.

This module MUST NOT import any seed/Keycard/secret-handling code. It only
reads/writes the two stealth settings via ``Settings``.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import List, Optional, Type

from PIL import ImageDraw

from .base import BaseStealthGame, new_canvas
from .dino import DinoGame
from .game_2048 import Game2048
from .snake import SnakeGame
from .tetris import TetrisGame
from .unlock import UnlockBuffer, parse_sequence


logger = logging.getLogger(__name__)


_PANIC_HOLD_MS = 10_000   # how long all three side keys must be held
_PANIC_POLL_S = 0.2       # menu/idle poll so panic is checked without input
_RESTART_DELAY_S = 1.0    # pause on game-over before returning to the menu


class StealthGameExit(Exception):
    """Raised to leave the console — unlock combo matched or panic fired."""


class StealthConsole:
    """Boot-time games console. Call ``run()`` once; it returns on unlock."""

    # Order shown in the menu.
    GAMES: List[Type[BaseStealthGame]] = [
        SnakeGame, Game2048, TetrisGame, DinoGame,
    ]

    def __init__(self, unlock_sequence_csv: Optional[str] = None):
        if unlock_sequence_csv is None:
            from seedsigner.models.settings import Settings
            from seedsigner.models.settings_definition import SettingsConstants
            unlock_sequence_csv = Settings.get_instance().get_value(
                SettingsConstants.SETTING__STEALTH_UNLOCK_SEQUENCE
            )
        self._unlock = UnlockBuffer(parse_sequence(unlock_sequence_csv))

        self._games: List[Type[BaseStealthGame]] = list(self.GAMES)
        self._input_q: "queue.Queue[str]" = queue.Queue()
        self._stop_input = threading.Event()
        self._input_thread: Optional[threading.Thread] = None
        self._panic_active_since: Optional[int] = None

    # ---- public entry point -------------------------------------------------

    def run(self) -> None:
        from seedsigner.gui.renderer import Renderer
        from seedsigner.hardware.buttons import (
            HardwareButtons, HardwareButtonsConstants,
        )

        renderer = Renderer.get_instance()
        buttons = HardwareButtons.get_instance()
        btn = HardwareButtonsConstants

        self._start_input_thread(buttons, btn)
        try:
            while True:
                game_cls = self._run_menu(renderer, btn)
                game = game_cls()
                game.reset(renderer.canvas_width, renderer.canvas_height)
                game.render(renderer)
                self._play(renderer, game, btn)
        except StealthGameExit:
            return
        finally:
            self._stop_input.set()
            if self._input_thread is not None:
                self._input_thread.join(timeout=0.5)

    # ---- menu ---------------------------------------------------------------

    def _run_menu(self, renderer, btn) -> Type[BaseStealthGame]:
        """Game-select menu. Returns the chosen game class.

        Raises ``StealthGameExit`` if the unlock combo or panic fires here.
        """
        idx = 0
        self._render_menu(renderer, idx)
        while True:
            try:
                key = self._input_q.get(timeout=_PANIC_POLL_S)
            except queue.Empty:
                key = None
            self._track_panic(self._monotonic_ms(), btn)
            if key is None:
                continue
            self._consume(key)  # may raise StealthGameExit
            if key == btn.KEY_UP:
                idx = (idx - 1) % len(self._games)
                self._render_menu(renderer, idx)
            elif key == btn.KEY_DOWN:
                idx = (idx + 1) % len(self._games)
                self._render_menu(renderer, idx)
            elif key in (btn.KEY_PRESS, btn.KEY_RIGHT):
                return self._games[idx]

    def _render_menu(self, renderer, selected: int) -> None:
        with renderer.lock:
            canvas = new_canvas(renderer)
            draw = ImageDraw.Draw(canvas)
            w = renderer.canvas_width
            draw.text((6, 6), "GAMES", fill=(160, 200, 220))
            top = 34
            avail = renderer.canvas_height - top - 6
            row_h = max(16, avail // max(1, len(self._games)))
            for i, game_cls in enumerate(self._games):
                y = top + i * row_h
                name = getattr(game_cls, "name", game_cls.__name__)
                if i == selected:
                    draw.rectangle([4, y, w - 4, y + row_h - 4],
                                   fill=(30, 50, 70))
                    draw.text((12, y + 2), "> " + name, fill=(240, 240, 240))
                else:
                    draw.text((12, y + 2), "  " + name, fill=(150, 170, 190))
            renderer.show_image(canvas)

    # ---- gameplay loop ------------------------------------------------------

    def _play(self, renderer, game: BaseStealthGame, btn) -> None:
        """Drive one game until it dies or KEY1 returns to the menu.

        Raises ``StealthGameExit`` if the unlock combo or panic fires.
        """
        tick_ms = game.tick_ms
        last_tick = self._monotonic_ms()
        while game.alive:
            now = self._monotonic_ms()
            if tick_ms is None:
                timeout_s = _PANIC_POLL_S
            else:
                timeout_s = max(0.0, (tick_ms - (now - last_tick)) / 1000.0)
            try:
                key = self._input_q.get(timeout=timeout_s)
            except queue.Empty:
                key = None

            self._track_panic(self._monotonic_ms(), btn)

            if key is not None:
                self._consume(key)  # may raise StealthGameExit
                if key == btn.KEY1:
                    return  # back to the console menu
                if game.handle_key(key, btn):
                    game.render(renderer)
                    if not game.alive:
                        break

            if tick_ms is not None and self._monotonic_ms() - last_tick >= tick_ms:
                game.step()
                last_tick = self._monotonic_ms()
                if game.alive:
                    game.render(renderer)
                tick_ms = game.tick_ms

        game.render_game_over(renderer)
        time.sleep(_RESTART_DELAY_S)

    # ---- unlock + panic -----------------------------------------------------

    def _consume(self, key: str) -> None:
        """Feed ``key`` to the unlock buffer; exit the console on a match."""
        if self._unlock.feed(key):
            raise StealthGameExit

    def _track_panic(self, now_ms: int, btn) -> None:
        # Best-effort: read the live GPIO state for the three side keys. If
        # the platform doesn't expose individual pin reads we never trigger.
        try:
            from seedsigner.hardware.buttons import (
                HardwareButtons, HardwareButtonsConstants,
            )
            buttons = HardwareButtons.get_instance()
            gpio_pins = getattr(buttons, "_gpio_pins", None)
            if not gpio_pins:
                self._panic_active_since = None
                return
            held = (
                self._is_low(gpio_pins, HardwareButtonsConstants.KEY1)
                and self._is_low(gpio_pins, HardwareButtonsConstants.KEY2)
                and self._is_low(gpio_pins, HardwareButtonsConstants.KEY3)
            )
        except Exception:
            self._panic_active_since = None
            return

        if not held:
            self._panic_active_since = None
            return
        if self._panic_active_since is None:
            self._panic_active_since = now_ms
            return
        if now_ms - self._panic_active_since >= _PANIC_HOLD_MS:
            self._do_panic_exit()

    @staticmethod
    def _is_low(gpio_pins, key) -> bool:
        pin = gpio_pins.get(key)
        if pin is None:
            return False
        try:
            return not pin.read()  # active-low
        except Exception:
            return False

    def _do_panic_exit(self) -> None:
        from seedsigner.models.settings import Settings
        from seedsigner.models.settings_definition import SettingsConstants

        try:
            settings = Settings.get_instance()
            settings.set_value(
                SettingsConstants.SETTING__STEALTH_BOOT,
                SettingsConstants.OPTION__DISABLED,
            )
            try:
                settings.save()
            except Exception:
                logger.exception("panic-exit: could not persist STEALTH_BOOT=Disabled")
        finally:
            raise StealthGameExit

    # ---- input thread -------------------------------------------------------

    def _start_input_thread(self, buttons, btn) -> None:
        keys = list(btn.ALL_KEYS)

        def _pump():
            while not self._stop_input.is_set():
                try:
                    key = buttons.wait_for(keys)
                except Exception:
                    logger.exception("stealth input pump error")
                    time.sleep(0.05)
                    continue
                if key is None:
                    continue
                self._input_q.put(key)

        t = threading.Thread(target=_pump, name="stealth-input", daemon=True)
        t.start()
        self._input_thread = t

    @staticmethod
    def _monotonic_ms() -> int:
        return int(time.monotonic() * 1000)
