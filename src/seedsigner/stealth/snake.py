"""Snake game used as the boot screen when stealth mode is enabled.

The game runs on the same ``Renderer`` and ``HardwareButtons`` singletons
the rest of the firmware uses. Input is forwarded over a ``queue.Queue``
populated by a background thread so the game can advance on a tick even
when the user is not pressing anything.

The game returns from ``run()`` when one of two things happens:

1. The player presses the configured unlock sequence (a suffix-match —
   see ``stealth.unlock``). This is the documented exit; the calling
   code in ``Controller.start()`` continues into the firmware.
2. The player holds ``KEY1 + KEY2 + KEY3`` together for 10 s — the
   *panic exit*. This disables the ``STEALTH_BOOT`` setting and signals
   the controller to reboot. Documented in ``AGENTS.md`` only, so it
   does not surface as part of the stealth UX.

The game does not touch any seed/Keycard module. It does not write to
disk except via the panic-exit code path, which only flips the
``STEALTH_BOOT`` setting back to ``Disabled``.
"""

from __future__ import annotations

import logging
import queue
import random
import threading
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from PIL import Image, ImageDraw

from .unlock import UnlockBuffer, parse_sequence


logger = logging.getLogger(__name__)


# Game tuning constants.
_BASE_TICK_MS = 220       # initial snake speed (one cell per tick)
_MIN_TICK_MS = 90         # speed cap as score grows
_TICK_DECAY_PER_FOOD = 8  # ms shaved off the tick after each food eaten
_PANIC_HOLD_MS = 10_000   # how long all three side keys must be held
_RESTART_DELAY_S = 1.0    # pause on game-over before reset


@dataclass
class _GameState:
    width: int
    height: int
    snake: List[Tuple[int, int]]
    food: Tuple[int, int]
    direction: Tuple[int, int]
    score: int = 0
    alive: bool = True

    @property
    def head(self) -> Tuple[int, int]:
        return self.snake[0]


class StealthGameExit(Exception):
    """Raised internally to break out of nested loops cleanly."""


class _PanicTriggered(StealthGameExit):
    """Player held the three side keys for ``_PANIC_HOLD_MS``."""


class SnakeGame:
    """Boot-time Snake game. Call ``run()`` once; it returns on unlock."""

    def __init__(self,
                 unlock_sequence_csv: Optional[str] = None,
                 *,
                 grid_cols: int = 16,
                 grid_rows: int = 12):
        self._grid_cols = grid_cols
        self._grid_rows = grid_rows
        if unlock_sequence_csv is None:
            from seedsigner.models.settings import Settings
            from seedsigner.models.settings_definition import SettingsConstants
            unlock_sequence_csv = Settings.get_instance().get_value(
                SettingsConstants.SETTING__STEALTH_UNLOCK_SEQUENCE
            )
        self._unlock = UnlockBuffer(parse_sequence(unlock_sequence_csv))

        self._random = random.Random(time.monotonic_ns())
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

        self._start_input_thread(buttons, HardwareButtonsConstants)
        try:
            while True:
                state = self._fresh_state(renderer.canvas_width, renderer.canvas_height)
                try:
                    self._play_until_dead(renderer, state, HardwareButtonsConstants)
                except StealthGameExit:
                    return
                if not state.alive:
                    self._render_game_over(renderer, state)
                    time.sleep(_RESTART_DELAY_S)
        finally:
            self._stop_input.set()
            if self._input_thread is not None:
                self._input_thread.join(timeout=0.5)

    # ---- internals ----------------------------------------------------------

    def _fresh_state(self, canvas_w: int, canvas_h: int) -> _GameState:
        # Centre the playfield in the canvas; cell size = floor(min/grid).
        cell_w = canvas_w // self._grid_cols
        cell_h = canvas_h // self._grid_rows
        cell = max(4, min(cell_w, cell_h))
        self._cell = cell
        self._origin_x = (canvas_w - cell * self._grid_cols) // 2
        self._origin_y = (canvas_h - cell * self._grid_rows) // 2

        mid_c = self._grid_cols // 2
        mid_r = self._grid_rows // 2
        snake = [(mid_c, mid_r), (mid_c - 1, mid_r), (mid_c - 2, mid_r)]
        return _GameState(
            width=self._grid_cols, height=self._grid_rows,
            snake=snake, food=self._spawn_food(snake),
            direction=(1, 0),
        )

    def _play_until_dead(self, renderer, state, btn) -> None:
        tick_ms = _BASE_TICK_MS
        last_tick = self._monotonic_ms()
        self._render_frame(renderer, state)

        while state.alive:
            now = self._monotonic_ms()
            timeout_s = max(0.0, (tick_ms - (now - last_tick)) / 1000.0)
            try:
                key = self._input_q.get(timeout=timeout_s)
            except queue.Empty:
                key = None

            if key is not None:
                self._track_panic(now, btn)
                if self._unlock.feed(key):
                    raise StealthGameExit
                self._apply_input(state, key, btn)
            else:
                # No key -> reset panic latch.
                self._panic_active_since = None

            if self._monotonic_ms() - last_tick >= tick_ms:
                self._advance(state)
                last_tick = self._monotonic_ms()
                if state.alive:
                    self._render_frame(renderer, state)
                tick_ms = max(_MIN_TICK_MS,
                              _BASE_TICK_MS - state.score * _TICK_DECAY_PER_FOOD)

    def _advance(self, state: _GameState) -> None:
        dx, dy = state.direction
        head_c, head_r = state.head
        new_head = (head_c + dx, head_r + dy)

        # Wall collision.
        if not (0 <= new_head[0] < state.width and 0 <= new_head[1] < state.height):
            state.alive = False
            return

        ate = (new_head == state.food)
        if not ate and new_head in state.snake[:-1]:
            # Self-collision (the tail cell is leaving on this tick, so OK).
            state.alive = False
            return

        state.snake.insert(0, new_head)
        if ate:
            state.score += 1
            state.food = self._spawn_food(state.snake)
        else:
            state.snake.pop()

    def _apply_input(self, state: _GameState, key: str, btn) -> None:
        # Direction keys: prevent 180° reverse-into-self.
        mapping = {
            btn.KEY_UP:    (0, -1),
            btn.KEY_DOWN:  (0, 1),
            btn.KEY_LEFT:  (-1, 0),
            btn.KEY_RIGHT: (1, 0),
        }
        new_dir = mapping.get(key)
        if new_dir is None:
            return
        cdx, cdy = state.direction
        ndx, ndy = new_dir
        if (cdx + ndx, cdy + ndy) == (0, 0):
            return  # would reverse into the snake's neck
        state.direction = new_dir

    def _spawn_food(self, snake: List[Tuple[int, int]]) -> Tuple[int, int]:
        occupied = set(snake)
        while True:
            cell = (self._random.randrange(self._grid_cols),
                    self._random.randrange(self._grid_rows))
            if cell not in occupied:
                return cell

    # ---- panic-exit handling ----

    def _track_panic(self, now_ms: int, btn) -> None:
        # We track it via "all three keys are currently held" by inspecting
        # the input thread's snapshot of the GPIO state. This is best-effort
        # — if the platform doesn't expose individual pin reads we just
        # never trigger panic.
        try:
            from seedsigner.hardware.buttons import (
                HardwareButtons, HardwareButtonsConstants,
            )
            buttons = HardwareButtons.get_instance()
            gpio_pins = getattr(buttons, "_gpio_pins", None)
            if not gpio_pins:
                return
            held = (
                self._is_low(gpio_pins, HardwareButtonsConstants.KEY1)
                and self._is_low(gpio_pins, HardwareButtonsConstants.KEY2)
                and self._is_low(gpio_pins, HardwareButtonsConstants.KEY3)
            )
        except Exception:
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

    # ---- input thread ----

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

    # ---- rendering ----

    def _render_frame(self, renderer, state: _GameState) -> None:
        with renderer.lock:
            canvas = Image.new("RGB",
                               (renderer.canvas_width, renderer.canvas_height),
                               color=(8, 12, 18))
            draw = ImageDraw.Draw(canvas)
            self._draw_playfield(draw, renderer)
            self._draw_food(draw, state)
            self._draw_snake(draw, state)
            self._draw_score(draw, state)
            renderer.show_image(canvas)

    def _render_game_over(self, renderer, state: _GameState) -> None:
        with renderer.lock:
            canvas = Image.new("RGB",
                               (renderer.canvas_width, renderer.canvas_height),
                               color=(8, 12, 18))
            draw = ImageDraw.Draw(canvas)
            self._draw_playfield(draw, renderer)
            self._draw_food(draw, state)
            self._draw_snake(draw, state, dim=True)
            label = f"Score {state.score}"
            self._draw_centered_text(draw, renderer, label, y_offset=-12)
            self._draw_centered_text(draw, renderer, "GAME OVER", y_offset=8)
            renderer.show_image(canvas)

    def _draw_playfield(self, draw: ImageDraw.ImageDraw, renderer) -> None:
        x0 = self._origin_x
        y0 = self._origin_y
        x1 = x0 + self._cell * self._grid_cols
        y1 = y0 + self._cell * self._grid_rows
        draw.rectangle([x0 - 1, y0 - 1, x1, y1], outline=(40, 60, 80))

    def _draw_food(self, draw: ImageDraw.ImageDraw, state: _GameState) -> None:
        c, r = state.food
        x0 = self._origin_x + c * self._cell
        y0 = self._origin_y + r * self._cell
        pad = max(1, self._cell // 6)
        draw.ellipse(
            [x0 + pad, y0 + pad, x0 + self._cell - pad, y0 + self._cell - pad],
            fill=(220, 70, 70),
        )

    def _draw_snake(self, draw: ImageDraw.ImageDraw, state: _GameState,
                    *, dim: bool = False) -> None:
        head_color = (90, 210, 130) if not dim else (60, 120, 80)
        body_color = (60, 170, 100) if not dim else (40, 90, 60)
        for i, (c, r) in enumerate(state.snake):
            x0 = self._origin_x + c * self._cell
            y0 = self._origin_y + r * self._cell
            color = head_color if i == 0 else body_color
            draw.rectangle(
                [x0 + 1, y0 + 1, x0 + self._cell - 1, y0 + self._cell - 1],
                fill=color,
            )

    def _draw_score(self, draw: ImageDraw.ImageDraw, state: _GameState) -> None:
        draw.text((4, 2), f"Score {state.score}", fill=(160, 200, 220))

    def _draw_centered_text(self, draw: ImageDraw.ImageDraw, renderer,
                            text: str, *, y_offset: int = 0) -> None:
        try:
            bbox = draw.textbbox((0, 0), text)
            tw = bbox[2] - bbox[0]
            th = bbox[3] - bbox[1]
        except Exception:
            tw, th = 6 * len(text), 10
        x = (renderer.canvas_width - tw) // 2
        y = (renderer.canvas_height - th) // 2 + y_offset
        draw.text((x, y), text, fill=(240, 240, 240))

    @staticmethod
    def _monotonic_ms() -> int:
        return int(time.monotonic() * 1000)
