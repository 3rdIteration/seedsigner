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

from .base import (
    BaseStealthGame, DEFAULT_MENU_ACCENT, new_canvas, stealth_font,
)
from .dino import DinoGame
from .game_2048 import Game2048
from .snake import SnakeGame
from .tetris import TetrisGame
from .unlock import UnlockBuffer, parse_sequence


logger = logging.getLogger(__name__)


_PANIC_HOLD_MS = 10_000   # how long all three side keys must be held
_PANIC_POLL_S = 0.2       # menu/idle poll so panic is checked without input
_RESTART_DELAY_S = 1.0    # pause on game-over before returning to the menu
_REPEAT_MIN_MS = 100      # min gap between repeated game/menu actions for a
                          # held key (caps auto-repeat at ~10/s, so a held
                          # button never floods the way ``wait_for`` repeats do)
_INPUT_QUEUE_MAX = 64     # backstop so a stalled consumer can't grow the queue


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
        self._input_q: "queue.Queue[str]" = queue.Queue(maxsize=_INPUT_QUEUE_MAX)
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
                # Drop a still-held select press so the chosen game doesn't act
                # on it on entry (e.g. Tetris hard-dropping immediately).
                self._flush_queue()
                game = game_cls()
                game.reset(renderer.canvas_width, renderer.canvas_height)
                game.render(renderer)
                self._play(renderer, game, btn)
                # Drop stale repeats from the game we just left before the menu.
                self._flush_queue()
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
        last_action: dict = {}
        while True:
            batch = self._drain_input(_PANIC_POLL_S)
            now = self._monotonic_ms()
            self._track_panic(now, btn)
            for key in batch:
                self._consume(key)  # raw — may raise StealthGameExit
                if key in (btn.KEY_PRESS, btn.KEY_RIGHT):
                    return self._games[idx]
                if key not in (btn.KEY_UP, btn.KEY_DOWN):
                    continue
                # Throttle held UP/DOWN so the list scrolls calmly instead of
                # flooding, and stops the moment the button is released.
                if now - last_action.get(key, -10_000) < _REPEAT_MIN_MS:
                    continue
                last_action[key] = now
                step = -1 if key == btn.KEY_UP else 1
                idx = (idx + step) % len(self._games)
                self._render_menu(renderer, idx)

    # Console-menu palette (cool arcade look over the shared dark background).
    _MENU_TITLE = (120, 200, 255)
    _MENU_DIVIDER = (40, 70, 96)
    _MENU_CARD_BG = (20, 30, 42)
    _MENU_CARD_SEL = (120, 200, 255)
    _MENU_TEXT = (210, 224, 236)
    _MENU_TEXT_DIM = (120, 140, 160)
    _MENU_TEXT_SEL = (8, 14, 22)
    _MENU_HINT = (90, 112, 134)

    def _render_menu(self, renderer, selected: int) -> None:
        with renderer.lock:
            try:
                canvas = self._draw_menu(renderer, selected)
            except Exception:
                # The boot menu must never crash; fall back to a plain,
                # font-/anchor-free render if anything (e.g. a missing font)
                # goes wrong in the styled path.
                logger.exception("stealth menu render failed; using fallback")
                canvas = self._draw_menu_fallback(renderer, selected)
            renderer.show_image(canvas)

    def _draw_menu(self, renderer, selected: int):
        """Styled 'arcade cards' menu. May raise; caller has a fallback."""
        canvas = new_canvas(renderer)
        draw = ImageDraw.Draw(canvas)
        w = renderer.canvas_width
        h = renderer.canvas_height

        title_font = stealth_font(22, semibold=True)
        name_font = stealth_font(18, semibold=True)
        hint_font = stealth_font(13, semibold=False)

        pad = 8
        # ---- header ------------------------------------------------------
        # Decorations are drawn as shapes, not font glyphs: OpenSans has no
        # geometric-shape characters (▶ ▲ ● …), which would render as tofu.
        draw.polygon([(pad, 7), (pad, 21), (pad + 11, 14)],
                     fill=self._MENU_TITLE)  # play-triangle badge
        draw.text((pad + 18, 6), "GAMES", fill=self._MENU_TITLE, font=title_font)
        # Three little console "dots" on the right for flavour.
        for k, dot in enumerate(((90, 210, 130), (220, 200, 80),
                                 (220, 100, 100))):
            cx = w - pad - 6 - k * 14
            draw.ellipse([cx - 4, 12, cx + 4, 20], fill=dot)
        header_bottom = 34
        draw.line([pad, header_bottom, w - pad, header_bottom],
                  fill=self._MENU_DIVIDER, width=1)

        # ---- game cards --------------------------------------------------
        top = header_bottom + 8
        hint_h = 20
        avail = h - top - hint_h - pad
        n = max(1, len(self._games))
        gap = 6
        row_h = max(20, (avail - gap * (n - 1)) // n)
        for i, game_cls in enumerate(self._games):
            y = top + i * (row_h + gap)
            name = getattr(game_cls, "name", game_cls.__name__)
            accent = getattr(game_cls, "menu_accent", DEFAULT_MENU_ACCENT)
            is_sel = (i == selected)

            # Card background.
            draw.rounded_rectangle(
                [pad, y, w - pad, y + row_h],
                radius=6,
                fill=self._MENU_CARD_SEL if is_sel else self._MENU_CARD_BG,
            )
            # Colored swatch (the game's accent).
            sw = row_h - 10
            sx, sy = pad + 8, y + 5
            draw.rounded_rectangle([sx, sy, sx + sw, sy + sw], radius=3,
                                   fill=accent)
            # Name, vertically centred on the card.
            text_color = self._MENU_TEXT_SEL if is_sel else self._MENU_TEXT
            draw.text((sx + sw + 10, y + row_h // 2), name,
                      fill=text_color, font=name_font, anchor="lm")
            # Play marker on the selected card (drawn triangle, not a glyph).
            if is_sel:
                mx = w - pad - 18
                my = y + row_h // 2
                draw.polygon([(mx, my - 6), (mx, my + 6), (mx + 11, my)],
                             fill=self._MENU_TEXT_SEL)

        # ---- footer hint (shapes + words; no special glyphs) -------------
        fy = h - 11
        move_w = self._text_w(draw, "move", hint_font)
        play_w = self._text_w(draw, "play", hint_font)
        tri_w = 9
        seg = tri_w + 5 + move_w + 16 + 10 + 5 + play_w
        fx = (w - seg) // 2
        # Up/down triangles for the "move" hint.
        cx = fx + tri_w // 2
        draw.polygon([(cx, fy - 7), (cx - 4, fy - 1), (cx + 4, fy - 1)],
                     fill=self._MENU_HINT)
        draw.polygon([(cx, fy + 7), (cx - 4, fy + 1), (cx + 4, fy + 1)],
                     fill=self._MENU_HINT)
        tx = fx + tri_w + 5
        draw.text((tx, fy), "move", fill=self._MENU_HINT, font=hint_font,
                  anchor="lm")
        # Action dot for the "play" hint.
        dot_x = tx + move_w + 16
        draw.ellipse([dot_x, fy - 5, dot_x + 10, fy + 5], fill=(120, 200, 255))
        draw.text((dot_x + 15, fy), "play", fill=self._MENU_HINT,
                  font=hint_font, anchor="lm")
        return canvas

    @staticmethod
    def _text_w(draw, text, font) -> int:
        try:
            b = draw.textbbox((0, 0), text, font=font)
            return b[2] - b[0]
        except Exception:
            return 6 * len(text)

    def _draw_menu_fallback(self, renderer, selected: int):
        """Anchor-free, font-optional menu — guaranteed not to raise."""
        canvas = new_canvas(renderer)
        draw = ImageDraw.Draw(canvas)
        w = renderer.canvas_width
        draw.text((6, 6), "GAMES", fill=self._MENU_TITLE)
        top = 34
        avail = renderer.canvas_height - top - 6
        row_h = max(16, avail // max(1, len(self._games)))
        for i, game_cls in enumerate(self._games):
            y = top + i * row_h
            name = getattr(game_cls, "name", game_cls.__name__)
            if i == selected:
                draw.rectangle([4, y, w - 4, y + row_h - 4], fill=(30, 50, 70))
                draw.text((12, y + 2), "> " + name, fill=(240, 240, 240))
            else:
                draw.text((12, y + 2), "  " + name, fill=(150, 170, 190))
        return canvas

    # ---- gameplay loop ------------------------------------------------------

    def _play(self, renderer, game: BaseStealthGame, btn) -> None:
        """Drive one game until it dies or KEY1 returns to the menu.

        Raises ``StealthGameExit`` if the unlock combo or panic fires.
        """
        tick_ms = game.tick_ms
        last_tick = self._monotonic_ms()
        last_action: dict = {}
        while game.alive:
            now = self._monotonic_ms()
            if tick_ms is None:
                timeout_s = _PANIC_POLL_S
            else:
                timeout_s = max(0.0, (tick_ms - (now - last_tick)) / 1000.0)

            # Drain the whole queue every frame: a held key never leaves a
            # backlog that keeps acting after the finger is lifted.
            batch = self._drain_input(timeout_s)
            now = self._monotonic_ms()
            self._track_panic(now, btn)

            dirty = False
            for key in batch:
                self._consume(key)  # raw — may raise StealthGameExit
                if key == btn.KEY1:
                    return  # back to the console menu
                # Throttle held-key repeats: at most one action per key per
                # ``_REPEAT_MIN_MS``, so a flood collapses to ~10/s and stops
                # the instant the queue empties.
                if now - last_action.get(key, -10_000) < _REPEAT_MIN_MS:
                    continue
                last_action[key] = now
                if game.handle_key(key, btn):
                    dirty = True
                    if not game.alive:
                        break
            if not game.alive:
                break
            if dirty:
                game.render(renderer)

            if tick_ms is not None and self._monotonic_ms() - last_tick >= tick_ms:
                game.step()
                last_tick = self._monotonic_ms()
                if game.alive:
                    game.render(renderer)
                tick_ms = game.tick_ms

        game.render_game_over(renderer)
        time.sleep(_RESTART_DELAY_S)

    # ---- input draining -----------------------------------------------------

    def _drain_input(self, timeout_s: float) -> List[str]:
        """Block up to ``timeout_s`` for the first key, then drain the rest.

        Returning every queued key at once (and so emptying the queue each
        frame) is what stops a held button's ``wait_for`` repeats from piling
        up into a backlog that keeps acting after the button is released.
        """
        batch: List[str] = []
        try:
            batch.append(self._input_q.get(timeout=timeout_s))
            while True:
                batch.append(self._input_q.get_nowait())
        except queue.Empty:
            pass
        return batch

    def _flush_queue(self) -> None:
        """Drop every queued key without consuming (used on transitions)."""
        try:
            while True:
                self._input_q.get_nowait()
        except queue.Empty:
            pass

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
                try:
                    self._input_q.put_nowait(key)
                except queue.Full:
                    # Consumer stalled (e.g. the game-over pause). Drop the
                    # oldest buffered key to make room rather than block here.
                    try:
                        self._input_q.get_nowait()
                    except queue.Empty:
                        pass
                    try:
                        self._input_q.put_nowait(key)
                    except queue.Full:
                        pass

        t = threading.Thread(target=_pump, name="stealth-input", daemon=True)
        t.start()
        self._input_thread = t

    @staticmethod
    def _monotonic_ms() -> int:
        return int(time.monotonic() * 1000)
