"""Shared contract for stealth-boot mini-games.

Every game rendered by :class:`seedsigner.stealth.console.StealthConsole`
subclasses :class:`BaseStealthGame`. The console owns everything shared
between games — the input thread, the unlock-sequence buffer and the
panic-exit handling — so a game only has to model its own state and draw
itself. This keeps each game small and keeps the secret-detection code in
exactly one place.

A game is driven like this by the console::

    game = SomeGame()
    game.reset(canvas_w, canvas_h)
    game.render(renderer)
    while game.alive:
        key = ...                       # a button press, or None on a tick
        if key is not None:
            if game.handle_key(key, btn):   # state changed -> redraw
                game.render(renderer)
        if game.tick_ms is not None and tick_elapsed:
            game.step()                 # advance one frame (real-time games)
            game.render(renderer)
    game.render_game_over(renderer)

``tick_ms`` returning ``None`` marks a **turn-based** game (e.g. 2048): the
console never calls :meth:`step` and only redraws after an input that
changed something.

This module MUST NOT import any seed/Keycard/secret-handling code (see the
package docstring and ``tests/test_stealth_import_guard.py``). It only
touches PIL and the ``Renderer`` singleton passed in by the console.
"""

from __future__ import annotations

from typing import Optional

from PIL import Image, ImageDraw


# Shared dark background used by every game and by the console menu.
BACKGROUND = (8, 12, 18)


def new_canvas(renderer) -> Image.Image:
    """A fresh full-screen canvas in the shared background colour."""
    return Image.new(
        "RGB",
        (renderer.canvas_width, renderer.canvas_height),
        color=BACKGROUND,
    )


def draw_centered_text(draw: ImageDraw.ImageDraw, renderer, text: str,
                       *, y_offset: int = 0,
                       fill=(240, 240, 240)) -> None:
    """Draw ``text`` centred on the canvas, offset vertically by ``y_offset``."""
    try:
        bbox = draw.textbbox((0, 0), text)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
    except Exception:
        tw, th = 6 * len(text), 10
    x = (renderer.canvas_width - tw) // 2
    y = (renderer.canvas_height - th) // 2 + y_offset
    draw.text((x, y), text, fill=fill)


class BaseStealthGame:
    """Base class for a stealth-boot mini-game.

    Subclasses must set :attr:`name`, implement :meth:`reset` and
    :meth:`draw_frame`, and update :attr:`alive` / :attr:`score`. Real-time
    games additionally override :attr:`tick_ms` and :meth:`step`; turn-based
    games leave ``tick_ms`` as ``None`` and act only in :meth:`handle_key`.
    """

    name: str = "Game"

    def __init__(self) -> None:
        self.alive: bool = True
        self.score: int = 0
        # Playfield geometry, filled in by ``_layout`` from ``reset``.
        self._cell: int = 0
        self._origin_x: int = 0
        self._origin_y: int = 0

    # ---- geometry -----------------------------------------------------------

    def _layout(self, canvas_w: int, canvas_h: int,
                cols: int, rows: int) -> None:
        """Centre a ``cols`` x ``rows`` grid in the canvas (cell >= 4 px)."""
        cell_w = canvas_w // cols
        cell_h = canvas_h // rows
        cell = max(4, min(cell_w, cell_h))
        self._cell = cell
        self._origin_x = (canvas_w - cell * cols) // 2
        self._origin_y = (canvas_h - cell * rows) // 2

    # ---- contract -----------------------------------------------------------

    def reset(self, canvas_w: int, canvas_h: int) -> None:
        """(Re)initialise game state for a canvas of the given size."""
        raise NotImplementedError

    @property
    def tick_ms(self) -> Optional[int]:
        """Auto-advance interval in ms, or ``None`` for a turn-based game."""
        return None

    def step(self) -> None:
        """Advance one tick (real-time games only); no-op by default."""

    def handle_key(self, key: str, btn) -> bool:
        """Apply an input. Return ``True`` if the visible state changed."""
        return False

    def draw_frame(self, draw: ImageDraw.ImageDraw, renderer,
                   *, dim: bool = False) -> None:
        """Draw the current frame onto ``draw``. ``dim`` is used on game-over."""
        raise NotImplementedError

    # ---- rendering (shared) -------------------------------------------------

    def render(self, renderer) -> None:
        with renderer.lock:
            canvas = new_canvas(renderer)
            draw = ImageDraw.Draw(canvas)
            self.draw_frame(draw, renderer)
            renderer.show_image(canvas)

    def render_game_over(self, renderer) -> None:
        with renderer.lock:
            canvas = new_canvas(renderer)
            draw = ImageDraw.Draw(canvas)
            self.draw_frame(draw, renderer, dim=True)
            draw_centered_text(draw, renderer, f"Score {self.score}",
                               y_offset=-12)
            draw_centered_text(draw, renderer, "GAME OVER", y_offset=8)
            renderer.show_image(canvas)
