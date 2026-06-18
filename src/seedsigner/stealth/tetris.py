"""Tetris — a stealth-boot mini-game.

A compact 10x18 well. LEFT/RIGHT move, UP rotates, DOWN soft-drops and
KEY_PRESS hard-drops. Full rows clear and the fall speeds up as more lines
go. The game ends when a freshly spawned piece has nowhere to go.

Real-time: ``tick_ms`` returns the current gravity interval, so the console
calls :meth:`step` on a timer to drop the active piece one row.

This module MUST NOT import any seed/Keycard/secret-handling code.
"""

from __future__ import annotations

import random
import time
from typing import List, Optional, Tuple

from PIL import ImageDraw

from .base import BaseStealthGame


COLS = 10
ROWS = 18

_BASE_TICK_MS = 650          # initial gravity interval
_MIN_TICK_MS = 140           # speed cap
_TICK_DECAY_PER_LINE = 35    # ms shaved off per line cleared

_LINE_SCORE = {1: 100, 2: 300, 3: 500, 4: 800}

# Base tetromino shapes as (row, col) cells in a local box.
SHAPES = {
    "I": [(0, 0), (0, 1), (0, 2), (0, 3)],
    "O": [(0, 0), (0, 1), (1, 0), (1, 1)],
    "T": [(0, 0), (0, 1), (0, 2), (1, 1)],
    "S": [(0, 1), (0, 2), (1, 0), (1, 1)],
    "Z": [(0, 0), (0, 1), (1, 1), (1, 2)],
    "J": [(0, 0), (1, 0), (1, 1), (1, 2)],
    "L": [(0, 2), (1, 0), (1, 1), (1, 2)],
}

COLORS = {
    "I": (80, 200, 220),
    "O": (220, 200, 80),
    "T": (180, 100, 200),
    "S": (100, 200, 120),
    "Z": (220, 100, 100),
    "J": (100, 120, 220),
    "L": (220, 150, 80),
}

Cell = Tuple[int, int]
Color = Tuple[int, int, int]


class TetrisGame(BaseStealthGame):
    name = "Tetris"

    def __init__(self):
        super().__init__()
        self._random = random.Random(time.monotonic_ns())
        self._grid: List[List[object]] = [[0] * COLS for _ in range(ROWS)]
        self._shape: List[Cell] = []
        self._color: Color = (200, 200, 200)
        self._pr = 0
        self._pc = 0
        self._lines = 0

    # ---- contract -----------------------------------------------------------

    def reset(self, canvas_w: int, canvas_h: int) -> None:
        self._layout(canvas_w, canvas_h, COLS, ROWS)
        self._grid = [[0] * COLS for _ in range(ROWS)]
        self._lines = 0
        self.score = 0
        self.alive = True
        self._spawn()

    @property
    def tick_ms(self) -> int:
        return max(_MIN_TICK_MS, _BASE_TICK_MS - self._lines * _TICK_DECAY_PER_LINE)

    def step(self) -> None:
        if not self.alive:
            return
        if not self._collides(self._shape, self._pr + 1, self._pc):
            self._pr += 1
        else:
            self._lock()

    def handle_key(self, key: str, btn) -> bool:
        if not self.alive:
            return False
        if key == btn.KEY_LEFT:
            if not self._collides(self._shape, self._pr, self._pc - 1):
                self._pc -= 1
                return True
            return False
        if key == btn.KEY_RIGHT:
            if not self._collides(self._shape, self._pr, self._pc + 1):
                self._pc += 1
                return True
            return False
        if key == btn.KEY_UP:
            rotated = self._rotate(self._shape)
            if not self._collides(rotated, self._pr, self._pc):
                self._shape = rotated
                return True
            return False
        if key == btn.KEY_DOWN:
            if not self._collides(self._shape, self._pr + 1, self._pc):
                self._pr += 1
            else:
                self._lock()
            return True
        if key == btn.KEY_PRESS:
            while not self._collides(self._shape, self._pr + 1, self._pc):
                self._pr += 1
            self._lock()
            return True
        return False

    # ---- mechanics ----------------------------------------------------------

    @staticmethod
    def _rotate(cells: List[Cell]) -> List[Cell]:
        """Rotate 90 deg clockwise and normalise to a (0,0) origin."""
        rotated = [(c, -r) for (r, c) in cells]
        min_r = min(r for r, _ in rotated)
        min_c = min(c for _, c in rotated)
        return [(r - min_r, c - min_c) for (r, c) in rotated]

    def _spawn(self) -> None:
        piece = self._random.choice(list(SHAPES))
        self._shape = list(SHAPES[piece])
        self._color = COLORS[piece]
        width = max(c for _, c in self._shape) + 1
        self._pc = (COLS - width) // 2
        self._pr = 0
        if self._collides(self._shape, self._pr, self._pc):
            self.alive = False

    def _collides(self, shape: List[Cell], pr: int, pc: int) -> bool:
        for (r, c) in shape:
            ar, ac = pr + r, pc + c
            if ac < 0 or ac >= COLS or ar >= ROWS:
                return True
            if ar >= 0 and self._grid[ar][ac]:
                return True
        return False

    def _lock(self) -> None:
        for (r, c) in self._shape:
            ar, ac = self._pr + r, self._pc + c
            if 0 <= ar < ROWS and 0 <= ac < COLS:
                self._grid[ar][ac] = self._color
        cleared = self._clear_lines()
        if cleared:
            self._lines += cleared
            self.score += _LINE_SCORE.get(cleared, cleared * 200)
        self._spawn()

    def _clear_lines(self) -> int:
        kept = [row for row in self._grid if not all(row)]
        cleared = ROWS - len(kept)
        if cleared:
            self._grid = [[0] * COLS for _ in range(cleared)] + kept
        return cleared

    # ---- rendering ----------------------------------------------------------

    def draw_frame(self, draw: ImageDraw.ImageDraw, renderer,
                   *, dim: bool = False) -> None:
        self._draw_border(draw)
        for r in range(ROWS):
            for c in range(COLS):
                color = self._grid[r][c]
                if color:
                    self._draw_cell(draw, r, c, color, dim)
        if self.alive:
            for (r, c) in self._shape:
                self._draw_cell(draw, self._pr + r, self._pc + c,
                                self._color, dim)
        if not dim:
            draw.text((4, 2), f"Lines {self._lines}", fill=(160, 200, 220))

    def _draw_border(self, draw: ImageDraw.ImageDraw) -> None:
        x0 = self._origin_x
        y0 = self._origin_y
        x1 = x0 + self._cell * COLS
        y1 = y0 + self._cell * ROWS
        draw.rectangle([x0 - 1, y0 - 1, x1, y1], outline=(40, 60, 80))

    def _draw_cell(self, draw: ImageDraw.ImageDraw, r: int, c: int,
                   color, dim: bool) -> None:
        if r < 0:
            return
        cell = self._cell
        x0 = self._origin_x + c * cell
        y0 = self._origin_y + r * cell
        if dim:
            color = tuple(ch // 2 for ch in color)
        draw.rectangle([x0 + 1, y0 + 1, x0 + cell - 1, y0 + cell - 1],
                       fill=color)
