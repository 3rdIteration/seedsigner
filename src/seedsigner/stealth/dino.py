"""Dino — a stealth-boot mini-game.

A one-button endless runner. The dino runs on the spot while obstacles
scroll in from the right; press UP (or the joystick) to jump. Hitting an
obstacle ends the run; the score is the distance travelled, and the game
speeds up the further you get.

Real-time: ``tick_ms`` returns the current frame interval; the console
calls :meth:`step` on a timer to advance the world.

This module MUST NOT import any seed/Keycard/secret-handling code.
"""

from __future__ import annotations

import random
import time
from typing import List

from PIL import ImageDraw

from .base import BaseStealthGame, stealth_font


COLS = 24
ROWS = 12
GROUND_ROW = ROWS - 2     # row the dino stands on / obstacles sit on
DINO_COL = 3              # dino's fixed column

_JUMP_V = 1.5             # initial upward velocity (cells/step)
_GRAVITY = 0.5            # pull-down per step
_OBSTACLE_CLEAR = 1.0     # dino must be this high to clear a 1-cell obstacle

_MIN_GAP = 6              # min steps between spawned obstacles
_MAX_GAP = 12             # max steps between spawned obstacles

_BASE_TICK_MS = 110       # initial frame interval
_MIN_TICK_MS = 55         # speed cap


class DinoGame(BaseStealthGame):
    name = "Dino"
    menu_accent = (230, 230, 230)

    def __init__(self):
        super().__init__()
        self._random = random.Random(time.monotonic_ns())
        self._obstacles: List[int] = []
        self._dino_h = 0.0
        self._vy = 0.0
        self._on_ground = True
        self._distance = 0
        self._spawn_countdown = _MIN_GAP

    # ---- contract -----------------------------------------------------------

    def reset(self, canvas_w: int, canvas_h: int) -> None:
        self._layout(canvas_w, canvas_h, COLS, ROWS)
        self._obstacles = []
        self._dino_h = 0.0
        self._vy = 0.0
        self._on_ground = True
        self._distance = 0
        self._spawn_countdown = self._random.randint(_MIN_GAP, _MAX_GAP)
        self.score = 0
        self.alive = True

    @property
    def tick_ms(self) -> int:
        return max(_MIN_TICK_MS, _BASE_TICK_MS - self._distance // 5)

    def step(self) -> None:
        if not self.alive:
            return
        # Vertical physics.
        if not self._on_ground:
            self._dino_h += self._vy
            self._vy -= _GRAVITY
            if self._dino_h <= 0:
                self._dino_h = 0.0
                self._vy = 0.0
                self._on_ground = True
        # Scroll obstacles left; drop the ones that left the screen.
        self._obstacles = [c - 1 for c in self._obstacles if c - 1 >= 0]
        self._spawn_countdown -= 1
        if self._spawn_countdown <= 0:
            self._obstacles.append(COLS - 1)
            self._spawn_countdown = self._random.randint(_MIN_GAP, _MAX_GAP)
        # Collision: an obstacle at the dino's column while it's too low.
        for c in self._obstacles:
            if c == DINO_COL and self._dino_h < _OBSTACLE_CLEAR:
                self.alive = False
                return
        # Survived this frame.
        self._distance += 1
        self.score = self._distance

    def handle_key(self, key: str, btn) -> bool:
        if not self.alive:
            return False
        if key in (btn.KEY_UP, btn.KEY_PRESS):
            if self._on_ground:
                self._vy = _JUMP_V
                self._on_ground = False
                return True
        return False

    # ---- rendering ----------------------------------------------------------

    def draw_frame(self, draw: ImageDraw.ImageDraw, renderer,
                   *, dim: bool = False) -> None:
        cell = self._cell
        ground_color = (40, 60, 80) if not dim else (24, 36, 48)
        dino_color = (90, 210, 130) if not dim else (60, 120, 80)
        obs_color = (220, 120, 80) if not dim else (120, 70, 50)

        # Ground line just under the standing row.
        gy = self._origin_y + (GROUND_ROW + 1) * cell
        draw.line([self._origin_x, gy,
                   self._origin_x + cell * COLS, gy], fill=ground_color)

        # Obstacles.
        for c in self._obstacles:
            self._draw_block(draw, c, GROUND_ROW, obs_color)

        # Dino.
        dino_row = GROUND_ROW - int(round(self._dino_h))
        if dino_row < 0:
            dino_row = 0
        self._draw_block(draw, DINO_COL, dino_row, dino_color)

        if not dim:
            draw.text((4, 2), f"Score {self.score}", fill=(160, 200, 220),
                      font=stealth_font(14, semibold=True))

    def _draw_block(self, draw: ImageDraw.ImageDraw, c: int, r: int,
                    color) -> None:
        cell = self._cell
        x0 = self._origin_x + c * cell
        y0 = self._origin_y + r * cell
        draw.rectangle([x0 + 1, y0 + 1, x0 + cell - 1, y0 + cell - 1],
                       fill=color)
