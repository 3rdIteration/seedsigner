"""Snake — a stealth-boot mini-game.

The classic snake: steer with the D-pad, eat food to grow and speed up.
Walls **wrap** (leaving one edge re-enters from the opposite edge), so the
only way to die is to run into your own body.

The shared machinery — input thread, unlock-sequence detection and the
panic exit — lives in :class:`seedsigner.stealth.console.StealthConsole`;
this module only models and draws the game (see
:class:`seedsigner.stealth.base.BaseStealthGame`).

This module MUST NOT import any seed/Keycard/secret-handling code.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from PIL import ImageDraw

from .base import BaseStealthGame, stealth_font


# Game tuning constants.
_BASE_TICK_MS = 220       # initial snake speed (one cell per tick)
_MIN_TICK_MS = 90         # speed cap as score grows
_TICK_DECAY_PER_FOOD = 8  # ms shaved off the tick after each food eaten


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


class SnakeGame(BaseStealthGame):
    name = "Snake"
    menu_accent = (100, 200, 120)

    def __init__(self, *, grid_cols: int = 16, grid_rows: int = 12):
        super().__init__()
        self._grid_cols = grid_cols
        self._grid_rows = grid_rows
        self._random = random.Random(time.monotonic_ns())
        self._state: Optional[_GameState] = None

    # ---- contract -----------------------------------------------------------

    def reset(self, canvas_w: int, canvas_h: int) -> None:
        self._layout(canvas_w, canvas_h, self._grid_cols, self._grid_rows)
        mid_c = self._grid_cols // 2
        mid_r = self._grid_rows // 2
        snake = [(mid_c, mid_r), (mid_c - 1, mid_r), (mid_c - 2, mid_r)]
        self._state = _GameState(
            width=self._grid_cols, height=self._grid_rows,
            snake=snake, food=self._spawn_food(snake),
            direction=(1, 0),
        )
        self.alive = True
        self.score = 0

    @property
    def tick_ms(self) -> int:
        return max(_MIN_TICK_MS, _BASE_TICK_MS - self.score * _TICK_DECAY_PER_FOOD)

    def step(self) -> None:
        self._advance(self._state)
        self.alive = self._state.alive
        self.score = self._state.score

    def handle_key(self, key: str, btn) -> bool:
        return self._apply_input(self._state, key, btn)

    # ---- mechanics ----------------------------------------------------------

    def _advance(self, state: _GameState) -> None:
        dx, dy = state.direction
        head_c, head_r = state.head
        # Walls wrap: leaving one edge re-enters from the opposite edge.
        new_head = ((head_c + dx) % state.width, (head_r + dy) % state.height)

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

    def _apply_input(self, state: _GameState, key: str, btn) -> bool:
        # Direction keys: prevent 180 deg reverse-into-self.
        mapping = {
            btn.KEY_UP:    (0, -1),
            btn.KEY_DOWN:  (0, 1),
            btn.KEY_LEFT:  (-1, 0),
            btn.KEY_RIGHT: (1, 0),
        }
        new_dir = mapping.get(key)
        if new_dir is None:
            return False
        cdx, cdy = state.direction
        ndx, ndy = new_dir
        if (cdx + ndx, cdy + ndy) == (0, 0):
            return False  # would reverse into the snake's neck
        if new_dir == state.direction:
            return False
        state.direction = new_dir
        return True

    def _spawn_food(self, snake: List[Tuple[int, int]]) -> Tuple[int, int]:
        occupied = set(snake)
        # Fully-packed board (player "won") -> leave food on the head; the
        # next advance is a self-collision, which ends the game cleanly.
        if len(occupied) >= self._grid_cols * self._grid_rows:
            return snake[0]
        while True:
            cell = (self._random.randrange(self._grid_cols),
                    self._random.randrange(self._grid_rows))
            if cell not in occupied:
                return cell

    # ---- rendering ----------------------------------------------------------

    def draw_frame(self, draw: ImageDraw.ImageDraw, renderer,
                   *, dim: bool = False) -> None:
        state = self._state
        self._draw_playfield(draw)
        self._draw_food(draw, state)
        self._draw_snake(draw, state, dim=dim)
        if not dim:
            draw.text((4, 2), f"Score {state.score}", fill=(160, 200, 220),
                      font=stealth_font(14, semibold=True))

    def _draw_playfield(self, draw: ImageDraw.ImageDraw) -> None:
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
