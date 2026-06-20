"""2048 — a stealth-boot mini-game.

Turn-based 4x4 sliding-tile puzzle. The D-pad slides every tile; equal
neighbours merge once per move. A new tile (2, or occasionally 4) appears
after any move that changed the board. The game ends when the board is full
and no merges remain.

Turn-based means ``tick_ms`` is ``None``: the console never auto-advances
the game and only redraws after a move that changed something.

This module MUST NOT import any seed/Keycard/secret-handling code.
"""

from __future__ import annotations

import random
import time
from typing import List, Optional, Tuple

from PIL import ImageDraw

from .base import BaseStealthGame, stealth_font


_SIZE = 4

_TILE_COLORS = {
    0: (28, 34, 44),
    2: (60, 80, 100),
    4: (60, 104, 120),
    8: (80, 124, 80),
    16: (120, 124, 60),
    32: (146, 104, 60),
    64: (164, 84, 60),
    128: (164, 64, 104),
    256: (124, 64, 144),
    512: (84, 64, 164),
    1024: (60, 104, 164),
    2048: (60, 164, 120),
}


class Game2048(BaseStealthGame):
    name = "2048"
    menu_accent = (220, 200, 80)

    def __init__(self):
        super().__init__()
        self._random = random.Random(time.monotonic_ns())
        self._board: List[List[int]] = [[0] * _SIZE for _ in range(_SIZE)]

    # ---- contract -----------------------------------------------------------

    def reset(self, canvas_w: int, canvas_h: int) -> None:
        self._layout(canvas_w, canvas_h, _SIZE, _SIZE)
        self._board = [[0] * _SIZE for _ in range(_SIZE)]
        self.score = 0
        self.alive = True
        self._spawn()
        self._spawn()

    def handle_key(self, key: str, btn) -> bool:
        dirmap = {
            btn.KEY_LEFT: "L", btn.KEY_RIGHT: "R",
            btn.KEY_UP: "U", btn.KEY_DOWN: "D",
        }
        direction = dirmap.get(key)
        if direction is None:
            return False
        changed, gain = self._slide(direction)
        if not changed:
            return False
        self.score += gain
        self._spawn()
        if not self._has_moves():
            self.alive = False
        return True

    # ---- mechanics ----------------------------------------------------------

    @staticmethod
    def _compress_merge(line: List[int]) -> Tuple[List[int], int]:
        nonzero = [x for x in line if x]
        merged: List[int] = []
        gain = 0
        i = 0
        while i < len(nonzero):
            if i + 1 < len(nonzero) and nonzero[i] == nonzero[i + 1]:
                value = nonzero[i] * 2
                merged.append(value)
                gain += value
                i += 2
            else:
                merged.append(nonzero[i])
                i += 1
        merged += [0] * (_SIZE - len(merged))
        return merged, gain

    def _slide(self, direction: str) -> Tuple[bool, int]:
        b = self._board
        reverse = direction in ("R", "D")
        vertical = direction in ("U", "D")
        changed = False
        total_gain = 0
        for idx in range(_SIZE):
            if vertical:
                line = [b[r][idx] for r in range(_SIZE)]
            else:
                line = b[idx][:]
            if reverse:
                line = line[::-1]
            new_line, gain = self._compress_merge(line)
            total_gain += gain
            if new_line != line:
                changed = True
            if reverse:
                new_line = new_line[::-1]
            if vertical:
                for r in range(_SIZE):
                    b[r][idx] = new_line[r]
            else:
                b[idx] = new_line
        return changed, total_gain

    def _empty_cells(self) -> List[Tuple[int, int]]:
        return [(r, c) for r in range(_SIZE) for c in range(_SIZE)
                if self._board[r][c] == 0]

    def _spawn(self) -> None:
        empties = self._empty_cells()
        if not empties:
            return
        r, c = self._random.choice(empties)
        self._board[r][c] = 4 if self._random.random() < 0.1 else 2

    def _has_moves(self) -> bool:
        if self._empty_cells():
            return True
        for r in range(_SIZE):
            for c in range(_SIZE):
                v = self._board[r][c]
                if c + 1 < _SIZE and self._board[r][c + 1] == v:
                    return True
                if r + 1 < _SIZE and self._board[r + 1][c] == v:
                    return True
        return False

    # ---- rendering ----------------------------------------------------------

    def draw_frame(self, draw: ImageDraw.ImageDraw, renderer,
                   *, dim: bool = False) -> None:
        for r in range(_SIZE):
            for c in range(_SIZE):
                self._draw_tile(draw, r, c, self._board[r][c], dim=dim)
        if not dim:
            draw.text((4, 2), f"Score {self.score}", fill=(160, 200, 220),
                      font=stealth_font(14, semibold=True))

    def _draw_tile(self, draw: ImageDraw.ImageDraw, r: int, c: int,
                   value: int, *, dim: bool) -> None:
        cell = self._cell
        x0 = self._origin_x + c * cell
        y0 = self._origin_y + r * cell
        pad = max(1, cell // 16)
        color = _TILE_COLORS.get(value, (90, 90, 90))
        if dim:
            color = tuple(ch // 2 for ch in color)
        draw.rectangle([x0 + pad, y0 + pad, x0 + cell - pad, y0 + cell - pad],
                       fill=color)
        if value:
            text = str(value)
            # Size the digits to the tile so 1- to 4-digit values all fit.
            size = max(10, int(min(cell * 0.55, (cell - 8) / (0.62 * len(text)))))
            font = stealth_font(size, semibold=True)
            try:
                bbox = draw.textbbox((0, 0), text, font=font)
                tw = bbox[2] - bbox[0]
                th = bbox[3] - bbox[1]
                tx = x0 + (cell - tw) // 2 - bbox[0]
                ty = y0 + (cell - th) // 2 - bbox[1]
            except Exception:
                tw, th = 6 * len(text), 10
                tx = x0 + (cell - tw) // 2
                ty = y0 + (cell - th) // 2
            draw.text((tx, ty), text, fill=(245, 245, 245), font=font)
