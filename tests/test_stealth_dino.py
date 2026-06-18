"""Tests for ``seedsigner.stealth.dino.DinoGame``."""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def _btn():
    b = MagicMock()
    b.KEY_UP = "KEY_UP"
    b.KEY_PRESS = "KEY_PRESS"
    return b


def _game():
    from seedsigner.stealth.dino import DinoGame
    g = DinoGame()
    g.reset(240, 120)
    g._obstacles = []
    g._spawn_countdown = 9999  # keep spawns out of these deterministic tests
    return g


class TestDino(unittest.TestCase):
    def test_jump_rises_then_lands(self):
        g = _game()
        btn = _btn()
        self.assertTrue(g._on_ground)
        self.assertTrue(g.handle_key("KEY_UP", btn))
        self.assertFalse(g._on_ground)
        heights = []
        for _ in range(40):
            g.step()
            heights.append(g._dino_h)
            if g._on_ground:
                break
        self.assertGreater(max(heights), 1.0)  # cleared a 1-cell obstacle height
        self.assertTrue(g._on_ground)          # came back down

    def test_cannot_double_jump(self):
        g = _game()
        btn = _btn()
        self.assertTrue(g.handle_key("KEY_UP", btn))
        self.assertFalse(g.handle_key("KEY_UP", btn))  # already airborne

    def test_obstacle_at_dino_column_kills_when_low(self):
        from seedsigner.stealth.dino import DINO_COL
        g = _game()
        g._obstacles = [DINO_COL + 1]
        g.step()  # obstacle scrolls onto the dino column while grounded
        self.assertFalse(g.alive)

    def test_jumping_clears_obstacle(self):
        from seedsigner.stealth.dino import DINO_COL
        g = _game()
        btn = _btn()
        g.handle_key("KEY_UP", btn)
        g.step()                      # rise
        g.step()                      # rise more (h > 1)
        self.assertGreater(g._dino_h, 1.0)
        g._obstacles = [DINO_COL + 1]
        g.step()                      # obstacle reaches dino column, but it's high
        self.assertTrue(g.alive)

    def test_score_tracks_distance(self):
        g = _game()
        for _ in range(5):
            g.step()
        self.assertEqual(g.score, 5)


if __name__ == "__main__":
    unittest.main()
