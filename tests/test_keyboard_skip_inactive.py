"""Keyboard navigation skips deactivated ("greyed") keys when opted in.

The BIP-39 word-entry dictionary greys out letters that can't continue a valid
word. With ``Keyboard.skip_inactive_keys`` enabled, D-pad navigation must land
on the next *available* key instead of letting the cursor sit on a deactivated
one. With the flag off (the default for PIN/PUK/passphrase/hex keyboards) the
behaviour is unchanged.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock


for _mod in ["RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
             "smartcard", "smartcard.System", "pygame"]:
    sys.modules.setdefault(_mod, MagicMock())

SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)

from PIL import Image, ImageDraw  # noqa: E402

from seedsigner.gui.keyboard import Keyboard  # noqa: E402
from seedsigner.hardware.buttons import HardwareButtonsConstants  # noqa: E402


CHARSET = "abcdefghijklmnopqrstuvwxyz"
# 5x6 grid → rows: [abcdef][ghijkl][mnopqr][stuvwx][yz + DEL]


def _make_keyboard():
    img = Image.new("RGB", (240, 240))
    draw = ImageDraw.Draw(img)
    return Keyboard(
        draw=draw,
        charset=CHARSET,
        rows=5,
        cols=6,
        rect=(0, 40, 200, 240),
        auto_wrap=[Keyboard.WRAP_LEFT, Keyboard.WRAP_RIGHT],
        render_now=False,
    )


class TestSkipInactiveKeys(unittest.TestCase):
    def _greyed(self, active):
        return set(CHARSET) - set(active)

    def test_right_skips_to_next_active_letter_in_row(self):
        kb = _make_keyboard()
        active = ["a", "e", "m", "z"]      # a & e share row 0 (x=0 and x=4)
        kb.update_active_keys(active)
        kb.skip_inactive_keys = True
        kb.set_selected_key("a")
        ret = kb.update_from_input(HardwareButtonsConstants.KEY_RIGHT)
        # b, c, d are greyed → cursor lands directly on the next active letter.
        self.assertEqual(ret, "e")

    def test_down_skips_to_next_active_letter_in_column(self):
        kb = _make_keyboard()
        active = ["a", "m", "z"]           # a (row0,x0) and m (row2,x0) share col 0
        kb.update_active_keys(active)
        kb.skip_inactive_keys = True
        kb.set_selected_key("a")
        ret = kb.update_from_input(HardwareButtonsConstants.KEY_DOWN)
        # g (row1,x0) is greyed → skip straight to m.
        self.assertEqual(ret, "m")

    def test_navigation_never_rests_on_a_greyed_key(self):
        kb = _make_keyboard()
        active = ["a", "e", "m", "z"]
        greyed = self._greyed(active)
        kb.update_active_keys(active)
        kb.skip_inactive_keys = True
        kb.set_selected_key("a")
        # Horizontal wraps (never exits) so every landing is an active letter or
        # an always-active additional key (DEL); never a greyed letter.
        for _ in range(40):
            ret = kb.update_from_input(HardwareButtonsConstants.KEY_RIGHT)
            self.assertNotIn(ret, greyed)

    def test_disabled_flag_lands_on_greyed_keys(self):
        # Control: without the opt-in, navigation still rests on greyed keys.
        kb = _make_keyboard()
        active = ["a", "z"]
        greyed = self._greyed(active)
        kb.update_active_keys(active)
        self.assertFalse(kb.skip_inactive_keys)  # default off
        kb.set_selected_key("a")
        seen_greyed = False
        for _ in range(6):
            ret = kb.update_from_input(HardwareButtonsConstants.KEY_RIGHT)
            if ret in greyed:
                seen_greyed = True
        self.assertTrue(seen_greyed)

    def test_all_letters_active_is_a_no_op(self):
        # Nothing greyed → skip loop must not change where a single press lands.
        kb_skip = _make_keyboard()
        kb_skip.update_active_keys(list(CHARSET))
        kb_skip.skip_inactive_keys = True
        kb_skip.set_selected_key("a")
        ret_skip = kb_skip.update_from_input(HardwareButtonsConstants.KEY_RIGHT)

        kb_plain = _make_keyboard()
        kb_plain.update_active_keys(list(CHARSET))
        kb_plain.set_selected_key("a")
        ret_plain = kb_plain.update_from_input(HardwareButtonsConstants.KEY_RIGHT)

        self.assertEqual(ret_skip, ret_plain)
        self.assertEqual(ret_skip, "b")


if __name__ == "__main__":
    unittest.main()
