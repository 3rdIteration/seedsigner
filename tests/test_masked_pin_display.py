"""Regression guard for the masked PIN pad's phantom first digit.

``MaskedPINEntryDisplay`` inherits from ``TextEntryDisplay``, whose
``cur_text`` defaults to a single space so the block/bar cursor always has
a glyph to draw. For the masked PIN pad that phantom space made
``filled = min(len(cur_text), num_slots)`` equal to ``1`` *before any key
was pressed*, so the first slot rendered as already-filled and the first
real keypress appeared to do nothing (the dots lagged a digit behind). The
fix overrides the default to an empty string; these tests pin it.
"""

from __future__ import annotations

import dataclasses
import os
import sys
import unittest
from unittest.mock import MagicMock, patch


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def _install_hw_mocks():
    for mod in [
        "RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
        "smartcard", "smartcard.System", "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
    ]:
        sys.modules.setdefault(mod, MagicMock())


_install_hw_mocks()


class TestMaskedPinPhantomDigit(unittest.TestCase):
    def test_cur_text_defaults_to_empty_not_space(self):
        from seedsigner.gui.keyboard import MaskedPINEntryDisplay

        fields = {f.name: f for f in dataclasses.fields(MaskedPINEntryDisplay)}
        # The exact bug was inheriting TextEntryDisplay's single-space default.
        self.assertEqual(fields["cur_text"].default, "")
        self.assertNotEqual(fields["cur_text"].default, " ")

    def test_filled_slot_count_tracks_entered_digits(self):
        """A freshly-constructed pad has zero filled slots, and the count
        rises one-for-one with each digit — no off-by-one phantom."""
        from PIL import Image
        from seedsigner.gui.keyboard import MaskedPINEntryDisplay

        canvas = Image.new("RGB", (240, 240))
        # render() draws only rounded rects + dots (no glyphs), so the font
        # that __post_init__ loads is never used — stub it so the test does
        # not depend on font resources.
        with patch("seedsigner.gui.keyboard.Fonts.get_font", return_value=MagicMock()):
            disp = MaskedPINEntryDisplay(
                num_slots=6,
                canvas=canvas,
                rect=(8, 48, 232, 88),
                is_centered=False,
            )

            # Default state: nothing entered yet -> zero filled slots.
            self.assertEqual(disp.cur_text, "")
            self.assertEqual(min(len(disp.cur_text), disp.num_slots), 0)

            # Each render(cur_text=...) must keep filled == len(input), so the
            # first keypress fills exactly the first slot.
            for entered in ["", "1", "12", "123456"]:
                disp.render(entered)
                self.assertEqual(
                    min(len(disp.cur_text), disp.num_slots), len(entered),
                )


if __name__ == "__main__":
    unittest.main()
