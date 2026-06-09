"""Keycard import-seed entry points: scan word-count acceptance and the
``Type words`` length chooser.

Regression cover:

* ``_capture_via_scan`` must accept every valid BIP-39 length —
  15 words used to be missing from the accepted tuple.
* The import source chooser routes ``Type words`` through a 12/15/18/21/24
  length sub-chooser into ``_capture_via_keyboard``.
"""

from __future__ import annotations

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


def _import_view():
    from seedsigner.views.keycard_views import ToolsKeycardImportSeedView
    return ToolsKeycardImportSeedView.__new__(ToolsKeycardImportSeedView)


def _scan_with_phrase(words):
    view = _import_view()
    view.run_screen = MagicMock()
    fake_decoder = MagicMock()
    fake_decoder.is_complete = True
    fake_decoder.is_seed = True
    fake_decoder.get_seed_phrase.return_value = list(words)
    with patch("seedsigner.models.decode_qr.DecodeQR", return_value=fake_decoder):
        return view._capture_via_scan()


class TestScanWordCounts(unittest.TestCase):
    def test_accepts_all_valid_bip39_lengths(self):
        for count in (12, 15, 18, 21, 24):
            phrase = _scan_with_phrase(["abandon"] * count)
            self.assertEqual(len(phrase), count, f"{count}-word scan rejected")

    def test_rejects_invalid_length(self):
        with self.assertRaises(RuntimeError):
            _scan_with_phrase(["abandon"] * 13)


class TestTypeWordsChooser(unittest.TestCase):
    def _run_with_choices(self, screen_returns):
        view = _import_view()
        view.run_screen = MagicMock(side_effect=screen_returns)
        view._capture_via_keyboard = MagicMock(return_value=None)
        view.run()
        return view

    def test_each_length_routes_to_keyboard_capture(self):
        # Screens: DireWarning (Continue) -> Source (Type words) -> length.
        for idx, expected in enumerate((12, 15, 18, 21, 24)):
            view = self._run_with_choices([0, 1, idx])
            view._capture_via_keyboard.assert_called_once_with(expected)

    def test_back_out_of_length_chooser_skips_keyboard(self):
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        view = _import_view()
        view.run_screen = MagicMock(side_effect=[0, 1, RET_CODE__BACK_BUTTON])
        view._capture_via_keyboard = MagicMock()
        view.run()
        view._capture_via_keyboard.assert_not_called()


if __name__ == "__main__":
    unittest.main()
