"""NGRAVE 'Perfect Key' hex import into a Keycard.

The hex import reuses the whole ToolsKeycardImportSeedView push pipeline;
only the capture step is new. These tests exercise that capture step
(``_capture_via_hex``) in isolation: hex -> 32-byte BIP-39 entropy ->
24-word mnemonic, the 12-word (128-bit) variant, input validation, the
scan vs keyboard sources, and the wordlist-copy safety invariant from
CLAUDE.md.
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

HEX_SCREEN = "seedsigner.gui.screens.screen.KeycardHexEntryScreen"


def _import_view():
    from seedsigner.views.keycard_views import ToolsKeycardImportSeedView
    return ToolsKeycardImportSeedView.__new__(ToolsKeycardImportSeedView)


def _type_hex(view, hex_str):
    """Drive ``_capture_via_hex`` via the 'Type hex' keyboard path."""
    view.run_screen = MagicMock(return_value=1)  # method chooser -> Type hex
    fake_screen = MagicMock()
    fake_screen.return_value.display.return_value = hex_str
    with patch(HEX_SCREEN, fake_screen):
        return view._capture_via_hex()


class TestHexCapture(unittest.TestCase):
    def test_64_hex_returns_24_words(self):
        words = _type_hex(_import_view(), "00" * 32)
        self.assertEqual(len(words), 24)
        self.assertEqual(words[0], "abandon")
        self.assertEqual(words[-1], "art")

    def test_32_hex_returns_12_words(self):
        words = _type_hex(_import_view(), "00" * 16)
        self.assertEqual(len(words), 12)

    def test_known_vector_round_trips_to_fingerprint(self):
        from embit import bip39, bip32
        words = _type_hex(_import_view(), "0c1e24e5917779d297e14d45f14e1a1a")
        self.assertEqual(words[:3], ["army", "van", "defense"])
        seed = bip39.mnemonic_to_seed(" ".join(words), password="")
        fp = bip32.HDKey.from_seed(seed).my_fingerprint.hex()
        self.assertEqual(len(fp), 8)  # deterministic 4-byte fingerprint

    def test_accepts_0x_prefix_and_uppercase(self):
        words = _type_hex(_import_view(), "0X" + "AB" * 32)
        self.assertEqual(len(words), 24)

    def test_rejects_bad_length(self):
        # 40 hex chars is neither 32 nor 64.
        self.assertIsNone(_type_hex(_import_view(), "ab" * 20))

    def test_rejects_non_hex(self):
        self.assertIsNone(_type_hex(_import_view(), "zz" * 32))

    def test_back_out_of_source_chooser_returns_none(self):
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        view = _import_view()
        view.run_screen = MagicMock(return_value=RET_CODE__BACK_BUTTON)
        self.assertIsNone(view._capture_via_hex())

    def test_scan_path_uses_decoded_text(self):
        view = _import_view()
        view.run_screen = MagicMock(return_value=0)  # method chooser -> Scan QR
        view._scan_hex_text = MagicMock(return_value="00" * 32)
        words = view._capture_via_hex()
        self.assertEqual(len(words), 24)

    def test_words_are_independent_copies_of_wordlist(self):
        # CLAUDE.md: a wipe of the returned list must never corrupt the
        # shared BIP-39 WORDLIST, so every word must be a fresh object.
        from embit import bip39
        words = _type_hex(_import_view(), "ff" * 32)
        for w in words:
            idx = bip39.WORDLIST.index(w)
            self.assertIsNot(w, bip39.WORDLIST[idx])


class TestImportMenuOffersHex(unittest.TestCase):
    def test_hex_option_present(self):
        from seedsigner.views.keycard_views import ToolsKeycardImportSeedView
        self.assertEqual(
            ToolsKeycardImportSeedView.HEX.button_label, "Import hex (NGRAVE)",
        )


if __name__ == "__main__":
    unittest.main()
