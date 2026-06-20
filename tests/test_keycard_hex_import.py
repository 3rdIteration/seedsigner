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


def _normalise(hex_str):
    cleaned = "".join(hex_str.split()).lower()
    return cleaned[2:] if cleaned.startswith("0x") else cleaned


def _type_hex(view, hex_str, length_index=None):
    """Drive ``_capture_via_hex`` via the 'Type hex' keyboard path.

    ``_capture_via_hex`` now asks twice before the keyboard: a source chooser
    (-> Type hex) and a key-length chooser (24 vs 12 words). Unless
    ``length_index`` is given we pick the length to match ``hex_str`` (a 32-char
    value -> 12 words, anything else -> the default 24 words) so validation
    passes for valid inputs; an invalid input still hits the warning screen,
    which this driver tolerates.
    """
    if length_index is None:
        length_index = 1 if len(_normalise(hex_str)) == 32 else 0
    calls = {"n": 0}

    def _run_screen(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return 1            # source chooser -> Type hex
        if calls["n"] == 2:
            return length_index  # key-length chooser (0 -> 24 words, 1 -> 12)
        return 0                 # any later screen (e.g. the invalid-hex warning)

    view.run_screen = MagicMock(side_effect=_run_screen)
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

    def test_length_mismatch_is_rejected(self):
        # Choose 24 words (expects 64 hex) but type only 32 chars -> rejected,
        # so the chosen dimension can't be silently downgraded to a 12-word key.
        self.assertIsNone(_type_hex(_import_view(), "ab" * 16, length_index=0))

    def test_screen_is_sized_to_the_chosen_dimension(self):
        for length_index, expected in ((0, 64), (1, 32)):
            view = _import_view()
            calls = {"n": 0}

            def _run_screen(*a, **k):
                calls["n"] += 1
                return 1 if calls["n"] == 1 else length_index

            view.run_screen = MagicMock(side_effect=_run_screen)
            fake_screen = MagicMock()
            fake_screen.return_value.display.return_value = "0" * expected
            with patch(HEX_SCREEN, fake_screen):
                view._capture_via_hex()
            self.assertEqual(
                fake_screen.call_args.kwargs.get("num_chars"), expected,
                f"length_index {length_index} should size the keyboard to {expected} slots",
            )

    def test_back_out_of_length_chooser_returns_none(self):
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        view = _import_view()
        calls = {"n": 0}

        def _run_screen(*a, **k):
            calls["n"] += 1
            return 1 if calls["n"] == 1 else RET_CODE__BACK_BUTTON

        view.run_screen = MagicMock(side_effect=_run_screen)
        self.assertIsNone(view._capture_via_hex())


class TestGroupedHexEntryDisplay(unittest.TestCase):
    """The fixed-slot, blocks-of-8 hex display backing the Type-hex keyboard."""

    def _disp(self, num_slots=64):
        from PIL import Image
        from seedsigner.gui.keyboard import GroupedHexEntryDisplay
        canvas = Image.new("RGB", (240, 240))
        return GroupedHexEntryDisplay(
            num_slots=num_slots, canvas=canvas, rect=(8, 48, 232, 78),
            is_centered=False,
        )

    def test_empty_is_all_placeholders_in_blocks_of_8(self):
        display, cursor = self._disp(64)._compose("")
        self.assertEqual(cursor, 0)
        self.assertEqual(display.count(" "), 64 // 8 - 1)   # 7 group separators
        self.assertEqual(display.replace(" ", ""), "_" * 64)

    def test_partial_fills_left_to_right_with_grouping(self):
        display, cursor = self._disp(64)._compose("aabbccddeeff0011")  # 16 chars
        self.assertTrue(display.startswith("aabbccdd eeff0011 "))
        self.assertEqual(display.replace(" ", "").count("_"), 64 - 16)
        self.assertEqual(cursor, 16 + 2)  # two separators precede the 17th slot

    def test_full_buffer_has_no_placeholders_and_parks_cursor(self):
        display, cursor = self._disp(32)._compose("ab" * 16)  # 32 chars
        self.assertNotIn("_", display)
        self.assertEqual(cursor, len(display))
        self.assertEqual(display.count(" "), 32 // 8 - 1)   # 3 group separators

    def test_overlong_input_is_truncated_to_num_slots(self):
        display, _ = self._disp(32)._compose("ab" * 40)  # 80 chars
        self.assertEqual(display.replace(" ", ""), "ab" * 16)  # capped at 32

    def test_render_runs_without_error(self):
        for slots in (32, 64):
            disp = self._disp(slots)
            for text in ("", "aabb", "f" * slots):
                disp.render(text)  # must not raise


class TestFixedLengthFieldTopology(unittest.TestCase):
    def test_keyboard_screen_has_max_input_length(self):
        import dataclasses
        from seedsigner.gui.screens.screen import KeyboardScreen
        names = {f.name for f in dataclasses.fields(KeyboardScreen)}
        self.assertIn("max_input_length", names)

    def test_hex_entry_screen_has_num_chars(self):
        import dataclasses
        from seedsigner.gui.screens.screen import KeycardHexEntryScreen
        names = {f.name for f in dataclasses.fields(KeycardHexEntryScreen)}
        self.assertIn("num_chars", names)


class TestImportMenuOffersHex(unittest.TestCase):
    def test_hex_option_present(self):
        from seedsigner.views.keycard_views import ToolsKeycardImportSeedView
        self.assertEqual(
            ToolsKeycardImportSeedView.HEX.button_label, "Import hex (NGRAVE)",
        )


if __name__ == "__main__":
    unittest.main()
