"""Regression cover for the in-RAM secret-wipe hardening.

The seed import / generate / backup flows wipe their byte buffers and word
lists, but the *joined* plaintext mnemonic string and the *decoded*
passphrase string each hold the whole secret in one immutable allocation.
These tests assert that every such flow routes those two locals through
``wipe_string`` on exit (including early/error exits), and that doing so
never corrupts the shared global BIP-39 wordlist.

The wipe itself is best-effort (CPython GC); we test the *wiring* — that the
finally calls wipe_string with the right plaintext — not the memory effect.
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

MNEMONIC = ["abandon"] * 11 + ["about"]
MNEMONIC_STR = " ".join(MNEMONIC)
PASSPHRASE = "trezor"


def _new(view_cls):
    return view_cls.__new__(view_cls)


class TestImportSeedkeeperPushViewWipes(unittest.TestCase):
    """``ToolsKeycardImportSeedkeeperPushView`` — back-out at confirm."""

    def test_back_at_confirm_wipes_joined_mnemonic_and_passphrase(self):
        import seedsigner.views.keycard_views as kv
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON

        controller = MagicMock()
        controller.pending_keycard_mnemonic = list(MNEMONIC)
        controller.pending_keycard_passphrase = bytearray(PASSPHRASE.encode())

        view = _new(kv.ToolsKeycardImportSeedkeeperPushView)
        view.controller = controller
        view.run_screen = MagicMock(return_value=RET_CODE__BACK_BUTTON)

        wiped: list = []
        with patch.object(kv, "wipe_string", side_effect=wiped.append), \
             patch.object(kv, "_wipe_pending_setup_state", MagicMock()):
            view.run()

        self.assertIn(MNEMONIC_STR, wiped)
        self.assertIn(PASSPHRASE, wiped)


class TestGenerateSeedLoadViewWipes(unittest.TestCase):
    """``ToolsKeycardGenerateSeedLoadView`` — PIN cancelled at LOAD_KEY."""

    def test_pin_cancel_wipes_joined_mnemonic_and_passphrase(self):
        import seedsigner.views.keycard_views as kv
        from seedsigner.helpers.keycard import KeycardPinPromptCancelled

        controller = MagicMock()
        controller.pending_keycard_mnemonic = list(MNEMONIC)
        controller.pending_keycard_passphrase = bytearray(PASSPHRASE.encode())

        view = _new(kv.ToolsKeycardGenerateSeedLoadView)
        view.controller = controller

        wiped: list = []
        with patch.object(kv, "wipe_string", side_effect=wiped.append), \
             patch.object(kv, "_wipe_pending_setup_state", MagicMock()), \
             patch.object(
                 kv, "_open_unlocked_session_cached_or_prompt",
                 side_effect=KeycardPinPromptCancelled(),
             ):
            view.run()

        self.assertIn(MNEMONIC_STR, wiped)
        self.assertIn(PASSPHRASE, wiped)


class TestSeedkeeperSaveRunViewWipes(unittest.TestCase):
    """``ToolsKeycardSeedkeeperSaveRunView`` — back-out at the label screen."""

    def test_back_at_label_wipes_joined_mnemonic_and_passphrase(self):
        import seedsigner.views.keycard_views as kv

        controller = MagicMock()
        controller.pending_keycard_mnemonic = list(MNEMONIC)
        controller.pending_keycard_passphrase = bytearray(PASSPHRASE.encode())

        view = _new(kv.ToolsKeycardSeedkeeperSaveRunView)
        view.controller = controller
        view.remaining = []

        fake_label = MagicMock()
        fake_label.return_value.display.return_value = {"is_back_button": True}

        wiped: list = []
        with patch.object(kv, "wipe_string", side_effect=wiped.append), \
             patch(
                 "seedsigner.gui.screens.seed_screens.SeedAddPassphraseScreen",
                 fake_label,
             ):
            view.run()

        self.assertIn(MNEMONIC_STR, wiped)
        self.assertIn(PASSPHRASE, wiped)


class TestWipesLeaveWordlistIntact(unittest.TestCase):
    """A real (un-mocked) wipe of the joined strings must not touch the
    global BIP-39 wordlist — the joined mnemonic is a fresh allocation, not
    a list of wordlist references (CLAUDE.md secure-wipe rule)."""

    def test_real_wipe_keeps_bip39_wordlist_intact(self):
        import seedsigner.views.keycard_views as kv
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        from embit import bip39

        controller = MagicMock()
        # Use independent "".join copies as the real flow does.
        controller.pending_keycard_mnemonic = ["".join(w) for w in MNEMONIC]
        controller.pending_keycard_passphrase = bytearray(PASSPHRASE.encode())

        view = _new(kv.ToolsKeycardImportSeedkeeperPushView)
        view.controller = controller
        view.run_screen = MagicMock(return_value=RET_CODE__BACK_BUTTON)

        with patch.object(kv, "_wipe_pending_setup_state", MagicMock()):
            view.run()  # real wipe_string runs in the finally

        self.assertEqual(bip39.WORDLIST[0], "abandon")
        self.assertEqual(bip39.WORDLIST[3], "about")
        # The word we round-tripped must still match by value.
        self.assertIn("about", bip39.WORDLIST)


if __name__ == "__main__":
    unittest.main()
