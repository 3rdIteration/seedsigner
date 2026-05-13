"""Setup-chain routing + state-wipe tests.

Covers the post-Init chooser, the new on-card Generate flow, the
optional Seedkeeper offer, and the Import-success hand-off into the
same offer. The actual card APDU layer is stubbed; we exercise routing
and the controller-state invariants so a future regression that leaks
the mnemonic past LOAD_KEY or skips the wipe is caught here.
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


def _make_view(view_cls, *, run_screen_returns):
    """Construct a View bypassing the singleton-dependent __init__."""
    view = view_cls.__new__(view_cls)
    view.run_screen = MagicMock(return_value=run_screen_returns)
    view.controller = MagicMock()
    # Default: no pending state.
    view.controller.pending_keycard_mnemonic = None
    view.controller.pending_keycard_passphrase = None
    return view


class TestSetupChooserRouting(unittest.TestCase):
    def test_routes_to_generate(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardGenerateKeyView,
            ToolsKeycardSetupChooseSeedView,
        )
        view = _make_view(ToolsKeycardSetupChooseSeedView, run_screen_returns=0)
        dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardGenerateKeyView)

    def test_routes_to_import(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardImportSeedView,
            ToolsKeycardSetupChooseSeedView,
        )
        view = _make_view(ToolsKeycardSetupChooseSeedView, run_screen_returns=1)
        dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardImportSeedView)


class TestLengthChooser(unittest.TestCase):
    def test_12_words_p1_is_4(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardGenerateMnemonicLengthView,
            ToolsKeycardGenerateMnemonicRunView,
        )
        view = _make_view(
            ToolsKeycardGenerateMnemonicLengthView, run_screen_returns=0,
        )
        dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardGenerateMnemonicRunView)
        self.assertEqual(dest.view_args["word_count"], 12)

    def test_24_words(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardGenerateMnemonicLengthView,
            ToolsKeycardGenerateMnemonicRunView,
        )
        view = _make_view(
            ToolsKeycardGenerateMnemonicLengthView, run_screen_returns=1,
        )
        dest = view.run()
        self.assertEqual(dest.view_args["word_count"], 24)


class TestGenerateRunView(unittest.TestCase):
    def test_stashes_safe_word_copies(self):
        """Each stashed word must be ``"".join(WORDLIST[i])`` so a later
        wipe cannot corrupt the global wordlist."""
        from embit import bip39

        from seedsigner.views.keycard_views import (
            ToolsKeycardGenerateMnemonicRunView,
            ToolsKeycardGenerateSeedWordsView,
        )

        indices = [0, 5, 17, 42, 100, 2047, 1, 2, 3, 4, 6, 7]
        view = ToolsKeycardGenerateMnemonicRunView.__new__(
            ToolsKeycardGenerateMnemonicRunView,
        )
        view.word_count = 12
        view.controller = MagicMock()
        view.controller.pending_keycard_mnemonic = None
        view.controller.pending_keycard_passphrase = None

        fake_client = MagicMock()
        fake_client.generate_mnemonic.return_value = indices

        with patch(
            "seedsigner.views.keycard_views."
            "_open_unlocked_session_cached_or_prompt",
            return_value=(fake_client, MagicMock()),
        ):
            dest = view.run()

        self.assertIs(dest.View_cls, ToolsKeycardGenerateSeedWordsView)
        stashed = view.controller.pending_keycard_mnemonic
        self.assertEqual(len(stashed), 12)
        # Each stashed word must equal the canonical wordlist entry...
        for idx, word in zip(indices, stashed):
            self.assertEqual(word, bip39.WORDLIST[idx])
        # ...but must be an INDEPENDENT object so wipes don't reach
        # WORDLIST. Identity check is the strongest signal.
        for idx, word in zip(indices, stashed):
            self.assertIsNot(word, bip39.WORDLIST[idx])


class TestSkipPassphrasePath(unittest.TestCase):
    def test_backup_prompt_skip_jumps_to_passphrase(self):
        """Skip on the backup prompt MUST land on the passphrase
        prompt, NOT re-display the words."""
        from seedsigner.views.keycard_views import (
            ToolsKeycardGenerateSeedBackupPromptView,
            ToolsKeycardGenerateSeedPassphrasePromptView,
        )

        view = ToolsKeycardGenerateSeedBackupPromptView.__new__(
            ToolsKeycardGenerateSeedBackupPromptView,
        )
        view.controller = MagicMock()
        # Patch the SeedWordsBackupTestPromptScreen since it touches
        # the GUI; we just need the return value.
        with patch(
            "seedsigner.gui.screens.seed_screens."
            "SeedWordsBackupTestPromptScreen",
        ) as MockScreen:
            MockScreen.return_value.display.return_value = 1  # SKIP
            dest = view.run()
        self.assertIs(
            dest.View_cls, ToolsKeycardGenerateSeedPassphrasePromptView,
        )


class TestPassphrasePromptNoPassphrase(unittest.TestCase):
    def test_no_passphrase_stores_empty_bytearray(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardGenerateSeedLoadView,
            ToolsKeycardGenerateSeedPassphrasePromptView,
        )
        view = _make_view(
            ToolsKeycardGenerateSeedPassphrasePromptView, run_screen_returns=0,
        )
        dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardGenerateSeedLoadView)
        # bytearray() truthiness is False, but ``is None`` must be False:
        # the load view distinguishes "user explicitly skipped" from
        # "state cleared" via ``is None``.
        self.assertIsNotNone(view.controller.pending_keycard_passphrase)
        self.assertEqual(view.controller.pending_keycard_passphrase, bytearray())


class TestSeedkeeperOffer(unittest.TestCase):
    def test_absent_seedkeeper_skips_to_menu_and_wipes(self):
        """If no Seedkeeper applet is present we must NOT prompt; the
        mnemonic gets wiped on the way out."""
        from seedsigner.views.keycard_views import (
            ToolsKeycardMenuView,
            ToolsKeycardSeedkeeperOfferView,
        )

        view = ToolsKeycardSeedkeeperOfferView.__new__(
            ToolsKeycardSeedkeeperOfferView,
        )
        view.run_screen = MagicMock()
        view.controller = MagicMock()
        view.controller.pending_keycard_mnemonic = ["alpha", "bravo"]
        view.controller.pending_keycard_passphrase = bytearray(b"pp")

        fake_state = MagicMock()
        fake_state.seedkeeper_installed = False

        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=fake_state,
        ), patch(
            "seedsigner.helpers.keycard.reader.release_other_smartcard_holders",
        ):
            dest = view.run()

        self.assertIs(dest.View_cls, ToolsKeycardMenuView)
        self.assertIsNone(view.controller.pending_keycard_mnemonic)
        self.assertIsNone(view.controller.pending_keycard_passphrase)
        # No screen prompt should have been shown.
        view.run_screen.assert_not_called()

    def test_present_seedkeeper_prompts_user(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperFormatChooserView,
            ToolsKeycardSeedkeeperOfferView,
        )

        view = ToolsKeycardSeedkeeperOfferView.__new__(
            ToolsKeycardSeedkeeperOfferView,
        )
        view.run_screen = MagicMock(return_value=0)  # YES
        view.controller = MagicMock()
        view.controller.pending_keycard_mnemonic = ["a", "b"]
        view.controller.pending_keycard_passphrase = bytearray()

        fake_state = MagicMock()
        fake_state.seedkeeper_installed = True

        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=fake_state,
        ), patch(
            "seedsigner.helpers.keycard.reader.release_other_smartcard_holders",
        ):
            dest = view.run()

        self.assertIs(
            dest.View_cls, ToolsKeycardSeedkeeperFormatChooserView,
        )
        # Mnemonic must still be live; we'll need it for the save.
        self.assertEqual(
            view.controller.pending_keycard_mnemonic, ["a", "b"],
        )

    def test_present_seedkeeper_user_declines_wipes_and_returns(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardMenuView,
            ToolsKeycardSeedkeeperOfferView,
        )

        view = ToolsKeycardSeedkeeperOfferView.__new__(
            ToolsKeycardSeedkeeperOfferView,
        )
        view.run_screen = MagicMock(return_value=1)  # NO
        view.controller = MagicMock()
        view.controller.pending_keycard_mnemonic = ["a", "b"]
        view.controller.pending_keycard_passphrase = bytearray(b"x")

        fake_state = MagicMock()
        fake_state.seedkeeper_installed = True

        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=fake_state,
        ), patch(
            "seedsigner.helpers.keycard.reader.release_other_smartcard_holders",
        ):
            dest = view.run()

        self.assertIs(dest.View_cls, ToolsKeycardMenuView)
        self.assertIsNone(view.controller.pending_keycard_mnemonic)
        self.assertIsNone(view.controller.pending_keycard_passphrase)


class TestFormatChooser(unittest.TestCase):
    def test_picks_bip39(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperFormatChooserView,
            ToolsKeycardSeedkeeperSaveRunView,
        )
        view = _make_view(
            ToolsKeycardSeedkeeperFormatChooserView, run_screen_returns=0,
        )
        dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardSeedkeeperSaveRunView)
        self.assertEqual(dest.view_args["secret_type"], "bip39")

    def test_picks_password(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperFormatChooserView,
            ToolsKeycardSeedkeeperSaveRunView,
        )
        view = _make_view(
            ToolsKeycardSeedkeeperFormatChooserView, run_screen_returns=1,
        )
        dest = view.run()
        self.assertEqual(dest.view_args["secret_type"], "password")


class TestInitTailRoutesToChooser(unittest.TestCase):
    """The Init view must hand off to the new Setup chooser on success."""

    def test_init_success_routes_to_chooser(self):
        import re

        path = os.path.join(
            SRC_ROOT, "seedsigner", "views", "keycard_views.py",
        )
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        # We're looking for the Init success-tail destination — must
        # name the new chooser, not the old menu.
        self.assertIn(
            "Destination(\n                ToolsKeycardSetupChooseSeedView",
            source,
            "ToolsKeycardInitView success tail should route to the new "
            "Setup chooser (post-init guided flow).",
        )
        # Also assert the old "Pair, then Generate key." message is gone.
        self.assertNotIn(
            "Pair, then Generate key.",
            source,
            "Old post-init instruction copy still present; "
            "did you forget to update the success message?",
        )


class TestSetupMenuStillIntact(unittest.TestCase):
    """Per plan, the standalone Setup-menu entries stay where they are
    so users can re-run each step individually."""

    def test_setup_menu_routes(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardGenerateKeyView,
            ToolsKeycardImportSeedView,
            ToolsKeycardInitView,
            ToolsKeycardSetupMenuView,
        )
        expected = [
            ToolsKeycardInitView,
            ToolsKeycardGenerateKeyView,
            ToolsKeycardImportSeedView,
        ]
        for i, view_cls in enumerate(expected):
            view = _make_view(
                ToolsKeycardSetupMenuView, run_screen_returns=i,
            )
            dest = view.run()
            self.assertIs(dest.View_cls, view_cls)


if __name__ == "__main__":
    unittest.main()
