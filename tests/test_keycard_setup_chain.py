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
    def _offer_view(self, run_screen_return, seedkeeper_installed):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperOfferView,
        )
        view = ToolsKeycardSeedkeeperOfferView.__new__(
            ToolsKeycardSeedkeeperOfferView,
        )
        view.run_screen = MagicMock(return_value=run_screen_return)
        view.controller = MagicMock()
        view.controller.pending_keycard_mnemonic = ["a", "b"]
        view.controller.pending_keycard_passphrase = bytearray(b"pp")
        fake_state = MagicMock()
        fake_state.seedkeeper_installed = seedkeeper_installed
        return view, fake_state

    def _run(self, view, fake_state):
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=fake_state,
        ), patch(
            "seedsigner.helpers.keycard.reader.release_other_smartcard_holders",
        ):
            return view.run()

    def test_skip_wipes_and_returns_to_menu(self):
        from seedsigner.views.keycard_views import ToolsKeycardMenuView
        view, fake_state = self._offer_view(1, True)  # NO
        dest = self._run(view, fake_state)
        self.assertIs(dest.View_cls, ToolsKeycardMenuView)
        self.assertIsNone(view.controller.pending_keycard_mnemonic)
        self.assertIsNone(view.controller.pending_keycard_passphrase)

    def test_save_same_card_routes_to_dest_chooser(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperDestChooserView,
        )
        view, fake_state = self._offer_view(0, True)  # YES, co-resident
        dest = self._run(view, fake_state)
        self.assertIs(dest.View_cls, ToolsKeycardSeedkeeperDestChooserView)
        # Mnemonic must still be live; we'll need it for the save.
        self.assertEqual(view.controller.pending_keycard_mnemonic, ["a", "b"])

    def test_save_without_co_resident_also_routes_to_dest_chooser(self):
        """The Offer no longer probes — it always hands off to the
        destination chooser, which decides what to probe / install."""
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperDestChooserView,
        )
        view, fake_state = self._offer_view(0, False)  # YES, none co-resident
        dest = self._run(view, fake_state)
        self.assertIs(dest.View_cls, ToolsKeycardSeedkeeperDestChooserView)
        self.assertEqual(view.controller.pending_keycard_mnemonic, ["a", "b"])


class TestSeedkeeperDestChooser(unittest.TestCase):
    def _view(self, run_screen_return):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperDestChooserView,
        )
        view = ToolsKeycardSeedkeeperDestChooserView.__new__(
            ToolsKeycardSeedkeeperDestChooserView,
        )
        view.run_screen = MagicMock(return_value=run_screen_return)
        view.controller = MagicMock()
        view.controller.pending_keycard_mnemonic = ["a"]
        view.controller.pending_keycard_passphrase = bytearray(b"p")
        return view

    def test_this_card_routes_to_this_card_view(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperThisCardView,
        )
        dest = self._view(0).run()
        self.assertIs(dest.View_cls, ToolsKeycardSeedkeeperThisCardView)
        self.assertEqual(dest.view_args["remaining"], [])

    def test_other_card_routes_to_swap(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperSwapInsertView,
        )
        dest = self._view(1).run()
        self.assertIs(dest.View_cls, ToolsKeycardSeedkeeperSwapInsertView)

    def test_both_routes_to_this_card_with_remaining(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperThisCardView,
        )
        dest = self._view(2).run()
        self.assertIs(dest.View_cls, ToolsKeycardSeedkeeperThisCardView)
        self.assertEqual(dest.view_args["remaining"], ["other"])

    def test_back_wipes_and_returns_to_menu(self):
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        from seedsigner.views.keycard_views import ToolsKeycardMenuView
        view = self._view(RET_CODE__BACK_BUTTON)
        dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardMenuView)
        self.assertIsNone(view.controller.pending_keycard_mnemonic)


class TestSeedkeeperSwapInsert(unittest.TestCase):
    def _view(self, *, run_screen):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperSwapInsertView,
        )
        view = ToolsKeycardSeedkeeperSwapInsertView.__new__(
            ToolsKeycardSeedkeeperSwapInsertView,
        )
        view.run_screen = run_screen
        view.controller = MagicMock()
        view.controller.pending_keycard_mnemonic = ["a"]
        view.controller.pending_keycard_passphrase = bytearray(b"p")
        return view

    def _run(self, view, seedkeeper_installed):
        fake_state = MagicMock()
        fake_state.seedkeeper_installed = seedkeeper_installed
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=fake_state,
        ), patch(
            "seedsigner.helpers.keycard.reader.release_other_smartcard_holders",
        ):
            return view.run()

    def test_seedkeeper_found_routes_to_save(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperSaveRunView,
        )
        view = self._view(run_screen=MagicMock(return_value=0))  # Continue
        dest = self._run(view, seedkeeper_installed=True)
        self.assertIs(dest.View_cls, ToolsKeycardSeedkeeperSaveRunView)
        self.assertEqual(view.controller.pending_keycard_mnemonic, ["a"])

    def test_continue_back_wipes_and_returns_to_menu(self):
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        from seedsigner.views.keycard_views import ToolsKeycardMenuView
        view = self._view(run_screen=MagicMock(return_value=RET_CODE__BACK_BUTTON))
        dest = self._run(view, seedkeeper_installed=True)
        self.assertIs(dest.View_cls, ToolsKeycardMenuView)
        self.assertIsNone(view.controller.pending_keycard_mnemonic)

    def test_no_card_then_cancel_wipes(self):
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        from seedsigner.views.keycard_views import ToolsKeycardMenuView
        # First screen: Continue (0); retry screen: Back.
        view = self._view(
            run_screen=MagicMock(side_effect=[0, RET_CODE__BACK_BUTTON]),
        )
        dest = self._run(view, seedkeeper_installed=False)
        self.assertIs(dest.View_cls, ToolsKeycardMenuView)
        self.assertIsNone(view.controller.pending_keycard_mnemonic)


class TestSeedkeeperThisCard(unittest.TestCase):
    """Change 4: 'This card' probes, offers to install Seedkeeper when
    missing, and threads `remaining` to the format step."""

    def _view(self, *, run_screen, remaining=None):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperThisCardView,
        )
        view = ToolsKeycardSeedkeeperThisCardView.__new__(
            ToolsKeycardSeedkeeperThisCardView,
        )
        view.run_screen = run_screen
        view.remaining = remaining or []
        view.controller = MagicMock()
        view.controller.pending_keycard_mnemonic = ["a"]
        view.controller.pending_keycard_passphrase = bytearray(b"p")
        return view

    def _probe(self, seedkeeper_installed):
        fake_state = MagicMock()
        fake_state.seedkeeper_installed = seedkeeper_installed
        return patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=fake_state,
        ), patch(
            "seedsigner.helpers.keycard.reader.release_other_smartcard_holders",
        )

    def test_present_routes_to_save(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperSaveRunView,
        )
        view = self._view(run_screen=MagicMock(), remaining=["other"])
        p1, p2 = self._probe(True)
        with p1, p2:
            dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardSeedkeeperSaveRunView)
        self.assertEqual(dest.view_args["remaining"], ["other"])
        self.assertEqual(view.controller.pending_keycard_mnemonic, ["a"])

    def test_absent_install_ok_routes_to_save(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperSaveRunView,
        )
        # No applet → "No Seedkeeper applet" screen; user picks Install (0).
        view = self._view(run_screen=MagicMock(return_value=0))
        p1, p2 = self._probe(False)
        with p1, p2, patch(
            "seedsigner.views.view.install_seedkeeper_applet", return_value=None,
        ):
            dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardSeedkeeperSaveRunView)
        self.assertEqual(view.controller.pending_keycard_mnemonic, ["a"])

    def test_absent_cancel_wipes_and_returns_to_menu(self):
        from seedsigner.views.keycard_views import ToolsKeycardMenuView
        # No applet → user picks Cancel (1).
        view = self._view(run_screen=MagicMock(return_value=1))
        p1, p2 = self._probe(False)
        with p1, p2:
            dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardMenuView)
        self.assertIsNone(view.controller.pending_keycard_mnemonic)


class TestSeedkeeperSaveRun(unittest.TestCase):
    """Change 5 (keep seed on error) + Change 4 (Both sequencing)."""

    def _view(self, *, remaining=None, run_screen=None):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperSaveRunView,
        )
        view = ToolsKeycardSeedkeeperSaveRunView.__new__(
            ToolsKeycardSeedkeeperSaveRunView,
        )
        view.remaining = remaining or []
        view.run_screen = run_screen or MagicMock(return_value=0)
        view.controller = MagicMock()
        view.controller.pending_keycard_mnemonic = ["a", "b"]
        view.controller.pending_keycard_passphrase = bytearray(b"")
        return view

    def _patch_label(self):
        fake_screen = MagicMock()
        fake_screen.display.return_value = {"passphrase": "lbl"}
        return patch(
            "seedsigner.gui.screens.seed_screens.SeedAddPassphraseScreen",
            return_value=fake_screen,
        )

    def test_init_satochip_none_keeps_seed_and_returns_to_chooser(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperDestChooserView,
        )
        view = self._view()
        with self._patch_label(), patch(
            "seedsigner.helpers.seedkeeper_utils.init_satochip", return_value=None,
        ):
            dest = view.run()
        # Seed NOT wiped — the user can retry / pick another destination.
        self.assertIs(dest.View_cls, ToolsKeycardSeedkeeperDestChooserView)
        self.assertEqual(view.controller.pending_keycard_mnemonic, ["a", "b"])

    def test_save_error_keeps_seed_and_offers_retry(self):
        view = self._view()
        with self._patch_label(), patch(
            "seedsigner.helpers.seedkeeper_utils.init_satochip",
            return_value=MagicMock(),
        ), patch(
            "seedsigner.helpers.seedkeeper_utils.ensure_seedkeeper_capacity",
            side_effect=RuntimeError("boom"),
        ):
            dest = view.run()
        # _backup_error_retry shows a Retry screen (run_screen returns 0 =
        # Retry) and routes back to the destination chooser; seed preserved.
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperDestChooserView,
        )
        self.assertIs(dest.View_cls, ToolsKeycardSeedkeeperDestChooserView)
        self.assertEqual(view.controller.pending_keycard_mnemonic, ["a", "b"])

    def test_both_success_routes_to_swap_without_wipe(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperSwapInsertView,
        )
        view = self._view(remaining=["other"])
        with self._patch_label(), patch(
            "seedsigner.helpers.seedkeeper_utils.init_satochip",
            return_value=MagicMock(),
        ), patch(
            "seedsigner.helpers.seedkeeper_utils.ensure_seedkeeper_capacity",
            return_value=(True, 10, 1000),
        ), patch(
            "seedsigner.gui.screens.screen.LoadingScreenThread",
            return_value=MagicMock(),
        ), patch(
            "seedsigner.helpers.keycard.reader.release_other_smartcard_holders",
        ) as mock_release:
            dest = view.run()
        # First leg saved; seed kept for the second card.
        self.assertIs(dest.View_cls, ToolsKeycardSeedkeeperSwapInsertView)
        self.assertEqual(view.controller.pending_keycard_mnemonic, ["a", "b"])
        # The first save's pysatochip connector is torn down (its CardMonitor
        # observer removed) while card 1 is still inserted, BEFORE prompting the
        # swap — otherwise the stale observer reconnects to card 2 in the
        # background and starves the 2nd save ("Unable to find seedkeeper").
        mock_release.assert_called_once_with(view.controller)

    def test_single_success_wipes_and_returns_to_menu(self):
        from seedsigner.views.keycard_views import ToolsKeycardMenuView
        view = self._view(remaining=[])
        with self._patch_label(), patch(
            "seedsigner.helpers.seedkeeper_utils.init_satochip",
            return_value=MagicMock(),
        ), patch(
            "seedsigner.helpers.seedkeeper_utils.ensure_seedkeeper_capacity",
            return_value=(True, 10, 1000),
        ), patch(
            "seedsigner.gui.screens.screen.LoadingScreenThread",
            return_value=MagicMock(),
        ):
            dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardMenuView)
        self.assertIsNone(view.controller.pending_keycard_mnemonic)


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


class TestSetupEntriesReachableAfterReorg(unittest.TestCase):
    """The destructive lifecycle ops (``Generate key`` / ``Import seed`` /
    ``Initialise instance`` / ``Factory reset``) now live under a dedicated
    ``Set up / reset`` submenu, one level below ``This instance``. This pins
    that ``This instance`` exposes that submenu and every Setup step is still
    reachable through it so users can re-run each individually."""

    def test_this_instance_exposes_setup_reset_submenu(self):
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardSetupResetMenuView,
            ToolsKeycardThisInstanceMenuView,
        )
        # Rename hidden → Change PIN (0), Unblock PIN (1), Lock (2),
        # Set up / reset (3 — last).
        with patch.object(keycard_views, "_instance_rename_available", return_value=False):
            view = _make_view(ToolsKeycardThisInstanceMenuView, run_screen_returns=3)
            dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardSetupResetMenuView)

    def test_setup_steps_reachable_from_submenu(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardGenerateKeyView,
            ToolsKeycardImportSeedView,
            ToolsKeycardInitView,
            ToolsKeycardFactoryResetView,
            ToolsKeycardSetupResetMenuView,
        )
        # Set up / reset submenu: Generate (0), Import (1), Init (2),
        # Factory reset (3).
        expected = {
            0: ToolsKeycardGenerateKeyView,
            1: ToolsKeycardImportSeedView,
            2: ToolsKeycardInitView,
            3: ToolsKeycardFactoryResetView,
        }
        for i, view_cls in expected.items():
            view = _make_view(
                ToolsKeycardSetupResetMenuView, run_screen_returns=i,
            )
            dest = view.run()
            self.assertIs(dest.View_cls, view_cls)


if __name__ == "__main__":
    unittest.main()
