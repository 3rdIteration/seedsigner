"""Regression cover for pairing the card *before* the seed is collected.

The first Keycard session-op after a boot has no cached pairing, so the import
push's ``open_unlocked_session`` raised ``KeycardCardChangedError`` and bounced to
``ToolsKeycardPairView`` with **no resume** — it silently paired the card but then
re-ran ``ToolsKeycardImportSeedView`` from the top, discarding the just-typed seed
and leaving the card empty (the recurring "import doesn't save on the first try"
bug; the second attempt succeeded only because the first one cached the pairing).

``_ensure_card_paired`` now pairs up front, before any seed is collected, so the
later push finds the cached secret and succeeds on the first attempt. These tests
cover: an unpaired card routes to a pair-*then-resume* detour; an already-paired
card (ephemeral or persistent) skips it; a probe failure is advisory (continue);
``run()`` short-circuits to the detour without opening a session; and the happy
path loads the seed once and hands off to the backup offer.
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

# Canonical all-zeros-entropy 12-word mnemonic — a valid BIP-39 checksum.
MNEMONIC = ["abandon"] * 11 + ["about"]

_PROBE = "seedsigner.helpers.keycard.ui_helpers.identify_inserted_card"


def _new(view_cls):
    return view_cls.__new__(view_cls)


def _make_run_screen(words, word_calls):
    """``run_screen`` side_effect driving the import flow to a clean push.

    Words are fed one-per-call to the word-entry screen (recorded in
    ``word_calls`` so a re-type would show up as a doubled count); every other
    screen proceeds with its first option.
    """
    word_iter = iter(words)

    def dispatch(screen_cls, *args, **kwargs):
        name = getattr(screen_cls, "__name__", "")
        if name == "SeedMnemonicEntryScreen":
            word_calls.append(kwargs.get("title"))
            return next(word_iter)
        return 0

    return dispatch


def _build_import_view():
    import seedsigner.views.keycard_views as kv

    controller = MagicMock()
    controller.pending_keycard_mnemonic = None
    controller.pending_keycard_passphrase = None

    view = _new(kv.ToolsKeycardImportSeedView)
    view.controller = controller
    return kv, view, controller


class TestEnsureCardPaired(unittest.TestCase):
    """Unit cover for the ``_ensure_card_paired`` pre-pairing guard."""

    def _view(self):
        import seedsigner.views.keycard_views as kv
        view = _new(kv.ToolsKeycardImportSeedView)
        view.controller = MagicMock()
        return kv, view

    def test_unpaired_routes_to_pair_then_resume(self):
        kv, view = self._view()
        view.controller.get_ephemeral_secret_for.return_value = None
        view.controller.get_pairing_for.return_value = None

        with patch(_PROBE, return_value=(MagicMock(), b"\x01" * 16)):
            dest = kv._ensure_card_paired(view)

        self.assertIsNotNone(dest)
        # Routes through the pair view…
        self.assertIs(dest.View_cls, kv.ToolsKeycardPairView)
        # …carrying a resume target back to THIS view (so the user types once).
        resume = (dest.view_args or {}).get("next_destination")
        self.assertIsNotNone(resume)
        self.assertIs(resume.View_cls, kv.ToolsKeycardImportSeedView)

    def test_already_paired_ephemeral_skips_detour(self):
        kv, view = self._view()
        view.controller.get_ephemeral_secret_for.return_value = b"\xaa" * 32
        view.controller.get_pairing_for.return_value = None

        with patch(_PROBE, return_value=(MagicMock(), b"\x01" * 16)):
            dest = kv._ensure_card_paired(view)

        self.assertIsNone(dest)

    def test_already_paired_persistent_skips_detour(self):
        kv, view = self._view()
        view.controller.get_ephemeral_secret_for.return_value = None
        view.controller.get_pairing_for.return_value = object()  # cached PairingInfo

        with patch(_PROBE, return_value=(MagicMock(), b"\x01" * 16)):
            dest = kv._ensure_card_paired(view)

        self.assertIsNone(dest)

    def test_probe_failure_is_advisory(self):
        kv, view = self._view()

        with patch(_PROBE, side_effect=RuntimeError("no card")):
            dest = kv._ensure_card_paired(view)

        # Advisory: any probe failure continues the flow (None); the push step
        # surfaces the real card error downstream.
        self.assertIsNone(dest)


class TestImportRunPairingGate(unittest.TestCase):
    def test_run_routes_to_pair_when_unpaired_without_session(self):
        kv, view, controller = _build_import_view()
        from seedsigner.views.view import Destination

        view.run_screen = MagicMock()
        pair_dest = Destination(kv.ToolsKeycardPairView)
        session = MagicMock()

        with patch.object(kv, "_redirect_if_uninitialised", return_value=None), \
             patch.object(kv, "_ensure_card_paired", return_value=pair_dest), \
             patch.object(kv, "_open_unlocked_session_cached_or_prompt", session):
            dest = view.run()

        # The pairing detour short-circuits run() before any seed is collected.
        self.assertIs(dest, pair_dest)
        session.assert_not_called()
        view.run_screen.assert_not_called()

    def test_happy_path_first_try_loads_and_offers_backup(self):
        """Closes the missing happy-path coverage: a paired card loads on the
        first push and hands off to the SeedKeeper backup offer."""
        kv, view, controller = _build_import_view()

        word_calls: list = []
        view.run_screen = MagicMock(
            side_effect=_make_run_screen(MNEMONIC, word_calls),
        )

        client = MagicMock()
        session = MagicMock(return_value=(client, None))  # succeeds first try

        with patch.object(kv, "_redirect_if_uninitialised", return_value=None), \
             patch.object(kv, "_ensure_card_paired", return_value=None), \
             patch.object(kv, "_instance_key_present", return_value=False), \
             patch.object(kv, "_open_unlocked_session_cached_or_prompt", session), \
             patch.object(kv, "_invalidate_wallets_cache_for_active_aid", MagicMock()):
            dest = view.run()

        self.assertIs(dest.View_cls, kv.ToolsKeycardSeedkeeperOfferView)
        session.assert_called_once()              # no retry — first try worked
        client.load_bip39_seed.assert_called_once()
        self.assertEqual(len(word_calls), 12)     # typed exactly once
        self.assertEqual(controller.pending_keycard_mnemonic, MNEMONIC)


if __name__ == "__main__":
    unittest.main()
