"""Regression cover for the import-seed push *retry without re-typing*.

``ToolsKeycardImportSeedView`` used to discard every typed word when the final
LOAD_KEY push hit a transient card error (e.g. a secure-channel break or a
PIN/VERIFY hiccup): the error returned a ``Destination`` and the ``finally``
wiped the local ``words`` list, forcing the user to re-type the whole mnemonic.

The push step now loops: a transient error shows a Retry/Cancel screen and, on
Retry, re-opens a fresh session and re-sends LOAD_KEY reusing the already
derived ``seed64`` — never bouncing the user back to word entry. These tests
drive the full ``run()`` and assert the words are captured exactly once across
a failed-then-succeeding push, and that Cancel exits cleanly.
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


def _new(view_cls):
    return view_cls.__new__(view_cls)


def _make_run_screen(words, word_calls, retry_back=False):
    """Build a ``run_screen`` side_effect driving the import flow.

    ``words`` are fed one-per-call to the word-entry screen; ``word_calls`` is a
    list the dispatcher appends to on every word-entry call so the test can
    assert the words were captured exactly once. When ``retry_back`` is True the
    Retry screen returns BACK (Cancel) instead of proceeding.
    """
    from seedsigner.gui.screens import RET_CODE__BACK_BUTTON

    word_iter = iter(words)

    def dispatch(screen_cls, *args, **kwargs):
        name = getattr(screen_cls, "__name__", "")
        if name == "SeedMnemonicEntryScreen":
            word_calls.append(kwargs.get("title"))
            return next(word_iter)
        # The retry screen is the only WarningScreen whose single button is
        # labelled "Retry"; the "Push?" confirm uses "Push to card".
        button_data = kwargs.get("button_data") or []
        if button_data and getattr(button_data[0], "button_label", None) == "Retry":
            return RET_CODE__BACK_BUTTON if retry_back else 0
        # Every other screen (warn / Source / length / Passphrase? / Push? /
        # success OK) proceeds with its first option.
        return 0

    return dispatch


def _build_view():
    import seedsigner.views.keycard_views as kv

    controller = MagicMock()
    controller.pending_keycard_mnemonic = None
    controller.pending_keycard_passphrase = None

    view = _new(kv.ToolsKeycardImportSeedView)
    view.controller = controller
    return kv, view, controller


class TestImportSeedPushRetry(unittest.TestCase):
    def test_transient_error_then_retry_keeps_words(self):
        kv, view, controller = _build_view()
        from seedsigner.views.view import BackStackView  # noqa: F401

        word_calls: list = []
        view.run_screen = MagicMock(
            side_effect=_make_run_screen(MNEMONIC, word_calls),
        )

        client = MagicMock()
        session = MagicMock(
            side_effect=[RuntimeError("secure channel broke"), (client, None)],
        )

        with patch.object(kv, "_redirect_if_uninitialised", return_value=None), \
             patch.object(kv, "_instance_key_present", return_value=False), \
             patch.object(kv, "_open_unlocked_session_cached_or_prompt", session), \
             patch.object(kv, "_invalidate_wallets_cache_for_active_aid", MagicMock()):
            dest = view.run()

        # Succeeded on the 2nd push attempt and handed off to the backup offer.
        self.assertIs(dest.View_cls, kv.ToolsKeycardSeedkeeperOfferView)
        self.assertEqual(session.call_count, 2)
        client.load_bip39_seed.assert_called_once()
        # Words were captured exactly once (12 entries) — NOT re-typed (would be 24).
        self.assertEqual(len(word_calls), 12)
        # The validated mnemonic was stashed for the backup-offer chain.
        self.assertEqual(controller.pending_keycard_mnemonic, MNEMONIC)

    def test_cancel_on_retry_exits_without_retype(self):
        kv, view, controller = _build_view()
        from seedsigner.views.view import BackStackView

        word_calls: list = []
        view.run_screen = MagicMock(
            side_effect=_make_run_screen(MNEMONIC, word_calls, retry_back=True),
        )

        session = MagicMock(side_effect=RuntimeError("secure channel broke"))

        with patch.object(kv, "_redirect_if_uninitialised", return_value=None), \
             patch.object(kv, "_instance_key_present", return_value=False), \
             patch.object(kv, "_open_unlocked_session_cached_or_prompt", session), \
             patch.object(kv, "_invalidate_wallets_cache_for_active_aid", MagicMock()):
            dest = view.run()

        # Cancel (back) on the Retry screen exits to the back stack.
        self.assertIs(dest.View_cls, BackStackView)
        # Only one push attempt was made, and the words were entered once.
        self.assertEqual(session.call_count, 1)
        self.assertEqual(len(word_calls), 12)
        # Nothing was handed off to the backup chain on cancel.
        self.assertIsNone(controller.pending_keycard_mnemonic)


def _make_generate_run_screen(retry_back=False):
    """``run_screen`` side_effect for the on-card Generate push flow.

    The only branching screen is the transient-error WarningScreen whose single
    button is labelled "Retry"; every other screen (the "Seed loaded" OK) just
    proceeds. When ``retry_back`` is True the Retry screen returns BACK (Cancel).
    """
    from seedsigner.gui.screens import RET_CODE__BACK_BUTTON

    def dispatch(screen_cls, *args, **kwargs):
        button_data = kwargs.get("button_data") or []
        if button_data and getattr(button_data[0], "button_label", None) == "Retry":
            return RET_CODE__BACK_BUTTON if retry_back else 0
        return 0

    return dispatch


def _build_generate_view():
    import seedsigner.views.keycard_views as kv

    controller = MagicMock()
    # Fresh single-owner copies (mirrors production "".join storage) so a
    # wipe can't corrupt the shared MNEMONIC literals used for assertions.
    controller.pending_keycard_mnemonic = ["".join(w) for w in MNEMONIC]
    controller.pending_keycard_passphrase = bytearray()  # empty passphrase

    view = _new(kv.ToolsKeycardGenerateSeedLoadView)
    view.controller = controller
    return kv, view, controller


class TestGenerateSeedLoadRetry(unittest.TestCase):
    """The on-card Generate push has the same retry-without-discard contract.

    ``ToolsKeycardGenerateSeedLoadView`` derives the seed from the mnemonic the
    controller is already holding, so a transient LOAD_KEY failure must keep
    ``controller.pending_keycard_mnemonic`` intact for a Retry — losing an
    on-card-generated seed (no paper backup) would be unrecoverable.
    """

    def test_transient_error_then_retry_keeps_pending(self):
        kv, view, controller = _build_generate_view()

        view.run_screen = MagicMock(side_effect=_make_generate_run_screen())

        client = MagicMock()
        session = MagicMock(
            side_effect=[RuntimeError("secure channel broke"), (client, None)],
        )

        with patch.object(kv, "_open_unlocked_session_cached_or_prompt", session), \
             patch.object(kv, "_invalidate_wallets_cache_for_active_aid", MagicMock()):
            dest = view.run()

        # Succeeded on the 2nd push attempt and handed off to the backup offer.
        self.assertIs(dest.View_cls, kv.ToolsKeycardSeedkeeperOfferView)
        self.assertEqual(session.call_count, 2)
        client.load_bip39_seed.assert_called_once()
        # The pending mnemonic survived the transient failure (NOT wiped between
        # attempts) and is still set for the backup-offer chain.
        self.assertIsNotNone(controller.pending_keycard_mnemonic)
        self.assertEqual(controller.pending_keycard_mnemonic, MNEMONIC)

    def test_cancel_on_retry_discards_and_exits(self):
        kv, view, controller = _build_generate_view()
        from seedsigner.views.view import BackStackView

        view.run_screen = MagicMock(
            side_effect=_make_generate_run_screen(retry_back=True),
        )

        session = MagicMock(side_effect=RuntimeError("secure channel broke"))

        with patch.object(kv, "_open_unlocked_session_cached_or_prompt", session), \
             patch.object(kv, "_invalidate_wallets_cache_for_active_aid", MagicMock()):
            dest = view.run()

        # Cancel (back) on the Retry screen exits to the back stack.
        self.assertIs(dest.View_cls, BackStackView)
        # Only one push attempt was made before the user cancelled.
        self.assertEqual(session.call_count, 1)
        # The pending seed was wiped on the explicit discard.
        self.assertIsNone(controller.pending_keycard_mnemonic)


if __name__ == "__main__":
    unittest.main()
