"""Unit tests for ``views/keycard_views.py`` helpers.

Currently exercises only the small pieces that don't need a full
controller/screen plumbing -- in particular
``_error_destination`` which must keep ``skip_current_view=True`` so
that pressing OK on a Keycard error screen does NOT bounce the user
back into the failing view (re-running the failing wait_for_card and
trapping them on the same error).
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


# Same hardware mocks the other keycard tests use.
def _install_hw_mocks():
    for mod in [
        "RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
        "smartcard", "smartcard.System", "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
    ]:
        sys.modules.setdefault(mod, MagicMock())

_install_hw_mocks()


class TestErrorDestination(unittest.TestCase):
    def test_skip_current_view_is_true(self):
        """OK on a Keycard error screen must pop past the failing view.

        Without ``skip_current_view=True`` BackStackView returns to the
        view that originated the error; that view re-runs its
        wait_for_card and the user is stuck on the same error. This
        test pins the flag so the bug cannot regress.
        """
        from seedsigner.views.keycard_views import _error_destination, KeycardErrorView

        dest = _error_destination("Card not reachable", "no card detected")

        self.assertIs(dest.View_cls, KeycardErrorView)
        self.assertTrue(dest.skip_current_view)
        self.assertEqual(dest.view_args["title"], "Card not reachable")
        self.assertEqual(dest.view_args["message"], "no card detected")


class TestNoCardToast(unittest.TestCase):
    """Change 6: camera/scan sign flows show a subtle 'Insert a card first'
    toast (like the Cards menu) and stay, instead of a heavy ErrorScreen."""

    def test_helper_toasts_and_stays_on_no_card(self):
        from unittest.mock import patch

        from seedsigner.helpers.keycard.reader import NoCardError
        from seedsigner.views import keycard_views
        from seedsigner.views.view import BackStackView

        view = MagicMock()
        fake_toast_instance = MagicMock(name="InfoToast_instance")
        fake_toast_cls = MagicMock(return_value=fake_toast_instance)
        with patch("seedsigner.gui.toast.InfoToast", fake_toast_cls):
            dest = keycard_views._no_card_toast_or_error(
                view, NoCardError("no card"), default_title="Signing failed",
            )
        # Subtle toast dispatched, default destination is BackStackView.
        fake_toast_cls.assert_called_once()
        self.assertEqual(
            fake_toast_cls.call_args.kwargs["label_text"], "Insert a card first",
        )
        view.controller.activate_toast.assert_called_once_with(fake_toast_instance)
        self.assertIs(dest.View_cls, BackStackView)

    def test_helper_falls_back_to_error_for_other_exceptions(self):
        from seedsigner.views import keycard_views

        view = MagicMock()
        dest = keycard_views._no_card_toast_or_error(
            view, RuntimeError("boom"), default_title="Signing failed",
        )
        self.assertFalse(view.controller.activate_toast.called)
        self.assertIs(dest.View_cls, keycard_views.KeycardErrorView)
        self.assertTrue(dest.view_args["return_to_main"])

    def test_no_card_wipes_cached_pin(self):
        """Card confirmed absent → drop cached PINs (reader-independent
        backstop for the unreliable PC/SC 'removed' event on contactless
        readers). A non-card error must NOT wipe."""
        from unittest.mock import patch

        from seedsigner.helpers.keycard.reader import NoCardError, NoReaderError
        from seedsigner.views import keycard_views

        for exc in (NoCardError("no card"), NoReaderError("no reader")):
            view = MagicMock()
            with patch("seedsigner.gui.toast.InfoToast", MagicMock()):
                keycard_views._no_card_toast_or_error(
                    view, exc, default_title="Signing failed",
                )
            view.controller.wipe_card_session_secrets.assert_called_once()

        # Other exceptions fall through to the error screen without wiping.
        view = MagicMock()
        keycard_views._no_card_toast_or_error(
            view, RuntimeError("boom"), default_title="Signing failed",
        )
        self.assertFalse(view.controller.wipe_card_session_secrets.called)

    def test_eth_finalize_no_card_preserves_request_and_stays(self):
        from unittest.mock import patch

        from seedsigner.helpers.keycard.reader import NoCardError
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardSignEthFinalizeView
        from seedsigner.views.view import BackStackView

        view = ToolsKeycardSignEthFinalizeView.__new__(ToolsKeycardSignEthFinalizeView)
        view.controller = MagicMock()
        sentinel_request = object()
        view.controller.eth_sign_request = sentinel_request
        view.controller.has_any_keycard_auth.return_value = True

        fake_toast_cls = MagicMock(return_value=MagicMock())
        with patch.object(
            keycard_views, "_open_unlocked_session_cached_or_prompt",
            side_effect=NoCardError("no card"),
        ), patch("seedsigner.gui.toast.InfoToast", fake_toast_cls):
            dest = view.run()

        # Scanned request preserved (NOT nulled) so retry needs no re-scan.
        self.assertIs(view.controller.eth_sign_request, sentinel_request)
        self.assertTrue(view.controller.activate_toast.called)
        self.assertIs(dest.View_cls, BackStackView)

    def test_eth_finalize_card_changed_resumes_without_rescan(self):
        """A swapped card mid-sign keeps the scanned request and routes to
        pairing with a resume back into the finalize step (no re-scan)."""
        from unittest.mock import patch

        from seedsigner.helpers.keycard import KeycardCardChangedError
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardPairView, ToolsKeycardSignEthFinalizeView,
        )

        view = ToolsKeycardSignEthFinalizeView.__new__(ToolsKeycardSignEthFinalizeView)
        view.controller = MagicMock()
        sentinel_request = object()
        view.controller.eth_sign_request = sentinel_request
        view.controller.has_any_keycard_auth.return_value = True

        with patch.object(
            keycard_views, "_open_unlocked_session_cached_or_prompt",
            side_effect=KeycardCardChangedError(b"\xBB" * 16),
        ):
            dest = view.run()

        # Scanned request preserved (NOT nulled) so the resume needs no re-scan.
        self.assertIs(view.controller.eth_sign_request, sentinel_request)
        # Routed to pairing, set up to resume the finalize after a good pair.
        self.assertIs(dest.View_cls, ToolsKeycardPairView)
        self.assertTrue(dest.skip_current_view)
        resume = dest.view_args["next_destination"]
        self.assertIs(resume.View_cls, ToolsKeycardSignEthFinalizeView)
        self.assertTrue(resume.skip_current_view)

    def test_btc_psbt_finalize_card_changed_resumes_without_rescan(self):
        from unittest.mock import patch

        from seedsigner.helpers.keycard import KeycardCardChangedError
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardBtcSignPsbtFinalizeView, ToolsKeycardPairView,
        )

        view = ToolsKeycardBtcSignPsbtFinalizeView.__new__(
            ToolsKeycardBtcSignPsbtFinalizeView,
        )
        view.controller = MagicMock()
        sentinel_psbt = object()
        view.controller.btc_parsed_psbt = sentinel_psbt

        with patch.object(
            keycard_views, "_open_unlocked_session_cached_or_prompt",
            side_effect=KeycardCardChangedError(b"\xCC" * 16),
        ):
            dest = view.run()

        # Parsed PSBT preserved (NOT nulled) so the resume needs no re-scan.
        self.assertIs(view.controller.btc_parsed_psbt, sentinel_psbt)
        self.assertIs(dest.View_cls, ToolsKeycardPairView)
        resume = dest.view_args["next_destination"]
        self.assertIs(resume.View_cls, ToolsKeycardBtcSignPsbtFinalizeView)

    def test_pair_then_resume_builds_resumable_destination(self):
        from seedsigner.views.keycard_views import (
            _pair_then_resume, ToolsKeycardPairView,
            ToolsKeycardSignEthFinalizeView,
        )
        from seedsigner.views.view import Destination

        resume = Destination(ToolsKeycardSignEthFinalizeView)
        dest = _pair_then_resume(resume)
        self.assertIs(dest.View_cls, ToolsKeycardPairView)
        self.assertTrue(dest.skip_current_view)
        self.assertIs(dest.view_args["next_destination"], resume)
        # The resume hop also skips itself so the back stack stays clean
        # (no Pair/Finalize duplicates left behind after the detour).
        self.assertTrue(resume.skip_current_view)


class TestKeycardMenuRouting(unittest.TestCase):
    """Smoke tests for the scope-organised Keycard menu hierarchy:

        Keycard (top)
          ├─ Ethereum ›       → ToolsKeycardEthereumMenuView
          │   ├─ Sign request  → ToolsKeycardSignEthStartView
          │   ├─ View wallets  → ToolsKeycardWalletsListView
          │   └─ Connect software wallet → ToolsKeycardPairWalletView
          ├─ Bitcoin ›        → ToolsKeycardBitcoinMenuView
          ├─ Switch instance  → ToolsKeycardInstancesSwitchView  (only if >1 instance)
          ├─ Lock card        → ToolsKeycardLockView
          └─ Settings ›       → ToolsKeycardSettingsMenuView
              ├─ Manage Instances › → ToolsKeycardInstancesMenuView
              │   │  (once/session explainer first)
              │   ├─ This instance ›  → ToolsKeycardThisInstanceMenuView
              │   │   ├─ Generate key  → ToolsKeycardGenerateKeyView
              │   │   ├─ Import seed   → ToolsKeycardImportSeedView
              │   │   ├─ Change PIN    → ToolsKeycardChangePinView
              │   │   ├─ Pairing ›     → ToolsKeycardPairingMenuView
              │   │   │   ├─ Pair card      → ToolsKeycardPairView
              │   │   │   └─ Remove pairing → ToolsKeycardRemovePairingView
              │   │   ├─ Initialise instance → ToolsKeycardInitView
              │   │   └─ Factory reset → ToolsKeycardFactoryResetView
              │   ├─ Create instance  → ToolsKeycardInstancesCreateView
              │   └─ Delete instance  → ToolsKeycardInstancesDeleteView
              └─ Card ›           → ToolsKeycardCardMenuView
                  ├─ Status           → ToolsKeycardStatusView
                  ├─ Storage          → ToolsKeycardStorageView
                  └─ Uninstall applet → ToolsKeycardUninstallAppletView

    Each parametrised case mocks ``run_screen`` to return a specific
    button index and asserts the resulting ``Destination`` routes to the
    correct child view.
    """

    def _route(self, view_cls, button_index):
        # Bypass View.__init__ which expects a Controller singleton —
        # we only exercise routing logic, not screen rendering. The
        # Keycard top menu now calls ``run_card_gate`` on entry; patch
        # it to a no-op so routing tests stay focused on selection
        # behaviour rather than probe state.
        view = view_cls.__new__(view_cls)
        view.run_screen = MagicMock(return_value=button_index)
        view.controller = MagicMock()
        import seedsigner.helpers.card_probe as card_probe_mod
        from unittest.mock import patch
        with patch.object(card_probe_mod, "run_card_gate", return_value=None):
            return view.run()

    def _route_top(self, instance_count, button_index):
        """Route the top Keycard menu with a fixed cached instance count.

        Setting ``keycard_instance_count`` to a concrete int means the
        menu reads it instead of enumerating the card
        (``_count_keycard_instances`` is only called when the cached value
        is ``None``).
        """
        from seedsigner.views.keycard_views import ToolsKeycardMenuView
        import seedsigner.helpers.card_probe as card_probe_mod
        from unittest.mock import patch
        view = ToolsKeycardMenuView.__new__(ToolsKeycardMenuView)
        view.run_screen = MagicMock(return_value=button_index)
        view.controller = MagicMock()
        view.controller.keycard_instance_count = instance_count
        with patch.object(card_probe_mod, "run_card_gate", return_value=None):
            return view.run()

    def test_top_menu_routes_multi_instance(self):
        """With >1 instance, "Switch instance" is present (5 entries)."""
        from seedsigner.views.keycard_views import (
            ToolsKeycardEthereumMenuView,
            ToolsKeycardBitcoinMenuView,
            ToolsKeycardInstancesSwitchView,
            ToolsKeycardLockView,
            ToolsKeycardSettingsMenuView,
        )
        expected = [
            ToolsKeycardEthereumMenuView,
            ToolsKeycardBitcoinMenuView,
            ToolsKeycardInstancesSwitchView,
            ToolsKeycardLockView,
            ToolsKeycardSettingsMenuView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route_top(2, i)
            self.assertIs(dest.View_cls, view_cls,
                          f"top menu index {i} routes to {dest.View_cls.__name__}, "
                          f"expected {view_cls.__name__}")

    def test_top_menu_hides_switch_when_single_instance(self):
        """With exactly 1 instance, "Switch instance" is omitted (4 entries)
        and the remaining entries still route correctly."""
        from seedsigner.views.keycard_views import (
            ToolsKeycardEthereumMenuView,
            ToolsKeycardBitcoinMenuView,
            ToolsKeycardInstancesSwitchView,
            ToolsKeycardLockView,
            ToolsKeycardSettingsMenuView,
        )
        expected = [
            ToolsKeycardEthereumMenuView,
            ToolsKeycardBitcoinMenuView,
            ToolsKeycardLockView,
            ToolsKeycardSettingsMenuView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route_top(1, i)
            self.assertIs(dest.View_cls, view_cls,
                          f"top menu index {i} routes to {dest.View_cls.__name__}, "
                          f"expected {view_cls.__name__}")
        # No index in the single-instance menu routes to the switch view.
        self.assertNotIn(
            ToolsKeycardInstancesSwitchView,
            [self._route_top(1, i).View_cls for i in range(len(expected))],
        )

    def test_settings_menu_routes(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSettingsMenuView,
            ToolsKeycardInstancesMenuView,
            ToolsKeycardCardMenuView,
        )
        expected = [
            ToolsKeycardInstancesMenuView,
            ToolsKeycardCardMenuView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route(ToolsKeycardSettingsMenuView, i)
            self.assertIs(dest.View_cls, view_cls,
                          f"settings menu index {i} routes to {dest.View_cls.__name__}, "
                          f"expected {view_cls.__name__}")

    def test_manage_instances_menu_routes(self):
        """Manage Instances groups This instance + Create + Delete.

        The controller MagicMock makes ``keycard_instances_intro_shown``
        truthy, so the once-per-session explainer is skipped and the first
        ``run_screen`` call is the menu itself.
        """
        from seedsigner.views.keycard_views import (
            ToolsKeycardInstancesMenuView,
            ToolsKeycardThisInstanceMenuView,
            ToolsKeycardInstancesCreateView,
            ToolsKeycardInstancesDeleteView,
        )
        expected = [
            ToolsKeycardThisInstanceMenuView,
            ToolsKeycardInstancesCreateView,
            ToolsKeycardInstancesDeleteView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route(ToolsKeycardInstancesMenuView, i)
            self.assertIs(dest.View_cls, view_cls,
                          f"manage-instances index {i} routes to {dest.View_cls.__name__}, "
                          f"expected {view_cls.__name__}")

    def test_ethereum_menu_routes(self):
        # View wallets + Connect software wallet both go through the
        # derivation-scheme chooser first (Default vs Ledger Live); the
        # chooser's ``mode`` distinguishes the two flows.
        from seedsigner.views.keycard_views import (
            ToolsKeycardEthDerivationSchemeView,
            ToolsKeycardEthereumMenuView,
            ToolsKeycardSignEthStartView,
        )
        expected = [
            (ToolsKeycardSignEthStartView, None),
            (ToolsKeycardEthDerivationSchemeView, "view"),
            (ToolsKeycardEthDerivationSchemeView, "export"),
        ]
        for i, (view_cls, mode) in enumerate(expected):
            dest = self._route(ToolsKeycardEthereumMenuView, i)
            self.assertIs(dest.View_cls, view_cls,
                          f"ETH menu index {i} routes to {dest.View_cls.__name__}, "
                          f"expected {view_cls.__name__}")
            if mode is not None:
                self.assertEqual((dest.view_args or {}).get("mode"), mode)

    def test_bitcoin_menu_routes(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardBitcoinMenuView,
            ToolsKeycardBtcExportXpubView,
            ToolsKeycardBtcSignPsbtScanView,
            ToolsKeycardBtcSignMessageStartView,
            ToolsKeycardBtcAddressesListView,
        )
        expected = [
            ToolsKeycardBtcSignPsbtScanView,
            ToolsKeycardBtcSignMessageStartView,
            ToolsKeycardBtcAddressesListView,
            ToolsKeycardBtcExportXpubView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route(ToolsKeycardBitcoinMenuView, i)
            self.assertIs(dest.View_cls, view_cls,
                          f"BTC menu index {i} routes to {dest.View_cls.__name__}, "
                          f"expected {view_cls.__name__}")

    def test_this_instance_menu_routes(self):
        """With naming unavailable (Persistent Settings off / no microSD), the
        Rename entry is hidden. The Pairing entry was removed entirely."""
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardThisInstanceMenuView,
            ToolsKeycardGenerateKeyView,
            ToolsKeycardImportSeedView,
            ToolsKeycardChangePinView,
            ToolsKeycardUnblockPinView,
            ToolsKeycardInitView,
            ToolsKeycardFactoryResetView,
            ToolsKeycardLockView,
        )
        expected = [
            ToolsKeycardGenerateKeyView,
            ToolsKeycardImportSeedView,
            ToolsKeycardChangePinView,
            ToolsKeycardUnblockPinView,
            ToolsKeycardInitView,
            ToolsKeycardFactoryResetView,
            ToolsKeycardLockView,
        ]
        with patch.object(keycard_views, "_instance_rename_available", return_value=False):
            for i, view_cls in enumerate(expected):
                dest = self._route(ToolsKeycardThisInstanceMenuView, i)
                self.assertIs(dest.View_cls, view_cls)

    def test_this_instance_menu_no_pairing_entry(self):
        """The Pairing submenu is no longer reachable from This instance."""
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardThisInstanceMenuView, ToolsKeycardPairingMenuView,
        )
        for avail, count in ((True, 8), (False, 7)):
            with patch.object(keycard_views, "_instance_rename_available", return_value=avail):
                routed = [self._route(ToolsKeycardThisInstanceMenuView, i).View_cls
                          for i in range(count)]
            self.assertNotIn(ToolsKeycardPairingMenuView, routed)

    def test_this_instance_menu_shows_rename_when_available(self):
        """When naming is available the Rename entry appears after Change PIN
        and routes to the new view; the rest still route correctly."""
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardThisInstanceMenuView,
            ToolsKeycardGenerateKeyView,
            ToolsKeycardImportSeedView,
            ToolsKeycardChangePinView,
            ToolsKeycardUnblockPinView,
            ToolsKeycardThisInstanceRenameView,
            ToolsKeycardInitView,
            ToolsKeycardFactoryResetView,
            ToolsKeycardLockView,
        )
        expected = [
            ToolsKeycardGenerateKeyView,
            ToolsKeycardImportSeedView,
            ToolsKeycardChangePinView,
            ToolsKeycardUnblockPinView,
            ToolsKeycardThisInstanceRenameView,
            ToolsKeycardInitView,
            ToolsKeycardFactoryResetView,
            ToolsKeycardLockView,
        ]
        with patch.object(keycard_views, "_instance_rename_available", return_value=True):
            for i, view_cls in enumerate(expected):
                dest = self._route(ToolsKeycardThisInstanceMenuView, i)
                self.assertIs(dest.View_cls, view_cls)

    def test_rename_view_happy_path(self):
        """Rename resolves the UID, prompts a name (no password), writes it via
        instance_names, updates the controller cache, and returns to the menu."""
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardThisInstanceRenameView, ToolsKeycardThisInstanceMenuView,
        )
        view = ToolsKeycardThisInstanceRenameView.__new__(
            ToolsKeycardThisInstanceRenameView
        )
        view.run_screen = MagicMock()
        view.controller = MagicMock()
        uid = b"\x11" * 16
        view.controller.get_uid_for_aid.return_value = uid  # no SELECT needed
        with patch.object(keycard_views, "_instance_rename_available", return_value=True), \
             patch.object(keycard_views, "_prompt_for_text", return_value="Cold"), \
             patch("seedsigner.helpers.keycard.instance_names.set_name") as set_name, \
             patch("seedsigner.helpers.keycard.instance_names.get_name", return_value="Cold"):
            dest = view.run()
        set_name.assert_called_once_with(uid, "Cold")
        view.controller.set_instance_name_for.assert_called_once_with(uid, "Cold")
        self.assertIs(dest.View_cls, ToolsKeycardThisInstanceMenuView)

    def test_rename_view_gated_when_unavailable(self):
        """The Rename view itself refuses (no prompt) when naming is gated
        off, returning the neutral "Not available" error."""
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardThisInstanceRenameView, KeycardErrorView,
        )
        view = ToolsKeycardThisInstanceRenameView.__new__(
            ToolsKeycardThisInstanceRenameView
        )
        view.run_screen = MagicMock()
        view.controller = MagicMock()
        with patch.object(keycard_views, "_instance_rename_available", return_value=False):
            dest = view.run()
        self.assertIs(dest.View_cls, KeycardErrorView)
        self.assertEqual(dest.view_args["title"], "Not available")
        view.run_screen.assert_not_called()

    def test_pairing_menu_routes(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardPairingMenuView,
            ToolsKeycardPairView,
            ToolsKeycardRemovePairingView,
        )
        expected = [
            ToolsKeycardPairView,
            ToolsKeycardRemovePairingView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route(ToolsKeycardPairingMenuView, i)
            self.assertIs(dest.View_cls, view_cls)

    def test_card_menu_routes(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardCardMenuView,
            ToolsKeycardStatusView,
            ToolsKeycardStorageView,
            ToolsKeycardUninstallAppletView,
        )
        expected = [
            ToolsKeycardStatusView,
            ToolsKeycardStorageView,
            ToolsKeycardUninstallAppletView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route(ToolsKeycardCardMenuView, i)
            self.assertIs(dest.View_cls, view_cls)

    def test_wallets_cache_invalidation_drops_only_active_aid(self):
        """After Generate-key / Import-seed, the on-card master key
        changes; the View-wallets cache for the active AID must be
        invalidated so stale addresses don't show until reboot.
        Other AIDs' entries must be preserved (multi-instance cards).
        """
        from seedsigner.views.keycard_views import (
            _invalidate_wallets_cache_for_active_aid,
        )

        controller = MagicMock()
        controller.active_keycard_aid = bytes.fromhex("A0000008040001010101")
        other_aid_hex = bytes.fromhex("A0000008040001010102").hex()
        controller.keycard_wallets_data = {
            bytes(controller.active_keycard_aid).hex(): ["0xOLD1", "0xOLD2"],
            other_aid_hex: ["0xKEEP1"],
        }

        _invalidate_wallets_cache_for_active_aid(controller)

        self.assertNotIn(
            bytes(controller.active_keycard_aid).hex(),
            controller.keycard_wallets_data,
        )
        self.assertEqual(controller.keycard_wallets_data[other_aid_hex], ["0xKEEP1"])

    def test_wallets_cache_invalidation_tolerates_empty_dict(self):
        from seedsigner.views.keycard_views import (
            _invalidate_wallets_cache_for_active_aid,
        )

        controller = MagicMock()
        controller.active_keycard_aid = bytes.fromhex("A0000008040001010101")

        controller.keycard_wallets_data = None
        _invalidate_wallets_cache_for_active_aid(controller)
        self.assertIsNone(controller.keycard_wallets_data)

        controller.keycard_wallets_data = {}
        _invalidate_wallets_cache_for_active_aid(controller)
        self.assertEqual(controller.keycard_wallets_data, {})

    def test_leaf_returns_to_menu_skip_or_clear(self):
        """Every ``return Destination(ToolsKeycardMenuView ...)`` from a
        leaf flow must mark either ``skip_current_view=True`` or
        ``clear_history=True``. Without one of those flags the leaf view
        stays on the back stack, so pressing Back from the Keycard menu
        re-opens the just-completed flow (e.g. Export xpub).
        """
        import re

        path = os.path.join(SRC_ROOT, "seedsigner", "views", "keycard_views.py")
        with open(path, encoding="utf-8") as fh:
            source = fh.read()

        offenders = []
        for match in re.finditer(
            r"Destination\(ToolsKeycardMenuView(?P<args>[^)]*)\)",
            source,
        ):
            args = match.group("args")
            if "skip_current_view=True" in args or "clear_history=True" in args:
                continue
            line_no = source[: match.start()].count("\n") + 1
            offenders.append((line_no, match.group(0)))

        self.assertEqual(
            offenders, [],
            "Leaf returns to ToolsKeycardMenuView must set "
            "skip_current_view=True or clear_history=True; offenders: "
            f"{offenders}",
        )

    def test_init_pin_mismatch_reprompts_then_accepts(self):
        """Init must loop on PIN/Confirm mismatch and use the matched pair.

        Sequence we feed to ``prompt_for_pin``::

            1st prompt → "111111"   (initial)
            2nd prompt → "222222"   (confirm — MISMATCH)
            3rd prompt → "333333"   (retry initial)
            4th prompt → "333333"   (retry confirm — match)

        The PIN bytes passed to ``client.init`` must be the matched pair
        ``b"333333"``; the mismatched values must never reach the card.
        """
        from types import SimpleNamespace
        from unittest.mock import patch

        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON  # noqa: F401
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardInitView

        view = ToolsKeycardInitView.__new__(ToolsKeycardInitView)
        view.controller = MagicMock()

        # run_screen returns: DireWarning confirm → 0 (CONTINUE),
        # WarningScreen("PINs differ") → 0 (Retry), Warning("Write this down") → 0,
        # LargeIconStatusScreen("Initialised") → 0.
        view.run_screen = MagicMock(return_value=0)

        pin_buffers = [
            bytearray(b"111111"),
            bytearray(b"222222"),
            bytearray(b"333333"),
            bytearray(b"333333"),
        ]
        prompt_calls = {"n": 0}

        def fake_prompt_for_pin(parent, title):
            buf = pin_buffers[prompt_calls["n"]]
            prompt_calls["n"] += 1
            return buf

        fake_client = MagicMock()
        fake_connection = MagicMock()
        captured = {}

        def fake_init(pin_bytes, puk_bytes, secret, duress_pin=None,
                      max_pin_attempts=None):
            captured["pin"] = bytes(pin_bytes)
            captured["puk"] = bytes(puk_bytes)
            captured["duress"] = bytes(duress_pin) if duress_pin is not None else None

        fake_client.init.side_effect = fake_init

        with patch.object(keycard_views, "prompt_for_pin", side_effect=fake_prompt_for_pin), \
             patch.object(keycard_views, "prompt_for_text", return_value=None), \
             patch("seedsigner.helpers.card_probe.probe_card",
                   return_value=SimpleNamespace(
                       present=False, kind_match=False, initialised=False)), \
             patch("seedsigner.helpers.keycard.reader.wait_for_card",
                   return_value=fake_connection), \
             patch("seedsigner.helpers.keycard.reader.release_other_smartcard_holders"), \
             patch("seedsigner.helpers.keycard.client.KeycardClient",
                   return_value=fake_client), \
             patch("seedsigner.helpers.keycard.crypto.derive_pairing_secret",
                   return_value=b"\x11" * 32), \
             patch.object(keycard_views, "select_with_autodetect",
                          return_value=SimpleNamespace(app_version=0)):
            view.run()

        self.assertEqual(prompt_calls["n"], 4)
        self.assertEqual(captured["pin"], b"333333")
        self.assertEqual(len(captured["puk"]), 12)  # PUK_LENGTH
        # run_screen returns 0 → "Skip" on the Duress PIN chooser. To match
        # keycard-shell, Skip still provisions a *random* duress PIN (≠ main)
        # rather than leaving the applet's PUK[:6] default.
        self.assertIsNotNone(captured["duress"])
        self.assertEqual(len(captured["duress"]), 6)
        self.assertTrue(captured["duress"].isdigit())
        self.assertNotEqual(captured["duress"], captured["pin"])

    def test_init_already_initialised_blocks_before_pin(self):
        """An already-initialised card must short-circuit Init *before*
        any PIN/PUK prompt — the early read-only probe sees
        ``initialised=True`` and returns the "Already initialised" error
        without ever calling ``prompt_for_pin`` or ``client.init``.
        """
        from types import SimpleNamespace
        from unittest.mock import patch

        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardInitView

        view = ToolsKeycardInitView.__new__(ToolsKeycardInitView)
        view.controller = MagicMock()
        view.run_screen = MagicMock(return_value=0)

        fake_client = MagicMock()

        with patch.object(keycard_views, "prompt_for_pin") as prompt_mock, \
             patch("seedsigner.helpers.card_probe.probe_card",
                   return_value=SimpleNamespace(
                       present=True, kind_match=True, initialised=True)), \
             patch("seedsigner.helpers.keycard.client.KeycardClient",
                   return_value=fake_client):
            dest = view.run()

        prompt_mock.assert_not_called()
        fake_client.init.assert_not_called()
        self.assertIs(dest.View_cls, keycard_views.KeycardErrorView)
        self.assertEqual(dest.view_args["title"], "Already initialised")

    def test_init_late_guard_blocks_after_select(self):
        """Backstop: if no card was present at the early probe but an
        already-initialised card is inserted before INIT, the
        post-SELECT check (``app_version != 0``) must error out instead
        of letting ``client.init`` fail with the cryptic SW=0x6D00.
        """
        from types import SimpleNamespace
        from unittest.mock import patch

        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardInitView

        view = ToolsKeycardInitView.__new__(ToolsKeycardInitView)
        view.controller = MagicMock()
        view.run_screen = MagicMock(return_value=0)

        fake_client = MagicMock()
        fake_connection = MagicMock()

        with patch.object(keycard_views, "prompt_for_pin",
                          return_value=bytearray(b"123456")), \
             patch.object(keycard_views, "prompt_for_text", return_value=None), \
             patch("seedsigner.helpers.card_probe.probe_card",
                   return_value=SimpleNamespace(
                       present=False, kind_match=False, initialised=False)), \
             patch("seedsigner.helpers.keycard.reader.wait_for_card",
                   return_value=fake_connection), \
             patch("seedsigner.helpers.keycard.reader.release_other_smartcard_holders"), \
             patch("seedsigner.helpers.keycard.client.KeycardClient",
                   return_value=fake_client), \
             patch("seedsigner.helpers.keycard.crypto.derive_pairing_secret",
                   return_value=b"\x11" * 32), \
             patch.object(keycard_views, "select_with_autodetect",
                          return_value=SimpleNamespace(app_version=0x0300)):
            dest = view.run()

        fake_client.init.assert_not_called()
        self.assertIs(dest.View_cls, keycard_views.KeycardErrorView)
        self.assertEqual(dest.view_args["title"], "Already initialised")

    def _drive_duress_init(self, prompt_returns, duress_choice, pin_attempts=5):
        """Run ``ToolsKeycardInitView`` with scripted PIN prompts and a given
        "Duress PIN" chooser selection.

        ``prompt_returns`` is the ordered list returned by successive
        ``prompt_for_pin`` calls (each a ``bytearray`` or ``None``).
        ``duress_choice`` is the index the "Duress PIN" explainer/chooser
        screen returns (0 = Skip, 1 = Set duress PIN). ``pin_attempts`` is
        the value the ``SETTING__SCARD_PIN_ATTEMPTS`` lookup returns (the
        wizard forwards it to ``client.init`` as ``max_pin_attempts``).
        Returns ``(captured, shown_titles, dest)``.
        """
        from types import SimpleNamespace
        from unittest.mock import patch

        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardInitView

        view = ToolsKeycardInitView.__new__(ToolsKeycardInitView)
        view.controller = MagicMock()

        shown = []

        def fake_run_screen(screen_cls, **kwargs):
            title = kwargs.get("title")
            shown.append(title)
            if title == "Duress PIN":
                return duress_choice
            return 0

        view.run_screen = fake_run_screen

        prompt_state = {"n": 0}

        def fake_prompt_for_pin(parent, title):
            buf = prompt_returns[prompt_state["n"]]
            prompt_state["n"] += 1
            return buf

        fake_client = MagicMock()
        fake_connection = MagicMock()
        captured = {}

        def fake_init(pin_bytes, puk_bytes, secret, duress_pin=None,
                      max_pin_attempts=None):
            captured["pin"] = bytes(pin_bytes)
            captured["puk"] = bytes(puk_bytes)
            captured["duress"] = bytes(duress_pin) if duress_pin is not None else None
            captured["max_pin_attempts"] = max_pin_attempts

        fake_client.init.side_effect = fake_init

        fake_settings = MagicMock()
        fake_settings.get_value.return_value = pin_attempts

        with patch.object(keycard_views, "prompt_for_pin", side_effect=fake_prompt_for_pin), \
             patch("seedsigner.helpers.card_probe.probe_card",
                   return_value=SimpleNamespace(
                       present=False, kind_match=False, initialised=False)), \
             patch("seedsigner.helpers.keycard.reader.wait_for_card",
                   return_value=fake_connection), \
             patch("seedsigner.helpers.keycard.reader.release_other_smartcard_holders"), \
             patch("seedsigner.helpers.keycard.client.KeycardClient",
                   return_value=fake_client), \
             patch("seedsigner.helpers.keycard.crypto.derive_pairing_secret",
                   return_value=b"\x11" * 32), \
             patch("seedsigner.models.settings.Settings.get_instance",
                   return_value=fake_settings), \
             patch.object(keycard_views, "select_with_autodetect",
                          return_value=SimpleNamespace(app_version=0)):
            dest = view.run()

        captured["init_called"] = fake_client.init.called
        return captured, shown, dest

    def test_init_with_duress_passes_duress_bytes(self):
        """'Set duress PIN' + a distinct 6-digit PIN forwards it to
        ``client.init`` as ``duress_pin`` and still chains to the seed
        chooser."""
        from seedsigner.views import keycard_views

        captured, shown, dest = self._drive_duress_init(
            prompt_returns=[
                bytearray(b"111111"),  # main PIN
                bytearray(b"111111"),  # confirm main
                bytearray(b"654321"),  # duress PIN
                bytearray(b"654321"),  # confirm duress
            ],
            duress_choice=1,
        )
        self.assertEqual(captured["pin"], b"111111")
        self.assertEqual(captured["duress"], b"654321")
        self.assertIn("Duress PIN", shown)
        self.assertIs(dest.View_cls, keycard_views.ToolsKeycardSetupChooseSeedView)

    def test_init_forwards_pin_attempts_setting(self):
        """The 'Smartcard PIN Attempts' setting is forwarded to
        ``client.init`` as ``max_pin_attempts`` so Keycard instances honour
        the configured limit instead of the hardcoded applet default."""
        captured, _shown, _dest = self._drive_duress_init(
            prompt_returns=[
                bytearray(b"111111"),  # main PIN
                bytearray(b"111111"),  # confirm main
                bytearray(b"654321"),  # duress PIN
                bytearray(b"654321"),  # confirm duress
            ],
            duress_choice=1,
            pin_attempts=7,
        )
        self.assertEqual(captured["max_pin_attempts"], 7)

    def test_init_duress_equal_main_reprompts(self):
        """A duress PIN equal to the main PIN must be rejected (the applet
        would route to the decoy and lose the real wallet), show the
        "Must differ" warning, and re-prompt — the equal value never
        reaches ``client.init``."""
        captured, shown, dest = self._drive_duress_init(
            prompt_returns=[
                bytearray(b"111111"),  # main PIN
                bytearray(b"111111"),  # confirm main
                bytearray(b"111111"),  # duress == main → rejected
                bytearray(b"111111"),  # confirm duress
                bytearray(b"654321"),  # retry duress → OK
                bytearray(b"654321"),  # confirm retry
            ],
            duress_choice=1,
        )
        self.assertIn("Must differ", shown)
        self.assertEqual(captured["duress"], b"654321")

    def test_init_duress_cancel_uses_random_duress(self):
        """Backing out of the duress PIN entry doesn't abort init (the main
        PIN is already committed); to match keycard-shell it provisions a
        *random* duress PIN (≠ main) rather than leaving the PUK[:6] default."""
        captured, shown, dest = self._drive_duress_init(
            prompt_returns=[
                bytearray(b"111111"),  # main PIN
                bytearray(b"111111"),  # confirm main
                None,                  # back out of duress entry
            ],
            duress_choice=1,
        )
        self.assertTrue(captured["init_called"])
        self.assertEqual(len(captured["duress"]), 6)
        self.assertTrue(captured["duress"].isdigit())
        self.assertNotEqual(captured["duress"], b"111111")
        self.assertEqual(captured["pin"], b"111111")

    def test_instance_cap_blocks_create_at_ceiling(self):
        """``ToolsKeycardInstancesCreateView`` must short-circuit to an
        error destination when ``MAX_KEYCARD_INSTANCES`` Keycard instances
        already exist, and must never call ``install_for_install_with_fallback``.
        """
        from unittest.mock import patch

        from seedsigner.helpers.keycard.global_platform import (
            AppletInstance, MAX_KEYCARD_INSTANCES,
        )
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardInstancesCreateView,
        )

        # A full card: one Keycard instance per slot, 1..MAX (9-byte canonical).
        full_instances = [
            AppletInstance(
                aid=KEYCARD_APPLET_AID + bytes([suffix]),
                life_cycle=0, privileges=0,
            )
            for suffix in range(0x01, 0x01 + MAX_KEYCARD_INSTANCES)
        ]

        view = ToolsKeycardInstancesCreateView.__new__(ToolsKeycardInstancesCreateView)
        view.controller = MagicMock()

        with patch.object(
            keycard_views, "_open_isd_channel",
            return_value=(MagicMock(), full_instances, MagicMock()),
        ), patch(
            "seedsigner.helpers.keycard.global_platform.install_for_install_with_fallback"
        ) as install_mock:
            dest = view.run()

        install_mock.assert_not_called()
        self.assertIs(dest.View_cls, keycard_views.KeycardErrorView)
        self.assertEqual(dest.view_args["title"], "Maximum reached")

    def test_create_auto_switches_active_instance(self):
        """A successful create must auto-activate the freshly-installed
        instance (set ``active_keycard_aid`` to the new AID) so the announced
        "Run Init next" targets it directly, instead of leaving the previous
        (already-initialised) instance active."""
        from unittest.mock import patch

        from seedsigner.helpers.keycard.global_platform import AppletInstance
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardInstancesCreateView,
            ToolsKeycardInstancesMenuView, _next_free_instance_aid,
        )

        # One existing instance at the boot-default AID (the active one).
        default_aid = bytes.fromhex("A0000008040001010101")
        existing = [AppletInstance(aid=default_aid, life_cycle=7, privileges=0)]
        expected_new = _next_free_instance_aid([default_aid])
        # Sanity: the new slot must differ from the active default.
        self.assertNotEqual(expected_new, default_aid)

        view = ToolsKeycardInstancesCreateView.__new__(ToolsKeycardInstancesCreateView)
        view.controller = MagicMock()
        view.controller.active_keycard_aid = default_aid
        # Confirm screens return a non-back sentinel so the flow proceeds.
        view.run_screen = MagicMock(return_value=object())

        with patch.object(
            keycard_views, "_open_isd_channel",
            return_value=(MagicMock(), existing, MagicMock()),
        ), patch(
            "seedsigner.helpers.keycard.global_platform.install_for_install_with_fallback"
        ) as install_mock:
            dest = view.run()

        install_mock.assert_called_once()
        # The active instance is now the one we just created.
        self.assertEqual(view.controller.active_keycard_aid, expected_new)
        # Count is invalidated so "Switch instance" re-probes (now >1).
        self.assertIsNone(view.controller.keycard_instance_count)
        self.assertIs(dest.View_cls, ToolsKeycardInstancesMenuView)

    def test_pin_management_view_removed(self):
        """``ToolsKeycardPinManagementMenuView`` was a one-entry indirection
        ("Change PIN" was the only item); since Change PIN now hangs
        directly off ``This instance``, the intermediate menu has been
        removed."""
        from seedsigner.views import keycard_views
        self.assertFalse(
            hasattr(keycard_views, "ToolsKeycardPinManagementMenuView"),
            "Stale ToolsKeycardPinManagementMenuView class is still present",
        )

    def test_instance_naming_present(self):
        """Instance naming is back, microSD-only: the name lives in the
        pairing blob's label slot (per-UID), read into a controller cache at
        pairing-load and rendered via ``_instance_display_name``. The new
        ``This instance ▸ Rename`` view exists and the controller exposes the
        name-cache helpers. The OLD label subsystem (``set_label_for`` and the
        standalone ``ToolsKeycardInstancesRenameView``) stays gone."""
        from seedsigner.controller import Controller
        from seedsigner.views import keycard_views
        self.assertTrue(
            hasattr(keycard_views, "ToolsKeycardThisInstanceRenameView"),
            "Rename view is missing",
        )
        self.assertTrue(hasattr(keycard_views, "_instance_display_name"))
        for meth in ("set_instance_name_for", "get_instance_name_for",
                     "get_instance_name_for_aid"):
            self.assertTrue(hasattr(Controller, meth), f"Controller.{meth} missing")
        # Old subsystem must not resurface.
        self.assertFalse(hasattr(Controller, "set_label_for"))
        self.assertFalse(hasattr(keycard_views, "ToolsKeycardInstancesRenameView"))

    def test_instance_display_name_resolution(self):
        """``_instance_display_name`` returns a cached name when present and
        falls back to the ``Inst N`` label otherwise — including the
        load-bearing guard against a bare MagicMock leaking into a title."""
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import KEYCARD_APPLET_AID
        aid = KEYCARD_APPLET_AID + b"\x01\x01"

        named = MagicMock()
        named.get_instance_name_for_aid.return_value = "Cold"
        self.assertEqual(keycard_views._instance_display_name(named, aid), "Cold")

        unnamed = MagicMock()
        unnamed.get_instance_name_for_aid.return_value = None
        self.assertEqual(keycard_views._instance_display_name(unnamed, aid), "Inst 1")

        # A bare MagicMock returns a truthy Mock — must fall back, not leak it.
        self.assertEqual(keycard_views._instance_display_name(MagicMock(), aid), "Inst 1")
        # No controller at all.
        self.assertEqual(keycard_views._instance_display_name(None, aid), "Inst 1")

    def test_instance_title_suffix(self):
        """``_instance_title_suffix`` drops the auto ``Inst N`` label when the
        card holds exactly one instance, but always keeps a custom name and
        keeps the label when the count is unknown or >1."""
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import KEYCARD_APPLET_AID
        aid = KEYCARD_APPLET_AID + b"\x01\x01"

        def controller(count, name):
            c = MagicMock()
            c.active_keycard_aid = aid
            c.keycard_instance_count = count
            c.get_instance_name_for_aid.return_value = name
            return c

        # Custom name always shows, regardless of count.
        self.assertEqual(keycard_views._instance_title_suffix(controller(1, "Cold")), "Cold")
        self.assertEqual(keycard_views._instance_title_suffix(controller(3, "Cold")), "Cold")
        # Single instance, no name → omit the suffix entirely.
        self.assertIsNone(keycard_views._instance_title_suffix(controller(1, None)))
        # >1 instance, no name → show the auto label.
        self.assertEqual(keycard_views._instance_title_suffix(controller(2, None)), "Inst 1")
        # Unknown count, no name → keep the label (never drop identity on a guess).
        self.assertEqual(keycard_views._instance_title_suffix(controller(None, None)), "Inst 1")

    def test_format_instance_label(self):
        """``_format_instance_label`` renders Keycard instance AIDs as the
        human-readable ``Inst N`` (N = the trailing instance byte), and
        falls back to the short-hex form for AIDs outside that pattern."""
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import KEYCARD_APPLET_AID

        self.assertEqual(
            keycard_views._format_instance_label(KEYCARD_APPLET_AID + b"\x01\x01"),
            "Inst 1",
        )
        self.assertEqual(
            keycard_views._format_instance_label(KEYCARD_APPLET_AID + b"\x01\x03"),
            "Inst 3",
        )
        # Non-instance AID (e.g. a SeedKeeper applet) → short-hex fallback.
        seedkeeper = bytes.fromhex("5361746f6368697000")
        self.assertEqual(
            keycard_views._format_instance_label(seedkeeper),
            keycard_views._format_aid_short(seedkeeper),
        )

    def test_manage_instances_intro_once_per_session(self):
        """The Manage Instances explainer shows once per boot, then later
        entries go straight to the menu."""
        from seedsigner.gui.screens.screen import (
            ButtonListScreen, LargeIconStatusScreen,
        )
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardInstancesMenuView,
            ToolsKeycardThisInstanceMenuView,
        )

        view = ToolsKeycardInstancesMenuView.__new__(ToolsKeycardInstancesMenuView)
        view.controller = MagicMock()
        view.controller.active_keycard_aid = KEYCARD_APPLET_AID + b"\x01\x01"
        view.controller.keycard_instances_intro_shown = False

        screens = []

        def fake_run_screen(screen_cls, **kwargs):
            screens.append(screen_cls)
            return 0  # Continue, then first menu entry (This instance)

        view.run_screen = fake_run_screen

        # First entry: explainer screen, then the menu.
        dest = view.run()
        self.assertEqual(screens, [LargeIconStatusScreen, ButtonListScreen])
        self.assertTrue(view.controller.keycard_instances_intro_shown)
        self.assertIs(dest.View_cls, ToolsKeycardThisInstanceMenuView)

        # Second entry: explainer skipped, straight to the menu.
        screens.clear()
        dest = view.run()
        self.assertEqual(screens, [ButtonListScreen])
        self.assertIs(dest.View_cls, ToolsKeycardThisInstanceMenuView)

    def test_instances_switch_marks_active(self):
        """``ToolsKeycardInstancesSwitchView`` must mark exactly one option —
        the active instance — with a leading "» "."""
        from unittest.mock import patch

        from seedsigner.helpers.keycard.global_platform import AppletInstance
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardInstancesSwitchView,
        )

        active_aid = KEYCARD_APPLET_AID + b"\x01\x01"
        other_aid = KEYCARD_APPLET_AID + b"\x01\x02"
        instances = [
            AppletInstance(aid=active_aid, life_cycle=0, privileges=0),
            AppletInstance(aid=other_aid, life_cycle=0, privileges=0),
        ]

        view = ToolsKeycardInstancesSwitchView.__new__(ToolsKeycardInstancesSwitchView)
        view.controller = MagicMock()
        view.controller.active_keycard_aid = active_aid
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured.update(kwargs)
            return RET_CODE__BACK_BUTTON

        view.run_screen = fake_run_screen

        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON

        with patch.object(
            keycard_views, "_open_isd_channel",
            return_value=(MagicMock(), instances, MagicMock()),
        ), patch.object(
            keycard_views, "_instances_or_probe_fallback",
            side_effect=lambda controller, inst, conn: inst,
        ):
            view.run()

        labels = [b.button_label for b in captured["button_data"]]
        marked = [lbl for lbl in labels if lbl.startswith("» ")]
        self.assertEqual(len(marked), 1)
        self.assertIn(keycard_views._format_instance_label(active_aid), marked[0])

    def test_main_menu_title_shows_active_instance(self):
        """The main Keycard menu title surfaces the active instance label when
        the card holds more than one instance."""
        from unittest.mock import patch

        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardMenuView,
        )

        active_aid = KEYCARD_APPLET_AID + b"\x01\x01"
        view = ToolsKeycardMenuView.__new__(ToolsKeycardMenuView)
        view.controller = MagicMock()
        view.controller.active_keycard_aid = active_aid
        view.controller.keycard_instance_count = 2  # >1 → label shown
        view.controller.get_instance_name_for_aid.return_value = None  # no name
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured.update(kwargs)
            return RET_CODE__BACK_BUTTON

        view.run_screen = fake_run_screen

        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON

        with patch(
            "seedsigner.helpers.card_probe.run_card_gate", return_value=None,
        ):
            view.run()

        self.assertIn(
            keycard_views._format_instance_label(active_aid), captured["title"]
        )
        self.assertEqual(captured["title"], "Keycard · Inst 1")

    def test_main_menu_title_drops_label_for_single_instance(self):
        """With exactly one instance and no custom name, the title is the bare
        base — no noisy "· Inst N" suffix — and "Switch instance" is hidden."""
        from unittest.mock import patch

        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardMenuView,
        )

        active_aid = KEYCARD_APPLET_AID + b"\x01\x01"
        view = ToolsKeycardMenuView.__new__(ToolsKeycardMenuView)
        view.controller = MagicMock()
        view.controller.active_keycard_aid = active_aid
        view.controller.keycard_instance_count = 1  # single instance
        view.controller.get_instance_name_for_aid.return_value = None  # no name
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured.update(kwargs)
            return RET_CODE__BACK_BUTTON

        view.run_screen = fake_run_screen

        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON

        with patch(
            "seedsigner.helpers.card_probe.run_card_gate", return_value=None,
        ):
            view.run()

        self.assertEqual(captured["title"], "Keycard")
        labels = [b.button_label for b in captured["button_data"]]
        self.assertNotIn("Switch instance", labels)

    def test_main_menu_title_keeps_custom_name_for_single_instance(self):
        """A user-assigned name always shows, even with a single instance —
        only the auto "Inst N" fallback is dropped."""
        from unittest.mock import patch

        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardMenuView,
        )

        active_aid = KEYCARD_APPLET_AID + b"\x01\x01"
        view = ToolsKeycardMenuView.__new__(ToolsKeycardMenuView)
        view.controller = MagicMock()
        view.controller.active_keycard_aid = active_aid
        view.controller.keycard_instance_count = 1
        view.controller.get_instance_name_for_aid.return_value = "Cold"
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured.update(kwargs)
            return RET_CODE__BACK_BUTTON

        view.run_screen = fake_run_screen

        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON

        with patch(
            "seedsigner.helpers.card_probe.run_card_gate", return_value=None,
        ):
            view.run()

        self.assertEqual(captured["title"], "Keycard · Cold")

    def test_main_menu_probe_one_hides_switch_and_caches_count(self):
        """When the cached count is unknown, the menu takes the fast probe; a
        probe result of 1 caches the count and hides "Switch instance"."""
        from unittest.mock import patch

        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardMenuView,
        )

        active_aid = KEYCARD_APPLET_AID + b"\x01\x01"
        view = ToolsKeycardMenuView.__new__(ToolsKeycardMenuView)
        view.controller = MagicMock()
        view.controller.active_keycard_aid = active_aid
        view.controller.keycard_instance_count = None  # force a probe
        view.controller.get_instance_name_for_aid.return_value = None
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured.update(kwargs)
            return RET_CODE__BACK_BUTTON

        view.run_screen = fake_run_screen

        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON

        with patch(
            "seedsigner.helpers.card_probe.run_card_gate", return_value=None,
        ), patch.object(
            keycard_views, "_probe_keycard_instance_count", return_value=1,
        ):
            view.run()

        self.assertEqual(view.controller.keycard_instance_count, 1)
        self.assertEqual(captured["title"], "Keycard")
        labels = [b.button_label for b in captured["button_data"]]
        self.assertNotIn("Switch instance", labels)


class TestCountKeycardInstances(unittest.TestCase):
    """``_count_keycard_instances`` drives whether "Switch instance" shows.

    It must count via the authoritative GET STATUS enumeration (the real
    AIDs the card reports) and NOT a guessed/capped AID range — otherwise a
    multi-instance card whose instances sit at non-standard suffixes would
    under-count to 1 and wrongly hide "Switch instance" (the reported bug).
    """

    def _instances(self, *aids):
        from seedsigner.helpers.keycard.global_platform import AppletInstance
        return [AppletInstance(aid=a, life_cycle=0, privileges=0) for a in aids]

    def test_counts_all_reported_keycard_instances(self):
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, _count_keycard_instances,
        )
        # Five instances, including a slot BEYOND MAX_KEYCARD_INSTANCES (0x20 >
        # 16 — the capped cleartext probe would miss it), plus one non-Keycard
        # applet that must be filtered out.
        aids = [KEYCARD_APPLET_AID + bytes([0x01, n]) for n in (1, 2, 3, 4, 0x20)]
        non_keycard = bytes.fromhex("5365656448656570657200")  # "SeedHeeper"-ish
        instances = self._instances(*aids, non_keycard)
        conn = MagicMock()
        with patch.object(
            keycard_views, "_open_isd_channel",
            return_value=(MagicMock(), instances, conn),
        ):
            self.assertEqual(_count_keycard_instances(MagicMock()), 5)
        conn.disconnect.assert_called_once()

    def test_single_instance_counts_one(self):
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, _count_keycard_instances,
        )
        instances = self._instances(KEYCARD_APPLET_AID + b"\x01\x01")
        with patch.object(
            keycard_views, "_open_isd_channel",
            return_value=(MagicMock(), instances, MagicMock()),
        ):
            self.assertEqual(_count_keycard_instances(MagicMock()), 1)

    def test_empty_enumeration_returns_none(self):
        """No Keycard instances reported (GET STATUS unsupported/empty) →
        None, so the caller keeps the entry visible rather than hide on a
        false zero."""
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import _count_keycard_instances
        with patch.object(
            keycard_views, "_open_isd_channel",
            return_value=(MagicMock(), [], MagicMock()),
        ):
            self.assertIsNone(_count_keycard_instances(MagicMock()))

    def test_error_returns_none(self):
        """Any failure (no card / non-default ISD keys) → None → entry stays
        visible; never hide the only way to switch on an error."""
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import _count_keycard_instances
        with patch.object(
            keycard_views, "_open_isd_channel",
            side_effect=RuntimeError("no ISD keys"),
        ):
            self.assertIsNone(_count_keycard_instances(MagicMock()))


class TestProbeKeycardInstanceCount(unittest.TestCase):
    """``_probe_keycard_instance_count`` is the FAST, unauthenticated probe the
    top menu uses on entry to decide whether to show "Switch instance" and
    whether the title carries the ``Inst N`` suffix.

    It must NOT open the GP/ISD secure channel (that was the menu-entry stall
    and fails slowly on non-default ISD keys). It is a *bounded* probe — the
    result is ``1`` or ``2`` (meaning "≥2"), never an exact count > 2, since
    both consumers only care about the ``==1`` boundary. For 0 hits / no card /
    error it returns ``None`` so the caller keeps the entry and the label
    visible (never decide identity on a blank read).
    """

    def _probe(self, hits, raises=False):
        from unittest.mock import patch
        from seedsigner.views.keycard_views import _probe_keycard_instance_count
        import seedsigner.helpers.keycard.global_platform as gp
        import seedsigner.helpers.keycard.reader as reader
        conn = MagicMock()
        wait = MagicMock(side_effect=RuntimeError("no card")) if raises \
            else MagicMock(return_value=conn)
        with patch.object(reader, "release_other_smartcard_holders", MagicMock()), \
                patch.object(reader, "wait_for_card", wait), \
                patch.object(gp, "probe_keycard_instance_aids",
                             MagicMock(return_value=hits)):
            result = _probe_keycard_instance_count(MagicMock())
        return result, conn

    def test_two_distinct_slots_returns_count(self):
        from seedsigner.views.keycard_views import KEYCARD_APPLET_AID as A
        # One physical instance partial-matches several candidate forms, so
        # two real instances (slots 1 & 2) appear as a spread of hits.
        hits = [
            A,                       # bare prefix (no slot) — must be ignored
            A + bytes([0x01]),       # 9-byte slot 1
            A + bytes([0x01, 0x01]), # 10-byte slot 1
            A + bytes([0x02]),       # 9-byte slot 2
            A + bytes([0x01, 0x02]), # 10-byte slot 2
        ]
        result, conn = self._probe(hits)
        self.assertEqual(result, 2)
        conn.disconnect.assert_called_once()

    def test_single_slot_returns_one(self):
        """A single instance partial-matches the bare prefix plus both AID
        forms of its slot; the bare prefix is dropped and the one distinct slot
        byte yields an exact count of 1 (so the caller hides "Switch instance"
        and drops the ``Inst N`` suffix)."""
        from seedsigner.views.keycard_views import KEYCARD_APPLET_AID as A
        hits = [A, A + bytes([0x01]), A + bytes([0x01, 0x01])]
        result, _ = self._probe(hits)
        self.assertEqual(result, 1)

    def test_bare_prefix_only_returns_none(self):
        from seedsigner.views.keycard_views import KEYCARD_APPLET_AID as A
        result, _ = self._probe([A])
        self.assertIsNone(result)

    def test_empty_returns_none(self):
        result, _ = self._probe([])
        self.assertIsNone(result)

    def test_error_returns_none(self):
        result, _ = self._probe([], raises=True)
        self.assertIsNone(result)

    def test_forwards_cheap_probe_knobs(self):
        """The fast menu probe must ask for the *cheap* variant — 9-byte form
        only, early-exit at the 2nd slot — so the raised ceiling (16) does not
        re-introduce a ~32-SELECT menu-entry stall."""
        from unittest.mock import patch
        from seedsigner.views.keycard_views import _probe_keycard_instance_count
        import seedsigner.helpers.keycard.global_platform as gp
        import seedsigner.helpers.keycard.reader as reader
        probe = MagicMock(return_value=[])
        with patch.object(reader, "release_other_smartcard_holders", MagicMock()), \
                patch.object(reader, "wait_for_card", MagicMock(return_value=MagicMock())), \
                patch.object(gp, "probe_keycard_instance_aids", probe):
            _probe_keycard_instance_count(MagicMock())
        self.assertEqual(probe.call_args.kwargs.get("canonical_only"), True)
        self.assertEqual(probe.call_args.kwargs.get("stop_after_slots"), 2)


class TestProbeInstanceAidsKnobs(unittest.TestCase):
    """``probe_keycard_instance_aids`` early-exit + canonical-only behaviour
    that keeps the fast menu probe cheap despite the raised ceiling."""

    class _Conn:
        """Fake PC/SC connection: SW=9000 for the given AIDs, 0x6A82 else."""
        def __init__(self, present):
            self.present = {bytes(a) for a in present}
            self.selected = []

        def transmit(self, apdu):
            aid = bytes(apdu[5:5 + apdu[4]])
            self.selected.append(aid)
            if aid in self.present:
                return [], 0x90, 0x00
            return [], 0x6A, 0x82

    def test_canonical_only_skips_legacy_form(self):
        from seedsigner.helpers.keycard.global_platform import (
            probe_keycard_instance_aids,
        )
        from seedsigner.views.keycard_views import KEYCARD_APPLET_AID as A
        conn = self._Conn([A + bytes([0x01])])
        probe_keycard_instance_aids(conn, canonical_only=True)
        # No 10-byte legacy candidate (prefix + 0x01 + slot) may be SELECTed.
        legacy = [a for a in conn.selected if len(a) == len(A) + 2]
        self.assertEqual(legacy, [])

    def test_stop_after_slots_early_exits(self):
        from seedsigner.helpers.keycard.global_platform import (
            probe_keycard_instance_aids,
        )
        from seedsigner.views.keycard_views import KEYCARD_APPLET_AID as A
        # Instances in slots 1..4; with stop_after_slots=2 the probe must stop
        # after the 2nd distinct slot responds and not SELECT slots 3/4.
        present = [A + bytes([s]) for s in range(1, 5)]
        conn = self._Conn(present)
        hits = probe_keycard_instance_aids(
            conn, canonical_only=True, stop_after_slots=2,
        )
        slots = {h[-1] for h in hits if len(h) > len(A)}
        self.assertEqual(len(slots), 2)
        self.assertNotIn(A + bytes([0x03]), conn.selected)

    def test_uncapped_full_count(self):
        from seedsigner.helpers.keycard.global_platform import (
            probe_keycard_instance_aids,
        )
        from seedsigner.views.keycard_views import KEYCARD_APPLET_AID as A
        # The management/diagnostics path (no cap) sees every slot.
        present = [A + bytes([s]) for s in (1, 3, 5)]
        conn = self._Conn(present)
        hits = probe_keycard_instance_aids(conn)
        slots = {h[-1] for h in hits if len(h) > len(A)}
        self.assertEqual(slots, {1, 3, 5})


class TestCreateInstanceMemoryGate(unittest.TestCase):
    """``ToolsKeycardInstancesCreateView`` memory-awareness: a soft low-space
    warning, the "Create anyway" override, and self-calibration of the
    per-instance footprint from the free-NV delta around INSTALL."""

    def _view(self, existing_count=1):
        from seedsigner.helpers.keycard.global_platform import AppletInstance
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardInstancesCreateView,
        )
        existing = [
            AppletInstance(aid=KEYCARD_APPLET_AID + bytes([s]),
                           life_cycle=7, privileges=0)
            for s in range(1, 1 + existing_count)
        ]
        view = ToolsKeycardInstancesCreateView.__new__(ToolsKeycardInstancesCreateView)
        view.controller = MagicMock()
        view.controller.keycard_measured_instance_nv = None
        return view, existing

    def test_low_space_warns_and_back_cancels(self):
        """When the estimate says there's no room, the first screen is the
        'Low space' warning; backing out aborts without installing."""
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.view import BackStackView
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON

        view, existing = self._view(existing_count=1)
        view.run_screen = MagicMock(return_value=RET_CODE__BACK_BUTTON)
        with patch.object(keycard_views, "_open_isd_channel",
                          return_value=(MagicMock(), existing, MagicMock())), \
             patch.object(keycard_views, "_safe_channel_free_nv",
                          return_value=3000), \
             patch("seedsigner.helpers.keycard.global_platform."
                   "install_for_install_with_fallback") as install_mock:
            dest = view.run()

        self.assertEqual(view.run_screen.call_args_list[0].kwargs["title"], "Low space")
        install_mock.assert_not_called()
        self.assertIs(dest.View_cls, BackStackView)

    def test_sufficient_space_skips_low_space_warning(self):
        from unittest.mock import patch
        from seedsigner.views import keycard_views

        view, existing = self._view(existing_count=1)
        # Non-back sentinel so confirm proceeds through install.
        view.run_screen = MagicMock(return_value=object())
        with patch.object(keycard_views, "_open_isd_channel",
                          return_value=(MagicMock(), existing, MagicMock())), \
             patch.object(keycard_views, "_safe_channel_free_nv",
                          return_value=100000), \
             patch("seedsigner.helpers.keycard.global_platform."
                   "install_for_install_with_fallback") as install_mock:
            view.run()

        titles = [c.kwargs.get("title") for c in view.run_screen.call_args_list]
        self.assertNotIn("Low space", titles)
        self.assertIn("Create instance?", titles)
        install_mock.assert_called_once()

    def test_install_delta_calibrates_per_instance_nv(self):
        from unittest.mock import patch
        from seedsigner.views import keycard_views

        view, existing = self._view(existing_count=1)
        view.run_screen = MagicMock(return_value=object())
        # free_nv read twice: pre-INSTALL baseline, then post-INSTALL.
        with patch.object(keycard_views, "_open_isd_channel",
                          return_value=(MagicMock(), existing, MagicMock())), \
             patch.object(keycard_views, "_safe_channel_free_nv",
                          side_effect=[100000, 98000]), \
             patch("seedsigner.helpers.keycard.global_platform."
                   "install_for_install_with_fallback"):
            view.run()

        # delta 2000 is in [256, 16384] -> stored as the card's per-instance cost.
        self.assertEqual(view.controller.keycard_measured_instance_nv, 2000)

    def test_implausible_delta_ignored(self):
        from unittest.mock import patch
        from seedsigner.views import keycard_views

        view, existing = self._view(existing_count=1)
        view.run_screen = MagicMock(return_value=object())
        # A negative/garbage delta (free went UP) must not poison calibration.
        with patch.object(keycard_views, "_open_isd_channel",
                          return_value=(MagicMock(), existing, MagicMock())), \
             patch.object(keycard_views, "_safe_channel_free_nv",
                          side_effect=[98000, 100000]), \
             patch("seedsigner.helpers.keycard.global_platform."
                   "install_for_install_with_fallback"):
            view.run()

        self.assertIsNone(view.controller.keycard_measured_instance_nv)


class TestProbeKeycardInstanceCountMenuEntry(unittest.TestCase):
    def test_menu_entry_uses_probe_and_never_opens_isd(self):
        """The top menu on entry (cache unknown) must take the cleartext probe
        and NEVER the GP/ISD handshake — the performance contract."""
        from unittest.mock import patch
        from seedsigner.views.keycard_views import (
            ToolsKeycardMenuView, ToolsKeycardSettingsMenuView,
        )
        from seedsigner.views import keycard_views
        import seedsigner.helpers.card_probe as card_probe_mod

        view = ToolsKeycardMenuView.__new__(ToolsKeycardMenuView)
        view.run_screen = MagicMock(return_value=0)  # pick "Ethereum"
        view.controller = MagicMock()
        view.controller.keycard_instance_count = None  # force a probe

        isd_guard = MagicMock(side_effect=AssertionError(
            "menu entry must not open the ISD channel"))
        with patch.object(card_probe_mod, "run_card_gate", return_value=None), \
                patch.object(keycard_views, "_open_isd_channel", isd_guard), \
                patch.object(keycard_views, "_probe_keycard_instance_count",
                             MagicMock(return_value=None)) as probe:
            dest = view.run()
        probe.assert_called_once()
        isd_guard.assert_not_called()
        # Probe → None keeps "Switch instance" visible: index 0 is Ethereum.
        from seedsigner.views.keycard_views import ToolsKeycardEthereumMenuView
        self.assertIs(dest.View_cls, ToolsKeycardEthereumMenuView)


class TestPinLockLifecycle(unittest.TestCase):
    """PIN cache must be droppable on demand (Lock card) and on instance
    switch, so the user can re-enter a different (e.g. duress) PIN without
    a factory reset / reboot."""

    def test_lock_view_wipes_and_returns_to_menu(self):
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardLockView, ToolsKeycardMenuView,
        )

        view = ToolsKeycardLockView.__new__(ToolsKeycardLockView)
        view.controller = MagicMock()
        view.run_screen = MagicMock(return_value=0)

        dest = view.run()

        view.controller.wipe_card_session_secrets.assert_called_once()
        self.assertIs(dest.View_cls, ToolsKeycardMenuView)
        self.assertTrue(dest.clear_history)

    def test_lock_view_name_is_neutral(self):
        """The Lock action must never reveal the decoy/duress wallet:
        no screen string may mention duress/decoy/alt."""
        from seedsigner.views.keycard_views import ToolsKeycardLockView

        view = ToolsKeycardLockView.__new__(ToolsKeycardLockView)
        view.controller = MagicMock()
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured.update(kwargs)
            return 0

        view.run_screen = fake_run_screen
        view.run()

        haystack = (captured.get("title", "") + " " + captured.get("text", "")).lower()
        for forbidden in ("duress", "decoy", "alt"):
            self.assertNotIn(forbidden, haystack)

    def test_instance_switch_wipes_cached_pins(self):
        from unittest.mock import patch

        from seedsigner.helpers.keycard.global_platform import AppletInstance
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardInstancesSwitchView,
        )

        active_aid = KEYCARD_APPLET_AID + b"\x01\x01"
        other_aid = KEYCARD_APPLET_AID + b"\x01\x02"
        instances = [
            AppletInstance(aid=active_aid, life_cycle=0, privileges=0),
            AppletInstance(aid=other_aid, life_cycle=0, privileges=0),
        ]

        view = ToolsKeycardInstancesSwitchView.__new__(ToolsKeycardInstancesSwitchView)
        view.controller = MagicMock()
        view.controller.active_keycard_aid = active_aid
        view.controller.keycard_wallets_data = {}

        # First call (ButtonListScreen) picks index 1 (the *other* instance);
        # any later screen (the "Active set" status) just returns OK.
        calls = {"n": 0}

        def fake_run_screen(screen_cls, **kwargs):
            calls["n"] += 1
            return 1 if calls["n"] == 1 else 0

        view.run_screen = fake_run_screen

        with patch.object(
            keycard_views, "_open_isd_channel",
            return_value=(MagicMock(), instances, MagicMock()),
        ), patch.object(
            keycard_views, "_instances_or_probe_fallback",
            side_effect=lambda controller, inst, conn: inst,
        ):
            view.run()

        # Active instance changed AND the cached PIN(s) were dropped so the
        # next op re-prompts.
        self.assertEqual(view.controller.active_keycard_aid, other_aid)
        view.controller.forget_all_pins.assert_called_once()

    def test_cancelled_instance_switch_does_not_wipe(self):
        """Backing out of the switch must NOT wipe cached PINs."""
        from unittest.mock import patch

        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        from seedsigner.helpers.keycard.global_platform import AppletInstance
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardInstancesSwitchView,
        )

        active_aid = KEYCARD_APPLET_AID + b"\x01\x01"
        instances = [AppletInstance(aid=active_aid, life_cycle=0, privileges=0)]

        view = ToolsKeycardInstancesSwitchView.__new__(ToolsKeycardInstancesSwitchView)
        view.controller = MagicMock()
        view.controller.active_keycard_aid = active_aid
        view.run_screen = MagicMock(return_value=RET_CODE__BACK_BUTTON)

        with patch.object(
            keycard_views, "_open_isd_channel",
            return_value=(MagicMock(), instances, MagicMock()),
        ), patch.object(
            keycard_views, "_instances_or_probe_fallback",
            side_effect=lambda controller, inst, conn: inst,
        ):
            view.run()

        self.assertFalse(view.controller.forget_all_pins.called)


class TestCardSwapDetection(unittest.TestCase):
    """Reader-independent card-swap detection.

    The PC/SC ``removed`` event is unreliable on contactless readers, so a
    swapped card must be caught *synchronously* — both when re-entering the
    Keycard menus and before the View-wallets / View-addresses flows serve
    cached (card-derived) addresses straight from the cache.
    """

    AID = bytes.fromhex("A00000080400010101")

    # ---- detect_card_swap (the extracted primitive) -----------------

    def test_detect_card_swap_wipes_on_change(self):
        from seedsigner.helpers.keycard.ui_helpers import detect_card_swap

        controller = MagicMock()
        controller.last_authenticated_keycard_uid = b"AAAA"
        controller.active_keycard_aid = self.AID

        swapped = detect_card_swap(controller, b"BBBB")

        self.assertTrue(swapped)
        controller.wipe_card_session_secrets.assert_called_once()
        # AID->UID map restored for the active AID against the NEW card.
        controller.remember_aid_for_uid.assert_called_once_with(self.AID, b"BBBB")
        # MUST NOT claim an authenticated session — only open_unlocked_session
        # sets this after a successful VERIFY_PIN.
        self.assertEqual(controller.last_authenticated_keycard_uid, b"AAAA")

    def test_detect_card_swap_noop_on_same_card(self):
        from seedsigner.helpers.keycard.ui_helpers import detect_card_swap

        controller = MagicMock()
        controller.last_authenticated_keycard_uid = b"AAAA"

        self.assertFalse(detect_card_swap(controller, b"AAAA"))
        self.assertFalse(controller.wipe_card_session_secrets.called)

    def test_detect_card_swap_noop_when_no_prior_card(self):
        from seedsigner.helpers.keycard.ui_helpers import detect_card_swap

        controller = MagicMock()
        controller.last_authenticated_keycard_uid = None

        self.assertFalse(detect_card_swap(controller, b"BBBB"))
        self.assertFalse(controller.wipe_card_session_secrets.called)

    # ---- View-wallets warm-cache guard (ETH + BTC) ------------------

    def _make_view(self, view_cls):
        from seedsigner.views.keycard_views import ETH_SCHEME_STANDARD
        view = view_cls.__new__(view_cls)
        view.start_index = 0
        view.selected_button_index = 0
        view.initial_scroll = 0
        view.scheme = ETH_SCHEME_STANDARD  # ETH list reads it; BTC ignores it
        view.mode = "view"  # ETH wallets list reads it; BTC view ignores it
        view.controller = MagicMock()
        view.controller.has_any_keycard_auth.return_value = True
        view.controller.active_keycard_aid = self.AID
        return view

    def _warm_cache(self, view, chain="eth"):
        aid_hex = bytes(self.AID).hex()
        key = aid_hex if chain == "eth" else f"{aid_hex}:{chain}"
        addrs = [f"0xCARD_A_{i:02d}" for i in range(10)]
        view.controller.keycard_wallets_data = {key: list(addrs)}
        return addrs

    def test_eth_wallets_warm_cache_swap_reruns(self):
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardWalletsListView

        view = self._make_view(ToolsKeycardWalletsListView)
        self._warm_cache(view)
        view.run_screen = MagicMock()

        with patch.object(keycard_views, "verify_active_card_unchanged",
                          return_value=True):
            dest = view.run()

        # Swap detected -> re-run (cache is stale) instead of serving it.
        self.assertIs(dest.View_cls, ToolsKeycardWalletsListView)
        self.assertEqual(
            dest.view_args,
            {"start_index": 0, "scheme": "standard", "mode": "view"},
        )
        # The stale addresses were never rendered.
        self.assertFalse(view.run_screen.called)

    def test_eth_wallets_warm_cache_same_card_serves(self):
        from unittest.mock import patch
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardWalletsListView

        view = self._make_view(ToolsKeycardWalletsListView)
        addrs = self._warm_cache(view)
        view.run_screen = MagicMock(return_value=RET_CODE__BACK_BUTTON)

        with patch.object(keycard_views, "verify_active_card_unchanged",
                          return_value=False), \
                patch.object(keycard_views, "_instance_title_suffix",
                             return_value=None):
            view.run()

        # Same card -> serve the cached addresses, no re-derive.
        self.assertEqual(view.run_screen.call_args.kwargs["addresses"], addrs)

    def test_eth_wallets_warm_cache_no_card_toasts(self):
        from unittest.mock import patch
        from seedsigner.helpers.keycard.reader import NoCardError
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardWalletsListView
        from seedsigner.views.view import BackStackView

        view = self._make_view(ToolsKeycardWalletsListView)
        self._warm_cache(view)
        view.run_screen = MagicMock()

        with patch.object(keycard_views, "verify_active_card_unchanged",
                          side_effect=NoCardError("no card")):
            dest = view.run()

        # No-card -> drop cached secrets + subtle toast, stay one step back.
        view.controller.wipe_card_session_secrets.assert_called_once()
        self.assertIs(dest.View_cls, BackStackView)

    def test_btc_addresses_warm_cache_swap_reruns(self):
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardBtcAddressesListView

        view = self._make_view(ToolsKeycardBtcAddressesListView)
        self._warm_cache(view, chain="btc")
        view.run_screen = MagicMock()

        with patch.object(keycard_views, "verify_active_card_unchanged",
                          return_value=True):
            dest = view.run()

        self.assertIs(dest.View_cls, ToolsKeycardBtcAddressesListView)
        self.assertEqual(dest.view_args, {"start_index": 0})
        self.assertFalse(view.run_screen.called)

    # ---- run_card_gate menu-entry guard -----------------------------

    def _gate(self, *, kind, prev_uid, probe_uid):
        from unittest.mock import patch
        from seedsigner.helpers import card_probe
        from seedsigner.helpers.card_probe import ProbeResult

        view = MagicMock()
        view.controller.last_authenticated_keycard_uid = prev_uid
        view.controller.active_keycard_aid = self.AID
        probe = ProbeResult(
            present=True, kind_match=True, initialised=True,
            instance_uid=probe_uid, app_version=3,
        )
        with patch.object(card_probe, "probe_card", return_value=probe):
            dest = card_probe.run_card_gate(
                view, kind, title="Keycard", setup_view=MagicMock(),
            )
        return view, dest

    def test_run_card_gate_keycard_wipes_on_swap(self):
        view, dest = self._gate(kind="keycard", prev_uid=b"AAAA",
                                probe_uid=b"BBBB")
        self.assertIsNone(dest)  # OK path: proceed to the menu
        view.controller.wipe_card_session_secrets.assert_called_once()

    def test_run_card_gate_keycard_no_wipe_on_same_card(self):
        view, dest = self._gate(kind="keycard", prev_uid=b"BBBB",
                                probe_uid=b"BBBB")
        self.assertIsNone(dest)
        self.assertFalse(view.controller.wipe_card_session_secrets.called)

    def test_run_card_gate_seedkeeper_never_swap_checks(self):
        # Different UID, but a SeedKeeper gate must never run the
        # Keycard-specific swap detection.
        view, dest = self._gate(kind="seedkeeper", prev_uid=b"AAAA",
                                probe_uid=b"BBBB")
        self.assertFalse(view.controller.wipe_card_session_secrets.called)


class TestFactoryResetCleanupScope(unittest.TestCase):
    """Factory reset blanks only the *active* instance on-card, so the
    device-side pairing cleanup must be scoped to that instance's UID —
    other instances' saved pairings must survive. When the UID can't be
    determined it falls back to a full clear so a just-blanked card never
    keeps a stale pairing."""

    def _run_reset(self, reset_uid):
        from unittest.mock import patch

        from seedsigner.helpers.keycard import pairing_storage
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardFactoryResetView,
        )

        view = ToolsKeycardFactoryResetView.__new__(ToolsKeycardFactoryResetView)
        view.controller = MagicMock()
        view.controller.active_keycard_aid = KEYCARD_APPLET_AID + b"\x01\x01"
        # run_screen: DireWarning confirm (0, not BACK) then OK (0).
        view.run_screen = MagicMock(return_value=0)

        fake_client = MagicMock()
        fake_client.select_response.instance_uid = reset_uid
        fake_client.factory_reset.return_value = None

        with patch.object(pairing_storage, "remove") as remove_one, \
             patch.object(pairing_storage, "remove_all") as remove_all, \
             patch("seedsigner.helpers.keycard.reader.wait_for_card",
                   return_value=MagicMock()), \
             patch("seedsigner.helpers.keycard.reader.release_other_smartcard_holders"), \
             patch("seedsigner.helpers.keycard.client.KeycardClient",
                   return_value=fake_client), \
             patch.object(keycard_views, "select_with_autodetect"):
            view.run()
        return view.controller, remove_one, remove_all

    def test_known_uid_scopes_cleanup_to_instance(self):
        uid = bytes.fromhex("aabbccddeeff0011")
        controller, remove_one, remove_all = self._run_reset(uid)
        remove_one.assert_called_once_with(instance_uid=uid)
        remove_all.assert_not_called()
        controller.forget_pairing_for.assert_called_once_with(uid)
        controller.forget_all_pairings.assert_not_called()

    def test_unknown_uid_falls_back_to_full_clear(self):
        controller, remove_one, remove_all = self._run_reset(None)
        remove_all.assert_called_once()
        remove_one.assert_not_called()
        controller.forget_all_pairings.assert_called_once()
        controller.forget_pairing_for.assert_not_called()


# EIP-712 "Ether Mail" worked example from the spec.  Also used in
# test_keycard_signer.py — kept inline here because the tests/ directory
# isn't a package, so cross-test imports don't resolve.
_ETHER_MAIL = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Person": [
            {"name": "name", "type": "string"},
            {"name": "wallet", "type": "address"},
        ],
        "Mail": [
            {"name": "from", "type": "Person"},
            {"name": "to", "type": "Person"},
            {"name": "contents", "type": "string"},
        ],
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail", "version": "1", "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    },
    "message": {
        "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
        "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
        "contents": "Hello, Bob!",
    },
}


class TestEthDigestView(unittest.TestCase):
    """ERC-8213: the digest screen inserted between Details and the raw-data
    viewer.  Single page for transactions (Calldata digest); three pages for
    EIP-712 typed-data (digest + domain hash + message hash); skipped for
    legacy tx without calldata, personal-sign, and anything else.
    """

    @staticmethod
    def _make_view(request, page=0):
        from seedsigner.views.keycard_views import ToolsKeycardSignEthDigestView

        view = ToolsKeycardSignEthDigestView.__new__(ToolsKeycardSignEthDigestView)
        view.page = page
        view.run_screen = MagicMock(return_value=0)
        view.controller = MagicMock()
        view.controller.eth_sign_request = request
        return view

    def _make_legacy_request(self, data: bytes):
        from seedsigner.helpers.ethereum.tx_legacy import LegacyTx
        from seedsigner.helpers.ethereum.ur_codec import (
            CryptoKeypath, DATA_TYPE_LEGACY_TX, EthSignRequest,
        )
        tx = LegacyTx(
            nonce=0, gas_price=10**9, gas_limit=100000,
            to=bytes.fromhex("1111111111111111111111111111111111111111"),
            value=0, data=data, chain_id=1,
        )
        return EthSignRequest(
            request_id=b"\xaa" * 16,
            sign_data=tx.signing_bytes(),
            data_type=DATA_TYPE_LEGACY_TX,
            chain_id=1,
            derivation_path=CryptoKeypath(
                components=[44 | 0x80000000, 60 | 0x80000000, 0],
            ),
        )

    def _make_typed_data_request(self):
        import json as _json
        from seedsigner.helpers.ethereum.ur_codec import (
            CryptoKeypath, DATA_TYPE_TYPED_DATA, EthSignRequest,
        )
        ETHER_MAIL = _ETHER_MAIL
        return EthSignRequest(
            request_id=b"\xbb" * 16,
            sign_data=_json.dumps(ETHER_MAIL).encode("utf-8"),
            data_type=DATA_TYPE_TYPED_DATA,
            chain_id=1,
            derivation_path=CryptoKeypath(
                components=[44 | 0x80000000, 60 | 0x80000000, 0],
            ),
        )

    def test_calldata_legacy_shows_one_page(self):
        from seedsigner.helpers.ethereum.erc8213 import compute_calldata_digest

        calldata = bytes.fromhex("a9059cbb" + "00" * 60 + "01" + "00" * 3)
        request = self._make_legacy_request(calldata)
        view = self._make_view(request, page=0)

        from seedsigner.views.keycard_views import ToolsKeycardSignEthConfirmView
        dest = view.run()

        view.run_screen.assert_called_once()
        kwargs = view.run_screen.call_args.kwargs
        digest_hex = compute_calldata_digest(calldata).hex()
        self.assertIn("Calldata digest", kwargs["text"])
        self.assertIn(digest_hex[:32], kwargs["text"])
        self.assertIn(digest_hex[32:], kwargs["text"])
        self.assertEqual(kwargs["title"], "Digest 1/1")
        # Linear wizard: at most two buttons so the hash is never crowded.
        self.assertLessEqual(len(kwargs["button_data"]), 2)
        # Button index 0 is CONTINUE on the (single, last) page; we return 0,
        # so routing goes to the final Confirm gate.
        self.assertIs(dest.View_cls, ToolsKeycardSignEthConfirmView)
        # Button index 1 is the optional "Show data" drill-down.
        view.run_screen.return_value = 1
        dest = view.run()
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthDataView")

    def test_empty_calldata_skips_digest_screen(self):
        request = self._make_legacy_request(b"")
        view = self._make_view(request)

        from seedsigner.views.keycard_views import ToolsKeycardSignEthConfirmView
        dest = view.run()

        view.run_screen.assert_not_called()
        self.assertIs(dest.View_cls, ToolsKeycardSignEthConfirmView)
        self.assertTrue(dest.skip_current_view)

    def test_personal_sign_skips_digest_screen(self):
        from seedsigner.helpers.ethereum.ur_codec import (
            CryptoKeypath, DATA_TYPE_PERSONAL_MESSAGE, EthSignRequest,
        )
        request = EthSignRequest(
            request_id=b"\xcc" * 16,
            sign_data=b"hello",
            data_type=DATA_TYPE_PERSONAL_MESSAGE,
            chain_id=1,
            derivation_path=CryptoKeypath(
                components=[44 | 0x80000000, 60 | 0x80000000, 0],
            ),
        )
        view = self._make_view(request)
        dest = view.run()

        view.run_screen.assert_not_called()
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthConfirmView")
        self.assertTrue(dest.skip_current_view)

    def test_typed_data_three_pages(self):
        from seedsigner.helpers.ethereum import eip712
        ETHER_MAIL = _ETHER_MAIL

        request = self._make_typed_data_request()

        # Page 0: EIP-712 digest.
        view = self._make_view(request, page=0)
        view.run_screen.return_value = 0  # NEXT
        dest = view.run()
        kwargs = view.run_screen.call_args.kwargs
        self.assertEqual(kwargs["title"], "Digest 1/3")
        self.assertIn("EIP-712 digest", kwargs["text"])
        self.assertIn(eip712.signing_hash(ETHER_MAIL).hex()[:32], kwargs["text"])
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthDigestView")
        self.assertEqual(dest.view_args["page"], 1)

        # Page 1: Domain hash.
        view = self._make_view(request, page=1)
        view.run_screen.return_value = 0  # NEXT
        dest = view.run()
        kwargs = view.run_screen.call_args.kwargs
        self.assertEqual(kwargs["title"], "Digest 2/3")
        self.assertIn("Domain hash", kwargs["text"])
        self.assertIn(eip712.domain_separator(ETHER_MAIL).hex()[:32], kwargs["text"])
        self.assertEqual(dest.view_args["page"], 2)

        # Page 2: Message hash — last page, so the primary button is CONTINUE
        # (NEXT is absent) and it advances to the final Confirm gate.
        view = self._make_view(request, page=2)
        view.run_screen.return_value = 0  # CONTINUE
        dest = view.run()
        kwargs = view.run_screen.call_args.kwargs
        self.assertEqual(kwargs["title"], "Digest 3/3")
        self.assertIn("Message hash", kwargs["text"])
        self.assertIn(eip712.message_hash(ETHER_MAIL).hex()[:32], kwargs["text"])
        self.assertLessEqual(len(kwargs["button_data"]), 2)
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthConfirmView")


class TestEthDetailsViewRouting(unittest.TestCase):
    """Details view routes to ToolsKeycardSignEthDecodedView (the human-readable
    decode step) for txs with calldata and for EIP-712 typed-data; the decode
    step then leads on to the digest screens.  Bug where typed-data showed the
    first 64 hex chars of the raw JSON as the "EIP-712 hash" is also gone.
    """

    @staticmethod
    def _make_view(request, click_index=0):
        from seedsigner.views.keycard_views import ToolsKeycardSignEthDetailsView

        view = ToolsKeycardSignEthDetailsView.__new__(ToolsKeycardSignEthDetailsView)
        view.run_screen = MagicMock(return_value=click_index)
        view.controller = MagicMock()
        view.controller.eth_sign_request = request
        return view

    def test_typed_data_does_not_fake_an_eip712_hash(self):
        # The pre-ERC-8213 code printed the first 64 hex chars of the raw
        # JSON payload and labelled it "EIP-712 hash:".  Make sure that
        # exact misleading string is gone.
        import json as _json
        from seedsigner.helpers.ethereum.ur_codec import (
            CryptoKeypath, DATA_TYPE_TYPED_DATA, EthSignRequest,
        )
        ETHER_MAIL = _ETHER_MAIL

        request = EthSignRequest(
            request_id=b"\xdd" * 16,
            sign_data=_json.dumps(ETHER_MAIL).encode("utf-8"),
            data_type=DATA_TYPE_TYPED_DATA,
            chain_id=1,
            derivation_path=CryptoKeypath(
                components=[44 | 0x80000000, 60 | 0x80000000, 0],
            ),
        )
        view = self._make_view(request, click_index=0)  # click SHOW_DIGEST
        dest = view.run()

        kwargs = view.run_screen.call_args.kwargs
        # No bogus hex preview.
        self.assertNotIn("EIP-712 hash:", kwargs["text"])
        # And we DO show the primary type so the user has a sanity hook.
        self.assertIn("EIP-712 typed data", kwargs["text"])
        self.assertIn("Mail", kwargs["text"])
        # Routes onward to the human-readable decode step.
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthDecodedView")

    def test_tx_with_calldata_routes_to_decoded(self):
        # Legacy tx with non-empty data → the decode step is now the
        # entry-point, ahead of the digest screens.
        from seedsigner.helpers.ethereum.tx_legacy import LegacyTx
        from seedsigner.helpers.ethereum.ur_codec import (
            CryptoKeypath, DATA_TYPE_LEGACY_TX, EthSignRequest,
        )
        tx = LegacyTx(
            nonce=0, gas_price=10**9, gas_limit=21000,
            to=bytes.fromhex("11" * 20), value=0,
            data=b"\xde\xad\xbe\xef", chain_id=1,
        )
        request = EthSignRequest(
            request_id=b"\xee" * 16,
            sign_data=tx.signing_bytes(),
            data_type=DATA_TYPE_LEGACY_TX,
            chain_id=1,
            derivation_path=CryptoKeypath(
                components=[44 | 0x80000000, 60 | 0x80000000, 0],
            ),
        )
        view = self._make_view(request, click_index=0)  # Continue
        dest = view.run()
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthDecodedView")


class TestEthDecodedView(unittest.TestCase):
    """Human-readable decode step between Details and the digest screens.

    Known calldata renders the function name + parameters; an unknown selector
    renders a blind-signing warning; EIP-712 typed-data renders message fields.
    Continue → digest screens, "Show data" → raw-hex viewer, and empty calldata
    skips straight to the digest.  Display-only: nothing here is signed.
    """

    USDC = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"

    @staticmethod
    def _make_view(request, page=0, ret=0):
        from seedsigner.views.keycard_views import ToolsKeycardSignEthDecodedView

        view = ToolsKeycardSignEthDecodedView.__new__(ToolsKeycardSignEthDecodedView)
        view.page = page
        view.run_screen = MagicMock(return_value=ret)
        view.controller = MagicMock()
        view.controller.eth_sign_request = request
        return view

    def _legacy_to(self, to_hex: str, data: bytes):
        from seedsigner.helpers.ethereum.tx_legacy import LegacyTx
        from seedsigner.helpers.ethereum.ur_codec import (
            CryptoKeypath, DATA_TYPE_LEGACY_TX, EthSignRequest,
        )
        tx = LegacyTx(
            nonce=0, gas_price=10**9, gas_limit=100000,
            to=bytes.fromhex(to_hex), value=0, data=data, chain_id=1,
        )
        return EthSignRequest(
            request_id=b"\xaa" * 16,
            sign_data=tx.signing_bytes(),
            data_type=DATA_TYPE_LEGACY_TX,
            chain_id=1,
            derivation_path=CryptoKeypath(
                components=[44 | 0x80000000, 60 | 0x80000000, 0],
            ),
        )

    @staticmethod
    def _transfer_calldata(to_hex: str, amount: int) -> bytes:
        from seedsigner.helpers.ethereum.function_registry import function_selector
        return (function_selector("transfer(address,uint256)")
                + bytes(12) + bytes.fromhex(to_hex) + amount.to_bytes(32, "big"))

    def test_known_transfer_decodes_token_aware(self):
        # tx.to is the USDC contract → amount renders with the token symbol.
        data = self._transfer_calldata("11" * 20, 5_000_000)
        request = self._legacy_to(self.USDC, data)

        view = self._make_view(request, page=0, ret=0)  # NEXT (page 0 of 2)
        dest = view.run()
        kwargs = view.run_screen.call_args.kwargs
        self.assertEqual(kwargs["title"], "Decoded 1/2")
        self.assertIn("transfer", kwargs["text"])
        # second page carries the token-aware amount, last-page Continue→Digest
        view = self._make_view(request, page=1, ret=0)  # CONTINUE
        dest = view.run()
        kwargs = view.run_screen.call_args.kwargs
        self.assertIn("5 USDC", kwargs["text"])
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthDigestView")

    def test_show_data_drilldown(self):
        data = self._transfer_calldata("11" * 20, 1)
        request = self._legacy_to(self.USDC, data)
        view = self._make_view(request, page=0, ret=1)  # SHOW_DATA
        dest = view.run()
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthDataView")

    def test_unknown_selector_blind_warning(self):
        request = self._legacy_to("11" * 20, bytes.fromhex("deadbeef") + bytes(32))
        view = self._make_view(request, page=0, ret=0)  # CONTINUE (single page)
        dest = view.run()
        kwargs = view.run_screen.call_args.kwargs
        self.assertIn("Blind signing", kwargs["text"])
        self.assertIn("deadbeef", kwargs["text"])
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthDigestView")

    def test_empty_calldata_skips_to_digest(self):
        request = self._legacy_to("11" * 20, b"")
        view = self._make_view(request)
        dest = view.run()
        view.run_screen.assert_not_called()
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthDigestView")
        self.assertTrue(dest.skip_current_view)

    def test_typed_data_message_pages_then_digest(self):
        import json as _json
        from seedsigner.helpers.ethereum.ur_codec import (
            CryptoKeypath, DATA_TYPE_TYPED_DATA, EthSignRequest,
        )
        request = EthSignRequest(
            request_id=b"\xbb" * 16,
            sign_data=_json.dumps(_ETHER_MAIL).encode("utf-8"),
            data_type=DATA_TYPE_TYPED_DATA,
            chain_id=1,
            derivation_path=CryptoKeypath(
                components=[44 | 0x80000000, 60 | 0x80000000, 0],
            ),
        )
        # Page 0 shows the EIP-712 domain/primary type.
        view = self._make_view(request, page=0, ret=0)  # NEXT
        view.run()
        kwargs = view.run_screen.call_args.kwargs
        self.assertIn("Mail", kwargs["text"])
        # A high page index clamps to the last page → Continue advances to the
        # digest hashes (without needing to know the exact page count).
        view = self._make_view(request, page=99, ret=0)  # CONTINUE on last page
        dest = view.run()
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthDigestView")


def _make_legacy_request(data: bytes):
    """Standalone helper mirroring TestEthDigestView._make_legacy_request so
    the data/confirm test classes can build a request without inheritance."""
    from seedsigner.helpers.ethereum.tx_legacy import LegacyTx
    from seedsigner.helpers.ethereum.ur_codec import (
        CryptoKeypath, DATA_TYPE_LEGACY_TX, EthSignRequest,
    )
    tx = LegacyTx(
        nonce=0, gas_price=10**9, gas_limit=100000,
        to=bytes.fromhex("11" * 20),
        value=0, data=data, chain_id=1,
    )
    return EthSignRequest(
        request_id=b"\xaa" * 16,
        sign_data=tx.signing_bytes(),
        data_type=DATA_TYPE_LEGACY_TX,
        chain_id=1,
        derivation_path=CryptoKeypath(
            components=[44 | 0x80000000, 60 | 0x80000000, 0],
        ),
    )


class TestEthDataView(unittest.TestCase):
    """Optional raw-data drill-down.  Linear-wizard navigation: one primary
    button (Next page / Continue), top-nav back walks back a page; never more
    than one list button so the hex is never crowded."""

    @staticmethod
    def _make_view(request, page=0, ret=0):
        from seedsigner.views.keycard_views import ToolsKeycardSignEthDataView

        view = ToolsKeycardSignEthDataView.__new__(ToolsKeycardSignEthDataView)
        view.page = page
        view.run_screen = MagicMock(return_value=ret)
        view.controller = MagicMock()
        view.controller.eth_sign_request = request
        return view

    def test_multi_page_next_then_continue(self):
        # 200 bytes of calldata → 400 hex chars → ceil(400/96) = 5 pages.
        request = _make_legacy_request(bytes(range(200)))

        # First page: NEXT advances; single list button.
        view = self._make_view(request, page=0, ret=0)
        dest = view.run()
        kwargs = view.run_screen.call_args.kwargs
        self.assertEqual(kwargs["title"], "Data 1/5")
        self.assertEqual(len(kwargs["button_data"]), 1)
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthDataView")
        self.assertEqual(dest.view_args["page"], 1)
        # Pages push normally (no skip) so back walks back one page at a time.
        self.assertFalse(getattr(dest, "skip_current_view", False))

        # Last page: CONTINUE advances to the Confirm gate.
        view = self._make_view(request, page=4, ret=0)
        dest = view.run()
        kwargs = view.run_screen.call_args.kwargs
        self.assertEqual(kwargs["title"], "Data 5/5")
        self.assertEqual(len(kwargs["button_data"]), 1)
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthConfirmView")

    def test_back_returns_to_back_stack(self):
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        from seedsigner.views.view import BackStackView

        request = _make_legacy_request(bytes(range(200)))
        view = self._make_view(request, page=2, ret=RET_CODE__BACK_BUTTON)
        dest = view.run()
        self.assertIs(dest.View_cls, BackStackView)

    def test_empty_data_skips_to_confirm(self):
        request = _make_legacy_request(b"")
        view = self._make_view(request, page=0)
        dest = view.run()
        view.run_screen.assert_not_called()
        self.assertEqual(dest.View_cls.__name__, "ToolsKeycardSignEthConfirmView")
        self.assertTrue(dest.skip_current_view)


class TestEthConfirmView(unittest.TestCase):
    """Final confirmation gate: one action, advances to Finalize; back arrow
    returns to the previous review step."""

    @staticmethod
    def _make_view(request, ret=0):
        from seedsigner.views.keycard_views import ToolsKeycardSignEthConfirmView

        view = ToolsKeycardSignEthConfirmView.__new__(ToolsKeycardSignEthConfirmView)
        view.run_screen = MagicMock(return_value=ret)
        view.controller = MagicMock()
        view.controller.eth_sign_request = request
        return view

    def test_confirm_advances_to_finalize(self):
        from seedsigner.views.keycard_views import ToolsKeycardSignEthFinalizeView

        request = _make_legacy_request(b"\xde\xad\xbe\xef")
        view = self._make_view(request, ret=0)
        dest = view.run()
        kwargs = view.run_screen.call_args.kwargs
        self.assertEqual(kwargs["title"], "Confirm")
        self.assertEqual(len(kwargs["button_data"]), 1)
        self.assertIs(dest.View_cls, ToolsKeycardSignEthFinalizeView)

    def test_back_returns_to_back_stack(self):
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        from seedsigner.views.view import BackStackView

        request = _make_legacy_request(b"\xde\xad\xbe\xef")
        view = self._make_view(request, ret=RET_CODE__BACK_BUTTON)
        dest = view.run()
        self.assertIs(dest.View_cls, BackStackView)


class TestEthSignButtonBudget(unittest.TestCase):
    """Regression guard: the text-behind-buttons bug was caused by stacking
    up to five buttons on LargeIconStatusScreen, which collapsed the TextArea.
    Every signing review screen must keep at most two list buttons."""

    def _button_data(self, view):
        view.run()
        return view.run_screen.call_args.kwargs["button_data"]

    def test_overview_and_details_single_button(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSignEthOverviewView, ToolsKeycardSignEthDetailsView,
        )
        request = _make_legacy_request(b"\xde\xad\xbe\xef")
        for cls in (ToolsKeycardSignEthOverviewView, ToolsKeycardSignEthDetailsView):
            view = cls.__new__(cls)
            view.run_screen = MagicMock(return_value=0)
            view.controller = MagicMock()
            view.controller.eth_sign_request = request
            self.assertLessEqual(len(self._button_data(view)), 2, cls.__name__)

    def test_digest_pages_at_most_two_buttons(self):
        from seedsigner.helpers.ethereum.ur_codec import (
            CryptoKeypath, DATA_TYPE_TYPED_DATA, EthSignRequest,
        )
        import json as _json
        from seedsigner.views.keycard_views import ToolsKeycardSignEthDigestView

        request = EthSignRequest(
            request_id=b"\xbb" * 16,
            sign_data=_json.dumps(_ETHER_MAIL).encode("utf-8"),
            data_type=DATA_TYPE_TYPED_DATA,
            chain_id=1,
            derivation_path=CryptoKeypath(
                components=[44 | 0x80000000, 60 | 0x80000000, 0],
            ),
        )
        for page in range(3):
            view = ToolsKeycardSignEthDigestView.__new__(ToolsKeycardSignEthDigestView)
            view.page = page
            view.run_screen = MagicMock(return_value=0)
            view.controller = MagicMock()
            view.controller.eth_sign_request = request
            view.run()
            button_data = view.run_screen.call_args.kwargs["button_data"]
            self.assertLessEqual(len(button_data), 2, f"page {page}")


class TestBtcSignMessageScanRouting(unittest.TestCase):
    """Sparrow generates ``signmessage <path> ascii:<msg>`` QRs, which the
    decoder surfaces as ``QRType.SIGN_MESSAGE``. The pre-fix scan view only
    accepted ``is_text`` / ``is_bytes`` and bailed out with
    "Unsupported encoding. Message must be UTF-8 text.". These tests pin
    the accepted QR types and the path propagation so the regression
    cannot come back.
    """

    @staticmethod
    def _make_scan_view(decoder):
        from seedsigner.views.keycard_views import ToolsKeycardBtcSignMessageScanView

        view = ToolsKeycardBtcSignMessageScanView.__new__(
            ToolsKeycardBtcSignMessageScanView,
        )
        view.decoder = decoder
        view.controller = MagicMock()
        view.run_screen = MagicMock(return_value=0)
        return view

    def test_sign_message_qr_is_accepted(self):
        decoder = MagicMock()
        decoder.is_sign_message = True
        decoder.is_text = False
        decoder.is_bytes = False
        view = self._make_scan_view(decoder)
        self.assertTrue(view.is_valid_qr_type)

    def test_sparrow_qr_routes_to_finalize_with_path(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardBtcSignMessageFinalizeView,
        )

        decoder = MagicMock()
        decoder.is_complete = True
        decoder.is_sign_message = True
        decoder.is_text = False
        decoder.is_bytes = False
        decoder.get_qr_data.return_value = {
            "derivation_path": "m/84'/0'/0'/0/0",
            "message": "Hello from Sparrow",
        }
        view = self._make_scan_view(decoder)

        dest = view.run()

        self.assertIs(dest.View_cls, ToolsKeycardBtcSignMessageFinalizeView)
        self.assertEqual(dest.view_args["message"], "Hello from Sparrow")
        self.assertEqual(dest.view_args["derivation_path"], "m/84'/0'/0'/0/0")

    def test_finalize_view_uses_qr_path_when_provided(self):
        from unittest.mock import patch

        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardBtcSignMessageFinalizeView,
        )

        view = ToolsKeycardBtcSignMessageFinalizeView.__new__(
            ToolsKeycardBtcSignMessageFinalizeView,
        )
        view.message = "hello"
        view.derivation_path = "m/84'/0'/0'/0/3"
        view.controller = MagicMock()
        view.controller.has_any_keycard_auth.return_value = True
        view.run_screen = MagicMock(return_value=0)

        fake_client = MagicMock()
        sign_calls = []

        def fake_sign(client, message, path):
            sign_calls.append((message, path))
            return "Hb64sig=="

        with patch.object(
            keycard_views, "_open_unlocked_session_cached_or_prompt",
            return_value=(fake_client, MagicMock()),
        ), patch(
            "seedsigner.helpers.keycard_btc_signer.sign_message",
            side_effect=fake_sign,
        ):
            view.run()

        self.assertEqual(sign_calls, [("hello", "m/84'/0'/0'/0/3")])

    def test_finalize_view_falls_back_to_default_path(self):
        from unittest.mock import patch

        from seedsigner.helpers.bitcoin import DEFAULT_BTC_PATH
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardBtcSignMessageFinalizeView,
        )

        view = ToolsKeycardBtcSignMessageFinalizeView.__new__(
            ToolsKeycardBtcSignMessageFinalizeView,
        )
        view.message = "hello"
        view.derivation_path = None
        view.controller = MagicMock()
        view.controller.has_any_keycard_auth.return_value = True
        view.run_screen = MagicMock(return_value=0)

        sign_calls = []

        def fake_sign(client, message, path):
            sign_calls.append((message, path))
            return "Hb64sig=="

        with patch.object(
            keycard_views, "_open_unlocked_session_cached_or_prompt",
            return_value=(MagicMock(), MagicMock()),
        ), patch(
            "seedsigner.helpers.keycard_btc_signer.sign_message",
            side_effect=fake_sign,
        ):
            view.run()

        self.assertEqual(sign_calls, [("hello", DEFAULT_BTC_PATH)])


class TestWrongCardDetection(unittest.TestCase):
    """Reject a scanned ETH request / BTC PSBT that belongs to a *different*
    wallet than the one on the active card, BEFORE signing — replicating
    keycard-shell's early 'wrong keycard' reject (which today only surfaces
    much later, on the online app, after we've already signed and shown a QR).
    """

    # 0x04-prefixed uncompressed pubkey; arbitrary bytes (no curve check in
    # compress_pubkey / pubkey_to_address, both are pure hashes).
    PUB65 = b"\x04" + bytes(range(64))

    class _FakeClient:
        """Stand-in Keycard client: records derivations, returns a fixed
        pubkey in the bare ``0x80 0x41 04...`` TLV form accepted by both
        ``extract_pubkey`` and ``keycard_btc_signer._parse_pubkey_only``."""

        def __init__(self, pub65):
            self.pub65 = pub65
            self.derived = []

        def derive_key(self, components, source=0):
            self.derived.append(list(components))

        def export_pubkey(self, path_components=None, extended=False):
            return bytes([0x80, 0x41]) + self.pub65

    def _make_request(self, *, address=None, source_fingerprint=None):
        from seedsigner.helpers.ethereum.ur_codec import (
            CryptoKeypath, DATA_TYPE_LEGACY_TX, EthSignRequest,
        )
        return EthSignRequest(
            request_id=b"\x11" * 16,
            sign_data=b"\x00",
            data_type=DATA_TYPE_LEGACY_TX,
            chain_id=1,
            derivation_path=CryptoKeypath(
                components=[44 | 0x80000000, 60 | 0x80000000, 0 | 0x80000000, 0, 0],
                source_fingerprint=source_fingerprint,
            ),
            address=address,
        )

    # ---- card-identity helpers --------------------------------------

    def test_card_eth_address_matches_local_derivation(self):
        from seedsigner.views import keycard_views
        from seedsigner.helpers.ethereum.address import (
            pubkey_to_address, to_checksum_address,
        )
        client = self._FakeClient(self.PUB65)
        components = [44 | 0x80000000, 60 | 0x80000000, 0 | 0x80000000, 0, 0]
        addr = keycard_views._card_eth_address_at(client, components)
        self.assertEqual(addr, to_checksum_address(pubkey_to_address(self.PUB65)))
        # Derived at the requested full path (from master).
        self.assertEqual(client.derived[-1], components)

    def test_card_master_fingerprint(self):
        from seedsigner.views import keycard_views
        from seedsigner.helpers.bitcoin import xpub as btc_xpub
        from seedsigner.helpers.keycard_btc_signer import compress_pubkey
        client = self._FakeClient(self.PUB65)
        fp = keycard_views._card_master_fingerprint(client)
        self.assertEqual(fp, btc_xpub.pubkey_fingerprint(compress_pubkey(self.PUB65)))
        # Derived from the master (empty path).
        self.assertEqual(client.derived[-1], [])

    # ---- _eth_request_card_mismatch ---------------------------------

    def test_mismatch_by_address(self):
        from seedsigner.views import keycard_views
        client = self._FakeClient(self.PUB65)
        req = self._make_request(address=b"\x42" * 20)  # not our derived addr
        self.assertTrue(keycard_views._eth_request_card_mismatch(client, req))

    def test_match_by_address(self):
        from seedsigner.views import keycard_views
        from seedsigner.helpers.ethereum.address import pubkey_to_address
        client = self._FakeClient(self.PUB65)
        req = self._make_request(address=pubkey_to_address(self.PUB65))
        self.assertFalse(keycard_views._eth_request_card_mismatch(client, req))

    def test_mismatch_by_fingerprint(self):
        from seedsigner.views import keycard_views
        client = self._FakeClient(self.PUB65)
        req = self._make_request(source_fingerprint=b"\xde\xad\xbe\xef")
        self.assertTrue(keycard_views._eth_request_card_mismatch(client, req))

    def test_match_by_fingerprint(self):
        from seedsigner.views import keycard_views
        from seedsigner.helpers.bitcoin import xpub as btc_xpub
        from seedsigner.helpers.keycard_btc_signer import compress_pubkey
        client = self._FakeClient(self.PUB65)
        fp = btc_xpub.pubkey_fingerprint(compress_pubkey(self.PUB65))
        req = self._make_request(source_fingerprint=fp)
        self.assertFalse(keycard_views._eth_request_card_mismatch(client, req))

    def test_no_identity_cannot_verify_proceeds(self):
        """A request carrying neither address nor fingerprint can't be
        verified — don't block a possibly-valid signature, and don't even
        touch the card."""
        from seedsigner.views import keycard_views
        client = self._FakeClient(self.PUB65)
        req = self._make_request()
        self.assertFalse(keycard_views._eth_request_card_mismatch(client, req))
        self.assertEqual(client.derived, [])

    def test_mismatch_by_int_fingerprint(self):
        """Real wallets (Keystone/Frame/keycard-shell) encode the fingerprint
        as a uint32 → it decodes to an int. Must compare correctly and NOT
        crash on bytes(<int>). This is the case the device hit in the wild."""
        from seedsigner.views import keycard_views
        client = self._FakeClient(self.PUB65)
        # 0xDEADBEEF as an int, NOT bytes — differs from the card fp.
        req = self._make_request(source_fingerprint=0xDEADBEEF)
        self.assertTrue(keycard_views._eth_request_card_mismatch(client, req))

    def test_match_by_int_fingerprint(self):
        from seedsigner.views import keycard_views
        from seedsigner.helpers.bitcoin import xpub as btc_xpub
        from seedsigner.helpers.keycard_btc_signer import compress_pubkey
        client = self._FakeClient(self.PUB65)
        fp_int = int.from_bytes(
            btc_xpub.pubkey_fingerprint(compress_pubkey(self.PUB65)), "big"
        )
        req = self._make_request(source_fingerprint=fp_int)
        self.assertFalse(keycard_views._eth_request_card_mismatch(client, req))

    def test_address_preferred_over_fingerprint(self):
        """With both present the address is authoritative (also catches a
        wrong derivation path): a matching fingerprint must NOT rescue a
        mismatched address."""
        from seedsigner.views import keycard_views
        from seedsigner.helpers.bitcoin import xpub as btc_xpub
        from seedsigner.helpers.keycard_btc_signer import compress_pubkey
        client = self._FakeClient(self.PUB65)
        matching_fp = btc_xpub.pubkey_fingerprint(compress_pubkey(self.PUB65))
        req = self._make_request(address=b"\x42" * 20, source_fingerprint=matching_fp)
        self.assertTrue(keycard_views._eth_request_card_mismatch(client, req))

    # ---- ETH verify-card view routing -------------------------------

    def _make_verify_view(self, request):
        from seedsigner.views.keycard_views import ToolsKeycardSignEthVerifyCardView
        view = ToolsKeycardSignEthVerifyCardView.__new__(ToolsKeycardSignEthVerifyCardView)
        view.controller = MagicMock()
        view.controller.eth_sign_request = request
        view.controller.has_any_keycard_auth.return_value = True
        return view

    def test_scan_routes_to_verify_view(self):
        from seedsigner.views.keycard_views import (
            ScanEthSignRequestView, ToolsKeycardSignEthVerifyCardView,
        )
        view = ScanEthSignRequestView.__new__(ScanEthSignRequestView)
        view.run_screen = MagicMock()
        view.controller = MagicMock()
        view.decoder = MagicMock()
        view.decoder.is_complete = True
        req = self._make_request(address=b"\x42" * 20)
        view.decoder.get_eth_sign_request.return_value = req
        dest = view.run()
        self.assertIs(view.controller.eth_sign_request, req)
        self.assertIs(dest.View_cls, ToolsKeycardSignEthVerifyCardView)

    def test_verify_view_mismatch_routes_to_error_and_clears(self):
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import KeycardErrorView
        req = self._make_request(address=b"\x42" * 20)
        view = self._make_verify_view(req)
        with patch.object(
            keycard_views, "_open_unlocked_session_cached_or_prompt",
            return_value=(MagicMock(), MagicMock()),
        ), patch.object(
            keycard_views, "_eth_request_card_mismatch", return_value=True,
        ):
            dest = view.run()
        self.assertIs(dest.View_cls, KeycardErrorView)
        self.assertEqual(dest.view_args["title"], "Wrong card")
        self.assertTrue(dest.view_args["return_to_main"])
        # Bad request dropped so it can't leak into a later flow.
        self.assertIsNone(view.controller.eth_sign_request)

    def test_verify_view_match_routes_to_overview(self):
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardSignEthOverviewView
        req = self._make_request(address=b"\x42" * 20)
        view = self._make_verify_view(req)
        with patch.object(
            keycard_views, "_open_unlocked_session_cached_or_prompt",
            return_value=(MagicMock(), MagicMock()),
        ), patch.object(
            keycard_views, "_eth_request_card_mismatch", return_value=False,
        ):
            dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardSignEthOverviewView)
        self.assertIs(view.controller.eth_sign_request, req)

    def test_verify_view_no_card_preserves_request_and_stays(self):
        from unittest.mock import patch
        from seedsigner.helpers.keycard.reader import NoCardError
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardSignEthVerifyCardView
        req = self._make_request(address=b"\x42" * 20)
        view = self._make_verify_view(req)
        with patch.object(
            keycard_views, "_open_unlocked_session_cached_or_prompt",
            side_effect=NoCardError("no card"),
        ), patch("seedsigner.gui.toast.InfoToast", MagicMock()):
            dest = view.run()
        # Request preserved + stay on the verify view → retry without re-scan.
        self.assertIs(view.controller.eth_sign_request, req)
        self.assertIs(dest.View_cls, ToolsKeycardSignEthVerifyCardView)
        self.assertTrue(view.controller.activate_toast.called)

    # ---- Finalize defense in depth ----------------------------------

    def test_finalize_rejects_mismatch_without_signing(self):
        """Even if the verify view were bypassed, Finalize must re-check and
        refuse to sign for another wallet."""
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardSignEthFinalizeView, KeycardErrorView,
        )
        req = self._make_request(source_fingerprint=0xDEADBEEF)
        view = ToolsKeycardSignEthFinalizeView.__new__(ToolsKeycardSignEthFinalizeView)
        view.controller = MagicMock()
        view.controller.eth_sign_request = req
        view.controller.has_any_keycard_auth.return_value = True
        with patch.object(
            keycard_views, "_open_unlocked_session_cached_or_prompt",
            return_value=(MagicMock(), MagicMock()),
        ), patch.object(
            keycard_views, "_eth_request_card_mismatch", return_value=True,
        ), patch(
            "seedsigner.helpers.keycard_signer.sign_with_keycard",
        ) as mock_sign:
            dest = view.run()
        mock_sign.assert_not_called()
        self.assertIs(dest.View_cls, KeycardErrorView)
        self.assertEqual(dest.view_args["title"], "Wrong card")
        self.assertIsNone(view.controller.eth_sign_request)

    def test_finalize_signs_when_match(self):
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardSignEthFinalizeView, ToolsKeycardSignEthQrDisplayView,
        )
        req = self._make_request(source_fingerprint=0xDEADBEEF)
        view = ToolsKeycardSignEthFinalizeView.__new__(ToolsKeycardSignEthFinalizeView)
        view.controller = MagicMock()
        view.controller.eth_sign_request = req
        view.controller.has_any_keycard_auth.return_value = True
        with patch.object(
            keycard_views, "_open_unlocked_session_cached_or_prompt",
            return_value=(MagicMock(), MagicMock()),
        ), patch.object(
            keycard_views, "_eth_request_card_mismatch", return_value=False,
        ), patch(
            "seedsigner.helpers.keycard_signer.sign_with_keycard",
            return_value=MagicMock(),
        ) as mock_sign:
            dest = view.run()
        mock_sign.assert_called_once()
        self.assertIs(dest.View_cls, ToolsKeycardSignEthQrDisplayView)

    # ---- BTC PSBT ownership check -----------------------------------

    class _FakeDer:
        def __init__(self, fp):
            self.fingerprint = fp

    class _FakeInput:
        def __init__(self, fps):
            self.bip32_derivations = {i: TestWrongCardDetection._FakeDer(fp)
                                      for i, fp in enumerate(fps)}

    class _FakePsbt:
        def __init__(self, inputs):
            self.inputs = inputs

    def _make_btc_review_view(self, psbt):
        from seedsigner.views.keycard_views import ToolsKeycardBtcSignPsbtReviewView
        view = ToolsKeycardBtcSignPsbtReviewView.__new__(ToolsKeycardBtcSignPsbtReviewView)
        view.controller = MagicMock()
        view.controller.has_any_keycard_auth.return_value = True
        view.controller.psbt = psbt
        return view

    def test_btc_review_rejects_wrong_wallet(self):
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import KeycardErrorView
        card_fp = b"\xaa\xbb\xcc\xdd"
        other_fp = b"\x11\x22\x33\x44"
        view = self._make_btc_review_view(self._FakePsbt([self._FakeInput([other_fp])]))
        with patch.object(
            keycard_views, "_open_unlocked_session_cached_or_prompt",
            return_value=(MagicMock(), MagicMock()),
        ), patch.object(
            keycard_views, "_card_master_fingerprint", return_value=card_fp,
        ):
            dest = view.run()
        self.assertIs(dest.View_cls, KeycardErrorView)
        self.assertEqual(dest.view_args["title"], "Wrong card")
        self.assertTrue(dest.view_args["return_to_main"])
        self.assertIsNone(view.controller.psbt)

    def test_btc_review_accepts_matching_wallet(self):
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardBtcSignPsbtFinalizeView
        from seedsigner.helpers.bitcoin import psbt_helpers
        card_fp = b"\xaa\xbb\xcc\xdd"
        view = self._make_btc_review_view(self._FakePsbt([self._FakeInput([card_fp])]))
        view.run_screen = MagicMock(return_value=0)  # press "Sign"
        fake_parsed = MagicMock()
        fake_parsed.inputs = []
        fake_parsed.outputs = []
        fake_parsed.fee_sats = 0
        with patch.object(
            keycard_views, "_open_unlocked_session_cached_or_prompt",
            return_value=(MagicMock(), MagicMock()),
        ), patch.object(
            keycard_views, "_card_master_fingerprint", return_value=card_fp,
        ), patch.object(psbt_helpers, "extract", return_value=fake_parsed):
            dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardBtcSignPsbtFinalizeView)

    def test_btc_review_no_hints_keeps_extract_error(self):
        """A PSBT with NO bip32 derivations anywhere must keep extract()'s
        own 'missing hints' error, not be mislabeled 'Wrong card'."""
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import KeycardErrorView
        from seedsigner.helpers.bitcoin import psbt_helpers
        view = self._make_btc_review_view(self._FakePsbt([self._FakeInput([])]))
        with patch.object(
            keycard_views, "_open_unlocked_session_cached_or_prompt",
            return_value=(MagicMock(), MagicMock()),
        ), patch.object(
            keycard_views, "_card_master_fingerprint", return_value=b"\xaa\xbb\xcc\xdd",
        ), patch.object(
            psbt_helpers, "extract",
            side_effect=ValueError("input 0: PSBT missing BIP-32 derivation hints"),
        ):
            dest = view.run()
        self.assertIs(dest.View_cls, KeycardErrorView)
        self.assertEqual(dest.view_args["title"], "PSBT rejected")


class TestInstanceNameResolution(unittest.TestCase):
    """Regression cover for the instance-name→AID resolution bugs:

    * a name must never bleed from one instance onto another via the
      global ``last_keycard_uid`` (the "merging the device id with the
      name" symptom);
    * enumeration must resolve **every** instance's UID so non-active rows
      show their real name, not just ``Inst N``;
    * card-specific AID→UID state must be cleared on swap so a re-inserted
      different card can't render the previous card's name.
    """

    def _bare_controller(self):
        """A Controller with only the attributes the name path touches —
        avoids the heavy ``get_instance()`` singleton/thread setup."""
        from seedsigner.controller import Controller
        from seedsigner.helpers.keycard.commands import APPLET_AID
        c = Controller.__new__(Controller)
        c.keycard_aid_to_uid = {}
        c.keycard_instance_names = {}
        c.last_keycard_uid = None
        c.active_keycard_aid = APPLET_AID
        return c

    def test_name_does_not_bleed_via_last_keycard_uid(self):
        """The active AID with NO exact AID→UID entry must resolve to None
        even when ``last_keycard_uid`` points at a *different*, named
        instance — no fallback guess."""
        from unittest.mock import patch
        c = self._bare_controller()
        other_uid = b"\x22" * 16
        c.last_keycard_uid = other_uid  # a different instance was selected
        # other_uid HAS a name on disk; the active AID has no mapping.
        with patch(
            "seedsigner.helpers.keycard.instance_names.get_name",
            return_value="Other",
        ) as get_name:
            self.assertIsNone(c.get_instance_name_for_aid(c.active_keycard_aid))
        get_name.assert_not_called()  # never even looked the other name up

    def test_name_resolves_for_mapped_aid(self):
        """Positive path: once an AID→UID entry exists, the disk name is
        returned and cached."""
        from unittest.mock import patch
        c = self._bare_controller()
        uid = b"\x11" * 16
        c.remember_aid_for_uid(c.active_keycard_aid, uid)
        with patch(
            "seedsigner.helpers.keycard.instance_names.get_name",
            return_value="Cold",
        ) as get_name:
            self.assertEqual(c.get_instance_name_for_aid(c.active_keycard_aid), "Cold")
            # Cached: a second read does not hit disk again.
            self.assertEqual(c.get_instance_name_for_aid(c.active_keycard_aid), "Cold")
        get_name.assert_called_once()

    def test_select_with_autodetect_records_aid_to_uid(self):
        """Every successful SELECT must record the AID→UID mapping, so the
        active instance's name resolves without the removed fallback."""
        from types import SimpleNamespace
        from seedsigner.helpers.keycard.ui_helpers import select_with_autodetect
        c = self._bare_controller()
        uid = b"\x33" * 16

        class FakeClient:
            def select(self, aid=None):
                return SimpleNamespace(instance_uid=uid)

        info = select_with_autodetect(FakeClient(), c)
        self.assertEqual(info.instance_uid, uid)
        self.assertEqual(c.get_uid_for_aid(c.active_keycard_aid), uid)

    def test_wipe_clears_aid_to_uid_and_last_uid(self):
        """Card-removed wipe drops the AID→UID map and last UID — a swapped
        card reuses the same AIDs with different UIDs."""
        c = self._bare_controller()
        c.keycard_pins = {}
        c.keycard_wallets_data = {}
        c.keycard_instance_count = 3
        c.keycard_measured_instance_nv = 2000
        c.forget_satochip_session = lambda: None
        c.keycard_aid_to_uid = {c.active_keycard_aid: b"\x44" * 16}
        c.keycard_instance_names = {b"\x44" * 16: "Hot"}
        c.last_keycard_uid = b"\x44" * 16

        c.wipe_card_session_secrets()

        self.assertEqual(c.keycard_aid_to_uid, {})
        self.assertIsNone(c.last_keycard_uid)
        self.assertEqual(c.keycard_instance_names, {})
        # Per-instance NV calibration is card-specific -> dropped on swap.
        self.assertIsNone(c.keycard_measured_instance_nv)
        self.assertIsNone(c.keycard_instance_count)

    def test_resolve_instance_uids_selects_each_aid(self):
        """``_resolve_instance_uids`` SELECTs every AID and records its UID;
        a per-AID failure is swallowed (that row stays ``Inst N``)."""
        from types import SimpleNamespace
        from seedsigner.views.keycard_views import (
            _resolve_instance_uids, KEYCARD_APPLET_AID,
        )
        from seedsigner.helpers.keycard.client import KeycardClient
        from unittest.mock import patch
        c = self._bare_controller()
        aid1 = KEYCARD_APPLET_AID + b"\x01\x01"
        aid2 = KEYCARD_APPLET_AID + b"\x01\x02"
        uids = {aid1: b"\xa1" * 16, aid2: b"\xa2" * 16}

        def fake_select(self, aid=None):
            if aid not in uids:
                raise RuntimeError("boom")
            return SimpleNamespace(instance_uid=uids[aid])

        with patch.object(KeycardClient, "select", fake_select):
            _resolve_instance_uids(c, MagicMock(), [aid1, aid2])

        self.assertEqual(c.get_uid_for_aid(aid1), uids[aid1])
        self.assertEqual(c.get_uid_for_aid(aid2), uids[aid2])

    def test_switch_view_shows_real_names_for_all_instances(self):
        """End-to-end: the Switch list resolves UIDs for every instance, so
        BOTH rows render their stored name — not just the active one."""
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardInstancesSwitchView, KEYCARD_APPLET_AID,
        )
        from seedsigner.helpers.keycard.global_platform import AppletInstance

        aid1 = KEYCARD_APPLET_AID + b"\x01\x01"
        aid2 = KEYCARD_APPLET_AID + b"\x01\x02"
        uid1, uid2 = b"\xb1" * 16, b"\xb2" * 16
        names = {uid1: "Alice", uid2: "Bob"}
        instances = [
            AppletInstance(aid=aid1, life_cycle=0, privileges=0),
            AppletInstance(aid=aid2, life_cycle=0, privileges=0),
        ]

        c = self._bare_controller()
        # Active is neither row, so neither gets the "» " active marker.
        c.active_keycard_aid = KEYCARD_APPLET_AID + b"\x01\x09"

        view = ToolsKeycardInstancesSwitchView.__new__(ToolsKeycardInstancesSwitchView)
        view.controller = c
        captured = {}

        from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON

        def fake_run_screen(screen_cls, **kwargs):
            captured["button_data"] = kwargs["button_data"]
            return RET_CODE__BACK_BUTTON

        view.run_screen = fake_run_screen

        def fake_resolve(controller, connection, aids):
            controller.remember_aid_for_uid(aid1, uid1)
            controller.remember_aid_for_uid(aid2, uid2)

        with patch.object(
            keycard_views, "_open_isd_channel",
            return_value=(MagicMock(), instances, MagicMock()),
        ), patch.object(
            keycard_views, "_resolve_instance_uids", side_effect=fake_resolve,
        ), patch(
            "seedsigner.helpers.keycard.instance_names.get_name",
            side_effect=lambda uid, **kw: names.get(bytes(uid)),
        ):
            view.run()

        labels = [b.button_label for b in captured["button_data"]]
        self.assertEqual(labels, ["Alice", "Bob"])


class TestInstanceAidAllocation(unittest.TestCase):
    """Regression cover for the instance-AID collision bug: a new instance
    must never reuse an occupied slot and must mint the 9-byte canonical form.
    Now that both the boot default and every minted instance use the 9-byte
    form, slot 1 (the first instance) legitimately equals ``APPLET_AID`` — the
    old "must differ from the 10-byte default" invariant no longer applies."""

    def _prefix(self):
        from seedsigner.views.keycard_views import KEYCARD_APPLET_AID
        return KEYCARD_APPLET_AID

    def test_next_free_aid_skips_9byte_occupied_slots(self):
        """The exact trezor-card failure: three 9-byte instances occupy slots
        1-3, so the next AID is the 9-byte slot 4 — NOT a colliding ...0101."""
        from seedsigner.views.keycard_views import _next_free_instance_aid
        from seedsigner.helpers.keycard.commands import APPLET_AID
        p = self._prefix()
        existing = [p + bytes([0x01]), p + bytes([0x02]), p + bytes([0x03])]
        result = _next_free_instance_aid(existing)
        self.assertEqual(result, p + bytes([0x04]))
        self.assertEqual(len(result), len(p) + 1)       # 9-byte canonical
        self.assertNotIn(result, existing)
        self.assertNotEqual(result, APPLET_AID)         # slot 4, not the slot-1 default

    def test_next_free_aid_never_emits_existing(self):
        """A 9-byte and a 10-byte AID at the SAME slot 1 → next is slot 2,
        and never equals either existing AID."""
        from seedsigner.views.keycard_views import _next_free_instance_aid
        p = self._prefix()
        existing = [p + bytes([0x01]), p + bytes([0x01, 0x01])]  # both slot 1
        result = _next_free_instance_aid(existing)
        self.assertEqual(result, p + bytes([0x02]))
        self.assertNotIn(result, existing)

    def test_next_free_aid_empty_mints_9byte_canonical(self):
        from seedsigner.views.keycard_views import _next_free_instance_aid
        from seedsigner.helpers.keycard.commands import APPLET_AID
        p = self._prefix()
        result = _next_free_instance_aid([])
        self.assertEqual(result, p + bytes([0x01]))
        self.assertEqual(len(result), len(p) + 1)
        # Slot 1 == the 9-byte boot default now (both forms unified).
        self.assertEqual(result, APPLET_AID)

    def test_next_free_aid_mixed_lengths_fill_smallest(self):
        """Slot 1 (9-byte) and slot 3 (10-byte) used → returns slot 2."""
        from seedsigner.views.keycard_views import _next_free_instance_aid
        p = self._prefix()
        existing = [p + bytes([0x01]), p + bytes([0x01, 0x03])]
        self.assertEqual(_next_free_instance_aid(existing), p + bytes([0x02]))

    def test_next_free_aid_full_raises(self):
        from seedsigner.helpers.keycard.global_platform import MAX_KEYCARD_INSTANCES
        from seedsigner.views.keycard_views import _next_free_instance_aid
        p = self._prefix()
        # Every slot 1..MAX occupied (alternating 9-/10-byte forms) -> no free
        # slot, so allocation must raise.
        existing = [
            (p + bytes([slot]) if slot % 2 else p + bytes([0x01, slot]))
            for slot in range(0x01, 0x01 + MAX_KEYCARD_INSTANCES)
        ]
        with self.assertRaises(RuntimeError):
            _next_free_instance_aid(existing)

    def test_format_instance_label_both_forms(self):
        from seedsigner.views import keycard_views
        p = self._prefix()
        # 9-byte canonical → Inst N (was previously short-hex)
        self.assertEqual(keycard_views._format_instance_label(p + bytes([0x02])), "Inst 2")
        # 10-byte legacy → Inst N
        self.assertEqual(keycard_views._format_instance_label(p + bytes([0x01, 0x03])), "Inst 3")
        # A 9-byte and a 10-byte AID at the same slot BOTH render Inst 1
        # (intended ambiguity; the Delete screen disambiguates via full AID).
        self.assertEqual(keycard_views._format_instance_label(p + bytes([0x01])), "Inst 1")
        self.assertEqual(keycard_views._format_instance_label(p + bytes([0x01, 0x01])), "Inst 1")

    def test_format_aid_short_full_for_short_aids(self):
        from seedsigner.views import keycard_views
        p = self._prefix()
        nine = keycard_views._format_aid_short(p + bytes([0x01]))      # a00000080400010101
        ten = keycard_views._format_aid_short(p + bytes([0x01, 0x01]))  # a0000008040001010101
        self.assertNotIn("…", nine)
        self.assertNotIn("…", ten)
        self.assertNotEqual(nine, ten)                 # distinguishable now
        self.assertEqual(nine, (p + bytes([0x01])).hex())
        # A genuinely long AID (>12 bytes) still truncates.
        long_aid = bytes(range(13))
        self.assertIn("…", keycard_views._format_aid_short(long_aid))

    def test_delete_view_full_aid_disambiguates(self):
        """Two same-slot instances (9-byte + 10-byte ...0101) must render as
        DISTINCT Delete rows so the destructive pick can't hit the wrong one."""
        from unittest.mock import patch
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            ToolsKeycardInstancesDeleteView, KEYCARD_APPLET_AID,
        )
        from seedsigner.helpers.keycard.global_platform import AppletInstance
        from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON

        nine = KEYCARD_APPLET_AID + bytes([0x01])
        ten = KEYCARD_APPLET_AID + bytes([0x01, 0x01])
        instances = [
            AppletInstance(aid=nine, life_cycle=0, privileges=0),
            AppletInstance(aid=ten, life_cycle=0, privileges=0),
        ]
        view = ToolsKeycardInstancesDeleteView.__new__(ToolsKeycardInstancesDeleteView)
        view.controller = MagicMock()
        view.controller.get_instance_name_for_aid.return_value = None  # no names
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured["button_data"] = kwargs["button_data"]
            return RET_CODE__BACK_BUTTON

        view.run_screen = fake_run_screen
        with patch.object(
            keycard_views, "_open_isd_channel",
            return_value=(MagicMock(), instances, MagicMock()),
        ):
            view.run()

        labels = [b.button_label for b in captured["button_data"]]
        self.assertEqual(len(labels), 2)
        self.assertNotEqual(labels[0], labels[1])        # disambiguated
        self.assertIn(nine.hex(), labels[0])
        self.assertIn(ten.hex(), labels[1])


if __name__ == "__main__":
    unittest.main()
