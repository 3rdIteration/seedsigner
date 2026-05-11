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


class TestKeycardMenuRouting(unittest.TestCase):
    """Smoke tests for the reorganised Keycard menu hierarchy:

        Keycard (top)
          ├─ Sign ETH       → ToolsKeycardSignEthStartView
          ├─ View wallets   → ToolsKeycardWalletsListView
          ├─ Export xpub    → ToolsKeycardPairWalletView
          ├─ Setup ›        → ToolsKeycardSetupMenuView
          │   ├─ Initialise card → ToolsKeycardInitView
          │   ├─ Generate key    → ToolsKeycardGenerateKeyView
          │   └─ Import seed     → ToolsKeycardImportSeedView
          └─ Manage ›       → ToolsKeycardManageMenuView
              ├─ Status      → ToolsKeycardStatusView
              ├─ Change PIN  → ToolsKeycardChangePinView
              ├─ Instances   → ToolsKeycardInstancesMenuView
              └─ Advanced ›  → ToolsKeycardAdvancedMenuView

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

    def test_top_menu_routes(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardMenuView,
            ToolsKeycardSignEthStartView,
            ToolsKeycardWalletsListView,
            ToolsKeycardPairWalletView,
            ToolsKeycardSetupMenuView,
            ToolsKeycardManageMenuView,
        )
        expected = [
            ToolsKeycardSignEthStartView,
            ToolsKeycardWalletsListView,
            ToolsKeycardPairWalletView,
            ToolsKeycardSetupMenuView,
            ToolsKeycardManageMenuView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route(ToolsKeycardMenuView, i)
            self.assertIs(dest.View_cls, view_cls,
                          f"top menu index {i} routes to {dest.View_cls.__name__}, "
                          f"expected {view_cls.__name__}")

    def test_setup_menu_routes(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardSetupMenuView,
            ToolsKeycardInitView,
            ToolsKeycardGenerateKeyView,
            ToolsKeycardImportSeedView,
        )
        expected = [
            ToolsKeycardInitView,
            ToolsKeycardGenerateKeyView,
            ToolsKeycardImportSeedView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route(ToolsKeycardSetupMenuView, i)
            self.assertIs(dest.View_cls, view_cls)

    def test_manage_menu_routes(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardManageMenuView,
            ToolsKeycardStatusView,
            ToolsKeycardChangePinView,
            ToolsKeycardInstancesMenuView,
            ToolsKeycardAdvancedMenuView,
        )
        expected = [
            ToolsKeycardStatusView,
            ToolsKeycardChangePinView,
            ToolsKeycardInstancesMenuView,
            ToolsKeycardAdvancedMenuView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route(ToolsKeycardManageMenuView, i)
            self.assertIs(dest.View_cls, view_cls)

    def test_advanced_menu_routes(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardAdvancedMenuView,
            ToolsKeycardPairView,
            ToolsKeycardRemovePairingView,
            ToolsKeycardFactoryResetView,
            ToolsKeycardUninstallAppletView,
        )
        expected = [
            ToolsKeycardPairView,
            ToolsKeycardRemovePairingView,
            ToolsKeycardFactoryResetView,
            ToolsKeycardUninstallAppletView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route(ToolsKeycardAdvancedMenuView, i)
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

    def test_pin_management_view_removed(self):
        """``ToolsKeycardPinManagementMenuView`` was a one-entry indirection
        ("Change PIN" was the only item); since Change PIN now hangs
        directly off Manage, the intermediate menu has been removed."""
        from seedsigner.views import keycard_views
        self.assertFalse(
            hasattr(keycard_views, "ToolsKeycardPinManagementMenuView"),
            "Stale ToolsKeycardPinManagementMenuView class is still present",
        )


if __name__ == "__main__":
    unittest.main()
