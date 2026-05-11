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
        # we only exercise routing logic, not screen rendering.
        view = view_cls.__new__(view_cls)
        view.run_screen = MagicMock(return_value=button_index)
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
        )
        expected = [
            ToolsKeycardPairView,
            ToolsKeycardRemovePairingView,
            ToolsKeycardFactoryResetView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route(ToolsKeycardAdvancedMenuView, i)
            self.assertIs(dest.View_cls, view_cls)

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
