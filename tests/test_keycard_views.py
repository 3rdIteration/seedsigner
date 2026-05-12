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

        def fake_init(pin_bytes, puk_bytes, secret):
            captured["pin"] = bytes(pin_bytes)
            captured["puk"] = bytes(puk_bytes)

        fake_client.init.side_effect = fake_init

        with patch.object(keycard_views, "prompt_for_pin", side_effect=fake_prompt_for_pin), \
             patch.object(keycard_views, "prompt_for_text", return_value=None), \
             patch("seedsigner.helpers.keycard.reader.wait_for_card",
                   return_value=fake_connection), \
             patch("seedsigner.helpers.keycard.reader.release_other_smartcard_holders"), \
             patch("seedsigner.helpers.keycard.client.KeycardClient",
                   return_value=fake_client), \
             patch("seedsigner.helpers.keycard.crypto.derive_pairing_secret",
                   return_value=b"\x11" * 32), \
             patch.object(keycard_views, "select_with_autodetect"):
            view.run()

        self.assertEqual(prompt_calls["n"], 4)
        self.assertEqual(captured["pin"], b"333333")
        self.assertEqual(len(captured["puk"]), 12)  # PUK_LENGTH
        # No label entered -> pending_keycard_label must be cleared.
        self.assertIsNone(view.controller.pending_keycard_label)

    def test_init_captures_wallet_label_for_pair(self):
        """Init must stash the typed wallet name in
        ``controller.pending_keycard_label`` so the next PAIR persists
        it alongside the pairing blob.
        """
        from unittest.mock import patch

        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardInitView

        view = ToolsKeycardInitView.__new__(ToolsKeycardInitView)
        view.controller = MagicMock()
        view.controller.pending_keycard_label = None
        view.run_screen = MagicMock(return_value=0)

        with patch.object(keycard_views, "prompt_for_pin",
                          side_effect=[bytearray(b"123456"), bytearray(b"123456")]), \
             patch.object(keycard_views, "prompt_for_text",
                          return_value="  Cold Wallet  "), \
             patch("seedsigner.helpers.keycard.reader.wait_for_card",
                   return_value=MagicMock()), \
             patch("seedsigner.helpers.keycard.reader.release_other_smartcard_holders"), \
             patch("seedsigner.helpers.keycard.client.KeycardClient",
                   return_value=MagicMock()), \
             patch("seedsigner.helpers.keycard.crypto.derive_pairing_secret",
                   return_value=b"\x11" * 32), \
             patch.object(keycard_views, "select_with_autodetect"):
            view.run()

        # Whitespace-stripped, ready for pairing_storage.save.
        self.assertEqual(view.controller.pending_keycard_label, "Cold Wallet")

    def test_instance_cap_blocks_create_at_four(self):
        """``ToolsKeycardInstancesCreateView`` must short-circuit to an
        error destination when 4 Keycard instances already exist, and
        must never call ``install_for_install_with_fallback``.
        """
        from unittest.mock import patch

        from seedsigner.helpers.keycard.global_platform import (
            AppletInstance, MAX_KEYCARD_INSTANCES,
        )
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardInstancesCreateView,
        )

        self.assertEqual(MAX_KEYCARD_INSTANCES, 4)

        # Four installed Keycard instances at AIDs ...010101..010104.
        full_instances = [
            AppletInstance(
                aid=KEYCARD_APPLET_AID + bytes([0x01, suffix]),
                life_cycle=0, privileges=0,
            )
            for suffix in range(0x01, 0x05)
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
