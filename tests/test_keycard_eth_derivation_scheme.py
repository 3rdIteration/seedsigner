"""Tests for the ETH derivation-scheme chooser (Default vs Ledger Live).

An imported Ledger Live seed matches our *first* wallet but not the rest,
because Ledger Live iterates the BIP-44 *account* index
(``m/44'/60'/i'/0/0``) while our default iterates the *address* index
(``m/44'/60'/0'/0/i``). These tests cover:

* the pure path helpers ``_eth_wallet_components`` / ``_eth_wallet_path_str``;
* per-scheme cache namespacing in ``_wallets_cache_for_active_aid``;
* the ``View wallets`` list deriving the right path per scheme;
* the chooser + Ledger Live account-picker routing;
* the ``Connect software wallet`` export deriving ``m/44'/60'/N'`` and
  passing ``account=N`` to the QR encoder.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, call, patch


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

AID = bytes.fromhex("A00000080400010101")
_H = 0x80000000


class TestPathHelpers(unittest.TestCase):
    def test_standard_iterates_address_index(self):
        from seedsigner.views.keycard_views import (
            ETH_SCHEME_STANDARD, _eth_wallet_components, _eth_wallet_path_str,
        )
        self.assertEqual(
            _eth_wallet_components(ETH_SCHEME_STANDARD, 5),
            [44 | _H, 60 | _H, 0 | _H, 0, 5],
        )
        self.assertEqual(
            _eth_wallet_path_str(ETH_SCHEME_STANDARD, 5), "m/44'/60'/0'/0/5",
        )

    def test_ledger_live_iterates_account_index(self):
        from seedsigner.views.keycard_views import (
            ETH_SCHEME_LEDGER_LIVE, _eth_wallet_components, _eth_wallet_path_str,
        )
        self.assertEqual(
            _eth_wallet_components(ETH_SCHEME_LEDGER_LIVE, 5),
            [44 | _H, 60 | _H, 5 | _H, 0, 0],
        )
        self.assertEqual(
            _eth_wallet_path_str(ETH_SCHEME_LEDGER_LIVE, 5), "m/44'/60'/5'/0/0",
        )

    def test_account_zero_is_identical_across_schemes(self):
        # Why the user sees only the first wallet match: account 0 is the
        # same path under both schemes.
        from seedsigner.views.keycard_views import (
            ETH_SCHEME_LEDGER_LIVE, ETH_SCHEME_STANDARD, _eth_wallet_components,
        )
        self.assertEqual(
            _eth_wallet_components(ETH_SCHEME_STANDARD, 0),
            _eth_wallet_components(ETH_SCHEME_LEDGER_LIVE, 0),
        )


class TestCacheNamespacing(unittest.TestCase):
    def test_schemes_use_distinct_cache_keys(self):
        from seedsigner.views.keycard_views import (
            ETH_SCHEME_LEDGER_LIVE, ETH_SCHEME_STANDARD,
            _wallets_cache_for_active_aid,
        )
        controller = MagicMock()
        controller.active_keycard_aid = AID
        controller.keycard_wallets_data = None

        std = _wallets_cache_for_active_aid(controller, scheme=ETH_SCHEME_STANDARD)
        std.append("0xSTD")
        ll = _wallets_cache_for_active_aid(controller, scheme=ETH_SCHEME_LEDGER_LIVE)

        # Distinct list — Ledger Live must not see the standard addresses.
        self.assertEqual(ll, [])
        # Standard keeps the historical bare-AID key; LL gets a suffix.
        self.assertEqual(
            set(controller.keycard_wallets_data),
            {AID.hex(), AID.hex() + ":eth:ll"},
        )
        # All keys stay AID-prefixed so swap/key-change invalidation drops them.
        for key in controller.keycard_wallets_data:
            self.assertTrue(key == AID.hex() or key.startswith(AID.hex() + ":"))


class TestWalletsListDerivesPerScheme(unittest.TestCase):
    def _run_list(self, scheme):
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardWalletsListView

        view = ToolsKeycardWalletsListView.__new__(ToolsKeycardWalletsListView)
        view.start_index = 0
        view.selected_button_index = 0
        view.initial_scroll = 0
        view.scheme = scheme
        view.controller = MagicMock()
        view.controller.has_any_keycard_auth.return_value = True
        view.controller.active_keycard_aid = AID
        view.controller.keycard_wallets_data = None
        view.run_screen = MagicMock(return_value=RET_CODE__BACK_BUTTON)

        client = MagicMock()
        client.export_pubkey.return_value = b"\x04" + bytes(64)

        with patch.object(keycard_views, "_open_unlocked_session_cached_or_prompt",
                          return_value=(client, None)), \
                patch.object(keycard_views, "_extract_pubkey",
                             return_value=b"pub"), \
                patch.object(keycard_views, "pubkey_to_address",
                             return_value=b"addr"), \
                patch.object(keycard_views, "to_checksum_address",
                             return_value="0xADDR"), \
                patch.object(keycard_views, "_instance_title_suffix",
                             return_value=None), \
                patch("seedsigner.gui.screens.screen.LoadingScreenThread",
                      MagicMock()):
            view.run()
        return client.derive_key.call_args_list

    def test_standard_derives_address_index(self):
        from seedsigner.views.keycard_views import ETH_SCHEME_STANDARD
        calls = self._run_list(ETH_SCHEME_STANDARD)
        self.assertEqual(
            calls,
            [call([44 | _H, 60 | _H, 0 | _H, 0, i]) for i in range(10)],
        )

    def test_ledger_live_derives_account_index(self):
        from seedsigner.views.keycard_views import ETH_SCHEME_LEDGER_LIVE
        calls = self._run_list(ETH_SCHEME_LEDGER_LIVE)
        self.assertEqual(
            calls,
            [call([44 | _H, 60 | _H, i | _H, 0, 0]) for i in range(10)],
        )


class TestSchemeChooserRouting(unittest.TestCase):
    def _choose(self, mode, selected_index):
        from seedsigner.views.keycard_views import (
            ToolsKeycardEthDerivationSchemeView,
        )
        view = ToolsKeycardEthDerivationSchemeView.__new__(
            ToolsKeycardEthDerivationSchemeView)
        view.mode = mode
        view.controller = MagicMock()
        view.run_screen = MagicMock(return_value=selected_index)
        return view.run()

    def test_view_default_routes_to_list_standard(self):
        from seedsigner.views.keycard_views import (
            ETH_SCHEME_STANDARD, ToolsKeycardWalletsListView,
        )
        dest = self._choose("view", 0)
        self.assertIs(dest.View_cls, ToolsKeycardWalletsListView)
        self.assertEqual(dest.view_args, {"scheme": ETH_SCHEME_STANDARD})

    def test_view_ledger_live_routes_to_list_ledger(self):
        from seedsigner.views.keycard_views import (
            ETH_SCHEME_LEDGER_LIVE, ToolsKeycardWalletsListView,
        )
        dest = self._choose("view", 1)
        self.assertIs(dest.View_cls, ToolsKeycardWalletsListView)
        self.assertEqual(dest.view_args, {"scheme": ETH_SCHEME_LEDGER_LIVE})

    def test_export_default_routes_to_pair_account0(self):
        from seedsigner.views.keycard_views import ToolsKeycardPairWalletView
        dest = self._choose("export", 0)
        self.assertIs(dest.View_cls, ToolsKeycardPairWalletView)
        self.assertEqual(dest.view_args, {"account": 0})

    def test_export_ledger_live_routes_to_account_picker(self):
        from seedsigner.views.keycard_views import ToolsKeycardEthLedgerAccountView
        dest = self._choose("export", 1)
        self.assertIs(dest.View_cls, ToolsKeycardEthLedgerAccountView)

    def test_account_picker_routes_to_pair_with_account(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardEthLedgerAccountView, ToolsKeycardPairWalletView,
        )
        view = ToolsKeycardEthLedgerAccountView.__new__(
            ToolsKeycardEthLedgerAccountView)
        view.controller = MagicMock()
        view.run_screen = MagicMock(return_value=2)  # "Account 2"
        dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardPairWalletView)
        self.assertEqual(dest.view_args, {"account": 2})


class TestPairWalletAccountDerivation(unittest.TestCase):
    def test_export_derives_account_n_and_passes_to_encoder(self):
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import ToolsKeycardPairWalletView

        view = ToolsKeycardPairWalletView.__new__(ToolsKeycardPairWalletView)
        view.account = 4
        view.controller = MagicMock()
        view.controller.has_any_keycard_auth.return_value = True
        view.run_screen = MagicMock()

        client = MagicMock()
        client.export_pubkey.return_value = b"\x04" + bytes(64)

        with patch.object(keycard_views, "_open_unlocked_session_cached_or_prompt",
                          return_value=(client, None)), \
                patch.object(keycard_views, "_extract_pubkey", return_value=b"pub"), \
                patch.object(keycard_views, "extract_extended_pubkey",
                             return_value=(b"pub", bytes(32))), \
                patch.object(keycard_views, "_hash160", return_value=bytes(20)), \
                patch.object(keycard_views, "_compress_pubkey", return_value=b"c"), \
                patch.object(keycard_views, "pubkey_to_address", return_value=b"a"), \
                patch.object(keycard_views, "to_checksum_address",
                             return_value="0x" + "a" * 40), \
                patch("seedsigner.models.encode_qr.EthHDKeyQrEncoder") as enc:
            view.run()

        # The account step derives m/44'/60'/4' and the first-address step
        # m/44'/60'/4'/0/0 — both with account index 4, not 0.
        derived = client.derive_key.call_args_list
        self.assertIn(call([44 | _H, 60 | _H, 4 | _H]), derived)
        self.assertIn(call([44 | _H, 60 | _H, 4 | _H, 0, 0]), derived)
        # The encoder is told which account it is exporting.
        self.assertEqual(enc.call_args.kwargs["account"], 4)


if __name__ == "__main__":
    unittest.main()
