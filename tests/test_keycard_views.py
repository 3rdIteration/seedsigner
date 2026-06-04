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
          ├─ Ethereum ›     → ToolsKeycardEthereumMenuView
          │   ├─ Connect w/ Software Wallet → ToolsKeycardPairWalletView
          │   ├─ Sign request  → ToolsKeycardSignEthStartView
          │   └─ View wallets  → ToolsKeycardWalletsListView
          ├─ Bitcoin ›      → ToolsKeycardBitcoinMenuView
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
            ToolsKeycardEthereumMenuView,
            ToolsKeycardBitcoinMenuView,
            ToolsKeycardSetupMenuView,
            ToolsKeycardManageMenuView,
        )
        expected = [
            ToolsKeycardEthereumMenuView,
            ToolsKeycardBitcoinMenuView,
            ToolsKeycardSetupMenuView,
            ToolsKeycardManageMenuView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route(ToolsKeycardMenuView, i)
            self.assertIs(dest.View_cls, view_cls,
                          f"top menu index {i} routes to {dest.View_cls.__name__}, "
                          f"expected {view_cls.__name__}")

    def test_ethereum_menu_routes(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardEthereumMenuView,
            ToolsKeycardPairWalletView,
            ToolsKeycardSignEthStartView,
            ToolsKeycardWalletsListView,
        )
        expected = [
            ToolsKeycardPairWalletView,
            ToolsKeycardSignEthStartView,
            ToolsKeycardWalletsListView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route(ToolsKeycardEthereumMenuView, i)
            self.assertIs(dest.View_cls, view_cls,
                          f"ETH menu index {i} routes to {dest.View_cls.__name__}, "
                          f"expected {view_cls.__name__}")

    def test_bitcoin_menu_routes(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardBitcoinMenuView,
            ToolsKeycardBtcExportXpubView,
            ToolsKeycardBtcSignPsbtScanView,
            ToolsKeycardBtcSignMessageStartView,
        )
        expected = [
            ToolsKeycardBtcExportXpubView,
            ToolsKeycardBtcSignPsbtScanView,
            ToolsKeycardBtcSignMessageStartView,
        ]
        for i, view_cls in enumerate(expected):
            dest = self._route(ToolsKeycardBitcoinMenuView, i)
            self.assertIs(dest.View_cls, view_cls,
                          f"BTC menu index {i} routes to {dest.View_cls.__name__}, "
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

    def test_rename_persists_label_without_password_prompt(self):
        """Renaming a Keycard instance must NEVER prompt for the pairing
        password. Labels are display strings (not secrets) and live in a
        plaintext per-UID file; the rename flow must work even when
        there is no on-disk pairing blob (the v3.2+ ephemeral case).
        """
        from unittest.mock import patch

        from seedsigner.helpers.keycard import pairing_storage
        from seedsigner.helpers.keycard.global_platform import AppletInstance
        from seedsigner.views import keycard_views
        from seedsigner.views.keycard_views import (
            KEYCARD_APPLET_AID, ToolsKeycardInstancesRenameView,
        )

        instance_aid = KEYCARD_APPLET_AID + b"\x01\x01"
        instance_uid = b"\xAB" * 16

        view = ToolsKeycardInstancesRenameView.__new__(
            ToolsKeycardInstancesRenameView,
        )
        view.controller = MagicMock()
        # run_screen returns the index of the chosen instance (first one).
        view.run_screen = MagicMock(return_value=0)

        fake_select = MagicMock()
        fake_select.instance_uid = instance_uid
        fake_client = MagicMock()
        fake_client.select.return_value = fake_select

        save_calls = []
        update_calls = []

        def fake_save_label_only(uid, label):
            save_calls.append((bytes(uid), label))

        def fake_update_label(*args, **kwargs):
            update_calls.append(args)
            # Pretend no persistent blob exists for this UID — the
            # silent best-effort blob-trailer refresh should swallow
            # PairingStorageError and move on.
            raise pairing_storage.PairingStorageError("no blob")

        with patch.object(
            keycard_views, "_open_isd_channel",
            return_value=(
                MagicMock(),
                [AppletInstance(aid=instance_aid, life_cycle=0, privileges=0)],
                MagicMock(),
            ),
        ), patch.object(
            keycard_views, "_instances_or_probe_fallback",
            side_effect=lambda controller, instances, conn: instances,
        ), patch(
            "seedsigner.helpers.keycard.reader.wait_for_card",
            return_value=MagicMock(),
        ), patch(
            "seedsigner.helpers.keycard.reader.release_other_smartcard_holders",
        ), patch(
            "seedsigner.helpers.keycard.client.KeycardClient",
            return_value=fake_client,
        ), patch.object(
            keycard_views, "prompt_for_text", return_value="Cold Wallet",
        ) as prompt_text, patch.object(
            pairing_storage, "save_label_only",
            side_effect=fake_save_label_only,
        ), patch.object(
            pairing_storage, "update_label", side_effect=fake_update_label,
        ):
            view.run()

        # Exactly one prompt: for the wallet name. The Pairing-password
        # prompt would be a SECOND prompt_for_text call — its absence is
        # the regression guard for the original UX bug.
        self.assertEqual(prompt_text.call_count, 1)
        # The plaintext label file got the new name keyed by instance UID.
        self.assertEqual(save_calls, [(instance_uid, "Cold Wallet")])
        # The in-memory cache reflects the rename so subsequent renders
        # don't fall back to the AID hex.
        view.controller.set_label_for.assert_called_with(
            instance_uid, "Cold Wallet",
        )


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


if __name__ == "__main__":
    unittest.main()
