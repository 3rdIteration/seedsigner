"""BTC "View addresses" (``ToolsKeycardBtcAddressesListView``).

Covers:

* Address correctness against the official BIP-84 test vectors
  (mnemonic ``abandon`` ×11 + ``about``): the card-side derivation is
  mocked with embit-derived pubkeys at ``m/84'/0'/0'/0/i`` and the view
  must render the canonical first/second receive addresses.
* Per-chain cache namespacing: the BTC list must not collide with the
  ETH "View wallets" cache for the same AID, and invalidation must drop
  both (key-change / instance-delete rule from CLAUDE.md).
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
        "periphery",
    ]:
        sys.modules.setdefault(mod, MagicMock())


_install_hw_mocks()


AID = bytes.fromhex("A000000804000101")
_H = 0x80000000

# Official BIP-84 test vectors (mnemonic "abandon" x11 + "about").
BIP84_ADDR_0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
BIP84_ADDR_1 = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"


def _vector_pubkeys(count: int):
    """Uncompressed pubkeys at m/84'/0'/0'/0/i for the BIP-84 test seed."""
    from embit import bip32, bip39

    seed = bip39.mnemonic_to_seed(("abandon " * 11 + "about").strip())
    root = bip32.HDKey.from_seed(seed)
    pubs = []
    for i in range(count):
        node = root.derive(f"m/84'/0'/0'/0/{i}")
        pub = node.to_public().key
        pub.compressed = False
        pubs.append(pub.sec())  # 65-byte uncompressed (0x04-prefixed)
    return pubs


def _make_controller():
    controller = MagicMock()
    controller.active_keycard_aid = AID
    controller.keycard_wallets_data = {}
    controller.has_any_keycard_auth.return_value = True
    return controller


def _run_list_view(controller, client):
    from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
    from seedsigner.views import keycard_views

    inst = keycard_views.ToolsKeycardBtcAddressesListView.__new__(
        keycard_views.ToolsKeycardBtcAddressesListView,
    )
    inst.start_index = 0
    inst.selected_button_index = 0
    inst.initial_scroll = 0
    inst.controller = controller
    inst.run_screen = MagicMock(return_value=RET_CODE__BACK_BUTTON)

    with patch.object(
        keycard_views, "_open_unlocked_session_cached_or_prompt",
        return_value=(client, MagicMock(name="pairing")),
    ), patch(
        "seedsigner.gui.screens.screen.LoadingScreenThread", MagicMock(),
    ), patch.object(
        keycard_views, "_instance_display_name", return_value="Inst 1",
    ):
        inst.run()
    return inst


class TestBtcAddressesDerivation(unittest.TestCase):
    def test_renders_bip84_vector_addresses(self):
        from seedsigner.views import keycard_views

        pubs = _vector_pubkeys(keycard_views.WALLETS_PER_PAGE)
        client = MagicMock()
        derived_paths = []
        client.derive_key.side_effect = lambda path: derived_paths.append(path)
        client.export_pubkey.side_effect = list(pubs)

        controller = _make_controller()
        _run_list_view(controller, client)

        cache = controller.keycard_wallets_data[AID.hex() + ":btc"]
        self.assertEqual(cache[0], BIP84_ADDR_0)
        self.assertEqual(cache[1], BIP84_ADDR_1)
        # Every derivation must target the BIP-84 receive chain.
        for i, path in enumerate(derived_paths):
            self.assertEqual(path, [84 | _H, 0 | _H, 0 | _H, 0, i])

    def test_btc_cache_is_separate_from_eth_cache(self):
        from seedsigner.views.keycard_views import _wallets_cache_for_active_aid

        controller = _make_controller()
        eth = _wallets_cache_for_active_aid(controller)
        btc = _wallets_cache_for_active_aid(controller, chain="btc")
        eth.append("0xabc")
        btc.append("bc1q...")

        self.assertEqual(controller.keycard_wallets_data[AID.hex()], ["0xabc"])
        self.assertEqual(
            controller.keycard_wallets_data[AID.hex() + ":btc"], ["bc1q..."],
        )

    def test_invalidation_drops_all_chains_for_the_aid(self):
        from seedsigner.views.keycard_views import (
            _invalidate_wallets_cache_for_active_aid,
            _wallets_cache_for_active_aid,
        )

        controller = _make_controller()
        _wallets_cache_for_active_aid(controller).append("0xabc")
        _wallets_cache_for_active_aid(controller, chain="btc").append("bc1q...")
        other_key = "deadbeef:btc"
        controller.keycard_wallets_data[other_key] = ["keep-me"]

        _invalidate_wallets_cache_for_active_aid(controller)

        self.assertNotIn(AID.hex(), controller.keycard_wallets_data)
        self.assertNotIn(AID.hex() + ":btc", controller.keycard_wallets_data)
        # Other AIDs' caches survive.
        self.assertEqual(controller.keycard_wallets_data[other_key], ["keep-me"])


if __name__ == "__main__":
    unittest.main()
