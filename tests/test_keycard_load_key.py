"""Tests for the LOAD_KEY APDU (BIP-39 seed import path).

Covers the APDU builder, length validation, and the client wrapper that
sends it through the secure channel.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock


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


SEED64 = bytes(range(64))


class TestLoadBip39SeedApdu(unittest.TestCase):
    def test_apdu_layout(self):
        from seedsigner.helpers.keycard.commands import (
            CLA_PROPRIETARY, INS_LOAD_KEY, LOAD_KEY_P1_BIP39_SEED,
            load_bip39_seed,
        )
        apdu = load_bip39_seed(SEED64)
        self.assertEqual(apdu[0], CLA_PROPRIETARY)
        self.assertEqual(apdu[1], INS_LOAD_KEY)
        self.assertEqual(apdu[2], LOAD_KEY_P1_BIP39_SEED)
        self.assertEqual(apdu[3], 0x00)
        self.assertEqual(apdu[4], 64)        # Lc = 64
        self.assertEqual(bytes(apdu[5:5 + 64]), SEED64)
        # No Le; the Status applet returns SW only.
        self.assertEqual(len(apdu), 5 + 64)

    def test_rejects_wrong_length(self):
        from seedsigner.helpers.keycard.commands import load_bip39_seed
        for bad in (b"", b"\x00" * 32, b"\x00" * 63, b"\x00" * 65, b"\x00" * 128):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    load_bip39_seed(bad)

    def test_constants_match_spec(self):
        """Renaming/repurposing these constants would silently break
        every keycard-shell-initialised card."""
        from seedsigner.helpers.keycard import commands
        self.assertEqual(commands.INS_LOAD_KEY, 0xD0)
        self.assertEqual(commands.LOAD_KEY_P1_BIP39_SEED, 0x03)


class TestLoadBip39SeedClient(unittest.TestCase):
    def test_client_validates_length(self):
        from seedsigner.helpers.keycard.client import KeycardClient
        connection = MagicMock()
        client = KeycardClient(connection)
        with self.assertRaises(ValueError):
            client.load_bip39_seed(b"\x00" * 32)

    def test_client_routes_through_protected_channel(self):
        from seedsigner.helpers.keycard.client import KeycardClient
        from seedsigner.helpers.keycard.commands import (
            INS_LOAD_KEY, LOAD_KEY_P1_BIP39_SEED,
        )

        client = KeycardClient(MagicMock())
        client._transmit_protected = MagicMock(return_value=b"")

        client.load_bip39_seed(SEED64)
        client._transmit_protected.assert_called_once_with(
            INS_LOAD_KEY, LOAD_KEY_P1_BIP39_SEED, 0x00, SEED64,
        )


class TestSeedToFingerprintReference(unittest.TestCase):
    """Sanity that the master-fingerprint computation we show to the
    user matches the canonical BIP-39 test vector. If embit ever changes
    semantics this catches the regression.
    """

    def test_abandon_about_master_fingerprint(self):
        from embit import bip32, bip39
        seed = bip39.mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about",
            password="",
        )
        root = bip32.HDKey.from_seed(seed)
        self.assertEqual(root.my_fingerprint.hex(), "73c5da0a")


if __name__ == "__main__":
    unittest.main()
