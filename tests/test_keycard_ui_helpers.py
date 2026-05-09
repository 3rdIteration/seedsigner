"""Unit tests for ``helpers/keycard/ui_helpers.py``.

These cover the pure helpers (path formatting, pubkey extraction, byte
wiping) and exercise the session-opening helper with a mocked client so
the secure-channel flow does not need real PC/SC hardware.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


# Mock hardware-dependent modules before importing anything that pulls them in.
def _install_hw_mocks():
    for mod in [
        "RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
        "smartcard", "smartcard.System", "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
    ]:
        sys.modules.setdefault(mod, MagicMock())

_install_hw_mocks()


class TestFormatPath(unittest.TestCase):
    def test_default_eth(self):
        from seedsigner.helpers.keycard.ui_helpers import format_path
        components = (
            44 | 0x80000000,
            60 | 0x80000000,
            0 | 0x80000000,
            0,
            0,
        )
        self.assertEqual(format_path(components), "m/44'/60'/0'/0/0")

    def test_no_components(self):
        from seedsigner.helpers.keycard.ui_helpers import format_path
        self.assertEqual(format_path([]), "m/")

    def test_mixed_hardened_and_soft(self):
        from seedsigner.helpers.keycard.ui_helpers import format_path
        # m/0/1'/2 — hardened only on the middle component.
        components = [0, 1 | 0x80000000, 2]
        self.assertEqual(format_path(components), "m/0/1'/2")

    def test_high_index_value(self):
        from seedsigner.helpers.keycard.ui_helpers import format_path
        # Soft index just below the hardened bit: 0x7FFFFFFF.
        self.assertEqual(format_path([0x7FFFFFFF]), "m/2147483647")


class TestExtractPubkey(unittest.TestCase):
    def _make_pubkey(self) -> bytes:
        # 65-byte uncompressed pubkey (0x04 prefix + 64 zero bytes is fine
        # for parser-only tests).
        return b"\x04" + bytes(range(1, 65))

    def test_template_a1_then_tlv_80(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_pubkey
        pubkey = self._make_pubkey()
        # Outer template 0xA1 with one inner TLV: tag 0x80, len 65.
        body = b"\x80\x41" + pubkey
        response = b"\xA1" + bytes([len(body)]) + body
        self.assertEqual(extract_pubkey(response), pubkey)

    def test_flat_tlv_without_outer_template(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_pubkey
        pubkey = self._make_pubkey()
        response = b"\x80\x41" + pubkey
        self.assertEqual(extract_pubkey(response), pubkey)

    def test_returns_none_for_empty(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_pubkey
        self.assertIsNone(extract_pubkey(b""))

    def test_returns_none_for_no_matching_tag(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_pubkey
        # Tag 0x81 instead of 0x80 — should be skipped, no pubkey returned.
        response = b"\x81\x41\x04" + bytes(64)
        self.assertIsNone(extract_pubkey(response))

    def test_returns_none_when_tag_present_but_pubkey_malformed(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_pubkey
        # tag 0x80 length 65 but missing 0x04 leading byte.
        response = b"\x80\x41" + b"\x00" + bytes(64)
        self.assertIsNone(extract_pubkey(response))


class TestWipeBytearray(unittest.TestCase):
    def test_wipes_in_place(self):
        from seedsigner.helpers.keycard.ui_helpers import wipe_bytearray
        buf = bytearray(b"123456")
        wipe_bytearray(buf)
        self.assertEqual(buf, bytearray(6))

    def test_handles_none(self):
        from seedsigner.helpers.keycard.ui_helpers import wipe_bytearray
        # Should not raise.
        wipe_bytearray(None)

    def test_wipes_empty_bytearray(self):
        from seedsigner.helpers.keycard.ui_helpers import wipe_bytearray
        buf = bytearray()
        wipe_bytearray(buf)
        self.assertEqual(buf, bytearray())


class TestOpenUnlockedSession(unittest.TestCase):
    def test_raises_when_not_paired(self):
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session
        view = MagicMock()
        view.controller.keycard_pairing = None
        with self.assertRaises(RuntimeError):
            open_unlocked_session(view, bytearray(b"123456"))

    def test_happy_path_calls_select_and_verify_pin(self):
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        view = MagicMock()
        pairing = MagicMock(name="pairing")
        view.controller.keycard_pairing = pairing
        pin = bytearray(b"123456")

        client = MagicMock()
        client_cls = MagicMock(return_value=client)

        with patch(
            "seedsigner.helpers.keycard.ui_helpers.KeycardClient", client_cls,
            create=True,
        ), patch(
            "seedsigner.helpers.keycard.ui_helpers.wait_for_card",
            return_value=MagicMock(name="connection"),
            create=True,
        ):
            # The function imports lazily; replicate the lazy patches by
            # patching the resolved module attributes after import.
            import seedsigner.helpers.keycard.client as kc_client
            import seedsigner.helpers.keycard.reader as kc_reader
            with patch.object(kc_client, "KeycardClient", client_cls), \
                 patch.object(kc_reader, "wait_for_card", return_value="conn"):
                returned_client, returned_pairing = open_unlocked_session(view, pin)

        self.assertIs(returned_pairing, pairing)
        self.assertIs(returned_client, client)
        client.select.assert_called_once()
        client.open_secure_channel.assert_called_once_with(pairing)
        client.verify_pin.assert_called_once_with(bytes(pin))


if __name__ == "__main__":
    unittest.main()
