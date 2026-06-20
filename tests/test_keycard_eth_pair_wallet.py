"""Tests for the Pair-with-wallet flow additions.

Covers:

* :func:`extract_extended_pubkey` — TLV parser for the extended export
  response that carries both the pubkey (tag 0x80) and chain code
  (tag 0x82).
* :class:`EthHDKeyQrEncoder` — round-trip a known account-level pubkey
  through the BC-UR fountain encoder and decode with
  ``urtypes.crypto.HDKey``.
* :func:`select_with_autodetect` — fall through ``0x6A82`` and update
  ``controller.active_keycard_aid`` on the first matching candidate.
* :func:`classify_card_error` — distinguish "cryptogram mismatch"
  from generic ``SecureChannelError`` so the user sees a useful label.
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
    ]:
        sys.modules.setdefault(mod, MagicMock())


_install_hw_mocks()


# Synthetic but well-formed test vector: a deterministic uncompressed
# secp256k1 point and 32 zero bytes for the chain code. We don't care
# whether the point is on-curve — extract_extended_pubkey is purely TLV.
_PUBKEY_UNCOMP = b"\x04" + bytes(range(1, 65))
_CHAIN_CODE = bytes(range(64, 96))  # 32 bytes
_PARENT_FP = b"\xDE\xAD\xBE\xEF"
_SOURCE_FP = b"\xCA\xFE\xBA\xBE"


class TestExtractExtendedPubkey(unittest.TestCase):
    def _wrap_a1(self, body: bytes) -> bytes:
        return b"\xA1" + bytes([len(body)]) + body

    def test_template_a1_with_pubkey_and_chain_code(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_extended_pubkey
        body = (
            b"\x80\x41" + _PUBKEY_UNCOMP   # tag 0x80, len 0x41 (65)
            + b"\x82\x20" + _CHAIN_CODE    # tag 0x82, len 0x20 (32)
        )
        result = extract_extended_pubkey(self._wrap_a1(body))
        self.assertIsNotNone(result)
        pubkey, chain_code = result
        self.assertEqual(pubkey, _PUBKEY_UNCOMP)
        self.assertEqual(chain_code, _CHAIN_CODE)

    def test_chain_code_before_pubkey_also_works(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_extended_pubkey
        body = (
            b"\x82\x20" + _CHAIN_CODE
            + b"\x80\x41" + _PUBKEY_UNCOMP
        )
        pubkey, chain_code = extract_extended_pubkey(self._wrap_a1(body))
        self.assertEqual(pubkey, _PUBKEY_UNCOMP)
        self.assertEqual(chain_code, _CHAIN_CODE)

    def test_missing_chain_code_returns_none(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_extended_pubkey
        body = b"\x80\x41" + _PUBKEY_UNCOMP
        self.assertIsNone(extract_extended_pubkey(self._wrap_a1(body)))

    def test_missing_pubkey_returns_none(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_extended_pubkey
        body = b"\x82\x20" + _CHAIN_CODE
        self.assertIsNone(extract_extended_pubkey(self._wrap_a1(body)))

    def test_chain_code_wrong_length_ignored(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_extended_pubkey
        body = b"\x80\x41" + _PUBKEY_UNCOMP + b"\x82\x10" + bytes(16)
        # 16-byte chain code is rejected — function should return None
        self.assertIsNone(extract_extended_pubkey(self._wrap_a1(body)))

    def test_empty_response_returns_none(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_extended_pubkey
        self.assertIsNone(extract_extended_pubkey(b""))


class TestEthHDKeyQrEncoder(unittest.TestCase):
    """Round-trip the produced UR through urtypes' HDKey decoder."""

    def _build_encoder(self):
        from seedsigner.models.encode_qr import EthHDKeyQrEncoder
        return EthHDKeyQrEncoder(
            pubkey=_PUBKEY_UNCOMP,
            chain_code=_CHAIN_CODE,
            parent_fingerprint=_PARENT_FP,
            source_fingerprint=_SOURCE_FP,
        )

    def test_round_trip_through_ur_fountain(self):
        from seedsigner.helpers.ur2.ur_decoder import URDecoder
        from urtypes.crypto import HDKey

        encoder = self._build_encoder()
        decoder = URDecoder()
        # Pull a generous number of fragments to satisfy the fountain.
        for _ in range(20):
            decoder.receive_part(encoder.next_part())
            if decoder.is_complete():
                break
        self.assertTrue(decoder.is_complete())
        ur = decoder.result_message()
        self.assertEqual(ur.type, "crypto-hdkey")

        hd = HDKey.from_cbor(ur.cbor)
        # Pubkey must be the 33-byte compressed form of our uncompressed key.
        expected_compressed = (
            (b"\x02" if _PUBKEY_UNCOMP[64] % 2 == 0 else b"\x03")
            + _PUBKEY_UNCOMP[1:33]
        )
        self.assertEqual(hd.key, expected_compressed)
        self.assertEqual(hd.chain_code, _CHAIN_CODE)
        self.assertEqual(hd.parent_fingerprint, _PARENT_FP)
        # Origin describes m/44'/60'/0' with our source fingerprint.
        self.assertIsNotNone(hd.origin)
        self.assertEqual(hd.origin.source_fingerprint, _SOURCE_FP)
        self.assertEqual(hd.origin.path(), "44'/60'/0'")
        # children == "0/*"
        self.assertIsNotNone(hd.children)
        self.assertEqual(hd.children.path(), "0/*")
        # SLIP-44 ETH coin type.
        self.assertIsNotNone(hd.use_info)
        self.assertEqual(hd.use_info.type, 60)

    def test_compressed_pubkey_prefix_uses_y_parity(self):
        # The compression byte should be 0x02 for even Y and 0x03 for odd Y.
        from seedsigner.models.encode_qr import EthHDKeyQrEncoder
        from seedsigner.helpers.ur2.ur_decoder import URDecoder
        from urtypes.crypto import HDKey

        # Build a pubkey with explicitly odd Y (last byte = 1).
        pub = b"\x04" + bytes(range(1, 33)) + bytes(range(33, 64)) + b"\x01"
        encoder = EthHDKeyQrEncoder(
            pubkey=pub,
            chain_code=_CHAIN_CODE,
            parent_fingerprint=_PARENT_FP,
            source_fingerprint=_SOURCE_FP,
        )
        decoder = URDecoder()
        for _ in range(20):
            decoder.receive_part(encoder.next_part())
            if decoder.is_complete():
                break
        hd = HDKey.from_cbor(decoder.result_message().cbor)
        self.assertEqual(hd.key[0:1], b"\x03")  # odd Y → 0x03 prefix

    def test_ledger_live_account_index_in_origin(self):
        # A non-zero account targets a Ledger Live account: the origin
        # path becomes 44'/60'/N' while children stay 0/* (the software
        # wallet derives 0/i within that account).
        from seedsigner.models.encode_qr import EthHDKeyQrEncoder
        from seedsigner.helpers.ur2.ur_decoder import URDecoder
        from urtypes.crypto import HDKey

        encoder = EthHDKeyQrEncoder(
            pubkey=_PUBKEY_UNCOMP,
            chain_code=_CHAIN_CODE,
            parent_fingerprint=_PARENT_FP,
            source_fingerprint=_SOURCE_FP,
            account=3,
        )
        decoder = URDecoder()
        for _ in range(20):
            decoder.receive_part(encoder.next_part())
            if decoder.is_complete():
                break
        hd = HDKey.from_cbor(decoder.result_message().cbor)
        self.assertEqual(hd.origin.path(), "44'/60'/3'")
        self.assertEqual(hd.children.path(), "0/*")

    def test_default_account_is_zero(self):
        # Regression: omitting account keeps the historical 44'/60'/0'.
        self.assertEqual(self._build_encoder().account, 0)

    def test_validation_rejects_bad_pubkey(self):
        from seedsigner.models.encode_qr import EthHDKeyQrEncoder
        with self.assertRaises(ValueError):
            EthHDKeyQrEncoder(
                pubkey=b"\x05" + bytes(64),  # wrong prefix
                chain_code=_CHAIN_CODE,
                parent_fingerprint=_PARENT_FP,
                source_fingerprint=_SOURCE_FP,
            )

    def test_validation_rejects_short_chain_code(self):
        from seedsigner.models.encode_qr import EthHDKeyQrEncoder
        with self.assertRaises(ValueError):
            EthHDKeyQrEncoder(
                pubkey=_PUBKEY_UNCOMP,
                chain_code=bytes(16),
                parent_fingerprint=_PARENT_FP,
                source_fingerprint=_SOURCE_FP,
            )

    def test_validation_rejects_short_fingerprint(self):
        from seedsigner.models.encode_qr import EthHDKeyQrEncoder
        with self.assertRaises(ValueError):
            EthHDKeyQrEncoder(
                pubkey=_PUBKEY_UNCOMP,
                chain_code=_CHAIN_CODE,
                parent_fingerprint=b"\x00\x00",
                source_fingerprint=_SOURCE_FP,
            )


class TestSelectWithAutodetect(unittest.TestCase):
    PREFIX = bytes.fromhex("A000000804000101")

    def _info(self):
        info = MagicMock()
        info.instance_uid = b"\xAA" * 16
        return info

    def test_first_call_succeeds_without_probing(self):
        from seedsigner.helpers.keycard.ui_helpers import select_with_autodetect
        client = MagicMock()
        info = self._info()
        client.select.return_value = info

        controller = MagicMock()
        original_aid = self.PREFIX + b"\x01"
        controller.active_keycard_aid = original_aid

        result = select_with_autodetect(client, controller)
        self.assertIs(result, info)
        client.select.assert_called_once_with(aid=original_aid)
        # active AID untouched on the happy path.
        self.assertEqual(controller.active_keycard_aid, original_aid)

    def test_probes_until_found_and_updates_active_aid(self):
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.ui_helpers import select_with_autodetect

        client = MagicMock()
        info = self._info()

        def fake_select(aid):
            # First call (active_aid) and 0102 fail; 0103 succeeds.
            if aid.endswith(b"\x03"):
                return info
            raise APDUError(0x6A82, "not found")

        client.select.side_effect = fake_select

        controller = MagicMock()
        controller.active_keycard_aid = self.PREFIX + b"\x01"

        result = select_with_autodetect(client, controller)
        self.assertIs(result, info)
        self.assertEqual(controller.active_keycard_aid, self.PREFIX + b"\x03")

    def test_probes_legacy_10byte_form(self):
        """Autodetect must also find a legacy 10-byte instance (prefix+01+X),
        not just the 9-byte canonical form."""
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.ui_helpers import select_with_autodetect

        client = MagicMock()
        info = self._info()
        ten_byte = self.PREFIX + b"\x01\x02"  # legacy slot-2 form

        def fake_select(aid):
            if aid == ten_byte:
                return info
            raise APDUError(0x6A82, "not found")

        client.select.side_effect = fake_select
        controller = MagicMock()
        controller.active_keycard_aid = self.PREFIX + b"\x01"

        result = select_with_autodetect(client, controller)
        self.assertIs(result, info)
        self.assertEqual(controller.active_keycard_aid, ten_byte)

    def test_raises_original_6a82_when_no_candidate_matches(self):
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.ui_helpers import select_with_autodetect

        client = MagicMock()
        client.select.side_effect = APDUError(0x6A82, "not found")

        controller = MagicMock()
        controller.active_keycard_aid = self.PREFIX + b"\x01"

        with self.assertRaises(APDUError) as ctx:
            select_with_autodetect(client, controller)
        self.assertEqual(ctx.exception.sw, 0x6A82)
        # active AID stays put on total failure.
        self.assertEqual(controller.active_keycard_aid, self.PREFIX + b"\x01")

    def test_non_6a82_error_propagates_immediately(self):
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.ui_helpers import select_with_autodetect

        client = MagicMock()
        client.select.side_effect = APDUError(0x6F00, "card died")

        controller = MagicMock()
        controller.active_keycard_aid = self.PREFIX + b"\x01"

        with self.assertRaises(APDUError) as ctx:
            select_with_autodetect(client, controller)
        self.assertEqual(ctx.exception.sw, 0x6F00)
        # Helper did NOT probe further once it saw a non-6A82 SW.
        client.select.assert_called_once()


class TestClassifyCardErrorWrongPassword(unittest.TestCase):
    """Step 0: the cryptogram-mismatch path is now relabelled."""

    def test_cryptogram_mismatch_is_wrong_password(self):
        from seedsigner.helpers.keycard.secure_channel import SecureChannelError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(
            SecureChannelError("card pairing cryptogram mismatch"),
        )
        self.assertEqual(title, "Wrong password")
        self.assertIn("password", body.lower())

    def test_other_secure_channel_error_unchanged(self):
        from seedsigner.helpers.keycard.secure_channel import SecureChannelError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(SecureChannelError("mac mismatch"))
        self.assertEqual(title, "Secure channel")
        # Body now surfaces the underlying reason for diagnostics.
        self.assertIn("mac mismatch", body)


if __name__ == "__main__":
    unittest.main()
