"""Tests for the GlobalPlatform / SCP02 module.

Covers the crypto primitives (padding, session-key derivation,
cryptogram, retail MAC, ICV update), the INITIALIZE_UPDATE response
parser, the SCP02 handshake against a deterministic mock card, and
the high-level INSTALL / DELETE / GET STATUS APDU layouts.
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


# ---------------------------------------------------------------------------
# Crypto primitives
# ---------------------------------------------------------------------------


class TestPadding(unittest.TestCase):
    def test_iso9797_method2_pads_to_block(self):
        from seedsigner.helpers.keycard.global_platform import _iso9797_pad
        self.assertEqual(_iso9797_pad(b""), b"\x80" + b"\x00" * 7)
        self.assertEqual(_iso9797_pad(b"\x01"), b"\x01\x80" + b"\x00" * 6)
        # Already at block boundary -> a full extra block of pad.
        self.assertEqual(_iso9797_pad(b"\x01" * 8), b"\x01" * 8 + b"\x80" + b"\x00" * 7)


class TestSessionKeyDerivation(unittest.TestCase):
    def test_derive_session_key_is_deterministic(self):
        from seedsigner.helpers.keycard.global_platform import (
            DEFAULT_ISD_KEY, KDF_CONST_S_ENC, derive_session_key,
        )
        seq = b"\x00\x01"
        a = derive_session_key(DEFAULT_ISD_KEY, KDF_CONST_S_ENC, seq)
        b = derive_session_key(DEFAULT_ISD_KEY, KDF_CONST_S_ENC, seq)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 16)

    def test_different_constants_yield_different_keys(self):
        from seedsigner.helpers.keycard.global_platform import (
            DEFAULT_ISD_KEY, KDF_CONST_S_ENC, KDF_CONST_S_MAC,
            KDF_CONST_S_DEK, derive_session_key,
        )
        seq = b"\x00\x05"
        s_enc = derive_session_key(DEFAULT_ISD_KEY, KDF_CONST_S_ENC, seq)
        s_mac = derive_session_key(DEFAULT_ISD_KEY, KDF_CONST_S_MAC, seq)
        s_dek = derive_session_key(DEFAULT_ISD_KEY, KDF_CONST_S_DEK, seq)
        self.assertEqual(len({s_enc, s_mac, s_dek}), 3)

    def test_argument_lengths_validated(self):
        from seedsigner.helpers.keycard.global_platform import (
            KDF_CONST_S_ENC, derive_session_key,
        )
        with self.assertRaises(ValueError):
            derive_session_key(b"\x00" * 8, KDF_CONST_S_ENC, b"\x00\x00")
        with self.assertRaises(ValueError):
            derive_session_key(b"\x00" * 16, b"\x00", b"\x00\x00")
        with self.assertRaises(ValueError):
            derive_session_key(b"\x00" * 16, KDF_CONST_S_ENC, b"\x00")


class TestCryptogram(unittest.TestCase):
    # Use a non-degenerate 2-key 3DES key (k1 != k2) so DES3 accepts it.
    KEY = bytes.fromhex("404142434445464748494A4B4C4D4E4F")

    def test_cryptogram_is_8_bytes(self):
        from seedsigner.helpers.keycard.global_platform import cryptogram
        out = cryptogram(self.KEY, [b"\x01" * 8, b"\x02\x03", b"\x04" * 6])
        self.assertEqual(len(out), 8)

    def test_cryptogram_changes_with_input_order(self):
        """Host vs card cryptograms differ only in payload order; the
        function should reflect that swap."""
        from seedsigner.helpers.keycard.global_platform import cryptogram
        host = b"\x01" * 8
        seq = b"\x00\x05"
        cc = b"\xa0\xa1\xa2\xa3\xa4\xa5"
        a = cryptogram(self.KEY, [host, seq, cc])
        b = cryptogram(self.KEY, [seq, cc, host])
        self.assertNotEqual(a, b)


class TestRetailMac(unittest.TestCase):
    def test_mac_length(self):
        from seedsigner.helpers.keycard.global_platform import retail_mac
        out = retail_mac(b"\x00" * 16, b"\x00" * 8, b"hello")
        self.assertEqual(len(out), 8)

    def test_mac_chains_via_icv(self):
        from seedsigner.helpers.keycard.global_platform import retail_mac
        s_mac = b"\x42" * 16
        m1 = retail_mac(s_mac, b"\x00" * 8, b"abcdefgh")
        # Re-MAC the same data with a different ICV — output must differ.
        m2 = retail_mac(s_mac, m1, b"abcdefgh")
        self.assertNotEqual(m1, m2)


class TestEncryptIcv(unittest.TestCase):
    def test_icv_update_is_deterministic(self):
        from seedsigner.helpers.keycard.global_platform import encrypt_icv
        out = encrypt_icv(b"\x42" * 16, b"\x01\x02\x03\x04\x05\x06\x07\x08")
        self.assertEqual(len(out), 8)
        self.assertEqual(out, encrypt_icv(b"\x42" * 16, b"\x01\x02\x03\x04\x05\x06\x07\x08"))


# ---------------------------------------------------------------------------
# INITIALIZE UPDATE parsing
# ---------------------------------------------------------------------------


class TestInitializeUpdateParser(unittest.TestCase):
    def test_parse_full_response(self):
        from seedsigner.helpers.keycard.global_platform import (
            parse_initialize_update_response,
        )
        # 28 bytes: 10 (kdv) + 1 (kver) + 1 (scp_id) + 2 (seq) + 6 (chal) + 8 (cryp)
        resp = (
            bytes(range(10))                # key diversification
            + b"\x00"                       # key version
            + b"\x02"                       # SCP02 id
            + b"\x00\x07"                   # sequence counter
            + bytes.fromhex("a0a1a2a3a4a5") # card challenge (6)
            + bytes.fromhex("ff00ff00ff00ff00")  # card cryptogram
        )
        parsed = parse_initialize_update_response(resp)
        self.assertEqual(parsed["sequence_counter"], b"\x00\x07")
        self.assertEqual(parsed["card_challenge"], bytes.fromhex("a0a1a2a3a4a5"))
        self.assertEqual(parsed["card_cryptogram"], bytes.fromhex("ff00ff00ff00ff00"))

    def test_parse_rejects_wrong_length(self):
        from seedsigner.helpers.keycard.global_platform import (
            GpProtocolError, parse_initialize_update_response,
        )
        with self.assertRaises(GpProtocolError):
            parse_initialize_update_response(b"\x00" * 27)


# ---------------------------------------------------------------------------
# SCP02 round-trip with a self-consistent mock card
# ---------------------------------------------------------------------------


class _MockCard:
    """A toy card connection that completes the SCP02 handshake against
    the same crypto our impl uses. This is a self-consistency test, not
    a spec-conformance test — but it catches every regression in the
    handshake/MAC chaining code.
    """

    def __init__(self):
        self.sequence_counter = b"\x00\x07"
        self.card_challenge = bytes.fromhex("a0a1a2a3a4a5")
        self.transmits = []
        self.last_host_challenge = None

    def transmit(self, apdu):
        from seedsigner.helpers.keycard.global_platform import (
            DEFAULT_ISD_KEY, KDF_CONST_S_ENC, cryptogram,
            derive_session_key,
        )
        self.transmits.append(list(apdu))

        # SELECT ISD: just respond OK with empty data.
        if apdu[0] == 0x00 and apdu[1] == 0xA4:
            return ([], 0x90, 0x00)

        # INITIALIZE_UPDATE
        if apdu[0] == 0x80 and apdu[1] == 0x50:
            host_challenge = bytes(apdu[5:13])
            self.last_host_challenge = host_challenge
            s_enc = derive_session_key(DEFAULT_ISD_KEY, KDF_CONST_S_ENC,
                                        self.sequence_counter)
            card_cryptogram = cryptogram(
                s_enc, [host_challenge, self.sequence_counter, self.card_challenge],
            )
            resp = (
                bytes(10)                      # key diversification
                + b"\x00"                      # key version
                + b"\x02"                      # SCP02 id
                + self.sequence_counter
                + self.card_challenge
                + card_cryptogram
            )
            return (list(resp), 0x90, 0x00)

        # EXTERNAL_AUTHENTICATE and authenticated commands: just OK.
        if apdu[0] == 0x84:
            return ([], 0x90, 0x00)

        # Anything else: SW=6D00.
        return ([], 0x6D, 0x00)


class TestScp02HandshakeRoundTrip(unittest.TestCase):
    def test_open_session(self):
        from seedsigner.helpers.keycard.global_platform import GpSecureChannel

        card = _MockCard()
        gp = GpSecureChannel(card)
        gp.select_isd()
        sess = gp.open(host_challenge=b"\x01\x02\x03\x04\x05\x06\x07\x08")

        # Session keys must be 16 bytes each and distinct.
        self.assertEqual(len(sess.s_enc), 16)
        self.assertEqual(len(sess.s_mac), 16)
        self.assertEqual(len(sess.s_dek), 16)
        self.assertEqual(len({sess.s_enc, sess.s_mac, sess.s_dek}), 3)
        # ICV chained from the EXTERNAL_AUTHENTICATE C-MAC.
        self.assertEqual(len(sess.icv), 8)

    def test_card_cryptogram_mismatch_raises(self):
        from seedsigner.helpers.keycard.global_platform import (
            GpProtocolError, GpSecureChannel,
        )

        class _BadCard(_MockCard):
            def transmit(self, apdu):
                data, sw1, sw2 = super().transmit(apdu)
                # If this is the IU response, flip a byte in the cryptogram.
                if apdu[0] == 0x80 and apdu[1] == 0x50:
                    bad = list(data)
                    bad[-1] ^= 0xFF
                    return (bad, sw1, sw2)
                return (data, sw1, sw2)

        gp = GpSecureChannel(_BadCard())
        gp.select_isd()
        with self.assertRaises(GpProtocolError):
            gp.open(host_challenge=b"\x01\x02\x03\x04\x05\x06\x07\x08")

    def test_subsequent_command_carries_cmac(self):
        """After open(), transmit_protected sends an APDU with an 8-byte
        MAC suffix and CLA=0x84."""
        from seedsigner.helpers.keycard.global_platform import (
            GpSecureChannel, INS_DELETE,
        )

        card = _MockCard()
        gp = GpSecureChannel(card)
        gp.select_isd()
        gp.open(host_challenge=b"\x01\x02\x03\x04\x05\x06\x07\x08")
        before = len(card.transmits)

        gp.transmit_protected(INS_DELETE, 0x00, 0x80, b"\x4F\x02\xAB\xCD")

        last = card.transmits[-1]
        self.assertEqual(last[0], 0x84)            # CLA with secure msg bit
        self.assertEqual(last[1], INS_DELETE)
        # Lc = 4 (data) + 8 (CMAC).
        self.assertEqual(last[4], 12)
        self.assertEqual(len(last) - 5, 12)        # body length matches Lc


# ---------------------------------------------------------------------------
# High-level operations: APDU layouts
# ---------------------------------------------------------------------------


class TestInstallForInstall(unittest.TestCase):
    def test_apdu_data_layout(self):
        from seedsigner.helpers.keycard.global_platform import (
            GpSecureChannel, install_for_install,
        )
        card = _MockCard()
        gp = GpSecureChannel(card)
        gp.select_isd()
        gp.open(host_challenge=b"\x01" * 8)

        package = bytes.fromhex("A0000008040001")
        applet = bytes.fromhex("A000000804000101")
        instance = bytes.fromhex("A00000080400010102")

        install_for_install(gp, package, applet, instance)

        apdu = card.transmits[-1]
        # CLA=0x84, INS=0xE6, P1=0x0C
        self.assertEqual(apdu[0], 0x84)
        self.assertEqual(apdu[1], 0xE6)
        self.assertEqual(apdu[2], 0x0C)
        # Data starts at index 5; first byte = len(package_aid) = 7
        self.assertEqual(apdu[5], len(package))
        self.assertEqual(bytes(apdu[6:6 + len(package)]), package)

    def test_rejects_short_instance_aid(self):
        from seedsigner.helpers.keycard.global_platform import (
            GpSecureChannel, install_for_install,
        )
        card = _MockCard()
        gp = GpSecureChannel(card)
        gp.select_isd()
        gp.open(host_challenge=b"\x01" * 8)
        with self.assertRaises(ValueError):
            install_for_install(gp,
                                package_aid=bytes.fromhex("A0000008040001"),
                                applet_aid=bytes.fromhex("A000000804000101"),
                                instance_aid=b"\x01\x02\x03\x04")  # 4 bytes


class TestDelete(unittest.TestCase):
    def test_apdu_layout_with_related(self):
        from seedsigner.helpers.keycard.global_platform import (
            GpSecureChannel, delete_aid, INS_DELETE,
        )
        card = _MockCard()
        gp = GpSecureChannel(card)
        gp.select_isd()
        gp.open(host_challenge=b"\x01" * 8)

        target = bytes.fromhex("A00000080400010102")
        delete_aid(gp, target, with_related=True)
        apdu = card.transmits[-1]
        self.assertEqual(apdu[0], 0x84)
        self.assertEqual(apdu[1], INS_DELETE)
        self.assertEqual(apdu[3], 0x80)            # P2 = with related
        # data starts at index 5: 0x4F LL AID … (then CMAC suffix)
        self.assertEqual(apdu[5], 0x4F)
        self.assertEqual(apdu[6], len(target))
        self.assertEqual(bytes(apdu[7:7 + len(target)]), target)


# ---------------------------------------------------------------------------
# GET STATUS TLV parser
# ---------------------------------------------------------------------------


class TestStatusTlvParser(unittest.TestCase):
    def test_parses_two_instances(self):
        from seedsigner.helpers.keycard.global_platform import _parse_status_tlv

        aid_a = bytes.fromhex("A000000804000101")
        aid_b = bytes.fromhex("A00000080400010102")
        # Each entry: E3 LL [4F LL AID] [9F70 01 LIFE] [C5 01 PRIV]
        entry_a = bytes([0x4F, len(aid_a)]) + aid_a + bytes.fromhex("9F70017FC50100")
        entry_b = bytes([0x4F, len(aid_b)]) + aid_b + bytes.fromhex("9F70017FC50100")
        payload = (
            bytes([0xE3, len(entry_a)]) + entry_a
            + bytes([0xE3, len(entry_b)]) + entry_b
        )

        parsed = _parse_status_tlv(payload)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].aid, aid_a)
        self.assertEqual(parsed[1].aid, aid_b)


class TestInstallForInstallWithFallback(unittest.TestCase):
    """``install_for_install_with_fallback`` retries with the split
    P1=0x04 + P1=0x08 form when the combined P1=0x0C is rejected with
    ``0x6982`` (security status not satisfied).
    """

    def _new_channel(self, install_responder):
        from seedsigner.helpers.keycard.global_platform import GpSecureChannel

        class _RecordingCard(_MockCard):
            def __init__(self):
                super().__init__()
                self.install_calls = []

            def transmit(self, apdu):
                # INSTALL: CLA=0x84 (secure), INS=0xE6.
                if apdu[0] == 0x84 and apdu[1] == 0xE6:
                    p1 = apdu[2]
                    self.install_calls.append(p1)
                    sw1, sw2 = install_responder(p1)
                    return ([], sw1, sw2)
                return super().transmit(apdu)

        card = _RecordingCard()
        gp = GpSecureChannel(card)
        gp.select_isd()
        gp.open(host_challenge=b"\x01" * 8)
        return gp, card

    def test_combined_form_succeeds_on_first_try(self):
        from seedsigner.helpers.keycard.global_platform import (
            install_for_install_with_fallback,
        )
        gp, card = self._new_channel(lambda p1: (0x90, 0x00))
        install_for_install_with_fallback(
            gp,
            package_aid=bytes.fromhex("A0000008040001"),
            applet_aid=bytes.fromhex("A000000804000101"),
            instance_aid=bytes.fromhex("A00000080400010102"),
        )
        self.assertEqual(card.install_calls, [0x0C])

    def test_falls_back_to_split_form_on_6982(self):
        from seedsigner.helpers.keycard.global_platform import (
            install_for_install_with_fallback,
        )

        def responder(p1):
            if p1 == 0x0C:
                return (0x69, 0x82)
            return (0x90, 0x00)

        gp, card = self._new_channel(responder)
        install_for_install_with_fallback(
            gp,
            package_aid=bytes.fromhex("A0000008040001"),
            applet_aid=bytes.fromhex("A000000804000101"),
            instance_aid=bytes.fromhex("A00000080400010102"),
        )
        # P1=0x0C tried first, then split into 0x04 + 0x08.
        self.assertEqual(card.install_calls, [0x0C, 0x04, 0x08])

    def test_does_not_fall_back_on_other_status_words(self):
        from seedsigner.helpers.keycard.global_platform import (
            GpProtocolError, install_for_install_with_fallback,
        )

        def responder(p1):
            # 0x6A88 = "Referenced data not found" — not a fallback case.
            return (0x6A, 0x88) if p1 == 0x0C else (0x90, 0x00)

        gp, card = self._new_channel(responder)
        with self.assertRaises(GpProtocolError):
            install_for_install_with_fallback(
                gp,
                package_aid=bytes.fromhex("A0000008040001"),
                applet_aid=bytes.fromhex("A000000804000101"),
                instance_aid=bytes.fromhex("A00000080400010102"),
            )
        self.assertEqual(card.install_calls, [0x0C])


class TestListInstancesFallbacks(unittest.TestCase):
    """``list_instances`` must:

    1. Page on ``0x6310`` ("more data available") without losing data.
    2. Fall back to legacy ``P2=0x00`` format when ``P2=0x02`` returns
       no entries.
    3. Survive ``0x6A88`` ("no match") cleanly.
    """

    def _open_channel(self, status_responder):
        from seedsigner.helpers.keycard.global_platform import GpSecureChannel

        class _StatusCard(_MockCard):
            def transmit(self, apdu):
                # GET STATUS: CLA=0x84, INS=0xF2.
                if apdu[0] == 0x84 and apdu[1] == 0xF2:
                    p2 = apdu[3]
                    return status_responder(p2)
                return super().transmit(apdu)

        gp = GpSecureChannel(_StatusCard())
        gp.select_isd()
        gp.open(host_challenge=b"\x01" * 8)
        return gp

    def test_pages_on_6310_and_concatenates(self):
        from seedsigner.helpers.keycard.global_platform import list_instances

        aid_a = bytes.fromhex("A000000804000101")
        aid_b = bytes.fromhex("A00000080400010102")
        entry_a = bytes([0x4F, len(aid_a)]) + aid_a + bytes.fromhex("9F70017FC50100")
        entry_b = bytes([0x4F, len(aid_b)]) + aid_b + bytes.fromhex("9F70017FC50100")
        page1 = bytes([0xE3, len(entry_a)]) + entry_a
        page2 = bytes([0xE3, len(entry_b)]) + entry_b
        responses = iter([page1, page2])
        sws = iter([(0x63, 0x10), (0x90, 0x00)])

        def responder(p2):
            return (list(next(responses)), *next(sws))

        gp = self._open_channel(responder)
        result = list_instances(gp)
        self.assertEqual([i.aid for i in result], [aid_a, aid_b])

    def test_falls_back_to_legacy_p2_00(self):
        from seedsigner.helpers.keycard.global_platform import list_instances

        aid = bytes.fromhex("A000000804000101")
        # Legacy entry: AID_len(1) || AID || life || privs
        legacy = bytes([len(aid)]) + aid + b"\x07\x00"

        def responder(p2):
            if p2 == 0x02:
                # Card doesn't support TLV format.
                return ([], 0x6A, 0x86)
            if p2 == 0x00:
                return (list(legacy), 0x90, 0x00)
            return ([], 0x6A, 0x88)

        gp = self._open_channel(responder)
        result = list_instances(gp)
        self.assertEqual([i.aid for i in result], [aid])

    def test_handles_6a88_as_empty(self):
        from seedsigner.helpers.keycard.global_platform import list_instances

        def responder(p2):
            return ([], 0x6A, 0x88)

        gp = self._open_channel(responder)
        result = list_instances(gp)
        self.assertEqual(result, [])


class TestKeycardInstanceAidCandidates(unittest.TestCase):
    def test_emits_both_forms_deduped_9byte_first(self):
        from seedsigner.helpers.keycard.global_platform import (
            keycard_instance_aid_candidates,
        )
        p = bytes.fromhex("A000000804000101")
        cands = keycard_instance_aid_candidates(p, slots=range(0x01, 0x03))
        # slots 1,2 → 9-byte then 10-byte each = 4 entries, no bare prefix.
        self.assertEqual(cands, [
            p + bytes([0x01]),        # 9-byte slot 1
            p + bytes([0x01, 0x01]),  # 10-byte slot 1
            p + bytes([0x02]),        # 9-byte slot 2
            p + bytes([0x01, 0x02]),  # 10-byte slot 2
        ])
        self.assertEqual(len(cands), len(set(cands)))  # de-duped
        self.assertNotIn(p, cands)                     # bare prefix excluded


class TestProbeKeycardInstanceAids(unittest.TestCase):
    def test_finds_aid_via_select(self):
        from seedsigner.helpers.keycard.global_platform import (
            probe_keycard_instance_aids,
        )

        prefix = bytes.fromhex("A000000804000101")
        target = prefix + bytes([0x01, 0x02])

        class _Conn:
            def __init__(self):
                self.calls = []

            def transmit(self, apdu):
                self.calls.append(list(apdu))
                # Each candidate is sent as `00 A4 04 00 LL AID 00`.
                aid_len = apdu[4]
                aid = bytes(apdu[5:5 + aid_len])
                if aid == target:
                    return ([], 0x90, 0x00)
                return ([], 0x6A, 0x82)

        conn = _Conn()
        found = probe_keycard_instance_aids(
            conn, package_prefix=prefix, instance_byte_range=range(0x01, 0x05),
        )
        self.assertEqual(found, [target])
        # Bare prefix + both forms (9-byte ``prefix+X`` and 10-byte
        # ``prefix+01+X``) for each of 4 slots = 1 + 8 = 9 SELECTs total.
        self.assertEqual(len(conn.calls), 9)

    def test_probes_both_aid_conventions(self):
        """A 9-byte canonical instance is found even though older builds only
        probed the 10-byte form (and vice-versa)."""
        from seedsigner.helpers.keycard.global_platform import (
            probe_keycard_instance_aids,
        )

        prefix = bytes.fromhex("A000000804000101")
        nine_byte = prefix + bytes([0x02])          # canonical real-card form
        ten_byte = prefix + bytes([0x01, 0x03])     # legacy SeedSigner form

        class _Conn:
            def transmit(self, apdu):
                aid = bytes(apdu[5:5 + apdu[4]])
                if aid in (nine_byte, ten_byte):
                    return ([], 0x90, 0x00)
                return ([], 0x6A, 0x82)

        found = probe_keycard_instance_aids(
            _Conn(), package_prefix=prefix, instance_byte_range=range(0x01, 0x05),
        )
        self.assertIn(nine_byte, found)
        self.assertIn(ten_byte, found)


class TestScpIdValidation(unittest.TestCase):
    """``open()`` rejects INITIALIZE UPDATE responses that advertise an
    unsupported SCP id, since our KDF only matches SCP02 (i='15')."""

    def test_rejects_non_scp02(self):
        from seedsigner.helpers.keycard.global_platform import (
            GpProtocolError, GpSecureChannel,
        )

        class _Scp01Card(_MockCard):
            def transmit(self, apdu):
                data, sw1, sw2 = super().transmit(apdu)
                if apdu[0] == 0x80 and apdu[1] == 0x50:
                    bad = list(data)
                    bad[11] = 0x01  # SCP id 0x01 instead of 0x02
                    return (bad, sw1, sw2)
                return (data, sw1, sw2)

        gp = GpSecureChannel(_Scp01Card())
        gp.select_isd()
        with self.assertRaisesRegex(GpProtocolError, "SCP id"):
            gp.open(host_challenge=b"\x01" * 8)


if __name__ == "__main__":
    unittest.main()
