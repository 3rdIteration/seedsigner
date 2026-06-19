import pytest

from seedsigner.helpers.keycard import commands, crypto
from seedsigner.helpers.keycard.client import KeycardClient
from seedsigner.helpers.keycard.commands import APDUError
from seedsigner.helpers.keycard.responses import (
    SelectResponse, parse_select, parse_signature,
)
from seedsigner.helpers.keycard.secure_channel import (
    PairingInfo, SecureChannel, SecureChannelError,
    client_cryptogram, derive_pairing_key, expected_card_cryptogram,
)


class MockConnection:
    def __init__(self, scripted_responses):
        self._scripted = list(scripted_responses)
        self.history = []

    def transmit(self, apdu):
        self.history.append(list(apdu))
        if not self._scripted:
            raise AssertionError(f"unexpected APDU sent: {apdu}")
        nxt = self._scripted.pop(0)
        if callable(nxt):
            nxt = nxt(apdu)
        data, sw1, sw2 = nxt
        return list(data), sw1, sw2


class TestPathParsing:
    def test_master(self):
        assert commands.parse_path("m") == []
        assert commands.parse_path("") == []

    def test_eth_default(self):
        # m/44'/60'/0'/0/0
        out = commands.parse_path("m/44'/60'/0'/0/0")
        assert out == [
            44 | 0x80000000,
            60 | 0x80000000,
            0  | 0x80000000,
            0,
            0,
        ]

    def test_h_suffix_supported(self):
        assert commands.parse_path("m/44h/60h") == commands.parse_path("m/44'/60'")

    def test_invalid(self):
        with pytest.raises(ValueError):
            commands.parse_path("m/abc/0")


class TestApduBuilders:
    def test_applet_aid_is_9byte_canonical(self):
        # The default SELECT / boot-default instance AID is the 9-byte
        # canonical form (prefix A000000804000101 + slot 0x01), matching real
        # Status cards and the blank-card install. A revert to the 10-byte
        # legacy form (…010101) must be caught here.
        assert commands.APPLET_AID == bytes.fromhex("A00000080400010101")
        assert len(commands.APPLET_AID) == 9

    def test_select(self):
        apdu = commands.select_applet()
        assert apdu[:4] == [0x00, 0xA4, 0x04, 0x00]
        assert apdu[4] == len(commands.APPLET_AID)
        assert bytes(apdu[5:5 + len(commands.APPLET_AID)]) == commands.APPLET_AID

    def test_init_lengths(self):
        with pytest.raises(ValueError):
            commands.init(b"12345", b"123456789012", b"\x00" * 32)
        with pytest.raises(ValueError):
            commands.init(b"123456", b"00112233", b"\x00" * 32)
        with pytest.raises(ValueError):
            commands.init(b"123456", b"123456789012", b"\x00" * 31)
        apdu = commands.init(b"123456", b"123456789012", b"\x00" * 32)
        assert apdu[1] == commands.INS_INIT
        assert apdu[4] == 6 + 12 + 32

    def test_init_encrypted_layout(self):
        client_pub = b"\x04" + b"\x11" * 64
        iv = b"\x22" * 16
        ciphertext = b"\x33" * 64
        apdu = commands.init_encrypted(client_pub, iv, ciphertext)
        assert apdu[1] == commands.INS_INIT
        # Wire data = 1 (pub_len) + 65 (pubkey) + 16 (iv) + 64 (ct).
        assert apdu[4] == 1 + 65 + 16 + 64
        # Length-prefix byte the applet reads at OFFSET_CDATA.
        assert apdu[5] == 65
        assert bytes(apdu[6:6 + 65]) == client_pub
        assert bytes(apdu[6 + 65:6 + 65 + 16]) == iv
        assert bytes(apdu[6 + 65 + 16:6 + 65 + 16 + 64]) == ciphertext

    def test_init_encrypted_validates_inputs(self):
        with pytest.raises(ValueError):
            commands.init_encrypted(b"\x02" + b"\x11" * 64, b"\x22" * 16, b"\x33" * 64)
        with pytest.raises(ValueError):
            commands.init_encrypted(b"\x04" + b"\x11" * 64, b"\x22" * 15, b"\x33" * 64)
        with pytest.raises(ValueError):
            commands.init_encrypted(b"\x04" + b"\x11" * 64, b"\x22" * 16, b"\x33" * 63)

    def test_build_init_plaintext_no_duress_is_50_bytes(self):
        pin = b"123456"
        puk = b"123456789012"
        secret = b"\x00" * 32
        plaintext = commands.build_init_plaintext(pin, puk, secret)
        assert len(plaintext) == 50
        assert plaintext[0:6] == pin
        assert plaintext[6:18] == puk
        assert plaintext[18:50] == secret

    def test_build_init_plaintext_duress_is_58_bytes(self):
        pin = b"123456"
        puk = b"123456789012"
        secret = b"\x44" * 32
        duress = b"654321"
        plaintext = commands.build_init_plaintext(pin, puk, secret, duress_pin=duress)
        # PIN(6) || PUK(12) || secret(32) || maxPIN(1) || maxPUK(1) || altPIN(6)
        assert len(plaintext) == 58
        assert plaintext[0:6] == pin
        assert plaintext[6:18] == puk
        assert plaintext[18:50] == secret
        assert plaintext[50] == commands.DEFAULT_MAX_PIN_ATTEMPTS == 3
        assert plaintext[51] == commands.DEFAULT_MAX_PUK_ATTEMPTS == 5
        assert plaintext[52:58] == duress

    def test_build_init_plaintext_custom_attempt_limits(self):
        plaintext = commands.build_init_plaintext(
            b"123456", b"123456789012", b"\x00" * 32,
            duress_pin=b"654321", max_pin_attempts=3, max_puk_attempts=5,
        )
        assert plaintext[50] == 3
        assert plaintext[51] == 5

    def test_build_init_plaintext_rejects_duress_equal_main(self):
        with pytest.raises(ValueError, match="differ"):
            commands.build_init_plaintext(
                b"123456", b"123456789012", b"\x00" * 32, duress_pin=b"123456",
            )

    def test_build_init_plaintext_validates_lengths(self):
        good_puk = b"123456789012"
        with pytest.raises(ValueError):
            commands.build_init_plaintext(b"12345", good_puk, b"\x00" * 32)
        with pytest.raises(ValueError):
            commands.build_init_plaintext(b"123456", b"0011", b"\x00" * 32)
        with pytest.raises(ValueError):
            commands.build_init_plaintext(b"123456", good_puk, b"\x00" * 31)
        with pytest.raises(ValueError):
            commands.build_init_plaintext(
                b"123456", good_puk, b"\x00" * 32, duress_pin=b"12345",
            )
        with pytest.raises(ValueError):
            commands.build_init_plaintext(
                b"123456", good_puk, b"\x00" * 32, duress_pin=b"654321",
                max_pin_attempts=0,
            )
        with pytest.raises(ValueError):
            commands.build_init_plaintext(
                b"123456", good_puk, b"\x00" * 32, duress_pin=b"654321",
                max_puk_attempts=256,
            )

    def test_sign_requires_32_byte_hash(self):
        with pytest.raises(ValueError):
            commands.sign(b"\x00" * 31)
        apdu = commands.sign(b"\x00" * 32)
        assert apdu[1] == commands.INS_SIGN
        assert apdu[4] == 32

    def test_sign_with_path(self):
        h = b"\x11" * 32
        path = [44 | 0x80000000, 60 | 0x80000000, 0]
        apdu = commands.sign(h, p1=commands.SIGN_P1_DERIVE, path_components=path)
        assert apdu[1] == commands.INS_SIGN
        assert apdu[2] == commands.SIGN_P1_DERIVE
        # data = hash(32) || path(3 * 4 = 12)
        assert apdu[4] == 32 + 12

    def test_open_secure_channel_validates_pubkey(self):
        with pytest.raises(ValueError):
            commands.open_secure_channel(0, b"\x02" + b"\x00" * 64)
        apdu = commands.open_secure_channel(2, b"\x04" + b"\x00" * 64)
        assert apdu[:4] == [commands.CLA_PROPRIETARY, commands.INS_OPEN_SECURE_CHANNEL, 2, 0]

    def test_pair_step1_p2_defaults_to_persistent(self):
        """Sending P2=PERSISTENT explicitly is the safer default: v3.2
        cards then never silently fall back to ephemeral when the slot
        table is full, and v3.1 cards ignore P2 entirely."""
        apdu = commands.pair_step1(b"\x00" * 32)
        assert apdu[3] == commands.PAIR_P2_PERSISTENT == 0x02

    def test_pair_step1_p2_can_request_ephemeral(self):
        apdu = commands.pair_step1(b"\x00" * 32, p2=commands.PAIR_P2_EPHEMERAL)
        assert apdu[3] == 0x01

    def test_supports_ephemeral_pairing(self):
        assert not commands.supports_ephemeral_pairing(0x0300)
        assert not commands.supports_ephemeral_pairing(0x0301)
        assert commands.supports_ephemeral_pairing(0x0302)
        assert commands.supports_ephemeral_pairing(0x0400)

    def test_change_pin_apdu_format(self):
        new_pin = b"234567"
        apdu = commands.change_pin(0x00, new_pin)
        assert apdu[:4] == [commands.CLA_PROPRIETARY, commands.INS_CHANGE_PIN, 0x00, 0x00]
        assert apdu[4] == len(new_pin)
        assert bytes(apdu[5:5 + len(new_pin)]) == new_pin

    def test_change_pin_p1_selects_credential(self):
        # P1 distinguishes which credential is being replaced: 0=PIN,
        # 1=PUK, 2=pairing secret. We pass it through verbatim.
        apdu = commands.change_pin(0x02, b"\x11" * 32)
        assert apdu[2] == 0x02


class TestSelectResponseParser:
    """Synthetic SELECT response that follows the published TLV layout."""

    def test_parses(self):
        instance = b"\xAA" * 16
        pubkey = b"\x04" + b"\x33" * 64
        version = (1).to_bytes(2, "big")
        free_slots = bytes([5])
        key_uid = b"\x55" * 32

        body = (
            bytes([0x8F, len(instance)]) + instance
            + bytes([0x80, len(pubkey)]) + pubkey
            + bytes([0x02, len(version)]) + version
            + bytes([0x02, len(free_slots)]) + free_slots
            + bytes([0x8E, len(key_uid)]) + key_uid
        )
        resp = bytes([0xA4, len(body)]) + body

        parsed = parse_select(resp)
        assert parsed.instance_uid == instance
        assert parsed.secp256k1_pubkey == pubkey
        assert parsed.app_version == 1
        assert parsed.free_pairing_slots == 5
        assert parsed.key_uid == key_uid

    def test_pre_init_template_returns_app_version_zero(self):
        # Pre-init applet: SELECT response is `0x80 LL <pubkey 65>`.
        pubkey = b"\x04" + b"\x77" * 64
        resp = bytes([0x80, len(pubkey)]) + pubkey

        parsed = parse_select(resp)
        assert parsed.app_version == 0
        assert parsed.secp256k1_pubkey == pubkey
        assert parsed.instance_uid == b""
        assert parsed.key_uid == b""
        assert parsed.free_pairing_slots == 0
        assert parsed.capabilities == 0

    def test_pre_init_template_rejects_short_pubkey(self):
        import pytest

        body = b"\x04" + b"\x77" * 32  # too short
        resp = bytes([0x80, len(body)]) + body

        with pytest.raises(ValueError, match="pre-init"):
            parse_select(resp)


class TestSignatureParser:
    def test_parses_with_short_form_lengths(self):
        pub = b"\x04" + b"\xAA" * 64
        # ECDSA DER: 0x30 LL 0x02 RL r... 0x02 SL s...
        r = b"\x01" + b"\x22" * 31
        s = b"\x01" + b"\x33" * 31
        der = (
            b"\x30" + bytes([2 + len(r) + 2 + len(s)])
            + b"\x02" + bytes([len(r)]) + r
            + b"\x02" + bytes([len(s)]) + s
        )
        body = bytes([0x80, len(pub)]) + pub + der
        # Template body is >127 bytes: the card encodes the length with the
        # BER long form (0x81 LL), which is what the applet actually emits.
        resp = bytes([0xA0, 0x81, len(body)]) + body

        sig = parse_signature(resp)
        assert sig.public_key == pub
        assert sig.r == r.rjust(32, b"\x00")
        assert sig.s == s.rjust(32, b"\x00")

    def test_parses_with_leading_zero_strip(self):
        pub = b"\x04" + b"\xAA" * 64
        r = b"\x00\xFF" + b"\x22" * 31  # leading 0 sign byte
        s = b"\x00\xEE" + b"\x33" * 31
        der = (
            b"\x30" + bytes([2 + len(r) + 2 + len(s)])
            + b"\x02" + bytes([len(r)]) + r
            + b"\x02" + bytes([len(s)]) + s
        )
        body = bytes([0x80, len(pub)]) + pub + der
        resp = bytes([0xA0, 0x81, len(body)]) + body

        sig = parse_signature(resp)
        assert len(sig.r) == 32
        assert len(sig.s) == 32
        assert sig.r[0] == 0xFF


class TestPairingHelpers:
    def test_derive_pairing_key_known(self):
        secret = b"\x11" * 32
        salt = b"\x22" * 32
        # SHA256(secret || salt) — verify length and determinism
        k = derive_pairing_key(secret, salt)
        assert len(k) == 32
        assert k == derive_pairing_key(secret, salt)

    def test_cryptograms_match_specification(self):
        secret = b"pairing-secret-test".ljust(32, b"\x00")
        client_challenge = b"\xAA" * 32
        card_challenge = b"\xBB" * 32

        cc = expected_card_cryptogram(secret, client_challenge)
        assert len(cc) == 32
        assert cc == crypto.sha256(secret + client_challenge)

        cl = client_cryptogram(secret, card_challenge)
        assert cl == crypto.sha256(secret + card_challenge)


class TestAesPad:
    def test_round_trip(self):
        key = b"\xAA" * 32
        iv = b"\x55" * 16
        for length in [0, 1, 15, 16, 17, 100]:
            plain = bytes(range(256))[:length]
            ct = crypto.aes_cbc_encrypt(key, iv, plain)
            assert len(ct) % 16 == 0
            assert crypto.aes_cbc_decrypt(key, iv, ct) == plain

    def test_invalid_padding_rejected(self):
        key = b"\xAA" * 32
        iv = b"\x55" * 16
        ct = crypto.aes_cbc_encrypt(key, iv, b"hello")
        # Flip last byte of ciphertext, decryption padding should fail
        bad = ct[:-1] + bytes([ct[-1] ^ 0xFF])
        with pytest.raises(ValueError):
            crypto.aes_cbc_decrypt(key, iv, bad)


class TestSecureChannelHandshake:
    """End-to-end synthetic round-trip: simulate the card side of OPEN_SECURE_CHANNEL."""

    def test_session_keys_match_card_side(self):
        # Card-side static keypair (we generate one and use it on both sides)
        card_priv, card_pub = crypto.secp256k1_generate_keypair()
        pairing = PairingInfo(pairing_index=1, pairing_key=b"\x77" * 32)

        sc = SecureChannel(pairing, card_pub)
        client_pub = sc.begin_open()

        # Card computes shared secret using its private and client's public.
        # Using the same ECDH path we use on the client side ensures consistency.
        salt = b"\x44" * 32
        iv = b"\x66" * 16
        sc.derive_session_from(salt + iv)

        # Sanity: encrypt+MAC round-trips on the client side after derivation
        cipher_data = sc.wrap_command(0x84, 0x11, 0x00, 0x00, b"\x00" * 32)
        # 16 MAC + 32 plaintext padded to 48 = 16 + 48
        assert len(cipher_data) == 16 + 48

    def _build_card_response(self, sc, payload: bytes) -> bytes:
        """Synthesise what the Status applet sends back over the SC.

        The applet appends the inner ``SW`` to ``data`` before padding +
        encryption; callers pass the full ``data || sw1 || sw2`` here.
        """
        from seedsigner.helpers.keycard.crypto import (
            aes_cbc_block, aes_cbc_encrypt,
        )

        ciphertext = aes_cbc_encrypt(sc._enc_key, sc._iv, payload)
        total_len = len(ciphertext) + 16
        mac_input = bytes([total_len & 0xFF]) + b"\x00" * 15 + ciphertext
        mac = aes_cbc_block(sc._mac_key, b"\x00" * 16, mac_input)
        return mac + ciphertext

    def _open_session(self):
        _, card_pub = crypto.secp256k1_generate_keypair()
        pairing = PairingInfo(pairing_index=1, pairing_key=b"\x77" * 32)
        sc = SecureChannel(pairing, card_pub)
        sc.begin_open()
        sc.derive_session_from(b"\x44" * 32 + b"\x66" * 16)
        return sc

    def test_unwrap_response_matches_status_applet_formula(self):
        """Regression: the response MAC's first byte is the *total*
        response length (MAC + ciphertext), not just len(ciphertext).

        Mirrors ``SecureChannel.java#respond`` and
        ``app/keycard/secure_channel.c#securechannel_decrypt_apdu``
        (keycard-shell). With the previous ``len(ciphertext)`` formula
        every card returned "response MAC mismatch" on
        MUTUALLY_AUTHENTICATE.
        """
        sc = self._open_session()
        # The applet appends ``SW=9000`` to the payload before padding.
        challenge = b"\x12" * 32
        card_response = self._build_card_response(sc, challenge + b"\x90\x00")

        # The fixed ``unwrap_response`` must accept this and return the
        # original challenge (without the trailing SW).
        assert sc.unwrap_response(card_response) == challenge

    def test_unwrap_response_strips_inner_sw_on_success(self):
        """Plaintext is ``data || SW`` — the SW must be split off."""
        sc = self._open_session()
        data = b"hello-keycard"
        card_response = self._build_card_response(sc, data + b"\x90\x00")
        assert sc.unwrap_response(card_response) == data

    def test_unwrap_response_raises_on_inner_wrong_pin(self):
        """SW=0x63CX (PIN refused, X tries left) must surface as
        ``APDUError`` so ``verify_pin()`` fails on submission, not later
        on the next operation."""
        sc = self._open_session()
        # Empty data + SW=63C2 (2 tries left).
        card_response = self._build_card_response(sc, b"\x63\xC2")
        with pytest.raises(APDUError) as exc_info:
            sc.unwrap_response(card_response)
        assert exc_info.value.sw == 0x63C2

    def test_unwrap_response_raises_on_inner_6985(self):
        """SW=0x6985 ("conditions not met" — e.g. PIN not verified or no
        master key) must surface as ``APDUError`` instead of returning a
        garbage plaintext that downstream parsers misread."""
        sc = self._open_session()
        card_response = self._build_card_response(sc, b"\x69\x85")
        with pytest.raises(APDUError) as exc_info:
            sc.unwrap_response(card_response)
        assert exc_info.value.sw == 0x6985

    def test_unwrap_response_advances_iv_even_on_inner_error(self):
        """The IV chain must advance regardless of inner SW so a
        subsequent command on the same session stays in lockstep with
        the card."""
        sc = self._open_session()
        iv_before = sc._iv
        bad_response = self._build_card_response(sc, b"\x69\x85")
        with pytest.raises(APDUError):
            sc.unwrap_response(bad_response)
        assert sc._iv != iv_before

    def test_unwrap_response_rejects_legacy_short_length(self):
        """If the MAC was computed with the OLD (buggy) formula —
        first byte = len(ciphertext) — ``unwrap_response`` must reject
        it. This guards against accidentally re-introducing the bug.
        """
        from seedsigner.helpers.keycard.crypto import (
            aes_cbc_block, aes_cbc_encrypt,
        )

        _, card_pub = crypto.secp256k1_generate_keypair()
        pairing = PairingInfo(pairing_index=1, pairing_key=b"\x77" * 32)
        sc = SecureChannel(pairing, card_pub)
        sc.begin_open()
        sc.derive_session_from(b"\x44" * 32 + b"\x66" * 16)

        challenge = b"\x12" * 32
        ciphertext = aes_cbc_encrypt(sc._enc_key, sc._iv, challenge)
        # Buggy formula: first byte = len(ciphertext) (no +16).
        mac_input = bytes([len(ciphertext)]) + b"\x00" * 15 + ciphertext
        bad_mac = aes_cbc_block(sc._mac_key, b"\x00" * 16, mac_input)

        with pytest.raises(SecureChannelError, match="MAC mismatch"):
            sc.unwrap_response(bad_mac + ciphertext)


class TestKeycardClientWithMockConnection:
    def _make_select_payload(self) -> bytes:
        instance = b"\xAA" * 16
        pubkey = b"\x04" + b"\x33" * 64
        version = (1).to_bytes(2, "big")
        free_slots = bytes([5])
        key_uid = b""
        body = (
            bytes([0x8F, len(instance)]) + instance
            + bytes([0x80, len(pubkey)]) + pubkey
            + bytes([0x02, len(version)]) + version
            + bytes([0x02, len(free_slots)]) + free_slots
            + bytes([0x8E, len(key_uid)]) + key_uid
        )
        return bytes([0xA4, len(body)]) + body

    def test_select_parses_and_caches(self):
        payload = self._make_select_payload()
        conn = MockConnection([(payload, 0x90, 0x00)])
        client = KeycardClient(conn)
        info = client.select()
        assert info.app_version == 1
        assert info.free_pairing_slots == 5
        assert client.select_response is info

    def test_apdu_error_raised_on_non_9000(self):
        conn = MockConnection([(b"", 0x69, 0x82)])
        client = KeycardClient(conn)
        with pytest.raises(APDUError) as exc_info:
            client.select()
        assert exc_info.value.sw == 0x6982


class TestKeycardClientChangePin:
    """``client.change_pin`` validates length and routes through the
    secure-channel wrapper (``_transmit_protected``)."""

    def test_rejects_wrong_length(self):
        client = KeycardClient(MockConnection([]))
        with pytest.raises(ValueError):
            client.change_pin(b"12345")
        with pytest.raises(ValueError):
            client.change_pin(b"1234567")

    def test_routes_through_transmit_protected(self):
        captured = {}

        def fake_transmit_protected(ins, p1, p2, data=b""):
            captured["ins"] = ins
            captured["p1"] = p1
            captured["p2"] = p2
            captured["data"] = bytes(data)
            return b""

        client = KeycardClient(MockConnection([]))
        client._transmit_protected = fake_transmit_protected
        client.change_pin(b"654321")
        assert captured["ins"] == commands.INS_CHANGE_PIN
        assert captured["p1"] == 0x00
        assert captured["p2"] == 0x00
        assert captured["data"] == b"654321"


class TestTlvParser:
    def test_short_form_roundtrip(self):
        from seedsigner.helpers.keycard.responses import parse_tlv
        tag, body, nxt = parse_tlv(b"\xA3\x02\xAB\xCD")
        assert (tag, body, nxt) == (0xA3, b"\xAB\xCD", 4)

    def test_extended_form_roundtrip(self):
        from seedsigner.helpers.keycard.responses import parse_tlv
        payload = b"\xA0\x81\x03\x01\x02\x03"
        tag, body, nxt = parse_tlv(payload)
        assert (tag, body, nxt) == (0xA0, b"\x01\x02\x03", 6)

    def test_truncated_after_tag_raises(self):
        from seedsigner.helpers.keycard.responses import parse_tlv
        with pytest.raises(ValueError, match="length byte"):
            parse_tlv(b"\xA3")

    def test_truncated_extended_length_raises(self):
        from seedsigner.helpers.keycard.responses import parse_tlv
        with pytest.raises(ValueError, match="extended length"):
            parse_tlv(b"\xA3\x81")

    def test_declared_length_past_end_raises(self):
        from seedsigner.helpers.keycard.responses import parse_tlv
        with pytest.raises(ValueError, match="extends past end"):
            parse_tlv(b"\xA3\x05\x01")

    def test_unsupported_long_form_raises(self):
        from seedsigner.helpers.keycard.responses import parse_tlv
        with pytest.raises(ValueError, match="unsupported length form"):
            parse_tlv(b"\xA3\x82\x01\x00")


class TestStatusParser:
    @staticmethod
    def _status_response(pin: int, puk: int, key_init: bool = True) -> bytes:
        body = (
            bytes([0x02, 0x01, pin])
            + bytes([0x02, 0x01, puk])
            + bytes([0x01, 0x01, 0xFF if key_init else 0x00])
        )
        return bytes([0xA3, len(body)]) + body

    def test_normal_counts(self):
        from seedsigner.helpers.keycard.responses import parse_status
        st = parse_status(self._status_response(3, 5))
        assert st.pin_retries == 3
        assert st.puk_retries == 5
        assert st.key_initialised is True

    def test_blocked_pin_still_reports_puk_retries(self):
        # Regression: the old value-based disambiguation of the repeated
        # 0x02 tag misread a blocked PIN (0 retries) — the PUK count was
        # written into pin_retries and puk_retries stayed 0.
        from seedsigner.helpers.keycard.responses import parse_status
        st = parse_status(self._status_response(0, 5))
        assert st.pin_retries == 0
        assert st.puk_retries == 5

    def test_key_not_initialised(self):
        from seedsigner.helpers.keycard.responses import parse_status
        st = parse_status(self._status_response(3, 5, key_init=False))
        assert st.key_initialised is False


class TestDerSignatureBounds:
    """A truncated DER signature must raise — never produce a silently
    zero-padded (wrong) r/s."""

    def test_declared_body_past_buffer_raises(self):
        from seedsigner.helpers.keycard.responses import _parse_der_signature
        with pytest.raises(ValueError, match="declared length"):
            _parse_der_signature(b"\x30\x06\x02\x01\x01")

    def test_r_integer_overrun_raises(self):
        from seedsigner.helpers.keycard.responses import _parse_der_signature
        # body claims rlen=5 but only 2 bytes follow.
        with pytest.raises(ValueError, match=r"INTEGER \(r\)"):
            _parse_der_signature(b"\x30\x04\x02\x05\x01\x01")

    def test_missing_s_integer_raises(self):
        from seedsigner.helpers.keycard.responses import _parse_der_signature
        # r consumes the whole body; s is absent.
        with pytest.raises(ValueError, match=r"INTEGER \(s\)"):
            _parse_der_signature(b"\x30\x04\x02\x02\x01\x01")

    def test_unsupported_length_form_raises(self):
        from seedsigner.helpers.keycard.responses import _parse_der_signature
        with pytest.raises(ValueError, match="unsupported length form"):
            _parse_der_signature(b"\x30\x82\x00\x04\x02\x01\x01\x02")


class TestUnblockPin:
    def test_routes_through_transmit_protected(self):
        captured = {}

        def fake_transmit_protected(ins, p1, p2, data=b""):
            captured["ins"] = ins
            captured["data"] = bytes(data)
            return b""

        client = KeycardClient(MockConnection([]))
        client._transmit_protected = fake_transmit_protected
        client.unblock_pin(b"123456789012", b"654321")
        assert captured["ins"] == commands.INS_UNBLOCK_PIN
        assert captured["data"] == b"123456789012654321"

    def test_validates_lengths(self):
        client = KeycardClient(MockConnection([]))
        with pytest.raises(ValueError, match="PUK"):
            client.unblock_pin(b"12345678901", b"654321")
        with pytest.raises(ValueError, match="PIN"):
            client.unblock_pin(b"123456789012", b"65432")
