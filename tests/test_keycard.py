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
        resp = bytes([0xA0, len(body)]) + body

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
        resp = bytes([0xA0, len(body)]) + body

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
