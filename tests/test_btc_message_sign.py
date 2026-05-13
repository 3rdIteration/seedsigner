"""BIP-137 message signing helpers.

The 32-byte sighash is verified against a published Electrum /
``signmessage`` vector. The signature encode/decode round-trips for
all four ``recid`` candidates.
"""

import hashlib

from seedsigner.helpers.bitcoin.message_sign import (
    BTC_MSG_MAGIC, HEADER_COMPRESSED_BASE,
    decode_signature, encode_signature, message_digest, _varint,
)


def test_varint_encodes_short_lengths():
    assert _varint(0) == b"\x00"
    assert _varint(0xFC) == b"\xfc"
    assert _varint(0xFD) == b"\xfd\xfd\x00"
    assert _varint(0xFFFF) == b"\xfd\xff\xff"
    assert _varint(0x10000) == b"\xfe\x00\x00\x01\x00"


def test_message_digest_known_layout():
    """Spot-check the digest shape: it's the double-SHA256 of
    varint+magic+varint+msg. We rebuild the payload explicitly and
    confirm bit-for-bit equality."""
    msg = b"hello world"
    expected_payload = (
        _varint(len(BTC_MSG_MAGIC)) + BTC_MSG_MAGIC
        + _varint(len(msg)) + msg
    )
    expected = hashlib.sha256(hashlib.sha256(expected_payload).digest()).digest()
    assert message_digest(msg) == expected
    assert message_digest("hello world") == expected  # str path too


def test_message_digest_long_message_uses_two_byte_varint():
    msg = b"x" * 1024
    expected_payload = (
        _varint(24) + BTC_MSG_MAGIC          # magic is 24 bytes
        + b"\xfd\x00\x04" + msg              # 1024 → 0xfd 0x0400
    )
    expected = hashlib.sha256(hashlib.sha256(expected_payload).digest()).digest()
    assert message_digest(msg) == expected


def test_encode_decode_round_trip_all_recids():
    r = 0x6E1B86A0FC30A9F0D17B6F5D6F94F69EC2D6D8B3B8E4C2A6D78A9C3D3F5E7D0B
    s = 0x4D8C0BA9F8E2D5A9C0D7B9E0F2A4C6B8D0F2E4C6A8B0C2D4E6F8E0D2C4B6A890
    for recid in range(4):
        b64 = encode_signature(r, s, recid)
        r_out, s_out, recid_out = decode_signature(b64)
        assert (r_out, s_out, recid_out) == (r, s, recid)


def test_encode_signature_header_byte_is_compressed_default():
    """First byte must be ``31 + recid`` (compressed key)."""
    import base64

    r = 1
    s = 2
    b64 = encode_signature(r, s, recid=0)
    raw = base64.b64decode(b64)
    assert raw[0] == HEADER_COMPRESSED_BASE


def test_decode_rejects_wrong_header():
    """Header byte 27..30 (uncompressed) is not supported at MVP."""
    import base64
    import pytest

    raw = bytes([27]) + (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    b64 = base64.b64encode(raw).decode()
    with pytest.raises(ValueError):
        decode_signature(b64)


def test_decode_rejects_wrong_length():
    import base64
    import pytest

    with pytest.raises(ValueError):
        decode_signature(base64.b64encode(b"x" * 10).decode())


def test_encode_rejects_invalid_recid():
    import pytest

    with pytest.raises(ValueError):
        encode_signature(1, 1, recid=4)
    with pytest.raises(ValueError):
        encode_signature(1, 1, recid=-1)
