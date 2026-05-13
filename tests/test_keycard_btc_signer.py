"""Unit tests for the pure-function helpers in ``keycard_btc_signer``.

The hardware-dependent paths (``export_xpub``, ``sign_psbt``,
``sign_message``) need a real Keycard + ``KeycardClient`` to exercise
end-to-end — those run under ``scripts/keycard_smoke_test.py --btc``.
Here we just verify the bits that have no card dependency:

  - BIP-32 path string parser
  - DER encoder for ECDSA (r, s) — round-trip via embit
  - Pubkey compression
  - Extended-export TLV parser
"""

import pytest

from embit.ec import Signature

from seedsigner.helpers.keycard_btc_signer import (
    _parse_extended_export, _parse_pubkey_only, compress_pubkey,
    encode_der_signature, path_str_to_components,
)


_HARDENED = 0x80000000


# ---------------------------------------------------------------------------
# Path parsing
# ---------------------------------------------------------------------------


def test_path_root_yields_empty():
    assert path_str_to_components("m") == []


def test_path_bip84_account_zero():
    assert path_str_to_components("m/84'/0'/0'") == [
        84 | _HARDENED, 0 | _HARDENED, 0 | _HARDENED,
    ]


def test_path_bip84_first_receive():
    assert path_str_to_components("m/84'/0'/0'/0/0") == [
        84 | _HARDENED, 0 | _HARDENED, 0 | _HARDENED, 0, 0,
    ]


def test_path_accepts_h_marker():
    assert path_str_to_components("m/84h/0h/0h/0/5") == [
        84 | _HARDENED, 0 | _HARDENED, 0 | _HARDENED, 0, 5,
    ]


def test_path_rejects_missing_prefix():
    with pytest.raises(ValueError):
        path_str_to_components("84'/0'/0'")


def test_path_rejects_overflow():
    with pytest.raises(ValueError):
        # 0x80000000 unhardened is not representable.
        path_str_to_components("m/2147483648")


# ---------------------------------------------------------------------------
# Pubkey compression
# ---------------------------------------------------------------------------


def test_compress_pubkey_even_y():
    # x = 1, y = ...0  (even). Build a fake 65-byte that ends in 0x00.
    raw = b"\x04" + b"\x01" * 32 + b"\xfe" * 31 + b"\x00"
    out = compress_pubkey(raw)
    assert out == b"\x02" + b"\x01" * 32


def test_compress_pubkey_odd_y():
    raw = b"\x04" + b"\x02" * 32 + b"\xfe" * 31 + b"\x01"
    out = compress_pubkey(raw)
    assert out == b"\x03" + b"\x02" * 32


def test_compress_pubkey_rejects_bad_prefix():
    with pytest.raises(ValueError):
        compress_pubkey(b"\x05" + b"\x00" * 64)


def test_compress_pubkey_rejects_bad_length():
    with pytest.raises(ValueError):
        compress_pubkey(b"\x04" + b"\x00" * 60)


# ---------------------------------------------------------------------------
# DER encoding
# ---------------------------------------------------------------------------


def test_encode_der_round_trips_via_embit():
    """Embit can parse our DER output back without raising, and the
    re-serialised bytes round-trip exactly."""
    r = 0x4F8C0BA9F8E2D5A9C0D7B9E0F2A4C6B8D0F2E4C6A8B0C2D4E6F8E0D2C4B6A890
    s = 0x6E1B86A0FC30A9F0D17B6F5D6F94F69EC2D6D8B3B8E4C2A6D78A9C3D3F5E7D0B
    der = encode_der_signature(r, s)
    parsed = Signature.parse(der)
    assert parsed.serialize() == der


def test_encode_der_matches_manual_layout():
    """Plain (r, s) with no high-bit padding: DER body is two
    ``02 20 <32-byte int>`` TLVs."""
    r = 0x4F8C0BA9F8E2D5A9C0D7B9E0F2A4C6B8D0F2E4C6A8B0C2D4E6F8E0D2C4B6A890
    s = 0x6E1B86A0FC30A9F0D17B6F5D6F94F69EC2D6D8B3B8E4C2A6D78A9C3D3F5E7D0B
    der = encode_der_signature(r, s)
    expected_body = (
        b"\x02\x20" + r.to_bytes(32, "big")
        + b"\x02\x20" + s.to_bytes(32, "big")
    )
    assert der == b"\x30" + bytes([len(expected_body)]) + expected_body


def test_encode_der_pads_high_bit_with_zero():
    """If the high bit of r or s is set, DER mandates a leading 0x00
    byte so the integer is unambiguously positive."""
    high_bit = 0x80 << (31 * 8)  # 32-byte int with MSB set
    der = encode_der_signature(high_bit | 1, 1)
    # tag 0x30, len, tag 0x02, len=0x21 (33), 0x00, r..., tag 0x02, len=0x01, 0x01
    assert der[2] == 0x02
    assert der[3] == 0x21
    assert der[4] == 0x00


# ---------------------------------------------------------------------------
# Extended-export TLV parser
# ---------------------------------------------------------------------------


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag, len(body)]) + body


def test_parse_extended_export_outer_template():
    pub = b"\x04" + b"\x11" * 64
    chain = b"\x22" * 32
    inner = _tlv(0x80, pub) + _tlv(0x82, chain)
    blob = _tlv(0xA1, inner)
    out_pub, out_chain = _parse_extended_export(blob)
    assert out_pub == pub
    assert out_chain == chain


def test_parse_extended_export_inline_tlvs():
    """Older firmware variants drop the outer ``0xA1`` template."""
    pub = b"\x04" + b"\x33" * 64
    chain = b"\x44" * 32
    blob = _tlv(0x80, pub) + _tlv(0x82, chain)
    out_pub, out_chain = _parse_extended_export(blob)
    assert out_pub == pub
    assert out_chain == chain


def test_parse_extended_export_rejects_missing_chain_code():
    pub = b"\x04" + b"\x11" * 64
    blob = _tlv(0xA1, _tlv(0x80, pub))
    with pytest.raises(ValueError):
        _parse_extended_export(blob)


def test_parse_pubkey_only_round_trip():
    pub = b"\x04" + b"\xab" * 64
    blob = _tlv(0xA1, _tlv(0x80, pub))
    assert _parse_pubkey_only(blob) == pub
