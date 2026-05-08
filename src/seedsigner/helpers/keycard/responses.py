"""Decoders for Keycard APDU response payloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


def parse_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("TLV: offset past end")
    tag = data[offset]
    if data[offset + 1] == 0x81:
        length = data[offset + 2]
        body_start = offset + 3
    else:
        length = data[offset + 1]
        body_start = offset + 2
    body = data[body_start : body_start + length]
    return tag, bytes(body), body_start + length


@dataclass(frozen=True)
class SelectResponse:
    instance_uid: bytes        # 16 bytes
    secp256k1_pubkey: bytes    # 65 bytes uncompressed
    app_version: int           # major<<8 | minor
    free_pairing_slots: int
    key_uid: bytes             # 32 bytes (or empty if no key)
    capabilities: int          # bitfield


def parse_select(response: bytes) -> SelectResponse:
    # ApplicationInfo template: 0xA4 ...
    tag, body, _ = parse_tlv(response, 0)
    if tag != 0xA4:
        raise ValueError(f"unexpected SELECT response tag {tag:02X}")
    cursor = 0
    fields: List[Tuple[int, bytes]] = []
    while cursor < len(body):
        t, b, cursor = parse_tlv(body, cursor)
        fields.append((t, b))

    # The Status Keycard ApplicationInfo template re-uses tag 0x02 twice
    # (application version, then free pairing slots) so we parse positionally.
    instance_uid = b""
    pubkey = b""
    version = 0
    free_slots = 0
    key_uid = b""
    capabilities = 0
    seen_int_tags = 0

    for t, b in fields:
        if t == 0x8F:
            instance_uid = b
        elif t == 0x80:
            pubkey = b
        elif t == 0x02:
            if seen_int_tags == 0:
                version = int.from_bytes(b, "big") if b else 0
            elif seen_int_tags == 1:
                free_slots = b[0] if b else 0
            seen_int_tags += 1
        elif t == 0x8E:
            key_uid = b
        elif t == 0x8D:
            capabilities = b[0] if b else 0

    return SelectResponse(
        instance_uid=instance_uid,
        secp256k1_pubkey=pubkey,
        app_version=version,
        free_pairing_slots=free_slots,
        key_uid=key_uid,
        capabilities=capabilities,
    )


@dataclass(frozen=True)
class StatusResponse:
    pin_retries: int
    puk_retries: int
    key_initialised: bool


def parse_status(response: bytes) -> StatusResponse:
    # Application Status template: 0xA3 [TLVs]
    tag, body, _ = parse_tlv(response, 0)
    if tag != 0xA3:
        raise ValueError(f"unexpected GET STATUS response tag {tag:02X}")
    cursor = 0
    pin_retries = 0
    puk_retries = 0
    key_init = False
    while cursor < len(body):
        t, b, cursor = parse_tlv(body, cursor)
        if t == 0x02 and pin_retries == 0:
            pin_retries = b[0] if b else 0
        elif t == 0x02 and puk_retries == 0:
            puk_retries = b[0] if b else 0
        elif t == 0x01:
            key_init = b == b"\xff" or (len(b) == 1 and b[0] != 0)
    return StatusResponse(pin_retries=pin_retries, puk_retries=puk_retries, key_initialised=key_init)


@dataclass(frozen=True)
class SignatureResponse:
    public_key: bytes  # 65 bytes uncompressed
    r: bytes           # 32 bytes
    s: bytes           # 32 bytes


def parse_signature(response: bytes) -> SignatureResponse:
    """Parse the SIGN response template.

    Format: 0xA0 [ public_key_tlv (0x80) || ECDSA signature DER (0x30) ].
    """
    tag, body, _ = parse_tlv(response, 0)
    if tag != 0xA0:
        raise ValueError(f"unexpected SIGN response tag {tag:02X}")

    cursor = 0
    pub_tag, pub, cursor = parse_tlv(body, cursor)
    if pub_tag != 0x80:
        raise ValueError(f"expected public key TLV (0x80), got {pub_tag:02X}")
    if len(pub) != 65 or pub[0] != 0x04:
        raise ValueError("public key must be 65-byte uncompressed (0x04-prefixed)")

    der = body[cursor:]
    r, s = _parse_der_signature(der)
    return SignatureResponse(public_key=pub, r=r, s=s)


def _parse_der_signature(der: bytes) -> Tuple[bytes, bytes]:
    if not der or der[0] != 0x30:
        raise ValueError("ECDSA DER must start with 0x30")
    if der[1] == 0x81:
        # length form: 0x30 0x81 LL
        body = der[3:3 + der[2]]
    else:
        body = der[2:2 + der[1]]
    cursor = 0
    if body[cursor] != 0x02:
        raise ValueError("ECDSA DER missing INTEGER (r)")
    rlen = body[cursor + 1]
    r = body[cursor + 2 : cursor + 2 + rlen]
    cursor += 2 + rlen
    if body[cursor] != 0x02:
        raise ValueError("ECDSA DER missing INTEGER (s)")
    slen = body[cursor + 1]
    s = body[cursor + 2 : cursor + 2 + slen]
    return _normalise_int(r), _normalise_int(s)


def _normalise_int(b: bytes) -> bytes:
    """Strip a leading 0x00 sign byte and left-pad to 32 bytes."""
    if len(b) == 33 and b[0] == 0:
        b = b[1:]
    if len(b) > 32:
        raise ValueError("ECDSA integer >32 bytes")
    return b.rjust(32, b"\x00")
