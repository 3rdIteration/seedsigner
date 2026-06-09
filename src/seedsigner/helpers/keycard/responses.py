"""Decoders for Keycard APDU response payloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


def parse_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("TLV: offset past end")
    tag = data[offset]
    if offset + 1 >= len(data):
        raise ValueError("TLV: missing length byte")
    length_byte = data[offset + 1]
    if length_byte == 0x81:
        if offset + 2 >= len(data):
            raise ValueError("TLV: missing extended length byte")
        length = data[offset + 2]
        body_start = offset + 3
    elif length_byte & 0x80:
        # Long forms beyond 0x81 never occur in Keycard responses; reject
        # rather than misparse the form byte as a short length.
        raise ValueError(f"TLV: unsupported length form {length_byte:02X}")
    else:
        length = length_byte
        body_start = offset + 2
    if body_start + length > len(data):
        raise ValueError("TLV: declared length extends past end of data")
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
    # Initialised applet returns ApplicationInfo template (tag 0xA4).
    # Pre-init applet (PIN/PUK/pairing-secret never set) returns just the
    # secure-channel pubkey under tag 0x80; app_version=0 is the sentinel
    # callers use to detect this state.
    tag, body, _ = parse_tlv(response, 0)
    if tag == 0x80:
        if len(body) != 65 or body[0] != 0x04:
            raise ValueError(
                "pre-init SELECT: expected 65-byte uncompressed pubkey"
            )
        return SelectResponse(
            instance_uid=b"",
            secp256k1_pubkey=bytes(body),
            app_version=0,
            free_pairing_slots=0,
            key_uid=b"",
            capabilities=0,
        )
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
    seen_int_tags = 0
    while cursor < len(body):
        t, b, cursor = parse_tlv(body, cursor)
        if t == 0x02:
            # The template re-uses tag 0x02 (PIN retries, then PUK retries)
            # so parse positionally — disambiguating by current value
            # misreads a blocked PIN (0 retries left) as the PUK slot.
            if seen_int_tags == 0:
                pin_retries = b[0] if b else 0
            elif seen_int_tags == 1:
                puk_retries = b[0] if b else 0
            seen_int_tags += 1
        elif t == 0x01:
            key_init = b == b"\xff" or (len(b) == 1 and b[0] != 0)
    return StatusResponse(pin_retries=pin_retries, puk_retries=puk_retries, key_initialised=key_init)


def parse_generate_mnemonic(response: bytes, word_count: int) -> List[int]:
    """Parse GENERATE MNEMONIC response into a list of BIP-39 word indices.

    The card returns ``2 * word_count`` bytes: 16-bit big-endian indices,
    one per word. Each index must be in 0..2047 (BIP-39 wordlist size).
    """
    expected_len = 2 * word_count
    if len(response) != expected_len:
        raise ValueError(
            f"GENERATE MNEMONIC: expected {expected_len} bytes, "
            f"got {len(response)}"
        )
    indices: List[int] = []
    for i in range(word_count):
        idx = int.from_bytes(response[2 * i : 2 * i + 2], "big")
        if idx >= 2048:
            raise ValueError(
                f"GENERATE MNEMONIC: word index {idx} out of BIP-39 range"
            )
        indices.append(idx)
    return indices


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
    # Strict bounds checks throughout: a truncated DER must raise, never
    # yield a silently-shortened r/s that _normalise_int would zero-pad
    # into a wrong-but-plausible signature.
    if not der or der[0] != 0x30:
        raise ValueError("ECDSA DER must start with 0x30")
    if len(der) < 2:
        raise ValueError("ECDSA DER truncated")
    if der[1] == 0x81:
        # length form: 0x30 0x81 LL
        if len(der) < 3:
            raise ValueError("ECDSA DER truncated")
        body_len = der[2]
        body_start = 3
    elif der[1] & 0x80:
        raise ValueError(f"ECDSA DER unsupported length form {der[1]:02X}")
    else:
        body_len = der[1]
        body_start = 2
    if body_start + body_len > len(der):
        raise ValueError("ECDSA DER declared length extends past buffer")
    body = der[body_start : body_start + body_len]

    cursor = 0
    if cursor + 2 > len(body) or body[cursor] != 0x02:
        raise ValueError("ECDSA DER missing INTEGER (r)")
    rlen = body[cursor + 1]
    if cursor + 2 + rlen > len(body):
        raise ValueError("ECDSA DER INTEGER (r) extends past buffer")
    r = body[cursor + 2 : cursor + 2 + rlen]
    cursor += 2 + rlen
    if cursor + 2 > len(body) or body[cursor] != 0x02:
        raise ValueError("ECDSA DER missing INTEGER (s)")
    slen = body[cursor + 1]
    if cursor + 2 + slen > len(body):
        raise ValueError("ECDSA DER INTEGER (s) extends past buffer")
    s = body[cursor + 2 : cursor + 2 + slen]
    return _normalise_int(r), _normalise_int(s)


def _normalise_int(b: bytes) -> bytes:
    """Strip a leading 0x00 sign byte and left-pad to 32 bytes."""
    if len(b) == 33 and b[0] == 0:
        b = b[1:]
    if len(b) > 32:
        raise ValueError("ECDSA integer >32 bytes")
    return b.rjust(32, b"\x00")
