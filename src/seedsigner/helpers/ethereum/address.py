from __future__ import annotations

from .keccak import keccak256


def pubkey_to_address(uncompressed_pubkey: bytes) -> bytes:
    if len(uncompressed_pubkey) == 65 and uncompressed_pubkey[0] == 0x04:
        body = uncompressed_pubkey[1:]
    elif len(uncompressed_pubkey) == 64:
        body = uncompressed_pubkey
    else:
        raise ValueError("expected 64-byte raw or 65-byte 0x04-prefixed pubkey")
    return keccak256(body)[-20:]


def to_checksum_address(address: bytes | str) -> str:
    if isinstance(address, str):
        s = address[2:] if address.startswith(("0x", "0X")) else address
        if len(s) != 40:
            raise ValueError("address hex must be 20 bytes")
        addr_bytes = bytes.fromhex(s)
    else:
        if len(address) != 20:
            raise ValueError("address must be 20 bytes")
        addr_bytes = address
    lowered = addr_bytes.hex()
    digest = keccak256(lowered.encode("ascii")).hex()
    out = ["0x"]
    for ch, dh in zip(lowered, digest):
        out.append(ch.upper() if int(dh, 16) >= 8 and ch.isalpha() else ch)
    return "".join(out)
