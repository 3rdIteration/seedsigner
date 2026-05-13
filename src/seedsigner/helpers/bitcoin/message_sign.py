"""BIP-137 message-signing helpers.

Matches Bitcoin Core / Electrum / ``keycard-shell``'s
"Bitcoin Signed Message:\n" magic and 65-byte ``[header || r || s]``
signature layout. The Keycard SIGN APDU only returns ``(r, s)``; the
recovery byte is reconstructed locally by trying recid 0..3 against
the known signer pubkey (same trick as ``keycard_signer.compute_v``
on the ETH side).

Sighash:
  double_sha256(varint(len(magic)) + magic +
                varint(len(message)) + message)

Header byte (compressed key only, P2WPKH default):
  27 + 4 + recid   →   recid 0..3

Output: 65-byte ``bytes`` → base64-encoded ``str``.
"""

from __future__ import annotations

import base64
import hashlib

BTC_MSG_MAGIC = b"Bitcoin Signed Message:\n"
# 27 (uncompressed) + 4 (compressed). MVP is P2WPKH which uses
# compressed keys exclusively.
HEADER_COMPRESSED_BASE = 27 + 4


def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def message_digest(message: bytes) -> bytes:
    """Return the 32-byte sighash for a BIP-137 message signature."""
    if isinstance(message, str):  # accept text input as a convenience
        message = message.encode("utf-8")
    payload = (
        _varint(len(BTC_MSG_MAGIC)) + BTC_MSG_MAGIC
        + _varint(len(message)) + message
    )
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()


def encode_signature(r: int, s: int, recid: int) -> str:
    """Pack ``(r, s, recid)`` into a base64-encoded BIP-137 signature.

    ``recid`` must be in 0..3. Header byte assumes compressed keys.
    """
    if not 0 <= recid <= 3:
        raise ValueError(f"recid out of range: {recid}")
    if not 0 < r < (1 << 256):
        raise ValueError("r out of range")
    if not 0 < s < (1 << 256):
        raise ValueError("s out of range")

    header = HEADER_COMPRESSED_BASE + recid
    raw = bytes([header]) + r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return base64.b64encode(raw).decode("ascii")


def decode_signature(b64: str) -> tuple[int, int, int]:
    """Inverse of :func:`encode_signature` — returns ``(r, s, recid)``.
    Used by tests."""
    raw = base64.b64decode(b64)
    if len(raw) != 65:
        raise ValueError(f"BIP-137 signature must be 65 bytes, got {len(raw)}")
    header = raw[0]
    if not (HEADER_COMPRESSED_BASE <= header <= HEADER_COMPRESSED_BASE + 3):
        raise ValueError(f"unexpected BIP-137 header byte: {header}")
    recid = header - HEADER_COMPRESSED_BASE
    r = int.from_bytes(raw[1:33], "big")
    s = int.from_bytes(raw[33:65], "big")
    return r, s, recid
