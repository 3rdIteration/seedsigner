from __future__ import annotations

from .keccak import keccak256


def personal_sign_hash(message: bytes) -> bytes:
    prefix = f"\x19Ethereum Signed Message:\n{len(message)}".encode("utf-8")
    return keccak256(prefix + message)
