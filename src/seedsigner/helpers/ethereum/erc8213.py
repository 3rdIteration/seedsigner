"""ERC-8213 calldata digest.

Hash of a transaction's calldata that the user can verify against a second
device before signing.  Defined by ERC-8213 as::

    digest = keccak256(  uint256_be(len(calldata))  ||  calldata  )
"""

from __future__ import annotations

from .keccak import keccak256


def compute_calldata_digest(calldata: bytes) -> bytes:
    length_word = len(calldata).to_bytes(32, "big")
    return keccak256(length_word + calldata)
