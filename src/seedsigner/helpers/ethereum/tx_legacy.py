from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import rlp
from .keccak import keccak256


@dataclass(frozen=True)
class LegacyTx:
    nonce: int
    gas_price: int
    gas_limit: int
    to: bytes
    value: int
    data: bytes = b""
    chain_id: Optional[int] = None

    def __post_init__(self):
        if self.to and len(self.to) != 20:
            raise ValueError("to must be 20 bytes (or empty for contract creation)")

    def _signing_fields(self) -> list:
        fields = [
            rlp.encode_int(self.nonce),
            rlp.encode_int(self.gas_price),
            rlp.encode_int(self.gas_limit),
            self.to,
            rlp.encode_int(self.value),
            self.data,
        ]
        if self.chain_id is not None:
            fields += [rlp.encode_int(self.chain_id), b"", b""]
        return fields

    def signing_bytes(self) -> bytes:
        return rlp.encode(self._signing_fields())

    def signing_hash(self) -> bytes:
        return keccak256(self.signing_bytes())

    def serialize_signed(self, recovery_id: int, r: bytes, s: bytes) -> bytes:
        if self.chain_id is not None:
            v = recovery_id + self.chain_id * 2 + 35
        else:
            v = recovery_id + 27
        fields = [
            rlp.encode_int(self.nonce),
            rlp.encode_int(self.gas_price),
            rlp.encode_int(self.gas_limit),
            self.to,
            rlp.encode_int(self.value),
            self.data,
            rlp.encode_int(v),
            _strip_leading_zeros(r),
            _strip_leading_zeros(s),
        ]
        return rlp.encode(fields)


def _strip_leading_zeros(b: bytes) -> bytes:
    i = 0
    while i < len(b) - 1 and b[i] == 0:
        i += 1
    return b[i:]
