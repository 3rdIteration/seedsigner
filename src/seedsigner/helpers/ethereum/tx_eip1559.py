from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from . import rlp
from .keccak import keccak256

TX_TYPE = b"\x02"


AccessList = List[Tuple[bytes, List[bytes]]]


@dataclass(frozen=True)
class EIP1559Tx:
    chain_id: int
    nonce: int
    max_priority_fee_per_gas: int
    max_fee_per_gas: int
    gas_limit: int
    to: bytes
    value: int
    data: bytes = b""
    access_list: AccessList = field(default_factory=list)

    def __post_init__(self):
        if self.to and len(self.to) != 20:
            raise ValueError("to must be 20 bytes (or empty for contract creation)")
        for entry in self.access_list:
            addr, keys = entry
            if len(addr) != 20:
                raise ValueError("access list address must be 20 bytes")
            for k in keys:
                if len(k) != 32:
                    raise ValueError("access list storage key must be 32 bytes")

    def _payload_fields(self) -> list:
        return [
            rlp.encode_int(self.chain_id),
            rlp.encode_int(self.nonce),
            rlp.encode_int(self.max_priority_fee_per_gas),
            rlp.encode_int(self.max_fee_per_gas),
            rlp.encode_int(self.gas_limit),
            self.to,
            rlp.encode_int(self.value),
            self.data,
            [[addr, list(keys)] for addr, keys in self.access_list],
        ]

    def signing_bytes(self) -> bytes:
        return TX_TYPE + rlp.encode(self._payload_fields())

    def signing_hash(self) -> bytes:
        return keccak256(self.signing_bytes())

    def serialize_signed(self, y_parity: int, r: bytes, s: bytes) -> bytes:
        if y_parity not in (0, 1):
            raise ValueError("y_parity must be 0 or 1")
        fields = self._payload_fields() + [
            rlp.encode_int(y_parity),
            _strip_leading_zeros(r),
            _strip_leading_zeros(s),
        ]
        return TX_TYPE + rlp.encode(fields)


def _strip_leading_zeros(b: bytes) -> bytes:
    i = 0
    while i < len(b) - 1 and b[i] == 0:
        i += 1
    return b[i:]
