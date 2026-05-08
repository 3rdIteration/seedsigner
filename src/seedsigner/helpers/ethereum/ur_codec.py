"""UR ``eth-sign-request`` and ``eth-signature`` codec.

Reference: https://github.com/KeystoneHQ/Keystone-developer-hub/blob/main/research/eth-sign-request.md
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from typing import List, Optional

from urtypes.cbor import DataItem, Decoder, Encoder, Tagging
from urtypes.cbor.data import Mapping as _UrMapping


def _unwrap_tagged(value, expected_tag: Optional[int] = None):
    """Strip a Tagging/DataItem wrapper.  Returns the underlying object."""
    if isinstance(value, (Tagging, DataItem)):
        if expected_tag is not None and value.tag != expected_tag:
            raise ValueError(f"expected CBOR tag {expected_tag}, got {value.tag}")
        return _unwrap_tagged(value.obj, None)
    if isinstance(value, _UrMapping):
        return value.map
    return value


# Keystone data-type registry
DATA_TYPE_LEGACY_TX = 1
DATA_TYPE_TYPED_DATA = 2
DATA_TYPE_PERSONAL_MESSAGE = 3
DATA_TYPE_TYPED_TX = 4   # EIP-1559 / EIP-2930

CBOR_TAG_UUID = 37
CBOR_TAG_KEYPATH = 304


@dataclass
class CryptoKeypath:
    components: List[int] = field(default_factory=list)
    """Hardened bit (0x80000000) is set on hardened components."""
    source_fingerprint: Optional[bytes] = None  # 4 bytes
    depth: Optional[int] = None

    def to_cbor_value(self) -> Tagging:
        flat: List = []
        for c in self.components:
            hardened = bool(c & 0x80000000)
            index = c & 0x7FFFFFFF
            flat.append(index)
            flat.append(hardened)
        body = {1: flat}
        if self.source_fingerprint is not None:
            if len(self.source_fingerprint) != 4:
                raise ValueError("source-fingerprint must be 4 bytes")
            body[2] = self.source_fingerprint
        if self.depth is not None:
            body[3] = self.depth
        return Tagging(CBOR_TAG_KEYPATH, body)

    @classmethod
    def from_cbor_value(cls, value) -> "CryptoKeypath":
        body = _unwrap_tagged(value, CBOR_TAG_KEYPATH)
        if not isinstance(body, dict):
            raise ValueError("crypto-keypath must be a map")
        flat = body.get(1, [])
        if len(flat) % 2 != 0:
            raise ValueError("crypto-keypath components list must have even length")
        components: List[int] = []
        for i in range(0, len(flat), 2):
            index = flat[i]
            hardened = flat[i + 1]
            if not isinstance(index, int):
                raise ValueError("only integer path components supported")
            if hardened:
                index |= 0x80000000
            components.append(index)
        return cls(
            components=components,
            source_fingerprint=body.get(2),
            depth=body.get(3),
        )


@dataclass
class EthSignRequest:
    request_id: bytes              # 16 bytes (uuid)
    sign_data: bytes
    data_type: int
    chain_id: int
    derivation_path: CryptoKeypath
    address: Optional[bytes] = None  # 20 bytes
    origin: Optional[str] = None

    def to_cbor(self) -> bytes:
        if len(self.request_id) != 16:
            raise ValueError("request-id must be a 16-byte uuid")
        body = {
            1: Tagging(CBOR_TAG_UUID, bytes(self.request_id)),
            2: bytes(self.sign_data),
            3: int(self.data_type),
            4: int(self.chain_id),
            5: self.derivation_path.to_cbor_value(),
        }
        if self.address is not None:
            if len(self.address) != 20:
                raise ValueError("address must be 20 bytes")
            body[6] = bytes(self.address)
        if self.origin is not None:
            body[7] = self.origin
        return _encode_cbor(body)

    @classmethod
    def from_cbor(cls, data: bytes) -> "EthSignRequest":
        body = Decoder(io.BytesIO(data)).decode()
        if not isinstance(body, dict):
            raise ValueError("eth-sign-request CBOR root must be a map")
        request_id = _unwrap_tagged(body.get(1), CBOR_TAG_UUID)
        if not isinstance(request_id, (bytes, bytearray)) or len(request_id) != 16:
            raise ValueError("request-id must be a 16-byte uuid")

        sign_data = body.get(2)
        if not isinstance(sign_data, (bytes, bytearray)):
            raise ValueError("sign-data must be a byte string")

        data_type = body.get(3)
        if not isinstance(data_type, int):
            raise ValueError("data-type must be an integer")

        chain_id = body.get(4, 0)
        if not isinstance(chain_id, int):
            raise ValueError("chain-id must be an integer")

        if 5 not in body:
            raise ValueError("derivation-path is required")
        path = CryptoKeypath.from_cbor_value(body[5])

        address = body.get(6)
        if address is not None and (not isinstance(address, (bytes, bytearray)) or len(address) != 20):
            raise ValueError("address must be 20 bytes")
        origin = body.get(7)
        if origin is not None and not isinstance(origin, str):
            raise ValueError("origin must be a text string")

        return cls(
            request_id=bytes(request_id),
            sign_data=bytes(sign_data),
            data_type=data_type,
            chain_id=chain_id,
            derivation_path=path,
            address=bytes(address) if address is not None else None,
            origin=origin,
        )


@dataclass
class EthSignature:
    request_id: bytes               # 16 bytes (uuid)
    signature: bytes                # r(32) || s(32) || v(>=1)
    origin: Optional[str] = None

    def to_cbor(self) -> bytes:
        if len(self.signature) < 65:
            raise ValueError("signature must be >= 65 bytes (r||s||v)")
        body = {
            1: Tagging(CBOR_TAG_UUID, bytes(self.request_id)),
            2: bytes(self.signature),
        }
        if self.origin is not None:
            body[3] = self.origin
        return _encode_cbor(body)

    @classmethod
    def from_cbor(cls, data: bytes) -> "EthSignature":
        body = Decoder(io.BytesIO(data)).decode()
        request_id = _unwrap_tagged(body.get(1), CBOR_TAG_UUID)
        return cls(
            request_id=bytes(request_id),
            signature=bytes(body[2]),
            origin=body.get(3),
        )


def _encode_cbor(value) -> bytes:
    out = io.BytesIO()
    enc = Encoder(out)
    _encode_value(enc, value)
    return out.getvalue()


def _encode_value(enc: Encoder, value) -> None:
    if isinstance(value, bool):
        enc.encode_boolean(value)
    elif isinstance(value, int):
        enc.encode_integer(value)
    elif isinstance(value, str):
        enc.encode_textstring(value)
    elif isinstance(value, (bytes, bytearray)):
        enc.encode_bytestring(bytes(value))
    elif isinstance(value, list):
        enc.encode_list(value)
    elif isinstance(value, dict):
        enc.encode_dict(value)
    elif isinstance(value, Tagging):
        enc.encode_tagging(value)
    elif value is None:
        enc.encode_null()
    else:
        raise TypeError(f"don't know how to encode {type(value).__name__}")
