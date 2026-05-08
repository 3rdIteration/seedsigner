from __future__ import annotations

from typing import List, Tuple, Union

RLPItem = Union[bytes, "RLPList"]
RLPList = List[RLPItem]


class RLPDecodingError(ValueError):
    pass


def _encode_length(length: int, offset: int) -> bytes:
    if length < 56:
        return bytes([offset + length])
    blen = length.to_bytes((length.bit_length() + 7) // 8, "big")
    if len(blen) > 8:
        raise ValueError("RLP item too long")
    return bytes([offset + 55 + len(blen)]) + blen


def encode(item: RLPItem) -> bytes:
    if isinstance(item, (bytes, bytearray)):
        b = bytes(item)
        if len(b) == 1 and b[0] < 0x80:
            return b
        return _encode_length(len(b), 0x80) + b
    if isinstance(item, list):
        payload = b"".join(encode(x) for x in item)
        return _encode_length(len(payload), 0xC0) + payload
    raise TypeError(f"Cannot RLP-encode {type(item).__name__}")


def encode_int(value: int) -> bytes:
    if value < 0:
        raise ValueError("RLP cannot encode negative integers")
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _decode_length(data: bytes, start: int) -> Tuple[int, int, bool]:
    if start >= len(data):
        raise RLPDecodingError("RLP: out of bounds")
    prefix = data[start]
    if prefix < 0x80:
        return start, 1, False
    if prefix < 0xB8:
        length = prefix - 0x80
        return start + 1, length, False
    if prefix < 0xC0:
        ll = prefix - 0xB7
        if start + 1 + ll > len(data):
            raise RLPDecodingError("RLP: long-string length out of bounds")
        length = int.from_bytes(data[start + 1 : start + 1 + ll], "big")
        return start + 1 + ll, length, False
    if prefix < 0xF8:
        length = prefix - 0xC0
        return start + 1, length, True
    ll = prefix - 0xF7
    if start + 1 + ll > len(data):
        raise RLPDecodingError("RLP: long-list length out of bounds")
    length = int.from_bytes(data[start + 1 : start + 1 + ll], "big")
    return start + 1 + ll, length, True


def _decode_at(data: bytes, start: int) -> Tuple[RLPItem, int]:
    payload_start, length, is_list = _decode_length(data, start)
    end = payload_start + length
    if end > len(data):
        raise RLPDecodingError("RLP: payload out of bounds")
    if not is_list:
        if start == payload_start and length == 1:
            return data[start : start + 1], start + 1
        return data[payload_start:end], end
    items: RLPList = []
    cursor = payload_start
    while cursor < end:
        item, cursor = _decode_at(data, cursor)
        items.append(item)
    if cursor != end:
        raise RLPDecodingError("RLP: list payload mismatch")
    return items, end


def decode(data: bytes) -> RLPItem:
    item, end = _decode_at(data, 0)
    if end != len(data):
        raise RLPDecodingError("RLP: trailing bytes")
    return item


def decode_int(data: bytes) -> int:
    if data == b"":
        return 0
    if data[0] == 0 and len(data) > 1:
        raise RLPDecodingError("RLP: integer with leading zero byte")
    return int.from_bytes(data, "big")
