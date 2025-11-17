import os

import pytest
from embit import bip39

from seedsigner.helpers.bitbox02_backup import Bitbox02BackupError, decode_bitbox02_backup


def _encode_varint(value: int) -> bytes:
    pieces = []
    while True:
        to_write = value & 0x7F
        value >>= 7
        if value:
            to_write |= 0x80
            pieces.append(to_write)
        else:
            pieces.append(to_write)
            break
    return bytes(pieces)


def _length_delimited(field_number: int, payload: bytes) -> bytes:
    tag = (field_number << 3) | 2
    return _encode_varint(tag) + _encode_varint(len(payload)) + payload


def _varint_field(field_number: int, value: int) -> bytes:
    tag = (field_number << 3) | 0
    return _encode_varint(tag) + _encode_varint(value)


def _build_backup_bytes(seed: bytes, seed_length: int = None) -> bytes:
    seed_length = seed_length or len(seed)

    backup_data = b"".join(
        [
            _varint_field(1, seed_length),
            _length_delimited(2, seed),
            _varint_field(3, 1_700_000_001),
            _length_delimited(4, b"bb02-firmware"),
        ]
    )

    metadata = b"".join(
        [
            _varint_field(1, 1_700_000_000),
            _length_delimited(2, b"test-backup"),
            _varint_field(3, 0),
        ]
    )

    backup_content = b"".join(
        [
            _length_delimited(1, b"".rjust(32, b"\x00")),
            _length_delimited(2, metadata),
            _varint_field(3, len(backup_data)),
            _length_delimited(4, backup_data),
        ]
    )

    backup_v1 = _length_delimited(1, backup_content)
    return _length_delimited(1, backup_v1)


def test_decode_round_trip_backup():
    entropy = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    backup_bytes = _build_backup_bytes(entropy)

    details = decode_bitbox02_backup(backup_bytes)

    assert details.mnemonic == bip39.mnemonic_from_bytes(entropy).split()
    assert details.name == "test-backup"
    assert details.generator == "bb02-firmware"
    assert details.birthdate == 1_700_000_001
    assert details.timestamp == 1_700_000_000
    assert details.seed_length == len(entropy)


def test_decode_rejects_mismatched_length():
    entropy = os.urandom(16)
    backup_bytes = _build_backup_bytes(entropy, seed_length=len(entropy) - 2)

    with pytest.raises(Bitbox02BackupError):
        decode_bitbox02_backup(backup_bytes)
