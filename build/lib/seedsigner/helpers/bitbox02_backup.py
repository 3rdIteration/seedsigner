import time
from dataclasses import dataclass
from typing import Optional

from embit import bip39


class Bitbox02BackupError(Exception):
    pass


@dataclass
class Bitbox02BackupDetails:
    mnemonic: list[str]
    name: Optional[str]
    generator: Optional[str]
    birthdate: Optional[int]
    timestamp: Optional[int]
    seed_length: int


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise Bitbox02BackupError("Unexpected end of data while parsing varint")

        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift

        if not byte & 0x80:
            break

        shift += 7
        if shift > 63:
            raise Bitbox02BackupError("Invalid varint encoding")

    return value, offset


def _read_length_delimited(data: bytes, offset: int) -> tuple[bytes, int]:
    length, offset = _read_varint(data, offset)
    end = offset + length
    if end > len(data):
        raise Bitbox02BackupError("Length-delimited field exceeds available data")
    return data[offset:end], end


def _skip_value(data: bytes, offset: int, wire_type: int) -> int:
    if wire_type == 0:
        _, offset = _read_varint(data, offset)
    elif wire_type == 1:
        offset += 8
    elif wire_type == 2:
        _, offset = _read_length_delimited(data, offset)
    elif wire_type == 5:
        offset += 4
    else:
        raise Bitbox02BackupError(f"Unsupported wire type: {wire_type}")
    if offset > len(data):
        raise Bitbox02BackupError("Unexpected end of data while skipping field")
    return offset


def _decode_backup_metadata(data: bytes) -> tuple[Optional[int], Optional[str], Optional[int]]:
    timestamp = None
    name = None
    mode = None
    offset = 0

    while offset < len(data):
        tag, offset = _read_varint(data, offset)
        field_number = tag >> 3
        wire_type = tag & 0x07

        if field_number == 1 and wire_type == 0:
            timestamp, offset = _read_varint(data, offset)
        elif field_number == 2 and wire_type == 2:
            raw_name, offset = _read_length_delimited(data, offset)
            name = raw_name.decode("utf-8", errors="replace")
        elif field_number == 3 and wire_type == 0:
            mode, offset = _read_varint(data, offset)
        else:
            offset = _skip_value(data, offset, wire_type)

    return timestamp, name, mode


def _decode_backup_data(data: bytes) -> tuple[int, bytes, Optional[int], Optional[str]]:
    seed_length = None
    seed_bytes: bytes | None = None
    birthdate = None
    generator = None
    offset = 0

    while offset < len(data):
        tag, offset = _read_varint(data, offset)
        field_number = tag >> 3
        wire_type = tag & 0x07

        if field_number == 1 and wire_type == 0:
            seed_length, offset = _read_varint(data, offset)
        elif field_number == 2 and wire_type == 2:
            seed_bytes, offset = _read_length_delimited(data, offset)
        elif field_number == 3 and wire_type == 0:
            birthdate, offset = _read_varint(data, offset)
        elif field_number == 4 and wire_type == 2:
            raw_generator, offset = _read_length_delimited(data, offset)
            generator = raw_generator.decode("utf-8", errors="replace")
        else:
            offset = _skip_value(data, offset, wire_type)

    if seed_length is None or seed_bytes is None:
        raise Bitbox02BackupError("Missing seed data in backup")

    if seed_length <= 0 or seed_length > len(seed_bytes) or seed_length % 4 != 0:
        raise Bitbox02BackupError("Invalid seed length in backup")

    if seed_length > 32:
        raise Bitbox02BackupError("Invalid seed length in backup")

    return seed_length, seed_bytes[:seed_length], birthdate, generator


def _decode_backup_content(data: bytes) -> tuple[bytes, Optional[int], Optional[str], Optional[int], Optional[str]]:
    metadata = None
    content_length = None
    backup_data_bytes = None
    offset = 0

    while offset < len(data):
        tag, offset = _read_varint(data, offset)
        field_number = tag >> 3
        wire_type = tag & 0x07

        if field_number == 1 and wire_type == 2:
            # checksum; ignore value for now
            _, offset = _read_length_delimited(data, offset)
        elif field_number == 2 and wire_type == 2:
            metadata_bytes, offset = _read_length_delimited(data, offset)
            metadata = _decode_backup_metadata(metadata_bytes)
        elif field_number == 3 and wire_type == 0:
            content_length, offset = _read_varint(data, offset)
        elif field_number == 4 and wire_type == 2:
            backup_data_bytes, offset = _read_length_delimited(data, offset)
        else:
            offset = _skip_value(data, offset, wire_type)

    if backup_data_bytes is None:
        raise Bitbox02BackupError("Backup payload missing backup data")

    if content_length is not None and content_length != len(backup_data_bytes):
        raise Bitbox02BackupError("Backup data length does not match content length")

    seed_length, seed_bytes, birthdate, generator = _decode_backup_data(backup_data_bytes)

    timestamp = None
    name = None
    if metadata:
        timestamp, name, _ = metadata

    return seed_bytes, timestamp, name, birthdate, generator


def decode_bitbox02_backup(data: bytes) -> Bitbox02BackupDetails:
    """Decode a BitBox02 microSD backup file.

    Args:
        data: The raw bytes read from the backup file.

    Returns:
        Bitbox02BackupDetails with mnemonic words and metadata.

    Raises:
        Bitbox02BackupError: If the backup payload cannot be parsed.
    """

    if not data:
        raise Bitbox02BackupError("Backup file is empty")

    offset = 0
    backup_v1_bytes = None

    while offset < len(data):
        tag, offset = _read_varint(data, offset)
        field_number = tag >> 3
        wire_type = tag & 0x07

        if field_number == 1 and wire_type == 2:
            backup_v1_bytes, offset = _read_length_delimited(data, offset)
        else:
            offset = _skip_value(data, offset, wire_type)

    if backup_v1_bytes is None:
        raise Bitbox02BackupError("Unsupported backup format")

    # BackupV1 -> BackupContent
    content_offset = 0
    backup_content_bytes = None
    while content_offset < len(backup_v1_bytes):
        tag, content_offset = _read_varint(backup_v1_bytes, content_offset)
        field_number = tag >> 3
        wire_type = tag & 0x07

        if field_number == 1 and wire_type == 2:
            backup_content_bytes, content_offset = _read_length_delimited(backup_v1_bytes, content_offset)
        else:
            content_offset = _skip_value(backup_v1_bytes, content_offset, wire_type)

    if backup_content_bytes is None:
        raise Bitbox02BackupError("Backup content missing")

    seed_bytes, timestamp, name, birthdate, generator = _decode_backup_content(backup_content_bytes)

    mnemonic = bip39.mnemonic_from_bytes(seed_bytes).split()

    return Bitbox02BackupDetails(
        mnemonic=mnemonic,
        name=name,
        generator=generator,
        birthdate=birthdate,
        timestamp=timestamp,
        seed_length=len(seed_bytes),
    )


def format_timestamp(timestamp: Optional[int]) -> str:
    if timestamp is None:
        return ""
    try:
        return time.strftime("%Y-%m-%d", time.localtime(timestamp))
    except Exception:
        return str(timestamp)
