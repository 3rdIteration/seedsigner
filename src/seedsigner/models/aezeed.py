from __future__ import annotations

_CRC32C_POLY = 0x82F63B78


def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ _CRC32C_POLY
            else:
                crc >>= 1
    return (~crc) & 0xFFFFFFFF


def _mnemonic_to_enciphered_bytes(words: list[str], word_to_index: dict[str, int]) -> bytes:
    """Convert a 24-word aezeed mnemonic into its 33-byte packed representation."""
    if len(words) != 24:
        raise ValueError("aezeed mnemonics must be exactly 24 words")

    accumulator = 0
    for word in words:
        index = word_to_index.get(word)
        if index is None:
            raise ValueError("word not in aezeed wordlist")
        accumulator = (accumulator << 11) | index

    return accumulator.to_bytes(33, byteorder="big", signed=False)


def has_valid_checksum(words: list[str], word_to_index: dict[str, int]) -> bool:
    """True if words form an aezeed mnemonic with a valid outer checksum.

    This verifies the 4-byte CRC32C/Castagnoli checksum over the first 29 bytes of
    the packed 33-byte enciphered cipherseed payload.
    """
    try:
        packed = _mnemonic_to_enciphered_bytes(words, word_to_index)
    except ValueError:
        return False

    payload = packed[:-4]
    checksum = packed[-4:]
    expected = _crc32c(payload).to_bytes(4, byteorder="big", signed=False)
    return checksum == expected
