from __future__ import annotations

import base64
import math
from Cryptodome.Hash import SHAKE256


def shake_stream(seed: bytes) -> SHAKE256.SHAKE256_XOF:
    return SHAKE256.new(seed)


def random_string_from_charset(seed: bytes, length: int, charset: str) -> str:
    if length <= 0:
        raise ValueError("Length must be positive")
    if not charset:
        raise ValueError("Charset must not be empty")
    stream = shake_stream(seed)
    result = []
    charset_len = len(charset)
    limit = (256 // charset_len) * charset_len
    while len(result) < length:
        chunk = stream.read(64)
        for byte in chunk:
            if byte >= limit:
                continue
            result.append(charset[byte % charset_len])
            if len(result) == length:
                break
    return "".join(result)


def hex_password_from_seed(seed: bytes, length: int) -> str:
    if length <= 0:
        raise ValueError("Length must be positive")
    num_bytes = math.ceil(length / 2)
    data = shake_stream(seed).read(num_bytes)
    return data.hex()[:length]


def base64_password_from_seed(seed: bytes, length: int) -> str:
    if length <= 0:
        raise ValueError("Length must be positive")
    num_bytes = math.ceil(length / 4 * 3)
    num_bytes = num_bytes + ((3 - (num_bytes % 3)) % 3)
    data = shake_stream(seed).read(num_bytes)
    encoded = base64.b64encode(data).decode("ascii").replace("=", "")
    return encoded[:length]


def base85_password_from_seed(seed: bytes, length: int) -> str:
    if length <= 0:
        raise ValueError("Length must be positive")
    num_bytes = math.ceil(length / 5 * 4)
    data = shake_stream(seed).read(num_bytes)
    encoded = base64.b85encode(data).decode("ascii")
    return encoded[:length]


def dice_roll_entropy_bits(roll_count: int) -> float:
    return roll_count * math.log2(6)


def length_from_entropy(entropy_bits: float, alphabet_size: int) -> int:
    if alphabet_size <= 1:
        raise ValueError("Alphabet size must be > 1")
    return int(entropy_bits // math.log2(alphabet_size))
