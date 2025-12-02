"""Utilities for the Datum Tool.

This module adapts the Krux Datum Tool helpers for use in SeedSigner.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Sequence, Tuple, Union

from binascii import hexlify, unhexlify
import base64

from embit import base58
from embit.bech32 import bech32_decode, Encoding

from urtypes import bytes as ur_bytes
from urtypes import crypto as ur_crypto

from seedsigner.helpers import kef

# Datum type identifiers
DATUM_DESCRIPTOR = "DESC"
DATUM_PSBT = "PSBT"
DATUM_XPUB = "XPUB"
DATUM_ADDRESS = "ADDR"

# UR types that the Datum tool can decode
DATUM_UR_TYPES = {
    DATUM_PSBT: ["crypto-psbt"],
}

# BBQR type hints preserved from the Krux implementation
DATUM_BBQR_TYPES = {
    DATUM_DESCRIPTOR: ["U"],
    DATUM_PSBT: ["P"],
    DATUM_XPUB: ["U"],
    DATUM_ADDRESS: ["U"],
}

STATIC_QR_MAX_SIZE = 4  # version 5 - 37x37 modules
SUFFICIENT_SAMPLE_SIZE = 512
SLOW_ENCODING_MAX_SIZE = 2 ** 14

DatumData = Union[str, bytes]


class DatumError(Exception):
    """Base error for datum helper failures."""


class DatumConversionError(DatumError):
    """Raised when an encoding conversion fails."""


# ---------------------------------------------------------------------------
# Base encoding helpers
# ---------------------------------------------------------------------------

B43CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:"


def _base43_decode(value: str) -> bytes:
    long_value = 0
    power = 1
    for char in reversed(value):
        digit = B43CHARS.find(char)
        if digit == -1:
            raise ValueError(f"forbidden character {char} for base 43")
        long_value += digit * power
        power *= 43
    result = bytearray()
    while long_value >= 256:
        long_value, mod = divmod(long_value, 256)
        result.append(mod)
    if long_value:
        result.append(long_value)
    for char in value:
        if char == B43CHARS[0]:
            result.append(0)
        else:
            break
    return bytes(reversed(result))


def _base43_encode(value: bytes) -> str:
    long_value = 0
    power = 1
    for char in reversed(value):
        long_value += power * char
        power <<= 8
    result = bytearray()
    while long_value >= 43:
        long_value, mod = divmod(long_value, 43)
        result.extend(B43CHARS[mod].encode())
    if long_value:
        result.extend(B43CHARS[long_value].encode())
    for char in value:
        if char == 0:
            result.extend(B43CHARS[0].encode())
        else:
            break
    return bytes(reversed(result)).decode()


def base_decode(value: str, base: int) -> bytes:
    if not isinstance(value, str):
        raise TypeError("Invalid value, expected str")
    if value == "":
        return b""
    if base == 32:
        padding = (-len(value)) % 8
        return base64.b32decode(value + "=" * padding, casefold=False)
    if base == 43:
        return _base43_decode(value)
    if base == 58:
        return base58.decode(value)
    if base == 64:
        return base64.b64decode(value)
    raise ValueError(f"Unsupported base: {base}")


def base_encode(value: bytes, base: int) -> str:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("Invalid value, expected bytes")
    if value == b"":
        return ""
    if base == 32:
        return base64.b32encode(value).decode().rstrip("=")
    if base == 43:
        return _base43_encode(bytes(value))
    if base == 58:
        return base58.encode(bytes(value))
    if base == 64:
        return base64.b64encode(value).decode()
    raise ValueError(f"Unsupported base: {base}")


# ---------------------------------------------------------------------------
# UR helpers
# ---------------------------------------------------------------------------


def urobj_to_data(ur_obj: Any) -> DatumData | None:
    """Extract raw data from a UR object."""

    if ur_obj.type == "crypto-bip39":
        return ur_crypto.BIP39.from_cbor(ur_obj.cbor).words
    if ur_obj.type == "crypto-account":
        account = ur_crypto.Account.from_cbor(ur_obj.cbor)
        return account.output_descriptors[0].descriptor()
    if ur_obj.type == "crypto-output":
        return ur_crypto.Output.from_cbor(ur_obj.cbor).descriptor()
    if ur_obj.type == "crypto-psbt":
        return ur_crypto.PSBT.from_cbor(ur_obj.cbor).data
    if ur_obj.type == "bytes":
        return ur_bytes.Bytes.from_cbor(ur_obj.cbor).data
    return None


# ---------------------------------------------------------------------------
# Encoding detection and datum identification
# ---------------------------------------------------------------------------


def convert_encoding(contents: DatumData, conversion: Union[str, int]) -> DatumData | None:
    """Convert between encodings.

    ``conversion`` mirrors the Krux implementation:
    * ``"hex"`` or ``"HEX"``
    * ``32``, ``43``, ``58``, ``64``
    * ``"utf8"``
    * ``"shift_case"``
    """

    from_bytes = isinstance(contents, (bytes, bytearray))

    try:
        if conversion in (32, 43, 58, 64):
            if from_bytes:
                return base_encode(bytes(contents), conversion)
            return base_decode(contents, conversion)
        if conversion == "hex":
            if from_bytes:
                return hexlify(contents).decode()
            return unhexlify(contents)
        if conversion == "HEX":
            if from_bytes:
                return hexlify(contents).decode().upper()
            return unhexlify(contents)
        if conversion == "utf8":
            if from_bytes:
                return bytes(contents).decode()
            return contents.encode()
        if conversion == "shift_case" and isinstance(contents, str):
            if contents == contents.lower():
                return contents.upper()
            if contents == contents.upper():
                return contents.lower()
    except Exception as exc:  # pragma: no cover - error mapped to None
        raise DatumConversionError(str(exc)) from exc

    raise DatumConversionError(f"Unsupported conversion: {conversion}")


def detect_encodings(str_data: str, verify: bool = True) -> List[Union[str, int]]:
    if not isinstance(str_data, str):
        raise TypeError("detect_encodings() expected str")

    encodings: List[Union[str, int]] = []
    sample = str_data[:SUFFICIENT_SAMPLE_SIZE]
    if not sample:
        return ["utf8"]

    min_chr = min(sample)
    max_chr = max(sample)
    length = len(str_data)

    if length % 2 == 0 and "0" <= min_chr:
        if max_chr <= "F":
            if not verify:
                encodings.append("HEX")
            else:
                try:
                    unhexlify(str_data)
                    encodings.append("HEX")
                except Exception:
                    pass
        elif max_chr <= "f":
            if not verify:
                encodings.append("hex")
            else:
                try:
                    unhexlify(str_data)
                    encodings.append("hex")
                except Exception:
                    pass

    if "2" <= min_chr and max_chr <= "Z":
        if not verify:
            encodings.append(32)
        else:
            try:
                base_decode(str_data, 32)
                encodings.append(32)
            except Exception:
                pass

    if length <= SLOW_ENCODING_MAX_SIZE and "0" <= min_chr:
        encoding = None
        if max_chr <= "Z":
            if not verify:
                encoding = Encoding.BECH32
            else:
                encoding, _, _ = bech32_decode(str_data)
        elif max_chr <= "z":
            if not verify:
                encoding = Encoding.BECH32
            else:
                encoding, _, _ = bech32_decode(str_data)
        if encoding == Encoding.BECH32:
            encodings.append("BECH32" if max_chr <= "Z" else "bech32")
        elif encoding == Encoding.BECH32M:
            encodings.append("BECH32M" if max_chr <= "Z" else "bech32m")

    if length <= SLOW_ENCODING_MAX_SIZE and "$" <= min_chr and max_chr <= "Z":
        if not verify:
            encodings.append(43)
        else:
            try:
                base_decode(str_data, 43)
                encodings.append(43)
            except Exception:
                pass

    if length <= SLOW_ENCODING_MAX_SIZE and "1" <= min_chr <= "z":
        if not verify:
            encodings.append(58)
        else:
            try:
                base_decode(str_data, 58)
                encodings.append(58)
            except Exception:
                pass

    if "+" <= min_chr and max_chr <= "z":
        if not verify:
            encodings.append(64)
        else:
            try:
                decoded = base_decode(str_data, 64)
                if base_encode(decoded, 64) == str_data:
                    encodings.append(64)
            except Exception:
                pass

    if ord(max_chr) <= 127:
        encodings.append("ascii")
    if 128 <= ord(max_chr) <= 255:
        encodings.append("latin-1")

    encodings.append("utf8")
    return encodings


def identify_datum(data: DatumData, encodings: Sequence[Union[str, int]] | None = None) -> str | None:
    if isinstance(data, bytes):
        if data[:5] == b"psbt\xff":
            return DATUM_PSBT
        return None

    if len(data) <= 33:
        return None

    encodings = list(encodings) if encodings is not None else detect_encodings(data)

    if data[:1] in "xyzYZtuvUV" and data[1:4] == "pub" and 58 in encodings:
        return DATUM_XPUB
    if (
        data[:1] == "["
        and "]" in data
        and data.split("]")[1][:1] in "xyzYZtuvUV"
        and data.split("]")[1][1:4] == "pub"
    ):
        return DATUM_XPUB
    if data.split("(")[0] in ("pkh", "sh", "wpkh", "wsh", "tr"):
        return DATUM_DESCRIPTOR
    if (
        (data[:1] in ("1", "3", "n", "2", "m") and 58 in encodings)
        or (
            data[:4].lower() in ("bc1p", "bc1q", "tb1p", "tb1q")
            and any(
                isinstance(enc, str) and enc.lower().startswith("bech32")
                for enc in encodings
            )
        )
    ):
        return DATUM_ADDRESS
    return None


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------


@dataclass
class DatumAnalysis:
    contents: DatumData
    about_prefix: str
    about: str
    encodings: List[Union[str, int]]
    datum: str | None
    sensitive: bool

    def preview(self) -> str:
        if isinstance(self.contents, bytes):
            return "0x" + hexlify(self.contents[:SUFFICIENT_SAMPLE_SIZE]).decode()
        return self.contents[:SUFFICIENT_SAMPLE_SIZE]


def analyze_contents(contents: DatumData) -> DatumAnalysis:
    if isinstance(contents, bytes):
        about_prefix = "binary:"
        about = f"{about_prefix} {len(contents)} bytes"
        encodings: List[Union[str, int]] = []
        sensitive = len(contents) in (16, 32) and max(contents) > 127
        datum = identify_datum(contents)
        return DatumAnalysis(contents, about_prefix, about, encodings, datum, sensitive)

    encodings = detect_encodings(contents)
    about_prefix = "text:"
    about = f"{about_prefix} {len(contents)} chars"
    words = contents[:256].split()
    sensitive = len(words) in (12, 24)
    if not sensitive and len(contents) in (12 * 4, 24 * 4):
        if all(c in "0123456789" for c in contents):
            sensitive = True
    datum = identify_datum(contents, encodings)
    return DatumAnalysis(contents, about_prefix, about, encodings, datum, sensitive)


# ---------------------------------------------------------------------------
# KEF helpers
# ---------------------------------------------------------------------------


@dataclass
class KEFMetadata:
    label: bytes
    version: int
    iterations: int

    def display_label(self) -> str:
        try:
            return self.label.decode()
        except UnicodeDecodeError:
            return "0x" + hexlify(self.label).decode()


def unwrap_kef_envelope(payload: bytes) -> Tuple[KEFMetadata, bytes]:
    label, version, iterations, ciphertext = kef.unwrap(payload)
    metadata = KEFMetadata(label=label, version=version, iterations=iterations)
    return metadata, ciphertext
