"""CSPRNG helpers for fresh Keycard credentials.

The Status Keycard INIT command takes a 6-digit PIN, a 12-digit PUK, and
a 32-byte pairing secret.  This module produces those values from
``os.urandom`` directly (no biased ``random.choice``), so the entropy of
each digit / byte is exactly that of the underlying CSPRNG.
"""

from __future__ import annotations

import os
import secrets


PIN_LENGTH = 6
PUK_LENGTH = 12
PAIRING_PASSWORD_ALPHABET = (
    "abcdefghijkmnpqrstuvwxyz"   # no l/o (lowercase look-alikes)
    "ABCDEFGHJKLMNPQRSTUVWXYZ"   # no I/O
    "23456789"                    # no 0/1
)
DEFAULT_PAIRING_PASSWORD_LENGTH = 16


def generate_pin(length: int = PIN_LENGTH) -> str:
    if length <= 0:
        raise ValueError("PIN length must be positive")
    return "".join(_choice("0123456789") for _ in range(length))


def generate_puk(length: int = PUK_LENGTH) -> str:
    if length <= 0:
        raise ValueError("PUK length must be positive")
    return "".join(_choice("0123456789") for _ in range(length))


def generate_pairing_password(length: int = DEFAULT_PAIRING_PASSWORD_LENGTH) -> str:
    if length <= 0:
        raise ValueError("password length must be positive")
    return "".join(_choice(PAIRING_PASSWORD_ALPHABET) for _ in range(length))


def _choice(alphabet: str) -> str:
    return alphabet[secrets.randbelow(len(alphabet))]
