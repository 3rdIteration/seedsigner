"""Common ISO/IEC 7816-4 status word helpers.

This module centralizes known ISO/IEC 7816-4 status words so that
smartcard-related components can provide more helpful error messages.
The dictionary can easily be extended as additional codes are
encountered.
"""
from __future__ import annotations

from typing import Dict

# Mapping of status word integers to human-friendly descriptions.
# Only a subset of the full ISO/IEC 7816-4 table is included here; add to this
# list as new codes are encountered in the wild.
ISO7816_STATUS_WORDS: Dict[int, str] = {
    0x6300: "State of non-volatile memory unchanged",
    0x6400: "State of non-volatile memory change is expected",
    0x6700: "Wrong length",
    0x6982: "Security status not satisfied",
    0x6985: "Conditions of use not satisfied",
    0x6A80: "Incorrect parameters in the data field",
    0x6A82: "File not found",
    0x6A83: "Record not found",
    0x6A84: "Not enough memory space",
    0x6A86: "Incorrect parameters P1 P2",
    0x6A88: "Referenced data not found",
    0x6B00: "Wrong parameters P1 P2",
    # Commonly returned when a command isn't implemented by the card's
    # firmware. Keep the wording simple so users understand the feature
    # isn't available on their card/app.
    0x6D00: "Feature not supported for this applet",
    0x6E00: "Class not supported",
    0x6F00: "Unknown error, no precise diagnosis",
    0x9000: "Success",
}

def format_sw_error(sw1: int, sw2: int) -> str:
    """Return a human friendly description of an ISO7816 status word.

    Args:
        sw1: First status byte.
        sw2: Second status byte.

    Returns:
        Description string that includes the hexadecimal status word. For
        unknown codes, a generic "unknown" message is returned.
    """
    status_word = (sw1 << 8) | sw2
    description = ISO7816_STATUS_WORDS.get(status_word)
    if description:
        return f"{description} ({status_word:#06x})"
    return f"Unknown status word: {status_word:#06x}"
