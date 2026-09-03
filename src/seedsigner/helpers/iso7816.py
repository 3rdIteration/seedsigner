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
    # Proprietary 0x9Cxx range used by the Satochip/SeedKeeper JavaCard applets
    # (see pysatochip's JCconstants.SEEDKEEPER_LOG_RES_DIC). These are not part
    # of ISO/IEC 7816-4 but surface through the same sw1/sw2 plumbing.
    0x9C01: "No memory left on card",
    0x9C03: "Operation not allowed",
    0x9C04: "Card setup not done",
    0x9C05: "Feature unsupported",
    0x9C08: "Secret not found",
    0x9C0B: "Invalid signature",
    0x9C0C: "Identity blocked",
    0x9C0F: "Invalid parameter",
    0x9C10: "Incorrect P1",
    0x9C11: "Incorrect P2",
    0x9C30: "Lock error",
    0x9C31: "Export not allowed",
    0x9C32: "Import data too long",
    0x9C33: "Wrong MAC during import",
    0x9C38: "Wrong secret type",
    0x9CFF: "Card internal error",
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
    if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        tries_left = sw2 & 0x0F
        attempt_word = "attempt" if tries_left == 1 else "attempts"
        return f"PIN is incorrect: {tries_left} {attempt_word} remaining ({status_word:#06x})"
    description = ISO7816_STATUS_WORDS.get(status_word)
    if description:
        return f"{description} ({status_word:#06x})"
    return f"Unknown status word: {status_word:#06x}"
