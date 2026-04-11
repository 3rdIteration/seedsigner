"""Best-effort secure memory clearing for sensitive Python objects.

Python does not guarantee secure deletion of string or bytes data.
These helpers use ctypes to overwrite the internal buffer of bytearray
and (where possible) bytes objects before they are garbage-collected.

Limitations:
    - Immutable ``str`` and ``bytes`` objects may have been copied by the
      interpreter (interning, concatenation) so zeroing the original does
      not guarantee all copies are erased.
    - Only CPython is supported; other interpreters may lay out objects
      differently.
    - This is a *mitigation*, not a guarantee. A sufficiently privileged
      attacker with access to the process memory may still recover data.
"""

import ctypes
import logging
import sys

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared-string detection
# ---------------------------------------------------------------------------
# On CPython 3.12+ every string literal (and several built-in objects) is
# marked *immortal*: its reference count is pinned to a platform-specific
# sentinel value and never changes.  Wiping such a string via ctypes.memset
# would corrupt every other reference to the same object — in particular it
# would destroy entries in the global BIP-39 / SLIP-39 wordlists, making
# subsequent seed validation fail until the process is restarted.
#
# We detect the immortal sentinel by inspecting a known-immortal object (the
# empty string "").  On CPython < 3.12 the empty string simply has a high
# (but not sentinel) refcount; the threshold below is generous enough to
# catch it and any other heavily-shared string.
# ---------------------------------------------------------------------------
_IMMORTAL_REFCOUNT: int = sys.getrefcount("")

# Strings with a refcount at or above this threshold are considered shared
# and must not be wiped.  On CPython 3.12+ this equals the immortal sentinel
# (~4 billion).  On older CPython we fall back to a conservative limit: any
# string referenced more than _SHARED_REFCOUNT_LIMIT times is almost
# certainly a global constant (wordlist entry, interned literal, etc.).
_SHARED_REFCOUNT_LIMIT: int = min(_IMMORTAL_REFCOUNT, 50)


def _is_shared(obj) -> bool:
    """Return True if *obj* appears to be shared or immortal.

    The reference count returned by ``sys.getrefcount`` includes one
    temporary reference for the argument itself.  In the typical call chain
    ``wipe_list → wipe_string → _is_shared`` an independent (single-owner)
    string has a refcount of about 5 (list element + loop variable +
    wipe_string param + _is_shared param + getrefcount arg).  Shared strings
    — especially immortal string literals on CPython 3.12+ — have a vastly
    higher count.
    """
    return sys.getrefcount(obj) >= _SHARED_REFCOUNT_LIMIT


def _wipe_buffer(obj, length: int) -> None:
    """Overwrite *length* bytes starting at the object's buffer address."""
    if length <= 0:
        return
    # id(obj) is the CPython memory address of the PyObject struct.
    # For bytes the buffer starts at an offset past the ob_refcnt,
    # ob_type, ob_size, and ob_shash fields.  The offset is
    # platform-dependent but sys.getsizeof gives us the total
    # allocation; the last *length* bytes are the data + NUL.
    buf_start = id(obj) + sys.getsizeof(obj) - length - 1
    ctypes.memset(buf_start, 0, length)


def wipe_bytes(b: bytes | bytearray | None) -> None:
    """Zero out the contents of a bytes or bytearray object in place."""
    if b is None:
        return
    if isinstance(b, bytearray):
        for i in range(len(b)):
            b[i] = 0
        return
    if isinstance(b, bytes) and len(b) > 0:
        _wipe_buffer(b, len(b))


def wipe_string(s: str | None) -> None:
    """Best-effort zeroing of a str object's internal buffer.

    Only works for ASCII/Latin-1 compact strings on CPython where each
    character occupies one byte.  For wider encodings the internal
    layout differs and this may not fully clear the data, but it will
    still overwrite a significant portion.

    **Safety guard**: if the string's reference count indicates it is shared
    or immortal (e.g. a BIP-39 wordlist entry), the wipe is skipped to
    prevent corrupting global data structures.
    """
    if s is None or len(s) == 0:
        return
    if _is_shared(s):
        logger.warning(
            "wipe_string: refusing to wipe shared/immortal string "
            "(refcount=%d, len=%d)",
            sys.getrefcount(s),
            len(s),
        )
        return
    # CPython compact ASCII strings store data right after the
    # PyASCIIObject struct.  sys.getsizeof includes the NUL terminator.
    buf_size = sys.getsizeof(s) - sys.getsizeof("")
    if buf_size > 0:
        buf_start = id(s) + sys.getsizeof("") - 1
        ctypes.memset(buf_start, 0, buf_size)


def wipe_list(lst: list | None) -> None:
    """Wipe all str/bytes elements of a list, then clear it."""
    if lst is None:
        return
    for item in lst:
        if isinstance(item, (bytes, bytearray)):
            wipe_bytes(item)
        elif isinstance(item, str):
            wipe_string(item)
    lst.clear()
