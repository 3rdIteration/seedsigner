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


_SHARED_WORDLIST_STR_IDS: set[int] | None = None


def _get_shared_wordlist_str_ids() -> set[int]:
    global _SHARED_WORDLIST_STR_IDS
    if _SHARED_WORDLIST_STR_IDS is not None:
        return _SHARED_WORDLIST_STR_IDS

    shared_ids: set[int] = set()
    try:
        from embit import bip39
        shared_ids.update(id(word) for word in bip39.WORDLIST)
    except (ImportError, ModuleNotFoundError):
        pass

    try:
        from shamir_mnemonic import wordlist as slip39_wordlist
        shared_ids.update(id(word) for word in slip39_wordlist.WORDLIST)
    except (ImportError, ModuleNotFoundError):
        pass

    _SHARED_WORDLIST_STR_IDS = shared_ids
    return _SHARED_WORDLIST_STR_IDS


def _is_shared_wordlist_string_ref(s: str) -> bool:
    return id(s) in _get_shared_wordlist_str_ids()


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
    """
    if s is None or len(s) == 0:
        return
    if _is_shared_wordlist_string_ref(s):
        # Defensive fallback: callers should store independent copies of wordlist
        # entries (e.g. "".join(word)) before any future wipe operation.
        # Never wipe shared global wordlist entries in place.
        logger.debug("Skipping wipe of shared wordlist string reference")
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
