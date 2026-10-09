"""Tests for seedsigner.helpers.secure_delete.

Focuses on the defense-in-depth refcount guard that prevents wipe_string()
from corrupting shared/immortal strings such as BIP-39 wordlist entries.
"""

import sys

from embit import bip39

from seedsigner.helpers.secure_delete import (
    _is_shared,
    wipe_bytes,
    wipe_dict,
    wipe_list,
    wipe_string,
    wipe_value,
)


def test_independent_copy_is_not_shared():
    """An independent copy created via ''.join() should NOT be detected as shared."""
    copy = "".join("abandon")
    assert not _is_shared(copy), (
        f"Independent copy detected as shared (refcount={sys.getrefcount(copy)})"
    )


def test_wordlist_entry_is_shared():
    """A direct reference to a bip39.WORDLIST entry should be detected as shared."""
    word = bip39.WORDLIST[0]
    assert _is_shared(word), (
        f"Wordlist entry not detected as shared (refcount={sys.getrefcount(word)})"
    )


def test_wipe_string_skips_shared_string():
    """wipe_string() must refuse to zero a shared/immortal string."""
    word = bip39.WORDLIST[42]
    original_value = "".join(word)  # Independent snapshot of the value
    wipe_string(word)
    # The wordlist entry must still contain its original value.
    assert bip39.WORDLIST[42] == original_value, (
        f"wipe_string corrupted shared string: "
        f"expected {original_value!r}, got {bip39.WORDLIST[42]!r}"
    )


def test_wipe_string_zeros_independent_copy():
    """wipe_string() must still zero strings that are independent copies."""
    original = "sensitive_data_12345"
    copy = "".join(original)
    wipe_string(copy)
    assert copy == "\x00" * len(original), (
        f"wipe_string did not zero independent copy: {copy!r}"
    )


def test_wipe_list_with_direct_wordlist_refs_does_not_corrupt():
    """Regression: wipe_list() called on a list of direct wordlist references
    must not corrupt the global BIP-39 wordlist."""
    # Take the first 12 wordlist entries by direct reference (simulating a bug
    # where "".join() was forgotten).
    originals = ["".join(w) for w in bip39.WORDLIST[:12]]
    direct_refs = list(bip39.WORDLIST[:12])

    wipe_list(direct_refs)

    for i in range(12):
        assert bip39.WORDLIST[i] == originals[i], (
            f"WORDLIST[{i}] corrupted: "
            f"expected {originals[i]!r}, got {bip39.WORDLIST[i]!r}"
        )


def test_wipe_list_with_independent_copies_wipes_correctly():
    """wipe_list() should still wipe independent copies."""
    words = ["".join(w) for w in bip39.WORDLIST[:5]]
    lengths = [len(w) for w in words]
    wipe_list(words)

    # After wipe_list, the list should be empty (cleared).
    assert words == []


def test_full_lifecycle_wordlist_integrity():
    """Simulate a complete seed entry lifecycle and verify wordlist integrity.

    This covers the full path: store words (via "".join), discard pending
    mnemonic (which calls wipe_list), and verify the global wordlist is
    still intact.
    """
    from seedsigner.models.seed_storage import SeedStorage
    import os

    # Generate a valid mnemonic
    entropy = os.urandom(16)
    mnemonic_str = bip39.mnemonic_from_bytes(entropy)
    valid_words = mnemonic_str.split()

    # Save originals for comparison
    original_wordlist = ["".join(w) for w in bip39.WORDLIST]

    # Simulate: enter words (as direct wordlist refs, worst case)
    storage = SeedStorage()
    storage.init_pending_mnemonic(num_words=12)
    for i, word in enumerate(valid_words):
        idx = bip39.WORDLIST.index(word)
        storage.update_pending_mnemonic(bip39.WORDLIST[idx], i)

    # Discard (triggers wipe_list)
    storage.discard_pending_mnemonic()

    # Verify full wordlist integrity
    for i in range(2048):
        assert bip39.WORDLIST[i] == original_wordlist[i], (
            f"WORDLIST[{i}] corrupted after discard: "
            f"expected {original_wordlist[i]!r}, got {bip39.WORDLIST[i]!r}"
        )


def test_wipe_list_overwrites_int_elements_before_clearing():
    """A PIN or an unlock secret held as list(bytes) has no buffer of its own
    to zero: the secret is which cached int each slot points at. clear() alone
    frees the slot array with those pointers still in it."""

    class RecordingList(list):
        def __init__(self, items):
            super().__init__(items)
            self.writes = []

        def __setitem__(self, index, value):
            self.writes.append((index, value))
            super().__setitem__(index, value)

    pin = RecordingList(b"123456")

    wipe_list(pin)

    assert pin.writes == [(i, 0) for i in range(6)]
    assert pin == []


def test_wipe_dict_zeroes_only_the_named_values():
    """Metadata next to a secret is often a code constant (a type tag, a
    source name). On CPython < 3.12 zeroing one in place corrupts it for the
    whole process, so only the values named as secret are wiped."""
    key = "".join("00112233445566778899AABBCCDDEEFF")
    tag = "".join("single")
    d = {"type": tag, "key": key}

    wipe_dict(d, ("key",))

    assert key == "\x00" * len(key)
    assert tag == "single"
    assert d == {}


def test_wipe_value_ignores_what_it_cannot_zero():
    """A value of another type is left alone rather than guessed at: a str
    walked as a list would hand wipe_string() its one-character pieces."""
    for value in (None, 7, ("a", "b"), object()):
        wipe_value(value)

    secret = "".join("hunter2")
    wipe_value(secret)
    assert secret == "\x00" * len("hunter2")


def test_wipe_bytes_skips_a_shared_one_byte_object():
    """CPython keeps one object per one-byte value. Zeroing it in place would
    turn that byte into NUL for every bytes value that uses it."""
    one_byte = bytes([7])

    wipe_bytes(one_byte)

    assert bytes([7])[0] == 7


def test_one_character_str_is_shared():
    """The same holds for one-character strings; before 3.11 their refcount
    is ordinary, so only the length gives them away."""
    assert _is_shared("".join(["q"]))
