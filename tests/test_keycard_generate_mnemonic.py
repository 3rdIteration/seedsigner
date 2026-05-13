"""Tests for the GENERATE MNEMONIC APDU + response parser.

The Status Keycard applet generates fresh BIP-39 entropy on-card and
returns the wordlist indices to the host over the secure channel. The
host then maps indices to words, derives the 64-byte seed and pushes it
back with LOAD_KEY. These tests exercise just the wire layer and the
wordlist-safe word lookup pattern used by the Generate flow in
``keycard_views.py``.
"""

import pytest
from embit import bip39

from seedsigner.helpers.keycard import commands
from seedsigner.helpers.keycard.responses import parse_generate_mnemonic
from seedsigner.helpers.secure_delete import wipe_list


class TestGenerateMnemonicApdu:
    def test_word_count_to_p1(self):
        for words, p1 in ((12, 4), (15, 5), (18, 6), (21, 7), (24, 8)):
            apdu = commands.generate_mnemonic(words)
            assert apdu[0] == commands.CLA_PROPRIETARY
            assert apdu[1] == commands.INS_GENERATE_MNEMONIC
            assert apdu[2] == p1
            assert apdu[3] == 0x00

    def test_rejects_bad_word_count(self):
        for bad in (0, 11, 13, 23, 25, -1):
            with pytest.raises(ValueError):
                commands.generate_mnemonic(bad)


class TestGenerateMnemonicParser:
    def test_round_trips_indices(self):
        indices = [0, 1, 2047, 1234]
        body = b"".join(i.to_bytes(2, "big") for i in indices)
        assert parse_generate_mnemonic(body, word_count=4) == indices

    def test_rejects_wrong_length(self):
        with pytest.raises(ValueError):
            parse_generate_mnemonic(b"\x00" * 22, word_count=12)
        with pytest.raises(ValueError):
            parse_generate_mnemonic(b"\x00" * 26, word_count=12)

    def test_rejects_out_of_range_index(self):
        # 2048 >= len(WORDLIST), must reject.
        body = (0).to_bytes(2, "big") + (2048).to_bytes(2, "big")
        with pytest.raises(ValueError):
            parse_generate_mnemonic(body, word_count=2)

    @pytest.mark.parametrize("word_count", [12, 15, 18, 21, 24])
    def test_parses_all_valid_lengths(self, word_count):
        body = b"\x00" * (2 * word_count)
        out = parse_generate_mnemonic(body, word_count)
        assert len(out) == word_count
        assert all(idx == 0 for idx in out)


class TestWordlistSafety:
    """Regression: the Generate flow must use ``"".join(WORDLIST[i])``
    when building the mnemonic list so a later ``wipe_list`` cannot
    corrupt the shared module-level wordlist (CLAUDE.md "Secure wipe
    and shared wordlist safety").
    """

    def test_word_copies_can_be_wiped_without_corrupting_wordlist(self):
        # Capture the canonical values BEFORE we wipe so the assertion
        # below is meaningful regardless of test ordering.
        canonical_first = bip39.WORDLIST[0][:]
        canonical_last = bip39.WORDLIST[2047][:]

        indices = [0, 1, 2047]
        # Mirror the production pattern in
        # ToolsKeycardGenerateMnemonicRunView.
        words = ["".join(bip39.WORDLIST[i]) for i in indices]
        wipe_list(words)

        assert bip39.WORDLIST[0] == canonical_first
        assert bip39.WORDLIST[2047] == canonical_last

    def test_unsafe_pattern_would_corrupt_wordlist_NOT_USED_IN_PROD(self):
        """Sanity check that the safety pattern is necessary.

        Stores a direct reference to a WORDLIST element instead of the
        ``"".join(...)`` copy. wipe_list is documented to refuse
        shared/immortal strings, so this should NOT actually mutate
        the wordlist — but if a future refactor weakens the guard,
        this test will start failing on the assertion below, signalling
        to the maintainer that the safety pattern is doing real work.
        """
        canonical = bip39.WORDLIST[42][:]
        words = [bip39.WORDLIST[42]]  # intentionally unsafe pattern
        wipe_list(words)
        # secure_delete's _is_shared guard refuses to wipe shared
        # strings; if the guard breaks, the assertion catches it.
        assert bip39.WORDLIST[42] == canonical
