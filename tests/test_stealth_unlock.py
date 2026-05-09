"""Tests for ``seedsigner.stealth.unlock``."""

from __future__ import annotations

import os
import sys
import unittest


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


class TestParseSequence(unittest.TestCase):
    def test_default_5_up(self):
        from seedsigner.stealth.unlock import parse_sequence
        self.assertEqual(
            parse_sequence("KEY_UP,KEY_UP,KEY_UP,KEY_UP,KEY_UP"),
            ["KEY_UP"] * 5,
        )

    def test_strip_whitespace_and_skip_blanks(self):
        from seedsigner.stealth.unlock import parse_sequence
        self.assertEqual(
            parse_sequence("KEY_UP , KEY_DOWN , , KEY_PRESS"),
            ["KEY_UP", "KEY_DOWN", "KEY_PRESS"],
        )

    def test_rejects_unknown_key(self):
        from seedsigner.stealth.unlock import parse_sequence, InvalidSequenceError
        with self.assertRaises(InvalidSequenceError):
            parse_sequence("KEY_UP,KEY_OVER_THE_RAINBOW,KEY_UP")

    def test_rejects_empty(self):
        from seedsigner.stealth.unlock import parse_sequence, InvalidSequenceError
        with self.assertRaises(InvalidSequenceError):
            parse_sequence("")
        with self.assertRaises(InvalidSequenceError):
            parse_sequence(None)
        with self.assertRaises(InvalidSequenceError):
            parse_sequence(",,,")

    def test_rejects_too_short(self):
        from seedsigner.stealth.unlock import parse_sequence, InvalidSequenceError
        with self.assertRaises(InvalidSequenceError):
            parse_sequence("KEY_UP,KEY_DOWN")

    def test_rejects_too_long(self):
        from seedsigner.stealth.unlock import parse_sequence, InvalidSequenceError
        too_long = ",".join(["KEY_UP"] * 13)
        with self.assertRaises(InvalidSequenceError):
            parse_sequence(too_long)

    def test_accepts_max_length(self):
        from seedsigner.stealth.unlock import parse_sequence
        max_seq = ",".join(["KEY_UP"] * 12)
        self.assertEqual(parse_sequence(max_seq), ["KEY_UP"] * 12)

    def test_accepts_min_length(self):
        from seedsigner.stealth.unlock import parse_sequence
        self.assertEqual(
            parse_sequence("KEY_UP,KEY_DOWN,KEY_PRESS"),
            ["KEY_UP", "KEY_DOWN", "KEY_PRESS"],
        )

    def test_case_sensitive(self):
        from seedsigner.stealth.unlock import parse_sequence, InvalidSequenceError
        with self.assertRaises(InvalidSequenceError):
            parse_sequence("key_up,key_up,key_up")


class TestUnlockBuffer(unittest.TestCase):
    def test_no_match_until_complete(self):
        from seedsigner.stealth.unlock import UnlockBuffer
        buf = UnlockBuffer(["KEY_UP"] * 5)
        for _ in range(4):
            self.assertFalse(buf.feed("KEY_UP"))
        self.assertTrue(buf.feed("KEY_UP"))

    def test_wrong_key_resets_via_suffix_window(self):
        from seedsigner.stealth.unlock import UnlockBuffer
        buf = UnlockBuffer(["KEY_UP"] * 5)
        # 4 correct, 1 wrong => last 5 are now [UP, UP, UP, UP, DOWN].
        for _ in range(4):
            buf.feed("KEY_UP")
        self.assertFalse(buf.feed("KEY_DOWN"))
        # Now 5 correct in a row matches even though we mis-pressed before.
        for _ in range(4):
            self.assertFalse(buf.feed("KEY_UP"))
        self.assertTrue(buf.feed("KEY_UP"))

    def test_mixed_sequence_match(self):
        from seedsigner.stealth.unlock import UnlockBuffer
        seq = ["KEY_UP", "KEY_DOWN", "KEY_LEFT", "KEY_RIGHT", "KEY_PRESS"]
        buf = UnlockBuffer(seq)
        for k in seq[:-1]:
            self.assertFalse(buf.feed(k))
        self.assertTrue(buf.feed(seq[-1]))

    def test_reset_clears_buffer(self):
        from seedsigner.stealth.unlock import UnlockBuffer
        buf = UnlockBuffer(["KEY_UP"] * 3)
        buf.feed("KEY_UP")
        buf.feed("KEY_UP")
        buf.reset()
        self.assertFalse(buf.feed("KEY_UP"))  # only 1 in buffer post-reset

    def test_constructor_rejects_empty_sequence(self):
        from seedsigner.stealth.unlock import UnlockBuffer, InvalidSequenceError
        with self.assertRaises(InvalidSequenceError):
            UnlockBuffer([])

    def test_constructor_rejects_unknown_keys(self):
        from seedsigner.stealth.unlock import UnlockBuffer, InvalidSequenceError
        with self.assertRaises(InvalidSequenceError):
            UnlockBuffer(["KEY_UP", "KEY_BANANA", "KEY_UP"])

    def test_sequence_length_property(self):
        from seedsigner.stealth.unlock import UnlockBuffer
        buf = UnlockBuffer(["KEY_UP", "KEY_DOWN", "KEY_PRESS"])
        self.assertEqual(buf.sequence_length, 3)


if __name__ == "__main__":
    unittest.main()
