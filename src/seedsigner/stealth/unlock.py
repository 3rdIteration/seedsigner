"""Stealth unlock buffer.

Reads ``HardwareButtonsConstants`` key names off a stream of presses and
fires when the most recent N presses match the configured sequence. Used
by the boot Snake game to decide when to leave the game and continue
into the firmware.

Design notes
------------
- The match is a *suffix* match: the buffer holds the last ``len(seq)``
  presses; firing only happens when the whole window equals ``seq``. This
  means an "almost right" attempt followed by a correct retype still
  unlocks (the correct tail wins), but no partial-progress signal is
  shown to the user.
- Pressing a key that is not part of the sequence does NOT reset the
  buffer; it just shifts it forward. This keeps the gesture indis-
  tinguishable from normal play.
- The buffer is cheap; the game can call ``feed`` on every input even
  when the user is just steering the snake.
"""

from __future__ import annotations

from collections import deque
from typing import Iterable, List


# Defined here (not imported from buttons.py) so this module stays
# importable in headless test environments that mock the hardware module.
_VALID_KEYS = frozenset({
    "KEY_UP", "KEY_DOWN", "KEY_LEFT", "KEY_RIGHT", "KEY_PRESS",
    "KEY1", "KEY2", "KEY3",
})

_MIN_SEQUENCE_LEN = 3
_MAX_SEQUENCE_LEN = 12


class InvalidSequenceError(ValueError):
    """Raised when the configured unlock sequence cannot be parsed."""


def parse_sequence(csv: str) -> List[str]:
    """Parse a comma-separated list of key constants into a Python list.

    Whitespace around tokens is trimmed. Tokens are case-sensitive and
    must match a known ``HardwareButtonsConstants`` name. Length is
    bounded between ``_MIN_SEQUENCE_LEN`` and ``_MAX_SEQUENCE_LEN``.
    """
    if csv is None:
        raise InvalidSequenceError("sequence is required")
    tokens = [t.strip() for t in csv.split(",") if t.strip()]
    if not tokens:
        raise InvalidSequenceError("sequence is empty")
    if len(tokens) < _MIN_SEQUENCE_LEN:
        raise InvalidSequenceError(
            f"sequence must be at least {_MIN_SEQUENCE_LEN} keys long"
        )
    if len(tokens) > _MAX_SEQUENCE_LEN:
        raise InvalidSequenceError(
            f"sequence must be at most {_MAX_SEQUENCE_LEN} keys long"
        )
    for tok in tokens:
        if tok not in _VALID_KEYS:
            raise InvalidSequenceError(f"unknown key: {tok!r}")
    return tokens


class UnlockBuffer:
    """Suffix-match buffer for the unlock combo.

    Usage::

        buf = UnlockBuffer(["KEY_UP"] * 5)
        for press in stream:
            if buf.feed(press):
                exit_game()
    """

    def __init__(self, sequence: Iterable[str]):
        self._sequence: List[str] = list(sequence)
        if not self._sequence:
            raise InvalidSequenceError("sequence must not be empty")
        if not all(s in _VALID_KEYS for s in self._sequence):
            raise InvalidSequenceError("sequence contains unknown keys")
        self._buf: deque = deque(maxlen=len(self._sequence))

    def feed(self, key: str) -> bool:
        """Append ``key`` to the buffer. Returns True iff the buffer matches."""
        self._buf.append(key)
        if len(self._buf) < len(self._sequence):
            return False
        return list(self._buf) == self._sequence

    def reset(self) -> None:
        self._buf.clear()

    @property
    def sequence_length(self) -> int:
        return len(self._sequence)
