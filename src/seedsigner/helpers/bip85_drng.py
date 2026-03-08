"""BIP85 Deterministic Random Number Generator using SHAKE256.

This module implements the BIP85-DRNG as specified in
https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#user-content-BIP85DRNG.
The generator seeds a SHAKE256 XOF with 64 bytes of BIP85 entropy and
exposes a ``read`` method suitable for use with libraries expecting a
file-like interface.
"""

from Cryptodome.Hash import SHAKE256


class BIP85DRNG:
    """Deterministic RNG backed by SHAKE256."""

    def __init__(self, entropy: bytes) -> None:
        if len(entropy) != 64:
            raise ValueError("Entropy must be exactly 64 bytes")
        self._shake = SHAKE256.new(entropy)

    @classmethod
    def new(cls, entropy: bytes) -> "BIP85DRNG":
        """Create a new BIP85DRNG instance from 64 bytes of entropy."""
        return cls(entropy)

    def read(self, n: int) -> bytes:
        """Read ``n`` bytes from the SHAKE256 stream."""
        return self._shake.read(n)
