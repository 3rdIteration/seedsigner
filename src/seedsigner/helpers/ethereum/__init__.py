"""Ethereum primitives shared across the SeedSigner ETH/Keycard flow."""

from __future__ import annotations

# BIP-44 default path for chain id 60 (Ethereum mainnet account 0, address 0).
# Used by:
#   - views/keycard_views.py (Export ETH address; default for Sign ETH when the
#     incoming request omits a derivation_path)
#   - scripts/keycard_smoke_test.py (default --path argument)
#   - tests covering the above call sites
DEFAULT_ETH_PATH = (
    44 | 0x80000000,
    60 | 0x80000000,
    0 | 0x80000000,
    0,
    0,
)

__all__ = ["DEFAULT_ETH_PATH"]
