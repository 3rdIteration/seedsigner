"""Known-token registry: contract address -> (symbol, decimals).

Offline we cannot read a token's ``decimals()``, so amounts for unknown tokens
are shown as raw integer units.  For a small set of major tokens we bundle the
(symbol, decimals) so a ``transfer`` / ``approve`` renders as e.g. ``5 USDC``.

This is a *display hint*: an unknown token simply renders raw units, and a wrong
entry can never change what is signed (the calldata digest is the source of
truth).  Keyed by chain id then lowercase 40-char hex address (no ``0x``).
Extend by adding rows; symbols are not authenticated, so keep to well-known
canonical contracts.
"""

from __future__ import annotations

from typing import Optional, Tuple

KNOWN_TOKENS = {
    1: {  # Ethereum mainnet
        "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USDC", 6),
        "dac17f958d2ee523a2206206994597c13d831ec7": ("USDT", 6),
        "6b175474e89094c44da98b954eedeac495271d0f": ("DAI", 18),
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": ("WETH", 18),
        "2260fac5e5542a773aa44fbcfedf7c193bc2c599": ("WBTC", 8),
    },
    10: {  # Optimism
        "0b2c639c533813f4aa9d7837caf62653d097ff85": ("USDC", 6),
        "94b008aa00579c1307b0ef2c499ad98a8ce58e58": ("USDT", 6),
        "4200000000000000000000000000000000000006": ("WETH", 18),
    },
    137: {  # Polygon
        "3c499c542cef5e3811e1192ce70d8cc03d5c3359": ("USDC", 6),
        "2791bca1f2de4661ed88a30c99a7a9449aa84174": ("USDC.e", 6),
        "c2132d05d31c914a87c6611c10748aeb04b58e8f": ("USDT", 6),
        "7ceb23fd6bc0add59e62ac25578270cff1b9f619": ("WETH", 18),
    },
    8453: {  # Base
        "833589fcd6edb6e08f4c7c32d4f71b54bda02913": ("USDC", 6),
        "4200000000000000000000000000000000000006": ("WETH", 18),
    },
    42161: {  # Arbitrum
        "af88d065e77c8cc2239327c5edb3a432268e5831": ("USDC", 6),
        "fd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": ("USDT", 6),
        "82af49447d8a07e3bd95bd0d56f35241523fbab1": ("WETH", 18),
    },
}


def lookup_token(chain_id: int, address: bytes) -> Optional[Tuple[str, int]]:
    if not address or len(address) != 20:
        return None
    return KNOWN_TOKENS.get(chain_id, {}).get(address.hex().lower())


def format_token_amount(raw: int, symbol: str, decimals: int) -> str:
    """Exact decimal formatting (no float), trailing zeros trimmed."""
    if decimals <= 0:
        return f"{raw} {symbol}"
    s = str(raw).rjust(decimals + 1, "0")
    int_part, frac_part = s[:-decimals], s[-decimals:].rstrip("0")
    value = int_part + ("." + frac_part if frac_part else "")
    return f"{value} {symbol}"
