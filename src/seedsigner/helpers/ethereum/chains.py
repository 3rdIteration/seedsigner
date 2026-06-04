"""Human-readable names for common EVM chain ids (display only)."""

from __future__ import annotations

# Curated, extensible.  Unknown ids fall back to ``chain <n>``.
CHAIN_NAMES = {
    1: "Ethereum",
    10: "Optimism",
    56: "BNB Chain",
    100: "Gnosis",
    137: "Polygon",
    324: "zkSync Era",
    8453: "Base",
    42161: "Arbitrum",
    42170: "Arbitrum Nova",
    43114: "Avalanche",
    59144: "Linea",
    534352: "Scroll",
    11155111: "Sepolia",
    17000: "Holesky",
}


def chain_label(chain_id: int) -> str:
    name = CHAIN_NAMES.get(chain_id)
    return f"{name} ({chain_id})" if name else f"chain {chain_id}"
