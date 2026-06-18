#!/usr/bin/env python3
"""Coverage probe for the offline ETH calldata decoder (build-machine tool).

Reports, for a list of common mainnet signatures, whether each resolves via the
**curated** registry, via the **bundled index / extended DB**, or falls through
to **blind signing**. Use it after rebuilding the selector index
(see ``scripts/fetch_eth_signatures.md``) to confirm the previously-blind
anchors are now covered.

    python scripts/probe_eth_signature_coverage.py [--input extra_sigs.txt]

``--input`` adds extra canonical signatures (one per line) to the built-in set —
e.g. paste the functions you actually hit blind-sign on.
"""

from __future__ import annotations

import argparse
import os
import sys

_SRC = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from seedsigner.helpers.ethereum.function_registry import (  # noqa: E402
    function_selector,
    resolve as resolve_curated,
)
from seedsigner.helpers.ethereum import signature_db  # noqa: E402


# Common mainnet functions worth verifying. Anything curated is resolved by the
# curated table (and excluded from the index by design); the rest must come from
# the bundled index / extended DB or they blind-sign.
DEFAULT_SIGS = [
    # ERC-20 / 721 / 1155
    "transfer(address,uint256)", "transferFrom(address,address,uint256)",
    "approve(address,uint256)", "setApprovalForAll(address,bool)",
    "safeTransferFrom(address,address,uint256)",
    # WETH / wrap
    "deposit()", "withdraw(uint256)",
    # Uniswap
    "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "execute(bytes,bytes[],uint256)",
    "multicall(bytes[])", "multicall(uint256,bytes[])",
    # ERC-4337 smart-account (now curated)
    "execute(address,uint256,bytes)",
    "executeBatch(address[],bytes[])",
    "executeBatch(address[],uint256[],bytes[])",
    # LayerZero OFT (now curated)
    "sendFrom(address,uint16,bytes32,uint256,address,address,bytes)",
    # Multicall3 (now curated)
    "aggregate3((address,bool,bytes)[])",
    # Safe / Aave / Compound / Lido / ENS / Curve (curated)
    "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
    "supply(address,uint256,address,uint16)", "submit(address)",
]


def classify(sig: str) -> str:
    try:
        sel = function_selector(sig)
    except Exception:
        return "BADSIG"
    if resolve_curated(sel) is not None:
        return "CURATED"
    hits = signature_db.resolve_all(sel)
    if not hits:
        return "BLIND"
    return "INDEX" if len(hits) == 1 else "AMBIG(%d)" % len(hits)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--input", help="extra canonical signatures, one per line")
    a = p.parse_args(argv)

    sigs = list(DEFAULT_SIGS)
    if a.input:
        with open(a.input, "r", encoding="utf-8") as fh:
            for raw in fh:
                s = raw.strip()
                if s and not s.startswith("#"):
                    sigs.append(s)

    counts = {}
    blind = []
    for s in sigs:
        verdict = classify(s)
        counts[verdict.split("(")[0]] = counts.get(verdict.split("(")[0], 0) + 1
        if verdict == "BLIND":
            blind.append(s)
        print(f"  {verdict:<10} {s}")

    total = len(sigs)
    covered = total - counts.get("BLIND", 0) - counts.get("BADSIG", 0)
    print(f"\ncovered {covered}/{total}  "
          + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if blind:
        print("\nstill blind:")
        for s in blind:
            print("  " + s)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
