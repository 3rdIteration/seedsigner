"""Selector → function resolution for offline calldata decoding.

The device is air-gapped, so there is no 4byte.directory / online ABI: we ship a
**curated** table of common function signatures (with friendly parameter names
and a ``kind`` used for nicer rendering) plus a **long-tail** list of additional
signatures decoded generically (no friendly names).  Every 4-byte selector is
computed here from its canonical signature via ``keccak256(sig)[:4]`` — the
table is therefore self-verifying: a typo'd signature simply produces a
different selector and fails its test, never a wrong-but-plausible decode.

This is a *display* aid only.  An unknown selector is not an error — the caller
shows a blind-signing warning and the raw hex / digest instead.

To extend: add a ``(signature, [param names], kind)`` row to ``CURATED`` for a
function you want rendered nicely, or just a signature string to ``LONG_TAIL``
to resolve its name + generic parameters.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from . import abi_decode
from .keccak import keccak256


# kind values that drive rendering in calldata_decoder
KIND_TRANSFER = "transfer"
KIND_APPROVE = "approve"
KIND_SWAP = "swap"
KIND_WRAP = "wrap"
KIND_PERMIT = "permit"
KIND_GENERIC = "generic"


@dataclass
class FunctionEntry:
    selector: bytes
    name: str
    signature: str
    arg_types: List["abi_decode.ABIType"]
    param_names: Optional[List[str]]  # friendly names (curated) or None
    kind: str


# (canonical signature, friendly parameter names, kind)
CURATED = [
    # --- ERC-20 -----------------------------------------------------------
    ("transfer(address,uint256)", ["to", "amount"], KIND_TRANSFER),
    ("transferFrom(address,address,uint256)", ["from", "to", "amount"], KIND_TRANSFER),
    ("approve(address,uint256)", ["spender", "amount"], KIND_APPROVE),
    # --- ERC-721 / ERC-1155 ----------------------------------------------
    ("safeTransferFrom(address,address,uint256)", ["from", "to", "tokenId"], KIND_TRANSFER),
    ("safeTransferFrom(address,address,uint256,bytes)", ["from", "to", "tokenId", "data"], KIND_TRANSFER),
    ("safeTransferFrom(address,address,uint256,uint256,bytes)", ["from", "to", "id", "amount", "data"], KIND_TRANSFER),
    ("setApprovalForAll(address,bool)", ["operator", "approved"], KIND_APPROVE),
    # --- WETH / wrapped native -------------------------------------------
    ("deposit()", [], KIND_WRAP),
    ("withdraw(uint256)", ["amount"], KIND_WRAP),
    # --- EIP-2612 / Permit2 ----------------------------------------------
    ("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
     ["owner", "spender", "value", "deadline", "v", "r", "s"], KIND_PERMIT),
    ("approve(address,address,uint160,uint48)",
     ["token", "spender", "amount", "expiration"], KIND_APPROVE),
    # --- Uniswap V2 router swaps -----------------------------------------
    ("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
     ["amountIn", "amountOutMin", "path", "to", "deadline"], KIND_SWAP),
    ("swapTokensForExactTokens(uint256,uint256,address[],address,uint256)",
     ["amountOut", "amountInMax", "path", "to", "deadline"], KIND_SWAP),
    ("swapExactETHForTokens(uint256,address[],address,uint256)",
     ["amountOutMin", "path", "to", "deadline"], KIND_SWAP),
    ("swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
     ["amountIn", "amountOutMin", "path", "to", "deadline"], KIND_SWAP),
    ("swapETHForExactTokens(uint256,address[],address,uint256)",
     ["amountOut", "path", "to", "deadline"], KIND_SWAP),
    # --- Uniswap V3 SwapRouter (with deadline) ---------------------------
    ("exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
     ["params"], KIND_SWAP),
    ("exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
     ["params"], KIND_SWAP),
    ("exactInput((bytes,address,uint256,uint256,uint256))", ["params"], KIND_SWAP),
    ("exactOutput((bytes,address,uint256,uint256,uint256))", ["params"], KIND_SWAP),
    # --- Uniswap V3 SwapRouter02 (no deadline) ---------------------------
    ("exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
     ["params"], KIND_SWAP),
    ("exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))",
     ["params"], KIND_SWAP),
    ("exactInput((bytes,address,uint256,uint256))", ["params"], KIND_SWAP),
    ("exactOutput((bytes,address,uint256,uint256))", ["params"], KIND_SWAP),
    # --- batching --------------------------------------------------------
    ("multicall(bytes[])", ["calls"], KIND_GENERIC),
    ("multicall(uint256,bytes[])", ["deadline", "calls"], KIND_GENERIC),
]


# Additional signatures resolved generically (name + typed params, no friendly
# labels).  Seeded with common state-changing functions; extend freely.
LONG_TAIL = [
    "increaseAllowance(address,uint256)",
    "decreaseAllowance(address,uint256)",
    "mint(address,uint256)",
    "mint(uint256)",
    "mint(address)",
    "burn(uint256)",
    "burn(address,uint256)",
    "deposit(uint256)",
    "deposit(uint256,address)",
    "withdraw(uint256,address,address)",
    "redeem(uint256,address,address)",
    "stake(uint256)",
    "unstake(uint256)",
    "claim()",
    "claimRewards()",
    "getReward()",
    "execute(bytes,bytes[])",
    "execute(bytes,bytes[],uint256)",
    "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
    "swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)",
    "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
    "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
    "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
    "wrapETH(uint256)",
    "unwrapWETH9(uint256,address)",
    "transferOwnership(address)",
    "renounceOwnership()",
    "delegate(address)",
]


def function_selector(signature: str) -> bytes:
    """First 4 bytes of keccak256 of the canonical signature."""
    return keccak256(signature.encode("ascii"))[:4]


def _name_of(signature: str) -> str:
    return signature[:signature.index("(")]


def _build() -> Dict[bytes, FunctionEntry]:
    table: Dict[bytes, FunctionEntry] = {}
    # Long tail first; curated entries overwrite on selector collision so the
    # friendly metadata always wins.
    for sig in LONG_TAIL:
        try:
            name, types = abi_decode.parse_signature(sig)
            sel = function_selector(sig)
            table[sel] = FunctionEntry(sel, name, sig, types, None, KIND_GENERIC)
        except ValueError:
            continue  # never let one bad row break the registry
    for sig, names, kind in CURATED:
        try:
            name, types = abi_decode.parse_signature(sig)
            sel = function_selector(sig)
            table[sel] = FunctionEntry(sel, name, sig, types, names, kind)
        except ValueError:
            continue
    return table


_BY_SELECTOR = _build()


def resolve(selector: bytes) -> Optional[FunctionEntry]:
    """Look up a 4-byte selector, or None if unknown."""
    return _BY_SELECTOR.get(bytes(selector))
