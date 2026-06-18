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
    # --- 1inch AggregationRouter V5 --------------------------------------
    # Every selector below is asserted against its known on-chain value in
    # tests/test_ethereum_signature_index.py (TestCuratedProtocolSelectors).
    ("swap(address,(address,address,address,address,uint256,uint256,uint256),bytes,bytes)",
     ["executor", "desc", "permit", "data"], KIND_SWAP),                       # 0x12aa3caf
    ("unoswap(address,uint256,uint256,uint256[])",
     ["srcToken", "amount", "minReturn", "pools"], KIND_SWAP),                 # 0x0502b1c5
    ("unoswapTo(address,address,uint256,uint256,uint256[])",
     ["recipient", "srcToken", "amount", "minReturn", "pools"], KIND_SWAP),    # 0xf78dc253
    # --- 0x Exchange Proxy ------------------------------------------------
    ("transformERC20(address,address,uint256,uint256,(uint32,bytes)[])",
     ["inputToken", "outputToken", "inputAmount", "minOutputAmount", "transformations"],
     KIND_SWAP),                                                              # 0x415565b0
    # --- CowSwap GPv2Settlement ------------------------------------------
    ("settle(address[],uint256[],(uint256,uint256,address,uint256,uint256,uint32,bytes32,uint256,uint256,uint256,bytes)[],(address,uint256,bytes)[][3])",
     ["tokens", "clearingPrices", "trades", "interactions"], KIND_GENERIC),    # 0x13d79a0b
    ("setPreSignature(bytes,bool)", ["orderUid", "signed"], KIND_GENERIC),     # 0xec6cb13f
    ("invalidateOrder(bytes)", ["orderUid"], KIND_GENERIC),                    # 0x15337bc0
    # --- CowSwap CoWSwapEthFlow (native-ETH orders) ----------------------
    # Single tuple param = EthFlowOrder.Data
    # (buyToken, receiver, sellAmount, buyAmount, appData, feeAmount, validTo,
    #  partiallyFillable, quoteId). param_names label the top-level arg only;
    # the tuple fields render positionally (order.0 … order.8).
    ("createOrder((address,address,uint256,uint256,bytes32,uint256,uint32,bool,int64))",
     ["order"], KIND_SWAP),                                                    # 0x322bba21
    ("invalidateOrder((address,address,uint256,uint256,bytes32,uint256,uint32,bool,int64))",
     ["order"], KIND_GENERIC),                                                 # 0x7bc41b96
    # --- Seaport 1.x (OpenSea) -------------------------------------------
    # Large nested structs; we surface the verified function name (and decode
    # params best-effort) instead of blind-signing. param_names label the
    # top-level args only.
    ("fulfillBasicOrder((address,uint256,uint256,address,address,address,uint256,uint256,uint8,uint256,uint256,bytes32,uint256,bytes32,bytes32,uint256,(uint256,address)[],bytes))",
     ["parameters"], KIND_GENERIC),                                           # 0xfb0f3ee1
    ("fulfillBasicOrder_efficient_6GL6yc((address,uint256,uint256,address,address,address,uint256,uint256,uint8,uint256,uint256,bytes32,uint256,bytes32,bytes32,uint256,(uint256,address)[],bytes))",
     ["parameters"], KIND_GENERIC),                                           # 0x00000000
    ("fulfillOrder(((address,address,(uint8,address,uint256,uint256,uint256)[],(uint8,address,uint256,uint256,uint256,address)[],uint8,uint256,uint256,bytes32,uint256,bytes32,uint256),bytes),bytes32)",
     ["order", "fulfillerConduitKey"], KIND_GENERIC),                         # 0xb3a34c4c
    ("fulfillAdvancedOrder(((address,address,(uint8,address,uint256,uint256,uint256)[],(uint8,address,uint256,uint256,uint256,address)[],uint8,uint256,uint256,bytes32,uint256,bytes32,uint256),uint120,uint120,bytes,bytes),(uint256,uint8,uint256,uint256,bytes32[])[],bytes32,address)",
     ["advancedOrder", "criteriaResolvers", "fulfillerConduitKey", "recipient"], KIND_GENERIC),  # 0xe7acab24
    ("fulfillAvailableOrders(((address,address,(uint8,address,uint256,uint256,uint256)[],(uint8,address,uint256,uint256,uint256,address)[],uint8,uint256,uint256,bytes32,uint256,bytes32,uint256),bytes)[],(uint256,uint256)[][],(uint256,uint256)[][],bytes32,uint256)",
     ["orders", "offerFulfillments", "considerationFulfillments", "fulfillerConduitKey", "maximumFulfilled"], KIND_GENERIC),  # 0xed98a574
    ("fulfillAvailableAdvancedOrders(((address,address,(uint8,address,uint256,uint256,uint256)[],(uint8,address,uint256,uint256,uint256,address)[],uint8,uint256,uint256,bytes32,uint256,bytes32,uint256),uint120,uint120,bytes,bytes)[],(uint256,uint8,uint256,uint256,bytes32[])[],(uint256,uint256)[][],(uint256,uint256)[][],bytes32,address,uint256)",
     ["advancedOrders", "criteriaResolvers", "offerFulfillments", "considerationFulfillments", "fulfillerConduitKey", "recipient", "maximumFulfilled"], KIND_GENERIC),  # 0x87201b41
    ("matchOrders(((address,address,(uint8,address,uint256,uint256,uint256)[],(uint8,address,uint256,uint256,uint256,address)[],uint8,uint256,uint256,bytes32,uint256,bytes32,uint256),bytes)[],((uint256,uint256)[],(uint256,uint256)[])[])",
     ["orders", "fulfillments"], KIND_GENERIC),                              # 0xa8174404
    ("matchAdvancedOrders(((address,address,(uint8,address,uint256,uint256,uint256)[],(uint8,address,uint256,uint256,uint256,address)[],uint8,uint256,uint256,bytes32,uint256,bytes32,uint256),uint120,uint120,bytes,bytes)[],(uint256,uint8,uint256,uint256,bytes32[])[],((uint256,uint256)[],(uint256,uint256)[])[],address)",
     ["advancedOrders", "criteriaResolvers", "fulfillments", "recipient"], KIND_GENERIC),  # 0xf2d12b12
    # --- Uniswap Universal Router ----------------------------------------
    # The dominant Uniswap entrypoint. Commands/inputs are an opaque program;
    # the digest + raw-data screens stay the source of truth for the details.
    ("execute(bytes,bytes[],uint256)", ["commands", "inputs", "deadline"], KIND_SWAP),     # 0x3593564c
    ("execute(bytes,bytes[])", ["commands", "inputs"], KIND_GENERIC),                      # 0x24856bc3
    # --- Permit2 (canonical 0x000000000022D473030F116dDEE9F6B43aC78BA3) ---
    ("permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
     ["owner", "permitSingle", "signature"], KIND_PERMIT),                                 # 0x2b67b570
    ("permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)",
     ["owner", "permitBatch", "signature"], KIND_PERMIT),                                  # 0x2a2d80d1
    ("transferFrom(address,address,uint160,address)",
     ["from", "to", "amount", "token"], KIND_TRANSFER),                                    # 0x36c78516
    ("lockdown((address,address)[])", ["approvals"], KIND_APPROVE),                        # 0xcc53287f
    # --- Safe (Gnosis Safe) multisig -------------------------------------
    ("execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
     ["to", "value", "data", "operation", "safeTxGas", "baseGas", "gasPrice",
      "gasToken", "refundReceiver", "signatures"], KIND_GENERIC),                         # 0x6a761202
    ("approveHash(bytes32)", ["hashToApprove"], KIND_GENERIC),                            # 0xd4d9bdcd
    ("addOwnerWithThreshold(address,uint256)", ["owner", "_threshold"], KIND_GENERIC),    # 0x0d582f13
    ("removeOwner(address,address,uint256)",
     ["prevOwner", "owner", "_threshold"], KIND_GENERIC),                                 # 0xf8dc5dd9
    ("swapOwner(address,address,address)",
     ["prevOwner", "oldOwner", "newOwner"], KIND_GENERIC),                                # 0xe318b52b
    ("changeThreshold(uint256)", ["_threshold"], KIND_GENERIC),                           # 0x694e80c3
    ("enableModule(address)", ["module"], KIND_GENERIC),                                  # 0x610b5925
    ("disableModule(address,address)", ["prevModule", "module"], KIND_GENERIC),           # 0xe009cfde
    # --- Aave V3 Pool ----------------------------------------------------
    ("supply(address,uint256,address,uint16)",
     ["asset", "amount", "onBehalfOf", "referralCode"], KIND_GENERIC),                    # 0x617ba037
    ("withdraw(address,uint256,address)", ["asset", "amount", "to"], KIND_GENERIC),       # 0x69328dec
    ("borrow(address,uint256,uint256,uint16,address)",
     ["asset", "amount", "interestRateMode", "referralCode", "onBehalfOf"], KIND_GENERIC),  # 0xa415bcad
    ("repay(address,uint256,uint256,address)",
     ["asset", "amount", "interestRateMode", "onBehalfOf"], KIND_GENERIC),                # 0x573ade81
    ("setUserUseReserveAsCollateral(address,bool)",
     ["asset", "useAsCollateral"], KIND_GENERIC),                                         # 0x5a3b74b9
    # --- Compound III (Comet) --------------------------------------------
    ("supply(address,uint256)", ["asset", "amount"], KIND_GENERIC),                       # 0xf2b9fdb8
    ("withdraw(address,uint256)", ["asset", "amount"], KIND_GENERIC),                     # 0xf3fef3a3
    ("supplyTo(address,address,uint256)", ["dst", "asset", "amount"], KIND_GENERIC),      # 0x4232cd63
    ("withdrawTo(address,address,uint256)", ["to", "asset", "amount"], KIND_GENERIC),     # 0xc3b35a7e
    # --- Lido (stETH / wstETH) -------------------------------------------
    ("submit(address)", ["referral"], KIND_WRAP),                                         # 0xa1903eab
    ("wrap(uint256)", ["stETHAmount"], KIND_WRAP),                                        # 0xea598cb0
    ("unwrap(uint256)", ["wstETHAmount"], KIND_WRAP),                                     # 0xde0e9a3e
    # --- ENS (ETHRegistrarController / resolver) -------------------------
    ("commit(bytes32)", ["commitment"], KIND_GENERIC),                                    # 0xf14fcbc8
    ("renew(string,uint256)", ["name", "duration"], KIND_GENERIC),                        # 0xacf1a841
    ("register(string,address,uint256,bytes32,address,bytes[],bool,uint16)",
     ["name", "owner", "duration", "secret", "resolver", "data", "reverseRecord",
      "ownerControlledFuses"], KIND_GENERIC),                                             # 0x74694a2b
    ("setAddr(bytes32,address)", ["node", "a"], KIND_GENERIC),                            # 0xd5fa2b00
    ("setName(string)", ["name"], KIND_GENERIC),                                          # 0xc47f0027
    # --- Curve StableSwap / crypto pools ---------------------------------
    ("exchange(int128,int128,uint256,uint256)", ["i", "j", "dx", "min_dy"], KIND_SWAP),  # 0x3df02124
    ("exchange(uint256,uint256,uint256,uint256)", ["i", "j", "dx", "min_dy"], KIND_SWAP),  # 0x5b41b908
    ("add_liquidity(uint256[2],uint256)", ["amounts", "min_mint_amount"], KIND_GENERIC),  # 0x0b4c7e4d
    ("add_liquidity(uint256[3],uint256)", ["amounts", "min_mint_amount"], KIND_GENERIC),  # 0x4515cef3
    ("remove_liquidity(uint256,uint256[2])", ["_amount", "min_amounts"], KIND_GENERIC),   # 0x5b36389c
    # --- 0x classic VIP swaps --------------------------------------------
    ("sellToUniswap(address[],uint256,uint256,bool)",
     ["tokens", "sellAmount", "minBuyAmount", "isSushi"], KIND_SWAP),                     # 0xd9627aa4
    ("sellEthForTokenToUniswapV3(bytes,uint256,address)",
     ["encodedPath", "minBuyAmount", "recipient"], KIND_SWAP),                            # 0x3598d8ab
    ("sellTokenForEthToUniswapV3(bytes,uint256,uint256,address)",
     ["encodedPath", "sellAmount", "minBuyAmount", "recipient"], KIND_SWAP),              # 0x803ba26d
    ("sellTokenForTokenToUniswapV3(bytes,uint256,uint256,address)",
     ["encodedPath", "sellAmount", "minBuyAmount", "recipient"], KIND_SWAP),              # 0x6af479b2
    # --- ERC-4626 vault --------------------------------------------------
    ("mint(uint256,address)", ["shares", "receiver"], KIND_GENERIC),                      # 0x94bf804d
    # --- ERC-4337 smart-account (SimpleAccount + EntryPoint) -------------
    # The dominant smart-wallet entrypoints. The inner call(s) are opaque
    # programs — the digest + raw-data screens stay the source of truth.
    ("execute(address,uint256,bytes)", ["to", "value", "data"], KIND_GENERIC),            # 0xb61d27f6
    ("executeBatch(address[],bytes[])", ["to", "data"], KIND_GENERIC),                    # 0x18dfb3c7
    ("executeBatch(address[],uint256[],bytes[])",
     ["to", "value", "data"], KIND_GENERIC),                                              # 0x47e1da2a
    ("handleOps((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[],address)",
     ["ops", "beneficiary"], KIND_GENERIC),                                               # 0x1fad948c
    # --- LayerZero OFT v1 (cross-chain token transfer) -------------------
    ("sendFrom(address,uint16,bytes32,uint256,address,address,bytes)",
     ["from", "dstChainId", "toAddress", "amount", "refundAddress",
      "zroPaymentAddress", "adapterParams"], KIND_TRANSFER),                              # 0x29adf087
    # --- Multicall3 (0xcA11bde05977b3631167028862bE2a173976CA11) ---------
    ("aggregate((address,bytes)[])", ["calls"], KIND_GENERIC),                            # 0x252dba42
    ("tryAggregate(bool,(address,bytes)[])", ["requireSuccess", "calls"], KIND_GENERIC),  # 0xbce38bd7
    ("aggregate3((address,bool,bytes)[])", ["calls"], KIND_GENERIC),                      # 0x82ad56cb
    ("aggregate3Value((address,bool,uint256,bytes)[])", ["calls"], KIND_GENERIC),         # 0x174dea71
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
