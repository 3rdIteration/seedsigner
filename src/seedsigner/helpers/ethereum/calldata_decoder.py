"""Decode transaction calldata / EIP-712 typed data into readable screen pages.

This is the single entry point the view layer calls.  It is **display-only**:
``decode_calldata`` never raises (any failure becomes a blind-signing result),
and nothing here influences the bytes that are signed — the ERC-8213 calldata
digest / EIP-712 hashes shown alongside remain the source of truth.

The page renderers return ``[(title, body)]`` tuples sized for the 240×240
display (≤2 short body lines).  Exactness is intentionally traded for
readability: long values are truncated with ``…``; the raw-hex "Show data"
drill-down and the digest screens cover byte-exact verification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple

from . import abi_decode, signature_db, tokens
from .address import to_checksum_address
from .function_registry import (
    KIND_APPROVE, KIND_GENERIC, resolve,
)

MAX_UINT256 = (1 << 256) - 1
_BODY_VALUE_LEN = 40      # max chars on the value line before truncation
_MAX_ROWS = 24            # cap on parameter/message rows (avoid page blow-up)


@dataclass
class DecodedCall:
    known: bool
    selector: bytes
    name: Optional[str] = None
    signature: Optional[str] = None
    kind: str = KIND_GENERIC
    # (label, ABIType, value) for each top-level parameter
    params: List[Tuple[str, "abi_decode.ABIType", Any]] = field(default_factory=list)
    decode_error: bool = False
    # False when the name came from the unverified extended DB (not the curated
    # registry) — the UI flags these as "(unverified)".
    verified: bool = True
    # True when the selector matched MORE THAN ONE extended signature (a 4-byte
    # collision): we refuse to guess and show an ambiguity warning instead.
    ambiguous: bool = False
    candidates: List[str] = field(default_factory=list)


def decode_calldata(data: bytes, chain_id: int = None, to_address: bytes = None) -> Optional[DecodedCall]:
    """Decode calldata for display.  Returns None for empty/no-call data.

    Never raises: malformed input or an unknown selector yields a
    ``known=False`` result (→ blind-signing warning).
    """
    try:
        data = bytes(data or b"")
        if len(data) == 0:
            return None
        if len(data) < 4:
            return DecodedCall(known=False, selector=data)
        selector = data[:4]
        entry = resolve(selector)
        if entry is None:
            # Curated miss → fall back to the larger, unverified extended DB.
            return _decode_extended(selector, data[4:])
        try:
            values = abi_decode.decode_parameters(entry.arg_types, data[4:])
        except ValueError:
            # Selector matched but parameters didn't decode — still useful to
            # show the function name, but flag that params are untrusted.
            return DecodedCall(
                known=True, selector=selector, name=entry.name,
                signature=entry.signature, kind=entry.kind, decode_error=True,
            )
        names = entry.param_names or [f"arg{i}" for i in range(len(values))]
        params = []
        for i, (t, v) in enumerate(zip(entry.arg_types, values)):
            label = names[i] if i < len(names) else f"arg{i}"
            params.append((label, t, v))
        return DecodedCall(
            known=True, selector=selector, name=entry.name,
            signature=entry.signature, kind=entry.kind, params=params,
        )
    except Exception:
        # Defence in depth — decoding must never break the signing flow.
        sel = bytes(data[:4]) if data else b""
        return DecodedCall(known=False, selector=sel)


def _decode_extended(selector: bytes, params_data: bytes) -> DecodedCall:
    """Resolve via the unverified extended signature DB.

    No match → blind.  Single match → decode generically, flagged
    ``verified=False``.  Multiple matches (a 4-byte selector collision) → first
    try to break the tie by **decode-consistency**: decode each candidate against
    the actual calldata and keep only those that fit it exactly.  The 4byte
    directory is full of same-selector junk with different argument shapes, so
    usually only the real signature survives.  If exactly one survives we decode
    it (still ``verified=False``); if 0 or >1 survive we keep the honest
    ambiguity warning rather than guess.
    """
    sigs = signature_db.resolve_all(selector)
    if not sigs:
        return DecodedCall(known=False, selector=selector)
    if len(sigs) > 1:
        survivors = _consistent_candidates(sigs, params_data)
        if len(survivors) == 1:
            return _decode_known_sig(selector, survivors[0], params_data)
        return DecodedCall(
            known=True, selector=selector, ambiguous=True, verified=False,
            candidates=sigs,
        )
    return _decode_known_sig(selector, sigs[0], params_data)


def _consistent_candidates(sigs: List[str], params_data: bytes) -> List[str]:
    """Subset of candidate signatures that ABI-decode the calldata *exactly*.

    Lets the bytes themselves break a 4-byte collision without trusting the DB:
    a candidate survives only if it parses and the parameter region is fully
    consumed (``abi_decode.decode_parameters_strict``).
    """
    survivors: List[str] = []
    for sig in sigs:
        try:
            _name, types = abi_decode.parse_signature(sig)
            abi_decode.decode_parameters_strict(types, params_data)
        except ValueError:
            continue
        survivors.append(sig)
    return survivors


def _decode_known_sig(selector: bytes, sig: str, params_data: bytes) -> DecodedCall:
    """Decode a single resolved (but unverified) signature against the calldata."""
    try:
        name, types = abi_decode.parse_signature(sig)
        values = abi_decode.decode_parameters(types, params_data)
    except ValueError:
        return DecodedCall(
            known=True, selector=selector, name=sig.split("(", 1)[0],
            signature=sig, kind=KIND_GENERIC, verified=False, decode_error=True,
        )
    params = [(f"arg{i}", t, v) for i, (t, v) in enumerate(zip(types, values))]
    return DecodedCall(
        known=True, selector=selector, name=name, signature=sig,
        kind=KIND_GENERIC, verified=False, params=params,
    )


# --- value formatting -------------------------------------------------------

def _format_eth(wei: int) -> str:
    """Exact 18-decimal native-coin formatting (no float), trailing zeros trimmed."""
    try:
        wei = int(wei)
    except (TypeError, ValueError):
        return "? ETH"
    s = str(wei).rjust(19, "0")
    int_part, frac_part = s[:-18], s[-18:].rstrip("0")
    value = int_part + ("." + frac_part if frac_part else "")
    return f"{value} ETH"


def _short(s: str, n: int = _BODY_VALUE_LEN) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


def _short_addr(b: bytes) -> str:
    try:
        cs = to_checksum_address(b)
    except ValueError:
        return "0x" + bytes(b).hex()
    return f"{cs[:8]}…{cs[-4:]}"


def _format_scalar(label: str, t: "abi_decode.ABIType", val: Any, kind: str,
                   chain_id, to_address) -> str:
    b = t.base
    if b == "address":
        return _short_addr(val)
    if b == "bool":
        return "true" if val else "false"
    if b in ("bytes", "fixed_bytes"):
        return _short("0x" + bytes(val).hex())
    if b == "string":
        return _short(val)
    if b in ("uint", "int"):
        if kind == KIND_APPROVE and label in ("amount", "value") and val == MAX_UINT256:
            return "UNLIMITED"
        token = tokens.lookup_token(chain_id, to_address) if to_address else None
        if token is not None and label in ("amount", "value"):
            return _short(tokens.format_token_amount(val, token[0], token[1]))
        return _short(str(val))
    return _short(str(val))


def _emit_rows(label: str, t: "abi_decode.ABIType", val: Any, rows: List[Tuple[str, str]],
               kind: str, chain_id, to_address) -> None:
    if len(rows) >= _MAX_ROWS:
        return
    if t.base == "tuple":
        for i, (ct, cv) in enumerate(zip(t.components, val)):
            _emit_rows(f"{label}.{i}", ct, cv, rows, kind, chain_id, to_address)
        return
    if t.base == "array":
        count = len(val)
        if t.element.base == "address" and count >= 2:
            summary = f"{_short_addr(val[0])} → {_short_addr(val[-1])}"
        elif count == 0:
            summary = "(empty)"
        else:
            summary = _short(_format_scalar(label, t.element, val[0], kind, chain_id, to_address))
        rows.append((f"{label} [{count}]", summary))
        return
    rows.append((label, _format_scalar(label, t, val, kind, chain_id, to_address)))


def _rows_for_call(decoded: DecodedCall, chain_id, to_address) -> List[Tuple[str, str]]:
    rows: List[Tuple[str, str]] = []
    for label, t, v in decoded.params:
        _emit_rows(label, t, v, rows, decoded.kind, chain_id, to_address)
        if len(rows) >= _MAX_ROWS:
            rows.append(("…", "more (see raw data)"))
            break
    return rows


def render_pages(decoded: DecodedCall, chain_id: int = None,
                 to_address: bytes = None, value: int = None) -> List[Tuple[str, str]]:
    """[(title, body)] pages for a DecodedCall.

    ``value`` (native-coin wei being sent by the call) is surfaced on the
    blind-signing page when non-zero so the user still sees the single most
    safety-relevant fact — that funds are leaving — even when the function
    itself can't be named.
    """
    if decoded.ambiguous:
        # Selector collision in the unverified DB — refuse to guess a name.
        sel = "0x" + bytes(decoded.selector).hex()
        return [("Ambiguous", f"{len(decoded.candidates)} possible funcs\n{sel}")]
    if not decoded.known:
        sel = "0x" + bytes(decoded.selector).hex() if decoded.selector else "(none)"
        # Surface what IS known: the value being sent (high-signal) or, failing
        # that, a pointer to the byte-exact verification screens. The selector
        # is shown either way so the user can look it up off-device.
        second = _format_eth(value) + " sent" if value else "verify digest + data"
        return [("Blind signing", f"unknown fn {sel}\n{second}")]

    title = decoded.name or "call"
    if not decoded.verified:
        # Name came from the unverified extended DB, not the curated registry.
        title = f"{title} (unverified)"
    if decoded.decode_error:
        return [(title, "params undecodable\nverify digest + data")]

    rows = _rows_for_call(decoded, chain_id, to_address)
    if not rows:
        return [(title, "no parameters")]
    # Header (function name) stays constant across pages; the caller's screen
    # title carries the page counter, the row label distinguishes each page.
    return [(title, f"{label}\n{value}") for label, value in rows]


def pages_for_calldata(data: bytes, chain_id: int = None,
                       to_address: bytes = None, value: int = None) -> List[Tuple[str, str]]:
    """Convenience: decode + render.  [] when there is no calldata."""
    decoded = decode_calldata(data, chain_id, to_address)
    if decoded is None:
        return []
    return render_pages(decoded, chain_id, to_address, value)


# --- EIP-712 typed-data message rendering -----------------------------------

def _json_scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        # Render 20-byte hex strings as short checksummed addresses.
        s = v[2:] if v.startswith(("0x", "0X")) else None
        if s is not None and len(s) == 40:
            try:
                return _short_addr(bytes.fromhex(s))
            except ValueError:
                pass
        return _short(v)
    return _short(str(v))


def _flatten_json(prefix: str, obj: Any, rows: List[Tuple[str, str]]) -> None:
    if len(rows) >= _MAX_ROWS:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten_json(f"{prefix}.{k}" if prefix else str(k), v, rows)
            if len(rows) >= _MAX_ROWS:
                return
    elif isinstance(obj, list):
        # Recurse INTO arrays (Permit2 batches, Seaport offers/considerations,
        # CowSwap trades…) so the user sees the contents, not just "[N]".
        # Bounded by _MAX_ROWS; the caller appends a "more (see raw data)" row.
        if not obj:
            rows.append((prefix, "[]"))
            return
        for i, v in enumerate(obj):
            _flatten_json(f"{prefix}[{i}]", v, rows)
            if len(rows) >= _MAX_ROWS:
                return
    else:
        rows.append((prefix, _json_scalar(obj)))


def render_typed_data_pages(typed: dict) -> List[Tuple[str, str]]:
    """[(title, body)] pages decoding an EIP-712 typed-data payload."""
    try:
        primary = str(typed.get("primaryType", "?"))
        domain = typed.get("domain", {}) or {}
        message = typed.get("message", {}) or {}
    except AttributeError:
        return [("Typed data", "could not parse\nverify hashes")]

    pages: List[Tuple[str, str]] = []
    # Page 0: domain context (what contract / app is asking for the signature).
    dom_name = domain.get("name")
    contract = domain.get("verifyingContract")
    dom_lines = []
    if dom_name:
        dom_lines.append(_short(str(dom_name)))
    if contract:
        dom_lines.append(_json_scalar(contract))
    pages.append((f"EIP-712: {primary}", "\n".join(dom_lines) if dom_lines else primary))

    rows: List[Tuple[str, str]] = []
    _flatten_json("", message, rows)
    if len(rows) >= _MAX_ROWS:
        rows.append(("…", "more (see raw data)"))
    for label, value in rows:
        pages.append((primary, f"{label or 'message'}\n{value}"))
    return pages
