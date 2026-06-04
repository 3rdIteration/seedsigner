"""Minimal, hardened ABI decoder for *display* of transaction calldata.

This decodes the parameters of a known function call so the user can see what a
transaction does (a transfer, an approve, a swap, …) before signing.  It is a
**display-only** aid: the bytes that get signed never depend on what this module
returns, and the ERC-8213 calldata digest remains the source of truth.

Calldata is fully untrusted input, so every length / offset read here is
bounds-checked, element counts are capped, and a global step budget bounds total
work regardless of how the encoding aliases its offsets.  Any inconsistency
raises ``ValueError``; callers must treat that as "could not decode" and fall
back to a blind-signing warning + raw hex.  The decoder never allocates a buffer
sized by an attacker-controlled length word.

Supported types: ``address``, ``bool``, ``uint<N>``/``int<N>``, ``bytes``,
``string``, ``bytes<N>`` (1..32), fixed/dynamic arrays ``T[]`` / ``T[k]``, and
tuples ``(...)``.  Anything else raises ``ValueError`` (→ fall back).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


# --- defensive limits -------------------------------------------------------
# A single dynamic-array element occupies at least one 32-byte head word, so a
# count larger than data/32 is impossible; this cap is an additional ceiling so
# even a small-but-pathological payload can't spin the element loop too long.
MAX_ARRAY_ELEMENTS = 4096
# Ceiling on a single bytes/string field (the per-call ``need()`` bound against
# the real data length is the true limit; this is belt-and-suspenders).
MAX_BYTES_LEN = 1 << 20
# Total decode-step budget.  Each decoded component/element costs one tick, so
# offset aliasing (many heads pointing at the same tail) can't blow up work.
MAX_STEPS = 200_000


@dataclass
class ABIType:
    """Parsed ABI type node.

    base ∈ {uint, int, address, bool, bytes, string, fixed_bytes, array, tuple}
    size: bit-width for uint/int, N for fixed_bytes, array length (None=dynamic)
    element: element type for arrays; components: member types for tuples.
    """

    base: str
    size: Optional[int] = None
    element: Optional["ABIType"] = None
    components: List["ABIType"] = field(default_factory=list)


# --- signature / type parsing ----------------------------------------------

def _split_top(s: str) -> List[str]:
    """Split a parameter list on top-level commas, respecting nested parens."""
    parts: List[str] = []
    depth = 0
    cur: List[str] = []
    for ch in s:
        if ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def _parse_array_suffix(suffix: str) -> List[Optional[int]]:
    """Parse a trailing ``[..][..]`` suffix into dims in appearance order."""
    dims: List[Optional[int]] = []
    s = suffix.strip()
    i = 0
    while i < len(s):
        if s[i] != "[":
            raise ValueError(f"bad array suffix: {suffix!r}")
        j = s.find("]", i)
        if j < 0:
            raise ValueError(f"unbalanced array suffix: {suffix!r}")
        inner = s[i + 1:j].strip()
        dims.append(int(inner) if inner else None)  # int() raises on garbage
        i = j + 1
    return dims


def _validate_int_bits(n: int) -> None:
    if not (8 <= n <= 256) or n % 8 != 0:
        raise ValueError(f"invalid integer width: {n}")


def _parse_base(core: str) -> ABIType:
    core = core.strip()
    if core == "address":
        return ABIType("address")
    if core == "bool":
        return ABIType("bool")
    if core == "string":
        return ABIType("string")
    if core == "bytes":
        return ABIType("bytes")
    if core.startswith("bytes"):
        n = int(core[5:])
        if not 1 <= n <= 32:
            raise ValueError(f"unsupported {core}")
        return ABIType("fixed_bytes", size=n)
    if core.startswith("uint"):
        n = int(core[4:]) if len(core) > 4 else 256
        _validate_int_bits(n)
        return ABIType("uint", size=n)
    if core.startswith("int"):
        n = int(core[3:]) if len(core) > 3 else 256
        _validate_int_bits(n)
        return ABIType("int", size=n)
    raise ValueError(f"unsupported type: {core!r}")


def parse_type(s: str) -> ABIType:
    s = s.strip()
    if not s:
        raise ValueError("empty type")
    if s[0] == "(":
        depth = 0
        end = -1
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end < 0:
            raise ValueError(f"unbalanced tuple: {s!r}")
        inner = s[1:end].strip()
        suffix = s[end + 1:]
        comps = [parse_type(p) for p in _split_top(inner)] if inner else []
        node = ABIType("tuple", components=comps)
    else:
        j = 0
        while j < len(s) and s[j] != "[":
            j += 1
        node = _parse_base(s[:j])
        suffix = s[j:]
    # Fold array dims in appearance order; the LAST dim is the outermost
    # (Solidity ``uint[2][3]`` == 3 arrays of 2).
    for dim in _parse_array_suffix(suffix):
        node = ABIType("array", size=dim, element=node)
    return node


def parse_signature(sig: str):
    """``"transfer(address,uint256)"`` -> ("transfer", [ABIType, ABIType])."""
    sig = sig.strip()
    i = sig.find("(")
    if i < 0:
        raise ValueError(f"not a function signature: {sig!r}")
    name = sig[:i]
    tup = parse_type(sig[i:])
    if tup.base != "tuple":
        raise ValueError(f"bad signature params: {sig!r}")
    return name, tup.components


def type_str(t: ABIType) -> str:
    """Canonical type string (for selector hashing / display)."""
    if t.base == "tuple":
        return "(" + ",".join(type_str(c) for c in t.components) + ")"
    if t.base == "array":
        inner = type_str(t.element)
        return f"{inner}[{t.size if t.size is not None else ''}]"
    if t.base == "fixed_bytes":
        return f"bytes{t.size}"
    if t.base in ("uint", "int"):
        return f"{t.base}{t.size}"
    return t.base


# --- decoding ---------------------------------------------------------------

@dataclass
class _Ctx:
    data: bytes
    steps: int = 0

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise ValueError("decode step budget exceeded")

    def need(self, end: int) -> None:
        if end > len(self.data):
            raise ValueError("calldata too short")


def _read_word(ctx: _Ctx, pos: int) -> bytes:
    if pos < 0:
        raise ValueError("negative offset")
    ctx.need(pos + 32)
    return ctx.data[pos:pos + 32]


def _read_uint_word(ctx: _Ctx, pos: int) -> int:
    return int.from_bytes(_read_word(ctx, pos), "big")


def _is_dynamic(t: ABIType) -> bool:
    if t.base in ("string", "bytes"):
        return True
    if t.base == "array":
        return t.size is None or _is_dynamic(t.element)
    if t.base == "tuple":
        return any(_is_dynamic(c) for c in t.components)
    return False


def _static_size(t: ABIType) -> int:
    """Head size (bytes) of a *static* type."""
    if t.base == "array" and t.size is not None:
        return t.size * _static_size(t.element)
    if t.base == "tuple":
        return sum(_static_size(c) for c in t.components)
    return 32


def _decode_components(types: List[ABIType], ctx: _Ctx, base: int) -> list:
    """Head/tail decode of a sequence of types whose region starts at ``base``.

    Dynamic members store a 32-byte offset (relative to ``base``) in the head;
    static members are encoded inline.
    """
    values = []
    head = base
    for t in types:
        ctx.tick()
        if _is_dynamic(t):
            rel = _read_uint_word(ctx, head)
            pos = base + rel
            if rel < 0 or pos > len(ctx.data):
                raise ValueError("dynamic offset out of range")
            values.append(_decode_single(t, ctx, pos))
            head += 32
        else:
            values.append(_decode_single(t, ctx, head))
            head += _static_size(t)
    return values


def _decode_single(t: ABIType, ctx: _Ctx, pos: int) -> Any:
    """Decode one value whose encoding begins at absolute offset ``pos``."""
    b = t.base
    if b == "uint":
        return _read_uint_word(ctx, pos)
    if b == "int":
        v = _read_uint_word(ctx, pos)
        return v - (1 << 256) if v >= (1 << 255) else v
    if b == "bool":
        return _read_uint_word(ctx, pos) != 0
    if b == "address":
        return _read_word(ctx, pos)[12:]  # last 20 bytes
    if b == "fixed_bytes":
        return _read_word(ctx, pos)[:t.size]
    if b in ("bytes", "string"):
        length = _read_uint_word(ctx, pos)
        if length > MAX_BYTES_LEN:
            raise ValueError("bytes/string field too large")
        start = pos + 32
        ctx.need(start + length)
        raw = ctx.data[start:start + length]
        return raw.decode("utf-8", "replace") if b == "string" else raw
    if b == "array":
        if t.size is None:
            count = _read_uint_word(ctx, pos)
            region = pos + 32
        else:
            count = t.size
            region = pos
        if count > MAX_ARRAY_ELEMENTS:
            raise ValueError("array too large")
        # Each element contributes >=32 bytes to the head region: a larger
        # count cannot physically fit, so reject before iterating.
        if count > 0 and count > (len(ctx.data) - region) // 32:
            raise ValueError("array count exceeds available data")
        return _decode_components([t.element] * count, ctx, region)
    if b == "tuple":
        return tuple(_decode_components(t.components, ctx, pos))
    raise ValueError(f"cannot decode type {b!r}")


def decode_parameters(types: List[ABIType], data: bytes) -> list:
    """Decode an ABI-encoded parameter region (no 4-byte selector).

    Raises ``ValueError`` on any malformed / out-of-bounds input.
    """
    ctx = _Ctx(data=bytes(data))
    return _decode_components(types, ctx, 0)
