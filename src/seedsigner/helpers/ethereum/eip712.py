from __future__ import annotations

from typing import Any, Dict, List, Set

from .keccak import keccak256


def _strip_array(t: str) -> str:
    i = t.find("[")
    return t[:i] if i >= 0 else t


def _find_dependencies(types: Dict[str, List[Dict[str, str]]], primary: str, found: Set[str]) -> Set[str]:
    if primary in found or primary not in types:
        return found
    found.add(primary)
    for member in types[primary]:
        base = _strip_array(member["type"])
        if base in types:
            _find_dependencies(types, base, found)
    return found


def encode_type(types: Dict[str, List[Dict[str, str]]], primary: str) -> bytes:
    deps = _find_dependencies(types, primary, set())
    deps.discard(primary)
    sorted_deps = [primary] + sorted(deps)
    parts: List[str] = []
    for name in sorted_deps:
        members = types[name]
        body = ",".join(f"{m['type']} {m['name']}" for m in members)
        parts.append(f"{name}({body})")
    return "".join(parts).encode("utf-8")


def type_hash(types: Dict[str, List[Dict[str, str]]], primary: str) -> bytes:
    return keccak256(encode_type(types, primary))


def _to_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        if value.startswith(("0x", "0X")):
            return bytes.fromhex(value[2:])
        return value.encode("utf-8")
    raise TypeError(f"cannot coerce {type(value).__name__} to bytes")


def _encode_atomic(value: Any, t: str) -> bytes:
    if t == "string":
        if not isinstance(value, str):
            raise TypeError("string field requires str value")
        return keccak256(value.encode("utf-8"))
    if t == "bytes":
        return keccak256(_to_bytes(value))
    if t.startswith("bytes"):
        n = int(t[5:])
        if not 1 <= n <= 32:
            raise ValueError(f"unsupported {t}")
        v = _to_bytes(value)
        if len(v) != n:
            raise ValueError(f"{t} must be {n} bytes (got {len(v)})")
        return v + b"\x00" * (32 - n)
    if t == "address":
        if isinstance(value, str):
            v = bytes.fromhex(value[2:] if value.startswith(("0x", "0X")) else value)
        else:
            v = bytes(value)
        if len(v) != 20:
            raise ValueError("address must be 20 bytes")
        return b"\x00" * 12 + v
    if t == "bool":
        return (1 if value else 0).to_bytes(32, "big")
    if t.startswith("uint"):
        n = int(t[4:]) if len(t) > 4 else 256
        v = int(value, 16) if isinstance(value, str) and value.startswith(("0x", "0X")) else int(value)
        if v < 0 or v >= 1 << n:
            raise ValueError(f"{t} out of range")
        return v.to_bytes(32, "big")
    if t.startswith("int"):
        n = int(t[3:]) if len(t) > 3 else 256
        v = int(value, 16) if isinstance(value, str) and value.startswith(("0x", "0X")) else int(value)
        if v < -(1 << (n - 1)) or v >= 1 << (n - 1):
            raise ValueError(f"{t} out of range")
        if v < 0:
            v += 1 << 256
        return v.to_bytes(32, "big")
    raise ValueError(f"unsupported atomic type: {t}")


def encode_data(types: Dict[str, List[Dict[str, str]]], primary: str, data: Dict[str, Any]) -> bytes:
    out: List[bytes] = [type_hash(types, primary)]
    for member in types[primary]:
        out.append(_encode_field(types, member["type"], data[member["name"]]))
    return b"".join(out)


def _encode_field(types: Dict[str, List[Dict[str, str]]], t: str, value: Any) -> bytes:
    if t in types:
        return keccak256(encode_data(types, t, value))
    if t.endswith("]"):
        base = _strip_array(t)
        encoded = b"".join(_encode_field(types, base, v) for v in value)
        return keccak256(encoded)
    return _encode_atomic(value, t)


def hash_struct(types: Dict[str, List[Dict[str, str]]], primary: str, data: Dict[str, Any]) -> bytes:
    return keccak256(encode_data(types, primary, data))


def domain_separator(typed_data: Dict[str, Any]) -> bytes:
    return hash_struct(typed_data["types"], "EIP712Domain", typed_data["domain"])


def message_hash(typed_data: Dict[str, Any]) -> bytes:
    return hash_struct(
        typed_data["types"], typed_data["primaryType"], typed_data["message"]
    )


def signing_hash(typed_data: Dict[str, Any]) -> bytes:
    return keccak256(
        b"\x19\x01" + domain_separator(typed_data) + message_hash(typed_data)
    )
