"""Extended (unverified) function-signature lookup for calldata decoding.

The curated table in ``function_registry.py`` is small and trusted (we control
it, selectors are computed from canonical signatures, friendly parameter names).
This module adds a *much larger but unverified* layer so more function calls can
be given a human-readable name — the same idea as the online 4byte directory,
but bounded and kept offline.

Two sources, both lazy (read on first use, never at import) and RAM-bounded:

1. **Baseline** — ``resources/eth_signatures.txt`` shipped inside the firmware
   image (part of the reproducible build, integrity-protected). Hand-vetted.
2. **microSD override** — ``<microSD>/eth_signatures.txt`` if present. This is
   where a user can drop a large dump (e.g. an export of the 4byte directory)
   to extend coverage without rebuilding firmware.

**Trust model.** Entries here are treated as *unverified hints*: the decoder
flags them, the ERC-8213 / EIP-712 digests stay the source of truth, and a
4-byte selector that maps to **more than one** signature (a collision — which
the 4byte directory is full of, including deliberately-poisoned entries) is
reported as **ambiguous** rather than guessed. Curated selectors are skipped
here so the trusted name always wins.

File format: one canonical signature per line (e.g. ``supply(address,uint256,
address,uint16)``); ``#`` comments and blank lines ignored. Selectors are
computed via keccak, so a typo just yields a different selector — never a
wrong-but-confident decode.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional

from .function_registry import function_selector, resolve as _resolve_curated

logger = logging.getLogger(__name__)

# RAM backstop: a hostile/huge microSD dump is truncated here instead of OOMing
# the Pi Zero. Only the (deduplicated) signature strings are held in memory;
# ABI types are parsed on demand for the single selector actually being decoded.
MAX_DB_ENTRIES = 50_000

_BASELINE_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "resources", "eth_signatures.txt")
)

# selector(4 bytes) -> list of distinct canonical signatures
_db: Optional[Dict[bytes, List[str]]] = None
# Test hook: when set, these paths replace the baseline + microSD sources.
_TEST_PATHS: Optional[List[str]] = None


def _microsd_path() -> Optional[str]:
    """Path to an optional user-supplied signature dump on the microSD."""
    try:
        from seedsigner.hardware.microsd import MicroSD
        p = MicroSD.get_microsd_dir() / "eth_signatures.txt"
        return str(p) if p.exists() else None
    except Exception:
        return None


def _source_paths() -> List[str]:
    if _TEST_PATHS is not None:
        return list(_TEST_PATHS)
    paths = [_BASELINE_PATH]
    micro = _microsd_path()
    if micro:
        paths.append(micro)
    return paths


def _looks_like_signature(line: str) -> bool:
    # Cheap structural check only — avoids a full ABI parse of every line so a
    # large dump loads fast. The real parse happens at decode time.
    if " " in line or not line.endswith(")"):
        return False
    name, sep, _ = line.partition("(")
    return bool(sep) and bool(name) and name[0].isalpha()


def _load() -> None:
    global _db
    db: Dict[bytes, List[str]] = {}
    seen: set = set()
    count = 0
    truncated = False
    for path in _source_paths():
        if truncated:
            break
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for raw in fh:
                    if count >= MAX_DB_ENTRIES:
                        truncated = True
                        logger.warning(
                            "eth signature DB capped at %d entries; rest of %s ignored",
                            MAX_DB_ENTRIES, path,
                        )
                        break
                    sig = raw.strip()
                    if not sig or sig.startswith("#") or not _looks_like_signature(sig):
                        continue
                    if sig in seen:
                        continue
                    seen.add(sig)
                    try:
                        sel = function_selector(sig)
                    except Exception:
                        continue
                    # A trusted curated entry always wins — don't shadow it and
                    # don't let it count toward a collision.
                    if _resolve_curated(sel) is not None:
                        continue
                    db.setdefault(sel, []).append(sig)
                    count += 1
        except OSError:
            continue
    _db = db


def resolve_extended(selector: bytes) -> List[str]:
    """Return the distinct canonical signatures for a selector (possibly >1).

    Empty list if the selector is unknown to the extended DB. More than one
    entry means a selector collision → the caller must treat it as *ambiguous*,
    not pick one.
    """
    if _db is None:
        _load()
    return list(_db.get(bytes(selector), []))


def _reset() -> None:
    """Drop the cached DB (test helper)."""
    global _db
    _db = None
