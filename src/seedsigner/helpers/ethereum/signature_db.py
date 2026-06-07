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
import mmap
import os
import struct
import zlib
from typing import Dict, List, Optional, Tuple

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


# ---------------------------------------------------------------------------
# Bundled binary selector index (full-4byte-scale coverage, on-disk, no RAM dict)
#
# A pre-computed, sorted, memory-mapped index lets us ship the entire 4byte
# directory (~1M+ signatures) without loading it into a Python dict (which would
# OOM the 512 MB Pi Zero) and without computing keccak for every entry at runtime
# (all selectors are precomputed at build time by ``scripts/build_eth_signature_index.py``).
#
# A decode runs ONCE per transaction and only needs O(log N) word reads over the
# mmap (~21 reads for 1.3M records) plus a short adjacent-record scan to gather
# selector collisions. Resident memory is just the handful of pages actually
# touched, not the whole file.
#
# File format (both little-endian) — kept in lock-step with the generator:
#   eth_sig_index.bin
#     header (32B): magic b"ESI1" | version:u16=1 | record_size:u16=12 |
#                   record_count:u32 | blob_size:u32 | blob_crc32:u32 | reserved(12B)
#     records (record_count * 12B), sorted by (selector, sig_offset):
#                   selector:4 raw bytes | sig_offset:u32 (absolute into blob) | sig_len:u32
#   eth_sig_blob.bin
#     header (16B): magic b"ESB1" | version:u16=1 | reserved:u16 | string_count:u32 | reserved:u32
#     body: concatenated ASCII signature strings (referenced by offset+len)
# ---------------------------------------------------------------------------
_INDEX_MAGIC = b"ESI1"
_BLOB_MAGIC = b"ESB1"
_INDEX_HEADER_SIZE = 32
_BLOB_HEADER_SIZE = 16
_INDEX_RECORD_SIZE = 12

# 4byte has deliberately-poisoned selectors that map to hundreds of bogus
# signatures. We only ever need to know "is this >1" (=> ambiguous, never
# guessed), so cap how many candidates we gather per selector.
_MAX_CANDIDATES = 32

# Optionally CRC32 the blob on first open to catch silent corruption. OFF by
# default: the bundled files are integrity-protected by the reproducible firmware
# build (read-only partition), and verifying would force reading the ENTIRE blob
# on the first decode (a perceptible one-time lag on the Pi Zero's slow SD). The
# cheap magic/version/size checks below still reject gross corruption without a
# full read; binary search then touches only a handful of pages. The generator
# always writes the CRC into the header, so it remains available for tooling.
_VERIFY_BLOB_CRC = False

_INDEX_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "resources", "eth_sig_index.bin")
)
_BLOB_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "resources", "eth_sig_blob.bin")
)

# Lazily-opened, validated index state. ``_index_state`` is the sentinel:
# None=not tried, "ok", "absent" (no files), "bad" (corrupt/unsupported).
_index_state: Optional[str] = None
_index_mm: Optional[mmap.mmap] = None
_blob_mm: Optional[mmap.mmap] = None
_index_fh = None
_blob_fh = None
_index_count = 0
# Test hook: when set, (index_path, blob_path) replace the bundled resource pair.
_TEST_INDEX_PATHS: Optional[Tuple[str, str]] = None


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


def _index_paths() -> Tuple[str, str]:
    if _TEST_INDEX_PATHS is not None:
        return _TEST_INDEX_PATHS
    return (_INDEX_PATH, _BLOB_PATH)


def _open_index() -> None:
    """Open + validate the bundled binary index once. Never raises.

    On any problem (missing files, bad magic/version, size mismatch, CRC
    mismatch, mmap failure) we record ``_index_state`` as ``"absent"``/``"bad"``
    and leave the mmaps as ``None`` so ``resolve_bundled`` returns ``[]`` and the
    signing flow proceeds blind rather than erroring.
    """
    global _index_state, _index_mm, _blob_mm, _index_fh, _blob_fh, _index_count
    idx_path, blob_path = _index_paths()
    try:
        idx_fh = open(idx_path, "rb")
    except OSError:
        _index_state = "absent"
        return
    blob_fh = None
    try:
        try:
            blob_fh = open(blob_path, "rb")
        except OSError:
            idx_fh.close()
            _index_state = "absent"
            return

        header = idx_fh.read(_INDEX_HEADER_SIZE)
        if len(header) != _INDEX_HEADER_SIZE or header[:4] != _INDEX_MAGIC:
            raise ValueError("bad index header")
        version, record_size = struct.unpack_from("<HH", header, 4)
        record_count, blob_size, blob_crc = struct.unpack_from("<III", header, 8)
        if version != 1 or record_size != _INDEX_RECORD_SIZE:
            raise ValueError("unsupported index version")
        idx_size = os.fstat(idx_fh.fileno()).st_size
        if idx_size != _INDEX_HEADER_SIZE + record_count * _INDEX_RECORD_SIZE:
            raise ValueError("index size mismatch")

        bheader = blob_fh.read(_BLOB_HEADER_SIZE)
        if len(bheader) != _BLOB_HEADER_SIZE or bheader[:4] != _BLOB_MAGIC:
            raise ValueError("bad blob header")
        if os.fstat(blob_fh.fileno()).st_size != blob_size:
            raise ValueError("blob size mismatch")

        idx_mm = mmap.mmap(idx_fh.fileno(), 0, access=mmap.ACCESS_READ)
        blob_mm = mmap.mmap(blob_fh.fileno(), 0, access=mmap.ACCESS_READ)
        if _VERIFY_BLOB_CRC and blob_crc != 0:
            if (zlib.crc32(blob_mm) & 0xFFFFFFFF) != blob_crc:
                idx_mm.close()
                blob_mm.close()
                raise ValueError("blob crc mismatch")

        _index_mm = idx_mm
        _blob_mm = blob_mm
        _index_fh = idx_fh
        _blob_fh = blob_fh
        _index_count = record_count
        _index_state = "ok"
    except Exception:
        try:
            idx_fh.close()
        except Exception:
            pass
        try:
            if blob_fh is not None:
                blob_fh.close()
        except Exception:
            pass
        _index_mm = _blob_mm = _index_fh = _blob_fh = None
        _index_count = 0
        _index_state = "bad"


def _record_selector(i: int) -> bytes:
    base = _INDEX_HEADER_SIZE + i * _INDEX_RECORD_SIZE
    return _index_mm[base:base + 4]


def _record_payload(i: int) -> Tuple[int, int]:
    base = _INDEX_HEADER_SIZE + i * _INDEX_RECORD_SIZE + 4
    return struct.unpack_from("<II", _index_mm, base)


def resolve_bundled(selector: bytes) -> List[str]:
    """Binary-search the bundled on-disk index for a 4-byte selector.

    Returns the distinct canonical signatures sharing this selector (0, 1, or
    many — >1 means a collision the caller must treat as *ambiguous*). Never
    raises: a missing/corrupt index or any error yields ``[]``. No full in-RAM
    load — O(log N) word reads over an mmap plus a short adjacent-record scan.
    """
    if _index_state is None:
        _open_index()
    if _index_mm is None or _blob_mm is None:
        return []
    target = bytes(selector)
    if len(target) != 4:
        return []
    try:
        # Leftmost record whose selector >= target.
        lo, hi = 0, _index_count
        while lo < hi:
            mid = (lo + hi) >> 1
            if _record_selector(mid) < target:
                lo = mid + 1
            else:
                hi = mid
        out: List[str] = []
        blob_len = len(_blob_mm)
        i = lo
        while i < _index_count and _record_selector(i) == target:
            off, ln = _record_payload(i)
            if off >= 0 and ln >= 0 and off + ln <= blob_len:
                out.append(bytes(_blob_mm[off:off + ln]).decode("ascii", "replace"))
            i += 1
            if len(out) >= _MAX_CANDIDATES:
                break
        return out
    except Exception:
        return []


def resolve_all(selector: bytes) -> List[str]:
    """Bundled binary index ∪ text DB (baseline + microSD), deduplicated.

    This is the entry point the calldata decoder uses. Curated-wins is enforced
    upstream (the decoder consults the curated registry first), and the generator
    excludes curated selectors from the binary index, so curated names never get
    shadowed here. A union with >1 distinct signature is still a collision →
    the decoder shows the ambiguity warning rather than guessing.
    """
    sel = bytes(selector)
    out = list(resolve_bundled(sel))
    seen = set(out)
    for sig in resolve_extended(sel):
        if sig not in seen:
            seen.add(sig)
            out.append(sig)
    return out


def _reset() -> None:
    """Drop the cached text DB and binary index (test helper)."""
    global _db, _index_state, _index_mm, _blob_mm, _index_fh, _blob_fh, _index_count
    _db = None
    for obj in (_index_mm, _blob_mm, _index_fh, _blob_fh):
        try:
            if obj is not None:
                obj.close()
        except Exception:
            pass
    _index_mm = _blob_mm = _index_fh = _blob_fh = None
    _index_count = 0
    _index_state = None
