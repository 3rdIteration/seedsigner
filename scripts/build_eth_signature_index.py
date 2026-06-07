#!/usr/bin/env python3
"""Build the bundled binary selector index for offline ETH calldata decoding.

This runs on the **build machine**, never on the air-gapped device. It reads a
plain-text dump of canonical function signatures (one per line — e.g. an export
of the 4byte.directory / openchain.xyz / ethereum-lists/4bytes datasets) and
emits the two memory-mappable resource files the firmware binary-searches at
runtime:

    src/seedsigner/resources/eth_sig_index.bin   (sorted fixed-width records)
    src/seedsigner/resources/eth_sig_blob.bin    (concatenated signature strings)

Self-verifying: every 4-byte selector is computed with the SAME
``function_registry.function_selector`` (keccak256) the firmware uses, so a
typo'd input line just yields a different selector — never a wrong-but-confident
decode. Curated selectors are excluded (the trusted name always wins). Output is
deterministic: the same input produces byte-identical files.

Usage:
    python scripts/build_eth_signature_index.py \
        --input signatures.txt \
        --out-index src/seedsigner/resources/eth_sig_index.bin \
        --out-blob  src/seedsigner/resources/eth_sig_blob.bin \
        [--keep-curated] [--max-sig-len 256] [--verify]

Where to get ``signatures.txt`` (build machine only — the firmware ships only the
generated .bin):
  * openchain.xyz signature-database export, or
  * the ethereum-lists/4bytes repo (flatten ``signatures/`` to one-sig-per-line), or
  * a 4byte.directory CSV/JSON export reduced to the ``text_signature`` column.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import zlib

_SRC = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from seedsigner.helpers.ethereum.function_registry import (  # noqa: E402
    function_selector,
    resolve as resolve_curated,
)
from seedsigner.helpers.ethereum.signature_db import (  # noqa: E402
    _BLOB_HEADER_SIZE,
    _BLOB_MAGIC,
    _INDEX_MAGIC,
    _INDEX_RECORD_SIZE,
    _looks_like_signature,
)


def _accept(sig: str, max_sig_len: int) -> bool:
    # Cheap structural filter, matching the runtime text loader. We do NOT
    # require a full ABI parse: the runtime still shows the function *name* even
    # when parameters are undecodable, so dropping such rows would needlessly
    # lose coverage. ASCII-only so blob bytes round-trip exactly.
    if not sig or len(sig) > max_sig_len:
        return False
    if not sig.isascii():
        return False
    return _looks_like_signature(sig)


def build(input_path, out_index, out_blob, *, exclude_curated=True,
          max_sig_len=256, verbose=True):
    """Read a one-signature-per-line dump and write the index + blob files.

    Returns (record_count, distinct_strings, index_bytes, blob_bytes).
    """
    pairs = set()           # (selector, signature) — dedup
    n_lines = n_skipped = n_curated = 0
    with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            sig = raw.strip()
            if not sig or sig.startswith("#"):
                continue
            n_lines += 1
            if not _accept(sig, max_sig_len):
                n_skipped += 1
                continue
            try:
                sel = function_selector(sig)
            except Exception:
                n_skipped += 1
                continue
            if exclude_curated and resolve_curated(sel) is not None:
                n_curated += 1
                continue
            pairs.add((sel, sig))

    # Sort by (selector bytes, signature) so collisions are contiguous and the
    # output is deterministic.
    records = sorted(pairs, key=lambda p: (p[0], p[1]))

    # Blob: dedup distinct strings, assign body offsets.
    body = bytearray()
    pos = {}
    for _sel, sig in records:
        if sig not in pos:
            pos[sig] = len(body)
            body += sig.encode("ascii")
    blob_body = bytes(body)
    blob_header = struct.pack("<4sHHII", _BLOB_MAGIC, 1, 0, len(pos), 0)
    blob_bytes = blob_header + blob_body
    blob_crc = zlib.crc32(blob_bytes) & 0xFFFFFFFF

    # Index: fixed-width sorted records. sig_offset is ABSOLUTE into the blob
    # file (i.e. includes the 16-byte blob header).
    rec = bytearray()
    for sel, sig in records:
        off = _BLOB_HEADER_SIZE + pos[sig]
        ln = len(sig.encode("ascii"))
        rec += sel + struct.pack("<II", off, ln)
    index_header = struct.pack(
        "<4sHHIII12x", _INDEX_MAGIC, 1, _INDEX_RECORD_SIZE,
        len(records), len(blob_bytes), blob_crc,
    )
    index_bytes = index_header + bytes(rec)

    _write_atomic(out_blob, blob_bytes)
    _write_atomic(out_index, index_bytes)

    if verbose:
        print(f"input lines (non-comment): {n_lines}")
        print(f"  skipped (malformed):     {n_skipped}")
        print(f"  excluded (curated):      {n_curated}")
        print(f"records:                   {len(records)}")
        print(f"distinct signatures:       {len(pos)}")
        print(f"index file:                {len(index_bytes):,} bytes -> {out_index}")
        print(f"blob file:                 {len(blob_bytes):,} bytes -> {out_blob}")
    return len(records), len(pos), len(index_bytes), len(blob_bytes)


def _write_atomic(path: str, data: bytes) -> None:
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def _verify(out_index, out_blob, input_path, max_sig_len):
    """Round-trip a sample of input selectors back through the runtime loader."""
    from seedsigner.helpers.ethereum import signature_db
    signature_db._reset()
    signature_db._TEST_INDEX_PATHS = (out_index, out_blob)
    try:
        checked = ok = 0
        with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
            for i, raw in enumerate(fh):
                sig = raw.strip()
                if not sig or sig.startswith("#") or not _accept(sig, max_sig_len):
                    continue
                sel = function_selector(sig)
                if resolve_curated(sel) is not None:
                    continue
                if i % 997 != 0:        # sample, not the whole file
                    continue
                checked += 1
                if sig in signature_db.resolve_bundled(sel):
                    ok += 1
        print(f"verify: {ok}/{checked} sampled selectors round-tripped")
        return ok == checked
    finally:
        signature_db._TEST_INDEX_PATHS = None
        signature_db._reset()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--input", required=True, help="one canonical signature per line")
    p.add_argument("--out-index", required=True)
    p.add_argument("--out-blob", required=True)
    p.add_argument("--keep-curated", action="store_true",
                   help="do NOT exclude selectors already in the curated registry")
    p.add_argument("--max-sig-len", type=int, default=256)
    p.add_argument("--verify", action="store_true",
                   help="round-trip a sample through the runtime loader after writing")
    a = p.parse_args(argv)

    build(a.input, a.out_index, a.out_blob,
          exclude_curated=not a.keep_curated, max_sig_len=a.max_sig_len)
    if a.verify:
        if not _verify(a.out_index, a.out_blob, a.input, a.max_sig_len):
            print("VERIFY FAILED", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
