#!/usr/bin/env python3
"""Crawl the 4byte.directory function-signature API into a one-sig-per-line dump.

Build-machine tool (needs internet); the device stays air-gapped. The dump it
writes is the ``--input`` for ``scripts/build_eth_signature_index.py``.

Why a crawl: openchain.xyz has more signatures (~3.8M) but exposes only a
per-selector *lookup*, no bulk export. 4byte.directory (~1.17M signatures, WITH
real collisions — a superset of the collision-free ``ethereum-lists/4bytes`` the
current bundled index was built from) is paginated (100/page), so we follow the
``next`` cursor politely.

    python scripts/fetch_4byte_signatures.py --out corpus.txt

Resumable: re-running appends only pages after the last one written (tracked in
``<out>.cursor``). Rate-limited (``--delay``, default 0.15s) to be a good citizen.
Idempotent enough for the generator, which dedups ``(selector, signature)`` pairs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request

API = "https://www.4byte.directory/api/v1/signatures/?page=1"


def _get(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "seedsigner-sig-fetch/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", required=True, help="output dump (one signature per line)")
    p.add_argument("--delay", type=float, default=0.15, help="seconds between page requests")
    p.add_argument("--max-pages", type=int, default=0, help="stop after N pages (0 = all)")
    a = p.parse_args(argv)

    cursor_path = a.out + ".cursor"
    url = API
    if os.path.exists(cursor_path):
        with open(cursor_path, "r", encoding="utf-8") as fh:
            saved = fh.read().strip()
        if saved:
            url = saved
            print(f"resuming from {url}", file=sys.stderr)

    written = 0
    pages = 0
    mode = "a" if os.path.exists(a.out) else "w"
    with open(a.out, mode, encoding="utf-8") as out:
        while url:
            # The API hands back http:// next-links; force https.
            if url.startswith("http://"):
                url = "https://" + url[len("http://"):]
            try:
                data = _get(url)
            except Exception as exc:
                print(f"\nstopped at {url}: {exc} (re-run to resume)", file=sys.stderr)
                break
            for row in data.get("results", []):
                sig = (row.get("text_signature") or "").strip()
                if sig:
                    out.write(sig + "\n")
                    written += 1
            pages += 1
            url = data.get("next") or ""
            with open(cursor_path, "w", encoding="utf-8") as fh:
                fh.write(url)
            if pages % 50 == 0:
                out.flush()
                print(f"  pages={pages} written={written}", file=sys.stderr)
            if a.max_pages and pages >= a.max_pages:
                print(f"reached --max-pages {a.max_pages}", file=sys.stderr)
                break
            if url:
                time.sleep(a.delay)

    print(f"done: {pages} pages, {written} signatures -> {a.out}", file=sys.stderr)
    if not url:
        # Completed the full crawl — drop the cursor so a later run starts fresh.
        try:
            os.remove(cursor_path)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
