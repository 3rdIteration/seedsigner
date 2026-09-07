#!/usr/bin/env python3
"""
Refresh src/seedsigner/resources/microsd-known-checksums.json.

The device's "Verify MicroSD" tool hashes the first 26 MiB of the raw card
(dd bs=1M count=26) and looks the digest up in that file. This script walks the
release assets of the repos below, fetches the first 26 MiB of every matching
image via an HTTP Range request, zero-pads short images to exactly 26 MiB (the
in-app flash flow zeroes the first 26 MiB of the card before dd, so a card
flashed with a <26 MiB image reads back as image + zero padding), and records
sha256 of those bytes.

Notes:
  * The hash is deliberately NOT the full-file sha256 from the release's
    .sha256.txt file. That only ever matched by accident, when the image
    happened to be exactly 26 MiB; images larger (0.8.7 = 50 MiB) or smaller
    than 26 MiB produce a different digest on-device.
  * Existing entries are never re-downloaded or modified: assets are tracked by
    repo+tag+asset name. Entries whose source_repo is "manual" (e.g. the
    zero-wiped-card marker) are always preserved.
  * On hash collisions between distinct assets, the existing entry wins.

Run manually with `python .github/scripts/update_microsd_checksums.py`, or let
.github/workflows/update-microsd-checksums.yml run it on a schedule and open a
PR. Set GITHUB_TOKEN to raise the API rate limit (optional).
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import sys
import urllib.request
from datetime import date, timezone, datetime

REPOS = [
    "SeedSigner/seedsigner",        # official images: seedsigner_os.X.Y.Z.<platform>.img
    "3rdIteration/seedsigner",      # fork builds: smartcard variants etc.
    "3rdIteration/seedsigner-os",
]
ASSET_PATTERN = re.compile(r"^seedsigner_os\..*\.img$")

# Must match the device-side read in ToolsMicroSDVerifyView (dd bs=1M count=26).
READ_BYTES = 26 * 1024 * 1024

# Smaller assets are not plausible OS images; treat as a bad upload.
MIN_ASSET_BYTES = 4 * 1024 * 1024

DEFAULT_OUT = (
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    + "/src/seedsigner/resources/microsd-known-checksums.json"
)


def _open(url, byte_range=None):
    headers = {
        "User-Agent": "seedsigner-checksum-updater",
        "Accept": "application/vnd.github+json",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if byte_range:
        headers["Range"] = byte_range
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers))


def iter_release_assets(repos):
    """Yield dicts: repo, tag, name, url for every matching image asset."""
    for repo in repos:
        page = 1
        while True:
            with _open(f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}") as r:
                releases = json.load(r)
            if not releases:
                break
            for rel in releases:
                for asset in rel.get("assets", []):
                    if ASSET_PATTERN.match(asset["name"]):
                        yield {
                            "repo": repo,
                            "tag": rel["tag_name"],
                            "name": asset["name"],
                            "url": asset["browser_download_url"],
                        }
            page += 1


def hash_first_26mib(url):
    """sha256 of the asset's first 26 MiB, zero-padded to exactly 26 MiB."""
    with _open(url, byte_range=f"bytes=0-{READ_BYTES - 1}") as r:
        content_range = r.headers.get("Content-Range") or ""
        total = None
        if "/" in content_range:
            tail = content_range.rsplit("/", 1)[1]
            if tail.isdigit():
                total = int(tail)
        elif (r.headers.get("Content-Length") or "").isdigit():
            total = int(r.headers["Content-Length"])

        chunks, size = [], 0
        while size < READ_BYTES:
            chunk = r.read(min(1024 * 1024, READ_BYTES - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)

    if total is not None and total < MIN_ASSET_BYTES:
        raise ValueError(f"implausibly small asset ({total} bytes)")
    expected = min(total, READ_BYTES) if total is not None else size
    if size != expected:
        raise ValueError(f"short read: got {size}, expected {expected}")

    data = b"".join(chunks)
    if len(data) < READ_BYTES:
        data += b"\x00" * (READ_BYTES - len(data))
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=DEFAULT_OUT, help="path to the checksums json")
    parser.add_argument("--workers", type=int, default=8, help="parallel downloads")
    parser.add_argument("--repos", nargs="+", default=REPOS, help="github repos to scan")
    args = parser.parse_args()

    data = {"updated": None, "images": {}}
    if os.path.exists(args.out):
        with open(args.out, encoding="utf-8") as fh:
            loaded = json.load(fh)
        if isinstance(loaded.get("images"), dict):
            data["images"] = loaded["images"]

    seen_assets = {
        (meta.get("source_repo"), meta.get("tag"), meta.get("name"))
        for meta in data["images"].values()
        if isinstance(meta, dict) and meta.get("source_repo") != "manual"
    }

    todo = [
        a for a in iter_release_assets(REPOS)
        if (a["repo"], a["tag"], a["name"]) not in seen_assets
    ]
    print(f"{len(todo)} new asset(s) to hash ({len(data['images'])} entries already known)")

    failures = []
    added, collided = 0, 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(hash_first_26mib, a["url"]): a for a in todo}
        for future in concurrent.futures.as_completed(futures):
            asset = futures[future]
            try:
                digest = future.result()
            except Exception as e:
                failures.append(f"{asset['repo']} {asset['tag']} {asset['name']}: {e}")
                print(f"  FAIL {asset['repo']} {asset['tag']} {asset['name']}: {e}", file=sys.stderr)
                continue
            if digest in data["images"]:
                collided += 1
                print(f"  dup  {asset['name']} ({asset['tag']}) matches existing entry")
            else:
                data["images"][digest] = {
                    "name": asset["name"],
                    "source_repo": asset["repo"],
                    "tag": asset["tag"],
                }
                added += 1
                print(f"  ok   {asset['name']} ({asset['tag']})")

    if failures:
        print(f"\n{len(failures)} failure(s); not writing 'updated'.", file=sys.stderr)

    data["updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    data["images"] = dict(sorted(data["images"].items(), key=lambda kv: (kv[1].get("name", ""), kv[0])))

    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    print(f"\nwrote {args.out}: {added} added, {collided} duplicate(s), {len(data['images'])} total entries")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
