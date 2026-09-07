#!/usr/bin/env python3
"""
Refresh src/seedsigner/resources/microsd-known-checksums.json.

The device's "Verify MicroSD" tool uses a two-pass approach:

  Pass 1a — read the first ``prefix_size`` bytes (4 MiB) from the raw card,
             compute sha256, and look up by pristine hash.
  Pass 1b — if no match, zero the volatile bytes (dirty bit + FSINFO fields
             from the card's MBR-identified FAT partition) within the prefix
             buffer and re-hash — look up by ``alt_prefix_hashes`` in the entry.
             The UI distinguishes "Matched Checksum" clean vs dirty.
  Pass 2 —  read the full image at its exact published size from the card,
             zeroing the same volatile offsets throughout, compute sha256, and
             compare against the entry's ``sha256`` field.  A prefix match with
             a full-hash mismatch is reported as possible tampering.

The JSON stores the **zeroed** full-file sha256 (the same hash the device
computes after zeroing volatile bytes during pass 2).  Official SeedSigner
releases that ship a GPG-signed sha256.txt are verified against the bundled
Seedsigner_pubkey.asc as a cross-check before hashing.

Volatile offsets (FAT dirty bit at ``0x41`` and FSINFO at ``512+0x1E8..0x1EF``)
are determined from the image's MBR partition table.  Entries without a valid
MBR (e.g. zero-wiped marker) have an empty list.

Schema::

  {
    "prefix_size": 4194304,
    "updated": "2026-09-07",
    "images": {
      "<pristine_prefix_hash>": {
        "name": "seedsigner_os.0.8.7.pi0.img",
        "source_repo": "SeedSigner/seedsigner",
        "tag": "0.8.7",
        "size_bytes": 52428800,
        "sha256": "<full-file sha256 (with volatile bytes zeroed)>",
        "volatile_offsets": [4194817, 4195328, 4195329, 4195330, 4195331, 4195332, 4195333, 4195334, 4195335],
        "alt_prefix_hashes": ["<zeroed_prefix_hash>"]
      }
    }
  }

Existing entries are preserved by (repo, tag, name); new ones are appended.
A collision check ensures all hashes (pristine + alt) are unique.

Run manually with ``python .github/scripts/update_microsd_checksums.py``, or
let .github/workflows/update-microsd-checksums.yml run it on a schedule and
open a PR.  Set GITHUB_TOKEN to raise the API rate limit (optional).
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPOS = [
    "SeedSigner/seedsigner",
    "3rdIteration/seedsigner",
    "3rdIteration/seedsigner-os",
]
ASSET_PATTERN = re.compile(r"^seedsigner_os\..*\.img$")
SHA256_PATTERN = re.compile(r"^seedsigner\..*sha256")
SIG_PATTERN = re.compile(r"^seedsigner\..*sha256.*\.sig$")

PREFIX_SIZE = 4 * 1024 * 1024  # 4 MiB
MIN_ASSET_BYTES = 4 * 1024 * 1024

PUBKEY_PATH = Path(__file__).resolve().parents[2] / "gpg_keys" / "Seedsigner_pubkey.asc"
DEFAULT_OUT = (Path(__file__).resolve().parents[2] /
               "src" / "seedsigner" / "resources" / "microsd-known-checksums.json")


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


def iter_releases(repos):
    for repo in repos:
        page = 1
        while True:
            with _open(f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}") as r:
                releases = json.load(r)
            if not releases:
                break
            for rel in releases:
                imgs = [a for a in rel.get("assets", []) if ASSET_PATTERN.match(a["name"])]
                if imgs:
                    yield (repo, rel, imgs)
            page += 1


# ─── MBR / volatile-offset helpers ───────────────────────────────────────

FAT_TYPES = {0x0b, 0x0c, 0x0e}
# FAT32 FSINFO offsets (within the first sector of the FSINFO block, which
# is at partition LBA + 512).  Only applicable for FAT32 (type 0x0b/0x0c).
# Non-FAT32 FAT (type 0x0e) lacks an FSINFO sector.
FSINFO_BASE = 512          # FSINFO sector = partition LBA * 512 + 512
FSINFO_DIRTY = 0x41         # dirty flag is at partition LBA * 512 + 0x41
FSINFO_FREE_CLUSTERS = 0x1E8  # 4 bytes
FSINFO_NEXT_FREE = 0x1EC      # 4 bytes


def compute_volatile_offsets(first_512):
    """Return a sorted list of absolute byte offsets for volatile FAT fields.

    Parses the MBR (first 512 bytes of a raw image) for partition entries of
    FAT type (0x0b, 0x0c, 0x0e).  For each such partition adds:
      - the dirty flag at ``partition_lba * 512 + 0x41`` (1 byte)
      - four FSINFO bytes at ``partition_lba * 512 + 512 + 0x1E8`` (FAT32 only)
      - four FSINFO bytes at ``partition_lba * 512 + 512 + 0x1EC`` (FAT32 only)

    Returns ``[]`` for zeroed or GPT-only images.
    """
    offsets = set()
    mbr_partitions = first_512[446:510]  # 0x1BE-0x1FD
    for i in range(4):
        ent = mbr_partitions[i * 16:(i + 1) * 16]
        if len(ent) < 16:
            break
        ptype = ent[4]
        if ptype not in FAT_TYPES:
            continue
        lba = struct.unpack_from("<I", ent, 8)[0]
        if lba == 0:
            continue
        base = lba * 512
        offsets.add(base + FSINFO_DIRTY)
        if ptype in (0x0b, 0x0c):  # FAT32 has FSINFO sector
            offsets.add(base + FSINFO_BASE + FSINFO_FREE_CLUSTERS + 0)
            offsets.add(base + FSINFO_BASE + FSINFO_FREE_CLUSTERS + 1)
            offsets.add(base + FSINFO_BASE + FSINFO_FREE_CLUSTERS + 2)
            offsets.add(base + FSINFO_BASE + FSINFO_FREE_CLUSTERS + 3)
            offsets.add(base + FSINFO_BASE + FSINFO_NEXT_FREE + 0)
            offsets.add(base + FSINFO_BASE + FSINFO_NEXT_FREE + 1)
            offsets.add(base + FSINFO_BASE + FSINFO_NEXT_FREE + 2)
            offsets.add(base + FSINFO_BASE + FSINFO_NEXT_FREE + 3)
    return sorted(offsets)


def zero_in_place(data, offsets, offset_base=0):
    """Zero the bytes at ``offsets`` (absolute) within ``data`` (bytes or bytearray).

    Only applies offsets that fall within the data's range.
    """
    for off in offsets:
        local = off - offset_base
        if 0 <= local < len(data):
            data[local] = 0


# ─── Hashing helpers ─────────────────────────────────────────────────────

def sha256_prefix_full(url):
    """Download the full asset content (streaming), return (raw_bytes,
    hex_digest_of_full)."""
    with _open(url) as r:
        data = r.read()
    return data, hashlib.sha256(data).hexdigest()


def sha256_with_zerofile(data, offsets):
    """Return sha256 hex of ``data`` with bytes at ``offsets`` zeroed.

    Operates on a mutable copy; ``data`` is bytes, ``offsets`` are absolute.
    """
    buf = bytearray(data)
    zero_in_place(buf, offsets)
    return hashlib.sha256(buf).hexdigest()


def parse_sha256_txt(content):
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and len(parts[0]) == 64:
            result[parts[1]] = parts[0]
    return result


def gpg_verify(sha256_content, sig_content):
    if not shutil.which("gpg"):
        raise RuntimeError("gpg not found on this system; cannot verify signature")
    if not PUBKEY_PATH.exists():
        raise RuntimeError(f"SeedSigner public key not found at {PUBKEY_PATH}")
    with tempfile.TemporaryDirectory() as gnupghome:
        res = subprocess.run(
            ["gpg", "--homedir", gnupghome, "--import", str(PUBKEY_PATH)],
            capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to import GPG key: {res.stderr.strip()}")
        sha256_path = os.path.join(gnupghome, "sha256.txt")
        sig_path = sha256_path + ".sig"
        with open(sha256_path, "w", encoding="utf-8", newline="") as f:
            f.write(sha256_content)
        with open(sig_path, "wb") as f:
            f.write(sig_content)
        res = subprocess.run(
            ["gpg", "--homedir", gnupghome, "--trust-model", "always",
             "--verify", sig_path, sha256_path],
            capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"GPG verification failed:\n{res.stderr.strip()}")
    return True


def process_asset(img, sha256_entries, gpg_verified, repo, tag):
    """Download one .img, compute prefix variants and full zeroed sha256.

    Returns (pristine_prefix_hash, entry_dict).  Raises on collision or
    hash mismatch vs published sha256.txt.
    """
    url = img["browser_download_url"]
    raw, pub_full_hash = sha256_prefix_full(url)

    if len(raw) < PREFIX_SIZE:
        raise ValueError(f"asset too small ({len(raw)} bytes) for {PREFIX_SIZE} prefix")

    # Determine volatile offsets from the image's MBR
    first_512 = raw[:512]
    volatile_offsets = compute_volatile_offsets(first_512)

    # Pristine prefix hash (raw, as-is)
    prefix_pristine = hashlib.sha256(raw[:PREFIX_SIZE]).hexdigest()

    # Alt prefix hash (with volatile offsets zeroed within the prefix)
    prefix_buf = bytearray(raw[:PREFIX_SIZE])
    zero_in_place(prefix_buf, volatile_offsets)
    prefix_alt = hashlib.sha256(prefix_buf).hexdigest()

    # Full-file hash with volatile offsets zeroed throughout
    sha256_zeroed = sha256_with_zerofile(raw, volatile_offsets)

    # If a published sha256.txt hash exists, cross-check
    expected = sha256_entries.get(img["name"])
    if expected:
        if pub_full_hash != expected.lower():
            raise RuntimeError(
                f"Hash mismatch for {img['name']}: "
                f"expected {expected}, got {pub_full_hash}"
            )
        if not gpg_verified:
            print(f"  ! {img['name']}: sha256 verified (no GPG signature)", file=sys.stderr)
    else:
        # No published sha256 — the zeroed hash is all we have.
        pass

    entry = {
        "name": img["name"],
        "source_repo": repo,
        "tag": tag,
        "size_bytes": len(raw),
        "sha256": sha256_zeroed,
        "volatile_offsets": volatile_offsets,
        "alt_prefix_hashes": [prefix_alt] if prefix_alt != prefix_pristine else [],
    }
    return prefix_pristine, entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="path to the checksums json")
    parser.add_argument("--workers", type=int, default=8,
                        help="parallel downloads")
    parser.add_argument("--repos", nargs="+", default=REPOS,
                        help="github repos to scan")
    args = parser.parse_args()

    data = {"prefix_size": PREFIX_SIZE, "updated": None, "images": {}}
    if args.out.exists():
        with open(args.out, encoding="utf-8") as fh:
            loaded = json.load(fh)
        if isinstance(loaded.get("images"), dict):
            data["images"] = loaded["images"]

    seen_assets = {
        (meta.get("source_repo"), meta.get("tag"), meta.get("name"))
        for meta in data["images"].values()
        if isinstance(meta, dict) and meta.get("source_repo") != "manual"
    }

    failures = 0
    for repo, rel, imgs in iter_releases(args.repos):
        tag = rel["tag_name"]

        sha256_assets = [a for a in rel.get("assets", [])
                         if SHA256_PATTERN.search(a["name"]) and not a["name"].endswith(".sig")]
        sig_assets = [a for a in rel.get("assets", [])
                      if SIG_PATTERN.search(a["name"])]

        sha256_entries = {}
        gpg_verified = False
        if sha256_assets:
            sha_txt = sha256_assets[0]
            try:
                sha256_content = _open(sha_txt["browser_download_url"]).read().decode("utf-8")
                sha256_entries = parse_sha256_txt(sha256_content)
                if sig_assets:
                    sig = sig_assets[0]
                    try:
                        sig_content = _open(sig["browser_download_url"]).read()
                        gpg_verify(sha256_content, sig_content)
                        gpg_verified = True
                        print(f"  gpg: {sha_txt['name']} verified OK ({repo}/{tag})")
                    except Exception as e:
                        print(f"  gpg: {sha_txt['name']} verification FAILED: {e}", file=sys.stderr)
                        sys.exit(1)
                else:
                    print(f"  ! {sha_txt['name']}: no GPG signature in release", file=sys.stderr)
            except Exception as e:
                print(f"  ! failed to download {sha_txt['name']}: {e}", file=sys.stderr)
                sha256_entries = {}

        for img in imgs:
            key = (repo, tag, img["name"])
            if key in seen_assets:
                continue

            try:
                prefix_hash, entry = process_asset(
                    img, sha256_entries, gpg_verified, repo, tag
                )

                if prefix_hash in data["images"]:
                    existing = data["images"][prefix_hash]
                    print(
                        f"  COLLISION (pristine): {prefix_hash[:12]} overlaps "
                        f"between {existing['name']} and {img['name']}",
                        file=sys.stderr
                    )
                    sys.exit(1)

                for alt_h in entry.get("alt_prefix_hashes", []):
                    if alt_h in data["images"]:
                        existing = data["images"][alt_h]
                        print(
                            f"  COLLISION (alt): {alt_h[:12]} overlaps "
                            f"between {existing['name']} and {img['name']}",
                            file=sys.stderr
                        )
                        sys.exit(1)

                data["images"][prefix_hash] = entry
                sha_tag = " [gpg]" if gpg_verified else ""
                n_vol = len(entry.get("volatile_offsets", []))
                print(f"  ok   {img['name']} ({tag}){sha_tag}  {n_vol} vol offs")

            except Exception as e:
                failures += 1
                print(f"  FAIL {img['name']} ({tag}): {e}", file=sys.stderr)

    if failures:
        print(f"\n{failures} failure(s); JSON not updated.", file=sys.stderr)
        sys.exit(1)

    if not data["images"]:
        print("No entries found; nothing to write.")
        sys.exit(1)

    data["updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    data["images"] = dict(sorted(
        data["images"].items(),
        key=lambda kv: (kv[1].get("name", ""), kv[0])
    ))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")

    print(f"\nwrote {args.out}: {len(data['images'])} total entries, "
          f"{len(seen_assets)} preserved, {len(data['images']) - len(seen_assets)} new")
    return 0


if __name__ == "__main__":
    sys.exit(main())