#!/usr/bin/env python3
"""
Refresh src/seedsigner/resources/microsd-known-checksums.json.

The device's "Verify MicroSD" tool uses a two-pass approach:
  Pass 1 — read the first ``prefix_size`` bytes (4 MiB) from the raw card,
            compute sha256, and look up the matching entry by prefix hash.
  Pass 2 — read the full image at its exact published size (``size_bytes``)
            from the card, compute sha256, and compare against the entry's
            ``sha256`` field.  A prefix match with a full-hash mismatch is
            reported as possible tampering.

This script walks the release assets of the repos below, records the 4 MiB
prefix hash and the full-file sha256 + size for each image, and optionally
GPG-verifies the release's sha256.txt against the bundled SeedSigner signing
key (``gpg_keys/Seedsigner_pubkey.asc``) before trusting the published hash.

Schema (``prefix_size`` is a top-level field so other projects can adopt the
same format with a different prefix):

  {
    "prefix_size": 4194304,
    "updated": "2026-09-07",
    "images": {
      "<sha256_of_first_4mib>": {
        "name": "seedsigner_os.0.8.7.pi0.img",
        "source_repo": "SeedSigner/seedsigner",
        "tag": "0.8.7",
        "size_bytes": 52428800,
        "sha256": "<full-file sha256>"
      }
    }
  }

Existing entries are never re-downloaded: assets are tracked by
repo+tag+asset name.  Manual entries (e.g. the zero-wiped-card marker) are
always preserved.  A collision check asserts that every prefix hash is unique
across all entries.

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
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPOS = [
    "SeedSigner/seedsigner",        # official images: seedsigner_os.X.Y.Z.<platform>.img
    "3rdIteration/seedsigner",      # fork builds: smartcard variants etc.
    "3rdIteration/seedsigner-os",
]
ASSET_PATTERN = re.compile(r"^seedsigner_os\..*\.img$")
SHA256_PATTERN = re.compile(r"^seedsigner\..*sha256")
SIG_PATTERN = re.compile(r"^seedsigner\..*sha256.*\.sig$")

# How many bytes the device reads for the initial prefix lookup.
PREFIX_SIZE = 4 * 1024 * 1024  # 4 MiB

# Smaller assets are not plausible OS images; treat as a bad upload.
MIN_ASSET_BYTES = 4 * 1024 * 1024

# Path to the bundled SeedSigner GPG signing key, relative to the repo root.
PUBKEY_PATH = Path(__file__).resolve().parents[2] / "gpg_keys" / "Seedsigner_pubkey.asc"

DEFAULT_OUT = (
    Path(__file__).resolve().parents[2]
    / "src" / "seedsigner" / "resources" / "microsd-known-checksums.json"
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


def iter_releases(repos):
    """Yield (repo, release_dict) for every release with at least one .img asset."""
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


def sha256_prefix(url):
    """Range-request first PREFIX_SIZE bytes, returns hex digest."""
    with _open(url, byte_range=f"bytes=0-{PREFIX_SIZE - 1}") as r:
        data = r.read(PREFIX_SIZE)
    return hashlib.sha256(data).hexdigest()


def sha256_file(url):
    """Full streaming download, returns (hex_digest, size_bytes)."""
    with _open(url) as r:
        h = hashlib.sha256()
        size = 0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def parse_sha256_txt(content):
    """Return {filename: hex_digest} from the release's sha256.txt content."""
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
    """Verify sig_content against sha256_content using the bundled SeedSigner key.

    Returns True on success.  Raises RuntimeError if gpg is unavailable,
    the key cannot be imported, or verification fails.
    """
    if not shutil.which("gpg"):
        raise RuntimeError("gpg not found on this system; cannot verify signature")

    if not PUBKEY_PATH.exists():
        raise RuntimeError(f"SeedSigner public key not found at {PUBKEY_PATH}")

    with tempfile.TemporaryDirectory() as gnupghome:
        # Import the SeedSigner signing key
        res = subprocess.run(
            ["gpg", "--homedir", gnupghome, "--import", str(PUBKEY_PATH)],
            capture_output=True, text=True
        )
        if res.returncode != 0:
            raise RuntimeError(f"Failed to import GPG key: {res.stderr.strip()}")

        # Write sha256 content and signature to temp files.  Use newline=""
        # so text-mode doesn't translate \n to \r\n on Windows: GPG
        # verification is byte-exact against the original signed content.
        sha256_path = os.path.join(gnupghome, "sha256.txt")
        sig_path = sha256_path + ".sig"
        with open(sha256_path, "w", encoding="utf-8", newline="") as f:
            f.write(sha256_content)
        with open(sig_path, "wb") as f:
            f.write(sig_content)

        # Verify
        res = subprocess.run(
            ["gpg", "--homedir", gnupghome, "--trust-model", "always",
             "--verify", sig_path, sha256_path],
            capture_output=True, text=True
        )
        if res.returncode != 0:
            raise RuntimeError(
                f"GPG verification failed:\n{res.stderr.strip()}"
            )
    return True


def process_asset(img, sha256_entries, gpg_verified, repo, tag):
    """Download and hash one .img asset, returning (prefix_hash, entry_dict).

    If ``sha256_entries`` contains the image name, the full-file hash is
    verified against the published value.  If ``gpg_verified`` is True, the
    sha256.txt was cryptographically signed by the SeedSigner release key.
    """
    url = img["browser_download_url"]

    # Pass 1: prefix hash (4 MiB, always via Range request)
    prefix = sha256_prefix(url)

    # Pass 2: full-file hash
    expected = sha256_entries.get(img["name"])
    if expected:
        actual, size = sha256_file(url)
        if actual != expected.lower():
            raise RuntimeError(
                f"Hash mismatch for {img['name']}: "
                f"expected {expected}, got {actual}"
            )
        if not gpg_verified:
            # sha256.txt existed but was not GPG-signed (or key wasn't
            # available); log a warning but still record the verified hash.
            print(f"  ! {img['name']}: sha256 verified (no GPG signature)", file=sys.stderr)
    else:
        # No sha256.txt available — full download and record.
        actual, size = sha256_file(url)

    return prefix, {
        "name": img["name"],
        "source_repo": repo,
        "tag": tag,
        "size_bytes": size,
        "sha256": actual,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="path to the checksums json")
    parser.add_argument("--workers", type=int, default=8,
                        help="parallel downloads")
    parser.add_argument("--repos", nargs="+", default=REPOS,
                        help="github repos to scan")
    args = parser.parse_args()

    # Load existing data (if any)
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

        # Collect sha256.txt and .sig assets for this release
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
                        f"  COLLISION: {prefix_hash[:12]} overlaps between "
                        f"{existing['name']} and {img['name']}",
                        file=sys.stderr
                    )
                    sys.exit(1)

                data["images"][prefix_hash] = entry
                sha_tag = " [gpg]" if gpg_verified else ""
                print(f"  ok   {img['name']} ({tag}){sha_tag}")

            except Exception as e:
                failures += 1
                print(f"  FAIL {img['name']} ({tag}): {e}", file=sys.stderr)

    if failures:
        print(f"\n{failures} failure(s); JSON not updated.", file=sys.stderr)
        sys.exit(1)

    if not data["images"]:
        print("No entries found; nothing to write.")
        sys.exit(1)

    # Verify no prefix-hash collisions
    if len(data["images"]) != len({k for k in data["images"]}):
        print("FATAL: prefix-hash collision detected in final data", file=sys.stderr)
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