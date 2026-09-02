"""Verify the bundled JavaCard CAP files against their sha256 manifests.

No hardware required — this runs in the ordinary suite.

Two directories hold CAP files, for deliberately different reasons:

* ``javacard-cap/`` ships in the SeedSigner-OS image and populates the on-device
  "Install Applet" picker (``_get_internal_cap_dir()`` globs it).
* ``tests/javacard-cap-legacy/`` holds superseded applet versions that only the
  hardware suite flashes. The OS image build prunes ``tests/``, so nothing here
  reaches a user's device.

``javacard-cap/javacard-cap.sha256`` has existed since the CAPs were added but no
code, test, or CI job ever read it. These tests make both manifests real: they are
what lets "SeedKeeper v0.1" name one specific, checkable applet build rather than
whatever happens to be on disk.
"""

import hashlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SHIPPING_DIR = REPO / "javacard-cap"
LEGACY_DIR = REPO / "tests" / "javacard-cap-legacy"

MANIFESTS = [
    SHIPPING_DIR / "javacard-cap.sha256",
    LEGACY_DIR / "javacard-cap-legacy.sha256",
]


def _listed(manifest: Path) -> dict:
    """Parse a ``sha256sum``-format manifest into {filename: digest}."""
    entries = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        # sha256sum marks binary-mode entries with a leading '*' on the name.
        entries[name.strip().lstrip("*")] = digest
    return entries


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda p: p.parent.name)
def test_manifest_lists_every_cap(manifest):
    listed = set(_listed(manifest))
    on_disk = {p.name for p in manifest.parent.glob("*.cap")}
    assert on_disk == listed, (
        f"{manifest.name} and the *.cap files in {manifest.parent.name}/ disagree: "
        f"unlisted={sorted(on_disk - listed)} missing={sorted(listed - on_disk)}"
    )


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda p: p.parent.name)
def test_manifest_digests_match(manifest):
    for name, expected in sorted(_listed(manifest).items()):
        actual = hashlib.sha256((manifest.parent / name).read_bytes()).hexdigest()
        assert actual == expected, f"{name}: expected {expected}, got {actual}"


def test_legacy_v1_cap_is_the_upstream_v0_1_release_asset():
    """Pin the exact artifact TestSeedKeeperV1 flashes.

    Toporin/Seedkeeper-Applet release v0.1, asset SeedKeeper-0.1-0.1.cap. The v0.1
    regression tests assert applet behaviour (0xA7 unimplemented, 0xA5 refusing with
    0x9C05, a hard-coded 4095-byte object memory), so they are only meaningful if
    "v0.1" is this specific build and not a self-built variant.
    """
    cap = LEGACY_DIR / "SeedKeeper-0.1-0.1.cap"
    assert cap.is_file(), f"missing legacy CAP: {cap}"
    assert cap.stat().st_size == 71495
    assert hashlib.sha256(cap.read_bytes()).hexdigest() == (
        "341d043fe7e30c167883ddb567e15f51baec59947343730681468a4835b727ac"
    )


def test_legacy_caps_are_not_also_shipped():
    """Superseded applets must never reach the device.

    javacard-cap/ feeds the on-device "Install Applet" picker and ships in the OS
    image, while the image build prunes tests/. A known-superseded applet in the
    shipping directory would be one tap away from users.
    """
    shipping = {p.name for p in SHIPPING_DIR.glob("*.cap")}
    legacy = {p.name for p in LEGACY_DIR.glob("*.cap")}
    assert not (shipping & legacy), (
        f"legacy CAP(s) also present in javacard-cap/: {sorted(shipping & legacy)}"
    )
