"""Unit tests for the SeedSigner-OS microSD / persistent-data directory resolver.

The resolver picks where settings and microSD I/O live on SeedSigner OS:
``/mnt/microsd`` (Raspberry Pi / La Frite convention) or ``/mnt/sdcard`` (Luckfox
SDK auto-mount, which doubles as a writable-rootfs store on card-less NAND/eMMC).
These tests fake ``os.path.ismount``/``isdir`` so they run anywhere.
"""
import os

import pytest

from seedsigner.hardware.microsd import resolve_seedsigner_os_data_dir


@pytest.fixture
def fake_fs(monkeypatch):
    """Fake the filesystem probes the resolver uses."""
    state = {"mounted": set(), "dirs": set()}
    monkeypatch.setattr(os.path, "ismount", lambda p: p in state["mounted"])
    monkeypatch.setattr(os.path, "isdir", lambda p: p in state["dirs"])
    return state


# --- Raspberry Pi / La Frite: /mnt/sdcard never exists -> behave exactly as before ---

def test_pi_with_card_uses_microsd(fake_fs):
    # A card mounted at /mnt/microsd; no /mnt/sdcard on these platforms.
    fake_fs["mounted"] = {"/mnt/microsd"}
    fake_fs["dirs"] = {"/mnt/microsd"}
    assert resolve_seedsigner_os_data_dir() == "/mnt/microsd"


def test_pi_without_card_defaults_to_microsd(fake_fs):
    # Stateless root, no card: nothing mounted, /mnt/sdcard absent.
    # Resolver returns the canonical /mnt/microsd (so is_inserted stays False when
    # the mountpoint dir is absent -> physical-card gating preserved).
    assert resolve_seedsigner_os_data_dir() == "/mnt/microsd"


# --- Luckfox: /mnt/sdcard is present (SDK) ---

def test_luckfox_card_at_sdcard_wins(fake_fs):
    # Card mounted at /mnt/sdcard; /mnt/microsd may exist only as a stale empty dir.
    fake_fs["mounted"] = {"/mnt/sdcard"}
    fake_fs["dirs"] = {"/mnt/microsd", "/mnt/sdcard"}
    assert resolve_seedsigner_os_data_dir() == "/mnt/sdcard"


def test_luckfox_no_card_falls_back_to_sdcard_dir(fake_fs):
    # NAND/eMMC, no card: only the SDK's /mnt/sdcard mountpoint dir exists (on the
    # writable rootfs) -> settings persist there.
    fake_fs["dirs"] = {"/mnt/sdcard"}
    assert resolve_seedsigner_os_data_dir() == "/mnt/sdcard"


def test_mounted_microsd_preferred_over_mounted_sdcard(fake_fs):
    # If both are mounted, the /mnt/microsd convention wins (deterministic order).
    fake_fs["mounted"] = {"/mnt/microsd", "/mnt/sdcard"}
    assert resolve_seedsigner_os_data_dir() == "/mnt/microsd"


def test_mount_beats_bare_dir(fake_fs):
    # A real mount always wins over a candidate that merely exists as a directory.
    fake_fs["mounted"] = {"/mnt/sdcard"}
    fake_fs["dirs"] = {"/mnt/microsd", "/mnt/sdcard"}
    assert resolve_seedsigner_os_data_dir() == "/mnt/sdcard"
