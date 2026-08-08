"""Unit tests for the SeedSigner-OS persistent-data directory resolver.

The resolver decides where settings live on SeedSigner OS: a mounted removable card
(``/mnt/microsd`` on Raspberry Pi / La Frite, ``/mnt/sdcard`` on the Luckfox SDK), or
the dedicated ``/userdata`` partition when no card is present.

The invariant these tests exist to protect: **the resolver must never return a
directory on the root filesystem.** Every probe is ``os.path.ismount``, never
``os.path.isdir``. Writing settings to the rootfs is what allowed an unclean shutdown
to destroy on-device state during UBIFS journal replay.

``os.path.ismount``/``isdir`` are faked so these run anywhere.
"""
import os

import pytest

from seedsigner.hardware.microsd import (
    resolve_microsd_mount,
    resolve_seedsigner_os_data_dir,
)


@pytest.fixture
def fake_fs(monkeypatch):
    """Fake the filesystem probes the resolver uses."""
    state = {"mounted": set(), "dirs": set()}
    monkeypatch.setattr(os.path, "ismount", lambda p: p in state["mounted"])
    monkeypatch.setattr(os.path, "isdir", lambda p: p in state["dirs"])
    return state


# --- the rootfs invariant ------------------------------------------------------

def test_bare_directory_is_never_used(fake_fs):
    """A mountpoint dir left on the rootfs must NOT be selected.

    Regression test for the card-less Luckfox NAND case: /mnt/sdcard exists as an
    empty directory on the writable UBIFS root. The old resolver returned it and
    settings were written to the rootfs.
    """
    fake_fs["dirs"] = {"/mnt/microsd", "/mnt/sdcard", "/userdata"}
    # Nothing mounted -> no persistent store, so the canonical default is returned.
    assert resolve_seedsigner_os_data_dir() == "/mnt/microsd"


def test_bare_directory_is_not_a_card(fake_fs):
    fake_fs["dirs"] = {"/mnt/microsd", "/mnt/sdcard"}
    assert resolve_microsd_mount() is None


# --- removable card wins -------------------------------------------------------

def test_card_at_microsd_wins(fake_fs):
    fake_fs["mounted"] = {"/mnt/microsd"}
    assert resolve_seedsigner_os_data_dir() == "/mnt/microsd"
    assert resolve_microsd_mount() == "/mnt/microsd"


def test_card_at_sdcard_wins(fake_fs):
    fake_fs["mounted"] = {"/mnt/sdcard"}
    fake_fs["dirs"] = {"/mnt/microsd", "/mnt/sdcard"}
    assert resolve_seedsigner_os_data_dir() == "/mnt/sdcard"
    assert resolve_microsd_mount() == "/mnt/sdcard"


def test_mounted_microsd_preferred_over_mounted_sdcard(fake_fs):
    # Deterministic order when both are mounted.
    fake_fs["mounted"] = {"/mnt/microsd", "/mnt/sdcard"}
    assert resolve_seedsigner_os_data_dir() == "/mnt/microsd"


def test_card_beats_userdata(fake_fs):
    # A card is user-visible and removable, so it takes priority over /userdata.
    fake_fs["mounted"] = {"/mnt/sdcard", "/userdata"}
    assert resolve_seedsigner_os_data_dir() == "/mnt/sdcard"


# --- /userdata fallback --------------------------------------------------------

def test_userdata_used_when_no_card(fake_fs):
    """Card-less Luckfox with a userdata partition persists to /userdata."""
    fake_fs["mounted"] = {"/userdata"}
    fake_fs["dirs"] = {"/mnt/sdcard", "/userdata"}
    assert resolve_seedsigner_os_data_dir() == "/userdata"


def test_userdata_must_be_a_mountpoint(fake_fs):
    # A /userdata directory that is not a mountpoint is part of the rootfs.
    fake_fs["dirs"] = {"/userdata"}
    assert resolve_seedsigner_os_data_dir() == "/mnt/microsd"


# --- Raspberry Pi / La Frite: no /userdata partition ---------------------------

def test_pi_with_card_uses_microsd(fake_fs):
    fake_fs["mounted"] = {"/mnt/microsd"}
    fake_fs["dirs"] = {"/mnt/microsd"}
    assert resolve_seedsigner_os_data_dir() == "/mnt/microsd"


def test_pi_without_card_defaults_to_microsd(fake_fs):
    # Stateless root, no card, no /userdata: persistence requires a physical card.
    assert resolve_seedsigner_os_data_dir() == "/mnt/microsd"
    assert resolve_microsd_mount() is None
