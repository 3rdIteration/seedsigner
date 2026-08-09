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
from pathlib import Path

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


# --- Persistent Settings availability ------------------------------------------
#
# Regression tests for the gate in Settings.handle_microsd_state_change. It used to
# key off "is a card inserted", which pinned Persistent Settings to Disabled on a
# card-less Luckfox even though /userdata was mounted and saving worked. The option
# must follow where settings can actually be stored, not whether a card is present.

@pytest.fixture
def seedsigner_os(monkeypatch):
    """Run the handler down its SeedSigner-OS path, with a fresh settings entry."""
    from seedsigner.hardware.microsd import MicroSD
    from seedsigner.models.settings import Settings
    from seedsigner.models.settings_definition import (
        SettingsConstants,
        SettingsDefinition,
    )

    monkeypatch.setattr(Settings, "is_seedsigner_os", staticmethod(lambda: True))

    # BaseTest.setup_class swaps MicroSD.get_instance for a Mock and its
    # teardown_class does not put it back, so once any BaseTest subclass has run,
    # every later test in the session sees that mock. These tests are about the
    # REAL is_inserted / has_persistent_storage logic reading the faked mounts, so
    # install a genuine instance for the duration. (Found the hard way: these
    # passed alone and failed in the full suite.)
    #
    # __new__ rather than the usual constructor: MicroSD inherits BaseThread, and
    # the two properties under test touch only Settings and os.path, so there is no
    # reason to start a thread.
    real_microsd = MicroSD.__new__(MicroSD)
    monkeypatch.setattr(MicroSD, "get_instance", classmethod(lambda cls: real_microsd))

    entry = SettingsDefinition.get_settings_entry(
        SettingsConstants.SETTING__PERSISTENT_SETTINGS
    )
    # These are module-level singletons mutated in place; restore them so test
    # order cannot matter.
    original = (entry.selection_options, entry.help_text)
    yield entry
    entry.selection_options, entry.help_text = original


def _handle(action):
    from seedsigner.hardware.microsd import MicroSD
    from seedsigner.models.settings import Settings

    Settings.handle_microsd_state_change(
        action=MicroSD.ACTION__INSERTED if action == "in" else MicroSD.ACTION__REMOVED
    )


def test_userdata_alone_keeps_persistent_settings_selectable(fake_fs, seedsigner_os):
    """The bug: card-less Luckfox with /userdata could not enable Persistent Settings."""
    from seedsigner.models.settings_definition import SettingsConstants

    fake_fs["mounted"] = {"/userdata"}
    _handle("out")

    assert seedsigner_os.selection_options == SettingsConstants.OPTIONS__ENABLED_DISABLED
    # And it must not claim an SD card is where the data goes.
    assert seedsigner_os.help_text == SettingsConstants.PERSISTENT_SETTINGS__ONBOARD__HELP_TEXT


def test_no_storage_at_all_disables_persistent_settings(fake_fs, seedsigner_os):
    """Pi / La Frite with no card: nothing to save to, so don't offer the option."""
    from seedsigner.models.settings_definition import SettingsConstants

    fake_fs["mounted"] = set()
    _handle("out")

    assert seedsigner_os.selection_options == SettingsConstants.OPTIONS__ONLY_DISABLED
    assert seedsigner_os.help_text == SettingsConstants.PERSISTENT_SETTINGS__SD_REMOVED__HELP_TEXT


def test_inserted_card_still_says_sd_card(fake_fs, seedsigner_os):
    from seedsigner.models.settings_definition import SettingsConstants

    fake_fs["mounted"] = {"/mnt/sdcard"}
    _handle("in")

    assert seedsigner_os.selection_options == SettingsConstants.OPTIONS__ENABLED_DISABLED
    assert seedsigner_os.help_text == SettingsConstants.PERSISTENT_SETTINGS__SD_INSERTED__HELP_TEXT


# --- writable staging dir --------------------------------------------------------
#
# resolve_microsd_images_dir must never raise. The GPG views call it before every
# file operation, and on a squashfs-root image with no card and no /userdata the
# resolver's fallback (/mnt/microsd) is genuinely unwritable -- /mnt is not one of
# the tmpfs overlays -- so a bare os.makedirs raised an uncaught OSError and took
# the whole view down.

def test_images_dir_uses_the_resolved_data_dir(fake_fs, monkeypatch, tmp_path):
    from seedsigner.hardware import microsd

    card = tmp_path / "card"
    card.mkdir()
    monkeypatch.setattr(microsd, "resolve_seedsigner_os_data_dir", lambda: str(card))

    got = microsd.resolve_microsd_images_dir()
    assert got == card / "microsd-images"
    assert got.is_dir()


def test_images_dir_falls_back_when_read_only(fake_fs, monkeypatch, tmp_path):
    """The reported bug: EROFS must degrade to tmpfs, not raise."""
    from seedsigner.hardware import microsd

    monkeypatch.setattr(microsd, "resolve_seedsigner_os_data_dir", lambda: "/mnt/microsd")

    fallback = tmp_path / "tmpfs-images"
    monkeypatch.setattr(microsd, "FALLBACK_IMAGES_DIR", str(fallback))

    real_makedirs = os.makedirs

    def readonly_makedirs(path, *args, **kwargs):
        # as_posix(): on Windows str(Path("/mnt/microsd")/"x") uses backslashes,
        # so a posix-prefix startswith would never match and the fake would
        # silently let the "read-only" path succeed.
        if Path(path).as_posix().startswith("/mnt/microsd"):
            raise OSError(30, "Read-only file system")
        return real_makedirs(path, *args, **kwargs)

    monkeypatch.setattr(os, "makedirs", readonly_makedirs)

    got = microsd.resolve_microsd_images_dir()
    assert got == fallback
    assert got.is_dir()


def test_images_dir_never_raises_even_with_no_writable_location(fake_fs, monkeypatch):
    """Both targets unwritable: return a path, let the caller fail on its own open()."""
    from seedsigner.hardware import microsd

    monkeypatch.setattr(microsd, "resolve_seedsigner_os_data_dir", lambda: "/mnt/microsd")

    def always_fails(path, *args, **kwargs):
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr(os, "makedirs", always_fails)

    got = microsd.resolve_microsd_images_dir()
    assert got == Path(microsd.FALLBACK_IMAGES_DIR)
