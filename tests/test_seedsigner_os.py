import os

import pytest

from seedsigner.helpers import hardening, seedsigner_os
from seedsigner.helpers.seedsigner_os import (
    is_seedsigner_os_dev_build,
    parse_diy_mount_log,
    read_diy_mount_status,
    signal_app_alive,
)
from seedsigner.models.settings import Settings


@pytest.fixture
def on_seedsigner_os(monkeypatch):
    monkeypatch.setattr(Settings, "is_seedsigner_os", classmethod(lambda cls: True))


@pytest.fixture
def off_device(monkeypatch):
    monkeypatch.setattr(Settings, "is_seedsigner_os", classmethod(lambda cls: False))


def _marker_present(monkeypatch, present: bool):
    monkeypatch.setattr(
        os.path, "exists", lambda p: present and p == "/usr/bin/microsd_notice.py"
    )


def test_marker_file_still_flags_a_dev_build(monkeypatch, on_seedsigner_os):
    """The Raspberry Pi dev overlay's marker file remains a valid signal: a Pi
    dev image is a dev image even if it happens to pass the exposure checks."""
    _marker_present(monkeypatch, True)
    monkeypatch.setattr(hardening, "is_hardened", lambda results=None: True)
    assert is_seedsigner_os_dev_build() is True


def test_hardened_image_without_marker_is_not_a_dev_build(monkeypatch, on_seedsigner_os):
    _marker_present(monkeypatch, False)
    monkeypatch.setattr(hardening, "is_hardened", lambda results=None: True)
    assert is_seedsigner_os_dev_build() is False


def test_unhardened_image_is_a_dev_build_even_without_the_marker(monkeypatch, on_seedsigner_os):
    """The regression that motivated this: no Luckfox build installs
    microsd_notice.py, so a Luckfox dev image warned about nothing. The verdict
    now comes from what is actually exposed."""
    _marker_present(monkeypatch, False)
    monkeypatch.setattr(hardening, "is_hardened", lambda results=None: False)
    assert is_seedsigner_os_dev_build() is True


def test_off_device_still_warns_when_unhardened(monkeypatch, off_device):
    """Desktop / dev-board runs genuinely fail exposure checks, so warning there
    is a true statement, not a false alarm — the verdict must not be gated on
    running from a SeedSigner OS image."""
    _marker_present(monkeypatch, False)
    monkeypatch.setattr(hardening, "is_hardened", lambda results=None: False)
    assert is_seedsigner_os_dev_build() is True


def test_off_device_hardened_does_not_warn(monkeypatch, off_device):
    """Still evidence-based off-device: nothing exposed, nothing to warn about."""
    _marker_present(monkeypatch, False)
    monkeypatch.setattr(hardening, "is_hardened", lambda results=None: True)
    assert is_seedsigner_os_dev_build() is False


# --------------------------------------------------------------------------
# Boot-watchdog liveness marker
# --------------------------------------------------------------------------

def test_signal_app_alive_writes_marker(tmp_path, monkeypatch, on_seedsigner_os):
    marker = tmp_path / "seedsigner-ready"
    monkeypatch.setattr(seedsigner_os, "READY_MARKER_PATH", str(marker))
    signal_app_alive()
    assert marker.exists()


def test_signal_app_alive_is_noop_off_device(tmp_path, monkeypatch, off_device):
    """Desktop has no OS watchdog; don't litter the filesystem."""
    marker = tmp_path / "seedsigner-ready"
    monkeypatch.setattr(seedsigner_os, "READY_MARKER_PATH", str(marker))
    signal_app_alive()
    assert not marker.exists()


def test_signal_app_alive_survives_unwritable_path(tmp_path, monkeypatch, on_seedsigner_os):
    """Never raise: this runs on the startup path, before the main loop's
    exception handling, so a failure here would crash the app outright."""
    monkeypatch.setattr(
        seedsigner_os, "READY_MARKER_PATH", str(tmp_path / "no-such-dir" / "ready")
    )
    signal_app_alive()  # must not raise


def test_liveness_is_signalled_before_blocking_interstitials():
    """Regression: the marker used to be written only in MainMenuView, so the
    blocking unhardened-build warning kept it from ever appearing and the OS
    watchdog rebooted a working device into Loader after 120s. Controller.start()
    must signal liveness before it runs any interstitial."""
    import inspect

    from seedsigner.controller import Controller

    source = inspect.getsource(Controller.start)
    alive_at = source.find("signal_app_alive()")
    warning_at = source.find("DeveloperOSWarningView().run()")
    assert alive_at != -1, "Controller.start() must signal liveness"
    assert warning_at != -1, "expected the interstitial warning in Controller.start()"
    assert alive_at < warning_at, "liveness must be signalled BEFORE the blocking warning"


# --------------------------------------------------------------------------
# DIY-tools mount log (/tmp/diy-mount.log)
# --------------------------------------------------------------------------

_OK_BLOCK = """\
=== diy-tools result ===
status=OK
reason=diy-tools verified and mounted at /mnt/diy
arch=armhf
computed=22e289c2caa58ed4d460735b03155a57537fa7e29b354ca4fc72a508fe3bdff8
pinned=22e289c2caa58ed4d460735b03155a57537fa7e29b354ca4fc72a508fe3bdff8
mount=/mnt/diy
"""

_MISMATCH_BLOCK = """\
=== diy-tools result ===
status=REFUSED_HASH_MISMATCH
reason=diy-tools.squashfs hash does not match the pinned value; refusing to mount an unverified image
arch=armhf
computed=deadbeef0000c0ffee1234567890abcdef1234567890abcdef1234567890abcdef
pinned=22e289c2caa58ed4d460735b03155a57537fa7e29b354ca4fc72a508fe3bdff8
"""


def test_parse_diy_mount_log_ok_block():
    text = (
        "Thu Aug 27 00:30:11 UTC 2026 ADD /dev/mmcblk1p1: mounting microsd\n"
        + _OK_BLOCK
    )
    block = parse_diy_mount_log(text)

    assert block == {
        "status": "OK",
        "reason": "diy-tools verified and mounted at /mnt/diy",
        "arch": "armhf",
        "computed": "22e289c2caa58ed4d460735b03155a57537fa7e29b354ca4fc72a508fe3bdff8",
        "pinned": "22e289c2caa58ed4d460735b03155a57537fa7e29b354ca4fc72a508fe3bdff8",
        "mount": "/mnt/diy",
    }


def test_parse_diy_mount_log_hash_mismatch_extracts_both_hashes():
    text = (
        "Thu Aug 27 01:02:44 UTC 2026 ADD /dev/mmcblk1p1: mounting microsd\n"
        + _MISMATCH_BLOCK
    )
    block = parse_diy_mount_log(text)

    assert block["status"] == "REFUSED_HASH_MISMATCH"
    # `computed` is the (wrong) hash of what's on the card; `pinned` is expected.
    assert block["computed"].startswith("deadbeef0000c0ffee")
    assert block["pinned"].startswith("22e289c2caa58ed4d460735b")


def test_parse_diy_mount_log_not_present_keeps_detail():
    text = (
        "Thu Aug 27 00:45:30 UTC 2026 ADD /dev/mmcblk1p1: mounting microsd\n"
        "=== diy-tools result ===\n"
        "status=NOT_PRESENT\n"
        "reason=no readable diy-tools.squashfs on microSD\n"
        "arch=armhf\n"
        "detail=sha256sum: can't open '/mnt/microsd/diy-tools.squashfs': No such file or directory\n"
    )
    block = parse_diy_mount_log(text)

    assert block["status"] == "NOT_PRESENT"
    assert (
        block["detail"]
        == "sha256sum: can't open '/mnt/microsd/diy-tools.squashfs': No such file or directory"
    )


def test_parse_diy_mount_log_multiple_blocks_last_wins():
    text = (
        "Thu Aug 27 00:30:11 UTC 2026 ADD /dev/mmcblk1p1: mounting microsd\n"
        + _OK_BLOCK
        + "Thu Aug 27 00:45:02 UTC 2026 REMOVE /dev/mmcblk1p1: unmounting\n"
        + "Thu Aug 27 00:45:30 UTC 2026 ADD /dev/mmcblk1p1: mounting microsd\n"
        + "=== diy-tools result ===\n"
        + "status=NOT_PRESENT\n"
        + "reason=no readable diy-tools.squashfs on microSD\n"
        + "arch=armhf\n"
    )
    block = parse_diy_mount_log(text)

    assert block["status"] == "NOT_PRESENT"
    assert "mount" not in block


def test_parse_diy_mount_log_trailing_incomplete_block_ignored():
    """A partially-written trailing block (no status yet) must fall back to the
    last COMPLETE block, e.g. after a power loss mid-append."""
    text = _OK_BLOCK + "=== diy-tools result ===\narch=armhf\n"
    block = parse_diy_mount_log(text)

    assert block is not None
    assert block["status"] == "OK"


def test_parse_diy_mount_log_marker_without_status_is_incomplete():
    """A block whose status line is empty (or absent) is not complete."""
    assert parse_diy_mount_log("=== diy-tools result ===\nstatus=\narch=armhf\n") is None
    assert parse_diy_mount_log("=== diy-tools result ===\narch=armhf\n") is None


def test_parse_diy_mount_log_reason_with_spaces_and_semicolons():
    """Values are split on the FIRST '=' only; spaces/semicolons survive intact."""
    text = (
        "=== diy-tools result ===\n"
        + "status=REFUSED_HASH_MISMATCH\n"
        + "reason=a b c; d e f; g=h\n"
    )
    block = parse_diy_mount_log(text)

    assert block["reason"] == "a b c; d e f; g=h"


def test_parse_diy_mount_log_empty_value_preserved():
    text = (
        "=== diy-tools result ===\n"
        + "status=NOT_PRESENT\n"
        + "detail=\n"
    )
    block = parse_diy_mount_log(text)

    assert block["status"] == "NOT_PRESENT"
    assert block["detail"] == ""


def test_parse_diy_mount_log_no_marker_returns_none():
    text = (
        "Thu Aug 27 00:30:11 UTC 2026 ADD /dev/mmcblk1p1: mounting microsd\n"
        + "status=OK\n"  # stray key=value outside any block must not count
    )
    assert parse_diy_mount_log(text) is None


def test_parse_diy_mount_log_empty_text_returns_none():
    assert parse_diy_mount_log("") is None
    assert parse_diy_mount_log(None) is None


def test_read_diy_mount_status_missing_file_is_no_information(tmp_path):
    """/tmp is tmpfs: no log file means 'no events since boot', not an error."""
    assert read_diy_mount_status(str(tmp_path / "does-not-exist.log")) is None


def test_read_diy_mount_status_empty_file_returns_none(tmp_path):
    log = tmp_path / "diy-mount.log"
    log.write_text("", encoding="utf-8")
    assert read_diy_mount_status(str(log)) is None


def test_read_diy_mount_status_io_error_never_raises(tmp_path):
    """A path that exists but can't be read as a file (a directory) must not
    crash app startup."""
    assert read_diy_mount_status(str(tmp_path)) is None


def test_read_diy_mount_status_reads_last_complete_block(tmp_path):
    log = tmp_path / "diy-mount.log"
    log.write_text(
        "Thu Aug 27 00:30:11 UTC 2026 ADD /dev/mmcblk1p1: mounting microsd\n"
        + _OK_BLOCK
        + "Thu Aug 27 01:02:44 UTC 2026 ADD /dev/mmcblk1p1: mounting microsd\n"
        + _MISMATCH_BLOCK,
        encoding="utf-8",
    )

    block = read_diy_mount_status(str(log))

    assert block["status"] == "REFUSED_HASH_MISMATCH"
    # The log must be left untouched (read-only access).
    assert log.read_text(encoding="utf-8").endswith(_MISMATCH_BLOCK)
