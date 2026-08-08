import os

import pytest

from seedsigner.helpers import hardening, seedsigner_os
from seedsigner.helpers.seedsigner_os import is_seedsigner_os_dev_build, signal_app_alive
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
