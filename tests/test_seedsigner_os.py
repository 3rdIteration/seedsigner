import os

import pytest

from seedsigner.helpers import hardening
from seedsigner.helpers.seedsigner_os import is_seedsigner_os_dev_build
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
