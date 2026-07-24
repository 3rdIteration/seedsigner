"""Tests for the generalized OS-environment detection (Axis B).

The board (Settings.RUNTIME_PROFILE) must never imply the OS: the same board can
run either SeedSigner OS or a development OS. Detection therefore relies on a
positive marker file, with a hostname fallback and a /home/pi dev-board check.
"""
import seedsigner.models.settings as settings_module
from seedsigner.models.settings import (
    Settings,
    _detect_os_environment,
    OS_ENV_SEEDSIGNER,
    OS_ENV_DEV_BOARD,
    OS_ENV_DESKTOP,
)


def _patch_exists(monkeypatch, marker=False, home_pi=False):
    def fake_exists(path):
        if path == settings_module.SEEDSIGNER_OS_MARKER:
            return marker
        if path == "/home/pi":
            return home_pi
        return False

    monkeypatch.setattr(settings_module.os.path, "exists", fake_exists)


def test_marker_present_is_seedsigner_os(monkeypatch):
    # Positive marker wins regardless of board/hostname.
    _patch_exists(monkeypatch, marker=True)
    assert _detect_os_environment("rpi_40", "anything", Settings.SEEDSIGNER_OS) == OS_ENV_SEEDSIGNER


def test_marker_wins_over_home_pi(monkeypatch):
    _patch_exists(monkeypatch, marker=True, home_pi=True)
    assert _detect_os_environment("rpi_40", "raspberrypi", Settings.SEEDSIGNER_OS) == OS_ENV_SEEDSIGNER


def test_hostname_fallback_is_seedsigner_os(monkeypatch):
    # Back-compat for images predating the marker.
    _patch_exists(monkeypatch, marker=False)
    assert _detect_os_environment("rpi_40", "seedsigner-os", Settings.SEEDSIGNER_OS) == OS_ENV_SEEDSIGNER


def test_home_pi_is_dev_board(monkeypatch):
    _patch_exists(monkeypatch, marker=False, home_pi=True)
    assert _detect_os_environment("rpi_40", "raspberrypi", Settings.SEEDSIGNER_OS) == OS_ENV_DEV_BOARD


def test_desktop_default(monkeypatch):
    _patch_exists(monkeypatch, marker=False, home_pi=False)
    assert _detect_os_environment("desktop", "my-laptop", Settings.SEEDSIGNER_OS) == OS_ENV_DESKTOP


def test_luckfox_without_markers_is_not_seedsigner_os(monkeypatch):
    # A Luckfox image is only recognized once it ships the marker or the
    # seedsigner-os hostname; without either it must not be mis-detected.
    _patch_exists(monkeypatch, marker=False, home_pi=False)
    assert _detect_os_environment("luckfox_22", "seedsigner luckfox pico", Settings.SEEDSIGNER_OS) == OS_ENV_DESKTOP
