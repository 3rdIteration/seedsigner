"""Tests for ToolsGPGMenuView dependency checking (pgpy + gnupg2)."""
import sys
import base  # noqa: F401  — ensure hardware mocks
import pytest
from unittest.mock import patch

from seedsigner.gui.screens import RET_CODE__BACK_BUTTON, ErrorScreen
from seedsigner.gui.screens.screen import ButtonListScreen, ButtonOption
from seedsigner.views import tools_views
from seedsigner.views.view import BackStackView


def _make_fake_run_screen(captured):
    """Return a fake run_screen that records the screen type and kwargs."""
    def fake_run_screen(self, screen, *args, **kwargs):
        captured["screen"] = screen
        captured["kwargs"] = kwargs
        return 0  # press the first (OK) button
    return fake_run_screen


def test_missing_pgpy_shows_error(monkeypatch):
    """When pgpy cannot be imported, an ErrorScreen mentioning 'pgpy' is shown."""
    captured = {}
    monkeypatch.setattr(
        tools_views.ToolsGPGMenuView, "run_screen",
        _make_fake_run_screen(captured),
    )
    # Hide pgpy so the import check fails
    real_pgpy = sys.modules.get("pgpy")
    monkeypatch.setitem(sys.modules, "pgpy", None)
    # Ensure gpg binary IS available so only pgpy is reported
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/gpg" if cmd == "gpg" else None)

    view = tools_views.ToolsGPGMenuView()
    dest = view.run()

    assert captured["screen"] is ErrorScreen
    assert "pgpy" in captured["kwargs"]["text"]
    assert dest.View_cls is BackStackView

    # Restore
    if real_pgpy is not None:
        monkeypatch.setitem(sys.modules, "pgpy", real_pgpy)


def test_missing_gpg_binary_shows_error(monkeypatch):
    """When the gpg binary is not found, an ErrorScreen mentioning 'gnupg2' is shown."""
    captured = {}
    monkeypatch.setattr(
        tools_views.ToolsGPGMenuView, "run_screen",
        _make_fake_run_screen(captured),
    )
    # gpg binary not found
    monkeypatch.setattr("shutil.which", lambda cmd: None)

    view = tools_views.ToolsGPGMenuView()
    dest = view.run()

    assert captured["screen"] is ErrorScreen
    assert "gnupg2" in captured["kwargs"]["text"]
    assert dest.View_cls is BackStackView


def test_missing_both_shows_both(monkeypatch):
    """When both pgpy and gpg are missing, both are listed."""
    captured = {}
    monkeypatch.setattr(
        tools_views.ToolsGPGMenuView, "run_screen",
        _make_fake_run_screen(captured),
    )
    real_pgpy = sys.modules.get("pgpy")
    monkeypatch.setitem(sys.modules, "pgpy", None)
    monkeypatch.setattr("shutil.which", lambda cmd: None)

    view = tools_views.ToolsGPGMenuView()
    dest = view.run()

    assert captured["screen"] is ErrorScreen
    text = captured["kwargs"]["text"]
    assert "pgpy" in text
    assert "gnupg2" in text
    assert dest.View_cls is BackStackView

    if real_pgpy is not None:
        monkeypatch.setitem(sys.modules, "pgpy", real_pgpy)


def test_all_deps_present_shows_menu(monkeypatch):
    """When both pgpy and gpg are available, the normal menu is shown."""
    import types
    captured = {}

    def fake_run_screen(self, screen, *args, **kwargs):
        captured["screen"] = screen
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(
        tools_views.ToolsGPGMenuView, "run_screen", fake_run_screen,
    )
    # Ensure gpg binary found
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/gpg" if cmd == "gpg" else None)
    # Ensure pgpy is importable (use a stub if not installed)
    if "pgpy" not in sys.modules or sys.modules["pgpy"] is None:
        monkeypatch.setitem(sys.modules, "pgpy", types.ModuleType("pgpy"))

    view = tools_views.ToolsGPGMenuView()
    dest = view.run()

    # Should show the ButtonListScreen menu, not ErrorScreen
    assert captured["screen"] is ButtonListScreen
    assert dest.View_cls is BackStackView
