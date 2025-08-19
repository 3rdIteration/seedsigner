import json
import types

import pytest

from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.controller import WipeTimerThread, Controller
import seedsigner.hardware.buttons as buttons


def test_persistent_settings_overrides_hardware_display(tmp_path, monkeypatch):
    # Simulate a settings file from real hardware with persistent settings enabled
    settings_path = tmp_path / "settings.json"
    with settings_path.open("w") as f:
        json.dump(
            {
                SettingsConstants.SETTING__DISPLAY_CONFIGURATION: SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240,
                SettingsConstants.SETTING__PERSISTENT_SETTINGS: SettingsConstants.OPTION__ENABLED,
            },
            f,
        )

    # Point settings module at the temporary file and reset singleton
    monkeypatch.setattr(Settings, "SETTINGS_FILENAME", str(settings_path))
    monkeypatch.setattr("seedsigner.models.settings.USING_MOCK_GPIO", True)
    # Skip smartcard side effects when settings are loaded
    monkeypatch.setattr(Settings, "set_value", lambda self, attr, val, save=True: Settings._instance._data.__setitem__(attr, val))
    Settings._instance = None

    settings = Settings.get_instance()

    # Loading hardware settings on a desktop should fall back to the desktop display
    assert (
        settings.get_value(SettingsConstants.SETTING__DISPLAY_CONFIGURATION)
        == SettingsConstants.DISPLAY_CONFIGURATION__DESKTOP__240x240
    )

    # GPIO stub exposes additional helpers
    from seedsigner.models import settings as settings_module

    settings_module.GPIO.setwarnings(False)
    settings_module.GPIO.output(1, settings_module.GPIO.LOW)


def test_wipe_timer_thread_skips_when_no_pygame(monkeypatch):
    # Pretend pygame is not installed and GPIO is unavailable
    monkeypatch.setattr(buttons, "pygame", None)
    monkeypatch.setattr(buttons, "USING_GPIO", False)
    dummy_controller = types.SimpleNamespace(
        settings=types.SimpleNamespace(get_value=lambda *args, **kwargs: 0),
        wipe_timer_ms=None,
        handle_wipe_timeout=lambda: None,
    )
    monkeypatch.setattr(Controller, "get_instance", classmethod(lambda cls: dummy_controller))

    thread = WipeTimerThread()
    thread.keep_running = False  # Exit immediately after setup

    # Should not raise even though HardwareButtons cannot be initialised
    thread.run()
