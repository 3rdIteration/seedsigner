import json

from seedsigner.models import settings as settings_module
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants


def test_invalid_display_config_falls_back(tmp_path, monkeypatch):
    # Simulate running on real hardware without desktop display support
    monkeypatch.setattr(settings_module, "USING_MOCK_GPIO", False)
    monkeypatch.setattr(
        SettingsConstants,
        "ALL_DISPLAY_CONFIGURATIONS",
        [
            (SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240, "st7789 240x240"),
            (SettingsConstants.DISPLAY_CONFIGURATION__ST7789__320x240, "st7789 320x240"),
            (SettingsConstants.DISPLAY_CONFIGURATION__ILI9341__320x240, "ili9341 320x240 (beta)"),
        ],
        raising=False,
    )

    # Create a settings file with an incompatible desktop display configuration
    settings_file = tmp_path / "settings.json"
    settings_data = {
        SettingsConstants.SETTING__DISPLAY_CONFIGURATION: SettingsConstants.DISPLAY_CONFIGURATION__DESKTOP__240x240,
    }
    settings_file.write_text(json.dumps(settings_data))

    monkeypatch.setattr(Settings, "SETTINGS_FILENAME", str(settings_file))

    # Reset singleton and load settings
    Settings._instance = None
    loaded = Settings.get_instance()

    assert (
        loaded.get_value(SettingsConstants.SETTING__DISPLAY_CONFIGURATION)
        == SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240
    )
