import json
import copy

from seedsigner.hardware.io_config import detect_runtime_profile, get_hardware_pin_mapping, load_io_config, runtime_profile_to_hardware_profile
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants


def test_detect_runtime_profile_luckfox_pico_pi():
    assert detect_runtime_profile("Luckfox Pico Pi") == "luckfox_pi"


def test_runtime_profile_to_hardware_profile_luckfox_pico_pi():
    assert runtime_profile_to_hardware_profile("luckfox_pi") == "FOX_PI"


def test_detect_runtime_profile_libre_computer_lafrite():
    assert detect_runtime_profile("Libre Computer AML-S805X-AC La Frite") == "lc_lafrite"


def test_runtime_profile_to_hardware_profile_libre_computer_lafrite():
    assert runtime_profile_to_hardware_profile("lc_lafrite") == "LC_LAFRITE"


def test_lc_lafrite_display_control_lines():
    mapping = get_hardware_pin_mapping("LC_LAFRITE")

    assert mapping["display"]["dc"] == ["/dev/gpiochip1", 79]
    assert mapping["display"]["rst"] == ["/dev/gpiochip1", 20]
    assert mapping["display"]["bl"] == ["/dev/gpiochip1", 25]


def test_lc_lafrite_buttons_use_pull_up_mapping():
    mapping = get_hardware_pin_mapping("LC_LAFRITE")

    assert mapping["buttons"]["KEY_UP"] == ["/dev/gpiochip0", 2, "pull_up"]
    assert mapping["buttons"]["KEY_DOWN"] == ["/dev/gpiochip1", 86, "pull_up"]
    assert mapping["buttons"]["KEY_LEFT"] == ["/dev/gpiochip1", 76, "pull_up"]
    assert mapping["buttons"]["KEY_RIGHT"] == ["/dev/gpiochip1", 84, "pull_up"]
    assert mapping["buttons"]["KEY_PRESS"] == ["/dev/gpiochip1", 85, "pull_up"]
    assert mapping["buttons"]["KEY1"] == ["/dev/gpiochip1", 83, "pull_up"]
    assert mapping["buttons"]["KEY2"] == ["/dev/gpiochip1", 82, "pull_up"]
    assert mapping["buttons"]["KEY3"] == ["/dev/gpiochip1", 81, "pull_up"]


def test_lc_lafrite_camera_uses_usb_device():
    mapping = get_hardware_pin_mapping("LC_LAFRITE")

    assert mapping["camera"]["device"] == "/dev/video1"
    assert mapping["camera"]["pixelformat"] == "YUYV"
    assert mapping["camera"]["framerate"] == 4


def test_fox_pi_display_control_lines_use_gpiochip_format():
    mapping = get_hardware_pin_mapping("FOX_PI")

    assert mapping["display"]["dc"] == ["/dev/gpiochip1", 27]
    assert mapping["display"]["rst"] == ["/dev/gpiochip1", 24]
    assert mapping["display"]["bl"] == ["/dev/gpiochip2", 6]


def test_fox_pi_buttons_use_gpiochip_pull_up_mapping():
    mapping = get_hardware_pin_mapping("FOX_PI")

    assert mapping["buttons"]["KEY_UP"] == ["/dev/gpiochip3", 25, "pull_up"]
    assert mapping["buttons"]["KEY_DOWN"] == ["/dev/gpiochip0", 1, "pull_up"]
    assert mapping["buttons"]["KEY_LEFT"] == ["/dev/gpiochip3", 26, "pull_up"]
    assert mapping["buttons"]["KEY_RIGHT"] == ["/dev/gpiochip0", 0, "pull_up"]
    assert mapping["buttons"]["KEY_PRESS"] == ["/dev/gpiochip1", 20, "pull_up"]
    assert mapping["buttons"]["KEY1"] == ["/dev/gpiochip4", 17, "pull_up"]
    assert mapping["buttons"]["KEY2"] == ["/dev/gpiochip3", 27, "pull_up"]
    assert mapping["buttons"]["KEY3"] == ["/dev/gpiochip1", 23, "pull_up"]


def test_fox_22_display_uses_gpiochip_format():
    mapping = get_hardware_pin_mapping("FOX_22")

    assert mapping["display"]["dc"] == ["/dev/gpiochip1", 20]
    assert mapping["display"]["rst"] == ["/dev/gpiochip1", 19]
    assert mapping["display"]["bl"] == ["/dev/gpiochip1", 11]


def test_fox_22_buttons_use_gpiochip_pull_up_mapping():
    mapping = get_hardware_pin_mapping("FOX_22")

    assert mapping["buttons"]["KEY_UP"] == ["/dev/gpiochip1", 25, "pull_up"]
    assert mapping["buttons"]["KEY_DOWN"] == ["/dev/gpiochip1", 27, "pull_up"]
    assert mapping["buttons"]["KEY_LEFT"] == ["/dev/gpiochip1", 24, "pull_up"]
    assert mapping["buttons"]["KEY_RIGHT"] == ["/dev/gpiochip1", 22, "pull_up"]
    assert mapping["buttons"]["KEY_PRESS"] == ["/dev/gpiochip1", 26, "pull_up"]
    assert mapping["buttons"]["KEY1"] == ["/dev/gpiochip1", 23, "pull_up"]
    assert mapping["buttons"]["KEY2"] == ["/dev/gpiochip0", 4, "pull_up"]
    assert mapping["buttons"]["KEY3"] == ["/dev/gpiochip1", 21, "pull_up"]


def test_fox_40_display_uses_gpiochip_format():
    mapping = get_hardware_pin_mapping("FOX_40")

    assert mapping["display"]["dc"] == ["/dev/gpiochip1", 24]
    assert mapping["display"]["rst"] == ["/dev/gpiochip1", 25]
    assert mapping["display"]["bl"] == ["/dev/gpiochip2", 8]


def test_fox_40_buttons_use_gpiochip_pull_up_mapping():
    mapping = get_hardware_pin_mapping("FOX_40")

    assert mapping["buttons"]["KEY_UP"] == ["/dev/gpiochip1", 26, "pull_up"]
    assert mapping["buttons"]["KEY_DOWN"] == ["/dev/gpiochip1", 21, "pull_up"]
    assert mapping["buttons"]["KEY_LEFT"] == ["/dev/gpiochip1", 27, "pull_up"]
    assert mapping["buttons"]["KEY_RIGHT"] == ["/dev/gpiochip1", 22, "pull_up"]
    assert mapping["buttons"]["KEY_PRESS"] == ["/dev/gpiochip1", 20, "pull_up"]
    assert mapping["buttons"]["KEY1"] == ["/dev/gpiochip1", 23, "pull_up"]
    assert mapping["buttons"]["KEY2"] == ["/dev/gpiochip1", 11, "pull_up"]
    assert mapping["buttons"]["KEY3"] == ["/dev/gpiochip1", 10, "pull_up"]


def test_lc_lafrite_display_config_is_st7789():
    """LC_LAFRITE platform should use the ST7789 display driver, not the desktop/pygame driver"""
    orig = Settings.RUNTIME_PROFILE
    try:
        Settings.RUNTIME_PROFILE = "lc_lafrite"
        display_config = Settings.get_platform_default_display_config()
        assert display_config == SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240
        assert display_config != SettingsConstants.DISPLAY_CONFIGURATION__DESKTOP__240x240
    finally:
        Settings.RUNTIME_PROFILE = orig


def test_desktop_runtime_profile_display_config_is_pygame():
    """Desktop profile should use the desktop/pygame display driver, not ST7789"""
    orig = Settings.RUNTIME_PROFILE
    try:
        Settings.RUNTIME_PROFILE = "desktop"
        display_config = Settings.get_platform_default_display_config()
        assert display_config == SettingsConstants.DISPLAY_CONFIGURATION__DESKTOP__240x240
        assert display_config != SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240
    finally:
        Settings.RUNTIME_PROFILE = orig


# ---------------------------------------------------------------------------
# CS "disabled" (SPI_NO_CS) support
# ---------------------------------------------------------------------------

def test_existing_profiles_have_no_cs_field_by_default():
    """Profiles without an explicit 'cs' field should not have the key at all,
    so that the driver defaults to normal kernel CS management."""
    config = load_io_config()
    for model in config["models"]:
        cs_value = model.get("display", {}).get("cs")
        # Only profiles that explicitly disable CS should have this field set.
        assert cs_value is None, (
            f"Profile {model.get('shortname', '')!r} unexpectedly has 'cs': {cs_value!r} in its display config"
        )


def test_cs_disabled_field_is_readable_from_pin_mapping():
    """When a profile has 'cs': 'disabled' in its display block the field
    must survive the get_hardware_pin_mapping() round-trip unchanged."""
    config = load_io_config()
    # Inject a temporary model with cs disabled to verify the round-trip.
    test_model = copy.deepcopy(config["models"][0])
    test_model["shortname"] = "_TEST_CS_DISABLED"
    test_model["runtime_profile"] = "_test_cs_disabled"
    test_model["regex"] = []
    test_model["display"]["cs"] = "disabled"
    config["models"].append(test_model)

    # Patch the in-memory config so get_hardware_pin_mapping can see it.
    import seedsigner.hardware.io_config as _io_cfg
    orig_loader = _io_cfg.load_io_config
    _io_cfg.load_io_config = lambda: config
    try:
        mapping = get_hardware_pin_mapping("_TEST_CS_DISABLED")
        assert mapping["display"].get("cs") == "disabled"
    finally:
        _io_cfg.load_io_config = orig_loader


def test_st7789_spi_extra_flags_when_cs_disabled():
    """ST7789.__init__ must pass extra_flags=0x40 (SPI_NO_CS) to periphery.SPI
    when the display config contains 'cs': 'disabled'."""
    from unittest.mock import MagicMock, patch

    pin_mapping = {
        "display": {
            "dc":  ["/dev/gpiochip0", 25],
            "rst": ["/dev/gpiochip0", 27],
            "bl":  ["/dev/gpiochip0", 24],
            "spi_bus": 0,
            "spi_device": 0,
            "cs": "disabled",
        }
    }

    with patch("seedsigner.hardware.displays.ST7789.GPIO"), \
         patch("seedsigner.hardware.displays.ST7789.SPI") as mock_spi_cls, \
         patch("seedsigner.hardware.displays.ST7789.Settings") as mock_settings, \
         patch("seedsigner.hardware.displays.ST7789.get_hardware_pin_mapping", return_value=pin_mapping):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        from seedsigner.hardware.displays import ST7789 as st7789_module
        # Prevent the full init sequence (reset + display commands) from running.
        with patch.object(st7789_module.ST7789, "init"):
            st7789_module.ST7789()

    mock_spi_cls.assert_called_once_with(
        "/dev/spidev0.0",
        0,
        40_000_000,
        extra_flags=0x40,
    )


def test_st7789_spi_extra_flags_default_when_cs_not_disabled():
    """ST7789.__init__ must pass extra_flags=0 to periphery.SPI when no 'cs'
    key is present in the display config (normal CE GPIO-managed CS)."""
    from unittest.mock import MagicMock, patch

    pin_mapping = {
        "display": {
            "dc":  ["/dev/gpiochip0", 25],
            "rst": ["/dev/gpiochip0", 27],
            "bl":  ["/dev/gpiochip0", 24],
            "spi_bus": 0,
            "spi_device": 0,
            # no 'cs' key → normal kernel CS management
        }
    }

    with patch("seedsigner.hardware.displays.ST7789.GPIO"), \
         patch("seedsigner.hardware.displays.ST7789.SPI") as mock_spi_cls, \
         patch("seedsigner.hardware.displays.ST7789.Settings") as mock_settings, \
         patch("seedsigner.hardware.displays.ST7789.get_hardware_pin_mapping", return_value=pin_mapping):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        from seedsigner.hardware.displays import ST7789 as st7789_module
        with patch.object(st7789_module.ST7789, "init"):
            st7789_module.ST7789()

    mock_spi_cls.assert_called_once_with(
        "/dev/spidev0.0",
        0,
        40_000_000,
        extra_flags=0,
    )
