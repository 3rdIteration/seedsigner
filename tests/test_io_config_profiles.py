from seedsigner.hardware.io_config import detect_runtime_profile, get_hardware_pin_mapping, runtime_profile_to_hardware_profile
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
    assert mapping["display"]["bl"] == "disabled"


def test_fox_22_buttons_use_gpiochip_pull_up_mapping():
    mapping = get_hardware_pin_mapping("FOX_22")

    assert mapping["buttons"]["KEY_UP"] == ["/dev/gpiochip1", 25, "pull_up"]
    assert mapping["buttons"]["KEY_DOWN"] == ["/dev/gpiochip1", 23, "pull_up"]
    assert mapping["buttons"]["KEY_LEFT"] == ["/dev/gpiochip1", 24, "pull_up"]
    assert mapping["buttons"]["KEY_RIGHT"] == ["/dev/gpiochip0", 4, "pull_up"]
    assert mapping["buttons"]["KEY_PRESS"] == ["/dev/gpiochip1", 22, "pull_up"]
    assert mapping["buttons"]["KEY1"] == ["/dev/gpiochip4", 16, "pull_up"]
    assert mapping["buttons"]["KEY2"] == ["/dev/gpiochip4", 17, "pull_up"]
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
