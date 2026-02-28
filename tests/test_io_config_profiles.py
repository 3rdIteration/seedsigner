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


def test_fox_pi_display_control_lines_match_waveshare_hat_pins():
    mapping = get_hardware_pin_mapping("FOX_PI")

    assert mapping["display"]["dc"] == [59]
    assert mapping["display"]["rst"] == [56]
    assert mapping["display"]["bl"] == [70]


def test_fox_pi_buttons_use_periphery_pull_up_mapping():
    mapping = get_hardware_pin_mapping("FOX_PI")

    assert mapping["buttons"]["KEY_UP"] == [121, "pull_up"]
    assert mapping["buttons"]["KEY_DOWN"] == [1, "pull_up"]
    assert mapping["buttons"]["KEY_LEFT"] == [122, "pull_up"]
    assert mapping["buttons"]["KEY_RIGHT"] == [0, "pull_up"]
    assert mapping["buttons"]["KEY_PRESS"] == [52, "pull_up"]
    assert mapping["buttons"]["KEY1"] == [145, "pull_up"]
    assert mapping["buttons"]["KEY2"] == [123, "pull_up"]
    assert mapping["buttons"]["KEY3"] == [55, "pull_up"]


def test_fox_22_display_uses_blue_board_gpio_numbers():
    mapping = get_hardware_pin_mapping("FOX_22")

    assert mapping["display"]["dc"] == [52]
    assert mapping["display"]["rst"] == [51]
    assert mapping["display"]["bl"] == [43]


def test_fox_22_buttons_use_blue_board_gpio_numbers():
    mapping = get_hardware_pin_mapping("FOX_22")

    assert mapping["buttons"]["KEY_UP"] == [57, "pull_up"]
    assert mapping["buttons"]["KEY_DOWN"] == [59, "pull_up"]
    assert mapping["buttons"]["KEY_LEFT"] == [56, "pull_up"]
    assert mapping["buttons"]["KEY_RIGHT"] == [54, "pull_up"]
    assert mapping["buttons"]["KEY_PRESS"] == [58, "pull_up"]
    assert mapping["buttons"]["KEY1"] == [55, "pull_up"]
    assert mapping["buttons"]["KEY2"] == [4, "pull_up"]
    assert mapping["buttons"]["KEY3"] == [53, "pull_up"]


def test_fox_40_display_uses_blue_board_gpio_numbers():
    mapping = get_hardware_pin_mapping("FOX_40")

    assert mapping["display"]["dc"] == [56]
    assert mapping["display"]["rst"] == [57]
    assert mapping["display"]["bl"] == [72]


def test_fox_40_buttons_use_pull_up_mapping():
    mapping = get_hardware_pin_mapping("FOX_40")

    assert mapping["buttons"]["KEY_UP"] == [58, "pull_up"]
    assert mapping["buttons"]["KEY_DOWN"] == [53, "pull_up"]
    assert mapping["buttons"]["KEY_LEFT"] == [59, "pull_up"]
    assert mapping["buttons"]["KEY_RIGHT"] == [54, "pull_up"]
    assert mapping["buttons"]["KEY_PRESS"] == [52, "pull_up"]
    assert mapping["buttons"]["KEY1"] == [55, "pull_up"]
    assert mapping["buttons"]["KEY2"] == [43, "pull_up"]
    assert mapping["buttons"]["KEY3"] == [42, "pull_up"]


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
