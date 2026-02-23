from seedsigner.hardware.io_config import detect_runtime_profile, get_hardware_pin_mapping, runtime_profile_to_hardware_profile


def test_detect_runtime_profile_luckfox_pico_pi():
    assert detect_runtime_profile("Luckfox Pico Pi") == "luckfox_pi"


def test_runtime_profile_to_hardware_profile_luckfox_pico_pi():
    assert runtime_profile_to_hardware_profile("luckfox_pi") == "FOX_PI"


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
