from seedsigner.hardware.io_config import detect_runtime_profile, get_hardware_pin_mapping, runtime_profile_to_hardware_profile


def test_detect_runtime_profile_luckfox_pico_pi():
    assert detect_runtime_profile("Luckfox Pico Pi") == "luckfox_pi"


def test_runtime_profile_to_hardware_profile_luckfox_pico_pi():
    assert runtime_profile_to_hardware_profile("luckfox_pi") == "FOX_PI"


def test_fox_pi_display_control_lines_match_waveshare_hat_pins():
    mapping = get_hardware_pin_mapping("FOX_PI")

    assert mapping["display"]["dc"] == ["/dev/gpiochip1", 27]
    assert mapping["display"]["rst"] == ["/dev/gpiochip1", 24]
    assert mapping["display"]["bl"] == ["/dev/gpiochip2", 6]


def test_fox_pi_buttons_use_periphery_pull_up_mapping():
    mapping = get_hardware_pin_mapping("FOX_PI")

    assert mapping["buttons"]["KEY_UP"] == ["/dev/gpiochip3", 26, "pull_up"]
    assert mapping["buttons"]["KEY_DOWN"] == ["/dev/gpiochip1", 20, "pull_up"]
    assert mapping["buttons"]["KEY_LEFT"] == ["/dev/gpiochip0", 1, "pull_up"]
    assert mapping["buttons"]["KEY_RIGHT"] == ["/dev/gpiochip3", 25, "pull_up"]
    assert mapping["buttons"]["KEY_PRESS"] == ["/dev/gpiochip0", 0, "pull_up"]
    assert mapping["buttons"]["KEY1"] == ["/dev/gpiochip4", 17, "pull_up"]
    assert mapping["buttons"]["KEY2"] == ["/dev/gpiochip3", 27, "pull_up"]
    assert mapping["buttons"]["KEY3"] == ["/dev/gpiochip1", 23, "pull_up"]
