from seedsigner.hardware.io_config import detect_runtime_profile, get_hardware_pin_mapping, runtime_profile_to_hardware_profile


def test_detect_runtime_profile_luckfox_pico_pi():
    assert detect_runtime_profile("Luckfox Pico Pi") == "luckfox_pi"


def test_runtime_profile_to_hardware_profile_luckfox_pico_pi():
    assert runtime_profile_to_hardware_profile("luckfox_pi") == "FOX_PI"


def test_fox_pi_display_control_lines_match_waveshare_hat_pins():
    mapping = get_hardware_pin_mapping("FOX_PI")

    assert mapping["display"]["rst"] == [56]
    assert mapping["display"]["dc"] == [59]
    assert mapping["display"]["bl"] == [70]
