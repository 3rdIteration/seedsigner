from seedsigner.hardware import platform as hw_platform


def _clear_caches():
    hw_platform.detect_platform.cache_clear()
    hw_platform.detect_luckfox_variant.cache_clear()
    hw_platform.get_luckfox_profile.cache_clear()


def test_detect_platform_from_env(monkeypatch):
    _clear_caches()
    monkeypatch.setenv("SEEDSIGNER_PLATFORM", hw_platform.PLATFORM__LUCKFOX)
    assert hw_platform.detect_platform() == hw_platform.PLATFORM__LUCKFOX


def test_detect_platform_luckfox_from_model(monkeypatch):
    _clear_caches()
    monkeypatch.delenv("SEEDSIGNER_PLATFORM", raising=False)

    def fake_read(paths):
        if "model" in paths[0]:
            return "Luckfox Pico"
        return ""

    monkeypatch.setattr(hw_platform, "_read_first_existing", fake_read)
    assert hw_platform.detect_platform() == hw_platform.PLATFORM__LUCKFOX


def test_detect_luckfox_variant_from_model(monkeypatch):
    _clear_caches()
    monkeypatch.setenv("SEEDSIGNER_PLATFORM", hw_platform.PLATFORM__LUCKFOX)
    monkeypatch.delenv("SEEDSIGNER_LUCKFOX_VARIANT", raising=False)

    monkeypatch.setattr(hw_platform, "_device_model_blob", lambda: "luckfox pico mini")
    assert hw_platform.detect_luckfox_variant() == hw_platform.LUCKFOX_VARIANT__PICO_MINI


def test_luckfox_profile_can_be_forced_to_max(monkeypatch):
    _clear_caches()
    monkeypatch.setenv("SEEDSIGNER_PLATFORM", hw_platform.PLATFORM__LUCKFOX)
    monkeypatch.setenv("SEEDSIGNER_LUCKFOX_VARIANT", hw_platform.LUCKFOX_VARIANT__PICO_MAX)

    profile = hw_platform.get_luckfox_profile()
    assert profile.variant == hw_platform.LUCKFOX_VARIANT__PICO_MAX
    assert "/dev/video12" in profile.video_devices


def test_luckfox_profiles_have_valid_pin_maps():
    _clear_caches()
    mini = hw_platform._LUCKFOX_PROFILE_PICO_MINI
    max_profile = hw_platform._LUCKFOX_PROFILE_PICO_MAX

    for profile in (mini, max_profile):
        assert profile.key_up_pin > 0
        assert profile.st7789_dc_pin > 0
        assert profile.video_devices


def test_luckfox_profile_alias_is_supported(monkeypatch):
    _clear_caches()
    monkeypatch.setenv("SEEDSIGNER_PLATFORM", hw_platform.PLATFORM__LUCKFOX)
    monkeypatch.setenv("SEEDSIGNER_LUCKFOX_VARIANT", "pico-mini")

    profile = hw_platform.get_luckfox_profile()
    assert profile.variant == hw_platform.LUCKFOX_VARIANT__PICO_MINI
