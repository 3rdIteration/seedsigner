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

    assert mapping["display"]["dc"] == ["/dev/gpiochip2", 8]
    assert mapping["display"]["rst"] == ["/dev/gpiochip1", 24]
    assert mapping["display"]["bl"] == ["/dev/gpiochip1", 25]


def test_fox_40_buttons_use_gpiochip_pull_up_mapping():
    mapping = get_hardware_pin_mapping("FOX_40")

    assert mapping["buttons"]["KEY_UP"] == ["/dev/gpiochip2", 9, "pull_up"]
    assert mapping["buttons"]["KEY_DOWN"] == ["/dev/gpiochip1", 26, "pull_up"]
    assert mapping["buttons"]["KEY_LEFT"] == ["/dev/gpiochip1", 19, "pull_up"]
    assert mapping["buttons"]["KEY_RIGHT"] == ["/dev/gpiochip1", 20, "pull_up"]
    assert mapping["buttons"]["KEY_PRESS"] == ["/dev/gpiochip1", 27, "pull_up"]
    assert mapping["buttons"]["KEY1"] == ["/dev/gpiochip1", 23, "pull_up"]
    assert mapping["buttons"]["KEY2"] == ["/dev/gpiochip1", 22, "pull_up"]
    assert mapping["buttons"]["KEY3"] == ["/dev/gpiochip1", 21, "pull_up"]


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


def _make_st7789_pin_mapping(cs=None):
    """Return a minimal display pin mapping for ST7789 tests."""
    mapping = {
        "display": {
            "dc":  ["/dev/gpiochip0", 25],
            "rst": ["/dev/gpiochip0", 27],
            "bl":  ["/dev/gpiochip0", 24],
            "spi_bus": 0,
            "spi_device": 0,
        }
    }
    if cs is not None:
        mapping["display"]["cs"] = cs
    return mapping


def _import_st7789_with_mocked_periphery():
    """Import the ST7789 module with the `periphery` hardware library mocked out.

    `periphery` is only available on actual hardware.  We stub it in
    sys.modules so that the module-level ``from periphery import GPIO, SPI``
    succeeds in a CI/test environment.
    """
    import sys
    import types
    from unittest.mock import MagicMock

    if "periphery" not in sys.modules:
        fake_periphery = types.ModuleType("periphery")
        fake_periphery.GPIO = MagicMock()
        fake_periphery.SPI = MagicMock()
        sys.modules["periphery"] = fake_periphery

    # Force a fresh import so the module picks up the mocked periphery.
    sys.modules.pop("seedsigner.hardware.displays.ST7789", None)
    import seedsigner.hardware.displays.ST7789 as st7789_module
    return st7789_module


def test_st7789_spi_extra_flags_when_cs_disabled():
    """ST7789.__init__ must pass extra_flags=0x40 (SPI_NO_CS) and SPI Mode 3
    to periphery.SPI when the display config contains 'cs': 'disabled'.

    Mode 3 (CPOL=1, CPHA=1, SCK idles HIGH) is required for CS-grounded
    ST7789 displays.  With CS permanently asserted the display's SPI
    interface is active from boot; in Mode 0 (SCK idles LOW) any SCK
    transitions during the Pi boot sequence are interpreted as clock edges
    and corrupt the display's shift register.  Mode 3 ensures SCK is
    driven HIGH as soon as the SPI bus is opened, eliminating that
    vulnerability (ref: TFT_eSPI issue #163).
    """
    from unittest.mock import patch

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping(cs="disabled")

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI") as mock_spi_cls, \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        st7789_module.ST7789(_width=240, _height=240)

    mock_spi_cls.assert_called_once_with(
        "/dev/spidev0.0",
        3,              # Mode 3 required for CS-grounded displays
        40_000_000,
        extra_flags=0x40,
    )


def test_st7789_spi_extra_flags_default_when_cs_not_disabled():
    """ST7789.__init__ must pass extra_flags=0 to periphery.SPI when no 'cs'
    key is present in the display config (normal CE GPIO-managed CS)."""
    from unittest.mock import patch

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping()  # no cs key

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI") as mock_spi_cls, \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        st7789_module.ST7789(_width=240, _height=240)

    mock_spi_cls.assert_called_once_with(
        "/dev/spidev0.0",
        0,
        40_000_000,
        extra_flags=0,
    )


def test_st7789_warns_on_kernel_managed_cs(caplog):
    """ST7789.__init__ must emit a WARNING when kernel-managed CE CS is active
    (cs not 'disabled').  The warning must describe all three LCD CS states
    (GND / wired-to-CE / floating) so the user knows when the display works and
    when it will fail silently."""
    import logging
    from unittest.mock import patch

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping()  # no cs key → kernel manages CE

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI"), \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping), \
         caplog.at_level(logging.WARNING, logger="seedsigner.hardware.displays.ST7789"):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        st7789_module.ST7789(_width=240, _height=240)

    warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    # Warning must mention the floating-CS silent failure path.
    assert any("floating" in msg for msg in warning_messages), (
        "Expected a warning mentioning floating LCD CS failure, got: " + str(warning_messages)
    )
    # Warning must acknowledge that LCD CS tied to GND works regardless of CE.
    assert any("GND" in msg for msg in warning_messages), (
        "Expected a warning that mentions GND as a working CS option, got: " + str(warning_messages)
    )


def test_st7789_no_warning_when_cs_disabled(caplog):
    """ST7789.__init__ must NOT emit a WARNING when 'cs': 'disabled' is set —
    the SPI_NO_CS path is the explicitly safe configuration."""
    import logging
    from unittest.mock import patch

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping(cs="disabled")

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI"), \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping), \
         caplog.at_level(logging.WARNING, logger="seedsigner.hardware.displays.ST7789"):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        st7789_module.ST7789(_width=240, _height=240)

    warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert not warning_messages, (
        "Unexpected WARNING when cs='disabled': " + str(warning_messages)
    )


def test_st7789_init_not_called_during_construction():
    """init() must NOT be called during __init__() — it is deferred to the
    first draw call so that CS can be tied to GND after the SPI bus opens
    but before the first frame is rendered."""
    from unittest.mock import patch

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping(cs="disabled")

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI"), \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping), \
         patch.object(st7789_module.ST7789, "init") as mock_init:
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7789_module.ST7789(_width=240, _height=240)

    mock_init.assert_not_called()
    assert display._display_initialized is False


def test_st7789_init_called_on_first_show_image():
    """_ensure_initialized() must call init() exactly once on the first call
    and not on subsequent calls."""
    from unittest.mock import patch

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping(cs="disabled")

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI"), \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping), \
         patch.object(st7789_module.ST7789, "init") as mock_init:
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7789_module.ST7789(_width=240, _height=240)

        assert not display._display_initialized
        mock_init.assert_not_called()

        # _ensure_initialized is the shared lazy-init gate called by all
        # public draw methods (show_image, clear, invert).
        display._ensure_initialized()
        assert mock_init.call_count == 1
        assert display._display_initialized is True

        # Subsequent calls must not trigger init() again.
        display._ensure_initialized()
        assert mock_init.call_count == 1


def test_st7789_invert_triggers_lazy_init():
    """invert() is the simplest public draw method; it must trigger lazy init
    on first call and not on subsequent calls."""
    from unittest.mock import patch

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping(cs="disabled")

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI"), \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping), \
         patch.object(st7789_module.ST7789, "init") as mock_init, \
         patch.object(st7789_module.ST7789, "command"):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7789_module.ST7789(_width=240, _height=240)

        mock_init.assert_not_called()

        display.invert(True)
        assert mock_init.call_count == 1
        assert display._display_initialized is True

        display.invert(False)
        assert mock_init.call_count == 1  # must not re-init


def test_st7789_init_does_not_set_inversion():
    """init() must NOT hardcode the inversion state (INVON/INVOFF).

    The Renderer applies the saved 'Invert colors' setting explicitly after
    driver creation; a hardcoded INVON in init() made the boot state ignore
    the setting and made toggling it in Settings appear reversed.
    """
    from unittest.mock import patch

    ST7789_INVOFF = 0x20
    ST7789_INVON = 0x21

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping(cs="disabled")

    commands_sent = []

    def fake_command(self_inner, cmd):
        commands_sent.append(cmd)

    def fake_reset(self_inner):
        pass  # skip RST toggling and its sleeps

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI"), \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping), \
         patch.object(st7789_module.ST7789, "reset", fake_reset), \
         patch.object(st7789_module.ST7789, "command", fake_command):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7789_module.ST7789(_width=240, _height=240)
        display.init()

    assert ST7789_INVON not in commands_sent, "init() must not hardcode INVON (0x21)"
    assert ST7789_INVOFF not in commands_sent, "init() must not hardcode INVOFF (0x20)"


def test_st7789_invert_sends_invon_invoft():
    """invert(True) must send INVON (0x21); invert(False) must send INVOFF (0x20)."""
    from unittest.mock import patch

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping(cs="disabled")

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI"), \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7789_module.ST7789(_width=240, _height=240)

        # Skip the lazy init so only invert()'s own command is captured.
        display._display_initialized = True

        with patch.object(display, "command") as mock_command:
            display.invert(True)
        assert [c.args[0] for c in mock_command.call_args_list] == [0x21]

        mock_command.reset_mock()
        with patch.object(display, "command") as mock_command:
            display.invert(False)
        assert [c.args[0] for c in mock_command.call_args_list] == [0x20]


def _import_st7789_mpy_with_mocked_periphery():
    """Import the st7789_mpy module with `periphery` mocked out (see
    _import_st7789_with_mocked_periphery)."""
    import sys
    import types
    from unittest.mock import MagicMock

    if "periphery" not in sys.modules:
        fake_periphery = types.ModuleType("periphery")
        fake_periphery.GPIO = MagicMock()
        fake_periphery.SPI = MagicMock()
        sys.modules["periphery"] = fake_periphery

    sys.modules.pop("seedsigner.hardware.displays.st7789_mpy", None)
    import seedsigner.hardware.displays.st7789_mpy as st7789_mpy_module
    return st7789_mpy_module


def test_st7789_mpy_init_cmds_do_not_set_inversion():
    """_ST7789_INIT_CMDS must NOT hardcode the inversion state; the Renderer
    applies the saved 'Invert colors' setting explicitly after driver creation."""
    st7789_mpy_module = _import_st7789_mpy_with_mocked_periphery()

    init_commands = [command for command, data, delay in st7789_mpy_module._ST7789_INIT_CMDS]
    assert b"\x21" not in init_commands, "_ST7789_INIT_CMDS must not hardcode INVON (0x21)"
    assert b"\x20" not in init_commands, "_ST7789_INIT_CMDS must not hardcode INVOFF (0x20)"


def test_st7789_init_called_on_first_clear():
    """init() must be called on the first clear() call if not yet initialized."""
    from unittest.mock import patch

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping(cs="disabled")

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI"), \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping), \
         patch.object(st7789_module.ST7789, "init") as mock_init, \
         patch.object(st7789_module.ST7789, "SetWindows"), \
         patch.object(st7789_module.ST7789, "_chunked_transfer"):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7789_module.ST7789(_width=240, _height=240)

        mock_init.assert_not_called()
        display.clear()
        assert mock_init.call_count == 1
        assert display._display_initialized is True


def test_st7789_init_sleeps_after_slpout():
    """init() must sleep at least 120 ms between SLPOUT (0x11) and DISPON (0x29).

    The ST7789 datasheet requires ≥120 ms after SLPOUT before any subsequent
    command.  Without this delay the display ignores DISPON and stays blank.

    The bug manifested with CS tied to GND but not with kernel-managed CE for
    two compounding reasons:

    1) Code path: SPI_NO_CS support and lazy init were introduced together.
       Users on the default kernel-CE path had eager init, giving hundreds of
       milliseconds of startup delay between SLPOUT and the first pixel write.
       Users on the new CS-to-GND path had lazy init (init() runs immediately
       before show_image()), removing that accidental gap.

    2) Hardware: with kernel-managed CE wired to LCD CS, the SPI driver pulses
       CE HIGH after every spi.transfer() call, giving the ST7789 a
       synchronisation edge.  With CS permanently grounded, there are no CE
       pulses and the display relies entirely on internal timing.

    The 120 ms sleep is the correct fix for both paths.
    """
    import time
    from unittest.mock import patch

    # ST7789 command codes relevant to this test.
    ST7789_SLPOUT = 0x11  # Sleep Out — wake the panel from post-reset sleep
    ST7789_DISPON = 0x29  # Display On — turn on the pixel output

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping(cs="disabled")

    commands_in_order = []

    def fake_command(self_inner, cmd):
        commands_in_order.append(("cmd", cmd, time.monotonic()))

    def fake_data(self_inner, val):
        # Data bytes carry no timing significance for this test; record
        # without a timestamp so the list stays compact.
        commands_in_order.append(("data", val, None))

    def fake_reset(self_inner):
        pass  # skip RST toggling

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI"), \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping), \
         patch.object(st7789_module.ST7789, "reset", fake_reset), \
         patch.object(st7789_module.ST7789, "command", fake_command), \
         patch.object(st7789_module.ST7789, "data", fake_data):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7789_module.ST7789(_width=240, _height=240)
        display.init()

    # Find the timestamps for SLPOUT and DISPON commands.
    slpout_t = next(
        (e[2] for e in commands_in_order if e[0] == "cmd" and e[1] == ST7789_SLPOUT),
        None,
    )
    dispon_t = next(
        (e[2] for e in commands_in_order if e[0] == "cmd" and e[1] == ST7789_DISPON),
        None,
    )

    assert slpout_t is not None, "SLPOUT (0x11) command not found in init() sequence"
    assert dispon_t is not None, "DISPON (0x29) command not found in init() sequence"
    assert dispon_t > slpout_t, "DISPON must be sent after SLPOUT"

    delay_ms = (dispon_t - slpout_t) * 1000
    assert delay_ms >= 120, (
        f"Must sleep ≥120 ms between SLPOUT and DISPON (ST7789 datasheet); "
        f"actual delay was {delay_ms:.1f} ms"
    )


def test_st7789_waits_120ms_between_reset_release_and_slpout():
    """RESX release → SLPOUT must be ≥120 ms (ST7789 datasheet).

    The datasheet imposes two separate waits after a hardware reset: 5 ms
    before any command may be sent, and 120 ms before SLPOUT specifically.
    Only the first was honoured (10 ms), and init() reaches SLPOUT after ~60
    register writes — roughly 20-30 ms — so SLPOUT was issued well inside the
    forbidden window.  The panel then intermittently never woke: every SPI
    transfer still succeeded and the screen simply stayed black.

    Because it is a race rather than a hard failure, it presented as a display
    that worked on some boots and not others, with a failure rate that shifted
    with anything altering boot load or CPU contention.

    Unlike the SLPOUT→DISPON test above, this deliberately does NOT stub out
    reset() — the gap under test is produced inside reset(), and stubbing it is
    precisely why the regression went uncovered.
    """
    import time
    from unittest.mock import patch

    ST7789_SLPOUT = 0x11

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping()

    events = []

    def fake_command(self_inner, cmd):
        events.append(("cmd", cmd, time.monotonic()))

    def fake_data(self_inner, val):
        events.append(("data", val, None))

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI"), \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping), \
         patch.object(st7789_module.ST7789, "command", fake_command), \
         patch.object(st7789_module.ST7789, "data", fake_data):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7789_module.ST7789(_width=240, _height=240)

        # Record RST line transitions. Attached after __init__ so the backlight
        # write during construction is not counted (the patched GPIO class hands
        # back one shared mock for dc/rst/bl).
        rst_writes = []
        display._rst.write.side_effect = (
            lambda value: rst_writes.append((value, time.monotonic()))
        )

        display.init()

    # RESX is released on the final write(True) of the reset pulse.
    release_t = next(
        (t for value, t in reversed(rst_writes) if value is True), None
    )
    assert release_t is not None, "reset() never drove RST high"

    slpout_t = next(
        (e[2] for e in events if e[0] == "cmd" and e[1] == ST7789_SLPOUT),
        None,
    )
    assert slpout_t is not None, "SLPOUT (0x11) command not found in init() sequence"

    delay_ms = (slpout_t - release_t) * 1000
    # The regression this catches is "no RESX→SLPOUT sleep at all" (delay
    # collapses to ~20-30 ms).  110 ms is well above that and tolerates the
    # ~10 ms that time.sleep can return early on a loaded Windows CI runner
    # relative to time.monotonic.  The implementation sleeps 150 ms, so a
    # healthy run lands at ~140-150 ms — far above this floor.
    assert delay_ms >= 110, (
        f"SLPOUT must not be sent until ≥120 ms after RESX is released "
        f"(ST7789 datasheet); actual delay was {delay_ms:.1f} ms"
    )


def test_st7789_falls_back_to_mode3_without_no_cs_on_einval():
    """When the kernel SPI driver rejects SPI_NO_CS (extra_flags=0x40) with
    EINVAL, ST7789.__init__ must retry in SPI Mode 3 with extra_flags=0.

    Some SoC SPI drivers (e.g. Luckfox Pico) do not implement SPI_NO_CS and
    return EINVAL at bus open time.  Mode 3 (CPOL=1, CPHA=1, SCK idles HIGH)
    is the essential fix for CS-grounded ST7789 displays and must remain active
    even when SPI_NO_CS is not available.
    """
    import errno as _errno
    from unittest.mock import patch, call, MagicMock

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping(cs="disabled")

    # First SPI() call raises EINVAL; second call succeeds.
    mock_spi_instance = MagicMock()
    einval_error = OSError(_errno.EINVAL, "Invalid argument")
    einval_error.errno = _errno.EINVAL
    mock_spi_cls = MagicMock(side_effect=[einval_error, mock_spi_instance])

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI", mock_spi_cls), \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7789_module.ST7789(_width=240, _height=240)

    # The driver must have been called twice: first with SPI_NO_CS, then without.
    assert mock_spi_cls.call_count == 2, (
        f"Expected 2 SPI() calls (primary + fallback), got {mock_spi_cls.call_count}"
    )
    first_call, second_call = mock_spi_cls.call_args_list
    # Primary attempt: Mode 3 + SPI_NO_CS.
    assert first_call == call("/dev/spidev0.0", 3, 40_000_000, extra_flags=0x40)
    # Fallback: Mode 3, no extra flags.
    assert second_call == call("/dev/spidev0.0", 3, 40_000_000, extra_flags=0)
    # The display object must be functional (using the fallback SPI instance).
    assert display._spi is mock_spi_instance


def test_st7789_does_not_swallow_non_einval_oserror():
    """OSError exceptions that are NOT EINVAL must propagate unchanged.

    Only EINVAL is a known 'driver does not support this flag' signal.
    Other errors (e.g. ENOENT — device file missing, EACCES — permission
    denied) indicate a different problem and must not be silently swallowed
    by the SPI_NO_CS fallback logic.
    """
    import errno as _errno
    from unittest.mock import patch, MagicMock

    st7789_module = _import_st7789_with_mocked_periphery()
    pin_mapping = _make_st7789_pin_mapping(cs="disabled")

    enoent_error = OSError(_errno.ENOENT, "No such file or directory")
    enoent_error.errno = _errno.ENOENT
    mock_spi_cls = MagicMock(side_effect=enoent_error)

    with patch.object(st7789_module, "GPIO"), \
         patch.object(st7789_module, "SPI", mock_spi_cls), \
         patch.object(st7789_module, "Settings") as mock_settings, \
         patch.object(st7789_module, "get_hardware_pin_mapping", return_value=pin_mapping):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        try:
            st7789_module.ST7789(_width=240, _height=240)
            assert False, "Expected OSError(ENOENT) to propagate but it was swallowed"
        except OSError as e:
            assert e.errno == _errno.ENOENT

    # Only one SPI() call should have been made — no retry on non-EINVAL errors.
    assert mock_spi_cls.call_count == 1


# ---------------------------------------------------------------------------
# ST7735 display driver tests (Waveshare 1.44" LCD HAT, 128x128)
# ---------------------------------------------------------------------------

def _make_st7735_pin_mapping(cs=None):
    """Return a minimal display pin mapping for ST7735 tests."""
    mapping = {
        "display": {
            "dc":  ["/dev/gpiochip0", 25],
            "rst": ["/dev/gpiochip0", 27],
            "bl":  ["/dev/gpiochip0", 24],
            "spi_bus": 0,
            "spi_device": 0,
        }
    }
    if cs is not None:
        mapping["display"]["cs"] = cs
    return mapping


def _import_st7735_with_mocked_periphery():
    """Import ST7735 with mocked periphery, analogous to _import_st7789_..."""
    import sys
    import types
    from unittest.mock import MagicMock

    if "periphery" not in sys.modules:
        fake_periphery = types.ModuleType("periphery")
        fake_periphery.GPIO = MagicMock()
        fake_periphery.SPI = MagicMock()
        sys.modules["periphery"] = fake_periphery

    sys.modules.pop("seedsigner.hardware.displays.ST7735", None)
    import seedsigner.hardware.displays.ST7735 as st7735_module
    return st7735_module


def test_st7735_dimensions():
    """ST7735 must report 128×128 resolution."""
    from unittest.mock import patch

    st7735_module = _import_st7735_with_mocked_periphery()
    pin_mapping = _make_st7735_pin_mapping()

    with patch.object(st7735_module, "GPIO"), \
         patch.object(st7735_module, "SPI"), \
         patch.object(st7735_module, "Settings") as mock_settings, \
         patch.object(st7735_module, "get_hardware_pin_mapping", return_value=pin_mapping):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7735_module.ST7735(_width=128, _height=128)

    assert display.width == 128
    assert display.height == 128


def test_st7735_spi_speed():
    """ST7735 must use 16 MHz SPI speed (datasheet max ~16 MHz)."""
    from unittest.mock import patch

    st7735_module = _import_st7735_with_mocked_periphery()
    pin_mapping = _make_st7735_pin_mapping()

    with patch.object(st7735_module, "GPIO"), \
         patch.object(st7735_module, "SPI") as mock_spi_cls, \
         patch.object(st7735_module, "Settings") as mock_settings, \
         patch.object(st7735_module, "get_hardware_pin_mapping", return_value=pin_mapping):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        st7735_module.ST7735(_width=128, _height=128)

    mock_spi_cls.assert_called_once_with(
        "/dev/spidev0.0",
        0,
        16_000_000,
        extra_flags=0,
    )


def test_st7735_spi_cs_disabled():
    """ST7735 must use SPI Mode 3 + SPI_NO_CS when cs='disabled'."""
    from unittest.mock import patch

    st7735_module = _import_st7735_with_mocked_periphery()
    pin_mapping = _make_st7735_pin_mapping(cs="disabled")

    with patch.object(st7735_module, "GPIO"), \
         patch.object(st7735_module, "SPI") as mock_spi_cls, \
         patch.object(st7735_module, "Settings") as mock_settings, \
         patch.object(st7735_module, "get_hardware_pin_mapping", return_value=pin_mapping):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        st7735_module.ST7735(_width=128, _height=128)

    mock_spi_cls.assert_called_once_with(
        "/dev/spidev0.0",
        3,
        16_000_000,
        extra_flags=0x40,
    )


def test_st7735_init_not_called_during_construction():
    """init() must be deferred (lazy init), same as ST7789."""
    from unittest.mock import patch

    st7735_module = _import_st7735_with_mocked_periphery()
    pin_mapping = _make_st7735_pin_mapping()

    with patch.object(st7735_module, "GPIO"), \
         patch.object(st7735_module, "SPI"), \
         patch.object(st7735_module, "Settings") as mock_settings, \
         patch.object(st7735_module, "get_hardware_pin_mapping", return_value=pin_mapping), \
         patch.object(st7735_module.ST7735, "init") as mock_init:
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7735_module.ST7735(_width=128, _height=128)

    mock_init.assert_not_called()
    assert display._display_initialized is False


def test_st7735_init_called_on_first_show_image():
    """_ensure_initialized() must call init() exactly once."""
    from unittest.mock import patch

    st7735_module = _import_st7735_with_mocked_periphery()
    pin_mapping = _make_st7735_pin_mapping()

    with patch.object(st7735_module, "GPIO"), \
         patch.object(st7735_module, "SPI"), \
         patch.object(st7735_module, "Settings") as mock_settings, \
         patch.object(st7735_module, "get_hardware_pin_mapping", return_value=pin_mapping), \
         patch.object(st7735_module.ST7735, "init") as mock_init:
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7735_module.ST7735(_width=128, _height=128)

        display._ensure_initialized()
        assert mock_init.call_count == 1
        assert display._display_initialized is True

        display._ensure_initialized()
        assert mock_init.call_count == 1


def test_st7735_init_sleeps_after_slpout():
    """init() must sleep ≥120 ms between SLPOUT and DISPON."""
    import time
    from unittest.mock import patch

    ST7735_SLPOUT = 0x11
    ST7735_DISPON = 0x29

    st7735_module = _import_st7735_with_mocked_periphery()
    pin_mapping = _make_st7735_pin_mapping()

    commands_in_order = []

    def fake_command(self_inner, cmd):
        commands_in_order.append(("cmd", cmd, time.monotonic()))

    def fake_data(self_inner, val):
        commands_in_order.append(("data", val, None))

    def fake_reset(self_inner):
        pass

    with patch.object(st7735_module, "GPIO"), \
         patch.object(st7735_module, "SPI"), \
         patch.object(st7735_module, "Settings") as mock_settings, \
         patch.object(st7735_module, "get_hardware_pin_mapping", return_value=pin_mapping), \
         patch.object(st7735_module.ST7735, "reset", fake_reset), \
         patch.object(st7735_module.ST7735, "command", fake_command), \
         patch.object(st7735_module.ST7735, "data", fake_data):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7735_module.ST7735(_width=128, _height=128)
        display.init()

    slpout_t = next(
        (e[2] for e in commands_in_order if e[0] == "cmd" and e[1] == ST7735_SLPOUT),
        None,
    )
    dispon_t = next(
        (e[2] for e in commands_in_order if e[0] == "cmd" and e[1] == ST7735_DISPON),
        None,
    )

    assert slpout_t is not None, "SLPOUT (0x11) not found in init() sequence"
    assert dispon_t is not None, "DISPON (0x29) not found in init() sequence"
    assert dispon_t > slpout_t, "DISPON must be sent after SLPOUT"

    delay_ms = (dispon_t - slpout_t) * 1000
    assert delay_ms >= 120, (
        f"Must sleep ≥120 ms between SLPOUT and DISPON; actual {delay_ms:.1f} ms"
    )


def test_st7735_falls_back_on_einval():
    """ST7735 must retry without SPI_NO_CS on EINVAL, keeping Mode 3."""
    import errno as _errno
    from unittest.mock import patch, call, MagicMock

    st7735_module = _import_st7735_with_mocked_periphery()
    pin_mapping = _make_st7735_pin_mapping(cs="disabled")

    mock_spi_instance = MagicMock()
    einval_error = OSError(_errno.EINVAL, "Invalid argument")
    einval_error.errno = _errno.EINVAL
    mock_spi_cls = MagicMock(side_effect=[einval_error, mock_spi_instance])

    with patch.object(st7735_module, "GPIO"), \
         patch.object(st7735_module, "SPI", mock_spi_cls), \
         patch.object(st7735_module, "Settings") as mock_settings, \
         patch.object(st7735_module, "get_hardware_pin_mapping", return_value=pin_mapping):
        mock_settings.get_platform_default_hardware_config.return_value = "RPI_40"
        display = st7735_module.ST7735(_width=128, _height=128)

    assert mock_spi_cls.call_count == 2
    first_call, second_call = mock_spi_cls.call_args_list
    assert first_call == call("/dev/spidev0.0", 3, 16_000_000, extra_flags=0x40)
    assert second_call == call("/dev/spidev0.0", 3, 16_000_000, extra_flags=0)
    assert display._spi is mock_spi_instance

