import builtins
import importlib
import io
import os
import stat
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

# Other test modules (via base.py) replace seedsigner.hardware.buttons in
# sys.modules with a MagicMock to avoid hardware dependencies.  We need the
# real module here, so pop any mock, force-import the real implementation,
# then **restore** the mock so the rest of the test suite is unaffected.
_saved_buttons_entry = sys.modules.pop("seedsigner.hardware.buttons", None)
_saved_hw_buttons_attr = None
if isinstance(_saved_buttons_entry, MagicMock):
    import seedsigner.hardware
    _saved_hw_buttons_attr = getattr(seedsigner.hardware, "buttons", None)
    if isinstance(_saved_hw_buttons_attr, MagicMock):
        delattr(seedsigner.hardware, "buttons")

buttons_module = importlib.import_module("seedsigner.hardware.buttons")

# Restore the mock so other tests that rely on it (e.g. PowerOffView importing
# USING_GPIO) continue to see the MagicMock instead of the real module.
if isinstance(_saved_buttons_entry, MagicMock):
    sys.modules["seedsigner.hardware.buttons"] = _saved_buttons_entry
    if isinstance(_saved_hw_buttons_attr, MagicMock):
        setattr(seedsigner.hardware, "buttons", _saved_hw_buttons_attr)


@pytest.fixture(autouse=True)
def reset_buttons_singleton():
    original = buttons_module.HardwareButtons._instance
    buttons_module.HardwareButtons._instance = None
    yield
    buttons_module.HardwareButtons._instance = original


def test_resolve_global_line_maps_sysfs_base_chip_to_real_devnode(monkeypatch):
    real_listdir = os.listdir
    real_open = builtins.open
    real_stat = os.stat

    def fake_listdir(path):
        path = str(path).replace("\\", "/")
        if path == "/sys/class/gpio":
            return ["gpiochip32"]
        if path == "/dev":
            return ["gpiochip0", "gpiochip1"]
        return real_listdir(path)

    def fake_open(path, mode="r", encoding=None):
        path = str(path).replace("\\", "/")
        data = {
            "/sys/class/gpio/gpiochip32/base": "32\n",
            "/sys/class/gpio/gpiochip32/ngpio": "32\n",
            "/sys/class/gpio/gpiochip32/dev": "254:1\n",
        }.get(path)
        if data is None:
            return real_open(path, mode=mode, encoding=encoding)
        return io.StringIO(data)

    def fake_stat(path, *args, **kwargs):
        path = str(path).replace("\\", "/")
        if path == "/dev/gpiochip0":
            return SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=(254, 0))
        if path == "/dev/gpiochip1":
            return SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=(254, 1))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(buttons_module.os, "listdir", fake_listdir)
    monkeypatch.setattr(buttons_module.os, "stat", fake_stat)
    monkeypatch.setattr(buttons_module.os, "major", lambda value: value[0], raising=False)
    monkeypatch.setattr(buttons_module.os, "minor", lambda value: value[1], raising=False)
    monkeypatch.setattr(builtins, "open", fake_open)

    resolved = buttons_module.HardwareButtons._resolve_global_line_to_chip(57)
    assert resolved is not None
    assert resolved[0].replace("\\", "/") == "/dev/gpiochip1"
    assert resolved[1] == 25


def test_singleton_not_poisoned_when_gpio_init_fails(monkeypatch):
    button_map = {
        "KEY_UP": ["/dev/gpiochip1", 25, "pull_up"],
        "KEY_DOWN": ["/dev/gpiochip1", 27, "pull_up"],
        "KEY_LEFT": ["/dev/gpiochip1", 24, "pull_up"],
        "KEY_RIGHT": ["/dev/gpiochip1", 22, "pull_up"],
        "KEY_PRESS": ["/dev/gpiochip1", 26, "pull_up"],
        "KEY1": ["/dev/gpiochip1", 23, "pull_up"],
        "KEY2": ["/dev/gpiochip0", 4, "pull_up"],
        "KEY3": ["/dev/gpiochip1", 21, "pull_up"],
    }

    monkeypatch.setattr(buttons_module, "USING_GPIO", True)
    monkeypatch.setattr(buttons_module.Settings, "get_platform_default_hardware_config", lambda: "FOX_22")
    monkeypatch.setattr(buttons_module, "get_hardware_pin_mapping", lambda _: {"buttons": button_map})
    monkeypatch.setattr(
        buttons_module.HardwareButtons,
        "_resolve_global_line_to_chip",
        staticmethod(lambda line: ("/dev/gpiochip1", line - 32) if line >= 32 else ("/dev/gpiochip0", line)),
    )

    class FailingGPIO:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("init failed")

    monkeypatch.setattr(buttons_module, "GPIO", FailingGPIO)

    with pytest.raises(RuntimeError, match="init failed"):
        buttons_module.HardwareButtons.get_instance()
    assert buttons_module.HardwareButtons._instance is None

    class WorkingGPIO:
        def __init__(self, *args, **kwargs):
            pass

        def close(self):
            pass

        def read(self):
            return True

    monkeypatch.setattr(buttons_module, "GPIO", WorkingGPIO)
    instance = buttons_module.HardwareButtons.get_instance()
    assert hasattr(instance, "last_input_time")


def test_resolve_sysfs_chip_to_devnode_falls_back_to_base_rank(monkeypatch):
    real_listdir = os.listdir
    real_open = builtins.open

    def fake_listdir(path):
        path = str(path).replace("\\", "/")
        if path == "/sys/class/gpio":
            return ["gpiochip0", "gpiochip32", "gpiochip96", "gpiochip128"]
        if path == "/dev":
            return ["gpiochip0", "gpiochip1", "gpiochip2", "gpiochip3"]
        return real_listdir(path)

    def fake_open(path, mode="r", encoding=None):
        path = str(path).replace("\\", "/")
        data = {
            "/sys/class/gpio/gpiochip0/base": "0\n",
            "/sys/class/gpio/gpiochip32/base": "32\n",
            "/sys/class/gpio/gpiochip96/base": "96\n",
            "/sys/class/gpio/gpiochip128/base": "128\n",
        }.get(path)
        if data is None:
            raise FileNotFoundError(path)
        return io.StringIO(data)

    monkeypatch.setattr(buttons_module.os, "listdir", fake_listdir)
    monkeypatch.setattr(buttons_module.os.path, "exists", lambda path: False)
    monkeypatch.setattr(builtins, "open", fake_open)

    resolved = buttons_module.HardwareButtons._resolve_sysfs_chip_to_devnode(
        "/sys/class/gpio/gpiochip32",
        "gpiochip32",
    )
    assert resolved is not None
    assert resolved.replace("\\", "/") == "/dev/gpiochip1"


def test_get_instance_is_thread_safe_single_initializer(monkeypatch):
    button_map = {
        "KEY_UP": ["/dev/gpiochip1", 25, "pull_up"],
        "KEY_DOWN": ["/dev/gpiochip1", 27, "pull_up"],
        "KEY_LEFT": ["/dev/gpiochip1", 24, "pull_up"],
        "KEY_RIGHT": ["/dev/gpiochip1", 22, "pull_up"],
        "KEY_PRESS": ["/dev/gpiochip1", 26, "pull_up"],
        "KEY1": ["/dev/gpiochip1", 23, "pull_up"],
        "KEY2": ["/dev/gpiochip0", 4, "pull_up"],
        "KEY3": ["/dev/gpiochip1", 21, "pull_up"],
    }

    monkeypatch.setattr(buttons_module, "USING_GPIO", True)
    monkeypatch.setattr(buttons_module.Settings, "get_platform_default_hardware_config", lambda: "FOX_22")
    monkeypatch.setattr(buttons_module, "get_hardware_pin_mapping", lambda _: {"buttons": button_map})
    monkeypatch.setattr(
        buttons_module.HardwareButtons,
        "_resolve_global_line_to_chip",
        staticmethod(lambda line: ("/dev/gpiochip1", line - 32) if line >= 32 else ("/dev/gpiochip0", line)),
    )

    class CountingGPIO:
        count = 0

        def __init__(self, *args, **kwargs):
            type(self).count += 1
            time.sleep(0.01)

        def close(self):
            pass

        def read(self):
            return True

    monkeypatch.setattr(buttons_module, "GPIO", CountingGPIO)

    results = []
    errors = []

    def worker():
        try:
            results.append(buttons_module.HardwareButtons.get_instance())
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors
    assert len(results) == 2
    assert results[0] is results[1]
    assert CountingGPIO.count == len(buttons_module.HardwareButtons.BUTTON_NAMES)


def test_disabled_button_skips_gpio_init(monkeypatch):
    button_map = {
        "KEY_UP": ["/dev/gpiochip1", 25, "pull_up"],
        "KEY_DOWN": ["/dev/gpiochip1", 27, "pull_up"],
        "KEY_LEFT": ["/dev/gpiochip1", 24, "pull_up"],
        "KEY_RIGHT": ["/dev/gpiochip1", 22, "pull_up"],
        "KEY_PRESS": ["/dev/gpiochip1", 26, "pull_up"],
        "KEY1": "disabled",
        "KEY2": "disabled",
        "KEY3": ["/dev/gpiochip1", 21, "pull_up"],
    }

    monkeypatch.setattr(buttons_module, "USING_GPIO", True)
    monkeypatch.setattr(buttons_module.Settings, "get_platform_default_hardware_config", lambda: "FOX_22")
    monkeypatch.setattr(buttons_module, "get_hardware_pin_mapping", lambda _: {"buttons": button_map})

    class TrackingGPIO:
        def __init__(self, *args, **kwargs):
            pass

        def close(self):
            pass

        def read(self):
            return True

    monkeypatch.setattr(buttons_module, "GPIO", TrackingGPIO)

    instance = buttons_module.HardwareButtons.get_instance()
    assert "KEY1" not in instance._gpio_pins
    assert "KEY2" not in instance._gpio_pins
    assert "KEY_UP" in instance._gpio_pins
    assert "KEY3" in instance._gpio_pins


def test_disabled_button_never_reports_low(monkeypatch):
    button_map = {
        "KEY_UP": ["/dev/gpiochip1", 25, "pull_up"],
        "KEY_DOWN": ["/dev/gpiochip1", 27, "pull_up"],
        "KEY_LEFT": ["/dev/gpiochip1", 24, "pull_up"],
        "KEY_RIGHT": ["/dev/gpiochip1", 22, "pull_up"],
        "KEY_PRESS": ["/dev/gpiochip1", 26, "pull_up"],
        "KEY1": "disabled",
        "KEY2": ["/dev/gpiochip0", 4, "pull_up"],
        "KEY3": ["/dev/gpiochip1", 21, "pull_up"],
    }

    monkeypatch.setattr(buttons_module, "USING_GPIO", True)
    monkeypatch.setattr(buttons_module.Settings, "get_platform_default_hardware_config", lambda: "FOX_22")
    monkeypatch.setattr(buttons_module, "get_hardware_pin_mapping", lambda _: {"buttons": button_map})

    class HighGPIO:
        def __init__(self, *args, **kwargs):
            pass

        def close(self):
            pass

        def read(self):
            return True

    monkeypatch.setattr(buttons_module, "GPIO", HighGPIO)

    instance = buttons_module.HardwareButtons.get_instance()
    # Disabled button should never register as low
    assert not instance.check_for_low(key="KEY1")
    # has_any_input should not crash when some buttons are disabled
    assert not instance.has_any_input()


# ---------------------------------------------------------------------------
# check_for_low latching tests – verifies that a brief button press (pressed
# and released between two slow polling calls) is still detected.
# ---------------------------------------------------------------------------

def _make_instance_with_controllable_pins(monkeypatch):
    """Create a HardwareButtons instance whose GPIO pins can be individually
    controlled via a ``pin_states`` dict (True = high / not pressed,
    False = low / pressed)."""

    pin_states = {}

    button_map = {
        "KEY_UP": ["/dev/gpiochip1", 25, "pull_up"],
        "KEY_DOWN": ["/dev/gpiochip1", 27, "pull_up"],
        "KEY_LEFT": ["/dev/gpiochip1", 24, "pull_up"],
        "KEY_RIGHT": ["/dev/gpiochip1", 22, "pull_up"],
        "KEY_PRESS": ["/dev/gpiochip1", 26, "pull_up"],
        "KEY1": ["/dev/gpiochip1", 17, "pull_up"],
        "KEY2": ["/dev/gpiochip0", 4, "pull_up"],
        "KEY3": ["/dev/gpiochip1", 21, "pull_up"],
    }

    class ControllableGPIO:
        def __init__(self, *args, **kwargs):
            self._name = None

        def close(self):
            pass

        def read(self):
            if self._name is not None:
                return pin_states.get(self._name, True)
            return True

    monkeypatch.setattr(buttons_module, "USING_GPIO", True)
    monkeypatch.setattr(buttons_module.Settings, "get_platform_default_hardware_config", lambda: "FOX_22")
    monkeypatch.setattr(buttons_module, "get_hardware_pin_mapping", lambda _: {"buttons": button_map})
    monkeypatch.setattr(buttons_module, "GPIO", ControllableGPIO)

    instance = buttons_module.HardwareButtons.get_instance()

    # Map each pin object to its button name so we can control read() values
    for name, pin_obj in instance._gpio_pins.items():
        pin_obj._name = name
        pin_states[name] = True  # all buttons start high (not pressed)

    return instance, pin_states


def test_check_for_low_detects_held_button(monkeypatch):
    """A button held across two check_for_low calls is detected."""
    instance, pin_states = _make_instance_with_controllable_pins(monkeypatch)

    # First call: pin goes low → records timestamp, returns False
    pin_states["KEY_PRESS"] = False  # pressed
    assert not instance.check_for_low(key="KEY_PRESS")

    # Simulate time passing beyond debounce threshold
    instance._low_since_ms["KEY_PRESS"] = int(time.time() * 1000) - 20

    # Second call: pin still low, debounce met → returns True
    assert instance.check_for_low(key="KEY_PRESS")


def test_check_for_low_no_double_fire_on_release(monkeypatch):
    """A button held long enough to return True on the debounced-low path
    must NOT fire again when it is subsequently released (pin goes high).
    This is the double-fire bug described in the issue."""
    instance, pin_states = _make_instance_with_controllable_pins(monkeypatch)

    # First call: pin goes low → records timestamp, returns False
    pin_states["KEY_PRESS"] = False
    assert not instance.check_for_low(key="KEY_PRESS")

    # Simulate time passing beyond debounce threshold
    instance._low_since_ms["KEY_PRESS"] = int(time.time() * 1000) - 20

    # Second call: pin still low, debounce met → returns True (first fire)
    assert instance.check_for_low(key="KEY_PRESS")

    # _low_since_ms must be cleared after the debounced-low return
    assert instance._low_since_ms["KEY_PRESS"] is None

    # Button is released
    pin_states["KEY_PRESS"] = True

    # Must NOT return True again – the press was already consumed
    assert not instance.check_for_low(key="KEY_PRESS")


def test_check_for_low_detects_released_button(monkeypatch):
    """A button pressed and released between two slow polling calls is detected
    (the latching fix for issue #342)."""
    instance, pin_states = _make_instance_with_controllable_pins(monkeypatch)

    # First call: pin is low → records timestamp, returns False
    pin_states["KEY_PRESS"] = False  # pressed
    assert not instance.check_for_low(key="KEY_PRESS")

    # Simulate time passing beyond debounce threshold
    instance._low_since_ms["KEY_PRESS"] = int(time.time() * 1000) - 20

    # Button is released before the next call
    pin_states["KEY_PRESS"] = True  # released

    # Second call: pin is high but was previously low → latched press detected
    assert instance.check_for_low(key="KEY_PRESS")

    # State is cleared after detection
    assert instance._low_since_ms["KEY_PRESS"] is None

    # Subsequent call with pin still high returns False (no double-fire)
    assert not instance.check_for_low(key="KEY_PRESS")


def test_check_for_low_ignores_noise_within_debounce(monkeypatch):
    """A very brief low (within debounce window) that goes high is not
    treated as a valid press."""
    instance, pin_states = _make_instance_with_controllable_pins(monkeypatch)

    # Pin goes low briefly
    pin_states["KEY_PRESS"] = False
    assert not instance.check_for_low(key="KEY_PRESS")

    # Do NOT advance the timestamp – debounce window not met
    # (_low_since_ms stays at current time, so next check is within debounce)

    # Pin goes high immediately
    pin_states["KEY_PRESS"] = True

    # Should NOT return True because debounce threshold was not met
    assert not instance.check_for_low(key="KEY_PRESS")

    # State should be cleared
    assert instance._low_since_ms["KEY_PRESS"] is None


def test_check_for_low_latching_works_with_keys_list(monkeypatch):
    """Latching works when checking multiple keys at once (the ANYCLICK
    pattern used in camera preview)."""
    instance, pin_states = _make_instance_with_controllable_pins(monkeypatch)

    anyclick = ["KEY_PRESS", "KEY1", "KEY2", "KEY3"]

    # KEY1 is briefly pressed
    pin_states["KEY1"] = False
    assert not instance.check_for_low(keys=anyclick)

    # Simulate time passing beyond debounce threshold
    instance._low_since_ms["KEY1"] = int(time.time() * 1000) - 20

    # KEY1 is released
    pin_states["KEY1"] = True

    # Should detect the latched press
    assert instance.check_for_low(keys=anyclick)


def test_wait_for_clears_low_state_preventing_phantom_press(monkeypatch):
    """After wait_for() returns a key press, check_for_low() must not see
    stale _low_since_ms state and report a phantom press (the 'camera
    captures immediately' bug)."""
    instance, pin_states = _make_instance_with_controllable_pins(monkeypatch)

    # wait_for() does ``from seedsigner.controller import Controller`` at
    # runtime.  Provide a lightweight mock module so we don't pull in heavy
    # dependencies (embit, etc.) that may not be installed in the test env.
    mock_controller = SimpleNamespace(
        screensaver_activation_ms=999_999_999,
        is_screensaver_running=False,
    )
    mock_controller_module = SimpleNamespace(
        Controller=SimpleNamespace(get_instance=lambda: mock_controller),
    )
    monkeypatch.setitem(sys.modules, "seedsigner.controller", mock_controller_module)

    # Pre-set the pin LOW and back-date _low_since_ms so wait_for() will
    # detect the press immediately (no threading needed).
    pin_states["KEY_PRESS"] = False
    instance._low_since_ms["KEY_PRESS"] = int(time.time() * 1000) - 20

    result = instance.wait_for(keys=["KEY_PRESS"])
    assert result == "KEY_PRESS"

    # wait_for() must have cleared _low_since_ms for the returned key
    assert instance._low_since_ms["KEY_PRESS"] is None

    # Now simulate the user releasing the button (as happens during screen
    # transition to the camera preview)
    pin_states["KEY_PRESS"] = True

    # check_for_low must NOT report a phantom press
    assert not instance.check_for_low(key="KEY_PRESS")
