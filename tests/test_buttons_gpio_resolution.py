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
# real module here, so pop any mock and force-import the real implementation.
_saved_buttons_mock = sys.modules.pop("seedsigner.hardware.buttons", None)
if isinstance(_saved_buttons_mock, MagicMock):
    # Also clear the attribute on the parent package so the real module can
    # be re-attached by the import machinery.
    import seedsigner.hardware
    if hasattr(seedsigner.hardware, "buttons") and isinstance(
        getattr(seedsigner.hardware, "buttons"), MagicMock
    ):
        delattr(seedsigner.hardware, "buttons")

buttons_module = importlib.import_module("seedsigner.hardware.buttons")


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
