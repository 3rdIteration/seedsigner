"""Hardware button abstraction supporting both periphery GPIO and desktop input.

This module exposes a :class:`HardwareButtons` singleton that hides the
differences between physical button input and desktop simulation input.
"""

import logging
import os
import re
import stat
import threading
import time
from typing import Dict, List, Tuple

try:
    from periphery import GPIO
    USING_GPIO = True
except ModuleNotFoundError:
    USING_GPIO = False
    GPIO = None
    try:
        import pygame  # type: ignore
    except ModuleNotFoundError:
        pygame = None

from seedsigner.models.singleton import Singleton
from seedsigner.models.settings import Settings
from seedsigner.hardware.io_config import get_hardware_pin_mapping

logger = logging.getLogger(__name__)


class OverrideInterrupt(Exception):
    """Raised by :meth:`HardwareButtons.wait_for` when ``trigger_override()``
    is called from another thread.

    Caught at the :meth:`seedsigner.gui.screens.screen.BaseScreen.display`
    boundary, which translates it to ``RET_CODE__BACK_BUTTON``. This is the
    propagation path used by:

    - ``Controller._on_card_removed_redirect`` (card removed while the user
      is in a card view → main loop redirects to MainMenu).
    - ``Controller.handle_wipe_timeout`` (inactivity timeout → MainMenu).

    Returning a sentinel value from ``wait_for`` was the historic approach
    but it didn't work: ``ButtonListScreen._run``/``LargeButtonScreen._run``
    only compare ``user_input`` against the known KEY_* constants, so a
    return of ``1000`` falls through the ``elif`` chain and the screen
    loops back to ``wait_for``, which then resets the override flag.
    """


DESKTOP_SCALE = 2
DESKTOP_LEFT_WIDTH = 160
DESKTOP_RIGHT_WIDTH = 80
DESKTOP_WIDTH = 240
DESKTOP_HEIGHT = 240
D_PAD_SIZE = 40
BTN_SIZE = 40
BTN_SPACING = 10


class HardwareButtons(Singleton):
    _instance_lock = threading.Lock()

    KEY_UP_PIN = "KEY_UP"
    KEY_DOWN_PIN = "KEY_DOWN"
    KEY_LEFT_PIN = "KEY_LEFT"
    KEY_RIGHT_PIN = "KEY_RIGHT"
    KEY_PRESS_PIN = "KEY_PRESS"
    KEY1_PIN = "KEY1"
    KEY2_PIN = "KEY2"
    KEY3_PIN = "KEY3"

    BUTTON_NAMES = [
        KEY_UP_PIN,
        KEY_DOWN_PIN,
        KEY_LEFT_PIN,
        KEY_RIGHT_PIN,
        KEY_PRESS_PIN,
        KEY1_PIN,
        KEY2_PIN,
        KEY3_PIN,
    ]

    @staticmethod
    def _resolve_global_line_to_chip(line: int) -> tuple[str, int] | None:
        """Map a global GPIO line number to (gpiochip device path, line offset)."""
        gpio_class_root = "/sys/class/gpio"
        try:
            chip_entries = [name for name in os.listdir(gpio_class_root) if name.startswith("gpiochip")]
        except Exception:
            return None

        for chip in chip_entries:
            chip_dir = os.path.join(gpio_class_root, chip)
            try:
                with open(os.path.join(chip_dir, "base"), "r", encoding="utf-8") as f_base:
                    base = int(f_base.read().strip())
                with open(os.path.join(chip_dir, "ngpio"), "r", encoding="utf-8") as f_ngpio:
                    ngpio = int(f_ngpio.read().strip())
            except Exception:
                continue

            if base <= line < (base + ngpio):
                chip_path = HardwareButtons._resolve_sysfs_chip_to_devnode(chip_dir, chip)
                if chip_path is not None:
                    return chip_path, line - base
                return None
        return None

    @staticmethod
    def _resolve_sysfs_chip_to_devnode(chip_dir: str, chip_name: str) -> str | None:
        """Resolve a sysfs gpiochip entry to a real /dev/gpiochipN character device path."""
        # Preferred: match the sysfs chip's major:minor to an actual char device in /dev.
        try:
            with open(os.path.join(chip_dir, "dev"), "r", encoding="utf-8") as f_dev:
                major_minor = f_dev.read().strip()
            major_str, minor_str = major_minor.split(":", 1)
            target_major = int(major_str)
            target_minor = int(minor_str)
        except Exception:
            target_major = None
            target_minor = None

        try:
            dev_entries = [name for name in os.listdir("/dev") if name.startswith("gpiochip")]
        except Exception:
            dev_entries = []

        if target_major is not None and target_minor is not None:
            for dev_name in dev_entries:
                dev_path = os.path.join("/dev", dev_name)
                try:
                    st = os.stat(dev_path)
                except Exception:
                    continue
                if not stat.S_ISCHR(st.st_mode):
                    continue
                if os.major(st.st_rdev) == target_major and os.minor(st.st_rdev) == target_minor:
                    return dev_path

        # Fallback for environments where sysfs names already match /dev names.
        direct_path = os.path.join("/dev", chip_name)
        if os.path.exists(direct_path):
            return direct_path

        # Fallback: map by rank in ascending global base order when sysfs names
        # are base-numbered (e.g., gpiochip32) but /dev nodes are index-numbered
        # (e.g., gpiochip1).
        try:
            chip_entries = [name for name in os.listdir("/sys/class/gpio") if name.startswith("gpiochip")]
            chips_with_base = []
            for entry in chip_entries:
                try:
                    with open(
                        os.path.join("/sys/class/gpio", entry, "base"),
                        "r",
                        encoding="utf-8",
                    ) as f_base:
                        base = int(f_base.read().strip())
                except Exception:
                    continue
                chips_with_base.append((base, entry))
            chips_with_base.sort(key=lambda item: item[0])
            chip_rank = next((idx for idx, (_, name) in enumerate(chips_with_base) if name == chip_name), None)
            if chip_rank is None:
                return None

            dev_candidates = []
            for name in dev_entries:
                match = re.fullmatch(r"gpiochip(\d+)", name)
                if match:
                    dev_candidates.append((int(match.group(1)), os.path.join("/dev", name)))
            dev_candidates.sort(key=lambda item: item[0])
            if chip_rank < len(dev_candidates):
                return dev_candidates[chip_rank][1]
        except Exception:
            return None
        return None

    @classmethod
    def set_desktop_scale(cls, scale: int) -> None:
        global DESKTOP_SCALE
        DESKTOP_SCALE = scale

    @classmethod
    def set_desktop_dimensions(cls, width: int, height: int) -> None:
        global DESKTOP_WIDTH, DESKTOP_HEIGHT
        DESKTOP_WIDTH = width
        DESKTOP_HEIGHT = height
        _recalc_desktop_layout()
        if cls._instance is not None and not USING_GPIO:
            cls._instance.button_rects = {
                key: pygame.Rect(
                    x * cls._instance.scale,
                    y * cls._instance.scale,
                    w * cls._instance.scale,
                    h * cls._instance.scale,
                )
                for key, (x, y, w, h) in DESKTOP_BUTTON_LAYOUT.items()
            }

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is not None:
                    return cls._instance
                instance = cls.__new__(cls)

                try:
                    if USING_GPIO:
                        hardware_config = Settings.get_platform_default_hardware_config()
                        hardware_mapping = get_hardware_pin_mapping(hardware_config)
                        pin_mapping = hardware_mapping["buttons"]
                        instance._gpio_pins = {}
                        for name in cls.BUTTON_NAMES:
                            pin_selector = pin_mapping.get(name) or pin_mapping.get(name.lower())
                            if pin_selector is None:
                                raise KeyError(f"Missing hardware button mapping for '{name}'")
                            if pin_selector == "disabled":
                                logger.info("Button %s is disabled via io_config", name)
                                continue
                            pin_bias = None
                            gpio_selector = pin_selector
                            # io_config.json button entries support either:
                            #   [chip, line]                -> no explicit bias
                            #   [chip, line, "pull_up"]     -> apply periphery bias
                            #   [line, "pull_up"]           -> resolve global line to
                            #                                  gpiochip+offset and apply bias
                            # and line-only selectors like [58] on platforms that expose
                            # global GPIO numbering through periphery.
                            if (
                                isinstance(pin_selector, list)
                                and len(pin_selector) >= 2
                                and isinstance(pin_selector[-1], str)
                            ):
                                pin_bias = pin_selector[-1]
                                gpio_selector = pin_selector[:-1]
                            if (
                                pin_bias
                                and isinstance(gpio_selector, list)
                                and len(gpio_selector) == 1
                                and isinstance(gpio_selector[0], int)
                            ):
                                resolved = cls._resolve_global_line_to_chip(gpio_selector[0])
                                if resolved is not None:
                                    gpio_selector = list(resolved)
                                else:
                                    logger.warning(
                                        "Unable to resolve global GPIO line %s for %s; using global selector without bias",
                                        gpio_selector[0],
                                        name,
                                    )
                                    pin_bias = None
                                    gpio_selector = [gpio_selector[0]]
                            if isinstance(pin_selector, int):
                                gpio_selector = [pin_selector]
                            try:
                                if pin_bias:
                                    instance._gpio_pins[name] = GPIO(*gpio_selector, "in", bias=pin_bias)
                                else:
                                    instance._gpio_pins[name] = GPIO(*gpio_selector, "in")
                            except Exception as exc:
                                if pin_bias and (
                                    "resource busy" in str(exc).lower()
                                    or "invalid argument" in str(exc).lower()
                                ):
                                    logger.warning(
                                        "GPIO open with bias failed for %s selector=%s bias=%s (%s); retrying without bias",
                                        name,
                                        gpio_selector,
                                        pin_bias,
                                        exc,
                                    )
                                    instance._gpio_pins[name] = GPIO(*gpio_selector, "in")
                                else:
                                    raise
                    else:
                        if pygame is None:
                            raise ModuleNotFoundError(
                                "pygame is required for desktop input; install requirements-desktop.txt"
                            )
                        pygame.init()
                        instance.scale = DESKTOP_SCALE
                        instance.key_map = {
                            pygame.K_UP: HardwareButtons.KEY_UP_PIN,
                            pygame.K_DOWN: HardwareButtons.KEY_DOWN_PIN,
                            pygame.K_LEFT: HardwareButtons.KEY_LEFT_PIN,
                            pygame.K_RIGHT: HardwareButtons.KEY_RIGHT_PIN,
                            pygame.K_RETURN: HardwareButtons.KEY_PRESS_PIN,
                            pygame.K_1: HardwareButtons.KEY1_PIN,
                            pygame.K_2: HardwareButtons.KEY2_PIN,
                            pygame.K_3: HardwareButtons.KEY3_PIN,
                        }
                        instance.reverse_map = {v: k for k, v in instance.key_map.items()}
                        instance.button_rects = {
                            key: pygame.Rect(
                                x * instance.scale,
                                y * instance.scale,
                                w * instance.scale,
                                h * instance.scale,
                            )
                            for key, (x, y, w, h) in DESKTOP_BUTTON_LAYOUT.items()
                        }

                    instance.override_ind = False
                    instance.cur_input = None
                    instance.cur_input_started = None
                    instance.debounce_threshold_ms = 10
                    instance._low_since_ms = {name: None for name in cls.BUTTON_NAMES}
                    instance.last_input_time = int(time.time() * 1000)
                    instance.first_repeat_threshold = 225
                    instance.next_repeat_threshold = 250
                except Exception:
                    if hasattr(instance, "_gpio_pins"):
                        for pin in instance._gpio_pins.values():
                            try:
                                pin.close()
                            except Exception:
                                pass
                    raise

                cls._instance = instance

        return cls._instance

    @classmethod
    def get_instance_no_hardware(cls):
        if cls._instance is None:
            cls._instance = cls.__new__(cls)

    def wait_for(self, keys: List = []) -> int:
        from seedsigner.controller import Controller

        controller = Controller.get_instance()
        self.override_ind = False

        while True:
            if self.override_ind:
                self.override_ind = False
                raise OverrideInterrupt()

            cur_time = int(time.time() * 1000)
            if cur_time - self.last_input_time > controller.screensaver_activation_ms and not controller.is_screensaver_running:
                controller.start_screensaver()
                self.update_last_input_time()
                time.sleep(self.next_repeat_threshold / 1000.0)
                continue

            if USING_GPIO:
                for key in keys:
                    if key not in self._gpio_pins:
                        continue
                    is_low = not self._gpio_pins[key].read()
                    if is_low:
                        low_since = self._low_since_ms.get(key)
                        if low_since is None:
                            self._low_since_ms[key] = cur_time
                            continue
                        if cur_time - low_since < self.debounce_threshold_ms:
                            continue
                        if self.cur_input != key:
                            self.cur_input = key
                            self.cur_input_started = cur_time
                            self.last_input_time = cur_time
                            self._low_since_ms[key] = None
                            return key
                        else:
                            if cur_time - self.last_input_time > self.next_repeat_threshold:
                                self.cur_input_started = cur_time
                                self.last_input_time = cur_time
                                self._low_since_ms[key] = None
                                return key
                            elif cur_time - self.cur_input_started > self.first_repeat_threshold:
                                self.last_input_time = cur_time
                                self._low_since_ms[key] = None
                                return key
                    else:
                        self._low_since_ms[key] = None
                        if self.cur_input == key:
                            self.cur_input = None
                            self.cur_input_started = None
                time.sleep(0.01)
            else:
                for event in pygame.event.get():
                    if event.type == pygame.KEYDOWN:
                        mapped = self.key_map.get(event.key)
                    elif event.type == pygame.MOUSEBUTTONDOWN:
                        mapped = None
                        for key, rect in self.button_rects.items():
                            if rect.collidepoint(event.pos):
                                mapped = key
                                break
                    else:
                        mapped = None

                    if mapped in keys:
                        if self.cur_input != mapped:
                            self.cur_input = mapped
                            self.cur_input_started = cur_time
                            self.last_input_time = cur_time
                            return mapped
                        else:
                            if cur_time - self.last_input_time > self.next_repeat_threshold:
                                self.cur_input_started = cur_time
                                self.last_input_time = cur_time
                                return mapped
                            elif cur_time - self.cur_input_started > self.first_repeat_threshold:
                                self.last_input_time = cur_time
                                return mapped
                time.sleep(0.01)

    def poll(self, keys: List = []) -> str | None:
        """Non-blocking variant of :meth:`wait_for`.

        Returns the first key in ``keys`` currently pressed (with the
        same debounce semantics as ``wait_for``), or ``None`` if no
        listed key is down. Intended for screens that must coexist with
        another wait source (e.g. a background event listener plus a
        Cancel press).
        """
        cur_time = int(time.time() * 1000)

        if USING_GPIO:
            for key in keys:
                if key not in self._gpio_pins:
                    continue
                if self._gpio_pins[key].read():
                    # High means released; reset any debounce window.
                    self._low_since_ms[key] = None
                    continue
                low_since = self._low_since_ms.get(key)
                if low_since is None:
                    self._low_since_ms[key] = cur_time
                    continue
                if cur_time - low_since < self.debounce_threshold_ms:
                    continue
                self._low_since_ms[key] = None
                self.cur_input = key
                self.cur_input_started = cur_time
                self.last_input_time = cur_time
                return key
            return None

        # Pygame fallback (desktop). Drain pending events; return first
        # mapped match.
        if pygame is None:
            return None
        if threading.current_thread() is threading.main_thread():
            pygame.event.pump()
        for event in pygame.event.get():
            if event.type == pygame.KEYDOWN:
                mapped = self.key_map.get(event.key)
            elif event.type == pygame.MOUSEBUTTONDOWN:
                mapped = None
                for key, rect in self.button_rects.items():
                    if rect.collidepoint(event.pos):
                        mapped = key
                        break
            else:
                mapped = None
            if mapped in keys:
                self.cur_input = mapped
                self.cur_input_started = cur_time
                self.last_input_time = cur_time
                return mapped
        return None

    def update_last_input_time(self):
        self.last_input_time = int(time.time() * 1000)

    def trigger_override(self) -> bool:
        self.override_ind = True

    def check_for_low(self, key=None, keys: List = None) -> bool:
        if key:
            keys = [key]

        if USING_GPIO:
            for key in keys:
                if key not in self._gpio_pins:
                    continue
                cur_time = int(time.time() * 1000)
                is_low = not self._gpio_pins[key].read()
                if is_low:
                    low_since = self._low_since_ms.get(key)
                    if low_since is None:
                        self._low_since_ms[key] = cur_time
                        continue
                    if cur_time - low_since < self.debounce_threshold_ms:
                        continue
                    self._low_since_ms[key] = None
                    self.update_last_input_time()
                    return True
                else:
                    # Pin is high. If it was previously observed as low, the
                    # button was pressed and released between polling calls.
                    # Treat this as a valid press provided the debounce
                    # interval was met, so that brief clicks are not lost in
                    # slow polling loops (e.g. camera preview).
                    low_since = self._low_since_ms.get(key)
                    if low_since is not None:
                        self._low_since_ms[key] = None
                        if cur_time - low_since >= self.debounce_threshold_ms:
                            self.update_last_input_time()
                            return True
            return False

        # macOS Cocoa requires event.pump() on the main thread or it raises
        # NSInternalInconsistencyException. Off-thread callers (screensaver,
        # toast, animation threads) skip the pump; pressed-state queries
        # still work against whatever the last main-thread pump captured.
        if threading.current_thread() is threading.main_thread():
            pygame.event.pump()
        pressed = pygame.key.get_pressed()
        for key in keys:
            pg_key = self.reverse_map.get(key)
            if pg_key and pressed[pg_key]:
                self.update_last_input_time()
                return True
        return False

    def has_any_input(self) -> bool:
        if USING_GPIO:
            for key in HardwareButtonsConstants.ALL_KEYS:
                if key not in self._gpio_pins:
                    continue
                if not self._gpio_pins[key].read():
                    return True
            return False

        if threading.current_thread() is threading.main_thread():
            pygame.event.pump()
        pressed = pygame.key.get_pressed()
        for key in HardwareButtonsConstants.ALL_KEYS:
            pg_key = self.reverse_map.get(key)
            if pg_key and pressed[pg_key]:
                return True
        return False

    def __del__(self):
        if hasattr(self, "_gpio_pins"):
            for pin in self._gpio_pins.values():
                pin.close()


def _recalc_desktop_layout() -> None:
    global D_PAD_CENTER_X, D_PAD_CENTER_Y, BTN_X, BTN_TOP, DESKTOP_BUTTON_LAYOUT

    D_PAD_CENTER_X = DESKTOP_LEFT_WIDTH // 2
    D_PAD_CENTER_Y = DESKTOP_HEIGHT // 2
    BTN_X = DESKTOP_LEFT_WIDTH + DESKTOP_WIDTH + (DESKTOP_RIGHT_WIDTH - BTN_SIZE) // 2
    BTN_TOP = DESKTOP_HEIGHT // 2 - (3 * BTN_SIZE + 2 * BTN_SPACING) // 2
    DESKTOP_BUTTON_LAYOUT = {
        HardwareButtons.KEY_UP_PIN: (
            D_PAD_CENTER_X - D_PAD_SIZE // 2,
            D_PAD_CENTER_Y - D_PAD_SIZE * 3 // 2,
            D_PAD_SIZE,
            D_PAD_SIZE,
        ),
        HardwareButtons.KEY_DOWN_PIN: (
            D_PAD_CENTER_X - D_PAD_SIZE // 2,
            D_PAD_CENTER_Y + D_PAD_SIZE // 2,
            D_PAD_SIZE,
            D_PAD_SIZE,
        ),
        HardwareButtons.KEY_LEFT_PIN: (
            D_PAD_CENTER_X - D_PAD_SIZE * 3 // 2,
            D_PAD_CENTER_Y - D_PAD_SIZE // 2,
            D_PAD_SIZE,
            D_PAD_SIZE,
        ),
        HardwareButtons.KEY_RIGHT_PIN: (
            D_PAD_CENTER_X + D_PAD_SIZE // 2,
            D_PAD_CENTER_Y - D_PAD_SIZE // 2,
            D_PAD_SIZE,
            D_PAD_SIZE,
        ),
        HardwareButtons.KEY_PRESS_PIN: (
            D_PAD_CENTER_X - D_PAD_SIZE // 2,
            D_PAD_CENTER_Y - D_PAD_SIZE // 2,
            D_PAD_SIZE,
            D_PAD_SIZE,
        ),
        HardwareButtons.KEY1_PIN: (
            BTN_X,
            BTN_TOP,
            BTN_SIZE,
            BTN_SIZE,
        ),
        HardwareButtons.KEY2_PIN: (
            BTN_X,
            BTN_TOP + BTN_SIZE + BTN_SPACING,
            BTN_SIZE,
            BTN_SIZE,
        ),
        HardwareButtons.KEY3_PIN: (
            BTN_X,
            BTN_TOP + 2 * (BTN_SIZE + BTN_SPACING),
            BTN_SIZE,
            BTN_SIZE,
        ),
    }


_recalc_desktop_layout()


class HardwareButtonsConstants:
    KEY_UP = HardwareButtons.KEY_UP_PIN
    KEY_DOWN = HardwareButtons.KEY_DOWN_PIN
    KEY_LEFT = HardwareButtons.KEY_LEFT_PIN
    KEY_RIGHT = HardwareButtons.KEY_RIGHT_PIN
    KEY_PRESS = HardwareButtons.KEY_PRESS_PIN
    KEY1 = HardwareButtons.KEY1_PIN
    KEY2 = HardwareButtons.KEY2_PIN
    KEY3 = HardwareButtons.KEY3_PIN

    OVERRIDE = 1000

    ALL_KEYS = [
        KEY_UP,
        KEY_DOWN,
        KEY_LEFT,
        KEY_RIGHT,
        KEY_PRESS,
        KEY1,
        KEY2,
        KEY3,
    ]

    KEYS__LEFT_RIGHT_UP_DOWN = [KEY_LEFT, KEY_RIGHT, KEY_UP, KEY_DOWN]
    KEYS__ANYCLICK = [KEY_PRESS, KEY1, KEY2, KEY3]
