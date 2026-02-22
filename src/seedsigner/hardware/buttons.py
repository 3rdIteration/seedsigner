"""Hardware button abstraction supporting both periphery GPIO and desktop input.

This module exposes a :class:`HardwareButtons` singleton that hides the
differences between physical button input and desktop simulation input.
"""

import logging
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

DESKTOP_SCALE = 2
DESKTOP_LEFT_WIDTH = 160
DESKTOP_RIGHT_WIDTH = 80
DESKTOP_WIDTH = 240
DESKTOP_HEIGHT = 240
D_PAD_SIZE = 40
BTN_SIZE = 40
BTN_SPACING = 10


class HardwareButtons(Singleton):
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
            cls._instance = cls.__new__(cls)

            if USING_GPIO:
                hardware_config = Settings.get_platform_default_hardware_config()
                hardware_mapping = get_hardware_pin_mapping(hardware_config)
                pin_mapping = hardware_mapping["buttons"]
                cls._instance._gpio_pins = {}
                for name in cls.BUTTON_NAMES:
                    pin_selector = pin_mapping.get(name) or pin_mapping.get(name.lower())
                    if pin_selector is None:
                        raise KeyError(f"Missing hardware button mapping for '{name}'")
                    pin_bias = None
                    gpio_selector = pin_selector
                    # io_config.py button entries support either:
                    #   [chip, line]                -> no explicit bias
                    #   [chip, line, "pull_up"]     -> apply periphery bias
                    # and line-only selectors like [58] on platforms that expose
                    # global GPIO numbering through periphery.
                    if (
                        isinstance(pin_selector, list)
                        and len(pin_selector) > 2
                        and isinstance(pin_selector[-1], str)
                    ):
                        pin_bias = pin_selector[-1]
                        gpio_selector = pin_selector[:-1]
                    if pin_bias:
                        cls._instance._gpio_pins[name] = GPIO(*gpio_selector, "in", bias=pin_bias)
                    else:
                        cls._instance._gpio_pins[name] = GPIO(*gpio_selector, "in")
            else:
                if pygame is None:
                    raise ModuleNotFoundError(
                        "pygame is required for desktop input; install requirements-desktop.txt"
                    )
                pygame.init()
                cls._instance.scale = DESKTOP_SCALE
                cls._instance.key_map = {
                    pygame.K_UP: HardwareButtons.KEY_UP_PIN,
                    pygame.K_DOWN: HardwareButtons.KEY_DOWN_PIN,
                    pygame.K_LEFT: HardwareButtons.KEY_LEFT_PIN,
                    pygame.K_RIGHT: HardwareButtons.KEY_RIGHT_PIN,
                    pygame.K_RETURN: HardwareButtons.KEY_PRESS_PIN,
                    pygame.K_1: HardwareButtons.KEY1_PIN,
                    pygame.K_2: HardwareButtons.KEY2_PIN,
                    pygame.K_3: HardwareButtons.KEY3_PIN,
                }
                cls._instance.reverse_map = {v: k for k, v in cls._instance.key_map.items()}
                cls._instance.button_rects = {
                    key: pygame.Rect(
                        x * cls._instance.scale,
                        y * cls._instance.scale,
                        w * cls._instance.scale,
                        h * cls._instance.scale,
                    )
                    for key, (x, y, w, h) in DESKTOP_BUTTON_LAYOUT.items()
                }

            cls._instance.override_ind = False
            cls._instance.cur_input = None
            cls._instance.cur_input_started = None
            cls._instance.last_input_time = int(time.time() * 1000)
            cls._instance.first_repeat_threshold = 225
            cls._instance.next_repeat_threshold = 250

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
                return HardwareButtonsConstants.OVERRIDE

            cur_time = int(time.time() * 1000)
            if cur_time - self.last_input_time > controller.screensaver_activation_ms and not controller.is_screensaver_running:
                controller.start_screensaver()
                self.update_last_input_time()
                time.sleep(self.next_repeat_threshold / 1000.0)
                continue

            if USING_GPIO:
                for key in keys:
                    if not self._gpio_pins[key].read():
                        if self.cur_input != key:
                            self.cur_input = key
                            self.cur_input_started = cur_time
                            self.last_input_time = cur_time
                            return key
                        else:
                            if cur_time - self.last_input_time > self.next_repeat_threshold:
                                self.cur_input_started = cur_time
                                self.last_input_time = cur_time
                                return key
                            elif cur_time - self.cur_input_started > self.first_repeat_threshold:
                                self.last_input_time = cur_time
                                return key
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

    def update_last_input_time(self):
        self.last_input_time = int(time.time() * 1000)

    def trigger_override(self) -> bool:
        self.override_ind = True

    def check_for_low(self, key=None, keys: List = None) -> bool:
        if key:
            keys = [key]

        if USING_GPIO:
            for key in keys:
                if not self._gpio_pins[key].read():
                    self.update_last_input_time()
                    return True
            return False

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
                if not self._gpio_pins[key].read():
                    return True
            return False

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
