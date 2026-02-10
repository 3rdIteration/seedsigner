import logging
import os
import time
from typing import Dict, List

from periphery import GPIO

from seedsigner.models.singleton import Singleton

logger = logging.getLogger(__name__)


_LUCKFOX_BUTTON_MAPPINGS: Dict[str, Dict[str, int]] = {
    # luckfox-pico-pro-max mapping used by the original Luckfox integration branch
    "max": {
        "KEY_UP": 58,
        "KEY_DOWN": 53,
        "KEY_LEFT": 59,
        "KEY_RIGHT": 54,
        "KEY_PRESS": 52,
        "KEY1": 55,
        "KEY2": 43,
        "KEY3": 42,
    },
    # pico-mini can be selected explicitly via env var; defaults to max if not set.
    "mini": {
        "KEY_UP": 58,
        "KEY_DOWN": 53,
        "KEY_LEFT": 59,
        "KEY_RIGHT": 54,
        "KEY_PRESS": 52,
        "KEY1": 55,
        "KEY2": 43,
        "KEY3": 42,
    },
}


def _detect_luckfox_profile() -> str:
    profile = os.getenv("SEEDSIGNER_LUCKFOX_PROFILE", "").strip().lower()
    if profile in _LUCKFOX_BUTTON_MAPPINGS:
        return profile

    # Auto-detect from device-tree model when available.
    model_path = "/proc/device-tree/model"
    try:
        with open(model_path, "rb") as f:
            model = f.read().decode("utf-8", errors="ignore").lower()
        if "mini" in model:
            return "mini"
        if "max" in model:
            return "max"
    except FileNotFoundError:
        pass

    return "max"


class HardwareButtons(Singleton):
    @classmethod
    def get_instance(cls):
        # This is the only way to access the one and only instance
        if cls._instance is None:
            cls._instance = cls.__new__(cls)
            cls._instance._profile = _detect_luckfox_profile()

            pin_mapping = _LUCKFOX_BUTTON_MAPPINGS[cls._instance._profile]
            cls._instance.GPIO = {
                pin: GPIO(pin, "in") for pin in pin_mapping.values()
            }

            cls._instance.override_ind = False

            logger.info(
                "HardwareButtons initialized with Luckfox profile '%s'",
                cls._instance._profile,
            )

            # Track state over time so we can apply input delays/ignores as needed
            cls._instance.cur_input = None  # Track which direction or button was last pressed
            cls._instance.cur_input_started = None  # Track when that input began
            cls._instance.last_input_time = int(time.time() * 1000)
            cls._instance.first_repeat_threshold = 225
            cls._instance.next_repeat_threshold = 250

        return cls._instance

    def wait_for(self, keys=[]) -> int:
        """
        Block execution until one of the target keys is pressed.

        Optionally override the wait by calling `trigger_override()`.
        """
        # TODO: Refactor to keep control in the Controller and not here
        from seedsigner.controller import Controller

        controller = Controller.get_instance()
        self.override_ind = False

        while True:
            if self.override_ind:
                # Break out of the wait_for without waiting for user input
                self.override_ind = False
                return HardwareButtonsConstants.OVERRIDE

            cur_time = int(time.time() * 1000)
            if (
                cur_time - self.last_input_time > controller.screensaver_activation_ms
                and controller.is_screensaver_start_allowed
            ):
                # Start the screensaver. Will block execution until input detected.
                controller.start_screensaver()

                # We're back. Update last_input_time to now.
                self.update_last_input_time()

                # Freeze any further processing for a moment to avoid having the wakeup
                #   input register in the resumed UI.
                time.sleep(self.next_repeat_threshold / 1000.0)

                # Resume from a fresh loop
                continue

            # Check each candidate key to see if it was pressed
            for key in keys:
                if self.GPIO[key].read() is False:
                    if self.cur_input != key:
                        self.cur_input = key
                        self.cur_input_started = int(time.time() * 1000)
                        self.last_input_time = self.cur_input_started
                        return key

                    # Still pressing the same input
                    if cur_time - self.last_input_time > self.next_repeat_threshold:
                        self.cur_input_started = cur_time
                        self.last_input_time = cur_time
                        return key

                    if cur_time - self.cur_input_started > self.first_repeat_threshold:
                        self.last_input_time = cur_time
                        return key

            time.sleep(0.01)  # wait 10 ms to give CPU chance to do other things

    def update_last_input_time(self):
        self.last_input_time = int(time.time() * 1000)

    def trigger_override(self) -> bool:
        """Set the override flag to break out of the current `wait_for` loop"""
        self.override_ind = True

    def add_events(self, keys=[]):
        pass

    def check_for_low(self, key: int = None, keys: List[int] = None) -> bool:
        """Returns True if one of the target keys/key is pressed"""
        if key:
            keys = [key]
        for cur_key in keys:
            if self.GPIO[cur_key].read() is False:
                self.update_last_input_time()
                return True
        return False

    def has_any_input(self) -> bool:
        """Returns True if any of the keys are pressed"""
        for key in HardwareButtonsConstants.ALL_KEYS:
            if self.GPIO[key].read() is False:
                return True
        return False


class HardwareButtonsConstants:
    _profile = _detect_luckfox_profile()
    _pins = _LUCKFOX_BUTTON_MAPPINGS[_profile]

    KEY_UP = _pins["KEY_UP"]
    KEY_DOWN = _pins["KEY_DOWN"]
    KEY_LEFT = _pins["KEY_LEFT"]
    KEY_RIGHT = _pins["KEY_RIGHT"]
    KEY_PRESS = _pins["KEY_PRESS"]

    KEY1 = _pins["KEY1"]
    KEY2 = _pins["KEY2"]
    KEY3 = _pins["KEY3"]

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
