import logging
import time
from typing import Dict, List, Tuple

try:
    import RPi.GPIO as GPIO
    USING_GPIO = True
except ModuleNotFoundError:
    USING_GPIO = False
    GPIO = None
    try:
        import pygame  # type: ignore
    except ModuleNotFoundError:
        pygame = None

from seedsigner.models.singleton import Singleton

logger = logging.getLogger(__name__)

# Dimensions for the desktop simulation
DESKTOP_SCALE = 2  # Updated when the desktop display is created
DESKTOP_LEFT_WIDTH = 160
DESKTOP_RIGHT_WIDTH = 80
DESKTOP_WIDTH = 240
DESKTOP_HEIGHT = 240


class HardwareButtons(Singleton):
    if USING_GPIO and GPIO.RPI_INFO['P1_REVISION'] == 3:  # RPi with 40-pin GPIO
        logger.info("Detected 40pin GPIO (Rasbperry Pi 2 and above)")
        KEY_UP_PIN = 31
        KEY_DOWN_PIN = 35
        KEY_LEFT_PIN = 29
        KEY_RIGHT_PIN = 37
        KEY_PRESS_PIN = 33

        KEY1_PIN = 40
        KEY2_PIN = 38
        KEY3_PIN = 36

    elif USING_GPIO:  # Older 26-pin models
        logger.info("Assuming 26 Pin GPIO (Raspberry P1 1)")
        KEY_UP_PIN = 5
        KEY_DOWN_PIN = 11
        KEY_LEFT_PIN = 3
        KEY_RIGHT_PIN = 15
        KEY_PRESS_PIN = 7

        KEY1_PIN = 16
        KEY2_PIN = 12
        KEY3_PIN = 8

    else:  # Desktop/keyboard mode
        KEY_UP_PIN = 1
        KEY_DOWN_PIN = 2
        KEY_LEFT_PIN = 3
        KEY_RIGHT_PIN = 4
        KEY_PRESS_PIN = 5

        KEY1_PIN = 6
        KEY2_PIN = 7
        KEY3_PIN = 8


    @classmethod
    def set_desktop_scale(cls, scale: int) -> None:
        """Override the default scaling for desktop mode."""
        global DESKTOP_SCALE
        DESKTOP_SCALE = scale


    @classmethod
    def get_instance(cls):
        # This is the only way to access the one and only instance
        if cls._instance is None:
            cls._instance = cls.__new__(cls)

            if USING_GPIO:
                # init GPIO hardware
                GPIO.setmode(GPIO.BOARD)
                GPIO.setup(HardwareButtons.KEY_UP_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
                GPIO.setup(HardwareButtons.KEY_DOWN_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
                GPIO.setup(HardwareButtons.KEY_LEFT_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
                GPIO.setup(HardwareButtons.KEY_RIGHT_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
                GPIO.setup(HardwareButtons.KEY_PRESS_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
                GPIO.setup(HardwareButtons.KEY1_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
                GPIO.setup(HardwareButtons.KEY2_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
                GPIO.setup(HardwareButtons.KEY3_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)

                cls._instance.GPIO = GPIO
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

            # Track state over time so we can apply input delays/ignores as needed
            cls._instance.cur_input = None           # Track which direction or button was last pressed
            cls._instance.cur_input_started = None   # Track when that input began
            cls._instance.last_input_time = int(time.time() * 1000)  # How long has it been since the last input?
            cls._instance.first_repeat_threshold = 225  # Long-press time required before returning continuous input
            cls._instance.next_repeat_threshold = 250  # Amount of time where we no longer consider input a continuous hold

        return cls._instance


    @classmethod
    def get_instance_no_hardware(cls):
        # This is the only way to access the one and only instance
        if cls._instance is None:
            cls._instance = cls.__new__(cls)


    def wait_for(self, keys=[]) -> int:
        """
        Block execution until one of the target keys is pressed.

        Optionally override the wait by calling `trigger_override()`.
        """
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
                    if self.GPIO.input(key) == GPIO.LOW:
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
        """ Set the override flag to break out of the current `wait_for` loop """
        self.override_ind = True


    def check_for_low(self, key: int = None, keys: List[int] = None) -> bool:
        """ Returns True if one of the target keys/key is pressed """
        if key:
            keys = [key]

        if USING_GPIO:
            for key in keys:
                if self.GPIO.input(key) == self.GPIO.LOW:
                    self.update_last_input_time()
                    return True
            return False
        else:
            pygame.event.pump()
            pressed = pygame.key.get_pressed()
            for key in keys:
                pg_key = self.reverse_map.get(key)
                if pg_key and pressed[pg_key]:
                    self.update_last_input_time()
                    return True
            return False


    def has_any_input(self) -> bool:
        """ Returns True if any of the keys are pressed """
        if USING_GPIO:
            for key in HardwareButtonsConstants.ALL_KEYS:
                if self.GPIO.input(key) == GPIO.LOW:
                    return True
            return False
        else:
            pygame.event.pump()
            pressed = pygame.key.get_pressed()
            for key in HardwareButtonsConstants.ALL_KEYS:
                pg_key = self.reverse_map.get(key)
                if pg_key and pressed[pg_key]:
                    return True
            return False


# Coordinates for clickable desktop buttons (unscaled)
D_PAD_SIZE = 40
D_PAD_CENTER_X = DESKTOP_LEFT_WIDTH // 2
D_PAD_CENTER_Y = DESKTOP_HEIGHT // 2

BTN_SIZE = 40
BTN_SPACING = 10
BTN_X = DESKTOP_LEFT_WIDTH + DESKTOP_WIDTH + (DESKTOP_RIGHT_WIDTH - BTN_SIZE) // 2
BTN_TOP = DESKTOP_HEIGHT // 2 - (3 * BTN_SIZE + 2 * BTN_SPACING) // 2

DESKTOP_BUTTON_LAYOUT: Dict[int, Tuple[int, int, int, int]] = {
    # D-pad on the left
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
    # Function buttons stacked on the right
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


# class used as short hand for static button/channel lookup values
class HardwareButtonsConstants:
    if USING_GPIO and GPIO.RPI_INFO['P1_REVISION'] == 3:
        KEY_UP = 31
        KEY_DOWN = 35
        KEY_LEFT = 29
        KEY_RIGHT = 37
        KEY_PRESS = 33

        KEY1 = 40
        KEY2 = 38
        KEY3 = 36
    elif USING_GPIO:
        KEY_UP = 5
        KEY_DOWN = 11
        KEY_LEFT = 3
        KEY_RIGHT = 15
        KEY_PRESS = 7

        KEY1 = 16
        KEY2 = 12
        KEY3 = 8
    else:
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
