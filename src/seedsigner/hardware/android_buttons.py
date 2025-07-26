import time
from collections import deque


class HardwareButtonsConstants:
    KEY_UP = 1
    KEY_DOWN = 2
    KEY_LEFT = 3
    KEY_RIGHT = 4
    KEY_PRESS = 5
    KEY1 = 6
    KEY2 = 7
    KEY3 = 8
    OVERRIDE = 1000

    ALL_KEYS = [KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY_PRESS, KEY1, KEY2, KEY3]
    KEYS__LEFT_RIGHT_UP_DOWN = [KEY_LEFT, KEY_RIGHT, KEY_UP, KEY_DOWN]
    KEYS__ANYCLICK = [KEY_PRESS, KEY1, KEY2, KEY3]


class HardwareButtons:
    """Touchscreen-based button interface for Android."""

    def __init__(self, width: int = 320, height: int = 240):
        from kivy.core.window import Window
        self.width = width
        self.height = height
        self._queue = deque()
        self.override_ind = False
        Window.bind(on_touch_down=self._on_touch_down)

    def _on_touch_down(self, window, touch):
        x, y = touch.pos
        w, h = self.width, self.height
        key = None
        if y > h * 0.75:
            if x < w * 0.33:
                key = HardwareButtonsConstants.KEY1
            elif x > w * 0.66:
                key = HardwareButtonsConstants.KEY3
            else:
                key = HardwareButtonsConstants.KEY2
        elif y < h * 0.25:
            key = HardwareButtonsConstants.KEY_UP
        elif x < w * 0.25:
            key = HardwareButtonsConstants.KEY_LEFT
        elif x > w * 0.75:
            key = HardwareButtonsConstants.KEY_RIGHT
        else:
            key = HardwareButtonsConstants.KEY_PRESS
        self._queue.append(key)

    def wait_for(self, keys=None) -> int:
        if keys is None:
            keys = HardwareButtonsConstants.ALL_KEYS
        while True:
            if self.override_ind:
                self.override_ind = False
                return HardwareButtonsConstants.OVERRIDE
            if self._queue:
                key = self._queue.popleft()
                if key in keys:
                    return key
            time.sleep(0.01)

    def update_last_input_time(self):
        pass

    def trigger_override(self) -> bool:
        self.override_ind = True
        return True

    def check_for_low(self, key=None, keys=None) -> bool:
        if key:
            keys = [key]
        elif keys is None:
            keys = HardwareButtonsConstants.ALL_KEYS
        for k in list(self._queue):
            if k in keys:
                return True
        return False

    def has_any_input(self) -> bool:
        return len(self._queue) > 0
