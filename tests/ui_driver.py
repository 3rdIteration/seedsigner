"""
    In-process UI test driver: run real Views and Screens with injected button
    presses and simulated camera frames.

    The normal flow tests (FlowTest) mock View.run_screen(), so Screens are never
    constructed -- screen-construction bugs and input-handling regressions can only
    be caught on-device or by the screenshot generator. This driver closes that gap:
    it swaps the hardware singletons (Renderer, HardwareButtons, Camera) for test
    stand-ins while leaving every line of application code untouched, so a flow test
    marked with real_screens=True drives actual Screens through their real _run()
    loops using a scripted list of button presses.

    Components:
      * make_test_renderer(): Renderer stand-in with a real in-memory PIL canvas;
        records every frame shown (session.renderer.frames).
      * ScriptedHardwareButtons: plays back a flat script of key presses, one per
        wait_for() call, across all screens in the flow. check_for_low() is served
        from a separate per-call poll feed for screens that poll instead of block.
      * MockCameraFeed: Camera stand-in playing back scripted frames (preview reads
        peek at the head; entropy reads consume).

    Usage with FlowTest:
        session = UISession(script=[KEY_DOWN, KEY_PRESS, ...])
        self.run_sequence([
            FlowStep(...),
            FlowStep(SomeView, real_screens=True),
        ], ui_session=session)
        assert len(session.renderer.frames) > 0

    Usage standalone (drive one Screen directly):
        with UISession(script=[...], camera_frames=[...]) as session:
            screen = SomeScreen(...)
            result = screen.display()
"""

import threading
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from PIL import Image, ImageDraw

# Must import test base before the Controller (sets up the hardware module mocks)
from base import BaseTest  # noqa: F401


class ScriptExhaustedError(Exception):
    """The screen asked for input (or a camera frame) the script didn't provide."""
    pass



def make_test_renderer(width=240, height=240) -> MagicMock:
    """A Renderer stand-in with a real in-memory canvas. Records every shown frame."""
    renderer = MagicMock()
    renderer.canvas_width = width
    renderer.canvas_height = height
    renderer.is_screenshot_generator = False

    canvas = Image.new("RGB", (width, height))
    renderer.canvas = canvas
    renderer.draw = ImageDraw.Draw(canvas)
    renderer.lock = threading.RLock()
    renderer.frames = []

    def show_image(image=None, alpha_overlay=None, is_background_thread=False):
        if image is not None:
            renderer.canvas.paste(image)
        renderer.frames.append(renderer.canvas.copy())

    renderer.show_image.side_effect = show_image
    return renderer



class ScriptedHardwareButtons(MagicMock):
    """
    HardwareButtons stand-in. `script` is a flat list of key constants (from the
    mocked HardwareButtonsConstants); each wait_for() call consumes and returns the
    next entry, regardless of which keys the screen says it's watching -- screens in
    these flows block on one input at a time, so the script maps 1:1 to user actions.

    `poll_responses` is an optional list of bools served one-per-call by
    check_for_low(), for screens that poll rather than block (e.g. image entropy).
    """

    def __init__(self, script=None, poll_responses=None):
        super().__init__()
        self._script = list(script or [])
        self._polls = list(poll_responses or [])
        self.override_ind = False
        # A real float: background threads (e.g. WipeTimerThread) read this and do
        # arithmetic on it; a bare MagicMock attribute would raise TypeError there.
        import time as _time
        self.last_input_time = _time.time() * 1000

    def update_last_input_time(self):
        import time as _time
        self.last_input_time = _time.time() * 1000

    @property
    def remaining_script(self) -> list:
        return list(self._script)

    def wait_for(self, keys=None):
        if self.override_ind:
            self.override_ind = False
            from seedsigner.hardware.buttons import HardwareButtonsConstants
            return HardwareButtonsConstants.OVERRIDE
        if not self._script:
            raise ScriptExhaustedError(
                "wait_for() called but the button script is exhausted; the screen is "
                "waiting for input the test didn't provide"
            )
        return self._script.pop(0)

    def check_for_low(self, key=None, keys=None):
        if not self._polls:
            raise ScriptExhaustedError(
                "check_for_low() called but no poll_responses were scripted; screens "
                "that poll for input need a poll_responses list on the UISession"
            )
        return self._polls.pop(0)

    def has_any_input(self):
        return bool(self._script) or bool(self._polls)



class MockCameraFeed(MagicMock):
    """
    Camera stand-in playing back scripted frames. preview=True reads peek at the head
    of the feed (the display frame); other reads consume (entropy frames).
    """

    def __init__(self, frames=None):
        super().__init__()
        self._frames = list(frames or [])

    @property
    def remaining_frames(self) -> int:
        return len(self._frames)

    def read_video_stream(self, as_image=False, preview=False):
        if not self._frames:
            raise ScriptExhaustedError(
                "read_video_stream() called but the camera frame feed is exhausted"
            )
        if preview:
            return self._frames[0]
        return self._frames.pop(0)



class UISession:
    """
    Context manager that swaps the hardware singletons for test stand-ins.

    * renderer: real-canvas Renderer recording frames (session.renderer.frames)
    * buttons: ScriptedHardwareButtons playing back `script` / `poll_responses`
    * camera: MockCameraFeed playing back `camera_frames` (when provided)

    Also configures the mocked HardwareButtonsConstants list attributes that screen
    input loops concatenate at call time (KEYS__ANYCLICK, KEYS__LEFT_RIGHT_UP_DOWN),
    restoring them on exit.
    """

    def __init__(self, script=None, poll_responses=None, camera_frames=None, canvas_size=(240, 240)):
        self.renderer = make_test_renderer(*canvas_size)
        self.buttons = ScriptedHardwareButtons(script=script, poll_responses=poll_responses)
        self.camera = MockCameraFeed(camera_frames) if camera_frames is not None else None

    def __enter__(self):
        from seedsigner.gui.renderer import Renderer
        from seedsigner.hardware.buttons import HardwareButtons, HardwareButtonsConstants

        self._patches = [
            patch.object(Renderer, "get_instance", return_value=self.renderer),
            patch.object(HardwareButtons, "get_instance", return_value=self.buttons),
        ]
        if self.camera is not None:
            from seedsigner.hardware.camera import Camera
            self._patches.append(patch.object(Camera, "get_instance", return_value=self.camera))

        # Screen input loops build their watch lists by concatenating these at call
        # time; the mocked module returns bare MagicMocks for them, which can't be
        # concatenated. Give them real lists of the (mock) key constants.
        self._saved_constants = {
            name: getattr(HardwareButtonsConstants, name, None)
            for name in ("KEYS__ANYCLICK", "KEYS__LEFT_RIGHT_UP_DOWN")
        }
        HardwareButtonsConstants.KEYS__ANYCLICK = [
            HardwareButtonsConstants.KEY_PRESS,
            HardwareButtonsConstants.KEY1,
            HardwareButtonsConstants.KEY2,
            HardwareButtonsConstants.KEY3,
        ]
        HardwareButtonsConstants.KEYS__LEFT_RIGHT_UP_DOWN = [
            HardwareButtonsConstants.KEY_LEFT,
            HardwareButtonsConstants.KEY_RIGHT,
            HardwareButtonsConstants.KEY_UP,
            HardwareButtonsConstants.KEY_DOWN,
        ]

        for p in self._patches:
            p.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        from seedsigner.hardware.buttons import HardwareButtonsConstants

        for name, value in self._saved_constants.items():
            if value is None:
                delattr(HardwareButtonsConstants, name)
            else:
                setattr(HardwareButtonsConstants, name, value)

        for p in reversed(self._patches):
            p.stop()
        return False



def make_noise_frame(width=240, height=240, seed=None) -> Image.Image:
    """A distinct non-blank frame; `seed` makes the content reproducible."""
    import os
    if seed is None:
        return Image.frombytes("RGBA", (width, height), os.urandom(width * height * 4))
    import random as _random
    rng = _random.Random(seed)
    return Image.frombytes(
        "RGBA", (width, height), bytes(rng.getrandbits(8) for _ in range(width * height * 4))
    )



# ---------------------------------------------------------------------------
# Button-script planning helpers
#
# These compute the flat list of key constants a UISession script needs to type
# text into the multi-keyboard entry screens (ToolsTextQRTextEntryScreen,
# ScanTypeEncryptionKeyScreen, SeedEncryptedQRMnemonicIDScreen) or a single-
# keyboard KeyboardScreen. The plan is derived by driving the *real* Keyboard
# objects of a throwaway screen instance through their real update_from_input()
# method, so it can't drift from the on-device behavior; and each plan is
# verified by replaying it against a fresh screen inside its own UISession
# before it's returned.
# ---------------------------------------------------------------------------


@contextmanager
def _renderer_patched():
    """Patch Renderer.get_instance() to a throwaway test renderer (for construction)."""
    from seedsigner.gui.renderer import Renderer
    with patch.object(Renderer, "get_instance", return_value=make_test_renderer()):
        yield



# Characters typed via additional keys rather than charset letters
_CHAR_TO_KEY_CODE = {" ": "SPACE"}


def _find_key(keyboard, char):
    """The Key object that types `char` on this keyboard (or None)."""
    code = _CHAR_TO_KEY_CODE.get(char, char)
    for row in keyboard.keys:
        for key in row:
            if key.code == code:
                return key
    return None



def plan_keyboard_script(keyboard, text) -> list:
    """
    Compute the joystick + KEY_PRESS sequence that types `text` on a single Keyboard.

    Uses only RIGHT/UP/DOWN movement (never LEFT), relying on WRAP_RIGHT to cycle
    within a row; every step is applied through the keyboard's real update_from_input()
    so the simulated selection state stays exactly in sync with what the screen will do.
    """
    from seedsigner.gui.keyboard import Keyboard
    from seedsigner.hardware.buttons import HardwareButtonsConstants

    if Keyboard.WRAP_RIGHT not in keyboard.auto_wrap:
        raise ValueError("plan_keyboard_script() requires a keyboard with WRAP_RIGHT auto-wrap")

    script = []
    for char in text:
        target_key = _find_key(keyboard, char)
        if target_key is None:
            raise ValueError(f"Character {char!r} is not on this keyboard's layout")

        # Move vertically toward the target row. We only ever move within range, so
        # an EXIT here means the plan is wrong (e.g. a screen without vertical keys).
        while keyboard.selected_key["y"] != target_key.index_y:
            move = HardwareButtonsConstants.KEY_DOWN if target_key.index_y > keyboard.selected_key["y"] else HardwareButtonsConstants.KEY_UP
            ret = keyboard.update_from_input(move)
            if ret in Keyboard.EXIT_DIRECTIONS:
                raise ValueError(f"Vertical navigation exited the keyboard while planning {char!r}")
            script.append(move)

        # Move horizontally within the row; with WRAP_RIGHT, RIGHT cycles through every key.
        row = keyboard.keys[keyboard.selected_key["y"]]
        cur_pos = row.index(keyboard.get_selected_key())
        tgt_pos = row.index(target_key)
        for _ in range((tgt_pos - cur_pos) % len(row)):
            ret = keyboard.update_from_input(HardwareButtonsConstants.KEY_RIGHT)
            if ret in Keyboard.EXIT_DIRECTIONS:
                raise ValueError(f"Horizontal navigation exited the keyboard while planning {char!r}")
            script.append(HardwareButtonsConstants.KEY_RIGHT)

        if _CHAR_TO_KEY_CODE.get(char, char) != keyboard.get_selected_key().code:
            raise ValueError(f"Keyboard simulation failed to land on {char!r}")

        # Lock in the character (the screen appends it on KEY_PRESS)
        script.append(HardwareButtonsConstants.KEY_PRESS)

    return script



# State of a multi-keyboard entry screen: (active_keyboard, button1_text, button2_text).
# The transitions below mirror ToolsTextQRTextEntryScreen._run() exactly.
_TEXT_ENTRY_INITIAL_STATE = ("abc", "ABC", "123")


def _text_entry_key1(state):
    kb, b1, b2 = state
    # Leaving a button-2 keyboard resets its button to the first of that cycle
    if kb == "digits":
        b2 = "123"
    elif kb == "sym1":
        b2 = "!@#"
    elif kb == "sym2":
        b2 = "*[]"
    if b1 == "abc":
        return ("abc", "ABC", b2)
    return ("ABC", "abc", b2)


def _text_entry_key2(state):
    kb, b1, b2 = state
    if kb == "abc":
        b1 = "abc"
    elif kb == "ABC":
        b1 = "ABC"
    if b2 == "123":
        return ("digits", b1, "!@#")
    if b2 == "!@#":
        return ("sym1", b1, "*[]")
    return ("sym2", b1, "123")


def _text_entry_switch_script(state, target_kb) -> list:
    """Shortest KEY1/KEY2 sequence from `state` to any state on `target_kb` (as move names)."""
    from collections import deque

    queue = deque([(state, [])])
    seen = {state}
    while queue:
        cur, path = queue.popleft()
        if cur[0] == target_kb:
            return path
        for name, transition in (("KEY1", _text_entry_key1), ("KEY2", _text_entry_key2)):
            nxt = transition(cur)
            if nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, path + [name]))
    raise ValueError(f"No keyboard switch sequence from {state} to {target_kb}")



def plan_text_entry_script(screen_cls, text, finish=True, **screen_kwargs) -> list:
    """
    Compute (and verify by replaying on a throwaway screen) the full button script for
    typing `text` into one of the multi-keyboard entry screens. Returns a flat list of
    key constants; ends with KEY3 (save) when finish=True.

    Supported screens: ToolsTextQRTextEntryScreen, ScanTypeEncryptionKeyScreen, and
    SeedEncryptedQRMnemonicIDScreen (identical keyboard layouts and input logic).
    """
    from seedsigner.hardware.buttons import HardwareButtonsConstants as K

    with _renderer_patched():
        sim_screen = screen_cls(**screen_kwargs)

    keyboards = {
        "abc": getattr(sim_screen, "keyboard_abc", None),
        "ABC": getattr(sim_screen, "keyboard_ABC", None),
        "digits": getattr(sim_screen, "keyboard_digits", None),
        "sym1": getattr(sim_screen, "keyboard_symbols_1", None),
        "sym2": getattr(sim_screen, "keyboard_symbols_2", None),
    }
    if any(kb is None for kb in keyboards.values()):
        raise TypeError(f"{screen_cls.__name__} doesn't have the expected multi-keyboard layout")

    script = []
    state = _TEXT_ENTRY_INITIAL_STATE
    for char in text:
        candidates = [name for name, kb in keyboards.items() if _find_key(kb, char) is not None]
        if not candidates:
            raise ValueError(f"Character {char!r} is not on any of {screen_cls.__name__}'s keyboards")

        best = min(candidates, key=lambda name: len(_text_entry_switch_script(state, name)))
        for move_name in _text_entry_switch_script(state, best):
            old_kb_name = state[0]
            state = (_text_entry_key1 if move_name == "KEY1" else _text_entry_key2)(state)
            # Mirror the screen's selection carry-over on keyboard swap
            keyboards[state[0]].set_selected_key_indices(
                x=keyboards[old_kb_name].selected_key["x"],
                y=keyboards[old_kb_name].selected_key["y"],
            )
            script.append(K.KEY1 if move_name == "KEY1" else K.KEY2)

        script += plan_keyboard_script(keyboards[state[0]], char)

    if finish:
        script.append(K.KEY3)

    # Verify the plan by replaying it against a fresh screen with real input handling.
    # Typed text is appended after any pre-filled initial value.
    initial_attr = next((a for a in ("textToEncode", "encryptionkey", "mnemonic_id") if a in screen_kwargs), None)
    expected_text = (screen_kwargs.get(initial_attr, "") + text) if initial_attr is not None else text

    with UISession(script=script) as session:
        result = screen_cls(**screen_kwargs).display()
    text_key = next((k for k in result if k != "is_back_button"), None)
    if text_key is None or result.get(text_key) != expected_text or "is_back_button" in result:
        raise ValueError(f"plan_text_entry_script replay failed for {text!r}: got {result}")

    return script



def plan_keyboard_screen_script(screen_cls, text, finish=True, **screen_kwargs) -> list:
    """
    Same as plan_text_entry_script() but for KeyboardScreen subclasses (a single keyboard;
    KEY3 save when show_save_button is set). Returns a flat list of key constants.
    """
    from seedsigner.hardware.buttons import HardwareButtonsConstants as K

    with _renderer_patched():
        sim_screen = screen_cls(**screen_kwargs)

    script = plan_keyboard_script(sim_screen.keyboard, text)
    if finish and getattr(sim_screen, "show_save_button", False):
        script.append(K.KEY3)

    with UISession(script=script) as session:
        result = screen_cls(**screen_kwargs).display()
    expected = text.strip()
    if result != expected:
        raise ValueError(f"plan_keyboard_screen_script replay failed for {text!r}: got {result!r}")

    return script
