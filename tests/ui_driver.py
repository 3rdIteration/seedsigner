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
        An entry may also be a DeferredInput token (Select, TypeWord), resolved one
        key at a time against the *live* Screen -- so a test says which option the
        user picked or which word they typed, rather than a KEY_DOWN count that
        silently rots when a menu or keyboard gains an entry.
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



class ScriptSelectionError(Exception):
    """A deferred script token couldn't be resolved against the screen asking for input."""
    pass



class DeferredInput:
    """
    A script entry that decides its keys from the *live* Screen rather than up front.

    ScriptedHardwareButtons calls next_key() once per wait_for(); the token stays at
    the head of the script until it returns None, at which point it is dropped and the
    script moves on. Because each key is chosen after seeing the screen's real state,
    these tokens self-correct instead of encoding a fixed key count that quietly means
    something different the next time a menu or keyboard layout changes.
    """

    # Guards a token that can never reach its target against looping forever.
    max_keys = 400

    def __init__(self):
        self._emitted = 0

    def next_key(self, screen, watched_keys=None):
        self._emitted += 1
        if self._emitted > self.max_keys:
            raise ScriptSelectionError(
                f"{self} gave up after {self.max_keys} keys without reaching its target "
                f"on {type(screen).__name__}"
            )
        return self._next_key(screen, watched_keys)

    def _next_key(self, screen, watched_keys):
        raise NotImplementedError



class Select(DeferredInput):
    """
    "Pick this option on whatever ButtonListScreen is running."

    `option` may be a ButtonOption (matched by identity, then by button_label), a
    plain label string, or an int index.
    """

    def __init__(self, option, click_key: str = None):
        super().__init__()
        self.option = option
        self.click_key = click_key
        self._clicked = False

    def __repr__(self):
        return f"Select({getattr(self.option, 'button_label', self.option)!r})"

    def _index_in(self, button_data: list) -> int:
        option = self.option
        if isinstance(option, int):
            if not 0 <= option < len(button_data):
                raise ScriptSelectionError(
                    f"{self}: index out of range for {len(button_data)} buttons"
                )
            return option

        for i, entry in enumerate(button_data):
            if entry is option:
                return i

        label = getattr(option, "button_label", option)
        matches = [i for i, entry in enumerate(button_data)
                   if getattr(entry, "button_label", entry) == label]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            available = [getattr(entry, "button_label", entry) for entry in button_data]
            raise ScriptSelectionError(f"{self} is not on this screen; options are {available}")
        raise ScriptSelectionError(f"{self} is ambiguous: matches indices {matches}")

    def _next_key(self, screen, watched_keys):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        if self._clicked:
            return None

        button_data = getattr(screen, "button_data", None)
        if button_data is None:
            raise ScriptSelectionError(
                f"{self} was scripted, but the screen asking for input is "
                f"{type(screen).__name__}, which has no button_data. Only "
                f"ButtonListScreen-style screens can be driven by Select(); script "
                f"explicit key constants for the rest."
            )

        # ButtonListScreen owns the highlighted row, and some screens pre-select one,
        # so read it rather than assuming the list starts at the top.
        if getattr(getattr(screen, "top_nav", None), "is_selected", False):
            # Focus sits on the BACK/power arrow; KEY_DOWN drops back into the list
            # without moving the selection.
            return K.KEY_DOWN

        target = self._index_in(button_data)
        current = getattr(screen, "selected_button", 0)

        if target != current:
            from seedsigner.gui.screens.screen import LargeButtonScreen
            if isinstance(screen, LargeButtonScreen):
                # 2-wide grid: UP/DOWN move by a whole row, LEFT/RIGHT within one.
                if target // 2 != current // 2:
                    return K.KEY_DOWN if target > current else K.KEY_UP
                return K.KEY_RIGHT if target > current else K.KEY_LEFT
            # ButtonListScreen: a flat list walked one row at a time.
            return K.KEY_DOWN if target > current else K.KEY_UP

        self._clicked = True
        click = self.click_key or K.KEY_PRESS
        if watched_keys is not None and click not in watched_keys:
            usable = [k for k in watched_keys if k in K.KEYS__ANYCLICK]
            if not usable:
                raise ScriptSelectionError(
                    f"{self}: screen isn't watching a click key ({watched_keys})"
                )
            click = usable[0]
        return click



class TypeWord(DeferredInput):
    """
    "Type this BIP-39 word on the running SeedMnemonicEntryScreen and select it."

    Walks the real keyboard to each letter in turn and locks it in, then scrolls the
    autocomplete list to the word and presses KEY2 to choose it. Every step is decided
    from the screen's own live state (`letters`, `keyboard.selected_key`,
    `possible_words`), so the letter-activation behaviour never has to be mirrored
    here -- which is exactly the part that would go stale.
    """

    def __init__(self, word: str):
        super().__init__()
        self.word = word
        self._selected = False

    def __repr__(self):
        return f"TypeWord({self.word!r})"

    def _next_key(self, screen, watched_keys):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        if self._selected:
            return None

        keyboard = getattr(screen, "keyboard", None)
        if keyboard is None or not hasattr(screen, "possible_words"):
            raise ScriptSelectionError(
                f"{self} was scripted, but the screen asking for input is "
                f"{type(screen).__name__}, not a SeedMnemonicEntryScreen."
            )

        # The screen keeps locked-in letters in `letters[:-1]`; `letters[-1]` is
        # whichever key the cursor is merely hovering over.
        locked = "".join(screen.letters[:-1]) if screen.letters else ""

        if len(locked) < len(self.word):
            if not self.word.startswith(locked):
                raise ScriptSelectionError(
                    f"{self}: the screen already holds {locked!r}, which is not a prefix "
                    f"of the word"
                )
            return self._key_toward(keyboard, self.word[len(locked)])

        # Whole word is entered; pick it out of the autocomplete list.
        possible = list(screen.possible_words)
        if self.word not in possible:
            raise ScriptSelectionError(
                f"{self}: not among the screen's matches after typing it ({possible[:5]})"
            )
        target = possible.index(self.word)
        current = screen.selected_possible_words_index
        if current > target:
            return K.KEY1   # scroll the matches list up
        if current < target:
            return K.KEY3   # scroll the matches list down

        self._selected = True
        return K.KEY2       # choose the highlighted match

    def _key_toward(self, keyboard, letter: str):
        """One step toward `letter`, or the click that locks it in."""
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        target = _find_key(keyboard, letter)
        if target is None:
            raise ScriptSelectionError(f"{self}: {letter!r} is not on the keyboard")

        return _step_toward(keyboard, target) or K.KEY_PRESS



class TypeKeys(DeferredInput):
    """
    "Type this string on the running KeyboardScreen."

    `text` is what the screen should end up holding, i.e. the *output* values -- for
    ToolsDiceEntropyEntryScreen that is "1".."6", not the dice glyphs its keys display
    (the screen's keys_to_values map is used to find the key for each value).

    Presses KEY3 to save at the end when the screen has a save button; screens that
    auto-return at return_after_n_chars (dice entropy) simply exit on the final press.
    """

    def __init__(self, text: str):
        super().__init__()
        self.text = text
        self._pressed = 0
        self._saved = False
        self._done = False

    def __repr__(self):
        preview = self.text if len(self.text) <= 12 else self.text[:12] + "..."
        return f"TypeKeys({preview!r})"

    def _next_key(self, screen, watched_keys):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        if self._done:
            return None

        if self._pressed >= len(self.text):
            # Everything is typed. A screen with a save button still needs the click;
            # one that auto-returns on the last character has already exited, so by now
            # `screen` is the next screen and this token is simply finished.
            if not self._saved and getattr(screen, "show_save_button", False) and hasattr(screen, "user_input"):
                self._saved = True
                return K.KEY3
            self._done = True
            return None

        keyboard = getattr(screen, "keyboard", None)
        if keyboard is None or not hasattr(screen, "user_input"):
            raise ScriptSelectionError(
                f"{self} was scripted, but the screen asking for input is "
                f"{type(screen).__name__}, not a KeyboardScreen."
            )

        value = self.text[self._pressed]
        key_char = self._key_char_for(screen, value)
        target = _find_key(keyboard, key_char)
        if target is None:
            raise ScriptSelectionError(f"{self}: no key produces {value!r} on this keyboard")

        move = _step_toward(keyboard, target)
        if move is None:
            self._pressed += 1
            return K.KEY_PRESS
        return move

    @staticmethod
    def _key_char_for(screen, value: str) -> str:
        """The key's display character for an output `value` (they differ on dice)."""
        mapping = getattr(screen, "keys_to_values", None)
        if not mapping:
            return value
        for key_char, mapped in mapping.items():
            if mapped == value:
                return key_char
        raise ScriptSelectionError(f"{value!r} is not in this screen's keys_to_values map")



class Back(DeferredInput):
    """
    "Leave the running screen by its back arrow."

    The plain BaseTopNavScreen info screens (Donate, Battery Info, System Info, Memory
    Info, Version) have no button list for Select() to work with: they exit by moving
    focus onto the top nav with KEY_LEFT/KEY_UP and clicking it
    (see BaseTopNavScreen._run). Works on ButtonListScreen-style screens too, where it
    is the "press BACK" gesture rather than choosing an option.
    """

    def __init__(self):
        super().__init__()
        self._clicked = False

    def __repr__(self):
        return "Back()"

    def _next_key(self, screen, watched_keys):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        if self._clicked:
            return None

        top_nav = getattr(screen, "top_nav", None)
        if top_nav is None:
            raise ScriptSelectionError(
                f"Back() was scripted, but {type(screen).__name__} has no top nav to "
                f"back out of."
            )
        if not getattr(top_nav, "show_back_button", False):
            raise ScriptSelectionError(
                f"Back() was scripted, but {type(screen).__name__} has no back button "
                f"(show_back_button is False)."
            )

        if not top_nav.is_selected:
            return K.KEY_UP

        self._clicked = True
        return K.KEY_PRESS



def select(*options) -> list:
    """Shorthand for a run of Select() tokens: `select(A, B, C)`."""
    return [Select(option) for option in options]


def type_words(words) -> list:
    """Shorthand for a run of TypeWord() tokens, one per mnemonic word."""
    return [TypeWord(word) for word in words]



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

    def __init__(self, script=None, poll_responses=None, screen_provider=None):
        super().__init__()
        self._script = list(script or [])
        self._polls = list(poll_responses or [])
        # Returns the Screen currently asking for input, so DeferredInput tokens can
        # be resolved against its real state. Supplied by UISession.
        self._screen_provider = screen_provider or (lambda: None)
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

        while True:
            if not self._script:
                raise ScriptExhaustedError(
                    "wait_for() called but the button script is exhausted; the screen is "
                    "waiting for input the test didn't provide"
                )
            entry = self._script[0]
            if not isinstance(entry, DeferredInput):
                return self._script.pop(0)

            key = entry.next_key(self._screen_provider(), keys)
            if key is None:
                # Token is finished; drop it and serve whatever comes next.
                self._script.pop(0)
                continue
            return key

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



def _assert_screen_can_exit(screen) -> None:
    """
    Fail fast on a screen that can never return.

    BaseTopNavScreen._run() spins on time.sleep(0.1) when a screen has neither a back
    nor a power button -- on device that is a screen you leave by other means, but in a
    test it is an unkillable loop that never asks for input, so the run would hang
    instead of failing. Name the problem instead.
    """
    from seedsigner.gui.screens.screen import BaseTopNavScreen

    if type(screen)._run is not BaseTopNavScreen._run:
        return  # has its own input loop; not the spinning case

    top_nav = getattr(screen, "top_nav", None)
    if top_nav is None:
        return
    if not getattr(top_nav, "show_back_button", False) and not getattr(top_nav, "show_power_button", False):
        raise ScriptSelectionError(
            f"{type(screen).__name__} has no back or power button, so its _run() loops "
            f"forever without ever asking for input. It cannot be driven by a UISession."
        )



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
        # The Screen currently running, so DeferredInput tokens can be resolved
        # against its real state (see _track_screen below).
        self.current_screen = None
        self.buttons = ScriptedHardwareButtons(
            script=script,
            poll_responses=poll_responses,
            screen_provider=lambda: self.current_screen,
        )
        self.camera = MockCameraFeed(camera_frames) if camera_frames is not None else None

    @property
    def remaining_script(self) -> list:
        """
        What the flow never consumed. A non-empty list at the end of a test means the
        flow asked for less input than the test scripted -- i.e. it did not go where
        the test says it went.
        """
        return self.buttons.remaining_script

    def _track_screen(self, real_display):
        """Wrap BaseScreen.display() so DeferredInput tokens can see the live Screen."""
        session = self

        def display(screen_self, *args, **kwargs):
            _assert_screen_can_exit(screen_self)
            previous = session.current_screen
            session.current_screen = screen_self
            try:
                return real_display(screen_self, *args, **kwargs)
            finally:
                session.current_screen = previous

        return display

    def __enter__(self):
        from seedsigner.gui.renderer import Renderer
        from seedsigner.gui.screens.screen import BaseScreen
        from seedsigner.hardware.buttons import HardwareButtons, HardwareButtonsConstants

        self._patches = [
            patch.object(Renderer, "get_instance", return_value=self.renderer),
            patch.object(HardwareButtons, "get_instance", return_value=self.buttons),
            patch.object(BaseScreen, "display", self._track_screen(BaseScreen.display)),
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



def _step_toward(keyboard, target_key):
    """
    The single key press that moves the keyboard's selection toward `target_key`,
    or None once it is already there.

    Vertical moves keep the current column and skip any row that has no key in it
    (Keyboard.get_key_below/above). So when the target row has no key in the column
    we are standing in, going "down" jumps straight past that row and coming back
    "up" jumps past it again -- an oscillation that never terminates. Step sideways
    onto a column the target row actually has before moving vertically.

    Callers apply the returned key to the real Keyboard (or let the real Screen do
    it) and call again, so the walk always reflects the keyboard's actual state.
    """
    from seedsigner.hardware.buttons import HardwareButtonsConstants as K

    if keyboard.get_selected_key() is target_key:
        return None

    cur_x = keyboard.selected_key["x"]
    cur_y = keyboard.selected_key["y"]

    if cur_y != target_key.index_y:
        if keyboard.get_key_at(cur_x, target_key.index_y) is None:
            # This column doesn't exist in the target row; slide along the current
            # row first (these keyboards auto-wrap right, so this always terminates).
            return K.KEY_RIGHT
        return K.KEY_DOWN if target_key.index_y > cur_y else K.KEY_UP

    # Right row: RIGHT cycles through it.
    return K.KEY_RIGHT



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

    # Any layout is crossed in far fewer moves than this; the cap turns a layout the
    # walk cannot solve into a named error instead of a hang.
    max_moves_per_char = 200

    script = []
    for char in text:
        target_key = _find_key(keyboard, char)
        if target_key is None:
            raise ValueError(f"Character {char!r} is not on this keyboard's layout")

        for _ in range(max_moves_per_char):
            move = _step_toward(keyboard, target_key)
            if move is None:
                break
            ret = keyboard.update_from_input(move)
            if ret in Keyboard.EXIT_DIRECTIONS:
                raise ValueError(f"Navigation exited the keyboard while planning {char!r}")
            script.append(move)
        else:
            raise ValueError(f"Could not navigate to {char!r} in {max_moves_per_char} moves")

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
