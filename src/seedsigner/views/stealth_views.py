"""Tools > Stealth boot views.

Three screens:

* ``ToolsStealthBootView``         Status + Toggle + Edit sequence.
* ``ToolsStealthBootRecordView``   Record a new unlock combo.
* ``ToolsStealthBootConfirmRecordView``  Save / discard the combo.

The settings (``SETTING__STEALTH_BOOT`` and
``SETTING__STEALTH_UNLOCK_SEQUENCE``) are HIDDEN, so this is the only
place they get touched in the regular UI.
"""

from __future__ import annotations

from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    LargeIconStatusScreen,
    WarningScreen,
)
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.hardware.buttons import HardwareButtonsConstants
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.stealth.unlock import (
    InvalidSequenceError, parse_sequence,
)
from seedsigner.views.view import (
    BackStackView, Destination, MainMenuView, View,
)


_MAX_SEQUENCE_LEN = 12


def _is_enabled() -> bool:
    settings = Settings.get_instance()
    return settings.get_value(
        SettingsConstants.SETTING__STEALTH_BOOT
    ) == SettingsConstants.OPTION__ENABLED


def _set_enabled(enabled: bool) -> None:
    settings = Settings.get_instance()
    settings.set_value(
        SettingsConstants.SETTING__STEALTH_BOOT,
        SettingsConstants.OPTION__ENABLED if enabled
        else SettingsConstants.OPTION__DISABLED,
    )
    try:
        settings.save()
    except Exception:
        pass


def _get_sequence_csv() -> str:
    return Settings.get_instance().get_value(
        SettingsConstants.SETTING__STEALTH_UNLOCK_SEQUENCE
    )


def _set_sequence(keys: list) -> None:
    settings = Settings.get_instance()
    settings.set_value(
        SettingsConstants.SETTING__STEALTH_UNLOCK_SEQUENCE,
        ",".join(keys),
    )
    try:
        settings.save()
    except Exception:
        pass


class ToolsStealthBootView(View):
    TOGGLE = ButtonOption("Toggle on/off")
    EDIT = ButtonOption("Edit unlock sequence")
    DONE = ButtonOption("Done")

    def run(self):
        enabled = _is_enabled()
        try:
            seq = parse_sequence(_get_sequence_csv())
            seq_label = " ".join(s.replace("KEY_", "") for s in seq)
        except InvalidSequenceError:
            seq_label = "(invalid)"

        title = f"Stealth: {'ON' if enabled else 'OFF'}"
        button_data = [self.TOGGLE, self.EDIT, self.DONE]
        ret = self.run_screen(
            ButtonListScreen,
            title=title,
            is_button_text_centered=False,
            button_data=button_data,
            status_headline=None,
        )
        if ret == RET_CODE__BACK_BUTTON or button_data[ret] == self.DONE:
            return Destination(BackStackView)
        if button_data[ret] == self.TOGGLE:
            _set_enabled(not enabled)
            return Destination(ToolsStealthBootView, skip_current_view=True)
        if button_data[ret] == self.EDIT:
            return Destination(ToolsStealthBootRecordView)
        return Destination(BackStackView)


class ToolsStealthBootRecordView(View):
    """Record a fresh unlock sequence by capturing key presses one by one.

    A short status screen shows the keys pressed so far. KEY_PRESS commits
    the recording (must be 3..12 keys); pressing a side button while the
    recording length is still 0 backs out.
    """

    def run(self):
        from seedsigner.gui.renderer import Renderer
        from seedsigner.hardware.buttons import HardwareButtons
        from PIL import Image, ImageDraw

        renderer = Renderer.get_instance()
        buttons = HardwareButtons.get_instance()

        recorded: list = []

        def _render():
            with renderer.lock:
                img = Image.new(
                    "RGB",
                    (renderer.canvas_width, renderer.canvas_height),
                    color=(8, 12, 18),
                )
                draw = ImageDraw.Draw(img)
                draw.text((6, 4), "Record sequence", fill=(220, 220, 220))
                draw.text((6, 22),
                          "Press up to 12 keys.",
                          fill=(160, 180, 200))
                draw.text((6, 36),
                          "Press joystick to save.",
                          fill=(160, 180, 200))
                pretty = " ".join(
                    s.replace("KEY_", "").replace("KEY", "K")
                    for s in recorded
                ) or "(none yet)"
                draw.text((6, 70), f"Got: {pretty}", fill=(180, 220, 200))
                renderer.show_image(img)

        _render()
        keys = list(HardwareButtonsConstants.ALL_KEYS)

        while True:
            key = buttons.wait_for(keys)
            if key == HardwareButtonsConstants.KEY_PRESS:
                if 3 <= len(recorded) <= _MAX_SEQUENCE_LEN:
                    return Destination(
                        ToolsStealthBootConfirmRecordView,
                        view_args={"recorded": recorded},
                    )
                self.run_screen(
                    WarningScreen,
                    title="Too short" if len(recorded) < 3 else "Too long",
                    status_headline=None,
                    text=f"Need 3..{_MAX_SEQUENCE_LEN} keys, got {len(recorded)}.",
                    show_back_button=True,
                )
                _render()
                continue
            # Side keys also cancel when nothing recorded yet.
            if not recorded and key in (
                HardwareButtonsConstants.KEY1,
                HardwareButtonsConstants.KEY2,
                HardwareButtonsConstants.KEY3,
            ):
                return Destination(BackStackView)
            if len(recorded) < _MAX_SEQUENCE_LEN:
                recorded.append(key)
                _render()


class ToolsStealthBootConfirmRecordView(View):
    SAVE = ButtonOption("Save")
    DISCARD = ButtonOption("Discard")

    def __init__(self, recorded: list):
        super().__init__()
        self.recorded = list(recorded)

    def run(self):
        # Validate before showing the confirm screen.
        try:
            parse_sequence(",".join(self.recorded))
        except InvalidSequenceError as exc:
            self.run_screen(
                WarningScreen,
                title="Invalid",
                status_headline=None,
                text=str(exc)[:120],
                show_back_button=False,
            )
            return Destination(BackStackView)

        pretty = " ".join(s.replace("KEY_", "") for s in self.recorded)
        button_data = [self.SAVE, self.DISCARD]
        ret = self.run_screen(
            ButtonListScreen,
            title="Save sequence?",
            is_button_text_centered=False,
            button_data=button_data,
            status_headline=pretty[:60],
        )
        if ret == RET_CODE__BACK_BUTTON or button_data[ret] == self.DISCARD:
            return Destination(BackStackView)

        _set_sequence(self.recorded)
        self.run_screen(
            LargeIconStatusScreen,
            title="Saved",
            status_headline=None,
            text="New unlock sequence stored.",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsStealthBootView, skip_current_view=True)
