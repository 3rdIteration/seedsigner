import time
import logging

from dataclasses import dataclass
from gettext import gettext as _
from PIL import Image
from PIL.ImageOps import autocontrast
from typing import List


from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.gui.components import Button, CheckboxButton, CheckedSelectionButton, FontAwesomeIconConstants, Fonts, GUIConstants, Icon, IconButton, IconTextLine, SeedSignerIconConstants, TextArea, resize_image_to_fit
from seedsigner.gui.screens.scan_screens import ScanScreen
from seedsigner.gui.screens.screen import BaseScreen, BaseTopNavScreen, ButtonListScreen, ButtonOption, KeyboardScreen
from seedsigner.models.threads import BaseThread
from seedsigner.hardware.buttons import HardwareButtonsConstants
from seedsigner.hardware.camera import Camera
from seedsigner.models.settings import SettingsConstants

logger = logging.getLogger(__name__)


@dataclass
class SettingsEntryUpdateSelectionScreen(ButtonListScreen):
    display_name: str = None
    help_text: str = None
    checked_buttons: List[int] = None
    settings_entry_type: str = SettingsConstants.TYPE__ENABLED_DISABLED

    def __post_init__(self):
        self.title = _("Settings")
        self.is_bottom_list = True
        self.use_checked_selection_buttons = True
        if self.settings_entry_type == SettingsConstants.TYPE__MULTISELECT:
            self.Button_cls = CheckboxButton
        else:
            self.Button_cls = CheckedSelectionButton

        if not self.button_data:
            # Ensure at least one placeholder option so the screen can render
            # even when no real selection choices are available.
            self.button_data = [ButtonOption(_("No options available"))]

        super().__post_init__()

        self.components.append(TextArea(
            text=_(self.display_name),
            font_size=GUIConstants.BODY_FONT_MAX_SIZE,
            is_text_centered=True,
            auto_line_break=True,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING
        ))

        if self.help_text:
            prev_component_bottom = self.components[-1].screen_y + self.components[-1].height
            self.components.append(TextArea(
                text=_(self.help_text),
                font_color=GUIConstants.LABEL_FONT_COLOR,
                is_text_centered=True,
                screen_y=prev_component_bottom + GUIConstants.COMPONENT_PADDING,
                auto_line_break=True,
            ))



@dataclass
class SettingPBFDK2IterationsScreen(KeyboardScreen):
    def __post_init__(self):
        self.title = _("PBKDF2 Iter.(in units of 10k)")
        self.user_input = ""

        # Specify the keys in the keyboard
        self.rows = 3
        self.cols = 5
        self.keys_charset = "0123456789"
        self.show_save_button = True

        super().__post_init__()



@dataclass
class IOTestScreen(BaseTopNavScreen):
    def __post_init__(self):
        # TRANSLATOR_NOTE: Short for "Input/Output"; screen to make sure the buttons and camera are working properly
        self.title = _("I/O Test")
        self.show_back_button = False
        self.resolution = (96, 96)
        self.framerate = 10
        self.instructions_text = None
        super().__post_init__()

        # D-pad pictogram
        input_button_width = GUIConstants.BUTTON_HEIGHT + 2
        input_button_height = input_button_width + 2
        dpad_center_x = GUIConstants.EDGE_PADDING + input_button_width + GUIConstants.COMPONENT_PADDING
        dpad_center_y = int((self.canvas_height - input_button_height)/2)

        self.joystick_click_button = IconButton(
            icon_name=FontAwesomeIconConstants.CIRCLE,
            icon_size=GUIConstants.ICON_INLINE_FONT_SIZE - 6,
            width=input_button_width,
            height=input_button_height,
            screen_x=dpad_center_x,
            screen_y=dpad_center_y,
            outline_color=GUIConstants.ACCENT_COLOR,
        )
        self.components.append(self.joystick_click_button)

        self.joystick_up_button = IconButton(
            icon_name=SeedSignerIconConstants.CHEVRON_UP,
            icon_size=GUIConstants.ICON_INLINE_FONT_SIZE,
            width=input_button_width,
            height=input_button_height,
            screen_x=dpad_center_x,
            screen_y=dpad_center_y - input_button_height - GUIConstants.COMPONENT_PADDING,
            outline_color=GUIConstants.ACCENT_COLOR,
        )
        self.components.append(self.joystick_up_button)

        self.joystick_down_button = IconButton(
            icon_name=SeedSignerIconConstants.CHEVRON_DOWN,
            icon_size=GUIConstants.ICON_INLINE_FONT_SIZE,
            width=input_button_width,
            height=input_button_height,
            screen_x=dpad_center_x,
            screen_y=dpad_center_y + input_button_height + GUIConstants.COMPONENT_PADDING,
            outline_color=GUIConstants.ACCENT_COLOR,
        )
        self.components.append(self.joystick_down_button)

        self.joystick_left_button = IconButton(
            icon_name=SeedSignerIconConstants.CHEVRON_LEFT,
            icon_size=GUIConstants.ICON_INLINE_FONT_SIZE,
            width=input_button_width,
            height=input_button_height,
            screen_x=dpad_center_x - input_button_width - GUIConstants.COMPONENT_PADDING,
            screen_y=dpad_center_y,
            outline_color=GUIConstants.ACCENT_COLOR,
        )
        self.components.append(self.joystick_left_button)

        self.joystick_right_button = IconButton(
            icon_name=SeedSignerIconConstants.CHEVRON_RIGHT,
            icon_size=GUIConstants.ICON_INLINE_FONT_SIZE,
            width=input_button_width,
            height=input_button_height,
            screen_x=dpad_center_x + input_button_width + GUIConstants.COMPONENT_PADDING,
            screen_y=dpad_center_y,
            outline_color=GUIConstants.ACCENT_COLOR,
        )
        self.components.append(self.joystick_right_button)

        # Hardware keys UI
        font = Fonts.get_font(GUIConstants.get_button_font_name(), GUIConstants.get_button_font_size())
        (left, top, text_width, bottom) = font.getbbox(text=_("Clear"), anchor="ls")
        icon = Icon(
            icon_name=FontAwesomeIconConstants.CAMERA, 
            icon_size=GUIConstants.ICON_INLINE_FONT_SIZE,
        )
        key_button_width = text_width + 2*GUIConstants.COMPONENT_PADDING + GUIConstants.EDGE_PADDING
        key_button_height = icon.height + int(1.5*GUIConstants.COMPONENT_PADDING)
        key2_y = int(self.canvas_height/2) - int(key_button_height/2)

        self.key2_button = Button(
            # TRANSLATOR_NOTE: Blank the screen
            text=_("Clear"),   # Initialize with text to set vertical centering
            width=key_button_width,
            height=key_button_height,
            screen_x=self.canvas_width - key_button_width + GUIConstants.EDGE_PADDING,
            screen_y=key2_y,
            outline_color=GUIConstants.ACCENT_COLOR,
            is_scrollable_text=False,  # Text has to dynamically update, can't use scrollable Button
        )
        self.key2_button.text = " "  # but default state is empty
        self.components.append(self.key2_button)

        self.key1_button = IconButton(
            icon_name=FontAwesomeIconConstants.CAMERA,
            width=key_button_width,
            height=key_button_height,
            screen_x=self.canvas_width - key_button_width + GUIConstants.EDGE_PADDING,
            screen_y=key2_y - 3*GUIConstants.COMPONENT_PADDING - key_button_height,
            outline_color=GUIConstants.ACCENT_COLOR,
        )
        self.components.append(self.key1_button)

        self.key3_button = Button(
            text=_("Exit"),
            width=key_button_width,
            height=key_button_height,
            screen_x=self.canvas_width - key_button_width + GUIConstants.EDGE_PADDING,
            screen_y=key2_y + 3*GUIConstants.COMPONENT_PADDING + key_button_height,
            outline_color=GUIConstants.ACCENT_COLOR,
            is_scrollable_text=False,  # No help for l10n, but currently ScrollableTextLine interferes with the small button's left edge. (TODO:)
        )
        self.components.append(self.key3_button)


    def _run(self):
        input_log_labels = {
            HardwareButtonsConstants.KEY_UP: "KEY_UP",
            HardwareButtonsConstants.KEY_DOWN: "KEY_DOWN",
            HardwareButtonsConstants.KEY_LEFT: "KEY_LEFT",
            HardwareButtonsConstants.KEY_RIGHT: "KEY_RIGHT",
            HardwareButtonsConstants.KEY_PRESS: "KEY_PRESS",
            HardwareButtonsConstants.KEY1: "KEY1",
            HardwareButtonsConstants.KEY2: "KEY2",
            HardwareButtonsConstants.KEY3: "KEY3",
        }
        cur_selected_button = self.key1_button
        msg_height = GUIConstants.ICON_LARGE_BUTTON_SIZE + 2*GUIConstants.COMPONENT_PADDING
        camera_message = TextArea(
            text=_("Capturing image..."),
            font_size=GUIConstants.get_top_nav_title_font_size(),
            is_text_centered=True,
            height=msg_height,
            screen_y=int((self.canvas_height - msg_height)/ 2),
        )
        while True:
            input = self.hw_inputs.wait_for(keys=HardwareButtonsConstants.ALL_KEYS)
            logger.info("I/O test input: %s", input_log_labels.get(input, str(input)))

            if input == HardwareButtonsConstants.KEY1:
                # Note that there are three distinct screen updates that happen at
                # different times, therefore we claim the `Renderer.lock` three separate
                # times.
                cur_selected_button = self.key1_button

                with self.renderer.lock:
                    # Render edges around message box
                    self.image_draw.rectangle(
                        (
                            -1, int((self.canvas_height - msg_height)/ 2) - 1,
                            self.canvas_width + 1, int((self.canvas_height + msg_height)/ 2) + 1
                        ),
                        fill="black",
                        outline=GUIConstants.ACCENT_COLOR,
                        width=1,
                    )
                    cur_selected_button.is_selected = True
                    cur_selected_button.render()
                    camera_message.render()
                    self.renderer.show_image()

                # Snap a pic, render it as the background, re-render all onscreen elements
                camera = Camera.get_instance()
                try:
                    # Different camera drivers accept different mode sets. Try a few
                    # known-good profiles and use the first that yields a frame.
                    capture_profiles = [
                        {"resolution": (640, 480), "framerate": 12},
                        {"resolution": (480, 480), "framerate": 6},
                        {"resolution": (1280, 720), "framerate": 4},
                        {"resolution": (320, 240), "framerate": 12},
                    ]

                    # Reset the button state once before attempting capture.
                    with self.renderer.lock:
                        cur_selected_button.is_selected = False
                        cur_selected_button.render()
                        self.renderer.show_image()

                    background_frame = None
                    for profile in capture_profiles:
                        try:
                            camera.start_video_stream_mode(
                                resolution=profile["resolution"],
                                framerate=profile["framerate"],
                                format="bgr",
                            )
                            time.sleep(1.0)
                            for attempt in range(10):
                                background_frame = camera.read_video_stream(as_image=True, preview=True)
                                if background_frame is not None:
                                    break
                                time.sleep(0.2)
                            if background_frame is not None:
                                break
                        except Exception as e:
                            logger.info("I/O test camera profile failed (%s): %s", profile, e)
                        finally:
                            camera.stop_video_stream_mode()

                    if background_frame is None:
                        logger.warning("I/O test camera capture failed: no frame returned")
                        continue
                    display_version = autocontrast(
                        background_frame,
                        cutoff=2
                    )
                    body_height = self.canvas_height - self.top_nav.height
                    display_version = resize_image_to_fit(
                        display_version,
                        target_size_x=self.canvas_width,
                        target_size_y=body_height,
                        sampling_method=Image.Resampling.BICUBIC,
                    )
                    with self.renderer.lock:
                        self.canvas.paste(display_version, (0, self.top_nav.height))
                        self.key2_button.text = _("Clear")
                        for component in self.components:
                            component.render()
                        self.renderer.show_image()
                except Exception as e:
                    logger.warning("I/O test camera capture failed: %s", e)
                    continue

                continue

            elif input == HardwareButtonsConstants.KEY2:
                cur_selected_button = self.key2_button

                # Clear the background
                with self.renderer.lock:
                    cur_selected_button.is_selected = True
                    self._render()
                    self.renderer.show_image()

                    # And then re-render Key2 in its initial state
                    self.key2_button.text = " "
                    cur_selected_button.is_selected = False
                    cur_selected_button.render()
                    self.renderer.show_image()
                
                continue

            elif input == HardwareButtonsConstants.KEY3:
                # Exit
                cur_selected_button = self.key3_button
                cur_selected_button.is_selected = True
                with self.renderer.lock:
                    cur_selected_button.render()
                    self.renderer.show_image()
                    return
            
            elif input == HardwareButtonsConstants.KEY_PRESS:
                cur_selected_button = self.joystick_click_button

            elif input == HardwareButtonsConstants.KEY_UP:
                cur_selected_button = self.joystick_up_button

            elif input == HardwareButtonsConstants.KEY_DOWN:
                cur_selected_button = self.joystick_down_button

            elif input == HardwareButtonsConstants.KEY_LEFT:
                cur_selected_button = self.joystick_left_button

            elif input == HardwareButtonsConstants.KEY_RIGHT:
                cur_selected_button = self.joystick_right_button

            with self.renderer.lock:
                cur_selected_button.is_selected = True
                cur_selected_button.render()
                self.renderer.show_image()

            with self.renderer.lock:
                cur_selected_button.is_selected = False
                cur_selected_button.render()
                self.renderer.show_image()

            time.sleep(0.1)



@dataclass
class DonateScreen(BaseTopNavScreen):
    def __post_init__(self):
        self.title = _("Donate")
        super().__post_init__()

        self.components.append(TextArea(
            # TRANSLATOR_NOTE: If your language uses the percent sign ("%"), your translation must also use two percent signs ("%%") due to python formatting oddities. "100%%" will be rendered as "100%".
            text=_("SeedSigner is 100%% free & open source, funded solely by the Bitcoin community.\n\nDonate onchain or LN at:").replace("%%", "%"),
            screen_y=self.top_nav.height + 3*GUIConstants.COMPONENT_PADDING,
        ))

        self.components.append(TextArea(
            text="seedsigner.com",
            font_name=GUIConstants.get_body_font_name(),
            font_size=28,
            font_color=GUIConstants.ACCENT_COLOR,
            supersampling_factor=1,
            screen_y=self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING
        ))


@dataclass
class BatteryInfoScreen(BaseTopNavScreen):
    """Display live battery information from the UPS HAT."""

    def __post_init__(self):
        self.title = _("Battery Info")
        super().__post_init__()

        from seedsigner.hardware.battery_hat import BatteryHat
        self.battery_hat = BatteryHat.get_instance()

        self.info_font_size = min(
            GUIConstants.get_body_font_size() + 4,
            GUIConstants.BODY_FONT_MAX_SIZE,
        )

        start_y = self.top_nav.height + 2 * GUIConstants.COMPONENT_PADDING
        self.voltage_text = TextArea(
            text=_("Load Voltage: --"),
            is_text_centered=True,
            screen_y=start_y,
            font_size=self.info_font_size,
        )
        self.components.append(self.voltage_text)

        start_y += self.voltage_text.height + GUIConstants.COMPONENT_PADDING
        self.current_text = TextArea(
            text=_("Current: --"),
            is_text_centered=True,
            screen_y=start_y,
            font_size=self.info_font_size,
        )
        self.components.append(self.current_text)

        start_y += self.current_text.height + GUIConstants.COMPONENT_PADDING
        self.power_text = TextArea(
            text=_("Power: --"),
            is_text_centered=True,
            screen_y=start_y,
            font_size=self.info_font_size,
        )
        self.components.append(self.power_text)

        start_y += self.power_text.height + GUIConstants.COMPONENT_PADDING
        self.percent_text = TextArea(
            text=_("Percent: --%"),
            is_text_centered=True,
            screen_y=start_y,
            font_size=self.info_font_size,
        )
        self.components.append(self.percent_text)

        start_y += self.percent_text.height + GUIConstants.COMPONENT_PADDING
        self.curve_text = TextArea(
            text=_("Curve: --"),
            is_text_centered=True,
            screen_y=start_y,
            font_size=self.info_font_size,
        )
        self.components.append(self.curve_text)

        self.threads.append(BatteryInfoScreen.UpdateThread(self))

    def _replace_info_text(self, attribute: str, text: str) -> None:
        text_area = getattr(self, attribute)
        updated_area = TextArea(
            text=text,
            is_text_centered=True,
            screen_y=text_area.screen_y,
            font_size=self.info_font_size,
        )
        try:
            index = self.components.index(text_area)
        except ValueError:
            index = None
        if index is None:
            self.components.append(updated_area)
        else:
            self.components[index] = updated_area
        setattr(self, attribute, updated_area)
        updated_area.render()

    class UpdateThread(BaseThread):
        def __init__(self, screen):
            super().__init__()
            self.screen = screen
            self.battery_hat = screen.battery_hat

        def run(self):
            while self.keep_running:
                if not self.battery_hat.is_enabled():
                    time.sleep(5)
                    continue
                voltage = None
                current = None
                power = None
                percent = None
                if self.battery_hat.detected:
                    voltage = self.battery_hat.get_voltage()
                    current = self.battery_hat.get_current()
                    power = self.battery_hat.get_power()
                    percent = self.battery_hat.get_percent()
                with self.screen.renderer.lock:
                    if voltage is not None:
                        voltage_text = _("Load Voltage: {:.3f} V").format(voltage)
                    else:
                        voltage_text = _("Load Voltage: --")
                    if current is not None:
                        current_text = _("Current: {:.3f} A").format(current/1000)
                    else:
                        current_text = _("Current: --")
                    if power is not None:
                        power_text = _("Power: {:.3f} W").format(power)
                    else:
                        power_text = _("Power: --")
                    if percent is not None:
                        percent_text = _("Percent: {:.1f}%").format(percent)
                    else:
                        percent_text = _("Percent: --%")
                    curve_label = self.battery_hat.get_curve_label()
                    if curve_label:
                        curve_text = _("Curve: {}").format(curve_label)
                    else:
                        curve_text = _("Curve: default")
                    self.screen._replace_info_text("voltage_text", voltage_text)
                    self.screen._replace_info_text("current_text", current_text)
                    self.screen._replace_info_text("power_text", power_text)
                    self.screen._replace_info_text("percent_text", percent_text)
                    self.screen._replace_info_text("curve_text", curve_text)
                    self.screen.renderer.show_image()
                time.sleep(5)



@dataclass
class SystemInfoScreen(BaseTopNavScreen):
    system_serial: str = ""
    microsd_serial: str = ""
    platform_name: str = ""
    platform_variant: str = ""

    def __post_init__(self):
        self.title = _("System Info")
        super().__post_init__()

        info_lines = [
            _("Platform: {platform_name}").format(platform_name=self.platform_name),
            _("Variant: {platform_variant}").format(platform_variant=self.platform_variant),
            _("Serial (CPU): {system_serial}").format(system_serial=self.system_serial),
            _("Serial (MicroSD): {microsd_serial}").format(microsd_serial=self.microsd_serial),
        ]

        start_y = self.top_nav.height + 2 * GUIConstants.COMPONENT_PADDING
        line_spacing = GUIConstants.COMPONENT_PADDING

        for line in info_lines:
            text_area = TextArea(
                text=line,
                screen_x=GUIConstants.EDGE_PADDING,
                width=self.canvas_width - 2 * GUIConstants.EDGE_PADDING,
                is_text_centered=False,
                auto_line_break=True,
                screen_y=start_y,
            )
            self.components.append(text_area)
            start_y += text_area.height + line_spacing


@dataclass
class SettingsQRConfirmationScreen(ButtonListScreen):
    config_name: str = None
    title: str = _mft("Settings QR")
    status_message: str = _mft("Settings updated...")
    is_bottom_list: bool = True

    def __post_init__(self):
        # Customize defaults
        self.button_data = [ButtonOption("Home")]
        self.show_back_button = False
        super().__post_init__()

        start_y = self.top_nav.height + 20
        if self.config_name:
            self.config_name_textarea = TextArea(
                text=f'"{self.config_name}"',  # User-supplied string (from SettingsQR); don't wrap to translate
                is_text_centered=True,
                auto_line_break=True,
                screen_y=start_y
            )
            self.components.append(self.config_name_textarea)
            start_y = self.config_name_textarea.screen_y + 50
        
        self.components.append(TextArea(
            text=_(self.status_message),
            is_text_centered=True,
            auto_line_break=True,
            screen_y=start_y
        ))
