import math
import time

from dataclasses import dataclass
from gettext import gettext as _
from typing import Any
from PIL import Image, ImageDraw
from seedsigner.hardware.camera import Camera
from seedsigner.helpers.qr import QR
from seedsigner.gui.components import FontAwesomeIconConstants, Fonts, GUIConstants, IconTextLine, SeedSignerIconConstants, TextArea, Button, IconButton
from seedsigner.gui.keyboard import Keyboard, TextEntryDisplay
from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON, BaseScreen, BaseTopNavScreen, ButtonListScreen, KeyboardScreen, WarningEdgesMixin, ButtonOption
from seedsigner.hardware.buttons import HardwareButtonsConstants
from seedsigner.models.settings_definition import SettingsConstants, SettingsDefinition



@dataclass
class ToolsImageEntropyLivePreviewScreen(BaseScreen):
    def __post_init__(self):
        super().__post_init__()

        self.camera = Camera.get_instance()
        self.camera.start_video_stream_mode(resolution=(self.canvas_width, self.canvas_height), framerate=24, format="rgb")


    def _run(self):
        # save preview image frames to use as additional entropy below
        preview_images = []
        max_entropy_frames = 50
        instructions_font = Fonts.get_font(GUIConstants.get_body_font_name(), GUIConstants.get_button_font_size())

        while True:
            if self.hw_inputs.check_for_low(HardwareButtonsConstants.KEY_LEFT):
                # Have to manually update last input time since we're not in a wait_for loop
                self.hw_inputs.update_last_input_time()
                self.words = []
                self.camera.stop_video_stream_mode()
                return RET_CODE__BACK_BUTTON

            frame = self.camera.read_video_stream(as_image=True)

            if frame is None:
                # Camera probably isn't ready yet
                time.sleep(0.01)
                continue

            # Check for ANYCLICK to take final entropy image
            if self.hw_inputs.check_for_low(keys=HardwareButtonsConstants.KEYS__ANYCLICK):
                # Have to manually update last input time since we're not in a wait_for loop
                self.hw_inputs.update_last_input_time()
                self.camera.stop_video_stream_mode()

                with self.renderer.lock:
                    self.renderer.canvas.paste(frame)

                    self.renderer.draw.text(
                        xy=(
                            int(self.renderer.canvas_width/2),
                            self.renderer.canvas_height - GUIConstants.EDGE_PADDING
                        ),
                        text=_("Capturing image..."),
                        fill=GUIConstants.ACCENT_COLOR,
                        font=instructions_font,
                        stroke_width=4,
                        stroke_fill=GUIConstants.BACKGROUND_COLOR,
                        anchor="ms"
                    )
                    self.renderer.show_image()

                return preview_images

            # If we're still here, it's just another preview frame loop
            with self.renderer.lock:
                self.renderer.canvas.paste(frame)

                self.renderer.draw.text(
                    xy=(
                        int(self.renderer.canvas_width/2),
                        self.renderer.canvas_height - GUIConstants.EDGE_PADDING
                    ),
                    text="< " + _("back") + "  |  " + _("click a button"),  # TODO: Render with UI elements instead of text
                    fill=GUIConstants.BODY_FONT_COLOR,
                    font=instructions_font,
                    stroke_width=4,
                    stroke_fill=GUIConstants.BACKGROUND_COLOR,
                    anchor="ms"
                )
                self.renderer.show_image()

            if len(preview_images) == max_entropy_frames:
                # Keep a moving window of the last n preview frames; pop the oldest
                # before we add the currest frame.
                preview_images.pop(0)
            preview_images.append(frame)



@dataclass
class ToolsImageEntropyFinalImageScreen(BaseScreen):
    final_image: Image = None

    def _run(self):
        instructions_font = Fonts.get_font(GUIConstants.get_body_font_name(), GUIConstants.get_button_font_size())

        with self.renderer.lock:
            self.renderer.canvas.paste(self.final_image)

            # TRANSLATOR_NOTE: A prompt to the user to either accept or reshoot the image
            reshoot = _("reshoot")

            # TRANSLATOR_NOTE: A prompt to the user to either accept or reshoot the image
            accept = _("accept")
            self.renderer.draw.text(
                xy=(
                    int(self.renderer.canvas_width/2),
                    self.renderer.canvas_height - GUIConstants.EDGE_PADDING
                ),
                text=" < " + reshoot + "  |  " + accept + " > ",
                fill=GUIConstants.BODY_FONT_COLOR,
                font=instructions_font,
                stroke_width=4,
                stroke_fill=GUIConstants.BACKGROUND_COLOR,
                anchor="ms"
            )
            self.renderer.show_image()

        # LEFT = reshoot, RIGHT / ANYCLICK = accept
        input = self.hw_inputs.wait_for([HardwareButtonsConstants.KEY_LEFT, HardwareButtonsConstants.KEY_RIGHT] + HardwareButtonsConstants.KEYS__ANYCLICK)
        if input == HardwareButtonsConstants.KEY_LEFT:
            return RET_CODE__BACK_BUTTON



@dataclass
class ToolsDiceEntropyEntryScreen(KeyboardScreen):

    def __post_init__(self):
        # TRANSLATOR_NOTE: current roll number vs total rolls (e.g. roll 7 of 50)
        self.title = _("Dice Roll {}/{}").format(1, self.return_after_n_chars)

        # Specify the keys in the keyboard
        self.rows = 3
        self.cols = 3
        self.keyboard_font_name = GUIConstants.ICON_FONT_NAME__FONT_AWESOME
        self.keyboard_font_size = 36
        self.keys_charset = "".join([
            FontAwesomeIconConstants.DICE_ONE,
            FontAwesomeIconConstants.DICE_TWO,
            FontAwesomeIconConstants.DICE_THREE,
            FontAwesomeIconConstants.DICE_FOUR,
            FontAwesomeIconConstants.DICE_FIVE,
            FontAwesomeIconConstants.DICE_SIX,
        ])

        # Map Key display chars to actual output values
        self.keys_to_values = {
            FontAwesomeIconConstants.DICE_ONE: "1",
            FontAwesomeIconConstants.DICE_TWO: "2",
            FontAwesomeIconConstants.DICE_THREE: "3",
            FontAwesomeIconConstants.DICE_FOUR: "4",
            FontAwesomeIconConstants.DICE_FIVE: "5",
            FontAwesomeIconConstants.DICE_SIX: "6",
        }

        # Now initialize the parent class
        super().__post_init__()
    

    def update_title(self) -> bool:
        self.title = _("Dice Roll {}/{}").format(self.cursor_position + 1, self.return_after_n_chars)
        return True



@dataclass
class ToolsCalcFinalWordFinalizePromptScreen(ButtonListScreen):
    mnemonic_length: int = None
    num_entropy_bits: int = None

    def __post_init__(self):
        # TRANSLATOR_NOTE: Build the last word in a 12 or 24 word BIP-39 mnemonic seed phrase.
        self.title = _("Build Final Word")
        self.is_bottom_list = True
        self.is_button_text_centered = True
        super().__post_init__()

        self.components.append(TextArea(
            # TRANSLATOR_NOTE: Final word calc. `mnemonic_length` = 12 or 24. `num_bits` = 7 or 3 (bits of entropy in final word).
            text=_("The {mnemonic_length}th word is built from {num_bits} more entropy bits plus auto-calculated checksum.").format(mnemonic_length=self.mnemonic_length, num_bits=self.num_entropy_bits),
            screen_y=self.top_nav.height + int(GUIConstants.COMPONENT_PADDING/2),
        ))



@dataclass
class ToolsCoinFlipEntryScreen(KeyboardScreen):
    def __post_init__(self):
        # Override values set by the parent class
        # TRANSLATOR_NOTE: current coin-flip number vs total flips (e.g. flip 3 of 4)
        self.title = _("Coin Flip {}/{}").format(1, self.return_after_n_chars)

        # Specify the keys in the keyboard
        self.rows = 1
        self.cols = 4
        self.key_height = GUIConstants.get_top_nav_title_font_size() + 2 + 2*GUIConstants.EDGE_PADDING
        self.keys_charset = "10"

        # Now initialize the parent class
        super().__post_init__()
    
        self.components.append(TextArea(
            # TRANSLATOR_NOTE: How we call the "front" side result during a coin toss.
            text=_("Heads = 1"),
            screen_y = self.keyboard.rect[3] + 4*GUIConstants.COMPONENT_PADDING,
        ))
        self.components.append(TextArea(
            # TRANSLATOR_NOTE: How we call the "back" side result during a coin toss.
            text=_("Tails = 0"),
            screen_y = self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING,
        ))


    def update_title(self) -> bool:
        # l10n_note already done.
        self.title = _("Coin Flip {}/{}").format(self.cursor_position + 1, self.return_after_n_chars)
        return True



@dataclass
class ToolsCalcFinalWordScreen(ButtonListScreen):
    selected_final_word: str = None
    selected_final_bits: str = None
    checksum_bits: str = None
    actual_final_word: str = None

    def __post_init__(self):
        self.is_bottom_list = True
        super().__post_init__()

        # First what's the total bit display width and where do the checksum bits start?
        bit_font_size = GUIConstants.get_button_font_size() + 2
        font = Fonts.get_font(GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME, bit_font_size)
        (left, top, bit_display_width, bit_font_height) = font.getbbox("0" * 11, anchor="lt")
        (left, top, checksum_x, bottom) = font.getbbox("0" * (11 - len(self.checksum_bits)), anchor="lt")
        bit_display_x = int((self.canvas_width - bit_display_width)/2)
        checksum_x += bit_display_x

        # Display the user's additional entropy input
        if self.selected_final_word:
            selection_text = self.selected_final_word
            keeper_selected_bits = self.selected_final_bits[:11 - len(self.checksum_bits)]

            # The word's least significant bits will be rendered differently to convey
            # the fact that they're being discarded.
            discard_selected_bits = self.selected_final_bits[-1*len(self.checksum_bits):]
        else:
            # User entered coin flips or all zeros
            selection_text = self.selected_final_bits
            keeper_selected_bits = self.selected_final_bits

            # We'll append spacer chars to preserve the vertical alignment (most
            # significant n bits always rendered in same column)
            discard_selected_bits = "_" * (len(self.checksum_bits))

        # TRANSLATOR_NOTE: The additional entropy the user supplied (e.g. coin flips)
        your_input = _('Your input: "{}"').format(selection_text)
        self.components.append(TextArea(
            text=your_input,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING - 2,  # Nudge to last line doesn't get too close to "Next" button
            height_ignores_below_baseline=True,  # Keep the next line (bits display) snugged up, regardless of text rendering below the baseline
        ))

        # ...and that entropy's associated 11 bits
        screen_y = self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING
        first_bits_line = TextArea(
            text=keeper_selected_bits,
            font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            font_size=bit_font_size,
            edge_padding=0,
            screen_x=bit_display_x,
            screen_y=screen_y,
            is_text_centered=False,
        )
        self.components.append(first_bits_line)

        # Render the least significant bits that will be replaced by the checksum in a
        # de-emphasized font color.
        if "_" in discard_selected_bits:
            screen_y += int(first_bits_line.height/2)  # center the underscores vertically like hypens
        self.components.append(TextArea(
            text=discard_selected_bits,
            font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            font_color=GUIConstants.LABEL_FONT_COLOR,
            font_size=bit_font_size,
            edge_padding=0,
            screen_x=checksum_x,
            screen_y=screen_y,
            is_text_centered=False,
        ))

        # Show the checksum..
        self.components.append(TextArea(
            # TRANSLATOR_NOTE: A function of "x" to be used for detecting errors in "x"
            text=_("Checksum"),
            edge_padding=0,
            screen_y=first_bits_line.screen_y + first_bits_line.height + 2*GUIConstants.COMPONENT_PADDING,
        ))

        # ...and its actual bits. Prepend spacers to keep vertical alignment
        checksum_spacer = "_" * (11 - len(self.checksum_bits))

        screen_y = self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING

        # This time we de-emphasize the prepended spacers that are irrelevant
        self.components.append(TextArea(
            text=checksum_spacer,
            font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            font_color=GUIConstants.LABEL_FONT_COLOR,
            font_size=bit_font_size,
            edge_padding=0,
            screen_x=bit_display_x,
            screen_y=screen_y + int(first_bits_line.height/2),  # center the underscores vertically like hypens
            is_text_centered=False,
        ))

        # And especially highlight (orange!) the actual checksum bits
        self.components.append(TextArea(
            text=self.checksum_bits,
            font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            font_size=bit_font_size,
            font_color=GUIConstants.ACCENT_COLOR,
            edge_padding=0,
            screen_x=checksum_x,
            screen_y=screen_y,
            is_text_centered=False,
        ))

        # And now the *actual* final word after merging the bit data
        self.components.append(TextArea(
            # TRANSLATOR_NOTE: labeled presentation of the last word in a BIP-39 mnemonic seed phrase.
            text=_('Final Word: "{}"').format(self.actual_final_word),
            screen_y=self.components[-1].screen_y + self.components[-1].height + 2*GUIConstants.COMPONENT_PADDING,
            height_ignores_below_baseline=True,  # Keep the next line (bits display) snugged up, regardless of text rendering below the baseline
        ))

        # Once again show the bits that came from the user's entropy...
        num_checksum_bits = len(self.checksum_bits)
        user_component = self.selected_final_bits[:11 - num_checksum_bits]
        screen_y = self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING
        self.components.append(TextArea(
            text=user_component,
            font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            font_size=bit_font_size,
            edge_padding=0,
            screen_x=bit_display_x,
            screen_y=screen_y,
            is_text_centered=False,
        ))

        # ...and append the checksum's bits, still highlighted in orange
        self.components.append(TextArea(
            text=self.checksum_bits,
            font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            font_color=GUIConstants.ACCENT_COLOR,
            font_size=bit_font_size,
            edge_padding=0,
            screen_x=checksum_x,
            screen_y=screen_y,
            is_text_centered=False,
        ))



@dataclass
class ToolsCalcFinalWordDoneScreen(ButtonListScreen):
    final_word: str = None
    mnemonic_word_length: int = 12
    fingerprint: str = None

    def __post_init__(self):
        # Manually specify 12 vs 24 case for easier ordinal translation
        if self.mnemonic_word_length == 12:
            # TRANSLATOR_NOTE: a label for the last word of a 12-word BIP-39 mnemonic seed phrase
            self.title = _("12th Word")
        else:
            # TRANSLATOR_NOTE: a label for the last word of a 24-word BIP-39 mnemonic seed phrase
            self.title = _("24th Word")
        self.is_bottom_list = True

        super().__post_init__()

        self.components.append(TextArea(
            text=f"""\"{self.final_word}\"""",
            font_size=26,
            is_text_centered=True,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        ))

        self.components.append(IconTextLine(
            icon_name=SeedSignerIconConstants.FINGERPRINT,
            icon_color=GUIConstants.INFO_COLOR,
            # TRANSLATOR_NOTE: a label for the shortened Key-id of a BIP-32 master HD wallet
            label_text=_("fingerprint"),
            value_text=self.fingerprint,
            is_text_centered=True,
            screen_y=self.components[-1].screen_y + self.components[-1].height + 3*GUIConstants.COMPONENT_PADDING,
        ))



@dataclass
class ToolsAddressExplorerAddressTypeScreen(ButtonListScreen):
    fingerprint: str = None
    wallet_descriptor_display_name: Any = None
    script_type: str = None
    custom_derivation_path: str = None

    def __post_init__(self):
        # TRANSLATOR_NOTE: a label for the tool to explore public addresses for this seed.
        self.title = _("Address Explorer")
        self.is_bottom_list = True
        super().__post_init__()

        if self.fingerprint:
            self.components.append(IconTextLine(
                icon_name=SeedSignerIconConstants.FINGERPRINT,
                icon_color=GUIConstants.INFO_COLOR,
                # TRANSLATOR_NOTE: a label for the shortened Key-id of a BIP-32 master HD wallet
                label_text=_("Fingerprint"),
                value_text=self.fingerprint,
                screen_x=GUIConstants.EDGE_PADDING,
                screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
            ))

            if self.script_type != SettingsConstants.CUSTOM_DERIVATION:
                self.components.append(IconTextLine(
                    icon_name=SeedSignerIconConstants.DERIVATION,
                    # TRANSLATOR_NOTE: a label for the derivation-path into a BIP-32 HD wallet
                    label_text=_("Derivation"),
                    value_text=SettingsDefinition.get_settings_entry(attr_name=SettingsConstants.SETTING__SCRIPT_TYPES).get_selection_option_display_name_by_value(value=self.script_type),
                    screen_x=GUIConstants.EDGE_PADDING,
                    screen_y=self.components[-1].screen_y + self.components[-1].height + 2*GUIConstants.COMPONENT_PADDING,
                ))
            else:
                self.components.append(IconTextLine(
                    icon_name=SeedSignerIconConstants.DERIVATION,
                    # l10n_note already exists.
                    label_text=_("Derivation"),
                    value_text=self.custom_derivation_path,
                    screen_x=GUIConstants.EDGE_PADDING,
                    screen_y=self.components[-1].screen_y + self.components[-1].height + 2*GUIConstants.COMPONENT_PADDING,
                ))

        else:
            self.components.append(IconTextLine(
                # TRANSLATOR_NOTE: a label for a BIP-380-ish Output Descriptor
                label_text=_("Wallet descriptor"),
                value_text=self.wallet_descriptor_display_name,  # TODO: English text from embit (e.g. "1 / 2 multisig"); make l10 friendly
                is_text_centered=True,
                screen_x=GUIConstants.EDGE_PADDING,
                screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
            ))



@dataclass
class ToolsTextQRTextEntryScreen(BaseTopNavScreen):
    textToEncode: str = ""

    # Only used by the screenshot generator
    initial_keyboard: str = None

    KEYBOARD__LOWERCASE_BUTTON_TEXT = "abc"
    KEYBOARD__UPPERCASE_BUTTON_TEXT = "ABC"
    KEYBOARD__DIGITS_BUTTON_TEXT = "123"
    KEYBOARD__SYMBOLS_1_BUTTON_TEXT = "!@#"
    KEYBOARD__SYMBOLS_2_BUTTON_TEXT = "*[]"


    def __post_init__(self):
        if not self.title:
            self.title = _("Text to Encode")

        super().__post_init__()

        keys_lower = "abcdefghijklmnopqrstuvwxyz"
        keys_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        keys_number = "0123456789"

        # Present the most common/puncutation-related symbols & the most human-friendly
        #   symbols first (limited to 18 chars).
        keys_symbol_1 = """!@#$%&();:,.-+='"?"""

        # Isolate the more math-oriented or just uncommon symbols
        keys_symbol_2 = """^*[]{}_\\|<>/`~"""


        # Set up the keyboard params
        self.right_panel_buttons_width = 56

        max_cols = 9
        text_entry_display_y = self.top_nav.height
        text_entry_display_height = 30

        keyboard_start_y = text_entry_display_y + text_entry_display_height + GUIConstants.COMPONENT_PADDING
        self.keyboard_abc = Keyboard(
            draw=self.renderer.draw,
            charset=keys_lower,
            rows=4,
            cols=max_cols,
            rect=(
                GUIConstants.COMPONENT_PADDING,
                keyboard_start_y,
                self.canvas_width - GUIConstants.COMPONENT_PADDING - self.right_panel_buttons_width,
                self.canvas_height - GUIConstants.EDGE_PADDING
            ),
            additional_keys=[
                Keyboard.KEY_SPACE_5,
                Keyboard.KEY_CURSOR_LEFT,
                Keyboard.KEY_CURSOR_RIGHT,
                Keyboard.KEY_BACKSPACE
            ],
            auto_wrap=[Keyboard.WRAP_LEFT, Keyboard.WRAP_RIGHT]
        )

        self.keyboard_ABC = Keyboard(
            draw=self.renderer.draw,
            charset=keys_upper,
            rows=4,
            cols=max_cols,
            rect=(
                GUIConstants.COMPONENT_PADDING,
                keyboard_start_y,
                self.canvas_width - GUIConstants.COMPONENT_PADDING - self.right_panel_buttons_width,
                self.canvas_height - GUIConstants.EDGE_PADDING
            ),
            additional_keys=[
                Keyboard.KEY_SPACE_5,
                Keyboard.KEY_CURSOR_LEFT,
                Keyboard.KEY_CURSOR_RIGHT,
                Keyboard.KEY_BACKSPACE
            ],
            auto_wrap=[Keyboard.WRAP_LEFT, Keyboard.WRAP_RIGHT],
            render_now=False
        )

        self.keyboard_digits = Keyboard(
            draw=self.renderer.draw,
            charset=keys_number,
            rows=3,
            cols=5,
            rect=(
                GUIConstants.COMPONENT_PADDING,
                keyboard_start_y,
                self.canvas_width - GUIConstants.COMPONENT_PADDING - self.right_panel_buttons_width,
                self.canvas_height - GUIConstants.EDGE_PADDING
            ),
            additional_keys=[
                Keyboard.KEY_CURSOR_LEFT,
                Keyboard.KEY_CURSOR_RIGHT,
                Keyboard.KEY_BACKSPACE
            ],
            auto_wrap=[Keyboard.WRAP_LEFT, Keyboard.WRAP_RIGHT],
            render_now=False
        )

        self.keyboard_symbols_1 = Keyboard(
            draw=self.renderer.draw,
            charset=keys_symbol_1,
            rows=4,
            cols=6,
            rect=(
                GUIConstants.COMPONENT_PADDING,
                keyboard_start_y,
                self.canvas_width - GUIConstants.COMPONENT_PADDING - self.right_panel_buttons_width,
                self.canvas_height - GUIConstants.EDGE_PADDING
            ),
            additional_keys=[
                Keyboard.KEY_SPACE_2,
                Keyboard.KEY_CURSOR_LEFT,
                Keyboard.KEY_CURSOR_RIGHT,
                Keyboard.KEY_BACKSPACE
            ],
            auto_wrap=[Keyboard.WRAP_LEFT, Keyboard.WRAP_RIGHT],
            render_now=False
        )

        self.keyboard_symbols_2 = Keyboard(
            draw=self.renderer.draw,
            charset=keys_symbol_2,
            rows=4,
            cols=6,
            rect=(
                GUIConstants.COMPONENT_PADDING,
                keyboard_start_y,
                self.canvas_width - GUIConstants.COMPONENT_PADDING - self.right_panel_buttons_width,
                self.canvas_height - GUIConstants.EDGE_PADDING
            ),
            additional_keys=[
                Keyboard.KEY_SPACE_2,
                Keyboard.KEY_CURSOR_LEFT,
                Keyboard.KEY_CURSOR_RIGHT,
                Keyboard.KEY_BACKSPACE
            ],
            auto_wrap=[Keyboard.WRAP_LEFT, Keyboard.WRAP_RIGHT],
            render_now=False
        )

        self.text_entry_display = TextEntryDisplay(
            canvas=self.renderer.canvas,
            rect=(
                GUIConstants.EDGE_PADDING,
                text_entry_display_y,
                self.canvas_width - self.right_panel_buttons_width,
                text_entry_display_y + text_entry_display_height
            ),
            font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME_JP,
            cursor_mode=TextEntryDisplay.CURSOR_MODE__BAR,
            is_centered=False,
            cur_text=''.join(self.textToEncode)
        )

        # Nudge the buttons off the right edge w/padding
        hw_button_x = self.canvas_width - self.right_panel_buttons_width + GUIConstants.COMPONENT_PADDING

        # Calc center button position first
        hw_button_y = int((self.canvas_height - GUIConstants.BUTTON_HEIGHT)/2)

        self.hw_button1 = Button(
            text=self.KEYBOARD__UPPERCASE_BUTTON_TEXT,
            is_text_centered=False,
            font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            font_size=GUIConstants.get_button_font_size() + 4,
            width=self.right_panel_buttons_width,
            screen_x=hw_button_x,
            screen_y=hw_button_y - 3*GUIConstants.COMPONENT_PADDING - GUIConstants.BUTTON_HEIGHT,
            is_scrollable_text=False,
        )

        self.hw_button2 = Button(
            text=self.KEYBOARD__DIGITS_BUTTON_TEXT,
            is_text_centered=False,
            font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            font_size=GUIConstants.get_button_font_size() + 4,
            width=self.right_panel_buttons_width,
            screen_x=hw_button_x,
            screen_y=hw_button_y,
            is_scrollable_text=False,
        )

        self.hw_button3 = IconButton(
            icon_name=SeedSignerIconConstants.CHECK,
            icon_color=GUIConstants.SUCCESS_COLOR,
            width=self.right_panel_buttons_width,
            screen_x=hw_button_x,
            screen_y=hw_button_y + 3*GUIConstants.COMPONENT_PADDING + GUIConstants.BUTTON_HEIGHT,
            is_scrollable_text=False,
        )


    def _render(self):
        super()._render()

        # Change from the default lowercase keyboard for the screenshot generator
        if self.initial_keyboard == self.KEYBOARD__UPPERCASE_BUTTON_TEXT:
            cur_keyboard = self.keyboard_ABC
            self.hw_button1.text = self.KEYBOARD__LOWERCASE_BUTTON_TEXT

        elif self.initial_keyboard == self.KEYBOARD__DIGITS_BUTTON_TEXT:
            cur_keyboard = self.keyboard_digits
            self.hw_button2.text = self.KEYBOARD__SYMBOLS_1_BUTTON_TEXT

        elif self.initial_keyboard == self.KEYBOARD__SYMBOLS_1_BUTTON_TEXT:
            cur_keyboard = self.keyboard_symbols_1
            self.hw_button2.text = self.KEYBOARD__SYMBOLS_2_BUTTON_TEXT

        elif self.initial_keyboard == self.KEYBOARD__SYMBOLS_2_BUTTON_TEXT:
            cur_keyboard = self.keyboard_symbols_2
            self.hw_button2.text = self.KEYBOARD__DIGITS_BUTTON_TEXT
        
        else:
            cur_keyboard = self.keyboard_abc

        self.text_entry_display.render()
        self.hw_button1.render()
        self.hw_button2.render()
        self.hw_button3.render()
        cur_keyboard.render_keys()

        self.renderer.show_image()


    def _run(self):
        cursor_position = len(self.textToEncode)
        cur_keyboard = self.keyboard_abc
        cur_button1_text = self.KEYBOARD__UPPERCASE_BUTTON_TEXT
        cur_button2_text = self.KEYBOARD__DIGITS_BUTTON_TEXT

        # Start the interactive update loop
        while True:
            input = self.hw_inputs.wait_for(HardwareButtonsConstants.ALL_KEYS)

            keyboard_swap = False

            with self.renderer.lock:
                # Check our two possible exit conditions
                # TODO: note the unusual return value, consider refactoring to a Response object in the future
                if input == HardwareButtonsConstants.KEY3:
                    # Save!
                    # First light up key3
                    if len(self.textToEncode) > 0:
                        self.hw_button3.is_selected = True
                        self.hw_button3.render()
                        self.renderer.show_image()
                        return dict(textToEncode=self.textToEncode)

                elif input == HardwareButtonsConstants.KEY_PRESS and self.top_nav.is_selected:
                    # Back button clicked
                    return dict(textToEncode=self.textToEncode, is_back_button=True)

                # Check for keyboard swaps
                if input == HardwareButtonsConstants.KEY1:
                    # First light up key1
                    self.hw_button1.is_selected = True
                    self.hw_button1.render()

                    # Return to the same button2 keyboard, if applicable
                    if cur_keyboard == self.keyboard_digits:
                        cur_button2_text = self.KEYBOARD__DIGITS_BUTTON_TEXT
                    elif cur_keyboard == self.keyboard_symbols_1:
                        cur_button2_text = self.KEYBOARD__SYMBOLS_1_BUTTON_TEXT
                    elif cur_keyboard == self.keyboard_symbols_2:
                        cur_button2_text = self.KEYBOARD__SYMBOLS_2_BUTTON_TEXT

                    if cur_button1_text == self.KEYBOARD__LOWERCASE_BUTTON_TEXT:
                        self.keyboard_abc.set_selected_key_indices(x=cur_keyboard.selected_key["x"], y=cur_keyboard.selected_key["y"])
                        cur_keyboard = self.keyboard_abc
                        cur_button1_text = self.KEYBOARD__UPPERCASE_BUTTON_TEXT
                    else:
                        self.keyboard_ABC.set_selected_key_indices(x=cur_keyboard.selected_key["x"], y=cur_keyboard.selected_key["y"])
                        cur_keyboard = self.keyboard_ABC
                        cur_button1_text = self.KEYBOARD__LOWERCASE_BUTTON_TEXT
                    cur_keyboard.render_keys()

                    # Show the changes; this loop will have two renders
                    self.renderer.show_image()

                    keyboard_swap = True
                    ret_val = None

                elif input == HardwareButtonsConstants.KEY2:
                    # First light up key2
                    self.hw_button2.is_selected = True
                    self.hw_button2.render()
                    self.renderer.show_image()

                    # And reset for next redraw
                    self.hw_button2.is_selected = False

                    # Return to the same button1 keyboard, if applicable
                    if cur_keyboard == self.keyboard_abc:
                        cur_button1_text = self.KEYBOARD__LOWERCASE_BUTTON_TEXT
                    elif cur_keyboard == self.keyboard_ABC:
                        cur_button1_text = self.KEYBOARD__UPPERCASE_BUTTON_TEXT

                    if cur_button2_text == self.KEYBOARD__DIGITS_BUTTON_TEXT:
                        self.keyboard_digits.set_selected_key_indices(x=cur_keyboard.selected_key["x"], y=cur_keyboard.selected_key["y"])
                        cur_keyboard = self.keyboard_digits
                        cur_keyboard.render_keys()
                        cur_button2_text = self.KEYBOARD__SYMBOLS_1_BUTTON_TEXT
                    elif cur_button2_text == self.KEYBOARD__SYMBOLS_1_BUTTON_TEXT:
                        self.keyboard_symbols_1.set_selected_key_indices(x=cur_keyboard.selected_key["x"], y=cur_keyboard.selected_key["y"])
                        cur_keyboard = self.keyboard_symbols_1
                        cur_keyboard.render_keys()
                        cur_button2_text = self.KEYBOARD__SYMBOLS_2_BUTTON_TEXT
                    elif cur_button2_text == self.KEYBOARD__SYMBOLS_2_BUTTON_TEXT:
                        self.keyboard_symbols_2.set_selected_key_indices(x=cur_keyboard.selected_key["x"], y=cur_keyboard.selected_key["y"])
                        cur_keyboard = self.keyboard_symbols_2
                        cur_keyboard.render_keys()
                        cur_button2_text = self.KEYBOARD__DIGITS_BUTTON_TEXT
                    cur_keyboard.render_keys()

                    # Show the changes; this loop will have two renders
                    self.renderer.show_image()

                    keyboard_swap = True
                    ret_val = None

                else:
                    # Process normal input
                    if input in [HardwareButtonsConstants.KEY_UP, HardwareButtonsConstants.KEY_DOWN] and self.top_nav.is_selected:
                        # We're navigating off the previous button
                        self.top_nav.is_selected = False
                        self.top_nav.render_buttons()

                        # Override the actual input w/an ENTER signal for the Keyboard
                        if input == HardwareButtonsConstants.KEY_DOWN:
                            input = Keyboard.ENTER_TOP
                        else:
                            input = Keyboard.ENTER_BOTTOM
                    elif input in [HardwareButtonsConstants.KEY_LEFT, HardwareButtonsConstants.KEY_RIGHT] and self.top_nav.is_selected:
                        # ignore
                        continue

                    ret_val = cur_keyboard.update_from_input(input)

                # Now process the result from the keyboard
                if ret_val in Keyboard.EXIT_DIRECTIONS:
                    self.top_nav.is_selected = True
                    self.top_nav.render_buttons()

                elif ret_val in Keyboard.ADDITIONAL_KEYS and input == HardwareButtonsConstants.KEY_PRESS:
                    if ret_val == Keyboard.KEY_BACKSPACE["code"]:
                        if cursor_position == 0:
                            pass
                        elif cursor_position == len(self.textToEncode):
                            self.textToEncode = self.textToEncode[:-1]
                        else:
                            self.textToEncode = self.textToEncode[:cursor_position - 1] + self.textToEncode[cursor_position:]

                        cursor_position -= 1

                    elif ret_val == Keyboard.KEY_CURSOR_LEFT["code"]:
                        cursor_position -= 1
                        if cursor_position < 0:
                            cursor_position = 0

                    elif ret_val == Keyboard.KEY_CURSOR_RIGHT["code"]:
                        cursor_position += 1
                        if cursor_position > len(self.textToEncode):
                            cursor_position = len(self.textToEncode)

                    elif ret_val == Keyboard.KEY_SPACE["code"]:
                        if cursor_position == len(self.textToEncode):
                            self.textToEncode += " "
                        else:
                            self.textToEncode = self.textToEncode[:cursor_position] + " " + self.textToEncode[cursor_position:]
                        cursor_position += 1

                    # Update the text entry display and cursor
                    self.text_entry_display.render(self.textToEncode, cursor_position)

                elif input == HardwareButtonsConstants.KEY_PRESS and ret_val not in Keyboard.ADDITIONAL_KEYS:
                    # User has locked in the current letter
                    if cursor_position == len(self.textToEncode):
                        self.textToEncode += ret_val
                    else:
                        self.textToEncode = self.textToEncode[:cursor_position] + ret_val + self.textToEncode[cursor_position:]
                    cursor_position += 1

                    # Update the text entry display and cursor
                    self.text_entry_display.render(self.textToEncode, cursor_position)

                elif input in HardwareButtonsConstants.KEYS__LEFT_RIGHT_UP_DOWN or keyboard_swap:
                    # Live joystick movement; haven't locked this new letter in yet.
                    # Leave current spot blank for now. Only update the active keyboard keys
                    # when a selection has been locked in (KEY_PRESS) or removed ("del").
                    pass
        
                if keyboard_swap:
                    # Show the hw buttons' updated text and not active state
                    self.hw_button1.text = cur_button1_text
                    self.hw_button2.text = cur_button2_text                
                    self.hw_button1.is_selected = False
                    self.hw_button2.is_selected = False
                    self.hw_button1.render()
                    self.hw_button2.render()

                self.renderer.show_image()



@dataclass
class ToolsTextQRReviewTextScreen(ButtonListScreen):
    textToEncode: str = None
    title: str = None

    def __post_init__(self):
        # Customize defaults
        self.is_bottom_list = True

        super().__post_init__()

        if " " in self.textToEncode:
            self.textToEncode = self.textToEncode.replace(" ", "\u2589")
        available_height = self.buttons[0].screen_y - self.top_nav.height - GUIConstants.COMPONENT_PADDING
        max_font_size = GUIConstants.get_top_nav_title_font_size() + 8
        min_font_size = GUIConstants.get_top_nav_title_font_size() - 4
        font_size = max_font_size
        max_lines = 5
        max_chars_per_line = -1
        found_solution = False
        for font_size in range(max_font_size, min_font_size-1, -2):
            if found_solution:
                break
            font = Fonts.get_font(font_name=GUIConstants.FIXED_WIDTH_FONT_NAME_JP, size=font_size)
            left, top, right, bottom  = font.getbbox("X")
            char_width, char_height = right - left, bottom
            for num_lines in range(1, max_lines+1):
                # Break the textToEncode into n lines
                chars_per_line = math.ceil(textwidth(self.textToEncode) / num_lines)
                if font_size <= min_font_size + 1 and num_lines == max_lines:
                    max_chars_per_line = math.floor((self.canvas_width - 2*GUIConstants.EDGE_PADDING) / char_width)
                    chars_per_line = min(chars_per_line, max_chars_per_line)
                textToEncode = []
                k = 0
                for i in range(0, num_lines):
                    buffer = ""
                    for j in range(k, len(self.textToEncode)):
                        c = self.textToEncode[j]
                        if textwidth(buffer + c) > chars_per_line:
                            if (textwidth(self.textToEncode[j:]) <= chars_per_line * (num_lines-1 - i) or
                                chars_per_line == max_chars_per_line):
                                textToEncode.append(buffer)
                                k = j
                            else:
                                chars_per_line += 1
                                textToEncode.append(buffer + c)
                                k = j + 1
                            break
                        elif textwidth(buffer + c) == chars_per_line:
                            textToEncode.append(buffer + c)
                            k = j + 1
                            break
                        elif j == len(self.textToEncode) - 1:
                            textToEncode.append(buffer + c)
                            break
                        buffer += c

                # Truncate the displayed textToEncode to fit within the screen
                if sum(len(x) for x in textToEncode) != len(self.textToEncode):
                    buffer = ""
                    for j in range(0, len(textToEncode[-1])):
                        c = textToEncode[-1][j]
                        if textwidth(buffer + c) <= chars_per_line - textwidth("\u2026"):
                            buffer += c
                        else:
                            break
                    buffer += "\u2026"
                    textToEncode[-1] = buffer

                for i in range(0, num_lines):
                    while textwidth(textToEncode[i]) < chars_per_line:
                        textToEncode[i] += " "

                # See if it fits in this configuration
                if chars_per_line * char_width <= self.canvas_width - 2*GUIConstants.EDGE_PADDING:
                    # Width is good...
                    if num_lines * char_height <= available_height:
                        # And the height is good!
                        found_solution = True
                        break

        # Set up each line of text
        screen_y = self.top_nav.height + int((available_height - char_height*num_lines)/2) - GUIConstants.COMPONENT_PADDING
        for line in textToEncode:
            self.components.append(TextArea(
                text=line,
                font_name=GUIConstants.FIXED_WIDTH_FONT_NAME_JP,
                font_size=font_size,
                font_color="orange",
                is_text_centered=True,
                screen_y=screen_y,
                allow_text_overflow=True
            ))
            screen_y += char_height + 2


def textwidth(text: str):
    import unicodedata
    count = 0
    for c in text:
        if unicodedata.east_asian_width(c) in 'FW':
            count += 2
        else:
            count += 1
    return count


@dataclass
class ToolsTextQRTranscribeModePromptScreen(ButtonListScreen):
    def __post_init__(self):
        self.is_bottom_list = True
        super().__post_init__()

        self.components.append(TextArea(
            text="The QR codes output in both modes may differ, but both are valid QR codes.",
            screen_y=self.top_nav.height,
            height=self.buttons[0].screen_y - self.top_nav.height,
        ))



@dataclass
class ToolsTranscribeTextQRWholeQRScreen(WarningEdgesMixin, ButtonListScreen):
    qr_data: str = None
    num_modules: int = None

    def __post_init__(self):
        self.title = "Transcribe Text QR"
        button_label = _("Begin {}x{}").format(self.num_modules, self.num_modules)
        self.button_data = [ButtonOption(button_label)]
        self.is_bottom_list = True
        self.status_color = GUIConstants.DIRE_WARNING_COLOR
        super().__post_init__()

        qr_height = self.buttons[0].screen_y - self.top_nav.height - GUIConstants.COMPONENT_PADDING
        qr_width = qr_height

        qr = QR()
        qr_image = qr.qrimage(
            data=self.qr_data,
            width=qr_width,
            height=qr_height,
            border=1,
            style=QR.STYLE__ROUNDED
        ).convert("RGBA")

        self.paste_images.append((qr_image, (int((self.canvas_width - qr_width)/2), self.top_nav.height)))



@dataclass
class ToolsTranscribeTextQRZoomedInScreen(BaseScreen):
    qr_data: str = None
    num_modules: int = None
    initial_block_x: int = 0
    initial_block_y: int = 0

    def __post_init__(self):
        super().__post_init__()

        # Render an oversized QR code that we can view up close
        self.pixels_per_block = 24

        # Border must accommodate the 3 blocks outside the center 5x5 mask plus up to
        # 2 empty blocks inside the 5x5 mask (29x29 and 33x33 have 4 and 3-block final col/row).
        self.qr_border = 5
        if self.num_modules == 21:
            # Optimize for 21x21
            self.qr_blocks_per_zoom = 7
        else:
            self.qr_blocks_per_zoom = 5

        self.qr_width = (self.qr_border + self.num_modules + self.qr_border) * self.pixels_per_block
        self.height = self.qr_width
        qr = QR()
        self.qr_image = qr.qrimage(
            self.qr_data,
            width=self.qr_width,
            height=self.height,
            border=self.qr_border,
            style=QR.STYLE__ROUNDED
        ).convert("RGBA")

        # Render gridlines but leave the 1-block border as-is
        draw = ImageDraw.Draw(self.qr_image)
        for i in range(self.qr_border, math.floor(self.qr_width/self.pixels_per_block) - self.qr_border):
            draw.line((i * self.pixels_per_block, self.qr_border * self.pixels_per_block, i * self.pixels_per_block, self.height - self.qr_border * self.pixels_per_block), fill="#bbb")
            draw.line((self.qr_border * self.pixels_per_block, i * self.pixels_per_block, self.qr_width - self.qr_border * self.pixels_per_block, i * self.pixels_per_block), fill="#bbb")

        # Prep the semi-transparent mask overlay
        # make a blank image for the overlay, initialized to transparent
        self.block_mask = Image.new("RGBA", (self.canvas_width, self.canvas_height), (255,255,255,0))
        draw = ImageDraw.Draw(self.block_mask)

        self.mask_width = int((self.canvas_width - self.qr_blocks_per_zoom * self.pixels_per_block)/2)
        self.mask_height = int((self.canvas_height - self.qr_blocks_per_zoom * self.pixels_per_block)/2)
        mask_rgba = (0, 0, 0, 226)
        draw.rectangle((0, 0, self.canvas_width, self.mask_height), fill=mask_rgba)
        draw.rectangle((0, self.canvas_height - self.mask_height - 1, self.canvas_width, self.canvas_height), fill=mask_rgba)
        draw.rectangle((0, self.mask_height, self.mask_width, self.canvas_height - self.mask_height), fill=mask_rgba)
        draw.rectangle((self.canvas_width - self.mask_width - 1, self.mask_height, self.canvas_width, self.canvas_height - self.mask_height), fill=mask_rgba)

        # Draw a box around the cutout portion of the mask for better visibility
        draw.line((self.mask_width, self.mask_height, self.mask_width, self.canvas_height - self.mask_height), fill=GUIConstants.ACCENT_COLOR)
        draw.line((self.canvas_width - self.mask_width, self.mask_height, self.canvas_width - self.mask_width, self.canvas_height - self.mask_height), fill=GUIConstants.ACCENT_COLOR)
        draw.line((self.mask_width, self.mask_height, self.canvas_width - self.mask_width, self.mask_height), fill=GUIConstants.ACCENT_COLOR)
        draw.line((self.mask_width, self.canvas_height - self.mask_height, self.canvas_width - self.mask_width, self.canvas_height - self.mask_height), fill=GUIConstants.ACCENT_COLOR)

        msg = _("click to exit")
        font = Fonts.get_font(GUIConstants.get_body_font_name(), GUIConstants.get_body_font_size())
        (left, top, right, bottom) = font.getbbox(msg, anchor="ls")
        msg_height = -1 * top + GUIConstants.COMPONENT_PADDING
        msg_width = right + 2*GUIConstants.COMPONENT_PADDING
        draw.rectangle(
            (
                int((self.canvas_width - msg_width)/2),
                self.canvas_height - msg_height,
                int((self.canvas_width + msg_width)/2),
                self.canvas_height
            ),
            fill=GUIConstants.BACKGROUND_COLOR,
        )
        draw.text(
            (int(self.canvas_width/2), self.canvas_height - int(GUIConstants.COMPONENT_PADDING/2)),
            msg,
            fill=GUIConstants.BODY_FONT_COLOR,
            font=font,
            anchor="ms"  # Middle, baSeline
        )



    def draw_block_labels(self):
        # Create overlay for block labels (e.g. "D-5")
        block_labels_x = ["1", "2", "3", "4", "5", "6", "7"]
        block_labels_y = ["A", "B", "C", "D", "E", "F", "G"]

        block_labels = Image.new("RGBA", (self.canvas_width, self.canvas_height), (255,255,255,0))
        draw = ImageDraw.Draw(block_labels)
        draw.rectangle((self.mask_width, 0, self.canvas_width - self.mask_width, self.pixels_per_block), fill=GUIConstants.ACCENT_COLOR)
        draw.rectangle((0, self.mask_height, self.pixels_per_block, self.canvas_height - self.mask_height), fill=GUIConstants.ACCENT_COLOR)

        label_font = Fonts.get_font(GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME, 28)
        x_label = block_labels_x[self.cur_block_x]
        (left, top, right, bottom) = label_font.getbbox(x_label, anchor="ls")
        x_label_height = -1 * top

        draw.text(
            (int(self.canvas_width/2), self.pixels_per_block - int((self.pixels_per_block - x_label_height)/2)),
            text=x_label,
            fill=GUIConstants.BUTTON_SELECTED_FONT_COLOR,
            font=label_font,
            anchor="ms",  # Middle, baSeline
        )

        y_label = block_labels_y[self.cur_block_y]
        (left, top, right, bottom) = label_font.getbbox(y_label, anchor="ls")
        y_label_height = -1 * top
        draw.text(
            (int(self.pixels_per_block/2), int((self.canvas_height + y_label_height) / 2)),
            text=y_label,
            fill=GUIConstants.BUTTON_SELECTED_FONT_COLOR,
            font=label_font,
            anchor="ms",  # Middle, baSeline
        )

        return block_labels


    def _render(self):
        # Track our current coordinates for the upper left corner of our view
        self.cur_block_x = self.initial_block_x
        self.cur_block_y = self.initial_block_y
        self.cur_x = (self.cur_block_x * self.qr_blocks_per_zoom * self.pixels_per_block) + self.qr_border * self.pixels_per_block - self.mask_width
        self.cur_y = (self.cur_block_y * self.qr_blocks_per_zoom * self.pixels_per_block) + self.qr_border * self.pixels_per_block - self.mask_height
        self.next_x = self.cur_x
        self.next_y = self.cur_y

        block_labels = self.draw_block_labels()

        self.renderer.show_image(
            self.qr_image.crop((self.cur_x, self.cur_y, self.cur_x + self.canvas_width, self.cur_y + self.canvas_height)),
            alpha_overlay=Image.alpha_composite(self.block_mask, block_labels)
        )


    def _run(self):
        while True:
            input = self.hw_inputs.wait_for(HardwareButtonsConstants.KEYS__LEFT_RIGHT_UP_DOWN + HardwareButtonsConstants.KEYS__ANYCLICK)
            if input == HardwareButtonsConstants.KEY_RIGHT:
                self.next_x = self.cur_x + self.qr_blocks_per_zoom * self.pixels_per_block
                self.cur_block_x += 1
                if self.next_x > self.qr_width - self.canvas_width:
                    self.next_x = self.cur_x
                    self.cur_block_x -= 1
            elif input == HardwareButtonsConstants.KEY_LEFT:
                self.next_x = self.cur_x - self.qr_blocks_per_zoom * self.pixels_per_block
                self.cur_block_x -= 1
                if self.next_x < 0:
                    self.next_x = self.cur_x
                    self.cur_block_x += 1
            elif input == HardwareButtonsConstants.KEY_DOWN:
                self.next_y = self.cur_y + self.qr_blocks_per_zoom * self.pixels_per_block
                self.cur_block_y += 1
                if self.next_y > self.height - self.canvas_height:
                    self.next_y = self.cur_y
                    self.cur_block_y -= 1
            elif input == HardwareButtonsConstants.KEY_UP:
                self.next_y = self.cur_y - self.qr_blocks_per_zoom * self.pixels_per_block
                self.cur_block_y -= 1
                if self.next_y < 0:
                    self.next_y = self.cur_y
                    self.cur_block_y += 1
            elif input in HardwareButtonsConstants.KEYS__ANYCLICK:
                return

            # Create overlay for block labels (e.g. "D-5")
            block_labels = self.draw_block_labels()

            if self.cur_x != self.next_x or self.cur_y != self.next_y:
                with self.renderer.lock:
                    self.renderer.show_image_pan(
                        self.qr_image,
                        self.cur_x, self.cur_y, self.next_x, self.next_y,
                        rate=self.pixels_per_block,
                        alpha_overlay=Image.alpha_composite(self.block_mask, block_labels)
                    )
                    self.cur_x = self.next_x
                    self.cur_y = self.next_y



@dataclass
class ToolsTranscribeTextQRConfirmQRPromptScreen(ButtonListScreen):
    def __post_init__(self):
        self.is_bottom_list = True
        super().__post_init__()

        self.components.append(TextArea(
            text="Optionally scan your transcribed text QR code to confirm that it reads back correctly.",
            screen_y=self.top_nav.height,
            height=self.buttons[0].screen_y - self.top_nav.height,
        ))

