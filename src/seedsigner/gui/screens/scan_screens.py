import math
import time

from dataclasses import dataclass
from PIL import Image, ImageDraw

from seedsigner.gui import renderer
from seedsigner.gui.keyboard import Keyboard, TextEntryDisplay
from seedsigner.hardware.buttons import HardwareButtonsConstants
from seedsigner.hardware.camera import Camera
from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.threads import BaseThread, ThreadsafeCounter

from .screen import BaseScreen, BaseTopNavScreen, ButtonListScreen
from ..components import GUIConstants, Fonts, SeedSignerIconConstants, Button, IconButton, TextArea




@dataclass
class ScanScreen(BaseScreen):
    """
    Live preview has to balance three competing threads:
    * Camera capturing frames and making them available to read.
    * Decoder analyzing frames for QR codes.
    * Live preview display writing frames to the screen.

    All of this would ideally be rewritten as in C/C++/Rust with python bindings for
    vastly improved performance.

    Until then, we have to balance the resources the Pi Zero has to work with. Thus, we
    set a modest fps target for the camera: 5fps. At this pace, the decoder and the live
    display can more or less keep up with the flow of frames without much wasted effort
    in any of the threads.

    Note: performance tuning was targeted for the Pi Zero.

    The resolution (480x480) has not been tweaked in order to guarantee that our
    decoding abilities remain as-is. It's possible that more optimizations could be made
    here (e.g. higher res w/no performance impact? Lower res w/same decoding but faster
    performance? etc).

    Note: This is quite a lot of important tasks for a Screen to be managing; much of
    this should probably be refactored into the Controller.
    """
    decoder: DecodeQR = None
    instructions_text: str = None
    resolution: tuple[int,int] = (480, 480)
    framerate: int = 6  # TODO: alternate optimization for Pi Zero 2W?
    render_rect: tuple[int,int,int,int] = None

    FRAME__ADDED_PART = 1
    FRAME__REPEATED_PART = 2
    FRAME__MISS = 3

    def __post_init__(self):
        from seedsigner.hardware.camera import Camera
        # Initialize the base class
        super().__post_init__()

        self.instructions_text = "< back  |  " + self.instructions_text

        self.camera = Camera.get_instance()
        self.camera.start_video_stream_mode(resolution=self.resolution, framerate=self.framerate, format="rgb")

        self.frames_decode_status = ThreadsafeCounter()
        self.frames_decoded_counter = ThreadsafeCounter()

        self.threads.append(ScanScreen.LivePreviewThread(
            camera=self.camera,
            decoder=self.decoder,
            renderer=self.renderer,
            instructions_text=self.instructions_text,
            render_rect=self.render_rect,
            frame_decode_status=self.frames_decode_status,
            frames_decoded_counter=self.frames_decoded_counter,
        ))


    class LivePreviewThread(BaseThread):
        def __init__(self, camera: Camera, decoder: DecodeQR, renderer: renderer.Renderer, instructions_text: str, render_rect: tuple[int,int,int,int], frame_decode_status: ThreadsafeCounter, frames_decoded_counter: ThreadsafeCounter):
            self.camera = camera
            self.decoder = decoder
            self.renderer = renderer
            self.instructions_text = instructions_text
            if render_rect:
                self.render_rect = render_rect            
            else:
                self.render_rect = (0, 0, self.renderer.canvas_width, self.renderer.canvas_height)
            self.frame_decode_status = frame_decode_status
            self.frames_decoded_counter = frames_decoded_counter
            self.last_frame_decoded_count = self.frames_decoded_counter.cur_count
            self.render_width = self.render_rect[2] - self.render_rect[0]
            self.render_height = self.render_rect[3] - self.render_rect[1]
            self.decoder_fps = "0.0"

            super().__init__()


        def run(self):
            instructions_font = Fonts.get_font(GUIConstants.BODY_FONT_NAME, GUIConstants.BUTTON_FONT_SIZE)

            # pre-calculate how big the animated QR percent display can be
            left, _, right, _ = instructions_font.getbbox("100%")
            progress_text_width = right - left

            start_time = time.time()
            num_frames = 0
            debug = False
            show_framerate = False  # enable for debugging / testing
            while self.keep_running:
                frame = self.camera.read_video_stream(as_image=True)
                if frame is not None:
                    num_frames += 1
                    cur_time = time.time()
                    cur_fps = num_frames / (cur_time - start_time)
                    
                    scan_text = None
                    progress_percentage = self.decoder.get_percent_complete()
                    if progress_percentage == 0:
                        # We've just started scanning, no results yet
                        if show_framerate:
                            scan_text = f"{cur_fps:0.2f} | {self.decoder_fps}"
                        else:
                            scan_text = self.instructions_text

                    elif debug:
                        # Special debugging output for animated QRs
                        scan_text = f"{self.decoder.get_percent_complete()}% | {self.decoder.get_percent_complete(weight_mixed_frames=True)}% (new)"
                        if show_framerate:
                            scan_text += f" {cur_fps:0.2f} | {self.decoder_fps}"

                    with self.renderer.lock:
                        if frame.width > self.render_width or frame.height > self.render_height:
                            frame = frame.resize(
                                (self.render_width, self.render_height),
                                resample=Image.NEAREST  # Use nearest neighbor for max speed
                            )

                        if scan_text:
                            # Note: shadowed text (adding a 'stroke' outline) can
                            # significantly slow down the rendering.
                            # Temp solution: render a slight 1px shadow behind the text
                            # TODO: Replace the instructions_text with a disappearing
                            # toast/popup (see: QR Brightness UI)?
                            draw = ImageDraw.Draw(frame)
                            draw.text(xy=(
                                        int(self.renderer.canvas_width/2 + 2),
                                        self.renderer.canvas_height - GUIConstants.EDGE_PADDING + 2
                                     ),
                                     text=scan_text,
                                     fill="black",
                                     font=instructions_font,
                                     anchor="ms")

                            # Render the onscreen instructions
                            draw.text(xy=(
                                        int(self.renderer.canvas_width/2),
                                        self.renderer.canvas_height - GUIConstants.EDGE_PADDING
                                     ),
                                     text=scan_text,
                                     fill=GUIConstants.BODY_FONT_COLOR,
                                     font=instructions_font,
                                     anchor="ms")

                        else:
                            # Render the progress bar
                            rectangle = Image.new('RGBA', (self.renderer.canvas_width - 2*GUIConstants.EDGE_PADDING, GUIConstants.BUTTON_HEIGHT), (0, 0, 0, 0))
                            draw = ImageDraw.Draw(rectangle)

                            # Start with a background rounded rectangle, same dims as the buttons
                            overlay_color = (0, 0, 0, 191)  # opacity ranges from 0-255
                            draw.rounded_rectangle(
                                (
                                    (0, 0),
                                    (rectangle.width, rectangle.height)
                                ),
                                fill=overlay_color,
                                radius=8,
                                outline=overlay_color,
                                width=2,
                            )

                            progress_bar_thickness = 4
                            progress_bar_width = rectangle.width - 2*GUIConstants.EDGE_PADDING - progress_text_width - int(GUIConstants.EDGE_PADDING/2)
                            progress_bar_xy = (
                                    (GUIConstants.EDGE_PADDING, int((rectangle.height - progress_bar_thickness) / 2)),
                                    (GUIConstants.EDGE_PADDING + progress_bar_width, int(rectangle.height + progress_bar_thickness) / 2)
                                )
                            draw.rounded_rectangle(
                                progress_bar_xy,
                                fill=GUIConstants.INACTIVE_COLOR,
                                radius=8
                            )

                            progress_percentage = self.decoder.get_percent_complete(weight_mixed_frames=True)
                            draw.rounded_rectangle(
                                (
                                    progress_bar_xy[0],
                                    (GUIConstants.EDGE_PADDING + int(progress_percentage * progress_bar_width / 100.0), progress_bar_xy[1][1])
                                ),
                                fill=GUIConstants.GREEN_INDICATOR_COLOR,
                                radius=8
                            )


                            draw.text(
                                xy=(rectangle.width - GUIConstants.EDGE_PADDING, int(rectangle.height / 2)),
                                text=f"{progress_percentage}%",
                                # text=f"100%",
                                fill=GUIConstants.BODY_FONT_COLOR,
                                font=instructions_font,
                                anchor="rm",  # right-justified, middle
                            )

                            frame.paste(rectangle, (GUIConstants.EDGE_PADDING, self.renderer.canvas_height - GUIConstants.EDGE_PADDING - rectangle.height), rectangle)

                            # Render the dot to indicate successful QR frame read
                            indicator_size = 10
                            self.last_frame_decoded_count = self.frames_decoded_counter.cur_count
                            status_color_map = {
                                ScanScreen.FRAME__ADDED_PART: GUIConstants.SUCCESS_COLOR,
                                ScanScreen.FRAME__REPEATED_PART: GUIConstants.INACTIVE_COLOR,
                                ScanScreen.FRAME__MISS: None,
                            }
                            status_color = status_color_map.get(self.frame_decode_status.cur_count)
                            if status_color:
                                # Good! Most recent frame successfully decoded.
                                # Draw the onscreen indicator dot
                                draw = ImageDraw.Draw(frame)
                                draw.ellipse(
                                    (
                                        (self.renderer.canvas_width - GUIConstants.EDGE_PADDING - indicator_size, self.renderer.canvas_height - GUIConstants.EDGE_PADDING - GUIConstants.BUTTON_HEIGHT - GUIConstants.COMPONENT_PADDING - indicator_size),
                                        (self.renderer.canvas_width - GUIConstants.EDGE_PADDING, self.renderer.canvas_height - GUIConstants.EDGE_PADDING - GUIConstants.BUTTON_HEIGHT - GUIConstants.COMPONENT_PADDING)
                                    ),
                                    fill=status_color,
                                    outline="black",
                                    width=1,
                                )

                        self.renderer.show_image(frame, show_direct=True)

                if self.camera._video_stream is None:
                    break


    def _run(self):
        """
            _render() is mostly meant to be a one-time initial drawing call to set up the
            Screen. Once interaction starts, the display updates have to be managed in
            _run(). The live preview is an extra-complex case.
        """
        num_frames = 0
        start_time = time.time()
        while True:
            frame = self.camera.read_video_stream()
            if frame is not None:
                status = self.decoder.add_image(frame)

                num_frames += 1
                decoder_fps = f"{num_frames / (time.time() - start_time):0.2f}"
                self.threads[0].decoder_fps = decoder_fps

                if status in (DecodeQRStatus.COMPLETE, DecodeQRStatus.INVALID):
                    self.camera.stop_video_stream_mode()
                    break

                self.frames_decoded_counter.increment()
                # Notify the live preview thread how our most recent decode went
                if status == DecodeQRStatus.FALSE:
                    # Did not find anything to decode in the current frame
                    self.frames_decode_status.set_value(self.FRAME__MISS)

                else:
                    if status == DecodeQRStatus.PART_COMPLETE:
                        # We received a valid frame that added new data
                        self.frames_decode_status.set_value(self.FRAME__ADDED_PART)

                    elif status == DecodeQRStatus.PART_EXISTING:
                        # We received a valid frame, but we've already seen in
                        self.frames_decode_status.set_value(self.FRAME__REPEATED_PART)
                
                if self.hw_inputs.check_for_low(HardwareButtonsConstants.KEY_RIGHT) or self.hw_inputs.check_for_low(HardwareButtonsConstants.KEY_LEFT):
                    self.camera.stop_video_stream_mode()
                    break



@dataclass
class ScanEncryptedQRScreen(ButtonListScreen):
    public_data: str = None

    def __post_init__(self):
        self.title = "Decrypt?"
        self.show_back_button = False
        self.is_bottom_list = True
        super().__post_init__()

        self.components.append(TextArea(
            text=self.public_data,
            screen_y=self.top_nav.height,
            is_text_centered=True,
        ))



@dataclass
class ScanTypeEncryptionKeyScreen(BaseTopNavScreen):
    title: str = "Encryption Key"
    encryptionkey: str = ""

    KEYBOARD__LOWERCASE_BUTTON_TEXT = "abc"
    KEYBOARD__UPPERCASE_BUTTON_TEXT = "ABC"
    KEYBOARD__DIGITS_BUTTON_TEXT = "123"
    KEYBOARD__SYMBOLS_1_BUTTON_TEXT = "!@#"
    KEYBOARD__SYMBOLS_2_BUTTON_TEXT = "*[]"


    def __post_init__(self):
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
            font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            cursor_mode=TextEntryDisplay.CURSOR_MODE__BAR,
            is_centered=False,
            cur_text=''.join(self.encryptionkey)
        )

        # Nudge the buttons off the right edge w/padding
        hw_button_x = self.canvas_width - self.right_panel_buttons_width + GUIConstants.COMPONENT_PADDING

        # Calc center button position first
        hw_button_y = int((self.canvas_height - GUIConstants.BUTTON_HEIGHT)/2)

        self.hw_button1 = Button(
            text=self.KEYBOARD__UPPERCASE_BUTTON_TEXT,
            is_text_centered=False,
            font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            font_size=GUIConstants.BUTTON_FONT_SIZE + 4,
            width=self.right_panel_buttons_width,
            screen_x=hw_button_x,
            screen_y=hw_button_y - 3*GUIConstants.COMPONENT_PADDING - GUIConstants.BUTTON_HEIGHT,
        )

        self.hw_button2 = Button(
            text=self.KEYBOARD__DIGITS_BUTTON_TEXT,
            is_text_centered=False,
            font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            font_size=GUIConstants.BUTTON_FONT_SIZE + 4,
            width=self.right_panel_buttons_width,
            screen_x=hw_button_x,
            screen_y=hw_button_y,
        )

        self.hw_button3 = IconButton(
            icon_name=SeedSignerIconConstants.CHECK,
            icon_color=GUIConstants.SUCCESS_COLOR,
            width=self.right_panel_buttons_width,
            screen_x=hw_button_x,
            screen_y=hw_button_y + 3*GUIConstants.COMPONENT_PADDING + GUIConstants.BUTTON_HEIGHT,
        )


    def _render(self):
        super()._render()

        self.text_entry_display.render()
        self.hw_button1.render()
        self.hw_button2.render()
        self.hw_button3.render()
        self.keyboard_abc.render_keys()

        self.renderer.show_image()


    def _run(self):
        cursor_position = len(self.encryptionkey)

        cur_keyboard = self.keyboard_abc
        cur_button1_text = self.KEYBOARD__UPPERCASE_BUTTON_TEXT
        cur_button2_text = self.KEYBOARD__DIGITS_BUTTON_TEXT

        # Start the interactive update loop
        while True:
            input = self.hw_inputs.wait_for(
                HardwareButtonsConstants.ALL_KEYS,
                check_release=True,
                release_keys=[HardwareButtonsConstants.KEY_PRESS, HardwareButtonsConstants.KEY1, HardwareButtonsConstants.KEY2, HardwareButtonsConstants.KEY3]
            )

            keyboard_swap = False

            # Check our two possible exit conditions
            # TODO: note the unusual return value, consider refactoring to a Response object in the future
            if input == HardwareButtonsConstants.KEY3:
                # Save!
                # First light up key3
                if len(self.encryptionkey) > 0:
                    self.hw_button3.is_selected = True
                    self.hw_button3.render()
                    self.renderer.show_image()
                    return dict(encryptionkey=self.encryptionkey)

            elif input == HardwareButtonsConstants.KEY_PRESS and self.top_nav.is_selected:
                # Back button clicked
                return dict(encryptionkey=self.encryptionkey, is_back_button=True)

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
                    elif cursor_position == len(self.encryptionkey):
                        self.encryptionkey = self.encryptionkey[:-1]
                    else:
                        self.encryptionkey = self.encryptionkey[:cursor_position - 1] + self.encryptionkey[cursor_position:]

                    cursor_position -= 1

                elif ret_val == Keyboard.KEY_CURSOR_LEFT["code"]:
                    cursor_position -= 1
                    if cursor_position < 0:
                        cursor_position = 0

                elif ret_val == Keyboard.KEY_CURSOR_RIGHT["code"]:
                    cursor_position += 1
                    if cursor_position > len(self.encryptionkey):
                        cursor_position = len(self.encryptionkey)

                elif ret_val == Keyboard.KEY_SPACE["code"]:
                    if cursor_position == len(self.encryptionkey):
                        self.encryptionkey += " "
                    else:
                        self.encryptionkey = self.encryptionkey[:cursor_position] + " " + self.encryptionkey[cursor_position:]
                    cursor_position += 1

                # Update the text entry display and cursor
                self.text_entry_display.render(self.encryptionkey, cursor_position)

            elif input == HardwareButtonsConstants.KEY_PRESS and ret_val not in Keyboard.ADDITIONAL_KEYS:
                # User has locked in the current letter
                if cursor_position == len(self.encryptionkey):
                    self.encryptionkey += ret_val
                else:
                    self.encryptionkey = self.encryptionkey[:cursor_position] + ret_val + self.encryptionkey[cursor_position:]
                cursor_position += 1

                # Update the text entry display and cursor
                self.text_entry_display.render(self.encryptionkey, cursor_position)

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
class ScanReviewEncryptionKeyScreen(ButtonListScreen):
    encryptionkey: str = None

    def __post_init__(self):
        # Customize defaults
        self.title = "Review\nEncryption Key"
        self.is_bottom_list = True

        super().__post_init__()

        if self.encryptionkey != self.encryptionkey.strip() or "  " in self.encryptionkey:
            self.encryptionkey = self.encryptionkey.replace(" ", "\u2589")
        available_height = self.buttons[0].screen_y - self.top_nav.height + GUIConstants.COMPONENT_PADDING
        max_font_size = GUIConstants.TOP_NAV_TITLE_FONT_SIZE + 8
        min_font_size = GUIConstants.TOP_NAV_TITLE_FONT_SIZE - 4
        font_size = max_font_size
        max_lines = 3
        encryptionkey = [self.encryptionkey]
        found_solution = False
        for font_size in range(max_font_size, min_font_size, -2):
            if found_solution:
                break
            font = Fonts.get_font(font_name=GUIConstants.FIXED_WIDTH_FONT_NAME, size=font_size)
            left, top, right, bottom  = font.getbbox("X")
            char_width, char_height = right - left, bottom
            for num_lines in range(1, max_lines+1):
                # Break the encryptionkey into n lines
                chars_per_line = math.ceil(len(self.encryptionkey) / num_lines)
                encryptionkey = []
                for i in range(0, len(self.encryptionkey), chars_per_line):
                    encryptionkey.append(self.encryptionkey[i:i+chars_per_line])

                # See if it fits in this configuration
                if char_width * len(encryptionkey[0]) <= self.canvas_width - 2*GUIConstants.EDGE_PADDING:
                    # Width is good...
                    if num_lines * char_height <= available_height:
                        # And the height is good!
                        found_solution = True
                        break

        # Set up each line of text
        screen_y = self.top_nav.height + int((available_height - char_height*num_lines)/2) - GUIConstants.COMPONENT_PADDING
        for line in encryptionkey:
            self.components.append(TextArea(
                text=line,
                font_name=GUIConstants.FIXED_WIDTH_FONT_NAME,
                font_size=font_size,
                is_text_centered=True,
                screen_y=screen_y,
                allow_text_overflow=True
            ))
            screen_y += char_height + 2
