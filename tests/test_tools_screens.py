import os

from unittest.mock import MagicMock, patch

from PIL import Image

# Must import test base before the Controller
from base import BaseTest

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.hardware.camera import Camera


"""
    We don't test other Screens; they mostly have simple UI nav, text entry, or button
    select behavior. But the image entropy screens have critical user interaction review
    checks that could impact the security of the generated seed. So explicit tests of
    those interactions are warranted.

    These tests have to simulate user button press sequences AND duration at various
    stages of the image entropy live review loop and final image review.

    These tests are not concerned with actual image content, entropy, etc.
"""


def make_noise_frame(width: int = 240, height: int = 240) -> Image.Image:
    # Random bytes are fine here: tests only need frames that are non-blank and
    # distinct from one another; nothing here feeds real entropy.
    return Image.frombytes("RGBA", (width, height), os.urandom(width * height * 4))


def make_mock_camera(frames: list) -> MagicMock:
    """
    Returns a mocked Camera whose read_video_stream() plays back the given frames in
    order.
    """
    camera = MagicMock()
    frame_feed = list(frames)

    def read_video_stream(as_image: bool = False):
        if not frame_feed:
            raise AssertionError("Camera frame script exhausted; the screen loop should have exited by now")
        return frame_feed.pop(0)

    camera.read_video_stream.side_effect = read_video_stream
    return camera


def make_mock_hw_inputs(left_script: list = None, anyclick_script: list = None) -> MagicMock:
    """
    Returns a mocked HardwareButtons whose check_for_low() plays back scripted
    responses.

    There are two types of input checks:
    * check_for_low(specific_key_constant). e.g. was KEY_LEFT (back) pressed?

    * check_for_low(keys=list_of_keys). e.g. was ANYCLICK pressed? (any of the click buttons)
    """
    left_feed = list(left_script or [])
    anyclick_feed = list(anyclick_script or [])
    hw_inputs = MagicMock()

    def check_for_low(key=None, keys=None):
        if keys is None:
            return left_feed.pop(0) if left_feed else False
        return anyclick_feed.pop(0) if anyclick_feed else False

    hw_inputs.check_for_low.side_effect = check_for_low
    return hw_inputs



class ImageEntropyScreenTestBase(BaseTest):

    def setup_method(self):
        super().setup_method()

        from seedsigner.gui.renderer import Renderer

        # tests/base.py mocks the whole renderer module; give each test a fresh renderer
        # whose canvas dims are real ints (the screens do math on them). Exposed as a
        # patch so screen construction restores the original when its `with` exits.
        self.mock_renderer = MagicMock()
        self.mock_renderer.canvas_width = 240
        self.mock_renderer.canvas_height = 240
        self.renderer_patch = patch.object(Renderer, "get_instance", return_value=self.mock_renderer)



class TestToolsImageEntropyLivePreviewScreen(ImageEntropyScreenTestBase):

    def build_screen(self, mock_camera: MagicMock, mock_hw_inputs: MagicMock):
        from seedsigner.gui.screens.tools_screens import ToolsImageEntropyLivePreviewScreen

        # Run within our mocked Renderer context
        with self.renderer_patch:
            with patch.object(Camera, "get_instance", return_value=mock_camera):
                screen = ToolsImageEntropyLivePreviewScreen()

        screen.hw_inputs = mock_hw_inputs
        return screen


    def test_button_held_from_start_never_captures_until_released(self):
        """
        A button already held down when the screen starts must not trigger the final
        image capture; only a fresh press after all buttons have been seen released
        may capture.
        """
        frames = [make_noise_frame() for i in range(5)]
        mock_camera = make_mock_camera(frames)

        # Button is held for the first two loop passes, released on the third, then
        # pressed again on the fourth.
        mock_hw_inputs = make_mock_hw_inputs(anyclick_script=[True, True, False, True])
        screen = self.build_screen(mock_camera, mock_hw_inputs)

        # The screen returns the live preview frames
        result = screen._run()

        # The held presses were ignored; the fresh press on the fourth pass captured.
        # Three frames were collected before the capture pass.
        assert result == frames[:3]
        mock_camera.stop_video_stream_mode.assert_called_once()


    def test_click_after_release_captures(self):
        """ Normal use: no buttons pressed at first, then a click captures. """
        frames = [make_noise_frame() for i in range(2)]
        mock_camera = make_mock_camera(frames)
        mock_hw_inputs = make_mock_hw_inputs(anyclick_script=[False, True])
        screen = self.build_screen(mock_camera, mock_hw_inputs)

        result = screen._run()

        assert result == frames[:1]
        mock_camera.stop_video_stream_mode.assert_called_once()


    def test_back_button_exits_immediately(self):
        """ KEY_LEFT backs out at any time, even before any frame is read. """
        mock_camera = make_mock_camera([])
        mock_hw_inputs = make_mock_hw_inputs(left_script=[True])
        screen = self.build_screen(mock_camera, mock_hw_inputs)

        result = screen._run()

        assert result == RET_CODE__BACK_BUTTON
        mock_camera.stop_video_stream_mode.assert_called_once()
        mock_camera.read_video_stream.assert_not_called()


class TestToolsImageEntropyFinalImageScreen(ImageEntropyScreenTestBase):

    def build_screen(self, mock_hw_inputs: MagicMock):
        from seedsigner.gui.screens.tools_screens import ToolsImageEntropyFinalImageScreen

        # Run within our mocked Renderer context
        with self.renderer_patch:
            screen = ToolsImageEntropyFinalImageScreen(final_image=MagicMock())
        screen.hw_inputs = mock_hw_inputs
        return screen


    def test_held_button_must_be_released_before_review_input(self):
        """
        The click that captured the photo can still be held down when the review
        screen appears; it must be released before accept/reshoot input is read, so
        one long press can never accept the photo sight unseen.
        """
        from seedsigner.hardware.buttons import HardwareButtonsConstants

        # Button held for two polls, released on the third; only then is the real
        # accept/reshoot decision awaited.
        mock_hw_inputs = make_mock_hw_inputs(anyclick_script=[True, True, False])
        mock_hw_inputs.wait_for.return_value = HardwareButtonsConstants.KEY_LEFT
        screen = self.build_screen(mock_hw_inputs)

        # Screen returns the back button code when the user chooses to reshoot (KEY_LEFT).
        result = screen._run()

        assert mock_hw_inputs.check_for_low.call_count == 3
        mock_hw_inputs.wait_for.assert_called_once()
        assert result == RET_CODE__BACK_BUTTON


    def test_accept_returns_none_to_advance(self):
        """ A (fresh) accept click falls through: the screen returns None. """
        from seedsigner.hardware.buttons import HardwareButtonsConstants

        mock_hw_inputs = make_mock_hw_inputs(anyclick_script=[False])
        mock_hw_inputs.wait_for.return_value = HardwareButtonsConstants.KEY_RIGHT
        screen = self.build_screen(mock_hw_inputs)

        result = screen._run()

        assert result is None
        mock_hw_inputs.wait_for.assert_called_once()
