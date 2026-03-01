"""Unit tests for the camera hardware abstraction layer.

Tests exercise the picamera2 (libcamera), picamera (legacy), and OpenCV code
paths using mocked libraries so that the tests run without real hardware.
"""
import sys
import types
from unittest.mock import MagicMock, patch, call
import numpy as np
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_picamera2_module():
    """Return a minimal stub for the ``picamera2`` package."""
    mod = types.ModuleType("picamera2")
    cam = MagicMock()
    # capture_array() returns an RGB frame (height x width x channels).
    cam.capture_array.return_value = np.zeros((480, 720, 3), dtype=np.uint8)
    mod.Picamera2 = MagicMock(return_value=cam)
    return mod


def _make_cv2_module():
    """Return a minimal stub for the ``cv2`` package."""
    mod = MagicMock()
    cap = MagicMock()
    cap.isOpened.return_value = True
    # Frame shape: (height, width, channels) → 480 rows × 720 cols.
    frame = np.zeros((480, 720, 3), dtype=np.uint8)
    cap.read.return_value = (True, frame)
    mod.VideoCapture.return_value = cap
    mod.CAP_PROP_FRAME_WIDTH = 3
    mod.CAP_PROP_FRAME_HEIGHT = 4
    return mod


# ---------------------------------------------------------------------------
# PiVideoStream tests
# ---------------------------------------------------------------------------

class TestPiVideoStreamDetection:
    """Verify that PiVideoStream selects the right backend."""

    def _import_fresh(self, picamera2_mod=None, picamera_mod=None, cv2_mod=None):
        """Import pivideostream with controlled sys.modules overrides."""
        # Remove any cached version of the module under test.
        sys.modules.pop("seedsigner.hardware.pivideostream", None)

        overrides = {}
        if picamera2_mod is not None:
            overrides["picamera2"] = picamera2_mod
        else:
            overrides["picamera2"] = None  # force ImportError

        if picamera_mod is not None:
            overrides["picamera"] = picamera_mod
            overrides["picamera.array"] = picamera_mod
        else:
            overrides["picamera"] = None
            overrides["picamera.array"] = None

        if cv2_mod is not None:
            overrides["cv2"] = cv2_mod
        else:
            overrides["cv2"] = None

        with patch.dict(sys.modules, overrides):
            from seedsigner.hardware import pivideostream
            # Reload so the module-level try/except runs with our overrides.
            import importlib
            importlib.reload(pivideostream)
            return pivideostream

    def test_prefers_picamera2_when_available(self):
        pic2_mod = _make_picamera2_module()
        pivideostream = self._import_fresh(picamera2_mod=pic2_mod)
        assert pivideostream.PICAMERA2_AVAILABLE is True
        assert pivideostream.PICAMERA_AVAILABLE is False

    def test_falls_back_to_picamera_when_picamera2_missing(self):
        # picamera stub
        pic_mod = MagicMock()
        pic_cam = MagicMock()
        pic_mod.PiCamera.return_value = pic_cam
        pic_mod.PiRGBArray = MagicMock()
        pivideostream = self._import_fresh(picamera_mod=pic_mod)
        assert pivideostream.PICAMERA2_AVAILABLE is False
        assert pivideostream.PICAMERA_AVAILABLE is True

    def test_falls_back_to_opencv_when_both_picamera_libs_missing(self):
        cv2_mod = _make_cv2_module()
        pivideostream = self._import_fresh(cv2_mod=cv2_mod)
        assert pivideostream.PICAMERA2_AVAILABLE is False
        assert pivideostream.PICAMERA_AVAILABLE is False

    def test_raises_when_no_camera_library_available(self):
        # No libraries at all – _import_fresh handles the reload.
        pivideostream = self._import_fresh()
        with pytest.raises(ModuleNotFoundError):
            pivideostream.PiVideoStream(resolution=(320, 240))


class TestPiVideoStreamPicamera2:
    """PiVideoStream behaviour when picamera2 is available."""

    def setup_method(self):
        self.pic2_mod = _make_picamera2_module()
        self.mock_cam = self.pic2_mod.Picamera2.return_value

        sys.modules.pop("seedsigner.hardware.pivideostream", None)
        with patch.dict(sys.modules, {
            "picamera2": self.pic2_mod,
            "picamera": None, "picamera.array": None, "cv2": None,
        }):
            import importlib
            from seedsigner.hardware import pivideostream
            importlib.reload(pivideostream)
            self.stream = pivideostream.PiVideoStream(resolution=(512, 384))

    def test_uses_picamera2(self):
        assert self.stream.use_picamera2 is True
        assert self.stream.use_picamera is False

    def test_configures_rgb888_video(self):
        self.mock_cam.create_video_configuration.assert_called_once()
        kwargs = self.mock_cam.create_video_configuration.call_args
        main_arg = kwargs[1].get("main") or kwargs[0][0]
        assert main_arg["format"] == "RGB888"

    def test_read_returns_none_before_frame(self):
        assert self.stream.read() is None


class TestPiVideoStreamOpenCV:
    """PiVideoStream behaviour when only OpenCV is available."""

    def setup_method(self):
        self.cv2_mod = _make_cv2_module()
        self.mock_cap = self.cv2_mod.VideoCapture.return_value

        sys.modules.pop("seedsigner.hardware.pivideostream", None)
        with patch.dict(sys.modules, {
            "picamera2": None, "picamera": None, "picamera.array": None,
            "cv2": self.cv2_mod,
        }):
            import importlib
            from seedsigner.hardware import pivideostream
            importlib.reload(pivideostream)
            self.stream = pivideostream.PiVideoStream(resolution=(320, 240), device_index=1)

    def test_uses_opencv(self):
        assert self.stream.use_picamera2 is False
        assert self.stream.use_picamera is False

    def test_opens_correct_device_index(self):
        self.cv2_mod.VideoCapture.assert_called_once_with(1)


# ---------------------------------------------------------------------------
# Camera (single-frame mode) tests
# ---------------------------------------------------------------------------

class TestCameraSingleFramePicamera2:
    """Camera.start_single_frame_mode / capture_frame / stop_single_frame_mode
    with picamera2 (libcamera) backend."""

    def _get_camera(self, mock_picam2):
        # Reset the singleton so we get a fresh instance.
        from seedsigner.hardware.camera import Camera
        Camera._instance = None
        Camera._picamera = None
        Camera._using_picamera2 = False

        with patch("seedsigner.models.settings.Settings.get_instance") as mock_settings:
            settings = MagicMock()
            settings.get_value.return_value = 0
            mock_settings.return_value = settings
            cam = Camera.get_instance()
        return cam

    def test_start_single_frame_mode_uses_picamera2(self):
        mock_cam_instance = MagicMock()
        mock_cam_instance.capture_array.return_value = np.zeros((480, 720, 3), dtype=np.uint8)

        with patch("seedsigner.hardware.camera.Camera.get_instance") as _:
            from seedsigner.hardware.camera import Camera
            Camera._instance = None
            Camera._picamera = None
            Camera._using_picamera2 = False
            Camera._camera_rotation = 0
            Camera._camera_index = 0
            Camera._video_stream = None
            cam = Camera.__new__(Camera)
            cam._picamera = None
            cam._using_picamera2 = False
            cam._camera_rotation = 0
            cam._camera_index = 0
            cam._video_stream = None

        with patch("seedsigner.hardware.camera.Camera.stop_single_frame_mode") as mock_stop, \
             patch.dict(sys.modules, {"picamera2": MagicMock(Picamera2=MagicMock(return_value=mock_cam_instance))}):
            cam.start_single_frame_mode(resolution=(720, 480))

        assert cam._using_picamera2 is True
        assert cam._picamera is mock_cam_instance

    def test_capture_frame_picamera2_returns_image(self):
        from PIL import Image
        from seedsigner.hardware.camera import Camera

        mock_cam_instance = MagicMock()
        # Frame shape: (height, width, channels) → 480 rows × 720 cols.
        mock_cam_instance.capture_array.return_value = np.zeros((480, 720, 3), dtype=np.uint8)

        cam = Camera.__new__(Camera)
        cam._picamera = mock_cam_instance
        cam._using_picamera2 = True
        cam._camera_rotation = 0

        result = cam.capture_frame()
        assert isinstance(result, Image.Image)
        mock_cam_instance.capture_array.assert_called_once()

    def test_stop_single_frame_mode_calls_stop_and_close(self):
        from seedsigner.hardware.camera import Camera

        mock_cam_instance = MagicMock()

        cam = Camera.__new__(Camera)
        cam._picamera = mock_cam_instance
        cam._using_picamera2 = True

        cam.stop_single_frame_mode()

        mock_cam_instance.stop.assert_called_once()
        mock_cam_instance.close.assert_called_once()
        assert cam._picamera is None
        assert cam._using_picamera2 is False
