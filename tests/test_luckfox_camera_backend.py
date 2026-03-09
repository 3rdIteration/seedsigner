from importlib import import_module
import sys

import pytest
from PIL import Image
from unittest.mock import MagicMock

from seedsigner.hardware.pivideostream import VideoStream


def _get_camera_class():
    camera_module = sys.modules.get("seedsigner.hardware.camera")
    if isinstance(camera_module, MagicMock):
        del sys.modules["seedsigner.hardware.camera"]
    return import_module("seedsigner.hardware.camera").Camera


class DummyVideoStream:
    def __init__(self, frame):
        self._frame = frame

    def read(self):
        return self._frame


def test_camera_read_video_stream_supports_pil_frames():
    camera_class = _get_camera_class()
    camera = camera_class.__new__(camera_class)
    camera._video_stream = DummyVideoStream(Image.new("RGB", (4, 4), color=(1, 2, 3)))
    camera._camera_rotation = 180

    frame = camera.read_video_stream(as_image=True)
    assert isinstance(frame, Image.Image)
    assert frame.size == (4, 4)


def test_camera_luckfox_stream_prefers_v4l2(monkeypatch):
    captured = {}

    class FakeVideoStream:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def start(self):
            captured["started"] = True

    monkeypatch.setattr("seedsigner.hardware.pivideostream.VideoStream", FakeVideoStream)

    camera_class = _get_camera_class()
    camera = camera_class.__new__(camera_class)
    camera._video_stream = None
    camera._camera_index = 0
    camera._runtime_profile = "luckfox_22"
    camera._hardware_camera_config = {
        "device": "/dev/video12",
        "resolution": (800, 600),
        "pixelformat": "NV12",
        "framerate": 10,
    }

    camera.start_video_stream_mode(resolution=(320, 240), framerate=12, format="rgb")

    assert captured["prefer_v4l2"] is True
    assert captured["resolution"] == (800, 600)
    assert captured["framerate"] == 10
    assert captured["camera_config"]["pixelformat"] == "NV12"
    assert captured["started"] is True


def test_camera_rpi_stream_uses_io_config(monkeypatch):
    captured = {}

    class FakeVideoStream:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def start(self):
            captured["started"] = True

    monkeypatch.setattr("seedsigner.hardware.pivideostream.VideoStream", FakeVideoStream)

    camera_class = _get_camera_class()
    camera = camera_class.__new__(camera_class)
    camera._video_stream = None
    camera._camera_index = 0
    camera._runtime_profile = "rpi_40"
    camera._hardware_camera_config = {
        "device": "/dev/video0",
        "resolution": (1280, 720),
        "framerate": 4,
    }

    camera.start_video_stream_mode(resolution=(512, 384), framerate=12, format="bgr")

    assert captured["prefer_v4l2"] is False
    assert captured["resolution"] == (1280, 720)
    assert captured["framerate"] == 4
    assert captured["started"] is True


def test_v4l2_frame_size_calculation():
    assert VideoStream._calculate_v4l2_frame_size(2, 2, "XR24") == 16
    assert VideoStream._calculate_v4l2_frame_size(2, 2, "NV12") == 6
    assert VideoStream._calculate_v4l2_frame_size(2, 2, "UYVY") == 8
    assert VideoStream._calculate_v4l2_frame_size(2, 2, "GREY") == 4


def test_decode_xr24_frame():
    stream = VideoStream.__new__(VideoStream)
    stream._v4l2_resolution = (1, 1)
    stream._v4l2_pixelformat = "XR24"

    image = stream._decode_v4l2_frame(bytes([10, 20, 30, 0]))
    assert isinstance(image, Image.Image)
    assert image.getpixel((0, 0)) == (30, 20, 10)


def test_configure_v4l2_capture_selects_supported_node(monkeypatch):
    stream = VideoStream.__new__(VideoStream)
    stream.use_v4l2 = False
    stream._camera_config = {"resolution": (800, 600), "framerate": 10, "pixelformat": "NV12"}
    stream.resolution = (320, 240)
    stream.framerate = 12

    monkeypatch.setattr("os.path.exists", lambda path: True)
    monkeypatch.setattr(stream, "_normalize_device_candidates", lambda: ["/dev/video12"])
    monkeypatch.setattr(stream, "_list_v4l2_formats", lambda device: {"NV12", "UYVY"})
    monkeypatch.setattr(stream, "_probe_v4l2_device", lambda *args, **kwargs: (True, True))
    monkeypatch.setattr(stream, "_get_negotiated_v4l2_format", lambda *args, **kwargs: (800, 600, "NV12", None))

    stream._configure_v4l2_capture()

    assert stream.use_v4l2 is True
    assert stream._v4l2_device == "/dev/video12"
    assert stream._v4l2_pixelformat == "NV12"
    assert stream._v4l2_resolution == (800, 600)
    assert stream._v4l2_use_set_parm is True


def test_camera_luckfox_profile_detection_includes_pico_pi():
    camera_class = _get_camera_class()
    assert camera_class._is_luckfox_profile("luckfox_pi") is True


def test_configure_v4l2_capture_uses_negotiated_resolution(monkeypatch):
    stream = VideoStream.__new__(VideoStream)
    stream.use_v4l2 = False
    stream._camera_config = {"resolution": (800, 600), "framerate": 10, "pixelformat": "NV12"}
    stream.resolution = (320, 240)
    stream.framerate = 12

    monkeypatch.setattr("os.path.exists", lambda path: True)
    monkeypatch.setattr(stream, "_normalize_device_candidates", lambda: ["/dev/video14"])
    monkeypatch.setattr(stream, "_list_v4l2_formats", lambda device: {"NV12"})
    monkeypatch.setattr(stream, "_probe_v4l2_device", lambda *args, **kwargs: (True, False))
    monkeypatch.setattr(stream, "_get_negotiated_v4l2_format", lambda *args, **kwargs: (576, 324, "NV12", None))

    stream._configure_v4l2_capture()

    assert stream.use_v4l2 is True
    assert stream._v4l2_device == "/dev/video14"
    assert stream._v4l2_pixelformat == "NV12"
    assert stream._v4l2_resolution == (576, 324)
    assert stream._v4l2_frame_size == (576 * 324 * 3) // 2


class _MockPiCameraMMALError(Exception):
    """Stand-in for picamera.exc.PiCameraMMALError in tests."""


def test_picamera_retry_on_init_failure(monkeypatch):
    """PiCamera init retries once when the first attempt raises PiCameraMMALError."""
    mock_camera = MagicMock()
    mock_raw = MagicMock()
    mock_picamera = MagicMock(side_effect=[_MockPiCameraMMALError("mmal error"), mock_camera])
    mock_pirgb = MagicMock(return_value=mock_raw)
    mock_camera.capture_continuous.return_value = iter([])

    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA2_AVAILABLE", False)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA_AVAILABLE", True)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiCamera", mock_picamera)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiCameraMMALError", _MockPiCameraMMALError)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiRGBArray", mock_pirgb)
    monkeypatch.setattr("time.sleep", lambda _: None)

    stream = VideoStream(resolution=(320, 240), framerate=12, format="bgr")

    assert stream.use_picamera is True
    assert stream.camera is mock_camera
    assert mock_picamera.call_count == 2


def test_picamera_no_retry_on_success(monkeypatch):
    """PiCamera init does not retry when the first attempt succeeds."""
    mock_camera = MagicMock()
    mock_raw = MagicMock()
    mock_picamera = MagicMock(return_value=mock_camera)
    mock_pirgb = MagicMock(return_value=mock_raw)
    mock_camera.capture_continuous.return_value = iter([])

    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA2_AVAILABLE", False)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA_AVAILABLE", True)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiCamera", mock_picamera)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiRGBArray", mock_pirgb)

    stream = VideoStream(resolution=(320, 240), framerate=12, format="bgr")

    assert stream.use_picamera is True
    assert stream.camera is mock_camera
    assert mock_picamera.call_count == 1


def test_picamera_retry_still_raises_on_second_failure(monkeypatch):
    """If both PiCamera init attempts fail, the exception propagates."""
    mock_picamera = MagicMock(
        side_effect=[_MockPiCameraMMALError("mmal error"), _MockPiCameraMMALError("mmal error again")]
    )

    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA2_AVAILABLE", False)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA_AVAILABLE", True)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiCamera", mock_picamera)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiCameraMMALError", _MockPiCameraMMALError)
    monkeypatch.setattr("time.sleep", lambda _: None)

    with pytest.raises(_MockPiCameraMMALError, match="mmal error again"):
        VideoStream(resolution=(320, 240), framerate=12, format="bgr")

    assert mock_picamera.call_count == 2


def test_picamera_always_captures_rgb(monkeypatch):
    """PiCamera capture_continuous is called with format='rgb' regardless of caller format."""
    mock_camera = MagicMock()
    mock_raw = MagicMock()
    mock_picamera = MagicMock(return_value=mock_camera)
    mock_pirgb = MagicMock(return_value=mock_raw)
    mock_camera.capture_continuous.return_value = iter([])

    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA2_AVAILABLE", False)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA_AVAILABLE", True)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiCamera", mock_picamera)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiRGBArray", mock_pirgb)

    VideoStream(resolution=(320, 240), framerate=12, format="bgr")

    mock_camera.capture_continuous.assert_called_once_with(
        mock_raw,
        format="rgb",
        use_video_port=True,
    )


def test_picamera2_used_when_available(monkeypatch):
    """Picamera2 is selected over picamera when PICAMERA2_AVAILABLE is True."""
    mock_picam2 = MagicMock()
    mock_picamera2_cls = MagicMock(return_value=mock_picam2)
    mock_picam2.create_video_configuration.return_value = {}

    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA2_AVAILABLE", True)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.Picamera2", mock_picamera2_cls)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA_AVAILABLE", False)

    stream = VideoStream(resolution=(320, 240), framerate=12, format="bgr")

    assert stream.use_picamera2 is True
    assert stream.use_picamera is False
    assert stream.camera is mock_picam2
    mock_picam2.configure.assert_called_once()
    mock_picam2.start.assert_called_once()


def test_picamera2_video_config_uses_rgb888(monkeypatch):
    """Picamera2 video configuration requests RGB888 format."""
    mock_picam2 = MagicMock()
    mock_picamera2_cls = MagicMock(return_value=mock_picam2)
    mock_picam2.create_video_configuration.return_value = {}

    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA2_AVAILABLE", True)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.Picamera2", mock_picamera2_cls)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA_AVAILABLE", False)

    VideoStream(resolution=(640, 480), framerate=15, format="bgr")

    call_kwargs = mock_picam2.create_video_configuration.call_args
    assert call_kwargs.kwargs["main"]["size"] == (640, 480)
    assert call_kwargs.kwargs["main"]["format"] == "RGB888"
    assert call_kwargs.kwargs["controls"]["FrameRate"] == 15.0


def test_picamera_fallback_when_picamera2_unavailable(monkeypatch):
    """Picamera is used when picamera2 is not available."""
    mock_camera = MagicMock()
    mock_raw = MagicMock()
    mock_picamera = MagicMock(return_value=mock_camera)
    mock_pirgb = MagicMock(return_value=mock_raw)
    mock_camera.capture_continuous.return_value = iter([])

    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA2_AVAILABLE", False)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA_AVAILABLE", True)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiCamera", mock_picamera)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiRGBArray", mock_pirgb)

    stream = VideoStream(resolution=(320, 240), framerate=12, format="bgr")

    assert stream.use_picamera is True
    assert stream.use_picamera2 is False
    assert stream.camera is mock_camera


def test_picamera2_not_used_for_v4l2_profile(monkeypatch):
    """Picamera2 is skipped when prefer_v4l2 is True (e.g. Luckfox profiles)."""
    mock_picam2 = MagicMock()
    mock_picamera2_cls = MagicMock(return_value=mock_picam2)

    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA2_AVAILABLE", True)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.Picamera2", mock_picamera2_cls)

    stream = VideoStream.__new__(VideoStream)
    stream._prefer_v4l2 = True
    stream._camera_config = {"resolution": (800, 600), "framerate": 10, "pixelformat": "NV12"}
    stream.resolution = (320, 240)
    stream.framerate = 12
    stream.use_picamera2 = False
    stream.use_v4l2 = False

    monkeypatch.setattr("os.path.exists", lambda path: True)
    monkeypatch.setattr(stream, "_normalize_device_candidates", lambda: ["/dev/video12"])
    monkeypatch.setattr(stream, "_list_v4l2_formats", lambda device: {"NV12"})
    monkeypatch.setattr(stream, "_probe_v4l2_device", lambda *args, **kwargs: (True, True))
    monkeypatch.setattr(stream, "_get_negotiated_v4l2_format", lambda *args, **kwargs: (800, 600, "NV12", None))

    stream._configure_v4l2_capture()

    mock_picamera2_cls.assert_not_called()
    assert stream.use_v4l2 is True
