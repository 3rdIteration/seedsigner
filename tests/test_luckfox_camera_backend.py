from importlib import import_module
import sys

import pytest
from PIL import Image
from unittest.mock import MagicMock, patch, call

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
    assert captured["framerate"] == 12
    assert captured["camera_config"]["pixelformat"] == "NV12"
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


def test_picamera_retry_on_init_failure(monkeypatch):
    """PiCamera init retries once when the first attempt raises."""
    mock_camera = MagicMock()
    mock_raw = MagicMock()
    mock_picamera = MagicMock(side_effect=[Exception("mmal error"), mock_camera])
    mock_pirgb = MagicMock(return_value=mock_raw)
    mock_camera.capture_continuous.return_value = iter([])

    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA_AVAILABLE", True)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiCamera", mock_picamera)
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

    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA_AVAILABLE", True)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiCamera", mock_picamera)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiRGBArray", mock_pirgb)

    stream = VideoStream(resolution=(320, 240), framerate=12, format="bgr")

    assert stream.use_picamera is True
    assert stream.camera is mock_camera
    assert mock_picamera.call_count == 1


def test_picamera_retry_still_raises_on_second_failure(monkeypatch):
    """If both PiCamera init attempts fail, the exception propagates."""
    mock_picamera = MagicMock(side_effect=[Exception("mmal error"), Exception("mmal error again")])

    monkeypatch.setattr("seedsigner.hardware.pivideostream.PICAMERA_AVAILABLE", True)
    monkeypatch.setattr("seedsigner.hardware.pivideostream.PiCamera", mock_picamera)
    monkeypatch.setattr("time.sleep", lambda _: None)

    with pytest.raises(Exception, match="mmal error again"):
        VideoStream(resolution=(320, 240), framerate=12, format="bgr")

    assert mock_picamera.call_count == 2
