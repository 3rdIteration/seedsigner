"""Threaded video capture that works with both PiCamera and OpenCV webcams."""

import logging
import time
from threading import Thread

logger = logging.getLogger(__name__)

# Attempt to support the legacy ``picamera`` module, the newer ``picamera2``
# library, or fall back to OpenCV if neither is available.
try:  # pragma: no cover - library import shim
    from picamera.array import PiRGBArray  # type: ignore
    from picamera import PiCamera  # type: ignore
    _BACKEND = "picamera"
except Exception:  # pragma: no cover
    try:
        from picamera2 import Picamera2  # type: ignore
        _BACKEND = "picamera2"
    except Exception:  # pragma: no cover
        PiCamera = None  # type: ignore
        PiRGBArray = None  # type: ignore
        Picamera2 = None  # type: ignore
        _BACKEND = None

try:  # optional dependency used for desktop webcams
    import cv2  # type: ignore
except Exception:  # pragma: no cover
    cv2 = None  # type: ignore


class PiVideoStream:
    """Continuously capture frames in a background thread."""

    def __init__(self, resolution=(320, 240), framerate=32, format="bgr", device_index=0, **kwargs):
        """
        Initialize the video stream.

        When running on a Pi with a supported picamera library available we use that;
        otherwise we fall back to OpenCV's ``VideoCapture`` on the given ``device_index``.
        """
        self.should_stop = False
        self.is_stopped = True
        self.frame = None
        self.device_index = device_index

        if _BACKEND == "picamera":
            self.camera = PiCamera(resolution=resolution, framerate=framerate, **kwargs)
            self.rawCapture = PiRGBArray(self.camera, size=resolution)
            self.stream = self.camera.capture_continuous(self.rawCapture, format=format, use_video_port=True)
        elif _BACKEND == "picamera2":
            self.camera = Picamera2()
            try:  # pragma: no cover - depends on library version
                config = self.camera.create_video_configuration(main={"size": resolution, "format": "RGB888"})
                self.camera.configure(config)
            except Exception:
                pass
            self.camera.start()
            self.stream = None
            self.rawCapture = None
        else:
            if cv2 is None:
                raise ModuleNotFoundError(
                    "OpenCV is required for desktop camera support; install requirements-desktop.txt"
                )
            self.camera = cv2.VideoCapture(self.device_index)
            self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
            self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])

        self.use_picamera = _BACKEND in ("picamera", "picamera2")

    def start(self):
        """Start the capture thread."""
        t = Thread(target=self.update, args=())
        t.daemon = True
        t.start()
        self.is_stopped = False
        return self

    def update(self):
        """Continuously read frames until :meth:`stop` is called."""
        if _BACKEND == "picamera":
            for f in self.stream:
                self.frame = f.array
                self.rawCapture.truncate(0)
                if self.should_stop:
                    logger.info("PiVideoStream: closing everything")
                    self.stream.close()
                    self.rawCapture.close()
                    self.camera.close()
                    self.should_stop = False
                    self.is_stopped = True
                    return
        elif _BACKEND == "picamera2":
            while not self.should_stop:
                self.frame = self.camera.capture_array()
            logger.info("PiVideoStream: closing everything")
            try:
                self.camera.stop()
                self.camera.close()
            except Exception:
                pass
            self.should_stop = False
            self.is_stopped = True
        else:
            while not self.should_stop:
                ret, frame = self.camera.read()
                if ret:
                    self.frame = frame
            self.camera.release()
            self.is_stopped = True

    def read(self):
        """Return the most recently captured frame."""
        return self.frame

    def stop(self):
        """Signal the capture thread to stop and wait for it to finish."""
        self.should_stop = True
        while not self.is_stopped:
            time.sleep(0.01)

