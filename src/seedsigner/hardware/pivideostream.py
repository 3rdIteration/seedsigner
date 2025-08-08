# import the necessary packages
import logging
from threading import Thread
import time

logger = logging.getLogger(__name__)

# Try to support both the legacy ``picamera`` module and the newer
# ``picamera2`` library. We attempt to import ``picamera`` first to maintain
# backwards compatibility. If that fails we fall back to ``picamera2``. If
# neither library is available, ``_BACKEND`` will remain ``None`` and users
# will receive an informative error when attempting to instantiate the stream.
try:  # pragma: no cover - library import shim
    from picamera.array import PiRGBArray  # type: ignore
    from picamera import PiCamera  # type: ignore
    _BACKEND = "picamera"
except Exception:  # pragma: no cover - the new module may be installed instead
    try:
        from picamera2 import Picamera2  # type: ignore
        _BACKEND = "picamera2"
    except Exception:  # pragma: no cover - no supported camera library
        PiCamera = None  # type: ignore
        PiRGBArray = None  # type: ignore
        Picamera2 = None  # type: ignore
        _BACKEND = None


# Modified from: https://github.com/jrosebr1/imutils
class PiVideoStream:
        def __init__(self, resolution=(320, 240), framerate=32, format="bgr", **kwargs):
                """Create a video stream using either picamera or picamera2."""
                if _BACKEND == "picamera":
                        self.camera = PiCamera(resolution=resolution, framerate=framerate, **kwargs)
                        self.rawCapture = PiRGBArray(self.camera, size=resolution)
                        self.stream = self.camera.capture_continuous(
                                self.rawCapture, format=format, use_video_port=True)
                elif _BACKEND == "picamera2":
                        self.camera = Picamera2()
                        try:  # pragma: no cover - depends on library version
                                config = self.camera.create_video_configuration(
                                        main={"size": resolution, "format": "RGB888"})
                                self.camera.configure(config)
                        except Exception:
                                pass
                        self.camera.start()
                        self.stream = None  # type: ignore
                        self.rawCapture = None  # type: ignore
                else:  # pragma: no cover
                        raise RuntimeError("No supported camera library found. Install picamera or picamera2.")

                self.frame = None
                self.should_stop = False
                self.is_stopped = True

        def start(self):
                t = Thread(target=self.update, args=())
                t.daemon = True
                t.start()
                self.is_stopped = False
                return self

        def update(self):
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
                else:
                        while True:
                                self.frame = self.camera.capture_array()
                                if self.should_stop:
                                        logger.info("PiVideoStream: closing everything")
                                        try:
                                                self.camera.stop()
                                                self.camera.close()
                                        except Exception:
                                                pass
                                        self.should_stop = False
                                        self.is_stopped = True
                                        return

        def read(self):
                return self.frame

        def stop(self):
                self.should_stop = True
                while not self.is_stopped:
                        pass
