import logging
import time
from threading import Thread

logger = logging.getLogger(__name__)

try:
    from picamera.array import PiRGBArray
    from picamera import PiCamera
    PICAMERA_AVAILABLE = True
except Exception:  # ModuleNotFoundError, ImportError, etc.
    PICAMERA_AVAILABLE = False
    try:
        import cv2  # type: ignore
    except Exception:
        cv2 = None


class PiVideoStream:
    """Video stream that falls back to OpenCV on desktops."""

    def __init__(self, resolution=(320, 240), framerate=32, format="bgr", device_index=0, **kwargs):
        self.should_stop = False
        self.is_stopped = True
        self.frame = None
        self.device_index = device_index

        if PICAMERA_AVAILABLE:
            self.camera = PiCamera(resolution=resolution, framerate=framerate, **kwargs)
            self.rawCapture = PiRGBArray(self.camera, size=resolution)
            self.stream = self.camera.capture_continuous(
                self.rawCapture, format=format, use_video_port=True
            )
            self.use_picamera = True
        else:
            if cv2 is None:
                raise ModuleNotFoundError(
                    "OpenCV is required for desktop camera support; install requirements-desktop.txt"
                )
            self.camera = cv2.VideoCapture(self.device_index)
            self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
            self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])
            self.use_picamera = False

    def start(self):
        t = Thread(target=self.update, args=())
        t.daemon = True
        t.start()
        self.is_stopped = False
        return self

    def update(self):
        if self.use_picamera:
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
            while not self.should_stop:
                ret, frame = self.camera.read()
                if ret:
                    self.frame = frame
            self.camera.release()
            self.is_stopped = True

    def read(self):
        return self.frame

    def stop(self):
        self.should_stop = True
        while not self.is_stopped:
            time.sleep(0.01)
