"""Threaded video capture backed by OpenCV."""

import logging
import time
from threading import Thread

logger = logging.getLogger(__name__)

try:
    import cv2  # type: ignore
except Exception:
    cv2 = None


class PiVideoStream:
    """Continuously capture frames in a background thread."""

    def __init__(self, resolution=(320, 240), framerate=32, format="bgr", device_index=0, **kwargs):
        self.should_stop = False
        self.is_stopped = True
        self.frame = None
        self.device_index = device_index

        if cv2 is None:
            raise ModuleNotFoundError(
                "OpenCV is required for camera support; install requirements-desktop.txt"
            )

        self.camera = cv2.VideoCapture(self.device_index)
        self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
        self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])
        self.camera.set(cv2.CAP_PROP_FPS, framerate)

    def start(self):
        t = Thread(target=self.update, args=())
        t.daemon = True
        t.start()
        self.is_stopped = False
        return self

    def update(self):
        while not self.should_stop:
            ret, frame = self.camera.read()
            if ret:
                self.frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

        self.camera.release()
        self.is_stopped = True

    def read(self):
        return self.frame

    def stop(self):
        self.should_stop = True
        while not self.is_stopped:
            time.sleep(0.01)
