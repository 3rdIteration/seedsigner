"""Threaded video capture using OpenCV."""

import logging
import time
from threading import Thread

logger = logging.getLogger(__name__)

try:
    import cv2  # type: ignore
except Exception:
    cv2 = None


class PiVideoStream:
    """Continuously capture frames in a background thread using OpenCV."""

    def __init__(self, resolution=(320, 240), framerate=32, format="bgr", device_index=0, **kwargs):
        """Initialize the video stream using OpenCV VideoCapture.
        
        Args:
            resolution: Tuple of (width, height) for video capture
            framerate: Frames per second (note: may not be supported by all cameras)
            format: Color format (bgr for OpenCV)
            device_index: Camera device index (0 for first camera)
        """
        self.should_stop = False
        self.is_stopped = True
        self.frame = None
        self.device_index = device_index

        if cv2 is None:
            raise ModuleNotFoundError(
                "OpenCV is required for camera support; install opencv-python"
            )
        
        self.camera = cv2.VideoCapture(self.device_index)
        self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
        self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])
        # Note: FPS setting may not work on all cameras
        self.camera.set(cv2.CAP_PROP_FPS, framerate)

    def start(self):
        """Start the capture thread."""
        t = Thread(target=self.update, args=())
        t.daemon = True
        t.start()
        self.is_stopped = False
        return self

    def update(self):
        """Continuously read frames until :meth:`stop` is called."""
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
