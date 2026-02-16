"""Threaded video capture that supports both PiCamera and OpenCV backends."""

import logging
import os
import time
from threading import Thread

logger = logging.getLogger(__name__)

try:
    from picamera.array import PiRGBArray
    from picamera import PiCamera

    PICAMERA_AVAILABLE = True
except Exception:
    PICAMERA_AVAILABLE = False
    PiRGBArray = None
    PiCamera = None

try:
    import cv2  # type: ignore
except Exception:
    cv2 = None


class VideoStream:
    """Continuously capture frames in a background thread."""

    def __init__(self, resolution=(320, 240), framerate=32, format="bgr", device_index=0, **kwargs):
        self.should_stop = False
        self.is_stopped = True
        self.frame = None
        self.device_index = int(device_index)
        self.resolution = resolution
        self.framerate = framerate
        self.use_picamera = False

        if PICAMERA_AVAILABLE:
            self.camera = PiCamera(resolution=resolution, framerate=framerate, **kwargs)
            self.raw_capture = PiRGBArray(self.camera, size=resolution)
            self.stream = self.camera.capture_continuous(
                self.raw_capture,
                format=format,
                use_video_port=True,
            )
            self.use_picamera = True
            return

        if cv2 is None:
            raise ModuleNotFoundError(
                "OpenCV is required for desktop camera support; install requirements-desktop.txt"
            )

        self.camera = self._open_cv_capture()
        self.stream = None
        self.raw_capture = None

    def _configure_capture(self, capture) -> None:
        capture.set(cv2.CAP_PROP_FRAME_WIDTH, self.resolution[0])
        capture.set(cv2.CAP_PROP_FRAME_HEIGHT, self.resolution[1])
        capture.set(cv2.CAP_PROP_FPS, self.framerate)

    def _open_cv_capture(self):
        candidates = [self.device_index]
        for idx in (0, 1, 2, 3):
            if idx not in candidates:
                candidates.append(idx)

        for idx in candidates:
            capture = None
            try:
                if os.name == "nt":
                    capture = cv2.VideoCapture(idx, cv2.CAP_DSHOW)
                    if not capture.isOpened():
                        capture.release()
                        capture = cv2.VideoCapture(idx, cv2.CAP_MSMF)
                else:
                    capture = cv2.VideoCapture(idx)

                if capture is not None and capture.isOpened():
                    self.device_index = idx
                    self._configure_capture(capture)
                    return capture
            except Exception:
                if capture is not None:
                    capture.release()
                continue

            if capture is not None:
                capture.release()
        return None

    def start(self):
        if not self.use_picamera:
            if self.camera is None or not self.camera.isOpened():
                raise Exception("Unable to open camera device")
            # Fail fast if the backend opened but cannot produce frames.
            for _ in range(20):
                ret, frame = self.camera.read()
                if ret:
                    self.frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    break
                time.sleep(0.05)
            if self.frame is None:
                self.camera.release()
                self.camera = None
                raise Exception("Unable to read frames from camera device")

        t = Thread(target=self.update, args=())
        t.daemon = True
        t.start()
        self.is_stopped = False
        return self

    def update(self):
        if self.use_picamera:
            for f in self.stream:
                self.frame = f.array
                self.raw_capture.truncate(0)
                if self.should_stop:
                    self.stream.close()
                    self.raw_capture.close()
                    self.camera.close()
                    self.should_stop = False
                    self.is_stopped = True
                    return
            return

        while not self.should_stop:
            ret, frame = self.camera.read()
            if ret:
                self.frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            else:
                time.sleep(0.01)

        self.camera.release()
        self.is_stopped = True

    def read(self):
        return self.frame

    def stop(self):
        self.should_stop = True
        while not self.is_stopped:
            time.sleep(0.01)


# Backward compatibility for existing imports.
PiVideoStream = VideoStream
