"""Threaded video capture for PiCamera, OpenCV, and Luckfox v4l2 backends."""

import logging
import os
import shutil
import subprocess
import time
from threading import Thread


from seedsigner.hardware.platform import get_luckfox_profile, is_luckfox

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
    """Continuously capture frames in a background thread."""

    def __init__(self, resolution=(320, 240), framerate=32, format="bgr", device_index=0, **kwargs):
        self.should_stop = False
        self.is_stopped = True
        self.frame = None
        self.device_index = device_index
        self.width, self.height = resolution
        self.v4l2_process = None

        if PICAMERA_AVAILABLE:
            self.backend = "picamera"
            self.camera = PiCamera(resolution=resolution, framerate=framerate, **kwargs)
            self.rawCapture = PiRGBArray(self.camera, size=resolution)
            self.stream = self.camera.capture_continuous(
                self.rawCapture, format=format, use_video_port=True
            )
            return

        if is_luckfox() and self._v4l2_available():
            self.backend = "v4l2"
            self.luckfox_profile = get_luckfox_profile()
            self.device = self._select_v4l2_device(device_index)
            self.frame_size = self.width * self.height
            self.camera = None
            return

        if cv2 is None:
            raise ModuleNotFoundError(
                "No supported camera backend found. Install OpenCV for desktop mode."
            )

        self.backend = "opencv"
        self.camera = cv2.VideoCapture(self.device_index)
        self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
        self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])

    def start(self):
        t = Thread(target=self.update, args=())
        t.daemon = True
        t.start()
        self.is_stopped = False
        return self

    def update(self):
        if self.backend == "picamera":
            self._update_picamera()
        elif self.backend == "v4l2":
            self._update_v4l2()
        else:
            self._update_opencv()

    def _update_picamera(self):
        for f in self.stream:
            self.frame = f.array
            self.rawCapture.truncate(0)
            if self.should_stop:
                logger.info("PiVideoStream: closing picamera stream")
                self.stream.close()
                self.rawCapture.close()
                self.camera.close()
                self.should_stop = False
                self.is_stopped = True
                return

    def _update_opencv(self):
        while not self.should_stop:
            ret, frame = self.camera.read()
            if ret:
                self.frame = frame
        self.camera.release()
        self.is_stopped = True

    def _update_v4l2(self):
        try:
            import numpy as np  # type: ignore
        except ModuleNotFoundError as e:
            raise ModuleNotFoundError("Luckfox v4l2 backend requires numpy") from e

        cmd = [
            "v4l2-ctl",
            f"--device={self.device}",
            f"--set-fmt-video=width={self.width},height={self.height},pixelformat=GREY",
            "--stream-mmap",
            "--stream-to=-",
            "--stream-count=0",
        ]
        self.v4l2_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=self.frame_size * 4,
        )

        while not self.should_stop:
            if self.v4l2_process.stdout is None:
                break
            frame_data = self.v4l2_process.stdout.read(self.frame_size)
            if len(frame_data) < self.frame_size:
                break
            grey = np.frombuffer(frame_data, dtype=np.uint8).reshape((self.height, self.width))
            self.frame = np.stack((grey, grey, grey), axis=-1)

        if self.v4l2_process and self.v4l2_process.poll() is None:
            self.v4l2_process.terminate()
            self.v4l2_process.wait(timeout=1)
        self.is_stopped = True

    def read(self):
        return self.frame

    def stop(self):
        self.should_stop = True
        while not self.is_stopped:
            time.sleep(0.01)

    def _v4l2_available(self) -> bool:
        return shutil.which("v4l2-ctl") is not None

    def _select_v4l2_device(self, preferred_index: int) -> str:
        preferred = f"/dev/video{preferred_index}"
        if os.path.exists(preferred):
            return preferred
        for candidate in self.luckfox_profile.video_devices:
            if os.path.exists(candidate):
                return candidate
        return preferred
