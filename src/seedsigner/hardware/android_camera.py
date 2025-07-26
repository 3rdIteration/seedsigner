import io
from threading import Thread
from PIL import Image


class AndroidCamera:
    """Camera implementation using OpenCV for Android."""

    def __init__(self):
        self._cap = None
        self._camera_rotation = 0

    # Public API mirrors seedsigner.hardware.camera.Camera
    def start_video_stream_mode(self, resolution=(512, 384), framerate=12, format="bgr"):
        import cv2
        self._cap = cv2.VideoCapture(0)
        self._cap.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
        self._cap.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])
        self._cap.set(cv2.CAP_PROP_FPS, framerate)

    def read_video_stream(self, as_image=False):
        import cv2
        if self._cap is None:
            raise Exception("Must call start_video_stream first.")
        ret, frame = self._cap.read()
        if not ret:
            return None
        if as_image:
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            return Image.fromarray(frame).rotate(90 + self._camera_rotation)
        return frame

    def stop_video_stream_mode(self):
        if self._cap is not None:
            self._cap.release()
            self._cap = None

    def start_single_frame_mode(self, resolution=(720, 480)):
        self.start_video_stream_mode(resolution)

    def capture_frame(self):
        if self._cap is None:
            raise Exception("Must call start_single_frame_mode first.")
        ret, frame = self._cap.read()
        if not ret:
            return None
        from cv2 import cvtColor, COLOR_BGR2RGB
        frame = cvtColor(frame, COLOR_BGR2RGB)
        return Image.fromarray(frame).rotate(90 + self._camera_rotation)

    def stop_single_frame_mode(self):
        self.stop_video_stream_mode()
