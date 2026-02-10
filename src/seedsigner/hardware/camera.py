"""Cross-platform camera abstraction used for scanning QR codes.

This module wraps either the Raspberry Pi camera modules or any system webcam
accessible via pygame or OpenCV. The :class:`Camera` class is implemented as a
singleton so the rest of the codebase can grab a single shared instance.
"""

import io
from PIL import Image
from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.models.singleton import Singleton
from seedsigner.hardware.platform import is_luckfox


class Camera(Singleton):
    """Singleton wrapper around PiCamera or a system webcam."""

    _video_stream = None
    _picamera = None
    _single_frame_stream = None
    _camera_rotation = None
    _camera_index = 0

    @staticmethod
    def list_cameras() -> list[tuple[int, str]]:
        """Return a list of available camera devices as ``(index, name)`` tuples."""
        options: list[tuple[int, str]] = []
        try:
            import pygame  # type: ignore

            pygame.camera.init()
            devices = pygame.camera.list_cameras()
            for i, dev in enumerate(devices):
                name = dev if isinstance(dev, str) else str(dev)
                options.append((i, name))
            pygame.camera.quit()
        except Exception:
            # Fall back to probing via OpenCV if pygame's camera module is unavailable.
            try:
                import cv2  # type: ignore

                i = 0
                consecutive_failures = 0
                while consecutive_failures < 3:
                    cap = cv2.VideoCapture(i)
                    if cap is not None and cap.isOpened():
                        options.append((i, f"Camera {i}"))
                        cap.release()
                        consecutive_failures = 0
                    else:
                        consecutive_failures += 1
                    i += 1
            except Exception:
                pass

        if not options:
            options = SettingsConstants.ALL_CAMERA_DEVICES
        return options

    @classmethod
    def get_instance(cls):
        """Return the singleton camera instance."""
        if cls._instance is None:
            cls._instance = cls.__new__(cls)
        cls._instance._camera_rotation = int(
            Settings.get_instance().get_value(SettingsConstants.SETTING__CAMERA_ROTATION)
        )
        idx = Settings.get_instance().get_value(
            SettingsConstants.SETTING__CAMERA_DEVICE, default_if_none=True
        )
        cls._instance._camera_index = int(idx) if idx is not None else 0
        return cls._instance

    def start_video_stream_mode(self, resolution=(512, 384), framerate=12, format="bgr"):
        """Begin streaming frames from the camera for a live preview."""
        from seedsigner.hardware.pivideostream import PiVideoStream

        if self._video_stream is not None:
            self.stop_video_stream_mode()

        self._video_stream = PiVideoStream(
            resolution=resolution,
            framerate=framerate,
            format=format,
            device_index=self._camera_index,
        )
        self._video_stream.start()

    def read_video_stream(self, as_image=False):
        """Return the latest frame from the video stream.

        If ``as_image`` is ``True`` a PIL :class:`Image` is returned instead of
        the raw numpy array.
        """
        if not self._video_stream:
            raise Exception("Must call start_video_stream first.")
        frame = self._video_stream.read()
        if not as_image:
            return frame
        if frame is not None:
            return Image.fromarray(frame.astype("uint8"), "RGB").convert("RGBA").rotate(
                90 + self._camera_rotation
            )
        return None

    def stop_video_stream_mode(self):
        """Stop the live video stream."""
        if self._video_stream is not None:
            self._video_stream.stop()
            self._video_stream = None

    def start_single_frame_mode(self, resolution=(720, 480)):
        """Prepare the camera to capture a single still frame."""
        if self._video_stream is not None:
            self.stop_video_stream_mode()
        if self._picamera is not None:
            if hasattr(self._picamera, "close"):
                self._picamera.close()
            else:
                self._picamera.release()
        if self._single_frame_stream is not None:
            self._single_frame_stream.stop()
            self._single_frame_stream = None

        try:
            from picamera import PiCamera

            self._picamera = PiCamera(resolution=resolution, framerate=24)
            self._picamera.start_preview()
        except Exception:
            try:
                import cv2  # type: ignore

                self._picamera = cv2.VideoCapture(self._camera_index)
                self._picamera.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
                self._picamera.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])
            except Exception:
                if not is_luckfox():
                    raise ModuleNotFoundError(
                        "OpenCV is required for desktop camera support; install requirements-desktop.txt",
                    )

                from seedsigner.hardware.pivideostream import PiVideoStream

                self._single_frame_stream = PiVideoStream(
                    resolution=resolution,
                    framerate=2,
                    format="rgb",
                    device_index=self._camera_index,
                ).start()

    def capture_frame(self):
        """Capture a single frame from the camera as a PIL image."""
        if self._picamera is None and self._single_frame_stream is None:
            raise Exception("Must call start_single_frame_mode first.")

        if hasattr(self._picamera, "capture"):
            # PiCamera path
            self._picamera.shutter_speed = self._picamera.exposure_speed
            self._picamera.exposure_mode = "off"
            g = self._picamera.awb_gains
            self._picamera.awb_mode = "off"
            self._picamera.awb_gains = g

            stream = io.BytesIO()
            self._picamera.capture(stream, format="jpeg")
            stream.seek(0)
            return Image.open(stream).rotate(90 + self._camera_rotation)

        if self._picamera is not None:
            # OpenCV path
            ret, frame = self._picamera.read()
            if not ret:
                return None
            return Image.fromarray(frame.astype("uint8"), "RGB").rotate(
                90 + self._camera_rotation
            )

        if self._single_frame_stream is not None:
            for _ in range(20):
                frame = self._single_frame_stream.read()
                if frame is not None:
                    return Image.fromarray(frame.astype("uint8"), "RGB").rotate(
                        90 + self._camera_rotation
                    )
            return None

        return None

    def stop_single_frame_mode(self):
        """Release any resources used for single-frame capture."""
        if self._picamera is not None:
            if hasattr(self._picamera, "close"):
                self._picamera.close()
            else:
                self._picamera.release()
            self._picamera = None

        if self._single_frame_stream is not None:
            self._single_frame_stream.stop()
            self._single_frame_stream = None

