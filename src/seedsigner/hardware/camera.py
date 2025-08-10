"""Cross-platform camera abstraction used for scanning QR codes.

This module wraps either the Raspberry Pi camera modules or any system webcam
accessible via pygame or OpenCV. The :class:`Camera` class is implemented as a
singleton so the rest of the codebase can grab a single shared instance.
"""

import io
from PIL import Image
from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.models.singleton import Singleton


class Camera(Singleton):
    """Singleton wrapper around PiCamera or a system webcam."""

    _video_stream = None
    _picamera = None
    _camera_rotation = None
    _camera_index = 0
    _picamera_backend = None

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
            self.stop_single_frame_mode()

        # Prefer the legacy picamera module if available to maintain backwards
        # compatibility. Fall back to picamera2 if necessary.
        try:  # pragma: no cover - hardware dependent
            from picamera import PiCamera  # type: ignore

            self._picamera = PiCamera(resolution=resolution, framerate=24)
            self._picamera.start_preview()
            self._picamera_backend = "picamera"
        except Exception:  # pragma: no cover
            try:
                from picamera2 import Picamera2  # type: ignore

                self._picamera = Picamera2()
                try:
                    config = self._picamera.create_still_configuration(
                        main={"size": resolution, "format": "RGB888"}
                    )
                    self._picamera.configure(config)
                except Exception:
                    pass
                self._picamera.start()
                self._picamera_backend = "picamera2"
            except Exception:
                try:
                    import cv2  # type: ignore
                except Exception as e:
                    raise ModuleNotFoundError(
                        "OpenCV is required for desktop camera support; install requirements-desktop.txt",
                    ) from e
                self._picamera = cv2.VideoCapture(self._camera_index)
                self._picamera.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
                self._picamera.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])
                self._picamera_backend = "opencv"

    def capture_frame(self):
        """Capture a single frame from the camera as a PIL image."""
        if self._picamera is None:
            raise Exception("Must call start_single_frame_mode first.")

        if self._picamera_backend == "picamera":
            # Set auto-exposure values
            self._picamera.shutter_speed = self._picamera.exposure_speed
            self._picamera.exposure_mode = "off"
            g = self._picamera.awb_gains
            self._picamera.awb_mode = "off"
            self._picamera.awb_gains = g

            stream = io.BytesIO()
            self._picamera.capture(stream, format="jpeg")

            # "Rewind" the stream to the beginning so we can read its content
            stream.seek(0)
            return Image.open(stream).rotate(90 + self._camera_rotation)

        if self._picamera_backend == "picamera2":
            frame = self._picamera.capture_array()
            return Image.fromarray(frame).rotate(90 + self._camera_rotation)

        # OpenCV path
        ret, frame = self._picamera.read()
        if not ret:
            return None
        return Image.fromarray(frame.astype("uint8"), "RGB").rotate(
            90 + self._camera_rotation
        )

    def stop_single_frame_mode(self):
        """Release any resources used for single-frame capture."""
        if self._picamera is not None:
            if self._picamera_backend == "picamera2":
                try:
                    self._picamera.stop()
                except Exception:
                    pass
                self._picamera.close()
            elif self._picamera_backend == "picamera":
                self._picamera.close()
            else:
                if hasattr(self._picamera, "close"):
                    self._picamera.close()
                else:
                    self._picamera.release()
            self._picamera = None
            self._picamera_backend = None

