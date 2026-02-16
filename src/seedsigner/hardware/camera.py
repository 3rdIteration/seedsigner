"""Cross-platform camera abstraction with interchangeable backends.

On Raspberry Pi systems this uses ``picamera`` when available (matching the
known-good dev-branch behavior). On desktop/other platforms it falls back to
OpenCV. All callers use the same `Camera` interface.
"""

import io

from PIL import Image

from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.models.singleton import Singleton


class Camera(Singleton):
    """Singleton wrapper around PiCamera/OpenCV camera access."""

    _video_stream = None
    _capture = None
    _camera_rotation = None
    _camera_index = 0

    @staticmethod
    def list_cameras() -> list[tuple[int, str]]:
        """Return available camera devices as ``(index, name)`` tuples."""
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
            try:
                import cv2  # type: ignore

                i = 0
                consecutive_failures = 0
                while consecutive_failures < 3:
                    cap = None
                    try:
                        cap = cv2.VideoCapture(i)
                        if cap is not None and cap.isOpened():
                            options.append((i, f"Camera {i}"))
                            consecutive_failures = 0
                        else:
                            consecutive_failures += 1
                    except Exception:
                        consecutive_failures += 1
                    finally:
                        if cap is not None:
                            cap.release()
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
            SettingsConstants.SETTING__CAMERA_DEVICE,
            default_if_none=True,
        )
        cls._instance._camera_index = int(idx) if idx is not None else 0
        return cls._instance

    def start_video_stream_mode(self, resolution=(512, 384), framerate=12, format="bgr"):
        """Begin streaming frames from the active backend."""
        from seedsigner.hardware.pivideostream import VideoStream

        if self._video_stream is not None:
            self.stop_video_stream_mode()

        self._video_stream = VideoStream(
            resolution=resolution,
            framerate=framerate,
            format=format,
            device_index=self._camera_index,
        )
        self._video_stream.start()

    def read_video_stream(self, as_image=False):
        """Read the most recent frame from stream mode."""
        if not self._video_stream:
            raise Exception("Must call start_video_stream_mode first.")
        frame = self._video_stream.read()
        if not as_image:
            return frame
        if frame is not None:
            return Image.fromarray(frame.astype("uint8"), "RGB").rotate(90 + self._camera_rotation)
        return None

    def stop_video_stream_mode(self):
        """Stop stream mode and release stream resources."""
        if self._video_stream is not None:
            self._video_stream.stop()
            self._video_stream = None

    def start_single_frame_mode(self, resolution=(720, 480)):
        """Prepare a backend for one-shot still capture."""
        if self._video_stream is not None:
            self.stop_video_stream_mode()
        if self._capture is not None:
            if hasattr(self._capture, "close"):
                self._capture.close()
            elif hasattr(self._capture, "release"):
                self._capture.release()
            self._capture = None

        try:
            from picamera import PiCamera  # type: ignore

            self._capture = PiCamera(resolution=resolution, framerate=24)
            self._capture.start_preview()
            return
        except Exception:
            pass

        try:
            import cv2  # type: ignore
        except Exception as e:
            raise ModuleNotFoundError(
                "OpenCV is required for desktop camera support; install requirements-desktop.txt"
            ) from e

        self._capture = cv2.VideoCapture(self._camera_index)
        self._capture.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
        self._capture.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])

    def capture_frame(self):
        """Capture a single frame as a PIL image from the active backend."""
        if self._capture is None:
            raise Exception("Must call start_single_frame_mode first.")

        if hasattr(self._capture, "capture"):
            self._capture.shutter_speed = self._capture.exposure_speed
            self._capture.exposure_mode = "off"
            gains = self._capture.awb_gains
            self._capture.awb_mode = "off"
            self._capture.awb_gains = gains

            stream = io.BytesIO()
            self._capture.capture(stream, format="jpeg")
            stream.seek(0)
            return Image.open(stream).rotate(90 + self._camera_rotation)

        import cv2  # type: ignore

        ret, frame = self._capture.read()
        if not ret:
            return None
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        return Image.fromarray(frame.astype("uint8"), "RGB").rotate(90 + self._camera_rotation)

    def stop_single_frame_mode(self):
        """Release single-frame backend resources."""
        if self._capture is not None:
            if hasattr(self._capture, "close"):
                self._capture.close()
            elif hasattr(self._capture, "release"):
                self._capture.release()
            self._capture = None
