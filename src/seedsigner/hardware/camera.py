"""Cross-platform camera abstraction with interchangeable backends.

On Raspberry Pi systems this uses ``picamera`` when available (matching the
known-good dev-branch behavior). On desktop/other platforms it falls back to
OpenCV. All callers use the same `Camera` interface.
"""

import io

from PIL import Image

from seedsigner.hardware.io_config import get_hardware_pin_mapping, runtime_profile_to_hardware_profile
from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.models.singleton import Singleton


class Camera(Singleton):
    """Singleton wrapper around PiCamera/OpenCV camera access."""

    _video_stream = None
    _capture = None
    _camera_rotation = None
    _camera_index = 0
    _runtime_profile = "desktop"
    _hardware_camera_config = None

    @staticmethod
    def _is_luckfox_profile(runtime_profile: str) -> bool:
        return runtime_profile in {"luckfox_22", "luckfox_40", "luckfox_pi"}

    @classmethod
    def _get_hardware_camera_config(cls):
        runtime_profile = Settings.RUNTIME_PROFILE
        hardware_profile = runtime_profile_to_hardware_profile(runtime_profile)
        if not hardware_profile:
            return None
        try:
            mapping = get_hardware_pin_mapping(hardware_profile)
        except Exception:
            return None
        camera = mapping.get("camera")
        if not camera:
            return None
        config = dict(camera)
        resolution = config.get("resolution")
        if isinstance(resolution, list) and len(resolution) == 2:
            config["resolution"] = (int(resolution[0]), int(resolution[1]))
        return config

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
        cls._instance._runtime_profile = Settings.RUNTIME_PROFILE
        cls._instance._hardware_camera_config = cls._get_hardware_camera_config()
        return cls._instance

    def start_video_stream_mode(self, resolution=(512, 384), framerate=12, format="bgr"):
        """Begin streaming frames from the active backend."""
        from seedsigner.hardware.pivideostream import VideoStream

        if self._video_stream is not None:
            self.stop_video_stream_mode()

        prefer_v4l2 = self._is_luckfox_profile(self._runtime_profile)
        stream_resolution = resolution
        stream_framerate = framerate
        stream_camera_config = dict(self._hardware_camera_config or {})
        if prefer_v4l2:
            # On Luckfox, prefer the board-specific io_config camera mode to
            # avoid unstable/unsupported requests from generic caller defaults.
            if stream_camera_config.get("resolution"):
                stream_resolution = tuple(stream_camera_config["resolution"])
            if stream_camera_config.get("framerate"):
                stream_framerate = int(stream_camera_config["framerate"])
            stream_camera_config["resolution"] = tuple(stream_resolution)

        self._video_stream = VideoStream(
            resolution=stream_resolution,
            framerate=stream_framerate,
            format=format,
            device_index=self._camera_index,
            camera_config=stream_camera_config,
            prefer_v4l2=prefer_v4l2,
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
            if isinstance(frame, Image.Image):
                return frame.rotate(90 + self._camera_rotation)
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
            elif hasattr(self._capture, "stop"):
                self._capture.stop()
            self._capture = None

        if self._is_luckfox_profile(self._runtime_profile):
            from seedsigner.hardware.pivideostream import VideoStream

            luckfox_config = dict(self._hardware_camera_config or {})
            luckfox_config["resolution"] = tuple(resolution)
            self._capture = VideoStream(
                resolution=luckfox_config["resolution"],
                framerate=6,
                device_index=self._camera_index,
                camera_config=luckfox_config,
                prefer_v4l2=True,
            )
            self._capture.start()
            return

        try:
            from picamera2 import Picamera2  # type: ignore

            self._capture = Picamera2()
            config = self._capture.create_still_configuration(
                main={"size": resolution, "format": "RGB888"}
            )
            self._capture.configure(config)
            self._capture.start()
            return
        except Exception:
            pass

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

        if hasattr(self._capture, "read") and hasattr(self._capture, "stop"):
            frame = self._capture.read()
            if frame is None:
                return None
            if isinstance(frame, Image.Image):
                return frame.rotate(90 + self._camera_rotation)
            return Image.fromarray(frame.astype("uint8"), "RGB").rotate(90 + self._camera_rotation)

        if hasattr(self._capture, "capture_array"):
            frame = self._capture.capture_array()
            return Image.fromarray(frame.astype("uint8"), "RGB").rotate(90 + self._camera_rotation)

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
            elif hasattr(self._capture, "stop"):
                self._capture.stop()
            self._capture = None
