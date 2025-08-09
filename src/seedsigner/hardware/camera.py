import io
from PIL import Image
from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.models.singleton import Singleton



class Camera(Singleton):
    _video_stream = None
    _picamera = None
    _camera_rotation = None
    _camera_index = 0

    @staticmethod
    def list_cameras() -> list[tuple[int, str]]:
        """Return a list of available camera devices as (index, name)."""
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
        # This is the only way to access the one and only Controller
        if cls._instance is None:
            cls._instance = cls.__new__(cls)
        cls._instance._camera_rotation = int(Settings.get_instance().get_value(SettingsConstants.SETTING__CAMERA_ROTATION))
        idx = Settings.get_instance().get_value(SettingsConstants.SETTING__CAMERA_DEVICE, default_if_none=True)
        cls._instance._camera_index = int(idx) if idx is not None else 0
        return cls._instance


    def start_video_stream_mode(self, resolution=(512, 384), framerate=12, format="bgr"):
        from seedsigner.hardware.pivideostream import PiVideoStream
        if self._video_stream is not None:
            self.stop_video_stream_mode()

        self._video_stream = PiVideoStream(resolution=resolution, framerate=framerate, format=format, device_index=self._camera_index)
        self._video_stream.start()


    def read_video_stream(self, as_image=False):
        if not self._video_stream:
            raise Exception("Must call start_video_stream first.")
        frame = self._video_stream.read()
        if not as_image:
            return frame
        else:
            if frame is not None:
                return Image.fromarray(frame.astype('uint8'), 'RGB').convert('RGBA').rotate(90 + self._camera_rotation)
        return None


    def stop_video_stream_mode(self):
        if self._video_stream is not None:
            self._video_stream.stop()
            self._video_stream = None


    def start_single_frame_mode(self, resolution=(720, 480)):
        if self._video_stream is not None:
            self.stop_video_stream_mode()
        if self._picamera is not None:
            if hasattr(self._picamera, "close"):
                self._picamera.close()
            else:
                self._picamera.release()

        try:
            from picamera import PiCamera
            self._picamera = PiCamera(resolution=resolution, framerate=24)
            self._picamera.start_preview()
        except Exception:
            try:
                import cv2  # type: ignore
            except Exception as e:
                raise ModuleNotFoundError(
                    "OpenCV is required for desktop camera support; install requirements-desktop.txt"
                ) from e
            self._picamera = cv2.VideoCapture(self._camera_index)
            self._picamera.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
            self._picamera.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])


    def capture_frame(self):
        if self._picamera is None:
            raise Exception("Must call start_single_frame_mode first.")

        if hasattr(self._picamera, "capture"):
            # PiCamera path
            self._picamera.shutter_speed = self._picamera.exposure_speed
            self._picamera.exposure_mode = 'off'
            g = self._picamera.awb_gains
            self._picamera.awb_mode = 'off'
            self._picamera.awb_gains = g

            stream = io.BytesIO()
            self._picamera.capture(stream, format='jpeg')
            stream.seek(0)
            return Image.open(stream).rotate(90 + self._camera_rotation)
        else:
            # OpenCV path
            ret, frame = self._picamera.read()
            if not ret:
                return None
            return Image.fromarray(frame.astype('uint8'), 'RGB').rotate(90 + self._camera_rotation)


    def stop_single_frame_mode(self):
        if self._picamera is not None:
            if hasattr(self._picamera, "close"):
                self._picamera.close()
            else:
                self._picamera.release()
            self._picamera = None

