import io

from gettext import gettext as _
from PIL import Image
from seedsigner.hardware.pivideostream import PiVideoStream
from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.models.singleton import Singleton


class CameraConnectionError(Exception):
    pass


class Camera(Singleton):
    _video_stream = None
    _picamera = None
    _camera_rotation = None

    @classmethod
    def get_instance(cls):
        # This is the only way to access the one and only Controller
        if cls._instance is None:
            cls._instance = cls.__new__(cls)
        cls._instance._camera_rotation = int(Settings.get_instance().get_value(SettingsConstants.SETTING__CAMERA_ROTATION))
        return cls._instance

    def start_video_stream_mode(self, resolution=(512, 384), framerate=12, format="bgr"):
        # Note: luckfox-pico-stock uses v4l2-ctl via PiVideoStream, not PiCamera
        # The resolution, framerate, and format parameters are accepted for API compatibility
        # but are configured via Settings/hardware config on luckfox
        if self._video_stream is not None:
            self.stop_video_stream_mode()

        # Start the video stream with the given resolution and framerate
        self._video_stream = PiVideoStream()
        self._video_stream.start()

    def read_video_stream(self, as_image=False):
        if not self._video_stream:
            raise Exception("Must call start_video_stream first.")

        frame = self._video_stream.read()
        if frame is None:
            return None

        if as_image:
            # Check if frame is already an Image object
            if isinstance(frame, Image.Image):
                img = frame
            else:
                # Convert the raw frame to an image
                img = Image.frombytes('RGB', (self._video_stream.width, self._video_stream.height), frame)

            return img.rotate(90 + self._camera_rotation)

        return frame

    def stop_video_stream_mode(self):
        if self._video_stream is not None:
            self._video_stream.stop()
            self._video_stream = None

    def start_single_frame_mode(self, resolution=(720, 480)):
        # Note: This method is from upstream but may not work on luckfox-pico-stock
        # which doesn't use PiCamera. Keeping for API compatibility.
        try:
            from picamera import PiCamera, PiCameraError
        except ImportError:
            # If picamera is not available (e.g., on luckfox), raise CameraConnectionError
            raise CameraConnectionError("PiCamera not available on this platform")
        
        if self._video_stream is not None:
            self.stop_video_stream_mode()
        if self._picamera is not None:
            self._picamera.close()

        try:
            self._picamera = PiCamera(resolution=resolution, framerate=24)
            self._picamera.start_preview()
        except PiCameraError:
            # This error most often occurs because the camera connection is loose
            raise CameraConnectionError()

    def capture_frame(self):
        # This method works differently depending on whether we're using video stream or single frame mode
        if self._picamera is not None:
            # Single frame mode using PiCamera (upstream behavior)
            # Set auto-exposure values
            self._picamera.shutter_speed = self._picamera.exposure_speed
            self._picamera.exposure_mode = 'off'
            g = self._picamera.awb_gains
            self._picamera.awb_mode = 'off'
            self._picamera.awb_gains = g

            stream = io.BytesIO()
            self._picamera.capture(stream, format='jpeg')

            # "Rewind" the stream to the beginning so we can read its content
            stream.seek(0)
            return Image.open(stream).rotate(90 + self._camera_rotation)
        elif self._video_stream is not None:
            # Video stream mode (luckfox behavior)
            # Capture a single frame
            frame = self._video_stream.read()
            if frame is None:
                raise Exception("Failed to capture frame.")
            return frame
        else:
            raise Exception("Must call start_single_frame_mode or start_video_stream_mode first.")

    def stop_single_frame_mode(self):
        if self._picamera is not None:
            self._picamera.close()
            self._picamera = None
