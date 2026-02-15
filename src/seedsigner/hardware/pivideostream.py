"""Threaded video capture that works with both PiCamera and OpenCV webcams."""

import logging
import time
from threading import Thread

logger = logging.getLogger(__name__)

# Try PiCamera first
try:
    from picamera.array import PiRGBArray
    from picamera import PiCamera
    PICAMERA_AVAILABLE = True
except Exception:
    PICAMERA_AVAILABLE = False

# Try OpenCV for fallback
try:
    import cv2  # type: ignore
    CV2_AVAILABLE = True
except Exception:
    CV2_AVAILABLE = False

# Try Luckfox-specific v4l2 approach
try:
    import subprocess
    import threading
    import os
    import io
    from PIL import Image
    from seedsigner.models.settings import Settings
    from seedsigner.models.settings_definition import SettingsConstants
    V4L2_AVAILABLE = True
except Exception:
    V4L2_AVAILABLE = False


class PiVideoStream:
    """Continuously capture frames in a background thread."""

    def __init__(self, resolution=(320, 240), framerate=32, format="bgr", device_index=0, **kwargs):
        """Initialize the video stream.

        When running on a Pi with the ``picamera`` library available we use that;
        when running on Luckfox Pico we use v4l2-ctl;
        otherwise we fall back to OpenCV's ``VideoCapture`` on the given
        ``device_index``.
        """
        self.should_stop = False
        self.is_stopped = True
        self.frame = None
        self.device_index = device_index

        # Try to detect Luckfox environment
        is_luckfox = V4L2_AVAILABLE
        try:
            if is_luckfox:
                hardware_config = Settings.get_instance().get_value(SettingsConstants.SETTING__HARDWARE_CONFIG)
                if hardware_config and "camera" in SettingsConstants.ALL_HARDWARE_PIN_CONFIGS__PIN_DEFINITIONS.get(hardware_config, {}):
                    self._init_luckfox(hardware_config)
                    return
        except Exception:
            is_luckfox = False

        # Fall back to PiCamera or OpenCV
        if PICAMERA_AVAILABLE:
            self.camera = PiCamera(resolution=resolution, framerate=framerate, **kwargs)
            self.rawCapture = PiRGBArray(self.camera, size=resolution)
            self.stream = self.camera.capture_continuous(
                self.rawCapture, format=format, use_video_port=True
            )
            self.use_picamera = True
            self.use_v4l2 = False
        elif CV2_AVAILABLE:
            self.camera = cv2.VideoCapture(self.device_index)
            self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
            self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])
            self.use_picamera = False
            self.use_v4l2 = False
        else:
            raise ModuleNotFoundError(
                "OpenCV is required for desktop camera support; install requirements-desktop.txt"
            )

    def _init_luckfox(self, hardware_config):
        """Initialize Luckfox-specific v4l2 capture."""
        pin_mapping = SettingsConstants.ALL_HARDWARE_PIN_CONFIGS__PIN_DEFINITIONS[hardware_config]["camera"]

        self.device = pin_mapping["device"]
        self.width, self.height = pin_mapping["resolution"]
        self.pixelformat = pin_mapping["pixelformat"]

        if self.pixelformat == "NV12":
            self.frame_size = self.width * self.height * 3 // 2
        elif self.pixelformat == "YUYV":
            self.frame_size = self.width * self.height * 2
        elif self.pixelformat == "GREY":
            self.frame_size = self.width * self.height
        elif self.pixelformat == "MJPG":
            self.frame_size = self.width * self.height
        else:
            raise Exception("Invalid pixelformat")

        self.lock = threading.Lock()
        self.use_picamera = False
        self.use_v4l2 = True

        logger.debug(f"Initialized PiVideoStream with device={self.device}, resolution={self.width}x{self.height}, "
              f"pixelformat={self.pixelformat}")

    def start(self):
        """Start the capture thread."""
        t = Thread(target=self.update, args=())
        t.daemon = True
        t.start()
        self.is_stopped = False
        return self

    def update(self):
        """Continuously read frames until :meth:`stop` is called."""
        if self.use_v4l2:
            self._update_v4l2()
        elif self.use_picamera:
            for f in self.stream:
                self.frame = f.array
                self.rawCapture.truncate(0)
                if self.should_stop:
                    logger.info("PiVideoStream: closing everything")
                    self.stream.close()
                    self.rawCapture.close()
                    self.camera.close()
                    self.should_stop = False
                    self.is_stopped = True
                    return
        else:
            while not self.should_stop:
                ret, frame = self.camera.read()
                if ret:
                    self.frame = frame
            self.camera.release()
            self.is_stopped = True

    def _update_v4l2(self):
        """Update loop for v4l2-based capture (Luckfox)."""
        cmd = [
            'v4l2-ctl',
            f'--device={self.device}',
            f'--set-fmt-video=width={self.width},height={self.height},pixelformat={self.pixelformat}',
            '--stream-mmap',
            '--stream-to=-',
            '--stream-count=0'
        ]

        logger.info(f"Running command: {' '.join(cmd)}")

        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=10 * self.frame_size
        )

        while not self.should_stop:
            try:
                start_time = time.time()

                frame_data = process.stdout.read(self.frame_size)
                read_time = time.time() - start_time

                if len(frame_data) < self.frame_size:
                    logger.error(f"Incomplete frame data received: {len(frame_data)} bytes")
                    break

                logger.debug(f"Frame read time: {read_time:.6f} seconds")
                start_processing = time.time()

                with self.lock:
                    start_conversion = time.time()
                    if self.pixelformat == "NV12":
                        self.frame = self.nv12_to_rgb_subprocess(frame_data, self.width, self.height)
                    elif self.pixelformat == "GREY":
                        self.frame = self.grey_to_pil(frame_data, self.width, self.height)
                    elif self.pixelformat == "YUYV":
                        self.frame = self.yuyv_to_rgb_opencv(frame_data, self.width, self.height)
                    elif self.pixelformat == "MJPG":
                        self.frame = self.mjpg_to_pil(frame_data, self.width, self.height)
                    else:
                        self.frame = None
                        raise Exception("Unable to read from camera")

                    conversion_time = time.time() - start_conversion
                    logger.debug(f"{self.pixelformat} to PIL Image conversion time: {conversion_time:.6f} seconds")

                processing_time = time.time() - start_processing
                logger.debug(f"Frame processing time (read+conversion): {processing_time:.6f} seconds")

            except Exception as e:
                logger.error(f"Error while reading frame: {e}")
                break

        process.terminate()
        process.wait()
        self.is_stopped = True
        logger.debug("Video stream stopped.")

    def read(self):
        """Return the most recently captured frame."""
        if self.use_v4l2:
            with self.lock:
                return self.frame
        return self.frame

    def stop(self):
        """Signal the capture thread to stop and wait for it to finish."""
        self.should_stop = True
        while not self.is_stopped:
            time.sleep(0.01)

    # Pixel format conversion methods for Luckfox
    def mjpg_to_pil(self, frame_data, width, height):
        """Converts MJPG format to a PIL RGB Image"""
        soi1 = frame_data.find(b'\xff\xd8', 1)
        soi2 = frame_data.find(b'\xff\xd8', soi1+10)
        logger.info(f"FRAME end index: {soi1}-{soi2}")
        pil_image = Image.open(io.BytesIO(frame_data[soi1:soi2]))
        return pil_image

    def yuyv_to_rgb_opencv(self, frame_data, width, height):
        """Converts YUYV format to a PIL RGB Image using OpenCV"""
        import cv2
        import numpy as np
        yuyv = np.frombuffer(frame_data, dtype=np.uint8)
        yuyv = yuyv.reshape((height, width, 2))
        rgb_frame = cv2.cvtColor(yuyv, cv2.COLOR_YUV2RGB_YUYV)
        pil_image = Image.fromarray(rgb_frame)
        return pil_image

    def nv12_to_rgb_opencv(self, frame_data, width, height):
        """Converts NV12 format to a PIL RGB Image using OpenCV"""
        import cv2
        import numpy as np
        nv12_array = np.frombuffer(frame_data, dtype=np.uint8)
        nv12_frame = nv12_array.reshape((height * 3 // 2, width))
        rgb_frame = cv2.cvtColor(nv12_frame, cv2.COLOR_YUV2RGB_NV12)
        pil_image = Image.fromarray(rgb_frame)
        return pil_image

    def nv12_to_rgb_subprocess(self, frame_data, width, height):
        """Converts NV12 format to a PIL RGB Image using a C subprocess"""
        WIDTH = width
        HEIGHT = height

        rgb_file = "/tmp/rgb_frame.bin"
        nv12_file = "/tmp/nv12_frame.bin"

        with open(nv12_file, "wb") as f:
            f.write(frame_data)

        cmd = [
            "/nv12_converter",
            nv12_file,
            rgb_file,
            str(WIDTH),
            str(HEIGHT),
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with open(rgb_file, "rb") as f:
            rgb_data = f.read()

        img = Image.frombytes("RGB", (WIDTH, HEIGHT), rgb_data)

        if WIDTH != 240 or HEIGHT != 240:
            img = img.resize((240, 240))

        os.remove(nv12_file)
        os.remove(rgb_file)

        return img

    def grey_to_pil(self, frame_data, width, height):
        """Converts grayscale bytes to a PIL Image"""
        img = Image.frombytes("L", (width, height), frame_data)

        if width != 240 or height != 240:
            img = img.resize((240, 240))

        return img

    def crop_to_square(self, image):
        width, height = image.size
        size = min(width, height)
        left = (width - size) // 2
        top = (height - size) // 2
        right = left + size
        bottom = top + size
        return image.crop((left, top, right, bottom))

    def yuyv_to_rgb(self, yuyv_data, width, height):
        """Convert YUYV data to RGB using only PIL"""
        rgb_data = bytearray(width * height * 3)

        for i in range(0, len(yuyv_data), 4):
            if i + 3 >= len(yuyv_data):
                break

            y0 = yuyv_data[i]
            u = yuyv_data[i + 1]
            y1 = yuyv_data[i + 2]
            v = yuyv_data[i + 3]

            u_signed = u - 128
            v_signed = v - 128

            for j, y in enumerate([y0, y1]):
                r = y + 1.402 * v_signed
                g = y - 0.344136 * u_signed - 0.714136 * v_signed
                b = y + 1.772 * u_signed

                r = max(0, min(255, int(r)))
                g = max(0, min(255, int(g)))
                b = max(0, min(255, int(b)))

                pixel_idx = (i // 4) * 2 + j
                row = pixel_idx // width
                col = pixel_idx % width

                if row < height and col < width:
                    rgb_idx = (row * width + col) * 3
                    rgb_data[rgb_idx] = r
                    rgb_data[rgb_idx + 1] = g
                    rgb_data[rgb_idx + 2] = b

        return bytes(rgb_data)

    def yuyv_to_pil(self, yuyv_data, width, height):
        """Convert YUYV data to PIL Image"""
        rgb_data = self.yuyv_to_rgb(yuyv_data, width, height)
        return Image.frombytes('RGB', (width, height), rgb_data)
