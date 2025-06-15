# import the necessary packages
import logging
import subprocess
import threading
import time
import os
import io
from PIL import Image

if os.environ.get("USE_OPENCV", "0") == "1":
    import cv2
    import numpy as np

from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants

logger = logging.getLogger(__name__)

class PiVideoStream:
    def __init__(self):


        hardware_config = Settings.get_instance().get_value(SettingsConstants.SETTING__HARDWARE_CONFIG)
        pin_mapping = SettingsConstants.ALL_HARDWARE_PIN_CONFIGS__PIN_DEFINITIONS[hardware_config]["camera"]

        self.device = pin_mapping["device"]
        self.width, self.height = pin_mapping["resolution"]
        self.pixelformat = pin_mapping["pixelformat"]

        if self.pixelformat == "NV12":
            self.frame_size = self.width * self.height * 3 // 2  # NV12 format size calculation
        elif self.pixelformat == "YUYV":
            self.frame_size = self.width * self.height * 2  # YUYV format size calculation
        elif self.pixelformat == "GREY":
            self.frame_size = self.width * self.height # GreyScale format size calculation
        elif self.pixelformat == "MJPG":
            self.frame_size = self.width * self.height  # MJPG format size calculation
        else:
            raise Exception("Invalid pixelformat")

        self.frame = None
        self.should_stop = False
        self.is_stopped = True
        self.lock = threading.Lock()  # Thread-safe frame handling

        logger.debug(f"Initialized PiVideoStream with device={self.device}, resolution={self.width}x{self.height}, "
              f"pixelformat={self.pixelformat}")

    def start(self):
        self.thread = threading.Thread(target=self.update, daemon=True)
        self.thread.start()
        self.is_stopped = False
        return self

    def update(self):
        cmd = [
            'v4l2-ctl',
            f'--device={self.device}',
            f'--set-fmt-video=width={self.width},height={self.height},pixelformat={self.pixelformat}',
            '--stream-mmap',
            '--stream-to=-',
            '--stream-count=0'  # Infinite stream
        ]

        logger.info(f"Running command: {' '.join(cmd)}")

        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=10 * self.frame_size
        )



        while not self.should_stop:
            try:
                start_time = time.time()

                # Read frame data
                frame_data = process.stdout.read(self.frame_size)
                read_time = time.time() - start_time

                if len(frame_data) < self.frame_size:
                    logger.error(f"Incomplete frame data received: {len(frame_data)} bytes")
                    break

                logger.debug(f"Frame read time: {read_time:.6f} seconds")
                start_processing = time.time()

                with self.lock:
                    # Record time for conversion
                    start_conversion = time.time()
                    if self.pixelformat == "NV12":
                        # Python Implementation
                        # self.frame = self.nv12_to_rgb(frame_data)
                        # C Implementation
                        self.frame = self.nv12_to_rgb_subprocess(frame_data, self.width, self.height)
                        # OpenCV Implementation
                        # self.frame = self.nv12_to_rgb_opencv(frame_data, self.width, self.height)
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
        with self.lock:
            # return the frame most recently read
            return self.frame

    def stop(self):
        self.should_stop = True
        while not self.is_stopped:
            time.sleep(0.01)

    # TODO: move all of these pixel format conversions to a separate file/class
    def mjpg_to_pil(self, frame_data, width, height):
        """
        Converts MJPG format to a PIL RGB Image
        """
        # Find the start of a 2nd image to find the end of the first image
        soi1 = frame_data.find(b'\xff\xd8',1)
        soi2 = frame_data.find(b'\xff\xd8',soi1+10)        
        logger.info(f"FRAME end index: {soi1}-{soi2}")
        pil_image = Image.open(io.BytesIO(frame_data[soi1:soi2]))

        # pil_image = Image.open(io.BytesIO(frame_data[0:soi]))

        return pil_image

    def yuyv_to_rgb_opencv(self, frame_data, width, height):
        """
        Converts YUYV format to a PIL RGB Image using OpenCV
        """
        # DO THESE IMPORTS HERE SO WE ONLY IMPORT WHEN WE NEED IT
        # SOME HARDWARE WONT SUPPORT THESE LIBRARIES
        # THIS WILL ACTUALLY BE SUPER SLOW TO HAVE THE IMPORTS HERE BUT LEAVE IT LIKE THIS FOR NOW
        import cv2
        import numpy as np
        # Convert bytes to numpy array
        yuyv = np.frombuffer(frame_data, dtype=np.uint8)
        # Reshape to (height, width, 2) for YUYV
        yuyv = yuyv.reshape((height, width, 2))
        # Convert to RGB using OpenCV
        rgb_frame = cv2.cvtColor(yuyv, cv2.COLOR_YUV2RGB_YUYV)
        # Convert to PIL Image
        pil_image = Image.fromarray(rgb_frame)
        return pil_image

    def nv12_to_rgb_opencv(self, frame_data, width, height):
        """
        Converts NV12 format to a PIL RGB Image using a C subprocess.

        Args:
            frame_data (bytes): NV12 frame data.

        Returns:
            Image: PIL Image in RGB format.
        """

        # Convert NV12 to RGB using OpenCV
        nv12_array = np.frombuffer(frame_data, dtype=np.uint8)
        nv12_frame = nv12_array.reshape((height * 3 // 2, width))
        
        # Convert to RGB
        rgb_frame = cv2.cvtColor(nv12_frame, cv2.COLOR_YUV2RGB_NV12)
        
        # Convert to PIL Image
        pil_image = Image.fromarray(rgb_frame)
        return pil_image



    def nv12_to_rgb_subprocess(self, frame_data, width, height):
        """
        Converts NV12 format to a PIL RGB Image using a C subprocess.

        Args:
            frame_data (bytes): NV12 frame data.

        Returns:
            Image: PIL Image in RGB format.
        """
        WIDTH = width
        HEIGHT = height

        # Declare Temporary Files
        rgb_file = "/tmp/rgb_frame.bin"
        nv12_file = "/tmp/nv12_frame.bin"

        # Save NV12 frame data to a temporary file
        with open(nv12_file, "wb") as f:
            f.write(frame_data)

        # Run the C converter subprocess
        cmd = [
            "/nv12_converter",
            nv12_file,
            rgb_file,
            str(WIDTH),
            str(HEIGHT),
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Load the RGB data from the output file
        with open(rgb_file, "rb") as f:
            rgb_data = f.read()

        # Create a PIL image from the RGB data
        img = Image.frombytes("RGB", (WIDTH, HEIGHT), rgb_data)

        # Resize if necessary (e.g., for a display resolution of 240x240)
        # Should I instead crop, then resize to minimize the distortion?
        if WIDTH != 240 or HEIGHT != 240:
            # img = self.crop_to_square(img)
            img = img.resize((240, 240))

        # Clean up temporary files
        os.remove(nv12_file)
        os.remove(rgb_file)

        return img

    def grey_to_pil(self, frame_data, width, height):
        """
        Converts grayscale bytes to a PIL Image.

        Args:
            frame_data (bytes): Grayscale frame data.
            width (int): Width of the frame.
            height (int): Height of the frame.

        Returns:
            Image: PIL Image in Grayscale format.
        """
        # Create a PIL image from the grayscale data
        img = Image.frombytes("L", (width, height), frame_data)

        # Resize if necessary (e.g., for a display resolution of 240x240)
        if width != 240 or height != 240:
            # img = self.crop_to_square(img)
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
    

    def yuyv_to_rgb(yuyv_data, width, height):
        """Convert YUYV data to RGB using only PIL"""
        rgb_data = bytearray(width * height * 3)  # RGB output buffer
        
        for i in range(0, len(yuyv_data), 4):  # Process 4 bytes at a time (2 pixels)
            if i + 3 >= len(yuyv_data):
                break
                
            # Extract YUYV components
            y0 = yuyv_data[i]     # Y for first pixel
            u = yuyv_data[i + 1]  # U (shared)
            y1 = yuyv_data[i + 2] # Y for second pixel  
            v = yuyv_data[i + 3]  # V (shared)
            
            # Convert to signed values
            u_signed = u - 128
            v_signed = v - 128
            
            # Convert both pixels to RGB
            for j, y in enumerate([y0, y1]):
                # YUV to RGB conversion
                r = y + 1.402 * v_signed
                g = y - 0.344136 * u_signed - 0.714136 * v_signed
                b = y + 1.772 * u_signed
                
                # Clamp to 0-255
                r = max(0, min(255, int(r)))
                g = max(0, min(255, int(g)))
                b = max(0, min(255, int(b)))
                
                # Calculate pixel position
                pixel_idx = (i // 4) * 2 + j  # Which pixel (0, 1, 2, 3...)
                row = pixel_idx // width
                col = pixel_idx % width
                
                if row < height and col < width:
                    rgb_idx = (row * width + col) * 3
                    rgb_data[rgb_idx] = r      # R
                    rgb_data[rgb_idx + 1] = g  # G
                    rgb_data[rgb_idx + 2] = b  # B
        
        return bytes(rgb_data)

    def yuyv_to_pil(yuyv_data, width, height):
        """Convert YUYV data to PIL Image"""
        rgb_data = yuyv_to_rgb(yuyv_data, width, height)
        return Image.frombytes('RGB', (width, height), rgb_data)