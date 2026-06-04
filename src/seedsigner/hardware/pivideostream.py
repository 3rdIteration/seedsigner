"""Threaded video capture with PiCamera, Luckfox V4L2, and OpenCV backends."""

import logging
import os
import re
import select
import subprocess
import time
from threading import Thread

from PIL import Image

logger = logging.getLogger(__name__)

try:
    from picamera2 import Picamera2  # type: ignore

    PICAMERA2_AVAILABLE = True
except Exception:
    PICAMERA2_AVAILABLE = False
    Picamera2 = None

try:
    from picamera.array import PiRGBArray
    from picamera import PiCamera
    from picamera.exc import PiCameraMMALError

    PICAMERA_AVAILABLE = True
except Exception:
    PICAMERA_AVAILABLE = False
    PiRGBArray = None
    PiCamera = None
    PiCameraMMALError = None

try:
    import cv2  # type: ignore
except Exception:
    cv2 = None

V4L2_PREFERRED_FORMATS = ("NV12", "UYVY", "XR24", "GREY")
LUCKFOX_DEVICE_FALLBACKS = ("/dev/video12", "/dev/video11", "/dev/video13", "/dev/video14", "/dev/video15")
MIN_LUCKFOX_CAPTURE_AREA = 320 * 240
PICAMERA2_PREVIEW_RESOLUTION = (240, 240)

DIAG_BOOT_DEVICE_CANDIDATES = (
    "/dev/disk/by-label/SEEDSIGNROS",
    "/dev/disk/by-uuid/BA5E-BA11",
    "/dev/mmcblk0p1",
    "/dev/mmcblk1p1",
)
DIAG_LOG_FILENAME = "camera_diag.log"
DIAG_MAX_BYTES = 64 * 1024


def _probe_hardware_info() -> dict:
    info = {"picamera2_available": PICAMERA2_AVAILABLE,
            "picamera_available": PICAMERA_AVAILABLE,
            "cv2_available": cv2 is not None}
    try:
        with open("/proc/device-tree/model", "rb") as f:
            info["device_tree_model"] = f.read().decode(errors="replace").strip("\x00\n ")
    except Exception:
        info["device_tree_model"] = None
    try:
        cpu = {}
        with open("/proc/cpuinfo", "r") as f:
            for line in f:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                key = key.strip()
                if key in {"model name", "Hardware", "Revision", "Serial", "Model"}:
                    cpu[key] = value.strip()
        info["cpuinfo"] = cpu
    except Exception:
        info["cpuinfo"] = {}
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    info["mem_total"] = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass
    return info


def _emit_camera_diagnostic(payload: dict) -> None:
    """Best-effort append-to-FAT-boot-partition so the user can read the log on
    a host after pulling the SD. Silent no-op when not running on a Pi with a
    SeedSigner boot partition mountable as vfat."""
    import json
    if os.name == "nt":
        return
    boot_dev = next((d for d in DIAG_BOOT_DEVICE_CANDIDATES if os.path.exists(d)), None)
    if not boot_dev:
        return
    mountpoint = "/tmp/seedsigner_boot_diag"
    try:
        os.makedirs(mountpoint, exist_ok=True)
    except Exception:
        return
    try:
        result = subprocess.run(
            ["mount", "-t", "vfat", "-o", "rw,sync", boot_dev, mountpoint],
            capture_output=True, text=True, check=False, timeout=5,
        )
        if result.returncode != 0:
            logger.info("Camera diag: mount %s -> %s failed (%s)",
                        boot_dev, mountpoint, result.stderr.strip())
            return
        try:
            target = os.path.join(mountpoint, DIAG_LOG_FILENAME)
            try:
                if os.path.getsize(target) > DIAG_MAX_BYTES:
                    with open(target, "r") as f:
                        tail = f.readlines()[-50:]
                    with open(target, "w") as f:
                        f.writelines(tail)
            except FileNotFoundError:
                pass
            except Exception:
                logger.exception("Camera diag: failed to trim log")
            with open(target, "a") as f:
                f.write(json.dumps(payload, default=str, sort_keys=True) + "\n")
            subprocess.run(["sync"], check=False, timeout=5)
        finally:
            subprocess.run(["umount", mountpoint], check=False, timeout=5)
    except Exception:
        logger.exception("Camera diag: write failed")


class VideoStream:
    """Continuously capture frames in a background thread."""

    def __init__(
        self,
        resolution=(320, 240),
        framerate=32,
        format="bgr",
        device_index=0,
        camera_config=None,
        prefer_v4l2=False,
        **kwargs,
    ):
        self.should_stop = False
        self.is_stopped = True
        self.frame = None
        self.display_frame = None
        self.preview_frame = None
        self.device_index = int(device_index)
        self.resolution = resolution
        self.framerate = framerate
        self.use_picamera = False
        self.use_picamera2 = False
        self.use_v4l2 = False
        self.camera = None
        self.stream = None
        self.raw_capture = None
        self._v4l2_process = None
        self._v4l2_device = None
        self._v4l2_pixelformat = None
        self._v4l2_resolution = None
        self._v4l2_frame_size = None
        self._v4l2_use_set_parm = False
        self._v4l2_decode_as_grey = False
        self._camera_config = camera_config or {}
        self._prefer_v4l2 = bool(prefer_v4l2)
        self._picamera2_has_lores = False

        if PICAMERA2_AVAILABLE and not self._prefer_v4l2:
            self.camera = Picamera2()
            # FrameRate must go through create_video_configuration because it
            # influences sensor mode selection. Everything else (AeEnable,
            # ExposureTime, AnalogueGain, AfMode, …) is a runtime control and
            # libcamera ignores those if you only pass them to configure(); they
            # have to be applied via set_controls() after start().
            raw_controls = dict(self._camera_config.get("picamera2_controls") or {})
            config_framerate = raw_controls.pop("FrameRate", float(framerate))
            config_kwargs = {
                "main": {"size": resolution, "format": "RGB888"},
                "controls": {"FrameRate": float(config_framerate)},
            }
            if resolution[0] >= PICAMERA2_PREVIEW_RESOLUTION[0] and resolution[1] >= PICAMERA2_PREVIEW_RESOLUTION[1]:
                # Keep decode on the main stream, but expose a smaller luma-only
                # preview stream to reduce UI update cost on slow Pi models.
                config_kwargs["lores"] = {
                    "size": PICAMERA2_PREVIEW_RESOLUTION,
                    "format": "YUV420",
                }
                self._picamera2_has_lores = True
            try:
                config = self.camera.create_video_configuration(**config_kwargs)
            except Exception:
                if self._picamera2_has_lores:
                    logger.exception("Picamera2 lores stream unavailable; falling back to main stream only")
                    self._picamera2_has_lores = False
                    del config_kwargs["lores"]
                    config = self.camera.create_video_configuration(**config_kwargs)
                else:
                    raise
            self.camera.configure(config)
            self.camera.start()
            set_controls_error = None
            if raw_controls:
                # Best-effort: libcamera silently drops controls the sensor
                # doesn't support (e.g. AfMode on Module 1/2). We log but don't
                # fail — the camera is still usable with defaults.
                try:
                    self.camera.set_controls(raw_controls)
                except Exception as exc:
                    logger.exception("Failed to apply Picamera2 runtime controls: %s", raw_controls)
                    set_controls_error = repr(exc)
            metadata_after_start = None
            try:
                metadata_after_start = self.camera.capture_metadata()
            except Exception as exc:
                metadata_after_start = {"_error": repr(exc)}
            camera_controls_supported = None
            try:
                camera_controls_supported = self.camera.camera_controls
            except Exception:
                pass
            _emit_camera_diagnostic({
                "ts": time.time(),
                "stage": "picamera2_init",
                "hardware": _probe_hardware_info(),
                "configured_resolution": list(resolution),
                "configured_framerate": framerate,
                "config_framerate_used": float(config_framerate),
                "runtime_controls_requested": raw_controls,
                "runtime_controls_set_error": set_controls_error,
                "metadata_after_start": metadata_after_start,
                "camera_controls_supported": camera_controls_supported,
                "has_lores_stream": self._picamera2_has_lores,
            })
            self.use_picamera2 = True
            return

        if PICAMERA_AVAILABLE and not self._prefer_v4l2:
            try:
                self.camera = PiCamera(resolution=resolution, framerate=framerate, **kwargs)
            except PiCameraMMALError:
                logger.warning("PiCamera init failed; retrying once after brief delay")
                time.sleep(0.5)
                self.camera = PiCamera(resolution=resolution, framerate=framerate, **kwargs)
            # Legacy PiCamera (Pi Zero v1 / ARMv6) uses object attributes for
            # exposure/gain/awb tuning. Critical ordering: set shutter_speed
            # and iso first, wait long enough for the sensor's AE to converge
            # onto our request, THEN flip exposure_mode='off' to *lock* it.
            # If exposure_mode='off' is set before the warmup, the firmware
            # clamps to whatever it had — observed 10000µs even when 4000µs
            # was requested.
            legacy_controls = self._camera_config.get("picamera_legacy_controls") or {}
            lock_keys = {"exposure_mode", "awb_mode"}
            awb_gains_value = legacy_controls.get("awb_gains")
            warmup_attrs = {k: v for k, v in legacy_controls.items()
                            if k not in lock_keys and k != "awb_gains"}
            applied = {}
            errors = {}
            for attr, value in warmup_attrs.items():
                try:
                    setattr(self.camera, attr, value)
                    applied[attr] = value
                except Exception as exc:
                    errors[attr] = repr(exc)
                    logger.exception("Failed to set PiCamera attr %s=%r", attr, value)
            time.sleep(2.5)
            pre_lock_readback = self._snapshot_picamera_state()
            # Now lock: exposure_mode='off' freezes the converged exposure;
            # awb_mode='off' + our gains freezes WB at our reproducible target.
            if "exposure_mode" in legacy_controls:
                try:
                    self.camera.exposure_mode = legacy_controls["exposure_mode"]
                    applied["exposure_mode"] = legacy_controls["exposure_mode"]
                except Exception as exc:
                    errors["exposure_mode"] = repr(exc)
            if "awb_mode" in legacy_controls:
                try:
                    self.camera.awb_mode = legacy_controls["awb_mode"]
                    applied["awb_mode"] = legacy_controls["awb_mode"]
                except Exception as exc:
                    errors["awb_mode"] = repr(exc)
            if awb_gains_value is not None:
                try:
                    self.camera.awb_gains = tuple(awb_gains_value)
                    applied["awb_gains"] = awb_gains_value
                except Exception as exc:
                    errors["awb_gains"] = repr(exc)
            time.sleep(0.5)
            post_lock_readback = self._snapshot_picamera_state()
            _emit_camera_diagnostic({
                "ts": time.time(),
                "stage": "picamera_legacy_init",
                "hardware": _probe_hardware_info(),
                "configured_resolution": list(resolution),
                "configured_framerate": framerate,
                "legacy_controls_requested": legacy_controls,
                "legacy_controls_applied": applied,
                "legacy_controls_errors": errors,
                "pre_lock_readback": pre_lock_readback,
                "post_lock_readback": post_lock_readback,
            })
            self.raw_capture = PiRGBArray(self.camera, size=resolution)
            self.stream = self.camera.capture_continuous(
                self.raw_capture,
                format="rgb",
                use_video_port=True,
            )
            self.use_picamera = True
            return

        if self._prefer_v4l2 and os.name != "nt" and self._is_v4l2_available():
            self._configure_v4l2_capture()
            return

        if cv2 is None:
            raise ModuleNotFoundError(
                "OpenCV is required for desktop camera support; install requirements-desktop.txt"
            )

        self.camera = self._open_cv_capture()

    def _snapshot_picamera_state(self) -> dict:
        readback = {}
        for attr in (
            "resolution", "framerate", "shutter_speed", "exposure_speed",
            "exposure_mode", "iso", "analog_gain", "digital_gain",
            "awb_mode", "awb_gains", "video_denoise", "image_denoise",
            "sharpness", "contrast", "brightness", "saturation",
            "exposure_compensation", "drc_strength",
        ):
            try:
                readback[attr] = getattr(self.camera, attr, "<missing>")
            except Exception as exc:
                readback[attr] = f"<error: {exc!r}>"
        return readback

    def _is_v4l2_available(self) -> bool:
        try:
            result = subprocess.run(
                ["v4l2-ctl", "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _normalize_device_candidates(self):
        configured_device = self._camera_config.get("device")
        candidates = []
        if configured_device:
            candidates.append(str(configured_device))
        candidates.extend(LUCKFOX_DEVICE_FALLBACKS)
        deduped = []
        for candidate in candidates:
            if candidate not in deduped:
                deduped.append(candidate)
        return deduped

    def _list_v4l2_formats(self, device: str) -> set[str]:
        try:
            result = subprocess.run(
                ["v4l2-ctl", "-d", device, "--list-formats-ext"],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
        except Exception:
            return set()

        if result.returncode != 0:
            return set()

        formats = set(re.findall(r"'([A-Z0-9]{4})'", result.stdout))
        return formats

    def _format_preferences(self):
        configured_format = str(self._camera_config.get("pixelformat", "")).upper()
        prefs = []
        if configured_format:
            prefs.append(configured_format)
        for fmt in V4L2_PREFERRED_FORMATS:
            if fmt not in prefs:
                prefs.append(fmt)
        return prefs

    def _probe_v4l2_device(self, device: str, width: int, height: int, pixelformat: str) -> tuple[bool, bool]:
        base_cmd = [
            "v4l2-ctl",
            "-d",
            device,
            f"--set-fmt-video=width={width},height={height},pixelformat={pixelformat}",
            "--stream-mmap",
            "--stream-count=2",
            "--stream-to=/dev/null",
        ]
        cmds = [
            [*base_cmd[:4], f"--set-parm={self.framerate}", *base_cmd[4:]],
            base_cmd,
        ]
        for idx, cmd in enumerate(cmds):
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
                if result.returncode == 0:
                    # idx == 0 means --set-parm worked.
                    return True, idx == 0
            except Exception:
                continue
        return False, False

    def _get_negotiated_v4l2_format(
        self,
        device: str,
        width: int,
        height: int,
        pixelformat: str,
    ) -> tuple[int, int, str, int | None]:
        """Query negotiated capture format after requesting width/height/pixelformat."""
        cmd = [
            "v4l2-ctl",
            "-d",
            device,
            f"--set-fmt-video=width={width},height={height},pixelformat={pixelformat}",
            "--get-fmt-video",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=3)
        except Exception:
            return width, height, pixelformat, None

        if result.returncode != 0:
            return width, height, pixelformat, None

        out = result.stdout
        wh_match = re.search(r"Width/Height\s*:\s*(\d+)\s*/\s*(\d+)", out)
        fmt_match = re.search(r"Pixel Format\s*:\s*'([A-Z0-9]{4})'", out)
        size_match = re.search(r"Size Image\s*:\s*(\d+)", out)

        negotiated_w = int(wh_match.group(1)) if wh_match else width
        negotiated_h = int(wh_match.group(2)) if wh_match else height
        negotiated_fmt = fmt_match.group(1) if fmt_match else pixelformat
        negotiated_size = int(size_match.group(1)) if size_match else None
        return negotiated_w, negotiated_h, negotiated_fmt, negotiated_size

    def _configure_v4l2_capture(self):
        width, height = self._camera_config.get("resolution", self.resolution)
        width = int(width)
        height = int(height)
        framerate = int(self._camera_config.get("framerate", self.framerate))
        configured_format = str(self._camera_config.get("pixelformat", "")).upper()
        configured_device = str(self._camera_config.get("device", "")).strip()
        preferences = self._format_preferences()
        small_mode_candidate = None

        for device in self._normalize_device_candidates():
            if not os.path.exists(device):
                continue

            available_formats = self._list_v4l2_formats(device)
            if not available_formats:
                continue

            chosen_format = None
            for candidate in preferences:
                if candidate in available_formats:
                    chosen_format = candidate
                    break
            if chosen_format is None:
                continue

            probe_ok, use_set_parm = self._probe_v4l2_device(device, width, height, chosen_format)
            if probe_ok:
                negotiated_w, negotiated_h, negotiated_fmt, negotiated_size = self._get_negotiated_v4l2_format(
                    device=device,
                    width=width,
                    height=height,
                    pixelformat=chosen_format,
                )
                # Skip thumbnail/scaled ISP nodes that can appear "live" but are not
                # suitable for stable full-screen preview/decoding on Luckfox.
                if negotiated_w * negotiated_h < MIN_LUCKFOX_CAPTURE_AREA and device != configured_device:
                    logger.info(
                        "Deferring V4L2 node %s due to small negotiated mode %sx%s",
                        device,
                        negotiated_w,
                        negotiated_h,
                    )
                    if small_mode_candidate is None:
                        small_mode_candidate = (
                            device,
                            negotiated_w,
                            negotiated_h,
                            negotiated_fmt,
                            negotiated_size,
                            use_set_parm,
                        )
                    continue

                self.use_v4l2 = True
                self._v4l2_device = device
                self._v4l2_pixelformat = negotiated_fmt
                self._v4l2_resolution = (negotiated_w, negotiated_h)
                self._v4l2_frame_size = self._calculate_v4l2_frame_size(
                    negotiated_w,
                    negotiated_h,
                    negotiated_fmt,
                )
                self._v4l2_use_set_parm = use_set_parm
                self.framerate = framerate
                self.resolution = (negotiated_w, negotiated_h)
                self._v4l2_decode_as_grey = configured_format == "GREY" and negotiated_fmt in {"NV12", "UYVY"}
                logger.info(
                    "Using V4L2 node %s at %sx%s (%s)",
                    self._v4l2_device,
                    negotiated_w,
                    negotiated_h,
                    negotiated_fmt,
                )
                return

        # If only lower-resolution ISP nodes are available, use the first one rather
        # than failing hard. This keeps camera functionality available on firmware
        # variants where mainpath nodes are reserved by another service.
        if small_mode_candidate is not None:
            device, negotiated_w, negotiated_h, negotiated_fmt, negotiated_size, use_set_parm = small_mode_candidate
            logger.info(
                "Falling back to V4L2 node %s with negotiated mode %sx%s (%s)",
                device,
                negotiated_w,
                negotiated_h,
                negotiated_fmt,
            )
            self.use_v4l2 = True
            self._v4l2_device = device
            self._v4l2_pixelformat = negotiated_fmt
            self._v4l2_resolution = (negotiated_w, negotiated_h)
            if negotiated_size is not None and negotiated_size > 0:
                self._v4l2_frame_size = negotiated_size
            else:
                self._v4l2_frame_size = self._calculate_v4l2_frame_size(
                    negotiated_w,
                    negotiated_h,
                    negotiated_fmt,
                )
            self._v4l2_use_set_parm = use_set_parm
            self.framerate = framerate
            self.resolution = (negotiated_w, negotiated_h)
            self._v4l2_decode_as_grey = configured_format == "GREY" and negotiated_fmt in {"NV12", "UYVY"}
            logger.info(
                "Using V4L2 node %s at %sx%s (%s)",
                self._v4l2_device,
                negotiated_w,
                negotiated_h,
                negotiated_fmt,
            )
            return

        raise Exception("Unable to open Luckfox camera device")

    @staticmethod
    def _calculate_v4l2_frame_size(width: int, height: int, pixelformat: str) -> int:
        if pixelformat == "XR24":
            return width * height * 4
        if pixelformat == "NV12":
            return (width * height * 3) // 2
        if pixelformat == "UYVY":
            return width * height * 2
        if pixelformat == "GREY":
            return width * height
        raise ValueError(f"Unsupported V4L2 pixel format: {pixelformat}")

    def _configure_capture(self, capture) -> None:
        capture.set(cv2.CAP_PROP_FRAME_WIDTH, self.resolution[0])
        capture.set(cv2.CAP_PROP_FRAME_HEIGHT, self.resolution[1])
        capture.set(cv2.CAP_PROP_FPS, self.framerate)

    def _open_cv_capture(self):
        configured_device = str(self._camera_config.get("device", "")).strip()
        if configured_device and os.name != "nt":
            capture = None
            try:
                # Prefer explicit io_config device paths on Linux SBCs where
                # /dev/video0 may be a decoder node instead of the USB camera.
                capture = cv2.VideoCapture(configured_device, cv2.CAP_V4L2)
                if capture is not None and capture.isOpened():
                    logger.info("Using configured camera device %s", configured_device)
                    self._configure_capture(capture)
                    return capture
            except Exception:
                if capture is not None:
                    capture.release()
            if capture is not None:
                capture.release()

        candidates = [self.device_index]
        for idx in (0, 1, 2, 3):
            if idx not in candidates:
                candidates.append(idx)

        for idx in candidates:
            capture = None
            try:
                if os.name == "nt":
                    capture = cv2.VideoCapture(idx, cv2.CAP_DSHOW)
                    if not capture.isOpened():
                        capture.release()
                        capture = cv2.VideoCapture(idx, cv2.CAP_MSMF)
                else:
                    capture = cv2.VideoCapture(idx)

                if capture is not None and capture.isOpened():
                    self.device_index = idx
                    self._configure_capture(capture)
                    return capture
            except Exception:
                if capture is not None:
                    capture.release()
                continue

            if capture is not None:
                capture.release()
        return None

    def _open_v4l2_stream(self):
        width, height = self._v4l2_resolution
        self._apply_v4l2_controls()
        cmd = [
            "v4l2-ctl",
            "-d",
            self._v4l2_device,
            f"--set-fmt-video=width={width},height={height},pixelformat={self._v4l2_pixelformat}",
            "--stream-mmap",
            "--stream-to=-",
        ]
        if self._v4l2_use_set_parm:
            cmd.insert(4, f"--set-parm={self.framerate}")
        self._v4l2_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=max(self._v4l2_frame_size * 2, 65536),
        )

    def _apply_v4l2_controls(self):
        """Apply optional V4L2 controls from camera config (best-effort)."""
        controls = self._camera_config.get("v4l2_controls")
        if not controls:
            return
        if isinstance(controls, str):
            controls = [controls]
        if not isinstance(controls, (list, tuple)):
            return

        for ctrl in controls:
            if not isinstance(ctrl, str) or "=" not in ctrl:
                continue
            cmd = ["v4l2-ctl", "-d", self._v4l2_device, f"--set-ctrl={ctrl}"]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=2)
                if result.returncode != 0:
                    logger.info("Ignoring unsupported V4L2 control on %s: %s", self._v4l2_device, ctrl)
            except Exception:
                logger.info("Unable to apply V4L2 control on %s: %s", self._v4l2_device, ctrl)

    def _read_exact(self, size: int, timeout_s: float) -> bytes | None:
        if self._v4l2_process is None or self._v4l2_process.stdout is None:
            return None

        fd = self._v4l2_process.stdout.fileno()
        deadline = time.monotonic() + timeout_s
        output = bytearray()
        while len(output) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                return None
            chunk = os.read(fd, size - len(output))
            if not chunk:
                return None
            output.extend(chunk)
        return bytes(output)

    @staticmethod
    def _clamp_color(value: int) -> int:
        if value < 0:
            return 0
        if value > 255:
            return 255
        return value

    def _nv12_to_image(self, frame_data: bytes, width: int, height: int) -> Image.Image:
        y_size = width * height
        y_plane = frame_data[:y_size]
        uv_plane = frame_data[y_size:]
        rgb_data = bytearray(width * height * 3)
        out = 0
        for row in range(height):
            y_row = row * width
            uv_row = (row // 2) * width
            for col in range(0, width, 2):
                y0 = y_plane[y_row + col]
                y1 = y_plane[y_row + col + 1]
                u = uv_plane[uv_row + col] - 128
                v = uv_plane[uv_row + col + 1] - 128

                c0 = y0 - 16
                c1 = y1 - 16
                if c0 < 0:
                    c0 = 0
                if c1 < 0:
                    c1 = 0

                r0 = self._clamp_color((298 * c0 + 409 * v + 128) >> 8)
                g0 = self._clamp_color((298 * c0 - 100 * u - 208 * v + 128) >> 8)
                b0 = self._clamp_color((298 * c0 + 516 * u + 128) >> 8)
                r1 = self._clamp_color((298 * c1 + 409 * v + 128) >> 8)
                g1 = self._clamp_color((298 * c1 - 100 * u - 208 * v + 128) >> 8)
                b1 = self._clamp_color((298 * c1 + 516 * u + 128) >> 8)

                rgb_data[out : out + 6] = bytes((r0, g0, b0, r1, g1, b1))
                out += 6
        return Image.frombytes("RGB", (width, height), bytes(rgb_data))

    def _uyvy_to_image(self, frame_data: bytes, width: int, height: int) -> Image.Image:
        rgb_data = bytearray(width * height * 3)
        out = 0
        for idx in range(0, len(frame_data), 4):
            u = frame_data[idx] - 128
            y0 = frame_data[idx + 1]
            v = frame_data[idx + 2] - 128
            y1 = frame_data[idx + 3]

            c0 = y0 - 16
            c1 = y1 - 16
            if c0 < 0:
                c0 = 0
            if c1 < 0:
                c1 = 0

            r0 = self._clamp_color((298 * c0 + 409 * v + 128) >> 8)
            g0 = self._clamp_color((298 * c0 - 100 * u - 208 * v + 128) >> 8)
            b0 = self._clamp_color((298 * c0 + 516 * u + 128) >> 8)
            r1 = self._clamp_color((298 * c1 + 409 * v + 128) >> 8)
            g1 = self._clamp_color((298 * c1 - 100 * u - 208 * v + 128) >> 8)
            b1 = self._clamp_color((298 * c1 + 516 * u + 128) >> 8)
            rgb_data[out : out + 6] = bytes((r0, g0, b0, r1, g1, b1))
            out += 6
        return Image.frombytes("RGB", (width, height), bytes(rgb_data))

    def _decode_v4l2_frame(self, frame_data: bytes):
        width, height = self._v4l2_resolution
        fmt = self._v4l2_pixelformat
        if fmt == "XR24":
            return Image.frombytes("RGB", (width, height), frame_data, "raw", "BGRX")
        if fmt == "GREY":
            return Image.frombytes("L", (width, height), frame_data).convert("RGB")
        if fmt == "NV12":
            if self._v4l2_decode_as_grey:
                y_plane = frame_data[: width * height]
                return Image.frombytes("L", (width, height), y_plane).convert("RGB")
            return self._nv12_to_image(frame_data, width, height)
        if fmt == "UYVY":
            if self._v4l2_decode_as_grey:
                y_plane = bytearray(width * height)
                out = 0
                for idx in range(0, len(frame_data), 4):
                    y_plane[out] = frame_data[idx + 1]
                    y_plane[out + 1] = frame_data[idx + 3]
                    out += 2
                return Image.frombytes("L", (width, height), bytes(y_plane)).convert("RGB")
            return self._uyvy_to_image(frame_data, width, height)
        raise ValueError(f"Unsupported V4L2 pixel format: {fmt}")

    def _read_v4l2_frame(self, timeout_s: float = 1.0):
        if self._v4l2_process is None:
            return None
        if self._v4l2_process.poll() is not None:
            return None
        frame_data = self._read_exact(self._v4l2_frame_size, timeout_s)
        if frame_data is None:
            return None
        try:
            return self._decode_v4l2_frame(frame_data)
        except Exception as exc:
            logger.warning("Unable to decode V4L2 frame (%s): %s", self._v4l2_pixelformat, exc)
            return None

    def _terminate_v4l2_process(self):
        if self._v4l2_process is None:
            return
        try:
            self._v4l2_process.terminate()
            self._v4l2_process.wait(timeout=1)
        except Exception:
            try:
                self._v4l2_process.kill()
            except Exception:
                pass
        self._v4l2_process = None

    def start(self):
        if self.use_v4l2:
            self._open_v4l2_stream()
            for _ in range(20):
                frame = self._read_v4l2_frame(timeout_s=0.5)
                if frame is not None:
                    self.frame = frame
                    break
            if self.frame is None:
                self._terminate_v4l2_process()
                raise Exception("Unable to read frames from Luckfox camera device")
        elif not self.use_picamera and not self.use_picamera2:
            if self.camera is None or not self.camera.isOpened():
                raise Exception("Unable to open camera device")
            # Fail fast if the backend opened but cannot produce frames.
            for _ in range(20):
                ret, frame = self.camera.read()
                if ret:
                    self.frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    break
                time.sleep(0.05)
            if self.frame is None:
                self.camera.release()
                self.camera = None
                raise Exception("Unable to read frames from camera device")

        t = Thread(target=self.update, args=())
        t.daemon = True
        t.start()
        self.is_stopped = False
        return self

    def update(self):
        if self.use_picamera2:
            # capture_array() blocks until the camera hardware delivers a new
            # frame, so this loop is naturally throttled to the camera's
            # framerate and does not busy-spin the CPU.
            while not self.should_stop:
                if self._picamera2_has_lores:
                    try:
                        captured = self.camera.capture_arrays(["main", "lores"])
                        arrays = captured
                        if (
                            isinstance(captured, tuple)
                            and len(captured) == 2
                            and isinstance(captured[0], (list, tuple))
                        ):
                            arrays = captured[0]
                        if isinstance(arrays, (list, tuple)) and len(arrays) >= 2:
                            self.display_frame = arrays[0]
                            self.frame = self._picamera2_main_to_greyscale(self.display_frame)
                            self.preview_frame = self._picamera2_lores_to_image(arrays[1])
                            continue
                    except Exception:
                        self._picamera2_has_lores = False
                        logger.exception("Picamera2 lores capture failed; falling back to main stream only")
                self.display_frame = self.camera.capture_array()
                self.frame = self._picamera2_main_to_greyscale(self.display_frame)
                self.preview_frame = None
            self.camera.stop()
            self.camera.close()
            self.should_stop = False
            self.is_stopped = True
            return

        if self.use_picamera:
            for f in self.stream:
                self.frame = f.array
                self.raw_capture.truncate(0)
                if self.should_stop:
                    self.stream.close()
                    self.raw_capture.close()
                    self.camera.close()
                    self.should_stop = False
                    self.is_stopped = True
                    return
            return

        if self.use_v4l2:
            while not self.should_stop:
                frame = self._read_v4l2_frame(timeout_s=0.5)
                if frame is not None:
                    self.frame = frame
                else:
                    time.sleep(0.01)
            self._terminate_v4l2_process()
            self.is_stopped = True
            return

        while not self.should_stop:
            ret, frame = self.camera.read()
            if ret:
                self.frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            else:
                time.sleep(0.01)

        self.camera.release()
        self.is_stopped = True

    def _picamera2_lores_to_image(self, frame_data):
        width, height = PICAMERA2_PREVIEW_RESOLUTION
        try:
            luminance = frame_data[:height, :width]
        except Exception:
            expected = width * height
            try:
                luminance = frame_data.reshape(-1)[:expected].reshape((height, width))
            except Exception:
                logger.exception("Unable to decode Picamera2 lores frame")
                return None
        return Image.fromarray(luminance.astype("uint8"), "L").convert("RGB")

    def _picamera2_main_to_greyscale(self, frame_data):
        try:
            if len(frame_data.shape) >= 3:
                # Use a single channel to avoid extra per-frame math on slow Pi models.
                return frame_data[:, :, 1]
        except Exception:
            logger.exception("Unable to convert Picamera2 main frame to greyscale")
        return frame_data

    def read(self, preview=False, display=False):
        if preview and self.preview_frame is not None:
            return self.preview_frame
        if display and self.display_frame is not None:
            return self.display_frame
        return self.frame

    def stop(self):
        self.should_stop = True
        while not self.is_stopped:
            time.sleep(0.01)


# Backward compatibility for existing imports.
PiVideoStream = VideoStream
