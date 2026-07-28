import logging
import os
import time
from pathlib import Path

from seedsigner.models.singleton import Singleton
from seedsigner.models.threads import BaseThread

logger = logging.getLogger(__name__)


# SeedSigner-OS removable/persistent data dirs, in priority order. "/mnt/microsd" is the
# Raspberry-Pi / Buildroot convention; "/mnt/sdcard" is where the Luckfox Pico SDK auto-mounts
# the physical card (and, with no card, an empty mountpoint on the writable NAND/eMMC rootfs, so
# writing there gives persistent settings without a dedicated partition).
MICROSD_DIR_CANDIDATES = ("/mnt/microsd", "/mnt/sdcard")


def resolve_seedsigner_os_data_dir() -> str:
    """Return the SeedSigner-OS microSD / persistent-data directory.

    Prefers a candidate that is an active mountpoint (a real card mounted at either
    location wins); otherwise the first candidate that exists as a directory (the
    writable-rootfs fallback used on card-less NAND/eMMC images); otherwise the
    canonical default ``/mnt/microsd``.

    Platform note: ``/mnt/sdcard`` only exists on Luckfox (the SDK creates it). On
    Raspberry Pi / La Frite the root filesystem is stateless (wipes on reboot), so
    persistence there *requires* a physical card; this resolver returns
    ``/mnt/microsd`` unchanged on those platforms (no ``/mnt/sdcard`` to match), so
    real-card detection and the persistent-settings enable/disable gating are
    preserved exactly. Only on Luckfox, whose root is writable, does the card-less
    ``/mnt/sdcard`` mountpoint provide a persistent store.
    """
    for path in MICROSD_DIR_CANDIDATES:
        if os.path.ismount(path):
            return path
    for path in MICROSD_DIR_CANDIDATES:
        if os.path.isdir(path):
            return path
    return MICROSD_DIR_CANDIDATES[0]


class MicroSD(Singleton, BaseThread):
    MOUNT_POINT = "/mnt/microsd"
    FIFO_PATH = "/tmp/mdev_fifo"
    FIFO_MODE = 0o600
    ACTION__INSERTED = "add"
    ACTION__REMOVED = "remove"


    @staticmethod
    def get_microsd_dir() -> Path:
        """Return the path used for microSD interactions based on the host environment.

        * SeedSignerOS: ``/mnt/microsd``
        * Development boards (e.g. Raspberry Pi OS): ``/boot``
        * Desktop mode: ``<repo_root>/microsd`` (created if missing)
        """
        from seedsigner.models.settings import Settings  # avoid circular import

        if Settings.is_seedsigner_os():
            return Path(resolve_seedsigner_os_data_dir())
        elif Settings.is_dev_board():
            # Development boards typically have a pi user and use /boot for the
            # accessible microSD directory.
            return Path("/boot")
        else:
            # Default to a local directory in the repository for desktop usage.
            repo_root = Path(__file__).resolve().parents[3]
            microsd_path = repo_root / "microsd"
            # A path getter must never crash the app: swallow storage failures
            # (e.g. ENOSPC / read-only fs) and just return the intended path.
            try:
                microsd_path.mkdir(exist_ok=True)
            except OSError as e:
                logger.warning(f"Could not create microSD dir {microsd_path}: {e}")
            return microsd_path

    @staticmethod
    def is_desktop_mode() -> bool:
        """Return True when running in a desktop development environment.

        SeedSigner OS reports a distinct hostname and development boards typically
        have a ``/home/pi`` directory. Anything else is treated as "desktop".
        """
        from seedsigner.models.settings import Settings  # avoid circular import

        return Settings.is_desktop()


    @classmethod
    def get_instance(cls):
        # This is the only way to access the one and only instance
        if cls._instance is None:
            # Instantiate the one and only instance
            microsd = cls.__new__(cls)
            cls._instance = microsd

            # explicitly call BaseThread __init__ since multiple class inheritance
            BaseThread.__init__(microsd)
    
        return cls._instance


    @property
    def is_inserted(self):
        from seedsigner.models.settings import Settings  # Import here to avoid circular import issues

        if Settings.is_seedsigner_os():
            return os.path.exists(resolve_seedsigner_os_data_dir())
        else:
            # Always True for dev boards / desktop
            return True


    def start_detection(self):
        self.start()


    def run(self):
        from seedsigner.controller import Controller
        from seedsigner.gui.toast import SDCardStateChangeToastManagerThread
        from seedsigner.models.settings import Settings  # Import here to avoid circular import issues
        action = ""
        
        # explicitly only microsd add/remove detection in seedsigner-os
        if Settings.is_seedsigner_os():

            # at start-up, get current status and inform Settings
            Settings.handle_microsd_state_change(
                action=MicroSD.ACTION__INSERTED if self.is_inserted else MicroSD.ACTION__REMOVED
            )

            # Set up the mdev FIFO. A storage/permission failure here must not
            # crash the detection thread; log and stop detection instead.
            try:
                if os.path.exists(self.FIFO_PATH):
                    os.remove(self.FIFO_PATH)

                os.mkfifo(self.FIFO_PATH, self.FIFO_MODE)
            except OSError as e:
                logger.error(f"Could not create microSD detection FIFO {self.FIFO_PATH}: {e}")
                return

            while self.keep_running:
                with open(self.FIFO_PATH) as fifo:
                    action = fifo.read()
                    logger.info(f"fifo message: {action}")

                    Settings.handle_microsd_state_change(action=action)
                    Controller.get_instance().activate_toast(SDCardStateChangeToastManagerThread(action=action))

                time.sleep(0.1)
