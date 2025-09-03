import logging
import os
import time
from pathlib import Path

from seedsigner.models.singleton import Singleton
from seedsigner.models.threads import BaseThread

logger = logging.getLogger(__name__)


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

        if Settings.HOSTNAME == Settings.SEEDSIGNER_OS:
            return Path("/mnt/microsd")
        elif os.path.exists("/home/pi"):
            # Development boards typically have a pi user and use /boot for the
            # accessible microSD directory.
            return Path("/boot")
        else:
            # Default to a local directory in the repository for desktop usage.
            repo_root = Path(__file__).resolve().parents[3]
            microsd_path = repo_root / "microsd"
            microsd_path.mkdir(exist_ok=True)
            return microsd_path


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

        if Settings.HOSTNAME == Settings.SEEDSIGNER_OS:
            return os.path.exists(MicroSD.MOUNT_POINT)
        else:
            # Always True for Raspi OS
            return True


    def start_detection(self):
        self.start()


    def run(self):
        from seedsigner.controller import Controller
        from seedsigner.gui.toast import SDCardStateChangeToastManagerThread
        from seedsigner.models.settings import Settings  # Import here to avoid circular import issues
        action = ""
        
        # explicitly only microsd add/remove detection in seedsigner-os
        if Settings.HOSTNAME == Settings.SEEDSIGNER_OS:

            # at start-up, get current status and inform Settings
            Settings.handle_microsd_state_change(
                action=MicroSD.ACTION__INSERTED if self.is_inserted else MicroSD.ACTION__REMOVED
            )

            if os.path.exists(self.FIFO_PATH):
                os.remove(self.FIFO_PATH)
            
            os.mkfifo(self.FIFO_PATH, self.FIFO_MODE)

            while self.keep_running:
                with open(self.FIFO_PATH) as fifo:
                    action = fifo.read()
                    logger.info(f"fifo message: {action}")

                    Settings.handle_microsd_state_change(action=action)
                    Controller.get_instance().activate_toast(SDCardStateChangeToastManagerThread(action=action))

                time.sleep(0.1)
