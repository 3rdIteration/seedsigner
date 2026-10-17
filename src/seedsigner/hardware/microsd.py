import logging
import os
import select
import time
from pathlib import Path

from seedsigner.models.singleton import Singleton
from seedsigner.models.threads import BaseThread

logger = logging.getLogger(__name__)


# Removable-card mountpoints, in priority order. "/mnt/microsd" is the Raspberry-Pi /
# Buildroot convention; "/mnt/sdcard" is where the Luckfox Pico SDK auto-mounts a card.
MICROSD_DIR_CANDIDATES = ("/mnt/microsd", "/mnt/sdcard")

# Dedicated writable partition for persistent data when no card is present. Every
# Luckfox board (Mini / Pro Max / Pi) gets a small one; Raspberry Pi / La Frite have no
# such partition, so this simply never matches there.
USERDATA_DIR = "/userdata"


def resolve_microsd_mount():
    """Return the mountpoint of a genuinely mounted removable card, else None.

    Strictly a *mountpoint* test: a bare directory is never a card.
    """
    for path in MICROSD_DIR_CANDIDATES:
        if os.path.ismount(path):
            return path
    return None


def resolve_seedsigner_os_data_dir() -> str:
    """Return the SeedSigner-OS persistent-data directory.

    Priority: a mounted removable card, then the dedicated ``/userdata`` partition,
    then the canonical ``/mnt/microsd`` -- which, when it is not a mountpoint, means
    "no persistent store available" (see ``MicroSD.has_persistent_storage``).

    NEVER RETURNS A DIRECTORY ON THE ROOT FILESYSTEM. Every candidate is tested with
    ``os.path.ismount``, never ``os.path.isdir``, so a bare mountpoint directory left
    behind on the rootfs can never be selected.

    That is a hard invariant, not a preference. The previous implementation fell back
    to the first candidate that merely *existed as a directory*, which on a card-less
    Luckfox NAND image resolved to ``/mnt/sdcard`` on the writable UBIFS root. Putting
    mutable state on the root filesystem means an unclean shutdown can lose or truncate
    it during UBIFS journal replay -- the same failure class that silently emptied
    ``/etc/luckfox.cfg`` and left boards with no display and no way to report why. The
    rootfs is to be treated as immutable after flashing; persistent state belongs on
    the card or on ``/userdata``.

    Platform note: ``/userdata`` does not exist on Raspberry Pi / La Frite, whose root
    is stateless, so persistence there still requires a physical card.
    """
    card = resolve_microsd_mount()
    if card is not None:
        return card
    if os.path.ismount(USERDATA_DIR):
        return USERDATA_DIR
    return MICROSD_DIR_CANDIDATES[0]


# Working directory for file-based operations (GPG signing/verification,
# encrypted output, image staging), relative to the resolved data dir.
MICROSD_IMAGES_SUBDIR = "microsd-images"

# Last-resort staging area when there is nowhere else writable. tmpfs, so it is
# always writable and always empty after a reboot.
FALLBACK_IMAGES_DIR = "/tmp/seedsigner-images"


def resolve_microsd_images_dir() -> Path:
    """Return a writable working directory for file-based operations.

    NEVER RAISES. Callers use this to stage files before an operation, and on a
    read-only root the naive ``os.makedirs(get_microsd_dir() / "microsd-images")``
    raises an uncaught ``OSError: [Errno 30] Read-only file system`` that takes
    the whole view down.

    That is reachable in normal use: ``resolve_seedsigner_os_data_dir`` falls
    back to the literal ``/mnt/microsd`` when there is no card AND no
    ``/userdata``, and ``/mnt`` is not one of the tmpfs overlays on a
    squashfs-root image, so the path is genuinely unwritable rather than merely
    absent.

    Falling back to tmpfs keeps the feature usable instead of crashing. The
    trade-off is deliberate and worth stating: files written there do not
    survive a reboot, which is the right failure mode for a device whose whole
    point is not to persist secrets, but it does mean an export can appear to
    succeed with nowhere durable to land. Callers that need the user to end up
    with a file on their card should check ``MicroSD.get_instance().is_inserted``
    and say so.
    """
    preferred = Path(resolve_seedsigner_os_data_dir()) / MICROSD_IMAGES_SUBDIR
    try:
        os.makedirs(preferred, exist_ok=True)
        return preferred
    except OSError as e:
        logger.warning(
            f"Could not create {preferred} ({e}); falling back to {FALLBACK_IMAGES_DIR}"
        )

    fallback = Path(FALLBACK_IMAGES_DIR)
    try:
        os.makedirs(fallback, exist_ok=True)
    except OSError as e:
        # Nothing left to try. Return the path anyway so the caller fails on its
        # own open() with a message naming the file, rather than here with a
        # message about a directory.
        logger.error(f"Could not create fallback staging dir {fallback}: {e}")
    return fallback


class MicroSD(Singleton, BaseThread):
    MOUNT_POINT = "/mnt/microsd"
    FIFO_PATH = "/tmp/mdev_fifo"
    FIFO_MODE = 0o600
    ACTION__INSERTED = "add"
    ACTION__REMOVED = "remove"
    # Mount-state re-check interval. The OS hotplug helper's FIFO message is
    # only a wake-up hint; this poll catches anything it missed.
    POLL_INTERVAL_SECONDS = 1.0


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
        """Is a physical removable card present?

        Drives the insert/remove toast and the microSD detection thread, so it must
        mean a real card and nothing else. Deliberately NOT "is there somewhere to
        persist settings" -- see ``has_persistent_storage``. Conflating the two is
        what previously let a bare ``/mnt/sdcard`` directory on the rootfs report a
        card that was not there.
        """
        from seedsigner.models.settings import Settings  # Import here to avoid circular import issues

        if Settings.is_seedsigner_os():
            return resolve_microsd_mount() is not None
        else:
            # Always True for dev boards / desktop
            return True


    @property
    def has_persistent_storage(self) -> bool:
        """Is there a writable, non-rootfs store for persistent settings?

        True for a mounted card OR the dedicated ``/userdata`` partition. This is the
        correct gate for saving settings: on a card-less Luckfox with ``/userdata``,
        settings must persist even though no card is inserted, while on a board with
        neither, saving must be skipped rather than silently writing to the rootfs.
        """
        from seedsigner.models.settings import Settings  # Import here to avoid circular import issues

        if Settings.is_seedsigner_os():
            return os.path.ismount(resolve_seedsigner_os_data_dir())
        else:
            # Always True for dev boards / desktop
            return True


    def start_detection(self):
        self.start()


    @classmethod
    def parse_fifo_actions(cls, data: bytes) -> list:
        """Extract the add/remove notifications from raw FIFO bytes, in order.

        Hotplug helpers write a bare ``add`` / ``remove`` with no separator, so
        back-to-back events read as one chunk (``b"removeadd"`` for a quick card
        swap). Anything else in the data is ignored.
        """
        text = data.decode("ascii", errors="ignore")
        actions = []
        i = 0
        while i < len(text):
            for action in (cls.ACTION__INSERTED, cls.ACTION__REMOVED):
                if text.startswith(action, i):
                    actions.append(action)
                    i += len(action)
                    break
            else:
                i += 1
        return actions


    @classmethod
    def detect_state_change(cls, was_inserted: bool, now_inserted: bool, fifo_actions: list):
        """Decide which state change (if any) to report to Settings and the toast.

        The mount state is the source of truth; FIFO messages only wake us up.
        The one case a pure state comparison misses is a card swapped faster
        than the poll: it reads as "still inserted", but the OS says a card was
        added, so the new card's settings.json must be loaded.
        """
        if now_inserted != was_inserted:
            return cls.ACTION__INSERTED if now_inserted else cls.ACTION__REMOVED
        if now_inserted and cls.ACTION__INSERTED in fifo_actions:
            return cls.ACTION__INSERTED
        return None


    def _open_fifo(self):
        """Create the hotplug FIFO and return a non-blocking fd, or None.

        O_RDWR because Linux lets a FIFO's reader also hold the write end: the
        fd then never reports EOF/POLLHUP between hotplug writers, so select()
        sleeps until real data arrives instead of spinning.
        """
        try:
            if os.path.lexists(self.FIFO_PATH):
                os.remove(self.FIFO_PATH)
            os.mkfifo(self.FIFO_PATH, self.FIFO_MODE)
            return os.open(self.FIFO_PATH, os.O_RDWR | os.O_NONBLOCK)
        except (OSError, AttributeError) as e:
            # A storage/permission failure must not kill detection: fall back to
            # polling the mount state alone.
            logger.error(
                f"Could not create microSD detection FIFO {self.FIFO_PATH}: {e}; "
                "falling back to polling the mount state"
            )
            return None


    def _wait_for_hint(self, fifo_fd) -> list:
        """Block up to POLL_INTERVAL_SECONDS for a FIFO message; return its actions."""
        if fifo_fd is None:
            time.sleep(self.POLL_INTERVAL_SECONDS)
            return []
        ready, _, _ = select.select([fifo_fd], [], [], self.POLL_INTERVAL_SECONDS)
        if not ready:
            return []
        try:
            data = os.read(fifo_fd, 256)
        except BlockingIOError:
            return []
        logger.info(f"fifo message: {data!r}")
        return self.parse_fifo_actions(data)


    def run(self):
        from seedsigner.controller import Controller
        from seedsigner.gui.toast import SDCardStateChangeToastManagerThread
        from seedsigner.models.settings import Settings  # Import here to avoid circular import issues

        # explicitly only microsd add/remove detection in seedsigner-os
        if not Settings.is_seedsigner_os():
            return

        # Create the FIFO BEFORE sampling the mount state. The OS hotplug helper
        # writes to it right after mounting; a card mounted between the sample
        # and the mkfifo used to be lost -- its "add" went into a plain file that
        # mkfifo then deleted -- and the app believed there was no card (so no
        # Persistent Settings) for the whole session. Any event from here on is
        # either queued in the FIFO or caught by the mount-state poll.
        fifo_fd = self._open_fifo()

        # at start-up, get current status and inform Settings
        inserted = self.is_inserted
        Settings.handle_microsd_state_change(
            action=MicroSD.ACTION__INSERTED if inserted else MicroSD.ACTION__REMOVED
        )

        try:
            while self.keep_running:
                fifo_actions = self._wait_for_hint(fifo_fd)
                now_inserted = self.is_inserted
                action = self.detect_state_change(inserted, now_inserted, fifo_actions)
                inserted = now_inserted
                if action is None:
                    continue
                logger.info(f"microSD state change: {action}")
                Settings.handle_microsd_state_change(action=action)
                Controller.get_instance().activate_toast(SDCardStateChangeToastManagerThread(action=action))
        finally:
            if fifo_fd is not None:
                os.close(fifo_fd)
