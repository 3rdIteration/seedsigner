import os
from pathlib import Path


OS_RELEASE_PATH = "/etc/seedsigner-os-release"


def is_seedsigner_os_dev_build() -> bool:
    """Return True if running on a developer SeedSignerOS image.

    Developer OS images include additional utilities such as
    ``/usr/bin/microsd_notice.py`` used during boot to load sources
    from an external microSD card. The presence of this file marks a
    development build that is not intended for production use.
    """
    return os.path.exists("/usr/bin/microsd_notice.py")


def get_os_release(path: str = OS_RELEASE_PATH) -> dict:
    """Parse the SeedSigner OS build-info marker (``KEY=VALUE``, os-release style).

    Generated at build time by seedsigner-os; carries the repo/branch/commit/date
    for both seedsigner-os and the seedsigner app. Returns an empty dict when the
    file is absent (desktop / dev), so callers degrade gracefully.
    """
    data: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as release_file:
            for line in release_file:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _sep, value = line.partition("=")
                data[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return data


def is_running_from_microsd() -> bool:
    """True when the running SeedSigner source is loaded from the microSD card
    (a dev workflow) rather than the embedded system partition.

    The dev launcher runs the app from ``/mnt/microsd/seedsigner/src`` when that
    directory exists, so the reliable, platform-independent check is whether this
    package's own path lives under the microSD mount point.
    """
    from seedsigner.hardware.microsd import MicroSD  # avoid circular import

    try:
        import seedsigner

        source_path = str(Path(seedsigner.__file__).resolve())
    except Exception:
        return False

    return source_path.startswith(MicroSD.MOUNT_POINT)

