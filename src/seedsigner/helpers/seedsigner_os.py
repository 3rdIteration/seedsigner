import os
from pathlib import Path


OS_RELEASE_PATH = "/etc/seedsigner-os-release"


def is_seedsigner_os_dev_build() -> bool:
    """Return True if the running image is NOT hardened for production use.

    Decided from the **live system** (see ``helpers.hardening``) rather than
    from a build flag or a marker file: a build flag can be set wrong and a
    marker file can be missing. This function previously keyed solely off
    ``/usr/bin/microsd_notice.py``, which only the Raspberry Pi dev overlay
    installs — so on Luckfox it was always False and a dev image (serial
    console, USB-ADB, telnet, no hardening) warned about nothing at all.

    The marker file is retained as an *additional* signal: a Pi dev image is
    still a dev image even if it happens to pass the exposure checks.

    Deliberately NOT restricted to SeedSigner OS images. A desktop or dev-board
    run genuinely fails several exposure checks, so warning there is a true
    statement rather than a false alarm, and "do not use real seeds" applies
    just as much. (``DesktopWarningView`` may also fire; the two say different
    things — one is about the environment, this one about what is exposed.)
    """
    if os.path.exists("/usr/bin/microsd_notice.py"):
        return True

    from seedsigner.helpers import hardening

    return not hardening.is_hardened()


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

