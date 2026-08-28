import os
import re
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


READY_MARKER_PATH = "/tmp/seedsigner-ready"


def signal_app_alive() -> None:
    """Tell the OS boot watchdog that the app is up.

    Liveness, NOT "the user reached Home". The Luckfox watchdog in
    start-seedsigner.sh reboots into Loader mode if this marker never appears
    within ~120s, and it only ever exists to catch an app that failed to start.

    It must therefore be written as soon as the app is running and rendering —
    before the startup interstitials. Those include the unhardened-build
    warning, which blocks for a button press: on an unattended boot nobody
    presses it, so writing the marker only at Home made any unhardened image
    reboot itself into Loader after 120s. The device was working and waiting
    for input, which is not what the watchdog is for.

    The separate U-Boot boot-counter clear stays at Home — that one genuinely
    means "healthy enough", and is the deeper failover.
    """
    from seedsigner.models.settings import Settings

    if not Settings.is_seedsigner_os():
        return
    try:
        with open(READY_MARKER_PATH, "w") as ready_file:
            ready_file.write("1")
    except OSError:
        pass


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


ERROR_MICROSD_EXPORT_MARKER_PATH = "/etc/seedsigner-error-microsd-export"


def is_error_microsd_export_enabled() -> bool:
    """Diagnostic aid, off by default: whether an OS/package-error screen (e.g.
    GPG Tools' "Missing packages") should offer a "Save to MicroSD" button for
    the exact error text already shown on screen.

    Gated by a build-time marker file rather than an app-source constant so a
    given image can opt in without a code change, and so the hardening
    self-check (helpers.hardening) can see it and flag it as an open exposure
    when present -- a build that ships this should not report itself as fully
    hardened, since it is a deliberately-added capability, however low-risk.
    """
    return os.path.exists(ERROR_MICROSD_EXPORT_MARKER_PATH)


TESTING_BUILD_MARKER_PATH = "/etc/seedsigner-testing-build"


def is_testing_build_enabled() -> bool:
    """Off by default. Swaps Home's normal 4 options for a hardware-bring-up set
    (I/O Test, Test Smartcard, Flash Applet, Settings) -- see views.view.MainMenuView.

    Gated by a build-time marker file (same pattern as
    is_error_microsd_export_enabled()) so an image can opt in without a code change,
    and by the SEEDSIGNER_TESTING_BUILD env var so a desktop/dev-board run can flip
    it on without rebuilding an image (see the --testing-build flag in main.py).
    """
    return (
        os.path.exists(TESTING_BUILD_MARKER_PATH)
        or os.environ.get("SEEDSIGNER_TESTING_BUILD") == "1"
    )


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


DIY_MOUNT_LOG_PATH = "/tmp/diy-mount.log"
DIY_MOUNT_RESULT_MARKER = "=== diy-tools result ==="

# Result-block fields are plain identifiers; anything else (e.g. a stray
# timestamped human-readable line that happens to contain "=") is ignored.
_DIY_MOUNT_FIELD_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def parse_diy_mount_log(text: str) -> dict | None:
    """Parse the last *complete* ``=== diy-tools result ===`` block from a
    /tmp/diy-mount.log dump.

    The mdev hook appends one block per microSD insert/remove event; each
    block is a run of ``key=value`` lines (values may contain spaces, never
    newlines) following the marker line. A block counts as complete only if it
    carries a non-empty ``status=`` value -- so a partially-written trailing
    block (e.g. power lost mid-append) is ignored in favor of the previous
    complete one. Everything before a block's own marker, and any lines that
    are not well-formed ``key=value`` pairs, are skipped.

    Returns the last complete block as a dict of string key/value pairs
    (split on the FIRST "=" only), or None when no complete block exists.
    """
    if not text:
        return None

    blocks = []
    current = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line == DIY_MOUNT_RESULT_MARKER:
            current = {}
            blocks.append(current)
            continue
        if current is None or "=" not in line:
            continue
        key, _sep, value = line.partition("=")
        if not _DIY_MOUNT_FIELD_KEY_RE.match(key):
            continue
        current[key] = value

    for block in reversed(blocks):
        if block.get("status"):
            return block
    return None


def read_diy_mount_status(path: str = DIY_MOUNT_LOG_PATH) -> dict | None:
    """Read the latest diy-tools mount result from /tmp/diy-mount.log.

    The log lives on tmpfs, so a missing file simply means "no mount events
    since boot" -- that is no information, not an error. Any IO problem is
    likewise swallowed and reported as None; this must never crash the app.
    The file is opened read-only and never modified or truncated.
    """
    try:
        with open(path, "r", encoding="utf-8") as log_file:
            text = log_file.read()
    except OSError:
        return None
    return parse_diy_mount_log(text)

