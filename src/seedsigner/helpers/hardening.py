"""Runtime hardening self-checks.

Answers "is this image actually hardened?" from the **live system** rather than
from a build flag or a marker file. A build flag can be set wrong and a marker
file can be missing — this is exactly how the developer warning silently failed
on Luckfox for every image, dev and non-dev alike — but what the kernel and
filesystem currently expose cannot lie.

Threat model: root-level code execution. The SeedSigner app runs as root, so
userspace tidying (stubbed binaries, deleted init scripts) is not a control by
itself — root can undo it. The checks below therefore look for capabilities
being *absent from the kernel*, which root cannot restore, and treat userspace
state only as corroboration.

Two consumers share this module:
  * the startup warning (fires when any CRITICAL check fails), and
  * Settings -> Advanced -> Test hardening (shows every check).

Every probe is READ-ONLY. Nothing here may write a file: a write probe is a side
effect, and on a persistent rootfs it leaves litter behind.

A probe that cannot determine an answer returns ``STATE_NA`` — never a failure.
False alarms on desktop or on an unfamiliar platform would train people to
ignore the warning, which is worse than no warning at all.

Paths are module-level constants so tests can point them at a fake tree.
"""

import os
import shutil
from dataclasses import dataclass
from typing import Callable

from gettext import gettext as _

# Probe targets (overridable in tests)
PROC_DIR = "/proc"
PROC_CMDLINE = "/proc/cmdline"
PROC_MODULES = "/proc/modules"
PROC_NET_TCP = "/proc/net/tcp"
PROC_MOUNTINFO = "/proc/self/mountinfo"
PROC_MOUNTS = "/proc/mounts"
SYS_CLASS_NET = "/sys/class/net"
SYS_CLASS_UDC = "/sys/class/udc"
SYS_CLASS_IEEE80211 = "/sys/class/ieee80211"
OEM_KO_DIR = "/oem/usr/ko"
LIB_MODULES_DIR = "/lib/modules"

# Substrings identifying a wireless driver module by filename.
WIFI_MODULE_PATTERNS = (
    "cfg80211", "mac80211", "8188", "8189", "8723", "aic8800", "atbm", "ssv6",
)
REMOTE_SHELL_DAEMONS = ("telnetd", "sshd", "dropbear")
LOGGING_DAEMONS = ("syslogd", "klogd")
DEV_TOOLS = ("pip", "pip3", "curl", "wget")
# Filesystems whose contents do not survive a reboot.
VOLATILE_FSTYPES = ("tmpfs", "ramfs")

STATE_PASS = "pass"
STATE_FAIL = "fail"
STATE_NA = "n/a"

SEVERITY_CRITICAL = "critical"
SEVERITY_INFO = "info"


@dataclass
class HardeningCheck:
    """One probe's result.

    ``open_name`` is the short noun used in the startup warning's "Open: ..."
    list — it must read sensibly in a comma-joined sentence on a 240x240 screen.
    """
    key: str
    label: str
    severity: str
    state: str
    detail: str = ""
    open_name: str = ""

    @property
    def failed(self) -> bool:
        return self.state == STATE_FAIL


# --------------------------------------------------------------------------
# Low-level readers. All swallow errors and report "unknown" rather than raise:
# a missing /proc entry means we cannot tell, not that the system is insecure.
# --------------------------------------------------------------------------

def _read_text(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def _list_dir(path: str) -> list[str] | None:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return None


def _af_inet_supported() -> bool | None:
    """True if an AF_INET socket can be created at all.

    With CONFIG_INET compiled out the address family does not exist and this
    raises. Creating (and immediately closing) an unbound socket is read-only —
    it touches no network and leaves nothing behind.
    """
    import socket

    if not hasattr(socket, "AF_INET"):
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return False
    except Exception:
        return None
    else:
        sock.close()
        return True


def _running_process_names() -> set[str] | None:
    """Process comm names from /proc/<pid>/comm."""
    entries = _list_dir(PROC_DIR)
    if entries is None:
        return None
    names: set[str] = set()
    for entry in entries:
        if not entry.isdigit():
            continue
        comm = _read_text(os.path.join(PROC_DIR, entry, "comm"))
        if comm:
            names.add(comm.strip())
    return names


def _find_modules(patterns: tuple[str, ...]) -> list[str]:
    """Loadable .ko files under the oem/module dirs matching any pattern."""
    found: list[str] = []
    for base in (OEM_KO_DIR, LIB_MODULES_DIR):
        if not os.path.isdir(base):
            continue
        for root, _dirs, files in os.walk(base):
            for name in files:
                if not name.endswith(".ko"):
                    continue
                lowered = name.lower()
                if any(pattern in lowered for pattern in patterns):
                    found.append(os.path.join(root, name))
    return found


def _root_mount() -> tuple[str, str, str] | None:
    """(fstype, options, super_options) for ``/`` from mountinfo, else None.

    mountinfo format: ... - <fstype> <source> <super options>
    """
    content = _read_text(PROC_MOUNTINFO)
    if content:
        for line in content.splitlines():
            if " - " not in line:
                continue
            left, _sep, right = line.partition(" - ")
            fields = left.split()
            # fields[4] is the mount point
            if len(fields) < 5 or fields[4] != "/":
                continue
            options = fields[5] if len(fields) > 5 else ""
            # Optional fields (fields[6:]) sit between the mount options and the
            # " - " separator. upperdir= normally lives in the super options on
            # the right, but scan both so parsing doesn't depend on where a
            # given kernel puts it.
            optional = ",".join(fields[6:]) if len(fields) > 6 else ""
            right_fields = right.split()
            fstype = right_fields[0] if right_fields else ""
            super_options = right_fields[2] if len(right_fields) > 2 else ""
            if optional:
                super_options = f"{super_options},{optional}" if super_options else optional
            return (fstype, options, super_options)

    # Fall back to /proc/mounts: <src> <mountpoint> <fstype> <options> ...
    content = _read_text(PROC_MOUNTS)
    if content:
        for line in content.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "/":
                return (parts[2], parts[3], parts[3])
    return None


def _mount_fstype_for_path(path: str) -> str | None:
    """fstype of the mount that contains ``path`` (longest-prefix match)."""
    content = _read_text(PROC_MOUNTS)
    if not content:
        return None
    best_len = -1
    best_type = None
    for line in content.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        mount_point, fstype = parts[1], parts[2]
        if path == mount_point or path.startswith(mount_point.rstrip("/") + "/"):
            if len(mount_point) > best_len:
                best_len, best_type = len(mount_point), fstype
    return best_type


# --------------------------------------------------------------------------
# CRITICAL checks — capabilities that expose the device. These drive the
# startup warning, so each must be a genuine exposure, not a matter of taste.
# --------------------------------------------------------------------------

def check_ip_stack() -> HardeningCheck:
    supported = _af_inet_supported()
    if supported is None:
        state, detail = STATE_NA, _("Could not probe AF_INET")
    elif supported:
        state, detail = STATE_FAIL, _("AF_INET sockets available")
    else:
        state, detail = STATE_PASS, _("No TCP/IP in kernel")
    return HardeningCheck(
        key="ip_stack", label=_("TCP/IP stack removed"), severity=SEVERITY_CRITICAL,
        state=state, detail=detail, open_name=_("network"),
    )


def check_network_interfaces() -> HardeningCheck:
    entries = _list_dir(SYS_CLASS_NET)
    if entries is None:
        state, detail = STATE_NA, _("No /sys/class/net")
    else:
        externals = [name for name in entries if name != "lo"]
        if externals:
            state = STATE_FAIL
            detail = _("Interfaces: {names}").format(names=", ".join(externals))
        else:
            state, detail = STATE_PASS, _("Loopback only")
    return HardeningCheck(
        key="net_ifaces", label=_("No network interfaces"), severity=SEVERITY_CRITICAL,
        state=state, detail=detail, open_name=_("network"),
    )


def check_wireless_stack() -> HardeningCheck:
    modules = _read_text(PROC_MODULES)
    ieee = _list_dir(SYS_CLASS_IEEE80211)
    if modules is None and ieee is None:
        state, detail = STATE_NA, _("Could not probe wireless")
    else:
        loaded = []
        if modules:
            for line in modules.splitlines():
                name = line.split(" ", 1)[0]
                if name in ("cfg80211", "mac80211"):
                    loaded.append(name)
        if loaded or ieee:
            state = STATE_FAIL
            detail = _("802.11 stack present")
        else:
            state, detail = STATE_PASS, _("No 802.11 stack")
    return HardeningCheck(
        key="wireless", label=_("No wireless stack"), severity=SEVERITY_CRITICAL,
        state=state, detail=detail, open_name=_("WiFi"),
    )


def check_wifi_modules() -> HardeningCheck:
    found = _find_modules(WIFI_MODULE_PATTERNS)
    if found:
        state = STATE_FAIL
        detail = _("{count} loadable driver(s)").format(count=len(found))
    else:
        state, detail = STATE_PASS, _("None on disk")
    return HardeningCheck(
        key="wifi_modules", label=_("No WiFi drivers on disk"), severity=SEVERITY_CRITICAL,
        state=state, detail=detail, open_name=_("WiFi"),
    )


def check_usb_gadget() -> HardeningCheck:
    """An empty /sys/class/udc means no device controller for a gadget to bind,
    so ADB cannot be started however much of its userspace survives."""
    entries = _list_dir(SYS_CLASS_UDC)
    if entries is None:
        state, detail = STATE_NA, _("No /sys/class/udc")
    elif entries:
        state = STATE_FAIL
        detail = _("UDC present: {names}").format(names=", ".join(entries))
    else:
        state, detail = STATE_PASS, _("No UDC, ADB impossible")
    return HardeningCheck(
        key="usb_gadget", label=_("USB gadget cannot bind"), severity=SEVERITY_CRITICAL,
        state=state, detail=detail, open_name=_("USB-ADB"),
    )


def check_serial_console() -> HardeningCheck:
    cmdline = _read_text(PROC_CMDLINE)
    if cmdline is None:
        state, detail = STATE_NA, _("No /proc/cmdline")
    else:
        consoles = [
            token for token in cmdline.split()
            if token.startswith("console=") and not token.startswith("console=ttynull")
        ]
        if consoles:
            state = STATE_FAIL
            detail = _("Console: {tokens}").format(tokens=" ".join(consoles))
        else:
            state, detail = STATE_PASS, _("No serial console")
    return HardeningCheck(
        key="serial_console", label=_("Serial console silenced"), severity=SEVERITY_CRITICAL,
        state=state, detail=detail, open_name=_("serial"),
    )


def check_remote_shells() -> HardeningCheck:
    names = _running_process_names()
    if names is None:
        state, detail = STATE_NA, _("Could not read process list")
    else:
        running = sorted(n for n in names if any(d in n for d in REMOTE_SHELL_DAEMONS))
        if running:
            state = STATE_FAIL
            detail = _("Running: {names}").format(names=", ".join(running))
        else:
            state, detail = STATE_PASS, _("None running")
    return HardeningCheck(
        key="remote_shells", label=_("No remote shell daemon"), severity=SEVERITY_CRITICAL,
        state=state, detail=detail, open_name=_("remote shell"),
    )


# --------------------------------------------------------------------------
# INFO checks — reported, never warned on.
# --------------------------------------------------------------------------

def check_panic_reboot() -> HardeningCheck:
    """Recovery rather than exposure: panic=N reboots instead of hanging, so the
    U-Boot boot-counter failover gets another chance to reach Loader mode."""
    cmdline = _read_text(PROC_CMDLINE)
    if cmdline is None:
        state, detail = STATE_NA, _("No /proc/cmdline")
    elif any(token.startswith("panic=") for token in cmdline.split()):
        state, detail = STATE_PASS, _("Reboot on panic armed")
    else:
        state, detail = STATE_FAIL, _("No panic= in cmdline")
    return HardeningCheck(
        key="panic_reboot", label=_("Reboot on kernel panic"), severity=SEVERITY_INFO,
        state=state, detail=detail,
    )


def check_logging_daemons() -> HardeningCheck:
    names = _running_process_names()
    if names is None:
        state, detail = STATE_NA, _("Could not read process list")
    else:
        running = sorted(n for n in names if any(d in n for d in LOGGING_DAEMONS))
        if running:
            state = STATE_FAIL
            detail = _("Running: {names}").format(names=", ".join(running))
        else:
            state, detail = STATE_PASS, _("None running")
    return HardeningCheck(
        key="logging", label=_("No logging daemons"), severity=SEVERITY_INFO,
        state=state, detail=detail,
    )


def check_dev_tools() -> HardeningCheck:
    present = [tool for tool in DEV_TOOLS if shutil.which(tool)]
    if present:
        state = STATE_FAIL
        detail = _("Present: {names}").format(names=", ".join(present))
    else:
        state, detail = STATE_PASS, _("None on PATH")
    return HardeningCheck(
        key="dev_tools", label=_("No dev/network tools"), severity=SEVERITY_INFO,
        state=state, detail=detail,
    )


def check_rootfs_non_persistent() -> HardeningCheck:
    """Root may be WRITABLE yet non-persistent: writes land in a volatile upper
    layer and are gone after reboot. So this must not test the ``ro`` flag — a
    correctly hardened image reports ``rw``. Detect the mechanism instead.

    Verifies that the mechanism is in place, not persistence empirically;
    proving the latter needs a marker written before a reboot and read after,
    which is stateful and not worth the writes.

    INFO for now — the control is not enabled yet, so failing it must not raise
    the unhardened warning. Promote to SEVERITY_CRITICAL once it ships.
    """
    mount = _root_mount()
    if mount is None:
        return HardeningCheck(
            key="rootfs", label=_("Root writes not persistent"), severity=SEVERITY_INFO,
            state=STATE_NA, detail=_("Could not read mount table"),
        )

    fstype, options, super_options = mount
    opts = f"{options},{super_options}"

    if fstype in VOLATILE_FSTYPES:
        state, detail = STATE_PASS, _("Root is {fstype}").format(fstype=fstype)
    elif fstype == "overlay":
        upper = ""
        for opt in opts.split(","):
            if opt.startswith("upperdir="):
                upper = opt.split("=", 1)[1]
                break
        upper_fs = _mount_fstype_for_path(upper) if upper else None
        if upper_fs in VOLATILE_FSTYPES:
            state = STATE_PASS
            detail = _("Overlay upper on {fstype}").format(fstype=upper_fs)
        elif upper_fs is None:
            state, detail = STATE_NA, _("Overlay upper layer unknown")
        else:
            state = STATE_FAIL
            detail = _("Overlay upper on {fstype}").format(fstype=upper_fs)
    elif "ro" in options.split(","):
        state, detail = STATE_PASS, _("Root mounted read-only")
    else:
        state = STATE_FAIL
        detail = _("Writable {fstype}, changes persist").format(fstype=fstype)

    return HardeningCheck(
        key="rootfs", label=_("Root writes not persistent"), severity=SEVERITY_INFO,
        state=state, detail=detail,
    )


# Order is the display order on the Test hardening screen.
ALL_CHECKS: tuple[Callable[[], HardeningCheck], ...] = (
    check_ip_stack,
    check_network_interfaces,
    check_wireless_stack,
    check_wifi_modules,
    check_usb_gadget,
    check_serial_console,
    check_remote_shells,
    check_rootfs_non_persistent,
    check_panic_reboot,
    check_logging_daemons,
    check_dev_tools,
)


def run_checks() -> list[HardeningCheck]:
    """Run every probe. A probe that raises is reported as n/a, never as a
    failure — a bug in a probe must not masquerade as an insecure device."""
    results: list[HardeningCheck] = []
    for check in ALL_CHECKS:
        try:
            results.append(check())
        except Exception:
            results.append(HardeningCheck(
                key=getattr(check, "__name__", "unknown"),
                label=_("Check failed to run"),
                severity=SEVERITY_INFO,
                state=STATE_NA,
                detail=_("Probe error"),
            ))
    return results


def failed_critical(results: list[HardeningCheck] | None = None) -> list[HardeningCheck]:
    if results is None:
        results = run_checks()
    return [r for r in results if r.severity == SEVERITY_CRITICAL and r.failed]


def is_hardened(results: list[HardeningCheck] | None = None) -> bool:
    """False when any CRITICAL exposure check failed.

    n/a never counts as a failure, so an unrecognised platform is reported as
    hardened rather than triggering a false alarm. Callers that care about
    "unknown" should look at the check states directly.
    """
    return not failed_critical(results)


def open_exposures(results: list[HardeningCheck] | None = None) -> list[str]:
    """De-duplicated short names of what is open, for the warning copy."""
    names: list[str] = []
    for check in failed_critical(results):
        name = check.open_name or check.label
        if name not in names:
            names.append(name)
    return names
