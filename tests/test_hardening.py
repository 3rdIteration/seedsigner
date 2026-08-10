"""Tests for the runtime hardening self-checks.

Every probe is driven off a fake /proc, /sys and PATH so these run on desktop
CI. The three cases that matter are a hardened tree (all CRITICAL checks pass),
a wide-open tree (they fail, naming the right exposures), and an indeterminate
tree — which must yield n/a rather than a false failure, since a false alarm
would train people to ignore the warning.
"""

import os

import pytest

from seedsigner.helpers import hardening


# --------------------------------------------------------------------------
# Fixtures: build fake /proc and /sys trees and point the module at them.
# --------------------------------------------------------------------------

def _write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def _point_module_at(monkeypatch, root, *, empty_path=True):
    monkeypatch.setattr(hardening, "PROC_DIR", str(root / "proc"))
    monkeypatch.setattr(hardening, "PROC_CMDLINE", str(root / "proc/cmdline"))
    monkeypatch.setattr(hardening, "PROC_MODULES", str(root / "proc/modules"))
    monkeypatch.setattr(hardening, "PROC_NET_TCP", str(root / "proc/net/tcp"))
    monkeypatch.setattr(hardening, "PROC_MOUNTINFO", str(root / "proc/self/mountinfo"))
    monkeypatch.setattr(hardening, "PROC_MOUNTS", str(root / "proc/mounts"))
    monkeypatch.setattr(hardening, "SYS_CLASS_NET", str(root / "sys/class/net"))
    monkeypatch.setattr(hardening, "SYS_CLASS_UDC", str(root / "sys/class/udc"))
    monkeypatch.setattr(hardening, "SYS_CLASS_IEEE80211", str(root / "sys/class/ieee80211"))
    monkeypatch.setattr(hardening, "OEM_KO_DIR", str(root / "oem/usr/ko"))
    monkeypatch.setattr(hardening, "LIB_MODULES_DIR", str(root / "lib/modules"))
    if empty_path:
        # An empty PATH means shutil.which() finds no dev tools.
        monkeypatch.setenv("PATH", str(root / "empty-bin"))
        os.makedirs(root / "empty-bin", exist_ok=True)


@pytest.fixture
def hardened(tmp_path, monkeypatch):
    """A fully hardened Luckfox-like tree."""
    root = tmp_path / "hardened"
    _write(root / "proc/cmdline", "root=ubi0:rootfs rootfstype=ubifs quiet loglevel=3 panic=5\n")
    _write(root / "proc/modules", "video_rkisp 12345 0 - Live 0x00000000\n")
    _write(root / "proc/mounts", "ubi0:rootfs / ubifs ro,relatime 0 0\ntmpfs /tmp tmpfs rw 0 0\n")
    _write(root / "proc/self/mountinfo",
           "1 0 0:1 / / ro,relatime - ubifs ubi0:rootfs ro\n")
    os.makedirs(root / "sys/class/net/lo", exist_ok=True)
    os.makedirs(root / "sys/class/udc", exist_ok=True)          # exists but empty
    os.makedirs(root / "oem/usr/ko", exist_ok=True)
    _write(root / "oem/usr/ko/video_rkisp.ko", "")               # camera module is fine
    # init only; no telnetd/sshd/syslogd
    _write(root / "proc/1/comm", "init\n")
    _point_module_at(monkeypatch, root)
    monkeypatch.setattr(hardening, "_af_inet_supported", lambda: False)
    return root


@pytest.fixture
def wide_open(tmp_path, monkeypatch):
    """An unhardened dev-style tree: networking, wifi, ADB, serial, telnet."""
    root = tmp_path / "open"
    _write(root / "proc/cmdline", "root=ubi0:rootfs console=ttyFIQ0,115200 rw\n")
    _write(root / "proc/modules", "cfg80211 100 1 - Live 0x0\nmac80211 100 1 - Live 0x0\n")
    _write(root / "proc/mounts", "ubi0:rootfs / ubifs rw,relatime 0 0\n")
    _write(root / "proc/self/mountinfo",
           "1 0 0:1 / / rw,relatime - ubifs ubi0:rootfs rw\n")
    os.makedirs(root / "sys/class/net/lo", exist_ok=True)
    os.makedirs(root / "sys/class/net/eth0", exist_ok=True)
    os.makedirs(root / "sys/class/udc/ffb00000.usb", exist_ok=True)
    os.makedirs(root / "sys/class/ieee80211/phy0", exist_ok=True)
    _write(root / "oem/usr/ko/8188fu.ko", "")
    _write(root / "oem/usr/ko/cfg80211.ko", "")
    _write(root / "proc/1/comm", "init\n")
    _write(root / "proc/42/comm", "telnetd\n")
    _write(root / "proc/43/comm", "syslogd\n")
    _point_module_at(monkeypatch, root)
    monkeypatch.setattr(hardening, "_af_inet_supported", lambda: True)
    return root


@pytest.fixture
def indeterminate(tmp_path, monkeypatch):
    """Nothing readable — every probe must report n/a, not failure."""
    root = tmp_path / "empty"
    os.makedirs(root, exist_ok=True)
    _point_module_at(monkeypatch, root)
    monkeypatch.setattr(hardening, "_af_inet_supported", lambda: None)
    return root


def _by_key(results):
    return {r.key: r for r in results}


# --------------------------------------------------------------------------
# Hardened
# --------------------------------------------------------------------------

def test_hardened_tree_passes_all_critical_checks(hardened):
    results = hardening.run_checks()
    criticals = [r for r in results if r.severity == hardening.SEVERITY_CRITICAL]
    assert criticals, "expected some CRITICAL checks"
    failures = [r.key for r in criticals if r.failed]
    assert failures == [], f"unexpected failures: {failures}"
    assert hardening.is_hardened(results) is True
    assert hardening.open_exposures(results) == []


def test_hardened_tree_info_checks(hardened):
    checks = _by_key(hardening.run_checks())
    assert checks["panic_reboot"].state == hardening.STATE_PASS
    assert checks["logging"].state == hardening.STATE_PASS
    assert checks["dev_tools"].state == hardening.STATE_PASS
    # ro root counts as non-persistent-enough
    assert checks["rootfs"].state == hardening.STATE_PASS


def test_camera_module_is_not_mistaken_for_wifi(hardened):
    """The oem module dir legitimately holds camera drivers; only wireless
    drivers should trip the wifi check."""
    assert _by_key(hardening.run_checks())["wifi_modules"].state == hardening.STATE_PASS


# --------------------------------------------------------------------------
# Wide open
# --------------------------------------------------------------------------

def test_open_tree_fails_expected_critical_checks(wide_open):
    checks = _by_key(hardening.run_checks())
    for key in ("ip_stack", "net_ifaces", "wireless", "wifi_modules",
                "usb_gadget", "serial_console", "remote_shells"):
        assert checks[key].state == hardening.STATE_FAIL, f"{key} should have failed"


def test_open_tree_is_not_hardened_and_names_exposures(wide_open):
    results = hardening.run_checks()
    assert hardening.is_hardened(results) is False
    exposures = hardening.open_exposures(results)
    # De-duplicated: ip_stack and net_ifaces both map to "network"
    assert exposures.count("network") == 1
    assert exposures.count("WiFi") == 1
    for expected in ("network", "WiFi", "USB-ADB", "serial", "remote shell"):
        assert expected in exposures, f"missing exposure: {expected}"


def test_open_tree_rootfs_writable_and_persistent(wide_open):
    check = _by_key(hardening.run_checks())["rootfs"]
    assert check.state == hardening.STATE_FAIL
    # INFO, so it must NOT by itself make the device "unhardened"
    assert check.severity == hardening.SEVERITY_INFO


# --------------------------------------------------------------------------
# Indeterminate — the false-alarm guard
# --------------------------------------------------------------------------

def test_indeterminate_tree_reports_na_not_failure(indeterminate):
    results = hardening.run_checks()
    assert all(not r.failed for r in results), \
        f"n/a must never be a failure: {[r.key for r in results if r.failed]}"
    assert hardening.is_hardened(results) is True
    assert hardening.open_exposures(results) == []


def test_probe_exception_becomes_na(monkeypatch, indeterminate):
    def boom():
        raise RuntimeError("probe blew up")

    monkeypatch.setattr(hardening, "ALL_CHECKS", (boom,))
    results = hardening.run_checks()
    assert len(results) == 1
    assert results[0].state == hardening.STATE_NA
    assert hardening.is_hardened(results) is True


# --------------------------------------------------------------------------
# Non-persistent rootfs: the control keeps root WRITABLE, so a naive "is it ro?"
# probe would report failure on a correctly hardened image.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("mountinfo, mounts, expected", [
    # overlay whose upper layer is in RAM -> writable but volatile: PASS.
    # Real mountinfo carries lowerdir/upperdir/workdir in the SUPER options,
    # i.e. after the " - <fstype> <source> " separator.
    ("1 0 0:1 / / rw,relatime - overlay overlay rw,lowerdir=/lower,upperdir=/tmp/up,workdir=/tmp/wk\n",
     "tmpfs /tmp tmpfs rw 0 0\n", hardening.STATE_PASS),
    # overlay whose upper layer is on flash -> writes persist: FAIL
    ("1 0 0:1 / / rw,relatime - overlay overlay rw,lowerdir=/lower,upperdir=/data/up,workdir=/data/wk\n",
     "ubi0:data /data ubifs rw 0 0\n", hardening.STATE_FAIL),
    # same, but upperdir appears in the optional-fields position instead
    ("1 0 0:1 / / rw,relatime upperdir=/tmp/up - overlay overlay rw\n",
     "tmpfs /tmp tmpfs rw 0 0\n", hardening.STATE_PASS),
    # whole root in RAM: PASS
    ("1 0 0:1 / / rw,relatime - tmpfs tmpfs rw\n", "", hardening.STATE_PASS),
    # genuinely read-only: PASS
    ("1 0 0:1 / / ro,relatime - ubifs ubi0:rootfs ro\n", "", hardening.STATE_PASS),
    # plain writable flash: FAIL
    ("1 0 0:1 / / rw,relatime - ubifs ubi0:rootfs rw\n", "", hardening.STATE_FAIL),
    # overlay with an upper layer we cannot place: n/a, not a guess
    ("1 0 0:1 / / rw,relatime upperdir=/mystery/up - overlay overlay rw\n",
     "", hardening.STATE_NA),
])
def test_rootfs_persistence_detection(tmp_path, monkeypatch, mountinfo, mounts, expected):
    root = tmp_path / "rootfs-case"
    _write(root / "proc/self/mountinfo", mountinfo)
    _write(root / "proc/mounts", mounts)
    _point_module_at(monkeypatch, root)
    assert hardening.check_rootfs_non_persistent().state == expected


def test_rootfs_falls_back_to_proc_mounts(tmp_path, monkeypatch):
    """mountinfo is preferred, but /proc/mounts alone must still work."""
    root = tmp_path / "fallback"
    _write(root / "proc/mounts", "ubi0:rootfs / ubifs rw,relatime 0 0\n")
    _point_module_at(monkeypatch, root)
    assert hardening.check_rootfs_non_persistent().state == hardening.STATE_FAIL


# --------------------------------------------------------------------------
# Individual probe details
# --------------------------------------------------------------------------

def test_ttynull_console_counts_as_silenced(tmp_path, monkeypatch):
    """console=ttynull is how the console is routed to a null sink; it is a
    hardening measure, not an exposure."""
    root = tmp_path / "ttynull"
    _write(root / "proc/cmdline", "root=/dev/mmcblk0p2 console=ttynull panic=5\n")
    _point_module_at(monkeypatch, root)
    assert hardening.check_serial_console().state == hardening.STATE_PASS


def test_dev_tools_detected_on_path(tmp_path, monkeypatch):
    root = tmp_path / "tools"
    bindir = root / "bin"
    os.makedirs(bindir, exist_ok=True)
    tool = bindir / "curl"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    _point_module_at(monkeypatch, root, empty_path=False)
    monkeypatch.setenv("PATH", str(bindir))
    check = hardening.check_dev_tools()
    # On platforms where the exec bit is not honoured, which() may miss it;
    # only assert the failure path when the tool is actually discoverable.
    import shutil as _shutil
    if _shutil.which("curl"):
        assert check.state == hardening.STATE_FAIL
        assert "curl" in check.detail
