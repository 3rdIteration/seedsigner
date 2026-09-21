# pylint: disable=missing-function-docstring
import errno
import itertools
import os
import pathlib
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

# Must import base before any seedsigner modules
from base import BaseTest

from seedsigner.models.settings import Settings
from seedsigner.views import microsd_views
from seedsigner.views.view import MainMenuView


SD_DEV = "/dev/mmcblk0"

# dd reports its progress on stderr; matching in/out counts mean success.
DD_OK = "64+0 records in\n64+0 records out\n"


class RecordingScreens:
    """Answers every run_screen() call and records the screens a View showed."""

    def __init__(self):
        self.calls = []

    def __call__(self, screen_cls, **kwargs):
        self.calls.append(kwargs)
        return 0  # always pick the first button

    @property
    def titles(self):
        return [call.get("title") for call in self.calls]

    @property
    def texts(self):
        # A screen's wording can arrive as either kwarg, e.g. the verify view
        # passes "Matched Checksum" as status_headline and the checksum as text.
        return [
            text
            for call in self.calls
            for text in (call.get("text"), call.get("status_headline"))
        ]

    def showed(self, needle: str) -> bool:
        return any(needle in (text or "") for text in self.texts)


class DummyLoadingScreenThread:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        pass

    def stop(self):
        pass


def patch_environment(monkeypatch, commands, on_seedsigner_os=True, dd_returncode=0,
                      cp_returncode=0):
    """Make a MicroSD View runnable headlessly and record the commands it runs."""
    hostname = "seedsigner-os" if on_seedsigner_os else "testhost"
    monkeypatch.setattr(
        "platform.uname", lambda: ("Linux", hostname, "", "", "", "")
    )
    monkeypatch.setattr(microsd_views, "LoadingScreenThread", DummyLoadingScreenThread)
    # The views ask the OS marker, not the hostname.
    monkeypatch.setattr(Settings, "is_seedsigner_os",
                        classmethod(lambda cls: on_seedsigner_os))
    # The kernel says nothing about the card unless a test sets it up with
    # fake_kernel(), and a card nobody can describe is never written.
    monkeypatch.setattr(microsd_views, "PROC_MOUNTINFO", os.devnull)
    monkeypatch.setattr(microsd_views, "SYS_BLOCK", os.devnull)
    # Flash Image resolves where its images live; keep that off the host's disk.
    monkeypatch.setattr(microsd_views, "flash_images_dir",
                        lambda: pathlib.Path("/test/microsd-images"))

    real_listdir = os.listdir

    def fake_listdir(path):
        if "microsd-images" in str(path):
            return ["seedsigner_os.img"]
        return real_listdir(path)

    monkeypatch.setattr(os, "listdir", fake_listdir)

    def fake_run(cmd, *args, **kwargs):
        commands.append(cmd)
        if cmd[0] == "cp":
            # `cp` output is checked for errors; anything on stderr aborts a flash.
            if cp_returncode != 0:
                return SimpleNamespace(
                    stdout="", stderr=f"cp: can't stat '{cmd[1]}': No such file or directory\n",
                    returncode=cp_returncode,
                )
            return SimpleNamespace(stdout="", stderr="", returncode=0)
        if cmd[0] == "sha256sum":
            return SimpleNamespace(stdout="0" * 64 + "  /tmp/img.img\n", stderr="", returncode=0)
        if dd_returncode != 0 and "dd" in cmd:
            return SimpleNamespace(
                stdout="", stderr="dd: /dev/mmcblk0: Input/output error\n",
                returncode=dd_returncode,
            )
        return SimpleNamespace(stdout="", stderr=DD_OK, returncode=0)

    monkeypatch.setattr("subprocess.run", fake_run)


# The device numbers the fake kernel gives the block devices tests mount by
# name. Any other source is a virtual filesystem, with a number of its own.
DEVNUMS = {
    SD_DEV: "179:0",
    f"{SD_DEV}p1": "179:1",
    f"{SD_DEV}p2": "179:2",
    "/dev/mmcblk1p1": "179:33",
    "/dev/sda2": "8:2",
    "/dev/dm-0": "254:0",
    "/dev/loop0": "7:0",
    "/dev/loop1": "7:1",
    "/dev/loop2": "7:2",
}

# A regular file standing where a device node should be
FILE = "file"


def fake_kernel(monkeypatch, tmp_path, mounts, loops=None, aliases=None, holders=None,
                claimed=(), nodes=None):
    """
    Point the views at a mountinfo and a /sys/block made up under tmp_path.

    mounts are /proc/mounts lines, oldest first. Each gets the device number
    of its source, or of the device aliases names for it: the kernel calls a
    root it mounted itself /dev/root, whatever it is on. SD_DEV has two
    partitions. loops maps loopN to the file it reads, or to None when sysfs
    will not say; holders maps a device on the card to those built on it.

    The kernel holds a device on the card while a mount of it is up, and holds
    the devices in claimed whatever comes off: swap, a filesystem no mount
    here shows, one an overlay keeps a copy of. Opening a held device for
    exclusive use, or the whole card while a partition of it is held, fails
    with EBUSY.

    /dev has a node for the card and for each partition, under the number
    sysfs gives it. nodes changes what stands at a path: a block device with
    another number, FILE, or None for nothing at all. The exclusive-open
    check runs as written, against that /dev.
    """
    devnums = dict(DEVNUMS)
    for alias, device in (aliases or {}).items():
        devnums[alias] = DEVNUMS[device]

    def covers(mountpoint, path):
        return path == mountpoint or path.startswith(mountpoint.rstrip("/") + "/")

    lines = []
    for i, mount in enumerate(mounts):
        source, mountpoint, fstype, options = mount.split()[:4]
        # Made on whichever earlier mount was on top at its path
        parent = next(
            (j for j in reversed(range(i)) if covers(mounts[j].split()[1], mountpoint)),
            -1,
        )
        devnum = devnums.get(source, f"0:{40 + i}")
        lines.append(
            f"{20 + i} {20 + parent} {devnum} / {mountpoint} rw shared:1"
            f" - {fstype} {source} {options}\n"
        )
    (tmp_path / "mountinfo").write_text("".join(lines))

    sys_block = tmp_path / "block"
    card = SD_DEV.rsplit("/", 1)[-1]
    blocks = {SD_DEV: sys_block / card}
    for n in (1, 2):
        blocks[f"{SD_DEV}p{n}"] = sys_block / card / f"{card}p{n}"
    for device, block in blocks.items():
        (block / "holders").mkdir(parents=True)
        (block / "dev").write_text(DEVNUMS[device] + "\n")
        for holder in (holders or {}).get(device, []):
            (block / "holders" / holder).touch()
    for loop, backing_file in (loops or {}).items():
        (sys_block / loop / "loop").mkdir(parents=True)
        (sys_block / loop / "dev").write_text(DEVNUMS[f"/dev/{loop}"] + "\n")
        if backing_file is not None:
            (sys_block / loop / "loop" / "backing_file").write_text(backing_file + "\n")

    monkeypatch.setattr(microsd_views, "PROC_MOUNTINFO", str(tmp_path / "mountinfo"))
    monkeypatch.setattr(microsd_views, "SYS_BLOCK", str(sys_block))

    # Every mount that is up, as (mountpoint, the device on the card it holds
    # or None), with the top one at each path last.
    card_devices = {DEVNUMS[device]: device for device in blocks}
    up = [
        (mount.split()[1].replace("\\040", " "),
         card_devices.get(devnums.get(mount.split()[0])))
        for mount in mounts
    ]
    dev = {device: DEVNUMS[device] for device in blocks}
    dev.update(nodes or {})
    run = subprocess.run

    def exclusive_open(script, argv):
        """Run script the way `python -c script *argv` would, on the fake /dev."""
        held = [device for _, device in up if device] + list(claimed)
        opened = {}
        fds = itertools.count(1 << 20)
        real_open, real_fstat, real_close = os.open, os.fstat, os.close

        def fake_open(path, flags, *args, **kwargs):
            if not str(path).startswith(SD_DEV):
                return real_open(path, flags, *args, **kwargs)
            node = dev.get(path)
            if node is None:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
            # O_EXCL without O_CREAT claims a block device, and anything else
            # opens as if it had not been asked for.
            if node != FILE and flags & os.O_EXCL and any(
                path == other or SD_DEV in (path, other) for other in held
            ):
                raise OSError(errno.EBUSY, os.strerror(errno.EBUSY), path)
            fd = next(fds)
            opened[fd] = node
            return fd

        def fake_fstat(fd, *args, **kwargs):
            if fd not in opened:
                return real_fstat(fd, *args, **kwargs)
            if opened[fd] == FILE:
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_rdev=0)
            major, minor = map(int, opened[fd].split(":"))
            return SimpleNamespace(st_mode=stat.S_IFBLK | 0o660,
                                   st_rdev=os.makedev(major, minor))

        def fake_close(fd):
            if opened.pop(fd, None) is None:
                real_close(fd)

        with monkeypatch.context() as patched:
            patched.setattr(os, "open", fake_open)
            patched.setattr(os, "fstat", fake_fstat)
            patched.setattr(os, "close", fake_close)
            patched.setattr(sys, "argv", ["-c", *argv])
            try:
                exec(script, {"__name__": "__main__"})  # pylint: disable=exec-used
            except SystemExit as e:
                if e.code not in (None, 0):
                    return SimpleNamespace(stdout="", stderr=f"{e.code}\n", returncode=1)
            except Exception as e:  # pylint: disable=broad-except
                return SimpleNamespace(stdout="", stderr=f"{type(e).__name__}: {e}\n",
                                       returncode=1)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    def kernel_run(cmd, *args, **kwargs):
        result = run(cmd, *args, **kwargs)
        if "umount" in cmd:
            # umount takes off the top mount at a path
            del up[max(i for i, (mountpoint, _) in enumerate(up) if mountpoint == cmd[-1])]
        elif "-c" in cmd and "O_EXCL" in cmd[cmd.index("-c") + 1]:
            return exclusive_open(cmd[cmd.index("-c") + 1], cmd[cmd.index("-c") + 2:])
        return result

    monkeypatch.setattr("subprocess.run", kernel_run)


def build_view(monkeypatch, view_cls):
    view = view_cls()
    screens = RecordingScreens()
    monkeypatch.setattr(view, "run_screen", screens, raising=False)
    return view, screens


def assert_no_dd(commands):
    """Nothing may read or write a device: no dd at all, and never `of=None`."""
    for cmd in commands:
        assert "dd" not in cmd, cmd
        assert not any("None" in part for part in cmd), cmd


def assert_dd_targets(commands, device):
    """Every dd must name the device that was detected, and nothing else."""
    dd_cmds = [cmd for cmd in commands if "dd" in cmd]
    assert dd_cmds, commands
    for cmd in dd_cmds:
        assert any(part.endswith(device) for part in cmd), cmd
        assert not any("None" in part for part in cmd), cmd


class TestNoCardMeansNoCommand(BaseTest):
    """No inserted card must mean no dd and no claim of success."""

    @pytest.mark.parametrize(
        "view_cls,success_text",
        [
            (microsd_views.ToolsMicroSDWipeZeroView, "MicroSD Wiped"),
            (microsd_views.ToolsMicroSDWipeRandomView, "MicroSD Wiped"),
            (microsd_views.ToolsMicroSDFlashView, "MicroSD Flashed"),
            (microsd_views.ToolsMicroSDVerifyView, "Matched Checksum"),
        ],
    )
    def test_no_card_is_refused(self, monkeypatch, view_cls, success_text):
        commands = []
        patch_environment(monkeypatch, commands)
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: None)

        view, screens = build_view(monkeypatch, view_cls)

        destination = view.run()

        # Staging the image in /tmp is allowed; touching a device is not.
        assert_no_dd(commands)
        assert not screens.showed(success_text)
        assert screens.showed("No MicroSD")
        assert destination.View_cls is MainMenuView


class TestCardInsertedAtThePrompt(BaseTest):
    """The card is detected at the point of use, i.e. after the insert prompt."""

    @pytest.mark.parametrize(
        "view_cls",
        [
            microsd_views.ToolsMicroSDWipeZeroView,
            microsd_views.ToolsMicroSDWipeRandomView,
        ],
    )
    def test_wipe_finds_a_card_inserted_after_the_prompt(self, monkeypatch, tmp_path, view_cls):
        commands = []
        patch_environment(monkeypatch, commands)
        fake_kernel(monkeypatch, tmp_path, mounts=[])

        view, screens = build_view(monkeypatch, view_cls)
        # The user only inserts the card once the View has asked for it.
        monkeypatch.setattr(
            microsd_views,
            "find_sd_card_device",
            lambda: SD_DEV if screens.showed("Insert MicroSD") else None,
        )

        destination = view.run()

        assert_dd_targets(commands, SD_DEV)
        assert screens.showed("MicroSD Wiped")
        assert destination.View_cls is MainMenuView

    def test_flash_finds_a_card_inserted_after_the_prompt(self, monkeypatch, tmp_path):
        commands = []
        patch_environment(monkeypatch, commands)
        fake_kernel(monkeypatch, tmp_path, mounts=[])

        view, screens = build_view(monkeypatch, microsd_views.ToolsMicroSDFlashView)
        monkeypatch.setattr(
            microsd_views,
            "find_sd_card_device",
            lambda: SD_DEV if screens.showed("Insert MicroSD") else None,
        )

        destination = view.run()

        assert_dd_targets(commands, SD_DEV)
        assert screens.showed("MicroSD Flashed")
        assert destination.View_cls is microsd_views.ToolsMicroSDVerifyView


class TestFlashOnADevHost(BaseTest):
    """The non-seedsigner-os flash branch has its own dd, so its own guard."""

    def test_no_card_is_refused(self, monkeypatch):
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=False)
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: None)

        view, screens = build_view(monkeypatch, microsd_views.ToolsMicroSDFlashView)

        destination = view.run()

        assert_no_dd(commands)
        assert screens.showed("No MicroSD")
        assert destination.View_cls is MainMenuView

    def test_a_present_card_is_flashed(self, monkeypatch, tmp_path):
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=False)
        fake_kernel(monkeypatch, tmp_path, mounts=[])
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)

        view, screens = build_view(monkeypatch, microsd_views.ToolsMicroSDFlashView)

        destination = view.run()

        assert_dd_targets(commands, SD_DEV)
        assert screens.showed("MicroSD Flashed")
        assert destination.View_cls is MainMenuView

    def test_a_failed_flash_is_reported(self, monkeypatch, tmp_path):
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=False, dd_returncode=1)
        fake_kernel(monkeypatch, tmp_path, mounts=[])
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)

        view, screens = build_view(monkeypatch, microsd_views.ToolsMicroSDFlashView)

        destination = view.run()

        assert not screens.showed("MicroSD Flashed")
        assert screens.showed("Input/output error")
        assert destination.View_cls is MainMenuView

    @pytest.mark.parametrize("on_seedsigner_os", [True, False])
    def test_a_failed_copy_writes_nothing(self, monkeypatch, tmp_path, on_seedsigner_os):
        # /tmp/img.img still holds whatever an earlier flash or Verify left
        # there, and dd would write that to the card instead.
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=on_seedsigner_os,
                          cp_returncode=1)
        fake_kernel(monkeypatch, tmp_path, mounts=[])
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)

        view, screens = build_view(monkeypatch, microsd_views.ToolsMicroSDFlashView)

        destination = view.run()

        assert_no_dd(commands)
        assert not screens.showed("MicroSD Flashed")
        assert destination.View_cls is MainMenuView


def fail_dd(monkeypatch, commands, which, stderr):
    """Make each dd which(cmd) picks exit 1 with stderr; the rest run as before."""
    run = subprocess.run

    def failing_run(cmd, *args, **kwargs):
        if "dd" in cmd and which(cmd):
            commands.append(cmd)
            return SimpleNamespace(stdout="", stderr=stderr, returncode=1)
        return run(cmd, *args, **kwargs)

    monkeypatch.setattr("subprocess.run", failing_run)


# GNU dd when closing the card fails: every record went out, and it failed.
DD_CLOSE_FAILED = (
    f"dd: closing output file '{SD_DEV}': Input/output error\n" + DD_OK
)


# GNU dd on a host with a German locale: the same success, in other words.
DD_OK_GERMAN = "64+0 Datensätze ein\n64+0 Datensätze aus\n"


def localized_dd(monkeypatch):
    """Make every dd report in German unless it runs with LC_ALL=C."""
    run = subprocess.run

    def localized_run(cmd, *args, **kwargs):
        data = run(cmd, *args, **kwargs)
        if "dd" in cmd and (kwargs.get("env") or {}).get("LC_ALL") != "C":
            return SimpleNamespace(stdout=data.stdout, stderr=DD_OK_GERMAN, returncode=data.returncode)
        return data

    monkeypatch.setattr("subprocess.run", localized_run)


class TestEveryStepIsChecked(BaseTest):
    """
    A flash or wipe succeeded only if every dd in it did. The zero pass that
    starts a SeedSigner OS flash was never looked at, and the rest went by
    dd's record counts alone.
    """

    def run_view(self, monkeypatch, tmp_path, view_cls, which, stderr, on_seedsigner_os=True):
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=on_seedsigner_os)
        fake_kernel(monkeypatch, tmp_path, mounts=[])
        fail_dd(monkeypatch, commands, which, stderr)
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)
        view, screens = build_view(monkeypatch, view_cls)
        return view.run(), screens, commands

    def test_a_failed_zero_pass_stops_the_flash(self, monkeypatch, tmp_path):
        destination, screens, commands = self.run_view(
            monkeypatch, tmp_path, microsd_views.ToolsMicroSDFlashView,
            which=lambda cmd: "if=/dev/zero" in cmd,
            stderr=f"dd: error writing '{SD_DEV}': Input/output error\n3+0 records in\n2+0 records out\n",
        )

        assert not any("if=/tmp/img.img" in cmd for cmd in commands), commands
        assert not screens.showed("MicroSD Flashed")
        assert screens.showed("Input/output error")
        assert destination.View_cls is MainMenuView

    @pytest.mark.parametrize("on_seedsigner_os", [True, False])
    def test_a_flash_whose_dd_failed_is_not_flashed(self, monkeypatch, tmp_path, on_seedsigner_os):
        destination, screens, _ = self.run_view(
            monkeypatch, tmp_path, microsd_views.ToolsMicroSDFlashView,
            which=lambda cmd: "if=/tmp/img.img" in cmd, stderr=DD_CLOSE_FAILED,
            on_seedsigner_os=on_seedsigner_os,
        )

        assert not screens.showed("MicroSD Flashed")
        assert screens.showed("Input/output error")
        assert destination.View_cls is MainMenuView

    @pytest.mark.parametrize("on_seedsigner_os", [True, False])
    @pytest.mark.parametrize(
        "view_cls",
        [microsd_views.ToolsMicroSDWipeZeroView, microsd_views.ToolsMicroSDWipeRandomView],
    )
    def test_a_wipe_whose_dd_failed_is_not_wiped(self, monkeypatch, tmp_path, view_cls, on_seedsigner_os):
        destination, screens, _ = self.run_view(
            monkeypatch, tmp_path, view_cls,
            which=lambda cmd: True, stderr=DD_CLOSE_FAILED, on_seedsigner_os=on_seedsigner_os,
        )

        assert not screens.showed("MicroSD Wiped")
        assert screens.showed("Input/output error")
        assert destination.View_cls is MainMenuView

    @pytest.mark.parametrize(
        "view_cls",
        [microsd_views.ToolsMicroSDWipeZeroView, microsd_views.ToolsMicroSDWipeRandomView],
    )
    def test_a_wipe_that_fills_the_card_is_wiped(self, monkeypatch, tmp_path, view_cls):
        # Writing until the card is full ends the only way it can: dd fails
        # with no space left.
        _, screens, _ = self.run_view(
            monkeypatch, tmp_path, view_cls, which=lambda cmd: True,
            stderr=f"dd: error writing '{SD_DEV}': No space left on device\n"
                   "15193+0 records in\n15192+1 records out\n",
        )

        assert screens.showed("MicroSD Wiped")


    @pytest.mark.parametrize("view_cls, on_seedsigner_os, done", [
        (microsd_views.ToolsMicroSDFlashView, True, "MicroSD Flashed"),
        (microsd_views.ToolsMicroSDFlashView, False, "MicroSD Flashed"),
        (microsd_views.ToolsMicroSDWipeZeroView, True, "MicroSD Wiped"),
        (microsd_views.ToolsMicroSDWipeRandomView, True, "MicroSD Wiped"),
    ])
    def test_dd_is_read_whatever_the_locale(self, monkeypatch, tmp_path, view_cls, on_seedsigner_os, done):
        # GNU dd translates its report, and sudo keeps the caller's locale:
        # read in any other language, a good write looked like a failed one.
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=on_seedsigner_os)
        fake_kernel(monkeypatch, tmp_path, mounts=[])
        localized_dd(monkeypatch)
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)
        view, screens = build_view(monkeypatch, view_cls)

        view.run()

        assert screens.showed(done)


class TestBlankCardIsStillACard(BaseTest):
    """A card with no partition table is in the slot; the tool zeroed it itself."""

    def fake_sysfs(self, layout):
        real_listdir = os.listdir

        def listdir(path):
            # Only sysfs is faked: other threads keep reading real directories
            # while this test runs, and they must not see this layout.
            if path == "/sys/block":
                return list(layout)
            device = str(path).rsplit("/", 1)[-1]
            if str(path).startswith("/sys/block/") and device in layout:
                return layout[device]
            return real_listdir(path)

        return listdir

    @pytest.mark.parametrize(
        "layout,expected",
        [
            ({"mmcblk0": ["mmcblk0p1", "size"]}, "/dev/mmcblk0"),
            # Freshly zero-wiped or brand-new: present, but no partition table
            ({"mmcblk0": ["size", "removable"]}, "/dev/mmcblk0"),
            ({}, None),
            ({"sda": ["sda1"]}, None),
        ],
    )
    def test_detection(self, monkeypatch, layout, expected):
        monkeypatch.setattr(os, "listdir", self.fake_sysfs(layout))
        # These are all SD cards; telling one from eMMC is covered separately.
        monkeypatch.setattr(microsd_views, "_mmc_device_type", lambda d: "SD")

        assert microsd_views.find_sd_card_device() == expected

    def test_a_partitioned_card_wins_over_a_blank_one(self, monkeypatch):
        layout = {"mmcblk0": ["size"], "mmcblk1": ["mmcblk1p1", "size"]}
        monkeypatch.setattr(os, "listdir", self.fake_sysfs(layout))
        monkeypatch.setattr(microsd_views, "_mmc_device_type", lambda d: "SD")

        assert microsd_views.find_sd_card_device() == "/dev/mmcblk1"


class TestVerifyReportsAFailedRead(BaseTest):
    """A checksum is only meaningful if dd actually read the card."""

    def test_failed_dd_is_not_reported_as_a_checksum(self, monkeypatch):
        commands = []
        patch_environment(monkeypatch, commands, dd_returncode=1)
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)

        view, screens = build_view(monkeypatch, microsd_views.ToolsMicroSDVerifyView)

        destination = view.run()

        assert not screens.showed("Matched Checksum")
        assert not screens.showed("Unfamilliar Checksum")
        assert screens.showed("Could not read")
        assert destination.View_cls is MainMenuView
