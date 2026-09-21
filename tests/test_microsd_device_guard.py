# pylint: disable=missing-function-docstring
import os
import pathlib
from types import SimpleNamespace

import pytest

# Must import base before any seedsigner modules
from base import BaseTest

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


def patch_environment(monkeypatch, commands, on_seedsigner_os=True, dd_returncode=0):
    """Make a MicroSD View runnable headlessly and record the commands it runs."""
    hostname = "seedsigner-os" if on_seedsigner_os else "testhost"
    monkeypatch.setattr(
        "platform.uname", lambda: ("Linux", hostname, "", "", "", "")
    )
    monkeypatch.setattr(microsd_views, "LoadingScreenThread", DummyLoadingScreenThread)
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
    def test_wipe_finds_a_card_inserted_after_the_prompt(self, monkeypatch, view_cls):
        commands = []
        patch_environment(monkeypatch, commands)

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

    def test_flash_finds_a_card_inserted_after_the_prompt(self, monkeypatch):
        commands = []
        patch_environment(monkeypatch, commands)

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

    def test_a_present_card_is_flashed(self, monkeypatch):
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=False)
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)

        view, screens = build_view(monkeypatch, microsd_views.ToolsMicroSDFlashView)

        destination = view.run()

        assert_dd_targets(commands, SD_DEV)
        assert destination.View_cls is MainMenuView


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
