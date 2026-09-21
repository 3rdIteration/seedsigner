"""Nothing is written to the card while a filesystem on it is still mounted."""
# Must import base before any seedsigner modules
from base import BaseTest

import os
import shutil
import subprocess
import sys

import pytest

from seedsigner.views import microsd_views

from test_microsd_device_guard import (
    DEVNUMS, FILE, SD_DEV, build_view, fake_kernel, patch_environment,
)


# What SeedSigner OS has mounted once mdev has seen a card go in: the card
# itself, and diy-tools.squashfs from the card on a loop device.
SEEDSIGNER_OS_MOUNTS = [
    "rootfs / rootfs rw 0 0",
    "proc /proc proc rw,relatime 0 0",
    f"{SD_DEV}p1 /mnt/microsd vfat rw,sync,relatime 0 0",
    "/dev/loop0 /mnt/diy squashfs ro,relatime 0 0",
]
SEEDSIGNER_OS_LOOPS = {"loop0": "/mnt/microsd/diy-tools.squashfs"}

# Raspberry Pi OS booted with no initramfs: the kernel mounts the root itself
# and lists it as /dev/root, whatever it is on -- here, the card.
DEV_ROOT_MOUNTS = [
    "/dev/root / ext4 rw,noatime 0 0",
    "devtmpfs /dev devtmpfs rw 0 0",
    "proc /proc proc rw 0 0",
    f"{SD_DEV}p1 /boot vfat rw 0 0",
]
DEV_ROOT_ON_THE_CARD = {"/dev/root": f"{SD_DEV}p2"}

# Raspberry Pi OS with raspi-config's overlay file system, as the overlayroot
# package sets it up: "/" is an overlay whose lower layer is the card's root
# partition, mounted read-only at /media/root-ro. The overlay keeps a copy of
# that mount of its own, so the partition stays in use after an umount of it.
OVERLAYROOT_MOUNTS = [
    "overlayroot / overlay rw,relatime,lowerdir=/media/root-ro,"
    "upperdir=/media/root-rw/overlay,workdir=/media/root-rw/overlay-workdir 0 0",
    "proc /proc proc rw 0 0",
    f"{SD_DEV}p2 /media/root-ro ext4 ro 0 0",
    "tmpfs-root /media/root-rw tmpfs rw 0 0",
    f"{SD_DEV}p1 /boot/firmware vfat rw 0 0",
]

# The same overlay made by an initramfs script: its lower layer was mounted at
# /lower before the root was switched, so no mount here shows it.
INITRAMFS_OVERLAY_MOUNTS = [
    "overlay / overlay rw,lowerdir=/lower,upperdir=/upper/data,workdir=/upper/work 0 0",
    "devtmpfs /dev devtmpfs rw 0 0",
    "proc /proc proc rw 0 0",
    f"{SD_DEV}p1 /boot/firmware vfat rw 0 0",
]

# A btrfs root the kernel mounted itself: listed as /dev/root, and under a
# device number btrfs made up rather than the partition's.
BTRFS_ROOT_MOUNTS = [
    "/dev/root / btrfs rw 0 0",
    "devtmpfs /dev devtmpfs rw 0 0",
    "proc /proc proc rw 0 0",
    f"{SD_DEV}p1 /boot/firmware vfat rw 0 0",
]

# Every way a Raspberry Pi OS host here runs from the card in its slot: the
# mounts, and what else the kernel says about the card.
RUNNING_FROM_THE_CARD = [
    pytest.param(DEV_ROOT_MOUNTS, {"aliases": DEV_ROOT_ON_THE_CARD}, id="dev-root"),
    pytest.param(OVERLAYROOT_MOUNTS, {"claimed": {f"{SD_DEV}p2"}}, id="overlayroot"),
    pytest.param(INITRAMFS_OVERLAY_MOUNTS, {"claimed": {f"{SD_DEV}p2"}}, id="initramfs-overlay"),
    pytest.param(BTRFS_ROOT_MOUNTS, {"claimed": {f"{SD_DEV}p2"}}, id="btrfs-root"),
]


def unmounted(commands):
    """The mountpoints umount was run on, in order."""
    return [cmd[-1] for cmd in commands if "umount" in cmd]


def writes(commands):
    """Indexes of the dd commands that write anywhere."""
    return [
        i for i, cmd in enumerate(commands)
        if "dd" in cmd and any(part.startswith("of=") for part in cmd)
    ]


class TestWhatHoldsTheCard(BaseTest):
    """
    A card's filesystem is held by more than its own mount. SeedSigner OS
    loop-mounts diy-tools.squashfs from the card at /mnt/diy, so unmounting
    /mnt/microsd alone either fails busy or leaves a live mount under dd.
    """

    def unmount(self, monkeypatch, tmp_path, mounts, loops=None, **kernel):
        commands = []
        patch_environment(monkeypatch, commands)
        fake_kernel(monkeypatch, tmp_path, mounts, loops, **kernel)
        return microsd_views.unmount_card(SD_DEV), commands

    def test_every_filesystem_on_the_card_and_nothing_else(self, monkeypatch, tmp_path):
        mounts = [
            "/dev/sda2 / ext4 rw 0 0",
            f"{SD_DEV}p1 /mnt/sdcard vfat rw 0 0",
            f"{SD_DEV}p2 /mnt/diy ext4 rw 0 0",
            "/dev/mmcblk1p1 /mnt/other vfat rw 0 0",
            f"{SD_DEV} /mnt/with\\040space vfat rw 0 0",
        ]

        ok, commands = self.unmount(monkeypatch, tmp_path, mounts)

        assert unmounted(commands) == [
            "/mnt/sdcard", "/mnt/diy", "/mnt/with space",
        ], commands
        assert ok

    def test_a_card_mounted_under_another_name_is_unmounted(self, monkeypatch, tmp_path):
        # A mount is listed under whatever name it was made by; only its device
        # number says which device it is.
        mounts = [
            "/dev/sda2 / ext4 rw 0 0",
            "/dev/disk/by-label/SEEDSIGNER /mnt/microsd vfat rw 0 0",
        ]

        ok, commands = self.unmount(monkeypatch, tmp_path, mounts,
                                    aliases={"/dev/disk/by-label/SEEDSIGNER": f"{SD_DEV}p1"})

        assert unmounted(commands) == ["/mnt/microsd"], commands
        assert ok

    def test_the_diy_tools_loop_mount_goes_before_the_card(self, monkeypatch, tmp_path):
        ok, commands = self.unmount(monkeypatch, tmp_path,
                                    SEEDSIGNER_OS_MOUNTS, SEEDSIGNER_OS_LOOPS)

        assert unmounted(commands) == ["/mnt/diy", "/mnt/microsd"], commands
        assert ok

    def test_the_loop_device_is_released_with_its_mount(self, monkeypatch, tmp_path):
        # A loop device left bound keeps the squashfs open, and with it the
        # card's filesystem busy.
        ok, commands = self.unmount(monkeypatch, tmp_path,
                                    SEEDSIGNER_OS_MOUNTS, SEEDSIGNER_OS_LOOPS)

        assert ["umount", "-d", "/mnt/diy"] in [cmd[-3:] for cmd in commands], commands
        assert ok

    def test_a_loop_mount_of_a_file_elsewhere_is_left_alone(self, monkeypatch, tmp_path):
        mounts = SEEDSIGNER_OS_MOUNTS + ["/dev/loop1 /mnt/old squashfs ro 0 0"]
        # Shares a prefix with /mnt/microsd, but is not on the card.
        loops = dict(SEEDSIGNER_OS_LOOPS, loop1="/mnt/microsd-old/diy-tools.squashfs")

        ok, commands = self.unmount(monkeypatch, tmp_path, mounts, loops)

        assert "/mnt/old" not in unmounted(commands), commands
        assert ok

    def test_a_loop_of_the_card_device_itself_is_unmounted(self, monkeypatch, tmp_path):
        mounts = SEEDSIGNER_OS_MOUNTS + ["/dev/loop2 /mnt/raw ext4 rw 0 0"]
        loops = dict(SEEDSIGNER_OS_LOOPS, loop2=f"{SD_DEV}p2")

        ok, commands = self.unmount(monkeypatch, tmp_path, mounts, loops)

        assert "/mnt/raw" in unmounted(commands), commands
        assert ok

    def test_nested_mounts_go_first_deepest_first(self, monkeypatch, tmp_path):
        mounts = [
            f"{SD_DEV}p1 /mnt/microsd vfat rw 0 0",
            f"{SD_DEV}p2 /mnt/microsd/boot vfat rw 0 0",
            "tmpfs /mnt/microsd/boot/tmp tmpfs rw 0 0",
        ]

        ok, commands = self.unmount(monkeypatch, tmp_path, mounts)

        assert unmounted(commands) == [
            "/mnt/microsd/boot/tmp", "/mnt/microsd/boot", "/mnt/microsd",
        ], commands
        assert ok

    def test_a_mount_on_top_of_the_card_comes_off_first(self, monkeypatch, tmp_path):
        # umount takes off only the top mount on a path; once for the tmpfs
        # would leave the card mounted underneath.
        mounts = [
            f"{SD_DEV}p1 /mnt/microsd vfat rw 0 0",
            "tmpfs /mnt/microsd tmpfs rw 0 0",
        ]

        ok, commands = self.unmount(monkeypatch, tmp_path, mounts)

        assert unmounted(commands) == ["/mnt/microsd", "/mnt/microsd"], commands
        assert ok

    def test_a_card_holding_the_root_filesystem_is_refused_untouched(self, monkeypatch, tmp_path):
        # Everything is mounted under "/", so "everything on the card" would
        # be /proc, /dev and the rest of the running system.
        mounts = [
            f"{SD_DEV}p2 / ext4 rw 0 0",
            "proc /proc proc rw 0 0",
            f"{SD_DEV}p1 /boot/firmware vfat rw 0 0",
        ]

        ok, commands = self.unmount(monkeypatch, tmp_path, mounts)

        assert unmounted(commands) == [], commands
        assert not ok

    @pytest.mark.parametrize("mounts,kernel", RUNNING_FROM_THE_CARD)
    def test_a_root_on_the_card_by_any_route_is_refused_untouched(self, monkeypatch, tmp_path, mounts, kernel):
        # None of these has a mount of the card at "/" to go by.
        ok, commands = self.unmount(monkeypatch, tmp_path, mounts, **kernel)

        assert unmounted(commands) == [], commands
        assert not ok

    def test_a_partition_in_use_as_swap_is_refused_untouched(self, monkeypatch, tmp_path):
        # Swap is not a mount; only the kernel knows the partition is in use.
        mounts = [
            "/dev/sda2 / ext4 rw 0 0",
            f"{SD_DEV}p1 /mnt/microsd vfat rw 0 0",
        ]

        ok, commands = self.unmount(monkeypatch, tmp_path, mounts, claimed={f"{SD_DEV}p2"})

        assert unmounted(commands) == [], commands
        assert not ok

    def test_a_filesystem_that_outlives_its_umount_is_a_refusal(self, monkeypatch, tmp_path):
        # umount can succeed and leave the filesystem up: an overlay keeps its
        # own copy of each layer's mount, a mount namespace its own copy of
        # the tree.
        ok, commands = self.unmount(monkeypatch, tmp_path, SEEDSIGNER_OS_MOUNTS,
                                    SEEDSIGNER_OS_LOOPS, claimed={f"{SD_DEV}p1"})

        assert unmounted(commands) == ["/mnt/diy", "/mnt/microsd"], commands
        assert not ok

    def test_an_overlay_built_on_the_card_goes_before_it(self, monkeypatch, tmp_path):
        # The overlay holds the card's filesystem through its own copy of the
        # mount: umount of /mnt/microsd succeeds and the card stays in use.
        mounts = SEEDSIGNER_OS_MOUNTS + [
            "overlay /mnt/merged overlay rw,lowerdir=/usr/share:/mnt/microsd/layer,"
            "upperdir=/tmp/upper,workdir=/tmp/work 0 0",
            # Shares a prefix with /mnt/microsd, but is not on the card.
            "overlay /mnt/old overlay ro,lowerdir=/mnt/microsd-old/layer 0 0",
        ]

        ok, commands = self.unmount(monkeypatch, tmp_path, mounts, SEEDSIGNER_OS_LOOPS)

        assert unmounted(commands) == ["/mnt/diy", "/mnt/merged", "/mnt/microsd"], commands
        assert ok

    def test_a_card_another_device_is_built_on_is_refused(self, monkeypatch, tmp_path):
        # dm-crypt or LVM on a partition: what is mounted is dm-0, and no
        # umount frees the card underneath it.
        mounts = [
            "/dev/sda2 / ext4 rw 0 0",
            "/dev/dm-0 /mnt/vault ext4 rw 0 0",
        ]

        ok, commands = self.unmount(monkeypatch, tmp_path, mounts,
                                    holders={f"{SD_DEV}p2": ["dm-0"]})

        assert unmounted(commands) == [], commands
        assert not ok

    def test_an_unreadable_mount_table_is_a_refusal(self, monkeypatch, tmp_path):
        commands = []
        patch_environment(monkeypatch, commands)
        fake_kernel(monkeypatch, tmp_path, SEEDSIGNER_OS_MOUNTS, SEEDSIGNER_OS_LOOPS)
        monkeypatch.setattr(microsd_views, "PROC_MOUNTINFO", str(tmp_path / "missing"))

        assert microsd_views.unmount_card(SD_DEV) is False
        assert unmounted(commands) == [], commands

    def test_a_mount_table_that_does_not_parse_is_a_refusal(self, monkeypatch, tmp_path):
        # /proc/mounts where mountinfo was expected: no device numbers to go by.
        commands = []
        patch_environment(monkeypatch, commands)
        fake_kernel(monkeypatch, tmp_path, SEEDSIGNER_OS_MOUNTS, SEEDSIGNER_OS_LOOPS)
        (tmp_path / "mountinfo").write_text("".join(line + "\n" for line in SEEDSIGNER_OS_MOUNTS))

        assert microsd_views.unmount_card(SD_DEV) is False
        assert unmounted(commands) == [], commands

    def test_a_card_sysfs_does_not_describe_is_a_refusal(self, monkeypatch, tmp_path):
        # Pulled after it was detected: without its device numbers there is
        # no telling which mounts are on it.
        commands = []
        patch_environment(monkeypatch, commands)
        fake_kernel(monkeypatch, tmp_path, SEEDSIGNER_OS_MOUNTS, SEEDSIGNER_OS_LOOPS)
        shutil.rmtree(tmp_path / "block" / SD_DEV.rsplit("/", 1)[-1])

        assert microsd_views.unmount_card(SD_DEV) is False
        assert unmounted(commands) == [], commands

    def test_a_loop_that_will_not_say_what_it_reads_is_a_refusal(self, monkeypatch, tmp_path):
        # Its mount might be on the card; guessing no would write under it.
        ok, commands = self.unmount(monkeypatch, tmp_path, SEEDSIGNER_OS_MOUNTS,
                                    loops={"loop0": None})

        assert unmounted(commands) == [], commands
        assert not ok

    def test_a_regular_file_at_the_cards_path_is_refused(self, monkeypatch, tmp_path):
        # O_EXCL without O_CREAT claims only a block device, so a file there
        # opened for exclusive use without complaint, and dd would have
        # written to it.
        ok, _ = self.unmount(monkeypatch, tmp_path, SEEDSIGNER_OS_MOUNTS,
                             SEEDSIGNER_OS_LOOPS, nodes={SD_DEV: FILE})

        assert not ok

    def test_a_regular_file_at_a_partitions_path_is_refused_untouched(self, monkeypatch, tmp_path):
        # Opening it says nothing about whether the partition is in use.
        ok, commands = self.unmount(monkeypatch, tmp_path, SEEDSIGNER_OS_MOUNTS,
                                    SEEDSIGNER_OS_LOOPS, nodes={f"{SD_DEV}p2": FILE})

        assert unmounted(commands) == [], commands
        assert not ok

    def test_another_block_device_at_the_cards_path_is_refused(self, monkeypatch, tmp_path):
        # A block device, and free, but not the one sysfs calls the card.
        ok, _ = self.unmount(monkeypatch, tmp_path, SEEDSIGNER_OS_MOUNTS,
                             SEEDSIGNER_OS_LOOPS, nodes={SD_DEV: DEVNUMS["/dev/sda2"]})

        assert not ok


class TestTheExclusiveOpenChecksWhatItOpened(BaseTest):
    """EXCLUSIVE_OPEN as a real interpreter runs it, on files a test can make."""

    @staticmethod
    def exclusive_open(path):
        # Its own number, so that only the kind of file can be what refuses it
        st = os.stat(path)
        devnum = f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"
        return subprocess.run(
            [sys.executable, "-c", microsd_views.EXCLUSIVE_OPEN, str(path), devnum],
            capture_output=True, text=True, check=False,
        )

    def test_a_regular_file_is_refused(self, tmp_path):
        stand_in = tmp_path / "mmcblk0"
        stand_in.write_bytes(bytes(512))

        result = self.exclusive_open(stand_in)

        assert result.returncode != 0
        assert "not a block device" in result.stderr, result.stderr

    def test_a_character_device_is_refused(self):
        result = self.exclusive_open(os.devnull)

        assert result.returncode != 0
        assert "not a block device" in result.stderr, result.stderr


# Every caller that writes to the card: both branches of Flash, and both
# wipes. The bool is whether it runs on SeedSigner OS.
RAW_WRITERS = [
    (microsd_views.ToolsMicroSDFlashView, True),
    (microsd_views.ToolsMicroSDFlashView, False),
    (microsd_views.ToolsMicroSDWipeZeroView, True),
    (microsd_views.ToolsMicroSDWipeRandomView, True),
]


class TestNothingIsWrittenUnderAMountedCard(BaseTest):
    """
    The views unmounted two hard-coded paths, and only when the hostname said
    SeedSigner OS. A Luckfox mounts its card at /mnt/sdcard, so a flash went
    straight under a live filesystem; Wipe (Random) unmounted nothing at all.
    """

    @pytest.mark.parametrize("view_cls,on_seedsigner_os", RAW_WRITERS)
    def test_the_card_is_unmounted_before_dd(self, monkeypatch, tmp_path, view_cls, on_seedsigner_os):
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=on_seedsigner_os)
        fake_kernel(monkeypatch, tmp_path, SEEDSIGNER_OS_MOUNTS, SEEDSIGNER_OS_LOOPS)
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)
        view, _ = build_view(monkeypatch, view_cls)

        view.run()

        assert unmounted(commands) == ["/mnt/diy", "/mnt/microsd"], commands
        last_umount = max(i for i, cmd in enumerate(commands) if "umount" in cmd)
        assert writes(commands) and last_umount < writes(commands)[0], commands

    @pytest.mark.parametrize("view_cls,on_seedsigner_os", RAW_WRITERS)
    def test_an_unreadable_mount_table_writes_nothing(self, monkeypatch, tmp_path, view_cls, on_seedsigner_os):
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=on_seedsigner_os)
        fake_kernel(monkeypatch, tmp_path, SEEDSIGNER_OS_MOUNTS, SEEDSIGNER_OS_LOOPS)
        monkeypatch.setattr(microsd_views, "PROC_MOUNTINFO", str(tmp_path / "missing"))
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)
        view, screens = build_view(monkeypatch, view_cls)

        view.run()

        assert not writes(commands), commands
        assert screens.showed("Could not unmount")

    @pytest.mark.parametrize("mounts,kernel", RUNNING_FROM_THE_CARD)
    @pytest.mark.parametrize("view_cls,on_seedsigner_os", RAW_WRITERS)
    def test_a_card_holding_the_running_system_is_never_written(self, monkeypatch, tmp_path, view_cls, on_seedsigner_os,
                                                                mounts, kernel):
        # On a Raspberry Pi the card in the slot is the one it booted from.
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=on_seedsigner_os)
        fake_kernel(monkeypatch, tmp_path, mounts, **kernel)
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)
        view, screens = build_view(monkeypatch, view_cls)

        view.run()

        assert unmounted(commands) == [], commands
        assert not writes(commands), commands
        assert screens.showed("Could not unmount")

    @pytest.mark.parametrize("view_cls,on_seedsigner_os", RAW_WRITERS)
    def test_a_card_still_in_use_after_its_umount_is_not_written(self, monkeypatch, tmp_path, view_cls, on_seedsigner_os):
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=on_seedsigner_os)
        fake_kernel(monkeypatch, tmp_path, SEEDSIGNER_OS_MOUNTS, SEEDSIGNER_OS_LOOPS,
                    claimed={f"{SD_DEV}p1"})
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)
        view, screens = build_view(monkeypatch, view_cls)

        view.run()

        assert unmounted(commands) == ["/mnt/diy", "/mnt/microsd"], commands
        assert not writes(commands), commands
        assert screens.showed("Could not unmount")

    @pytest.mark.parametrize("view_cls,on_seedsigner_os", RAW_WRITERS)
    def test_a_card_that_will_not_unmount_is_not_written(self, monkeypatch, view_cls, on_seedsigner_os):
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=on_seedsigner_os)
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)
        monkeypatch.setattr(microsd_views, "unmount_card", lambda dev: False)
        view, screens = build_view(monkeypatch, view_cls)

        view.run()

        assert not writes(commands), commands
        assert screens.showed("Could not unmount")

    @pytest.mark.parametrize("node", [FILE, DEVNUMS["/dev/sda2"]], ids=["file", "other-disk"])
    @pytest.mark.parametrize("view_cls,on_seedsigner_os", RAW_WRITERS)
    def test_a_path_that_is_not_the_card_is_not_written(self, monkeypatch, tmp_path, view_cls, on_seedsigner_os,
                                                        node):
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=on_seedsigner_os)
        fake_kernel(monkeypatch, tmp_path, SEEDSIGNER_OS_MOUNTS, SEEDSIGNER_OS_LOOPS,
                    nodes={SD_DEV: node})
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)
        view, screens = build_view(monkeypatch, view_cls)

        view.run()

        assert not writes(commands), commands
        assert screens.showed("Could not unmount")

    @pytest.mark.parametrize("on_seedsigner_os", [True, False])
    def test_the_image_is_copied_before_the_card_is_unmounted(self, monkeypatch, tmp_path, on_seedsigner_os):
        # Raspberry Pi OS keeps its images on /boot, which can be a partition
        # of the very card being flashed.
        commands = []
        patch_environment(monkeypatch, commands, on_seedsigner_os=on_seedsigner_os)
        fake_kernel(monkeypatch, tmp_path, [
            "/dev/sda2 / ext4 rw 0 0",
            f"{SD_DEV}p1 /boot vfat rw 0 0",
        ])
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)
        view, _ = build_view(monkeypatch, microsd_views.ToolsMicroSDFlashView)

        view.run()

        copy = next(i for i, cmd in enumerate(commands) if cmd[0] == "cp")
        first_umount = next(i for i, cmd in enumerate(commands) if "umount" in cmd)
        assert copy < first_umount, commands
