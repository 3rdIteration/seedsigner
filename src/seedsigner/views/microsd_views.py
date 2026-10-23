"""****************************************************************************
    MicroSD Views
****************************************************************************"""
import logging
import os
import stat
import sys
from pathlib import Path
from gettext import gettext as _
from typing import NamedTuple

from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    LargeIconStatusScreen,
    WarningScreen,
)
from seedsigner.gui.components import SeedSignerIconConstants
from seedsigner.gui.screens.screen import ButtonOption, LoadingScreenThread
from seedsigner.hardware.microsd import MicroSD, resolve_microsd_images_dir
from seedsigner.models.settings import Settings
from seedsigner.views.view import View, Destination, BackStackView, MainMenuView

logger = logging.getLogger(__name__)

# What the kernel says is mounted, and which block devices those are.
# Tests point these at a made-up tree.
PROC_MOUNTINFO = "/proc/self/mountinfo"
SYS_BLOCK = "/sys/block"

# Opens each device named on the command line for exclusive use, as mount and
# swapon do. The kernel refuses that with EBUSY while a filesystem, swap,
# device-mapper or md has the device -- or, for a whole disk, any partition of
# it -- whether or not any mount this process can see says so. It does that
# only for a block device, though: O_EXCL without O_CREAT is ignored for
# anything else, so a regular file at the card's path opens without complaint.
# So each device comes with the "major:minor" sysfs gives it, and what was
# opened must be the block device with that number.
EXCLUSIVE_OPEN = (
    "import os, stat, sys\n"
    "args = sys.argv[1:]\n"
    "for device, devnum in zip(args[::2], args[1::2], strict=True):\n"
    "    fd = os.open(device, os.O_RDONLY | os.O_EXCL)\n"
    "    st = os.fstat(fd)\n"
    "    os.close(fd)\n"
    "    if not stat.S_ISBLK(st.st_mode):\n"
    "        sys.exit(f'{device} is not a block device')\n"
    "    if f'{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}' != devnum:\n"
    "        sys.exit(f'{device} is not block device {devnum}')\n"
)

# Runs the dd commands on its command line in turn, with the card claimed
# the same way for as long as they last: EXCLUSIVE_OPEN lets go before dd
# starts, and anything could take the card in that gap. Each dd writes
# through the claimed file, of=/proc/self/fd/N, so nothing can mount the
# card meanwhile. And it must still be the card that was chosen, by its CID,
# before the first dd and after each one: a card pulled and another put in
# takes the same node and device number, and unmounted it passes every other
# check.
CLAIMED_WRITE = (
    "import json, os, stat, subprocess, sys\n"
    "device, devnum, cid_path, cid, commands = sys.argv[1:]\n"
    "def same_card():\n"
    "    try:\n"
    "        st = os.stat(device)\n"
    "        with open(cid_path) as f:\n"
    "            named = f.read().strip()\n"
    "    except OSError:\n"
    "        return False\n"
    "    return (stat.S_ISBLK(st.st_mode) and named == cid\n"
    "            and f'{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}' == devnum)\n"
    "fd = os.open(device, os.O_WRONLY | os.O_EXCL)\n"
    "st = os.fstat(fd)\n"
    "if not stat.S_ISBLK(st.st_mode):\n"
    "    sys.exit(f'{device} is not a block device')\n"
    "if f'{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}' != devnum:\n"
    "    sys.exit(f'{device} is not block device {devnum}')\n"
    "def changed():\n"
    "    print('The MicroSD card was changed.', file=sys.stderr)\n"
    "    sys.exit(75)\n"
    "for dd in json.loads(commands):\n"
    "    if not same_card():\n"
    "        changed()\n"
    "    dd = [f'of=/proc/self/fd/{fd}' if arg == f'of={device}' else arg for arg in dd]\n"
    "    code = subprocess.run(dd, pass_fds=(fd,)).returncode\n"
    "    # Before the exit code: a wipe that filled the card ends in an error\n"
    "    # that counts as success, and must not if another card was filled.\n"
    "    if not same_card():\n"
    "        changed()\n"
    "    if code:\n"
    "        sys.exit(code)\n"
)
# The exit status CLAIMED_WRITE gives when the card in the slot is not the one
# chosen. Whatever dd reported, nothing it wrote counts.
CARD_CHANGED = 75


def _mmc_device_type(device: str) -> str | None:
    """The MMC card type the kernel reports: "SD", "MMC" (eMMC) or "SDIO"."""
    try:
        with open(f"/sys/block/{device}/device/type") as f:
            return f.read().strip()
    except OSError:
        return None


def find_sd_card_device():
    """Return the device node of the inserted MicroSD card, or None.

    A card counts as present once its disk node exists, whether or not it
    carries a partition table. A brand-new card has none, and neither does one
    this tool just zero-wiped, so requiring a partition would make the wipe and
    flash tools blind to exactly the cards they are meant to work on. A
    partitioned card still wins, so a host with more than one MMC device keeps
    resolving to the same node as before.
    """
    import re
    blank = None
    for device in sorted(os.listdir("/sys/block")):
        if not re.fullmatch(r'mmcblk\d+', device):
            continue
        # eMMC is an mmcblk device too, and on a board that has it, it is the
        # board's own storage -- partitioned, so it used to win. Only a device
        # the kernel calls an SD card is ever a candidate, and one that will not
        # say what it is is not.
        if _mmc_device_type(device) != "SD":
            continue
        partitions = os.listdir(f"/sys/block/{device}")
        if any(p.startswith(device + "p") for p in partitions):
            return f"/dev/{device}"
        if blank is None:
            blank = f"/dev/{device}"
    return blank


def _unescape(field: str) -> str:
    """Undo the octal escapes mountinfo uses for spaces and the like: \\040"""
    import re
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def _read_sysfs(path: str) -> str:
    with open(path) as f:
        return f.read().rstrip("\n")


def _card_blocks(device: str) -> list[str]:
    """The sysfs directories of device and of every partition on it."""
    name = os.path.basename(device)
    disk = os.path.join(SYS_BLOCK, name)
    return [disk] + [
        os.path.join(disk, entry)
        for entry in sorted(os.listdir(disk))
        if entry.startswith(name)
    ]


def _loop_backing_files() -> dict[str, str]:
    """
    The file each bound loop device reads, keyed by its "major:minor".

    Raises OSError when one will not say: its mount may be on the card, and
    guessing that it is not would write under it.
    """
    loops = {}
    for name in os.listdir(SYS_BLOCK):
        block = os.path.join(SYS_BLOCK, name)
        # Only a loop device that is bound to a file has this directory.
        if os.path.isdir(os.path.join(block, "loop")):
            devnum = _read_sysfs(os.path.join(block, "dev"))
            loops[devnum] = _read_sysfs(os.path.join(block, "loop", "backing_file"))
    return loops


class _Mount(NamedTuple):
    id: str
    parent: str
    devnum: str
    mountpoint: str
    fstype: str
    source: str
    options: str


def _parse_mountinfo(mountinfo: str) -> list[_Mount]:
    """
    Each line of /proc/self/mountinfo as a _Mount.

    Raises ValueError on a line that is not mountinfo.
    """
    mounts = []
    for line in mountinfo.splitlines():
        # ID, parent ID, major:minor, root, mountpoint, options, any optional
        # fields, "-", then filesystem type, source and superblock options.
        # One space apart each, so an empty source is still a field.
        fields = line.split(" ")
        separator = fields.index("-", 6)
        if len(fields) < separator + 4:
            raise ValueError(f"not a mountinfo line: {line!r}")
        mounts.append(_Mount(
            *fields[:3],
            mountpoint=_unescape(fields[4]),
            fstype=fields[separator + 1],
            source=_unescape(fields[separator + 2]),
            options=fields[separator + 3],
        ))
    return mounts


def _overlay_layers(options: str) -> list[str]:
    """
    The directories an overlay is made of, from its superblock options:
    lowerdir (colon-separated), lowerdir+, datadir+, upperdir and workdir.
    """
    layers = []
    for option in options.split(","):
        name, _, value = option.partition("=")
        if name == "lowerdir":
            layers += value.split(":")
        elif name in ("lowerdir+", "datadir+", "upperdir", "workdir"):
            layers.append(value)
    return [_unescape(layer) for layer in layers]


def _mounts_holding(device: str, mounts: list[_Mount], card_devnums: set[str],
                    loops: dict[str, str]) -> list[tuple[str, bool]]:
    """
    Every mount that holds device, as (mountpoint, is a loop mount), in
    unmount order.

    A mount is on the card when its device number is the card's or one of its
    partitions'. The name it was mounted by does not say: a root the kernel
    mounted itself is listed as /dev/root, whatever it is on. The name still
    counts too, since btrfs gives its mounts a device number of their own. A
    loop device reading the card or a partition of it is on the card as well.

    A filesystem on the card is held by more than its own mount. SeedSigner OS
    loop-mounts diy-tools.squashfs from the card at /mnt/diy, and while that is
    up, /mnt/microsd will not come off. An overlay holds its layers through a
    copy of their mounts of its own, so /mnt/microsd comes off under one and
    the card stays in use all the same. So anything that sits on a listed
    mount is listed too: mounted inside it or on top of it, or a loop device
    or an overlay reading a path on it. Each mount is listed after everything
    that sits on it, so nested ones come before their parents.
    """
    import re
    card = re.compile(re.escape(device) + r"(p\d+)?")

    def on_card(mount: _Mount) -> bool:
        backing_file = loops.get(mount.devnum)
        return bool(
            mount.devnum in card_devnums
            or card.fullmatch(mount.source)
            or (backing_file is not None and card.fullmatch(backing_file))
        )

    def reads(mount: _Mount) -> list[str]:
        """The paths outside its own mountpoint a mount is made from."""
        if mount.devnum in loops:
            return [loops[mount.devnum]]
        if mount.fstype == "overlay":
            return _overlay_layers(mount.options)
        return []

    def covers(mountpoint: str, path: str) -> bool:
        return path == mountpoint or path.startswith(mountpoint.rstrip("/") + "/")

    def sits_on(upper: _Mount, lower: _Mount) -> bool:
        return upper.parent == lower.id or any(
            covers(lower.mountpoint, path) for path in reads(upper)
        )

    order = []
    seen = set()

    def take_off(i: int):
        seen.add(i)
        for j in range(len(mounts)):
            if j not in seen and sits_on(mounts[j], mounts[i]):
                take_off(j)
        order.append((mounts[i].mountpoint, mounts[i].devnum in loops))

    for i, mount in enumerate(mounts):
        if i not in seen and on_card(mount):
            take_off(i)
    return order


def _unclaimed(devices: dict[str, str]) -> bool:
    """
    True when the kernel lets every one of devices be opened exclusively, and
    each is the block device with the "major:minor" it maps to.
    """
    from subprocess import run
    args = [arg for device, devnum in devices.items() for arg in (device, devnum)]
    cmd = Settings.SU_COMMAND_PREFIX.split() + [sys.executable, "-c", EXCLUSIVE_OPEN] + args
    data = run(cmd, capture_output=True, text=True)
    logger.info(data)
    return data.returncode == 0


def unmount_card(device: str) -> bool:
    """
    Unmount everything that holds device; True only once all of it has gone.

    The raw-write tools used to unmount two hard-coded paths, and only when the
    hostname said SeedSigner OS. A Luckfox mounts its card at /mnt/sdcard, so a
    flash went straight under a live filesystem, and Wipe (Random) unmounted
    nothing at all. The kernel says what is mounted, and from which device, on
    every board. When it cannot be asked the answer is False: a failed read is
    not the same as nothing mounted.

    The mounts are not the whole answer, though. The kernel can be using the
    card with no mount here to show for it: swap, the lower layer of an
    overlay root mounted before the root was switched, a btrfs root listed as
    /dev/root under a device number of its own, a mount in another namespace.
    And a filesystem can outlive the umount of its mount. So the kernel is
    asked as well, by opening for exclusive use: before anything comes off,
    each partition no mount shows, and once everything has, the whole card.
    Each must turn out to be the block device sysfs numbers it, too, or the
    answer is about whatever else stands at its path.
    """
    from subprocess import run
    try:
        with open(PROC_MOUNTINFO) as f:
            mounts = _parse_mountinfo(f.read())
        blocks = _card_blocks(device)
        devnums = {
            os.path.basename(block): _read_sysfs(os.path.join(block, "dev"))
            for block in blocks
        }
        built_on = [
            holder
            for block in blocks
            for holder in os.listdir(os.path.join(block, "holders"))
        ]
        holding = _mounts_holding(device, mounts, set(devnums.values()), _loop_backing_files())
    except (OSError, ValueError) as e:
        logger.info("Cannot tell what holds %s: %s", device, e)
        return False

    if built_on:
        # device-mapper or md on the card: what is mounted is that device, and
        # no umount frees the card underneath it.
        logger.info("%s is in use by %s", device, built_on)
        return False

    if any(mountpoint == "/" for mountpoint, _ in holding):
        # Every mount sits under "/", so this would take the running system's
        # /proc, /dev and the rest down with it.
        logger.info("%s holds the root filesystem", device)
        return False

    # A partition in use that no mount shows -- or the card itself, when it
    # has none -- has nothing umount can take off. Asking before anything
    # comes off leaves a card the system runs from exactly as it was.
    disk = os.path.basename(device)
    partitions = [name for name in devnums if name != disk] or [disk]
    shown = {mount.devnum for mount in mounts} | {mount.source for mount in mounts}
    unseen = {
        f"/dev/{name}": devnums[name] for name in partitions
        if devnums[name] not in shown and f"/dev/{name}" not in shown
    }
    if unseen and not _unclaimed(unseen):
        logger.info("%s is in use by something no mount shows", device)
        return False

    # mdev tells Settings when a card is pulled out, and nobody tells it when
    # the card is unmounted here. So a save still waiting goes to the card
    # first, and Settings then hears what it would have heard from mdev,
    # whether or not everything came off.
    Settings.get_instance().flush_save()
    try:
        for mountpoint, is_loop in holding:
            cmd = Settings.SU_COMMAND_PREFIX.split() + ["umount", mountpoint]
            if is_loop:
                # Free the loop device as well: while it stays bound it keeps
                # its file open, and that file is on the card.
                cmd.insert(-1, "-d")
            data = run(cmd, capture_output=True, text=True)
            logger.info(data)
            if data.returncode != 0:
                return False
    finally:
        Settings.handle_microsd_state_change(MicroSD.ACTION__REMOVED)

    # umount can succeed and leave the filesystem up: an overlay keeps its own
    # copy of each layer's mount, another mount namespace its own copy of the
    # tree. Only the kernel can say the card is free.
    return _unclaimed({device: devnums[disk]})


def refuse_without_card(view: View, text: str) -> Destination:
    """Report that nothing was done and return to the main menu.

    find_sd_card_device() returns None when no card is in the slot, and every
    caller must check it immediately before running dd: a path looked up any
    earlier describes whichever card was inserted then, and None reaches dd as
    the literal string "None" (`of=None`, `if=None`), which either fails
    obscurely or writes to a file of that name.
    """
    view.run_screen(
        WarningScreen,
        title="Error",
        status_headline=None,
        text=text,
        show_back_button=False,
        button_data=[ButtonOption("Continue")]
    )
    return Destination(MainMenuView)


def dd_succeeded(data, wipe: bool = False) -> bool:
    """
    True when a dd that wrote to the card did everything it was asked to.

    It must exit cleanly: the record counts alone do not say, since dd
    reports every record it wrote even when it then fails.
    A wipe is the exception. It writes what it was asked to or until the
    card is full, and a full card makes dd fail with "No space left on
    device" once the job is done. Every record read must also have been
    written.
    """
    filled = wipe and "No space left on device" in data.stderr
    if data.returncode != 0 and not filled:
        return False

    records_in, records_out = 1, 0
    for line in data.stderr.split("\n"):
        if "records in" in line:
            records_in = line.split("+")[0]
        elif "records out" in line:
            records_out = line.split("+")[0]
    # A full card stops dd partway through a record
    return filled or records_in == records_out


def run_dd(cmd):
    """
    Run a dd whose report dd_succeeded() reads, in English whatever the locale.

    GNU dd translates its record counts and errors, and sudo passes the
    caller's locale through, so on a host set to any other language a good
    write read as a failed one.
    """
    from subprocess import run
    return run(cmd, capture_output=True, text=True, env={**os.environ, "LC_ALL": "C"})


def card_identity(device: str) -> str | None:
    """The card's CID, which names this one card, or None if it will not say."""
    try:
        return _read_sysfs(os.path.join(SYS_BLOCK, os.path.basename(device), "device", "cid"))
    except OSError:
        return None


def write_card(dd_cmds: list[list[str]], device: str, card: str):
    """
    Run dd_cmds, dds that write device, in turn, holding the card for
    exclusive use from before the first opens it until the last has
    finished, and only while it is still the card whose CID is card.

    They run under the su prefix, so none carries its own.
    """
    import json
    from subprocess import CompletedProcess
    try:
        devnum = _read_sysfs(os.path.join(SYS_BLOCK, os.path.basename(device), "dev"))
    except OSError as e:
        return CompletedProcess(dd_cmds, 1, "", f"Cannot tell which device {device} is: {e}\n")
    cid_path = os.path.join(SYS_BLOCK, os.path.basename(device), "device", "cid")
    return run_dd(
        Settings.SU_COMMAND_PREFIX.split()
        + [sys.executable, "-c", CLAIMED_WRITE, device, devnum, cid_path, card, json.dumps(dd_cmds)]
    )


def is_the_card(device: str) -> bool:
    """
    True when device is still the card: the block device sysfs numbers it.

    dd opens of= with O_CREAT, busybox's as well as GNU's, and busybox's has
    no conv=nocreat to stop it. A card pulled after it was unmounted takes
    its node with it, and dd then writes a regular file of that name instead
    -- in RAM, on devtmpfs -- and exits 0. devtmpfs never replaces a file it
    did not make, so that file would go on standing in for the card, even
    once the card is back, and every later flash, wipe and Verify would find
    it instead. So a regular file there is removed, and whatever went to it
    or came from it did not reach the card.
    """
    from subprocess import run
    try:
        devnum = _read_sysfs(os.path.join(SYS_BLOCK, os.path.basename(device), "dev"))
        node = os.stat(device)
    except OSError as e:
        logger.info("Cannot tell whether %s is the card: %s", device, e)
    else:
        if stat.S_ISBLK(node.st_mode) and f"{os.major(node.st_rdev)}:{os.minor(node.st_rdev)}" == devnum:
            return True
        logger.info("%s is not block device %s", device, devnum)

    try:
        stray = stat.S_ISREG(os.lstat(device).st_mode)
    except OSError:
        stray = False
    if stray:
        data = run(Settings.SU_COMMAND_PREFIX.split() + ["rm", "-f", device], capture_output=True, text=True)
        logger.info(data)
    return False


def write_failure(data, device: str, wipe: bool = False) -> str | None:
    """
    Why a dd that wrote to device did not write the card, or None if it did.

    The card is asked about first, whatever dd said: a dd that failed can
    have left a file in the card's place as well, having filled RAM with it.
    """
    if not is_the_card(device):
        return "The write did not reach the MicroSD card."
    if data.returncode == CARD_CHANGED:
        return "The MicroSD card was changed. It was not written in full."
    if not dd_succeeded(data, wipe):
        return data.stderr
    return None


class ToolsMicroSDMenuView(View):
    FLASH_IMAGE = ButtonOption("Flash Image")
    VERIFY_IMAGE = ButtonOption("Verify MicroSD")
    WIPE_ZERO = ButtonOption("Wipe (Zero)")
    WIPE_RANDOM = ButtonOption("Wipe (Random)")

    def run(self):
        button_data = [self.FLASH_IMAGE, self.VERIFY_IMAGE, self.WIPE_ZERO, self.WIPE_RANDOM]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="MicroSD Tools",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if MicroSD.is_desktop_mode():
            self.run_screen(
                WarningScreen,
                title="Unavailable",
                status_headline=None,
                text="MicroSD tools are not supported on desktop.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(ToolsMicroSDMenuView, skip_current_view=True)

        elif button_data[selected_menu_num] == self.FLASH_IMAGE:
            return Destination(ToolsMicroSDFlashView)

        elif button_data[selected_menu_num] == self.VERIFY_IMAGE:
            return Destination(ToolsMicroSDVerifyWarningView)

        elif button_data[selected_menu_num] == self.WIPE_ZERO:
            return Destination(ToolsMicroSDWipeZeroView)

        elif button_data[selected_menu_num] == self.WIPE_RANDOM:
            return Destination(ToolsMicroSDWipeRandomView)


def flash_images_dir() -> Path:
    """
    Where Flash Image finds images: one answer, for listing and for copying.

    It listed one hard-coded folder and copied from another spelling of it, so
    a board whose images live anywhere else -- a Luckfox with no card, writing
    to /userdata; a card on an alternate mount -- listed images it could not
    then find. SeedSigner OS resolves the data directory the way every other
    file tool does; a manual Raspberry Pi OS build keeps the boot partition.
    """
    if Settings.is_seedsigner_os():
        return resolve_microsd_images_dir()
    return Path("/boot/microsd-images")



class ToolsMicroSDFlashView(View):
    def run(self):
        from subprocess import run
        import hashlib, shutil
        from seedsigner.models.settings import Settings

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools read from the microSD card and may leak loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")]
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        images_dir = flash_images_dir()
        # A stock card has no images folder, and one that exists may be empty.
        # Both used to leave the flow through the generic error screen -- a
        # FileNotFoundError, then an IndexError from a button list with nothing
        # in it -- which made the feature look broken rather than empty.
        try:
            microsd_images = os.listdir(images_dir)
        except OSError as e:
            logger.info("No images to flash in %s: %s", images_dir, e)
            microsd_images = []

        if not microsd_images:
            self.run_screen(
                WarningScreen,
                title=_("Flash Image"),
                status_icon_name=SeedSignerIconConstants.WARNING,
                status_headline=None,
                text=_("No images found on the MicroSD card."),
                show_back_button=False,
                button_data=[ButtonOption(_("OK"))],
            )
            return Destination(BackStackView)

        microsd_images_buttons = []
        for file in microsd_images:
            microsd_images_buttons.append(ButtonOption(file))

        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select Image",
            is_button_text_centered=False,
            button_data=microsd_images_buttons
        )

        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        microsd_image = microsd_images[selected_file_num]
        logger.info("Selected: %s", microsd_image)

        if Settings.is_seedsigner_os():
            image_path = os.path.join(images_dir, microsd_image)
            data = run(['cp', image_path, '/tmp/img.img'], capture_output=True, text=True)
            logger.info(data)
            if data.returncode != 0 or len(data.stderr) > 1:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=data.stderr,
                    show_back_button=False,
                )
                return Destination(MainMenuView)

            ret = self.run_screen(
                WarningScreen,
                title="Notice",
                status_headline=None,
                text="Insert MicroSD to be Flashed",
                show_back_button=True,
                button_data=[ButtonOption("Continue")]
            )

            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            microsd_dev = find_sd_card_device()
            if microsd_dev is None:
                return refuse_without_card(self, "No MicroSD card detected. Nothing was written.")
            card = card_identity(microsd_dev)
            if card is None:
                return refuse_without_card(self, "Could not identify the MicroSD card. Nothing was written.")

            if not unmount_card(microsd_dev):
                return refuse_without_card(self, "Could not unmount the MicroSD card. Nothing was written.")

            self.loading_screen = LoadingScreenThread(text="Flashing MicroSD\n\n\n\n\n\n")
            self.loading_screen.start()

            # Zero the MicroSD first, then flash the image, under one claim.
            # A zero pass that fails stops there, and it is that failure that
            # is reported.
            data = write_card(
                [
                    ["dd", f"if=/dev/zero", f"of={microsd_dev}", "bs=1M", "count=26"],
                    ["dd", "if=/tmp/img.img", f"of={microsd_dev}"],
                ],
                microsd_dev, card,
            )
            logger.info(data)
            failure = write_failure(data, microsd_dev)

            self.loading_screen.stop()

            if failure is not None:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=failure,
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")]
                )
            else:
                ret = self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text="MicroSD Flashed",
                    show_back_button=False,
                    button_data=[ButtonOption("Verify"), ButtonOption("Skip Verification")]
                )

                if ret == 0:
                    return Destination(ToolsMicroSDVerifyView)
                else:
                    return Destination(MainMenuView)

        else:
            # Copy first: the images are on /boot, and /boot can be on the
            # card that is about to be unmounted.
            image_path = os.path.join(images_dir, microsd_image)
            data = run(['cp', image_path, '/tmp/img.img'], capture_output=True, text=True)
            logger.info(data)
            if data.returncode != 0:
                # /tmp/img.img still holds whatever an earlier flash or Verify
                # left there, and dd would write that to the card instead.
                return refuse_without_card(self, "Could not copy the image. Nothing was written.")

            microsd_dev = find_sd_card_device()
            if microsd_dev is None:
                return refuse_without_card(self, "No MicroSD card detected. Nothing was written.")
            card = card_identity(microsd_dev)
            if card is None:
                return refuse_without_card(self, "Could not identify the MicroSD card. Nothing was written.")

            if not unmount_card(microsd_dev):
                return refuse_without_card(self, "Could not unmount the MicroSD card. Nothing was written.")

            data = write_card([['dd', f'if=/tmp/img.img', f'of={microsd_dev}']], microsd_dev, card)
            logger.info(data)

            failure = write_failure(data, microsd_dev)
            if failure is not None:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=failure,
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")]
                )
            else:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text="MicroSD Flashed",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")]
                )

        return Destination(MainMenuView)


class ToolsMicroSDVerifyWarningView(View):
    def run(self):
        ret = self.run_screen(
            WarningScreen,
            title="Checksum Note",
            status_headline=None,
            text="Verification test will\nonly pass for freshly\nflashed (or Read Only)\nMicroSD Cards.",
            show_back_button=True,
            button_data=[ButtonOption("Continue")]
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        else:
            return Destination(ToolsMicroSDVerifyView)


class ToolsMicroSDVerifyView(View):
    known_checksums = {'5809d4ec68138c737b1b000db4c6ec60983e94544efd893bdfa40ebf19af60f4':'Zero Wiped (First 26MB)',
                       'a380cb93eb852254863718a9c000be9ec30cee14a78fc0ec90708308c17c1b8a':'seedsigner_os.0.7.0.pi0',
                       'fe0601e6da97c7711093b67a7102f8108f2bfb8a2478fd94fa9d3edea5adfb64':'seedsigner_os.0.7.0.pi02w',
                       '65be9209527ba03efe8093099dae8ec65725c90a758bc98678b9da31639637d7':'seedsigner_os.0.7.0.pi2',
                       'd574c1326d07e18b550e2f65e36a4678b05db882adb5cb8f8732ff8d75d59809':'seedsigner_os.0.7.0.pi4',
                       'c8d5352ed4a86c19eb9ef54f2920934f8ce460742b464ea94dc9114f9f4e039a':'seedsigner_os.0.8.0.pi02w.img',
                       '1d0f1c412f64b40e6aba21b5bacdb41d9323653c170ce06d0a3f1dd71fddb28e':'seedsigner_os.0.8.0.pi0.img',
                       '11c5553d75b3ebca4988ae3c4573b60b33a12bc4779282454ae34404ba797670':'seedsigner_os.0.8.0.pi2.img',
                       '917201e335bfc7ee4189f17827f954f89588dc0fdefdad80d26f2a65c5c8e6d0':'seedsigner_os.0.8.0.pi4.img',
                       '398d9bf9cda0858fe97c0788b353194c1c902335a858b7dbf5d7b213bda75d96':'seedsigner_os.0.8.5.pi02w.img',
                       'bcb901e27d309d85f086dc80b49b153d6b1caab2247eba2811731384d58f2f3e':'seedsigner_os.0.8.5.pi0.img',
                       '1e93a82e62d4a1defbdc777a6762a813f4cb5c3ef9090da0bd07542dfd6f62bf':'seedsigner_os.0.8.5.pi2.img',
                       'd298ffad3c765e11e48873efc6d1c65e4230528fde4d5bd4701bb507acbf493c':'seedsigner_os.0.8.5.pi4.img'}

    def run(self):
        from subprocess import run

        microsd_dev = find_sd_card_device()
        if microsd_dev is None:
            return refuse_without_card(self, "No MicroSD card detected. Nothing was read.")

        self.loading_screen = LoadingScreenThread(text="Reading MicroSD\n\n\n\n\n\n")
        self.loading_screen.start()

        dd_cmd = ["dd", f"if={microsd_dev}", "of=/tmp/img.img", "bs=1M", "count=26"]
        if not Settings.is_seedsigner_os():
            dd_cmd = ["sudo"] + dd_cmd
        read = run_dd(dd_cmd)
        logger.info(read)

        if not is_the_card(microsd_dev) or read.returncode != 0:
            # /tmp/img.img still holds whatever the last read or flash left
            # there, so hashing it now would report a checksum for that image
            # instead of for this card. A read of a file standing in for the
            # card is no better.
            self.loading_screen.stop()
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Could not read the MicroSD card.",
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )
            return Destination(MainMenuView)

        data = run(["sha256sum", "/tmp/img.img"], capture_output=True, text=True)
        logger.info(data)

        self.loading_screen.stop()

        checksum = data.stdout[:64]

        try:
            image_name = self.known_checksums[checksum]
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline="Matched Checksum",
                text=image_name[:20] + "\n" + image_name[20:40] + "\n" + image_name[40:60],
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )

        except KeyError:
            formatted_checksum = data.stdout[:16] + "\n" + data.stdout[16:32] + "\n" + data.stdout[32:48] + "\n" + data.stdout[48:64]

            self.run_screen(
                WarningScreen,
                title="Unfamilliar Checksum",
                status_headline=None,
                text=formatted_checksum,
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )

        return Destination(MainMenuView)


class ToolsMicroSDWipeZeroView(View):
    WIPE_64MB = ButtonOption("64MB")
    WIPE_256MB = ButtonOption("256MB")
    WIPE_ALL = ButtonOption("All")

    def run(self):
        from subprocess import run

        button_data = [self.WIPE_64MB, self.WIPE_256MB, self.WIPE_ALL]

        wipe_selection = self.run_screen(
                LargeIconStatusScreen,
                title="Wipe MicroSD",
                status_headline=None,
                text="Select amount to wipe (Larger takes longer)",
                status_icon_size=0,
                show_back_button=True,
                button_data=button_data,
            )

        if wipe_selection == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        wipesize_cmd_string = ""
        if button_data[wipe_selection] == self.WIPE_64MB:
            wipesize_cmd_string = " count=64"
        elif button_data[wipe_selection] == self.WIPE_256MB:
            wipesize_cmd_string = " count=256"

        ret = self.run_screen(
            WarningScreen,
            title="Notice",
            status_headline=None,
            text="Insert MicroSD to be Wiped",
            show_back_button=True,
            button_data=[ButtonOption("Continue")]
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        microsd_dev = find_sd_card_device()
        if microsd_dev is None:
            return refuse_without_card(self, "No MicroSD card detected. Nothing was wiped.")
        card = card_identity(microsd_dev)
        if card is None:
            return refuse_without_card(self, "Could not identify the MicroSD card. Nothing was wiped.")

        if not unmount_card(microsd_dev):
            return refuse_without_card(self, "Could not unmount the MicroSD card. Nothing was wiped.")

        self.loading_screen = LoadingScreenThread(text="Wiping MicroSD\n\n\n\n\n\n(This takes a while)")
        self.loading_screen.start()

        dd_cmd = ["dd", f"if=/dev/zero", f"of={microsd_dev}", "bs=1M"] + wipesize_cmd_string.split()
        data = write_card([dd_cmd], microsd_dev, card)
        logger.info(data)

        self.loading_screen.stop()

        failure = write_failure(data, microsd_dev, wipe=True)
        if failure is not None:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=failure,
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )
        else:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="MicroSD Wiped",
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )

        return Destination(MainMenuView)


class ToolsMicroSDWipeRandomView(View):
    WIPE_64MB = ButtonOption("64MB")
    WIPE_256MB = ButtonOption("256MB")
    WIPE_ALL = ButtonOption("All")

    def run(self):
        from subprocess import run

        button_data = [self.WIPE_64MB, self.WIPE_256MB, self.WIPE_ALL]

        wipe_selection = self.run_screen(
                LargeIconStatusScreen,
                title="Wipe MicroSD",
                status_headline=None,
                text="Select amount to wipe (Larger takes longer)",
                status_icon_size=0,
                show_back_button=True,
                button_data=button_data,
            )

        if wipe_selection == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        wipesize_cmd_string = ""
        if button_data[wipe_selection] == self.WIPE_64MB:
            wipesize_cmd_string = " count=64"
        elif button_data[wipe_selection] == self.WIPE_256MB:
            wipesize_cmd_string = " count=256"

        ret = self.run_screen(
            WarningScreen,
            title="Notice",
            status_headline=None,
            text="Insert MicroSD to be Wiped",
            show_back_button=True,
            button_data=[ButtonOption("Continue")]
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        microsd_dev = find_sd_card_device()
        if microsd_dev is None:
            return refuse_without_card(self, "No MicroSD card detected. Nothing was wiped.")
        card = card_identity(microsd_dev)
        if card is None:
            return refuse_without_card(self, "Could not identify the MicroSD card. Nothing was wiped.")

        if not unmount_card(microsd_dev):
            return refuse_without_card(self, "Could not unmount the MicroSD card. Nothing was wiped.")

        self.loading_screen = LoadingScreenThread(text="Wiping MicroSD\n\n\n\n\n\n(This takes a while)")
        self.loading_screen.start()

        dd_cmd = ["dd", f"if=/dev/urandom", f"of={microsd_dev}", "bs=1M"] + wipesize_cmd_string.split()
        data = write_card([dd_cmd], microsd_dev, card)
        logger.info(data)

        self.loading_screen.stop()

        failure = write_failure(data, microsd_dev, wipe=True)
        if failure is not None:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=failure,
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )
        else:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="MicroSD Wiped",
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )

        return Destination(MainMenuView)
