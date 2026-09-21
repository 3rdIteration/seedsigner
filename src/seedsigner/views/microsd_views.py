"""****************************************************************************
    MicroSD Views
****************************************************************************"""
import logging
import os
import platform
from pathlib import Path
from gettext import gettext as _

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
        partitions = os.listdir(f"/sys/block/{device}")
        if any(p.startswith(device + "p") for p in partitions):
            return f"/dev/{device}"
        if blank is None:
            blank = f"/dev/{device}"
    return blank


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

        if platform.uname()[1] == "seedsigner-os":
            image_path = os.path.join(images_dir, microsd_image)
            data = run(['cp', image_path, '/tmp/img.img'], capture_output=True, text=True)
            logger.info(data)
            if len(data.stderr) > 1:
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

            self.loading_screen = LoadingScreenThread(text="Flashing MicroSD\n\n\n\n\n\n")
            self.loading_screen.start()

            # Unmount everything
            if platform.uname()[1] == "seedsigner-os":
                data = run(["umount", "/mnt/diy"], capture_output=True, text=True)
                logger.info(data)

            if platform.uname()[1] == "seedsigner-os":
                data = run(["umount", "/mnt/microsd"], capture_output=True, text=True)
                logger.info(data)

            # Zero the MicroSD first
            dd_cmd = ["dd", f"if=/dev/zero", f"of={microsd_dev}", "bs=1M", "count=26"]
            if platform.uname()[1] != "seedsigner-os":
                dd_cmd = ["sudo"] + dd_cmd

            data = run(dd_cmd, capture_output=True, text=True)
            logger.info(data)

            # Then flash the image
            data = run(["dd", "if=/tmp/img.img", f"of={microsd_dev}"], capture_output=True, text=True)
            logger.info(data)

            self.loading_screen.stop()

            data_stderr_split = data.stderr.split('\n')

            inNum = 1
            outNum = 0
            for errorLine in data_stderr_split:
                if "records in" in errorLine:
                    inNum = errorLine.split("+")[0]
                    continue
                elif "records out" in errorLine:
                    outNum = errorLine.split("+")[0]
                    continue

            if inNum != outNum:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=data.stderr,
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
            microsd_dev = find_sd_card_device()
            if microsd_dev is None:
                return refuse_without_card(self, "No MicroSD card detected. Nothing was written.")

            image_path = os.path.join(images_dir, microsd_image)
            run(['cp', image_path, '/tmp/img.img'], check=False)
            run(['sudo', 'dd', f'if=/tmp/img.img', f'of={microsd_dev}'], check=False)

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
        if platform.uname()[1] != "seedsigner-os":
            dd_cmd = ["sudo"] + dd_cmd
        read = run(dd_cmd, capture_output=True, text=True)
        logger.info(read)

        if read.returncode != 0:
            # /tmp/img.img still holds whatever the last read or flash left
            # there, so hashing it now would report a checksum for that image
            # instead of for this card.
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

        self.loading_screen = LoadingScreenThread(text="Wiping MicroSD\n\n\n\n\n\n(This takes a while)")
        self.loading_screen.start()

        # Unmount everything
        if platform.uname()[1] == "seedsigner-os":
            data = run(["umount", "/mnt/diy"], capture_output=True, text=True)
            logger.info(data)

        if platform.uname()[1] == "seedsigner-os":
            data = run(["umount", "/mnt/microsd"], capture_output=True, text=True)
            logger.info(data)

        dd_cmd = ["dd", f"if=/dev/zero", f"of={microsd_dev}", "bs=1M"] + wipesize_cmd_string.split()
        if platform.uname()[1] != "seedsigner-os":
            dd_cmd = ["sudo"] + dd_cmd

        data = run(dd_cmd, capture_output=True, text=True)
        logger.info(data)

        self.loading_screen.stop()

        data_stderr_split = data.stderr.split('\n')

        inNum = 1
        outNum = 0
        for errorLine in data_stderr_split:
            if "records in" in errorLine:
                inNum = errorLine.split("+")[0]
                continue
            elif "records out" in errorLine:
                outNum = errorLine.split("+")[0]
                continue

        # The number of in/out records won't match we just keep writing until the disk is full...
        if "No space left on device" in data.stderr:
            outNum = inNum

        if inNum != outNum:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=data.stderr,
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

        self.loading_screen = LoadingScreenThread(text="Wiping MicroSD\n\n\n\n\n\n(This takes a while)")
        self.loading_screen.start()

        dd_cmd = ["dd", f"if=/dev/urandom", f"of={microsd_dev}", "bs=1M"] + wipesize_cmd_string.split()
        if platform.uname()[1] != "seedsigner-os":
            dd_cmd = ["sudo"] + dd_cmd

        data = run(dd_cmd, capture_output=True, text=True)
        logger.info(data)

        self.loading_screen.stop()

        data_stderr_split = data.stderr.split('\n')

        inNum = 1
        outNum = 0
        for errorLine in data_stderr_split:
            if "records in" in errorLine:
                inNum = errorLine.split("+")[0]
                continue

            if "records out" in errorLine:
                outNum = errorLine.split("+")[0]
                continue

        # The number of in/out records won't match we just keep writing until the disk is full...
        if "No space left on device" in data.stderr:
            outNum = inNum

        if inNum != outNum:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=data.stderr,
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
