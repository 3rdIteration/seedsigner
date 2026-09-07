"""****************************************************************************
    MicroSD Views
****************************************************************************"""
import logging
import os
import platform
from gettext import gettext as _

from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    LargeIconStatusScreen,
    WarningScreen,
)
from seedsigner.gui.screens.screen import ButtonOption, LoadingScreenThread
from seedsigner.hardware.microsd import MicroSD
from seedsigner.views.view import View, Destination, BackStackView, MainMenuView

logger = logging.getLogger(__name__)


def find_sd_card_device():
    import re
    for device in os.listdir("/sys/block"):
        if device.startswith("mmcblk") and re.fullmatch(r'mmcblk\d+', device):
            partitions = os.listdir(f"/sys/block/{device}")
            if any(p.startswith(device + "p") for p in partitions):
                return f"/dev/{device}"
    return None


def _load_known_checksums(path=None):
    """
    Return {sha256_hex: image_name} from resources/microsd-known-checksums.json.

    The json is refreshed by .github/workflows/update-microsd-checksums.yml.
    Deliberately forgiving: a missing or corrupt file yields an empty dict, so
    verification still runs and simply reports every card as an unfamiliar
    checksum instead of crashing.
    """
    import json
    from pathlib import Path

    try:
        if path is None:
            path = Path(__file__).parent.parent.resolve() / "resources" / "microsd-known-checksums.json"
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return {
            checksum.lower(): meta.get("name", checksum)
            for checksum, meta in data["images"].items()
            if isinstance(checksum, str) and isinstance(meta, dict)
        }
    except Exception as e:
        logger.info(f"microsd-known-checksums.json unavailable ({e}); no known images")
        return {}


def _format_image_name(name):
    """Wrap an image name for the 240px status screen: 3 lines of max 20 chars."""
    short = name[len("seedsigner_os."):] if name.startswith("seedsigner_os.") else name
    if short.endswith(".img"):
        short = short[:-len(".img")]
    lines = [short[i:i + 20] for i in range(0, len(short), 20)]
    if len(lines) > 3:
        lines = lines[:3]
        lines[2] = lines[2][:17] + "..."
    return "\n".join(lines)


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

        microsd_dev = find_sd_card_device()

        if platform.uname()[1] == "seedsigner-os":
            microsd_images = os.listdir('/mnt/microsd/microsd-images/')
        else:
            microsd_images = os.listdir('/boot/microsd-images/')

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
        logger.info("Selected:", microsd_image)

        if platform.uname()[1] == "seedsigner-os":
            image_path = os.path.join('/mnt/microsd/microsd-images', microsd_image)
            data = run(['cp', image_path, '/tmp/img.img'], capture_output=True, text=True)
            print(data)
            if len(data.stderr) > 1:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="data.stderr",
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
            image_path = os.path.join('/boot/microsd-images', microsd_image)
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
    def run(self):
        from subprocess import run

        self.loading_screen = LoadingScreenThread(text="Reading MicroSD\n\n\n\n\n\n")
        self.loading_screen.start()

        microsd_dev = find_sd_card_device()

        dd_cmd = ["dd", f"if={microsd_dev}", "of=/tmp/img.img", "bs=1M", "count=26"]
        if platform.uname()[1] != "seedsigner-os":
            dd_cmd = ["sudo"] + dd_cmd
        run(dd_cmd, check=False)

        data = run(["sha256sum", "/tmp/img.img"], capture_output=True, text=True)
        logger.info(data)

        self.loading_screen.stop()

        checksum = data.stdout[:64]

        try:
            image_name = _load_known_checksums()[checksum]
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline="Matched Checksum",
                text=_format_image_name(image_name),
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )

        except KeyError:
            formatted_checksum = data.stdout[:16] + "\n" + data.stdout[16:32] + "\n" + data.stdout[32:48] + "\n" + data.stdout[48:64]

            self.run_screen(
                WarningScreen,
                title="Unfamiliar Checksum",
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

        microsd_dev = find_sd_card_device()

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

        microsd_dev = find_sd_card_device()

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
