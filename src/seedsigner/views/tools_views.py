import base64
import hashlib
import hmac
import json
import logging
import os
import sys
import time
import platform
import binascii
import re
import subprocess
from pathlib import Path
import math
from embit.util import secp256k1
from embit.psbt import PSBT

from embit.descriptor import Descriptor
from embit.descriptor.checksum import checksum
from embit.bip32 import HDKey
from PIL import Image
from PIL.ImageOps import autocontrast
from gettext import gettext as _

from seedsigner.gui.components import FontAwesomeIconConstants, GUIConstants, SeedSignerIconConstants, resize_image_to_fill, reflow_text_into_pages
from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    DireWarningScreen,
    LargeIconStatusScreen,
    WarningScreen,
    ErrorScreen,
)
from seedsigner.gui.screens.scan_screens import ScanScreen
from seedsigner.gui.screens.tools_screens import (ToolsCalcFinalWordDoneScreen, ToolsCalcFinalWordFinalizePromptScreen,
    ToolsCalcFinalWordScreen, ToolsCoinFlipEntryScreen, ToolsDiceEntropyEntryScreen, ToolsImageEntropyFinalImageScreen,
    ToolsImageEntropyLivePreviewScreen, ToolsAddressExplorerAddressTypeScreen, ToolsTextQRTextEntryScreen, ToolsTextQRReviewTextScreen,
    ToolsTextQRTranscribeModePromptScreen, ToolsTranscribeTextQRWholeQRScreen, ToolsTranscribeTextQRZoomedInScreen,
    ToolsTranscribeTextQRConfirmQRPromptScreen, ToolsCommonFilterScreen, ToolsNetworkInfoScreen,
    ToolsBatteryCalibrationIntroScreen, ToolsBatteryCalibrationStartScreen, ToolsBatteryCalibrationRunningScreen)
from seedsigner.helpers import embit_utils, mnemonic_generation
from seedsigner.helpers import bip85_drng, diceware, password_generation
from seedsigner.helpers.iso7816 import format_sw_error
from seedsigner.helpers import ndef_helper
from seedsigner.models.decode_qr import DecodeQR
from seedsigner.models.encode_qr import GenericStaticQrEncoder
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.seed import Seed, InvalidSeedException
from seedsigner.models.seed import XprvSeed
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views.seed_views import (
    SeedDiscardView,
    SeedFinalizeView,
    SeedMnemonicEntryView,
    SeedOptionsView,
    SeedWordsWarningView,
    SeedExportXpubScriptTypeView,
    SeedExportXpubVerifyAddressView,
    LoadSeedView,
    SeedSlip39CreateFromBytesView,
    SeedSlip39RegenerateSharesView,
    AccountNumberView,
    SeedElectrumMnemonicStartView,
    SeedSlip39MnemonicStartView,
    SeedKeeperSelectView,
)

from .view import View, Destination, BackStackView, MainMenuView
from .satochip_bias import ToolsSatochipBiasCheckView
from .keycard_bias import ToolsKeycardBiasCheckView

from seedsigner.hardware.microsd import MicroSD
from seedsigner.hardware.rng_monitor import HardwareRngHealthMonitor
from seedsigner.helpers import seedkeeper_utils
from seedsigner.helpers.satochip_signer import (
    _call_with_timeout,
    _get_extended_key,
    format_path_string,
    normalize_signature_der,
)
from seedsigner.gui.screens import seed_screens
logger = logging.getLogger(__name__)

# Minimum RSA key size in bits to avoid weak keys.
MIN_RSA_KEY_BITS = 2048

from pysatochip.JCconstants import SEEDKEEPER_DIC_TYPE, SEEDKEEPER_DIC_ORIGIN, SEEDKEEPER_DIC_EXPORT_RIGHTS, BIP39_WORDLIST_DIC
from pysatochip.CardConnector import CardConnector, UnexpectedSW12Error
from binascii import unhexlify, hexlify

PASSWORD_TYPE_RANDOM = "random"
PASSWORD_TYPE_DICEWARE_EFF_SHORT = "diceware_eff_short"
PASSWORD_TYPE_DICEWARE_EFF_LONG = "diceware_eff_long"
PASSWORD_TYPE_DICEWARE_BIP39 = "diceware_bip39"
PASSWORD_TYPE_DICE_ROLLS = "dice_rolls"
PASSWORD_TYPE_HEX = "hex"
PASSWORD_TYPE_BASE64 = "base64"
PASSWORD_TYPE_BASE85 = "base85"

PASSWORD_WORD_SEPARATOR_NONE = "none"
PASSWORD_WORD_SEPARATOR_CAPITALISE = "capitalise"
PASSWORD_WORD_SEPARATOR_SPACE = "space"
PASSWORD_WORD_SEPARATOR_DOT = "dot"

PASSWORD_ENTROPY_CAMERA = "camera"
PASSWORD_ENTROPY_DICE = "dice"
PASSWORD_ENTROPY_BIP85 = "bip85"
PASSWORD_ENTROPY_HARDWARE_RNG = "hardware_rng"

BIP85_APP_HEX = 128169
BIP85_APP_BASE64 = 707764
BIP85_APP_BASE85 = 707785
BIP85_APP_DICE = 89101


def _clear_password_entropy_cache(controller) -> None:
    controller.password_generator_entropy_cache = None


def _cache_password_entropy(
    controller,
    *,
    password_type: str,
    strength_bits: int,
    entropy_source: str,
    word_count: int | None,
    roll_data: bytes | str | None = None,
    entropy_bytes: bytes | None = None,
) -> None:
    controller.password_generator_entropy_cache = {
        "password_type": password_type,
        "strength_bits": strength_bits,
        "entropy_source": entropy_source,
        "word_count": word_count,
        "roll_data": roll_data,
        "entropy_bytes": entropy_bytes,
    }


def _get_password_entropy_cache(controller) -> dict | None:
    return getattr(controller, "password_generator_entropy_cache", None)


def _read_secure_rng_bytes(num_bytes: int = 64) -> bytes:
    return os.urandom(num_bytes)


def _ensure_entropy_quality(entropy_bytes: bytes, error_text: str, min_entropy: float = 3.0) -> None:
    if not entropy_bytes or len(set(entropy_bytes)) == 1:
        raise ValueError(error_text)

    entropy_score = HardwareRngHealthMonitor.shannon_entropy(entropy_bytes)
    if entropy_score < min_entropy:
        raise ValueError(error_text)


def _system_entropy_salt() -> bytes:
    system_parts: list[bytes] = []

    def _append_file(path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content:
                system_parts.append(content.encode("utf-8"))
        except Exception:
            # Graceful fallback for non-Linux or unavailable procfs/sysfs files.
            pass

    _append_file("/proc/uptime")

    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
            cpuinfo = f.read()
        serial_line = next((line for line in cpuinfo.splitlines() if line.startswith("Serial")), "")
        if serial_line:
            system_parts.append(serial_line.encode("utf-8"))
    except Exception:
        pass

    try:
        mount_dev = None
        with open("/proc/mounts", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == MicroSD.MOUNT_POINT:
                    mount_dev = parts[0]
                    break
        if mount_dev:
            system_parts.append(mount_dev.encode("utf-8"))
            device = os.path.basename(mount_dev)
            parent_device = re.sub(r"p?\d+$", "", device)
            serial_path = f"/sys/class/block/{parent_device}/device/serial"
            _append_file(serial_path)
    except Exception:
        pass

    _append_file("/proc/meminfo")

    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            cpu_line = f.readline().strip()
        if cpu_line:
            system_parts.append(cpu_line.encode("utf-8"))
    except Exception:
        pass

    try:
        load_avg = os.getloadavg()
        system_parts.append(f"{load_avg[0]:.4f},{load_avg[1]:.4f},{load_avg[2]:.4f}".encode("utf-8"))
    except Exception:
        # Windows and some environments do not implement getloadavg().
        pass

    # Always include cross-platform runtime variability.
    system_parts.append(str(time.time_ns()).encode("utf-8"))
    system_parts.append(str(time.perf_counter_ns()).encode("utf-8"))
    system_parts.append(str(os.getpid()).encode("utf-8"))

    salt = b"|".join(system_parts)
    if not salt:
        salt = str(time.time_ns()).encode("utf-8")
    return salt
def _derive_hardware_rng_entropy_bytes() -> bytes:
    rng_entropy = _read_secure_rng_bytes(64)
    _ensure_entropy_quality(
        rng_entropy,
        _("System RNG entropy too low. Try again later."),
        min_entropy=4.0,
    )
    salt = _system_entropy_salt()
    derived_entropy = hashlib.sha256(rng_entropy + salt).digest()
    _ensure_entropy_quality(
        derived_entropy,
        _("System RNG derived entropy failed health checks."),
    )
    return derived_entropy


def _derive_camera_entropy_bytes(preview_images, final_image) -> bytes | None:
    # Build in some hardware-level uniqueness via CPU unique Serial num
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
            serial_line = next(
                (line for line in f if line.startswith("Serial")), ""
            )
        serial_num = serial_line.split(":")[-1].strip().encode("utf-8")
        serial_hash = hashlib.sha256(serial_num)
        hash_bytes = serial_hash.digest()
    except Exception as e:
        logger.info(repr(e), exc_info=True)
        hash_bytes = hashlib.sha256(os.urandom(32)).digest()

    # Build in modest entropy via millis since power on
    millis_hash = hashlib.sha256(hash_bytes + str(time.time()).encode("utf-8"))
    hash_bytes = millis_hash.digest()

    # Mix in entropy from hardware RNG or os.urandom fallback
    rng_entropy = _read_secure_rng_bytes(32)

    rng_hash = hashlib.sha256(hash_bytes + rng_entropy)
    hash_bytes = rng_hash.digest()

    # Build in better entropy by chaining the preview frames
    for frame in preview_images:
        img_hash = hashlib.sha256(hash_bytes + frame.tobytes())
        hash_bytes = img_hash.digest()

    # Finally build in our headline entropy via the new full-res image
    if not mnemonic_generation.byte_entropy_is_sufficient(final_image.tobytes()):
        return None
    return hashlib.sha256(hash_bytes + final_image.tobytes()).digest()


def _random_charset(random_options: dict) -> str:
    keys_lower = "abcdefghijklmnopqrstuvwxyz"
    keys_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    keys_number = "0123456789"
    keys_symbol_1 = """!@#$%&();:,.-+='"?"""
    keys_symbol_2 = """^*[]{}_\\|<>/`~"""
    charset = ""
    if random_options.get("lower"):
        charset += keys_lower
    if random_options.get("upper"):
        charset += keys_upper
    if random_options.get("digits"):
        charset += keys_number
    if random_options.get("special"):
        charset += keys_symbol_1 + keys_symbol_2
    return charset


def _bip85_supported_password_type(password_type: str) -> bool:
    return password_type in {
        PASSWORD_TYPE_DICEWARE_EFF_SHORT,
        PASSWORD_TYPE_DICEWARE_EFF_LONG,
        PASSWORD_TYPE_DICEWARE_BIP39,
        PASSWORD_TYPE_DICE_ROLLS,
        PASSWORD_TYPE_HEX,
        PASSWORD_TYPE_BASE64,
        PASSWORD_TYPE_BASE85,
    }


def _strength_to_length(entropy_bits: int, alphabet_size: int) -> int:
    return max(1, math.ceil(entropy_bits / math.log2(alphabet_size)))


def _dice_rolls_for_strength(entropy_bits: int) -> int:
    return max(1, math.ceil(entropy_bits / math.log2(6)))


def _is_diceware_password_type(password_type: str) -> bool:
    return password_type in {
        PASSWORD_TYPE_DICEWARE_EFF_SHORT,
        PASSWORD_TYPE_DICEWARE_EFF_LONG,
        PASSWORD_TYPE_DICEWARE_BIP39,
    }


def _diceware_word_count(password_type: str, entropy_bits: int) -> int:
    if password_type == PASSWORD_TYPE_DICEWARE_EFF_SHORT:
        word_bits = math.log2(1296)
    elif password_type == PASSWORD_TYPE_DICEWARE_EFF_LONG:
        word_bits = math.log2(7776)
    else:
        word_bits = 11
    return max(1, math.ceil(entropy_bits / word_bits))


def _format_word_password(words: list[str], separator: str) -> str:
    if separator == PASSWORD_WORD_SEPARATOR_CAPITALISE:
        return "".join(word.capitalize() for word in words)
    if separator == PASSWORD_WORD_SEPARATOR_SPACE:
        return " ".join(words)
    if separator == PASSWORD_WORD_SEPARATOR_DOT:
        return ".".join(words)
    return "".join(words)

class ToolsMenuView(View):
    IMAGE = ButtonOption(" New seed", FontAwesomeIconConstants.CAMERA)
    DICE = ButtonOption("New seed", FontAwesomeIconConstants.DICE)
    SLIP39_IMAGE = ButtonOption("SLIP39 seed", FontAwesomeIconConstants.CAMERA)
    SLIP39_DICE = ButtonOption("SLIP39 seed", FontAwesomeIconConstants.DICE)
    KEYBOARD = ButtonOption("Calc 12th/24th word", FontAwesomeIconConstants.KEYBOARD)
    ADDRESS_EXPLORER = ButtonOption("Address explorer")
    VERIFY_ADDRESS = ButtonOption("Verify address")
    TEXTQRCODE = ButtonOption("Text QR Code")
    PASSWORD_GENERATOR = ButtonOption("Password Generator", FontAwesomeIconConstants.LOCK)
    SMARTCARD = ButtonOption("Smartcard Tools", FontAwesomeIconConstants.LOCK)
    MICROSD = ButtonOption("MicroSD Tools")
    BATTERY_CALIBRATION = ButtonOption("Battery Calibration")
    GPG = ButtonOption("GPG Tools")
    CLEAR_DESCRIPTOR = ButtonOption("Clear Multisig Descriptor")
    NETWORK_INFO = ButtonOption("Network Info")

    def __init__(self, include_password_generator: bool = True):
        super().__init__()
        self.include_password_generator = include_password_generator

    def run(self):
        button_data = [self.IMAGE, self.DICE]

        if getattr(self, "include_password_generator", True):
            button_data.append(self.PASSWORD_GENERATOR)
        
        if self.settings.get_value(SettingsConstants.SETTING__SLIP39_SEEDS) == SettingsConstants.OPTION__ENABLED:
            button_data.extend([self.SLIP39_IMAGE, self.SLIP39_DICE])
        
        if self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_SUPPORT) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.SMARTCARD)
        
        from seedsigner.hardware.battery_hat import BatteryHat
        battery_calibration_button = self.BATTERY_CALIBRATION if BatteryHat.get_instance().is_enabled() else None

        button_data.extend([
            self.KEYBOARD,
            self.ADDRESS_EXPLORER,
            self.VERIFY_ADDRESS,
            self.TEXTQRCODE,
            self.MICROSD,
            battery_calibration_button,
            self.NETWORK_INFO if Path("/usr/bin/network-info").is_file() else None,
            self.GPG,
            self.CLEAR_DESCRIPTOR,
        ])
        button_data = [button for button in button_data if button is not None]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Tools"),
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.IMAGE:
            return Destination(ToolsImageEntropyLivePreviewView)

        elif button_data[selected_menu_num] == self.DICE:
            return Destination(ToolsDiceEntropyMnemonicLengthView)

        elif button_data[selected_menu_num] == self.SLIP39_IMAGE:
            self.controller.create_slip39 = True
            return Destination(ToolsImageEntropyLivePreviewView)

        elif button_data[selected_menu_num] == self.SLIP39_DICE:
            self.controller.create_slip39 = True
            return Destination(ToolsDiceEntropyMnemonicLengthView)

        elif button_data[selected_menu_num] == self.KEYBOARD:
            return Destination(ToolsCalcFinalWordNumWordsView)

        elif button_data[selected_menu_num] == self.ADDRESS_EXPLORER:
            return Destination(ToolsAddressExplorerSelectSourceView)

        elif button_data[selected_menu_num] == self.VERIFY_ADDRESS:
            from seedsigner.views.scan_views import ScanAddressView
            return Destination(ScanAddressView)

        elif button_data[selected_menu_num] == self.TEXTQRCODE:
            return Destination(ToolsTextQRView)

        elif button_data[selected_menu_num] == self.PASSWORD_GENERATOR:
            return Destination(ToolsPasswordGeneratorTypeView)

        elif button_data[selected_menu_num] == self.SMARTCARD:
            return Destination(ToolsSmartcardMenuView)
        
        elif button_data[selected_menu_num] == self.MICROSD:
            return Destination(ToolsMicroSDMenuView)

        elif button_data[selected_menu_num] == self.BATTERY_CALIBRATION:
            return Destination(ToolsBatteryCalibrationView)

        elif button_data[selected_menu_num] == self.NETWORK_INFO:
            return Destination(ToolsNetworkInfoView)

        elif button_data[selected_menu_num] == self.GPG:
            return Destination(ToolsGPGMenuView)

        elif button_data[selected_menu_num] == self.CLEAR_DESCRIPTOR:
            self.controller.multisig_wallet_descriptor = None
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Multisig Descriptor Cleared",
                show_back_button=False,
            )
            return Destination(BackStackView)



class ToolsBatteryCalibrationView(View):
    CALIBRATION_STEP = 5

    def run(self):
        from seedsigner.hardware.battery_hat import BatteryHat

        battery_hat = BatteryHat.get_instance()
        if not battery_hat.is_enabled():
            return Destination(BackStackView)

        battery_hat.process_discharge_log(step=self.CALIBRATION_STEP)

        microsd = MicroSD.get_instance()
        if not microsd.is_inserted:
            self.run_screen(
                WarningScreen,
                title=_("microSD card not detected"),
                status_headline=None,
                text=_("Insert a microSD card to save the discharge log."),
                button_data=[ButtonOption(_("Back"))],
            )
            return Destination(BackStackView)

        ret = self.run_screen(ToolsBatteryCalibrationIntroScreen)
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        ret = self.run_screen(ToolsBatteryCalibrationStartScreen)
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        log_path = battery_hat.get_discharge_log_path()
        ret = ToolsBatteryCalibrationRunningScreen(
            log_path=log_path,
            battery_hat=battery_hat,
        ).display()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(BackStackView)


class ToolsNetworkInfoView(View):
    def __init__(self, page_num: int = 0, paged_info: list[str] | None = None):
        super().__init__()
        self.page_num = page_num
        self.paged_info = paged_info


    def _get_network_info(self) -> str | None:
        try:
            result = subprocess.run(
                ["/usr/bin/network-info"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            return ""

        if result.returncode != 0:
            return ""

        return result.stdout.strip()


    def _prepare_pages(self) -> list[str] | None:
        network_info = self._get_network_info()
        if not network_info:
            return None

        start_y = GUIConstants.TOP_NAV_HEIGHT + GUIConstants.COMPONENT_PADDING
        end_y = self.renderer.canvas_height - GUIConstants.EDGE_PADDING - GUIConstants.BUTTON_HEIGHT - GUIConstants.COMPONENT_PADDING
        info_height = end_y - start_y

        return reflow_text_into_pages(
            text=network_info,
            width=self.renderer.canvas_width - 2 * GUIConstants.EDGE_PADDING,
            height=info_height,
            font_name=GUIConstants.FIXED_WIDTH_FONT_NAME,
            font_size=GUIConstants.get_body_font_size(),
        )


    def run(self):
        if self.paged_info is None:
            self.paged_info = self._prepare_pages()

        if not self.paged_info:
            self.run_screen(
                ErrorScreen,
                title=_("Network Info"),
                status_headline=_("Unavailable"),
                text=_("Unable to load network information."),
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        selected_menu_num = self.run_screen(
            ToolsNetworkInfoScreen,
            page_num=self.page_num,
            paged_info=self.paged_info,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if self.page_num >= len(self.paged_info) - 1:
            return Destination(BackStackView)

        return Destination(
            ToolsNetworkInfoView,
            view_args=dict(page_num=self.page_num + 1, paged_info=self.paged_info),
        )



"""****************************************************************************
    Image entropy Views
****************************************************************************"""
class ToolsImageEntropyLivePreviewView(View):
    def __init__(self, next_view: type = None, next_view_args: dict | None = None):
        super().__init__()
        self.next_view = next_view
        self.next_view_args = next_view_args

    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsImageEntropyLivePreviewScreen
        self.controller.image_entropy_preview_frames = None
        self.controller.image_entropy_final_image = None
        ret = self.run_screen(ToolsImageEntropyLivePreviewScreen)

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if isinstance(ret, tuple) and len(ret) == 2:
            self.controller.image_entropy_preview_frames, self.controller.image_entropy_final_image = ret
        else:
            self.controller.image_entropy_preview_frames = ret
        return Destination(
            ToolsImageEntropyFinalImageView,
            view_args=dict(next_view=self.next_view, next_view_args=self.next_view_args),
        )



class ToolsImageEntropyFinalImageView(View):
    def __init__(self, next_view: type = None, next_view_args: dict | None = None):
        super().__init__()
        self.next_view = next_view
        self.next_view_args = next_view_args

    def run(self):
        from PIL import Image
        from PIL.ImageOps import autocontrast
        from seedsigner.gui.screens.tools_screens import ToolsImageEntropyFinalImageScreen
        if not self.controller.image_entropy_final_image:
            from seedsigner.hardware.camera import Camera
            # Take the final full-res image
            camera = Camera.get_instance()
            img = None
            try:
                camera.start_video_stream_mode()
                time.sleep(1.0)
                for attempt in range(10):
                    img = camera.read_video_stream(as_image=True)
                    if img is not None:
                        break
                    logger.info(f"Attempt {attempt + 1} to capture entropy frame")
                    time.sleep(0.2)
            finally:
                camera.stop_video_stream_mode()

            if img is None:
                raise Exception("Failed to capture camera entropy image")

            self.controller.image_entropy_final_image = img

        # Prep a copy of the image for display:
        #   * Boost the contrast for better presentation (but preserve the original pixels)
        #   * Resize it to fit the screen
        boosted_version = autocontrast(self.controller.image_entropy_final_image, cutoff=2)
        display_version = resize_image_to_fill(
            boosted_version,
            target_size_x=self.canvas_width,
            target_size_y=self.canvas_height,
            sampling_method=Image.Resampling.BICUBIC,
        )
        
        ret = self.run_screen(
            ToolsImageEntropyFinalImageScreen,
            final_image=display_version
        )

        if ret == RET_CODE__BACK_BUTTON:
            # Go back to live preview and reshoot
            self.controller.image_entropy_final_image = None
            return Destination(BackStackView)
        
        next_view = self.next_view or ToolsImageEntropyMnemonicLengthView
        return Destination(next_view, view_args=self.next_view_args)



class ToolsImageEntropyMnemonicLengthView(View):
    TWELVE_WORDS = ButtonOption("12 words", return_data=12)
    FIFTEEN_WORDS = ButtonOption("15 words", return_data=15)
    EIGHTEEN_WORDS = ButtonOption("18 words", return_data=18)
    TWENTYONE_WORDS = ButtonOption("21 words", return_data=21)
    TWENTYFOUR_WORDS = ButtonOption("24 words", return_data=24)

    def run(self):
        if getattr(self.controller, "create_slip39", False):
            twenty = ButtonOption("20 words", return_data=20)
            thirty_three = ButtonOption("33 words", return_data=33)
            button_data = [twenty, thirty_three]
        else:
            allowed = self.settings.get_value(SettingsConstants.SETTING__SEED_WORD_LENGTHS)
            options = {
                12: self.TWELVE_WORDS,
                15: self.FIFTEEN_WORDS,
                18: self.EIGHTEEN_WORDS,
                21: self.TWENTYONE_WORDS,
                24: self.TWENTYFOUR_WORDS,
            }
            button_data = [options[l] for l in allowed]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Mnemonic Length"),
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        mnemonic_length = button_data[selected_menu_num].return_data

        from seedsigner.gui.screens.screen import LoadingScreenThread
        loading_screen = LoadingScreenThread(text=_("Processing..."))
        loading_screen.start()

        preview_images = self.controller.image_entropy_preview_frames
        seed_entropy_image = self.controller.image_entropy_final_image

        final_hash = _derive_camera_entropy_bytes(preview_images, seed_entropy_image)
        if final_hash is None:
            loading_screen.stop()
            self.run_screen(
                ErrorScreen,
                title=_("Poor Entropy"),
                status_headline=None,
                text=_("Camera entropy didn't appear random enough. Please try again."),
            )
            self.controller.image_entropy_preview_frames = None
            self.controller.image_entropy_final_image = None
            return Destination(BackStackView)

        if mnemonic_length in mnemonic_generation.ENTROPY_BYTES_REQUIRED:
            final_hash = final_hash[:mnemonic_generation.ENTROPY_BYTES_REQUIRED[mnemonic_length]]

        if getattr(self.controller, "create_slip39", False):
            secret = final_hash
        else:
            mnemonic = mnemonic_generation.generate_mnemonic_from_bytes(final_hash)

        loading_screen.stop()

        # Image should never get saved nor stick around in memory
        seed_entropy_image = None
        preview_images = None
        if not getattr(self.controller, "create_slip39", False):
            final_hash = None
        hash_bytes = None
        self.controller.image_entropy_preview_frames = None
        self.controller.image_entropy_final_image = None

        if getattr(self.controller, "create_slip39", False):
            self.controller.create_slip39 = False
            return Destination(SeedSlip39CreateFromBytesView, view_args=dict(secret=secret), clear_history=True)
        else:
            seed = Seed(mnemonic, wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE))
            self.controller.storage.set_pending_seed(seed)
            return Destination(SeedWordsWarningView, view_args={"seed_num": None}, clear_history=True)



"""****************************************************************************
    Dice rolls Views
****************************************************************************"""
class ToolsDiceEntropyMnemonicLengthView(View):
    """Prompt for mnemonic length when using dice entropy."""

    TWELVE = ButtonOption("12 words", return_data=12)
    FIFTEEN = ButtonOption("15 words", return_data=15)
    EIGHTEEN = ButtonOption("18 words", return_data=18)
    TWENTY_ONE = ButtonOption("21 words", return_data=21)
    TWENTY_FOUR = ButtonOption("24 words", return_data=24)
    TWENTY = ButtonOption(
        _("20 words ({} rolls)").format(mnemonic_generation.DICE_ROLLS_REQUIRED[12]),
        return_data=mnemonic_generation.DICE_ROLLS_REQUIRED[12],
    )
    THIRTY_THREE = ButtonOption(
        _("33 words ({} rolls)").format(mnemonic_generation.DICE_ROLLS_REQUIRED[24]),
        return_data=mnemonic_generation.DICE_ROLLS_REQUIRED[24],
    )

    def run(self):
        if getattr(self.controller, "create_slip39", False):
            button_data = [self.TWENTY, self.THIRTY_THREE]
        else:
            allowed = self.settings.get_value(SettingsConstants.SETTING__SEED_WORD_LENGTHS)
            options = {
                12: self.TWELVE,
                15: self.FIFTEEN,
                18: self.EIGHTEEN,
                21: self.TWENTY_ONE,
                24: self.TWENTY_FOUR,
            }
            button_data = [options[l] for l in allowed]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Mnemonic Length"),
            is_bottom_list=True,
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if getattr(self.controller, "create_slip39", False):
            total_rolls = button_data[selected_menu_num].return_data
        else:
            selected_length = button_data[selected_menu_num].return_data
            total_rolls = mnemonic_generation.DICE_ROLLS_REQUIRED[selected_length]
        return Destination(
            ToolsDiceEntropyEntryView,
            view_args=dict(total_rolls=total_rolls),
        )



class ToolsDiceEntropyEntryView(View):
    def __init__(self, total_rolls: int):
        super().__init__()
        self.total_rolls = total_rolls
    

    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsDiceEntropyEntryScreen
        ret = self.run_screen(
            ToolsDiceEntropyEntryScreen,
            return_after_n_chars=self.total_rolls,
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if not mnemonic_generation.dice_entropy_is_sufficient(ret):
            self.run_screen(
                ErrorScreen,
                title=_("Poor Entropy"),
                status_headline=None,
                text=_("Dice rolls didn't appear random enough. Please try again."),
            )
            return Destination(BackStackView)
        from seedsigner.gui.screens.screen import LoadingScreenThread
        loading_screen = LoadingScreenThread(text=_("Processing..."))
        loading_screen.start()

        if getattr(self.controller, "create_slip39", False):
            entropy_bytes = mnemonic_generation.generate_bytes_from_dice(ret)
            self.controller.create_slip39 = False
            loading_screen.stop()
            return Destination(SeedSlip39CreateFromBytesView, view_args=dict(secret=entropy_bytes), clear_history=True)
        else:
            dice_seed_phrase = mnemonic_generation.generate_mnemonic_from_dice(
                ret,
                wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE),
            )
            seed = Seed(dice_seed_phrase, wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE))
            self.controller.storage.set_pending_seed(seed)
            loading_screen.stop()
            return Destination(SeedWordsWarningView, view_args={"seed_num": None}, clear_history=True)



"""****************************************************************************
    Calc final word Views
****************************************************************************"""
class ToolsCalcFinalWordNumWordsView(View):
    TWELVE = ButtonOption("12 words", return_data=12)
    FIFTEEN = ButtonOption("15 words", return_data=15)
    EIGHTEEN = ButtonOption("18 words", return_data=18)
    TWENTY_ONE = ButtonOption("21 words", return_data=21)
    TWENTY_FOUR = ButtonOption("24 words", return_data=24)

    def run(self):
        allowed = self.settings.get_value(SettingsConstants.SETTING__SEED_WORD_LENGTHS)
        options = {
            12: self.TWELVE,
            15: self.FIFTEEN,
            18: self.EIGHTEEN,
            21: self.TWENTY_ONE,
            24: self.TWENTY_FOUR,
        }
        button_data = [options[l] for l in allowed]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Mnemonic Length"),
            is_bottom_list=True,
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        self.controller.storage.init_pending_mnemonic(button_data[selected_menu_num].return_data)

        return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True))



class ToolsCalcFinalWordFinalizePromptView(View):
    # TRANSLATOR_NOTE: Label to gather entropy through coin tosses
    COIN_FLIPS = ButtonOption("Coin flip entropy")

    # TRANSLATOR_NOTE: Label to gather entropy through user specified BIP-39 word
    SELECT_WORD = ButtonOption("Word selection entropy")

    # TRANSLATOR_NOTE: Label to allow user to default entropy as all-zeros
    ZEROS = ButtonOption("Finalize with zeros")

    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsCalcFinalWordFinalizePromptScreen
        mnemonic = self.controller.storage.pending_mnemonic
        mnemonic_length = len(mnemonic)
        total_bits = mnemonic_generation.ENTROPY_BYTES_REQUIRED[mnemonic_length] * 8
        num_entropy_bits = total_bits - ((mnemonic_length - 1) * 11)

        button_data = [self.COIN_FLIPS, self.SELECT_WORD, self.ZEROS]
        selected_menu_num = self.run_screen(
            ToolsCalcFinalWordFinalizePromptScreen,
            mnemonic_length=mnemonic_length,
            num_entropy_bits=num_entropy_bits,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.COIN_FLIPS:
            return Destination(ToolsCalcFinalWordCoinFlipsView)

        elif button_data[selected_menu_num] == self.SELECT_WORD:
            # Clear the final word slot, just in case we're returning via BACK button
            self.controller.storage.update_pending_mnemonic(None, mnemonic_length - 1)
            return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True, cur_word_index=mnemonic_length - 1))

        elif button_data[selected_menu_num] == self.ZEROS:
            # User skipped the option to select a final word to provide last bits of
            # entropy. We'll insert all zeros and piggy-back on the coin flip attr
            wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
            self.controller.storage.update_pending_mnemonic(Seed.get_wordlist(wordlist_language_code)[0], mnemonic_length - 1)
            return Destination(ToolsCalcFinalWordShowFinalWordView, view_args=dict(coin_flips="0" * num_entropy_bits))



class ToolsCalcFinalWordCoinFlipsView(View):
    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsCoinFlipEntryScreen
        mnemonic_length = len(self.controller.storage.pending_mnemonic)

        total_bits = mnemonic_generation.ENTROPY_BYTES_REQUIRED[mnemonic_length] * 8
        total_flips = total_bits - ((mnemonic_length - 1) * 11)
        
        ret_val = self.run_screen(
            ToolsCoinFlipEntryScreen,
            return_after_n_chars=total_flips,
        )

        if ret_val == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        else:
            return Destination(ToolsCalcFinalWordShowFinalWordView, view_args=dict(coin_flips=ret_val))



class ToolsCalcFinalWordShowFinalWordView(View):
    NEXT = ButtonOption("Next")

    def __init__(self, coin_flips: str = None):
        super().__init__()
        # Construct the actual final word. The user's selected_final_word
        # contributes:
        #   * 3 bits to a 24-word seed (plus 8-bit checksum)
        #   * 7 bits to a 12-word seed (plus 4-bit checksum)
        from seedsigner.helpers import mnemonic_generation

        wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
        wordlist = Seed.get_wordlist(wordlist_language_code)

        # Prep the user's selected word / coin flips and the actual final word for
        # the display.
        if coin_flips:
            self.selected_final_word = None
            self.selected_final_bits = coin_flips
        else:
            # Convert the user's final word selection into its binary index equivalent
            self.selected_final_word = self.controller.storage.pending_mnemonic[-1]
            self.selected_final_bits = format(wordlist.index(self.selected_final_word), '011b')

        if coin_flips:
            # fill the last bits (what will eventually be the checksum) with zeros
            binary_string = coin_flips + "0" * (11 - len(coin_flips))

            # retrieve the matching word for the resulting index
            wordlist_index = int(binary_string, 2)
            wordlist = Seed.get_wordlist(self.controller.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE))
            word = wordlist[wordlist_index]

            # update the pending mnemonic with our new "final" (pre-checksum) word
            self.controller.storage.update_pending_mnemonic(word, -1)

        # Now calculate the REAL final word (has a proper checksum)
        final_mnemonic = mnemonic_generation.calculate_checksum(
            mnemonic=self.controller.storage.pending_mnemonic,
            wordlist_language_code=wordlist_language_code,
        )

        # Update our pending mnemonic with the real final word
        self.controller.storage.update_pending_mnemonic(final_mnemonic[-1], -1)

        mnemonic = self.controller.storage.pending_mnemonic
        mnemonic_length = len(mnemonic)

        # And grab the actual final word's checksum bits
        self.actual_final_word = self.controller.storage.pending_mnemonic[-1]
        total_bits = mnemonic_generation.ENTROPY_BYTES_REQUIRED[mnemonic_length] * 8
        num_entropy_bits = total_bits - ((mnemonic_length - 1) * 11)
        num_checksum_bits = 11 - num_entropy_bits
        self.checksum_bits = format(wordlist.index(self.actual_final_word), '011b')[-num_checksum_bits:]


    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsCalcFinalWordScreen
        button_data = [self.NEXT]

        # TRANSLATOR_NOTE: label to calculate the last word of a BIP-39 mnemonic seed phrase
        title = _("Final Word Calc")

        selected_menu_num = self.run_screen(
            ToolsCalcFinalWordScreen,
            title=title,
            button_data=button_data,
            selected_final_word=self.selected_final_word,
            selected_final_bits=self.selected_final_bits,
            checksum_bits=self.checksum_bits,
            actual_final_word=self.actual_final_word,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.NEXT:
            return Destination(ToolsCalcFinalWordDoneView)



class ToolsCalcFinalWordDoneView(View):
    LOAD = ButtonOption("Load seed")
    DISCARD = ButtonOption("Discard", button_label_color="red")

    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsCalcFinalWordDoneScreen
        mnemonic = self.controller.storage.pending_mnemonic
        mnemonic_word_length = len(mnemonic)
        final_word = mnemonic[-1]

        button_data = [self.LOAD, self.DISCARD]

        selected_menu_num = self.run_screen(
            ToolsCalcFinalWordDoneScreen,
            final_word=final_word,
            mnemonic_word_length=mnemonic_word_length,
            fingerprint=self.controller.storage.get_pending_mnemonic_fingerprint(
                self.settings.get_value(SettingsConstants.SETTING__NETWORK),
                wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE),
            ),
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        self.controller.storage.convert_pending_mnemonic_to_pending_seed(
            wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE),
        )

        if button_data[selected_menu_num] == self.LOAD:
            return Destination(SeedFinalizeView)
        
        elif button_data[selected_menu_num] == self.DISCARD:
            return Destination(SeedDiscardView)



"""****************************************************************************
    Address Explorer Views
****************************************************************************"""
class ToolsAddressExplorerSelectSourceView(View):
    SCAN_SEED = ButtonOption("Scan a seed", SeedSignerIconConstants.QRCODE)
    SCAN_DESCRIPTOR = ButtonOption("Scan wallet descriptor", SeedSignerIconConstants.QRCODE)
    TYPE_12WORD = ButtonOption("Enter 12-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=12)
    TYPE_15WORD = ButtonOption("Enter 15-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=15)
    TYPE_18WORD = ButtonOption("Enter 18-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=18)
    TYPE_21WORD = ButtonOption("Enter 21-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=21)
    TYPE_24WORD = ButtonOption("Enter 24-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=24)
    LOADED_DESCRIPTOR = ButtonOption("Loaded Multisig Descriptor")
    SATOCHIP = ButtonOption("Load from Satochip", SeedSignerIconConstants.FINGERPRINT)
    TYPE_ELECTRUM = ButtonOption("Electrum Seed", FontAwesomeIconConstants.KEYBOARD)

    def run(self):
        from seedsigner.controller import Controller

        seeds = self.controller.storage.seeds
        button_data = []
        for seed in seeds:
            button_str = seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
            button_data.append(ButtonOption(button_str, SeedSignerIconConstants.FINGERPRINT))

        if self.controller.multisig_wallet_descriptor:
            button_data.append(self.LOADED_DESCRIPTOR)

        seed_lengths = self.settings.get_value(SettingsConstants.SETTING__SEED_WORD_LENGTHS)
        options = {
            12: self.TYPE_12WORD,
            15: self.TYPE_15WORD,
            18: self.TYPE_18WORD,
            21: self.TYPE_21WORD,
            24: self.TYPE_24WORD,
        }
        button_data = button_data + [self.SCAN_SEED, self.SCAN_DESCRIPTOR]
        if (
            self.settings.get_value(SettingsConstants.SETTING__SATOCHIP_SUPPORT)
            == SettingsConstants.OPTION__ENABLED
        ):
            button_data.append(self.SATOCHIP)
        button_data += [options[l] for l in seed_lengths]
        if self.settings.get_value(SettingsConstants.SETTING__ELECTRUM_SEEDS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TYPE_ELECTRUM)

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Address Explorer"),
            button_data=button_data,
            is_button_text_centered=False,
            is_bottom_list=True,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Most of the options require us to go through a side flow(s) before we can
        # continue to the address explorer. Set the Controller-level flow so that it
        # knows to re-route us once the side flow is complete.        
        self.controller.resume_main_flow = self.controller.FLOW__ADDRESS_EXPLORER

        if len(seeds) > 0 and selected_menu_num < len(seeds):
            # User selected one of the n seeds
            return Destination(
                SeedExportXpubScriptTypeView,
                view_args=dict(
                    seed_num=selected_menu_num,
                    sig_type=SettingsConstants.SINGLE_SIG,
                )
            )
        
        
        elif button_data[selected_menu_num] == self.LOADED_DESCRIPTOR:
            return Destination(ToolsAddressExplorerAddressTypeView)

        elif button_data[selected_menu_num] == self.SCAN_SEED:
            from seedsigner.views.scan_views import ScanSeedQRView
            return Destination(ScanSeedQRView)

        elif button_data[selected_menu_num] == self.SCAN_DESCRIPTOR:
            from seedsigner.views.scan_views import ScanWalletDescriptorView
            return Destination(ScanWalletDescriptorView)

        elif button_data[selected_menu_num] == self.SATOCHIP:
            return Destination(SatochipLoadDescriptorScriptTypeView)

        elif button_data[selected_menu_num] in [self.TYPE_12WORD, self.TYPE_15WORD, self.TYPE_18WORD, self.TYPE_21WORD, self.TYPE_24WORD]:
            from seedsigner.views.seed_views import SeedMnemonicEntryView

            self.controller.storage.init_pending_mnemonic(num_words=button_data[selected_menu_num].return_data)

            return Destination(SeedMnemonicEntryView)

        elif button_data[selected_menu_num] == self.TYPE_ELECTRUM:
            from seedsigner.views.seed_views import SeedElectrumMnemonicStartView
            return Destination(SeedElectrumMnemonicStartView)



class ToolsAddressExplorerAddressTypeView(View):
    # TRANSLATOR_NOTE: label for addresses where others send us incoming payments
    RECEIVE = ButtonOption("Receive addresses")

    # TRANSLATOR_NOTE: label for addresses that collect the change from our own outgoing payments
    CHANGE = ButtonOption("Change addresses")


    def __init__(self, seed_num: int = None, script_type: str = None, custom_derivation: str = None, account: int = 0):
        """
            If the explorer source is a seed, `seed_num` and `script_type` must be
            specified. `custom_derivation` can be specified as needed.

            If the source is a multisig or single sig wallet descriptor, `seed_num`,
            `script_type`, and `custom_derivation` should be `None`.
        """
        super().__init__()
        self.seed_num = seed_num
        self.script_type = script_type
        self.custom_derivation = custom_derivation
        self.account = account
    
        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)

        # Store everything in the Controller's `address_explorer_data` so we don't have
        # to keep passing vals around from View to View and recalculating.
        data = dict(
            seed_num=seed_num,
            network=self.settings.get_value(SettingsConstants.SETTING__NETWORK),
            embit_network=SettingsConstants.map_network_to_embit(network),
            script_type=script_type,
            account=account,
        )
        if self.seed_num is not None:
            self.seed = self.controller.storage.seeds[seed_num]
            data["seed_num"] = self.seed
            seed_derivation_override = self.seed.derivation_override(sig_type=SettingsConstants.SINGLE_SIG)

            if self.script_type == SettingsConstants.CUSTOM_DERIVATION:
                derivation_path = self.custom_derivation
            elif seed_derivation_override:
                derivation_path = seed_derivation_override
            else:
                from seedsigner.helpers import embit_utils
                derivation_path = embit_utils.get_standard_derivation_path(
                    network=self.settings.get_value(SettingsConstants.SETTING__NETWORK),
                    wallet_type=SettingsConstants.SINGLE_SIG,
                    script_type=self.script_type,
                    account=self.account,
                )

            data["derivation_path"] = derivation_path
            data["xpub"] = self.seed.get_xpub(derivation_path, network=network)
        
        else:
            data["wallet_descriptor"] = self.controller.multisig_wallet_descriptor

        self.controller.address_explorer_data = data


    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsAddressExplorerAddressTypeScreen
        data = self.controller.address_explorer_data

        wallet_descriptor_display_name = None
        if "wallet_descriptor" in data:
            from seedsigner.helpers.embit_utils import get_multisig_policy
            if data["wallet_descriptor"].is_basic_multisig:
                threshold, n = get_multisig_policy(data["wallet_descriptor"])
                # TRANSLATOR_NOTE: Multisig policy. For a "2 / 3 multisig" policy, "threshold" = 2; "n" = 3
                wallet_descriptor_display_name = _("{threshold} / {n} multisig").format(
                    threshold=threshold, n=n
                )
            else:
                # Single-sig descriptors (e.g. Satochip xpub-only loading) can also
                # be explored; fall back to embit's brief policy text.
                wallet_descriptor_display_name = data["wallet_descriptor"].brief_policy.split("multisig")[0].strip()

        script_type = data["script_type"] if "script_type" in data else None

        button_data = [self.RECEIVE, self.CHANGE]

        selected_menu_num = self.run_screen(
            ToolsAddressExplorerAddressTypeScreen,
            button_data=button_data,
            fingerprint=self.seed.get_fingerprint() if self.seed_num is not None else None,
            wallet_descriptor_display_name=wallet_descriptor_display_name,
            script_type=script_type,
            custom_derivation_path=self.custom_derivation,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            # If we entered this flow via an already-loaded seed's SeedOptionsView, we
            # need to clear the `resume_main_flow` so that we don't get stuck in a 
            # SeedOptionsView redirect loop.
            # TODO: Refactor to a cleaner `BackStack.get_previous_View_cls()`
            if len(self.controller.back_stack) > 1 and self.controller.back_stack[-2].View_cls == SeedOptionsView:
                # The BackStack has the current View on the top with the real "back" in second position.
                self.controller.resume_main_flow = None
                self.controller.address_explorer_data = None
            return Destination(BackStackView)
        
        elif button_data[selected_menu_num] in [self.RECEIVE, self.CHANGE]:
            return Destination(ToolsAddressExplorerAddressListView, view_args=dict(is_change=button_data[selected_menu_num] == self.CHANGE))



class ToolsAddressExplorerAddressListView(View):
    def __init__(self, is_change: bool = False, start_index: int = 0, selected_button_index: int = 0, initial_scroll: int = 0):
        super().__init__()
        self.is_change = is_change
        self.start_index = start_index
        self.selected_button_index = selected_button_index
        self.initial_scroll = initial_scroll


    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsAddressExplorerAddressListScreen
        self.loading_screen = None

        addresses = []
        button_data = []
        data = self.controller.address_explorer_data
        addrs_per_screen = 10

        addr_storage_key = "receive_addrs"
        if self.is_change:
            addr_storage_key = "change_addrs"

        if addr_storage_key in data and len(data[addr_storage_key]) >= self.start_index + addrs_per_screen:
            # We already calculated this range of addresses; just retrieve them
            addresses = data[addr_storage_key][self.start_index:self.start_index + addrs_per_screen]

        else:
            try:
                from seedsigner.gui.screens.screen import LoadingScreenThread
                from seedsigner.helpers import embit_utils
                # TRANSLATOR_NOTE: a status message that our payment addresses are being calculated
                self.loading_screen = LoadingScreenThread(text=_("Calculating addrs..."))
                self.loading_screen.start()

                if addr_storage_key not in data:
                    data[addr_storage_key] = []

                if "xpub" in data:
                    # Single sig explore from seed
                    if "script_type" in data and data["script_type"] != SettingsConstants.CUSTOM_DERIVATION:
                        # Standard derivation path
                        for i in range(self.start_index, self.start_index + addrs_per_screen):
                            address = embit_utils.get_single_sig_address(xpub=data["xpub"], script_type=data["script_type"], index=i, is_change=self.is_change, embit_network=data["embit_network"])
                            addresses.append(address)
                            data[addr_storage_key].append(address)
                    else:
                        # TODO: Custom derivation path
                        raise Exception(_("Custom Derivation address explorer not yet implemented"))

                elif "wallet_descriptor" in data:
                    from embit.descriptor import Descriptor
                    descriptor: Descriptor = data["wallet_descriptor"]
                    for i in range(self.start_index, self.start_index + addrs_per_screen):
                        address = embit_utils.get_multisig_address(descriptor=descriptor, index=i, is_change=self.is_change, embit_network=data["embit_network"])
                        addresses.append(address)
                        data[addr_storage_key].append(address)

            finally:
                # Everything is set. Stop the loading screen
                self.loading_screen.stop()

        selected_menu_num = self.run_screen(
            ToolsAddressExplorerAddressListScreen,
            title=_("Receive Addrs") if not self.is_change else _("Change Addrs"),
            start_index=self.start_index,
            addresses=addresses,
            selected_button=self.selected_button_index,
            scroll_y_initial_offset=self.initial_scroll,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        if selected_menu_num == len(addresses):
            # User clicked NEXT
            return Destination(ToolsAddressExplorerAddressListView, view_args=dict(is_change=self.is_change, start_index=self.start_index + addrs_per_screen))
        
        # Preserve the list's current scroll so we can return to the same spot
        initial_scroll = self.screen.buttons[0].scroll_y

        index = selected_menu_num + self.start_index
        return Destination(ToolsAddressExplorerAddressView, view_args=dict(index=index, address=addresses[selected_menu_num], is_change=self.is_change, start_index=self.start_index, parent_initial_scroll=initial_scroll), skip_current_view=True)



class ToolsAddressExplorerAddressView(View):
    # TODO: pull address str from controller.address_explorer_data and pass addr_storage_key and addr_index instead
    def __init__(self, index: int, address: str, is_change: bool, start_index: int, parent_initial_scroll: int = 0):
        super().__init__()
        self.index = index
        self.address = address
        self.is_change = is_change
        self.start_index = start_index
        self.parent_initial_scroll = parent_initial_scroll

    
    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import GenericStaticQrEncoder

        qr_encoder = GenericStaticQrEncoder(data=self.address)
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=qr_encoder,
        )
    
        # Exiting/Cancelling the QR display screen always returns to the list
        return Destination(ToolsAddressExplorerAddressListView, view_args=dict(is_change=self.is_change, start_index=self.start_index, selected_button_index=self.index - self.start_index, initial_scroll=self.parent_initial_scroll), skip_current_view=True)

"""****************************************************************************
    Text QR Code Views
****************************************************************************"""
class ToolsTextQRView(View):
    def run(self):
        ENCODE = ButtonOption("Encode text")
        DECODE = ButtonOption("Decode QR code")

        button_data = [ENCODE, DECODE]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Text QR Code"),
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == ENCODE:
            return Destination(ToolsTextQRTextEntryView)

        elif button_data[selected_menu_num] == DECODE:
            return Destination(ToolsTextQRScanQRCodeView)



# Re-exports for backward compatibility
from .microsd_views import *  # noqa: F401, F403
from .smartcard_views import *  # noqa: F401, F403
from .gpg_views import *  # noqa: F401, F403
from .password_generator_views import *  # noqa: F401, F403

# Star imports skip underscore-prefixed names; explicitly re-export them here.
from .password_generator_views import (  # noqa: F401
    _cache_password_entropy,
    _clear_password_entropy_cache,
    _diceware_word_count,
    _get_password_entropy_cache,
    _is_diceware_password_type,
    _save_password_to_seedkeeper,
    _text_qr_done_destination,
)

from .smartcard_views import (  # noqa: F401
    _get_specter_card_api,
    _normalize_bip39_mnemonic_text,
    _prompt_keycard_new_pin,
    _prompt_keycard_new_puk,
    _prompt_specter_new_pin,
    _unlock_specter_card_if_needed,
)

from .gpg_views import (  # noqa: F401
    _bip85_key_type_choices as _bip85_key_type_choices_gpg,
    _bip85_subkey_specs as _bip85_subkey_specs_gpg,
    _check_future_key_creation as _check_future_key_creation_gpg,
    _normalize_date_input as _normalize_date_input_gpg,
    _select_import_algo as _select_import_algo_gpg,
    _text_qr_done_destination as _text_qr_done_destination_gpg,
)

# Re-export for backward compatibility with tests and tools/bip85_pgp.py
_bip85_subkey_specs = _bip85_subkey_specs_gpg  # noqa: F401 W0603
_bip85_key_type_choices = _bip85_key_type_choices_gpg  # noqa: F401 W0603
_check_future_key_creation = _check_future_key_creation_gpg  # noqa: F401 W0603
_select_import_algo = _select_import_algo_gpg  # noqa: F401 W0603
_normalize_date_input = _normalize_date_input_gpg  # noqa: F401 W0603
