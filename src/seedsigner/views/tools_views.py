import base64
import hashlib
import json
import logging
import os
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
from seedsigner.models.decode_qr import DecodeQR
from seedsigner.models.encode_qr import GenericStaticQrEncoder
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.seed import Seed
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

from seedsigner.hardware.microsd import MicroSD
from seedsigner.hardware.rng_monitor import HardwareRngHealthMonitor
from seedsigner.helpers import seedkeeper_utils
from seedsigner.helpers.satochip_signer import (
    _call_with_timeout,
    _get_extended_key,
    format_path_string,
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
    ADDRESS_EXPLORER = ButtonOption("Address Explorer")
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
            allow_text_overflow=True,
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
        ret = ToolsImageEntropyLivePreviewScreen().display()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
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
            max_dim = max(self.canvas_width, self.canvas_height)

            # Final image will be at least 4x the number of pixels the screen can
            # actually display.
            camera.start_single_frame_mode(resolution=(2*max_dim, 2*max_dim))

            time.sleep(0.25)
            self.controller.image_entropy_final_image = camera.capture_frame()
            camera.stop_single_frame_mode()

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
        
        ret = ToolsImageEntropyFinalImageScreen(
            final_image=display_version
        ).display()

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

        selected_menu_num = ButtonListScreen(
            title=_("Mnemonic Length?"),
            button_data=button_data,
        ).display()

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
        selected_menu_num = ButtonListScreen(
            title=_("Mnemonic Length"),
            is_bottom_list=True,
            is_button_text_centered=True,
            button_data=button_data,
        ).display()

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
        ret = ToolsDiceEntropyEntryScreen(
            return_after_n_chars=self.total_rolls,
        ).display()

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
        selected_menu_num = ToolsCalcFinalWordFinalizePromptScreen(
            mnemonic_length=mnemonic_length,
            num_entropy_bits=num_entropy_bits,
            button_data=button_data,
        ).display()

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
        
        ret_val = ToolsCoinFlipEntryScreen(
            return_after_n_chars=total_flips,
        ).display()

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

        selected_menu_num = ToolsCalcFinalWordDoneScreen(
            final_word=final_word,
            mnemonic_word_length=mnemonic_word_length,
            fingerprint=self.controller.storage.get_pending_mnemonic_fingerprint(
                self.settings.get_value(SettingsConstants.SETTING__NETWORK),
                wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE),
            ),
            button_data=button_data,
        ).display()

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
        button_data = (
            button_data
            + [self.SCAN_SEED, self.SCAN_DESCRIPTOR, self.SATOCHIP]
            + [options[l] for l in seed_lengths]
        )
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
        self.controller.resume_main_flow = Controller.FLOW__ADDRESS_EXPLORER

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
    RECEIVE = ButtonOption("Receive Addresses")

    # TRANSLATOR_NOTE: label for addresses that collect the change from our own outgoing payments
    CHANGE = ButtonOption("Change Addresses")


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
            wallet_descriptor_display_name = data["wallet_descriptor"].brief_policy.replace(" (sorted)", "")
            wallet_descriptor_display_name = " / ".join(wallet_descriptor_display_name.split(" of ")) # i18n w/o l10n since coming from non-l10n embit

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

"""****************************************************************************
    Smartcard Views
****************************************************************************"""
class ToolsSmartcardMenuView(View):
    COMMON = ButtonOption("Common Functions")
    SATOCHIP = ButtonOption("Satochip Functions")
    SEEDKEEPER = ButtonOption("SeedKeeper Functions")
    Satochip_DIY = ButtonOption("DIY Tools")

    def run(self):
        button_data = [self.COMMON, self.SEEDKEEPER, self.SATOCHIP, self.Satochip_DIY]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Smartcard Tools",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.COMMON:
            return Destination(ToolsCommonView)
        
        elif button_data[selected_menu_num] == self.SATOCHIP:
            return Destination(ToolsSatochipView)
        
        elif button_data[selected_menu_num] == self.SEEDKEEPER:
            return Destination(ToolsSeedkeeperView)

        elif button_data[selected_menu_num] == self.Satochip_DIY:
            return Destination(ToolsSatochipDIYView)

class ToolsCommonView(View):
    FILTER = ButtonOption("Device Filter")
    INFO = ButtonOption("Card Info")
    GENUINE = ButtonOption("Genuine Check")
    CHANGE_PIN = ButtonOption("Change PIN")
    CHANGE_LABEL = ButtonOption("Change Label")
    CHANGE_NFC = ButtonOption("Change NFC Policy")
    FACTORY_RESET = ButtonOption("Factory Reset Card")

    def run(self):

        button_data = [
            self.FILTER,
            self.INFO,
            self.GENUINE,
            self.CHANGE_PIN,
            self.CHANGE_LABEL,
            self.CHANGE_NFC,
            self.FACTORY_RESET,
        ]

        selected_menu_num = self.run_screen(
                ButtonListScreen,
                title="Common Tools",
                is_button_text_centered=False,
                button_data=button_data
            )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.FILTER:
            return Destination(ToolsCommonFilterView)

        elif button_data[selected_menu_num] == self.INFO:
            return Destination(ToolsSmartcardInfoView)

        elif button_data[selected_menu_num] == self.GENUINE:
            return Destination(ToolsSmartcardGenuineCheckView)

        elif button_data[selected_menu_num] == self.CHANGE_PIN:
            return Destination(ToolsSatochipChangePinView)
        
        elif button_data[selected_menu_num] == self.CHANGE_LABEL:
            return Destination(ToolsSatochipChangeLabelView)

        elif button_data[selected_menu_num] == self.CHANGE_NFC:
            return Destination(ToolsSatochipChangeNFCView)

        elif button_data[selected_menu_num] == self.FACTORY_RESET:
            return Destination(ToolsSatochipFactoryResetView)


class ToolsCommonFilterView(View):
    def run(self):
        devices = [
            ("satochip", "Satochip"),
            ("seedkeeper", "Seedkeeper"),
            ("satodime", "Satodime"),
        ]

        selected = self.controller.tools_common_card_filter or [d[0] for d in devices]

        while True:
            button_data = [ButtonOption(name) for _, name in devices]
            checked = [i for i, (code, _) in enumerate(devices) if code in selected]

            ret = self.run_screen(
                ToolsCommonFilterScreen,
                button_data=button_data,
                checked_buttons=checked,
            )

            if ret == RET_CODE__BACK_BUTTON:
                if len(selected) == len(devices):
                    self.controller.tools_common_card_filter = None
                else:
                    self.controller.tools_common_card_filter = list(selected)
                return Destination(BackStackView)

            code = devices[ret][0]
            if code in selected:
                selected.remove(code)
            else:
                selected.append(code)

class ToolsSmartcardInfoView(View):
    def run(self):

        allowed = ["satochip", "seedkeeper", "satodime"]
        card_filter = self.controller.tools_common_card_filter or allowed
        card_filter = [c for c in card_filter if c in allowed]

        Satochip_Connector = seedkeeper_utils.init_satochip(
            self, init_card_filter=card_filter, require_pin=False
        )

        if not Satochip_Connector:
            return Destination(BackStackView)

        _resp, _sw1, _sw2, status = Satochip_Connector.card_get_status()

        info_lines = []

        card_type = getattr(Satochip_Connector, "card_type", "Unknown")
        info_lines.append(f"Type: {card_type}")

        uid = getattr(Satochip_Connector, "UID_SHA1", None)
        if not uid:
            uid_raw = getattr(Satochip_Connector, "UID", None)
            if uid_raw:
                uid = bytes(uid_raw).hex()
        if uid:
            info_lines.append(f"UID: {uid}")

        version = f"{status.get('protocol_major_version', 0)}.{status.get('protocol_minor_version', 0)}-" \
                  f"{status.get('applet_major_version', 0)}.{status.get('applet_minor_version', 0)}"
        info_lines.append(f"Version: {version}")

        pin0 = status.get("PIN0_remaining_tries")
        if pin0 is not None:
            info_lines.append(f"Remaining PIN tries: {pin0}")

        setup_done = status.get("setup_done")
        if setup_done is not None:
            setup_str = "Done" if setup_done else "Not done"
            if card_type == "Satochip" and "is_seeded" in status:
                setup_str += " (seeded)" if status["is_seeded"] else " (unseeded)"
            info_lines.append(f"Setup: {setup_str}")

        nfc_policy = status.get("nfc_policy")
        if nfc_policy is not None:
            nfc_map = {0: "Enabled", 1: "Disabled", 2: "Blocked"}
            info_lines.append(f"NFC: {nfc_map.get(nfc_policy, str(nfc_policy))}")

        text = "\n".join(info_lines)

        self.run_screen(
            LargeIconStatusScreen,
            title="Card Info",
            status_headline=None,
            text=text,
            status_icon_name="",
            show_back_button=True,
        )

        return Destination(BackStackView)

class ToolsSmartcardGenuineCheckView(View):
    def run(self):

        allowed = ["satochip", "seedkeeper", "satodime"]
        card_filter = self.controller.tools_common_card_filter or allowed
        card_filter = [c for c in card_filter if c in allowed]

        Satochip_Connector = seedkeeper_utils.init_satochip(
            self, init_card_filter=card_filter
        )

        if not Satochip_Connector:
            return Destination(BackStackView)

        try:
            initial_uid = getattr(Satochip_Connector, "UID_SHA1", None)
            is_genuine, _, _, _, txt_error = Satochip_Connector.card_verify_authenticity()

            # Workaround for occasional incorrect UID calculation in pysatochip
            # basically just try to connect again, using the PIN entered on the first attempt
            if not is_genuine or txt_error:
                print("Initial genuine check failed, retrying...")
                temp_pin = self.controller.Satochip_PIN
                try:

                    Satochip_Connector = seedkeeper_utils.init_satochip(
                        self,
                        init_card_filter=card_filter,
                        require_pin=False,
                    )
                    retry_uid = getattr(Satochip_Connector, "UID_SHA1", None)
                    can_retry_authenticity = True
                    if temp_pin and initial_uid == retry_uid:
                        Satochip_Connector.set_pin(0, temp_pin)
                    elif temp_pin:
                        can_retry_authenticity = False
                        txt_error = "Card changed during retry; re-enter PIN for this card."

                    if Satochip_Connector and can_retry_authenticity:
                        is_genuine, _, _, _, txt_error = (
                            Satochip_Connector.card_verify_authenticity()
                        )
                except Exception:
                    pass

            if txt_error:
                self.run_screen(
                    ErrorScreen,
                    title="Genuine Check",
                    status_headline=None,
                    text=f"Genuine check failed: {txt_error}",
                )
            elif is_genuine:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Genuine Check",
                    status_headline=None,
                    text="Card is genuine",
                )
            else:
                self.run_screen(
                    WarningScreen,
                    title="Genuine Check",
                    status_headline=None,
                    text="Card is NOT genuine",
                )
        except Exception as e:
            self.run_screen(
                ErrorScreen,
                title="Genuine Check",
                status_headline=None,
                text=f"Genuine: Error ({e})",
            )

        return Destination(BackStackView)

class ToolsSatochipChangePinView(View):
    def run(self):

        allowed = ["satochip", "seedkeeper"]
        card_filter = self.controller.tools_common_card_filter or ["satochip", "seedkeeper", "satodime"]
        card_filter = [c for c in card_filter if c in allowed]

        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=card_filter)

        if not Satochip_Connector:
            return Destination(BackStackView)

        new_pin_str = seedkeeper_utils.prompt_for_pin(self, "New PIN")

        if new_pin_str is None:
            return Destination(BackStackView)

        new_pin = list(new_pin_str.encode('utf8'))
        response, sw1, sw2 = Satochip_Connector.card_change_PIN(0, Satochip_Connector.pin, new_pin)
        if sw1 == 0x90 and sw2 == 0x00:
            logger.info("Success: Pin Changed")
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"PIN Updated",
                show_back_button=False,
            )
            # Update cached pin
            self.controller.Satochip_PIN = new_pin

        else:
            logger.info("Failure: Pin Change Failed")
            self.run_screen(
                WarningScreen,
                title="Invalid PIN",
                status_headline=None,
                text=f"Invalid PIN entered, select another and try again.",
                show_back_button=True,
            )
        
        return Destination(MainMenuView)
    
class ToolsSatochipChangeNFCView(View):
    def run(self):

        allowed = ["satochip", "seedkeeper"]
        card_filter = self.controller.tools_common_card_filter or ["satochip", "seedkeeper", "satodime"]
        card_filter = [c for c in card_filter if c in allowed]

        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=card_filter)

        if not Satochip_Connector:
            return Destination(BackStackView)

        # Just order the items to match NFC Policy: 0 = NFC_ENABLED, 1 = NFC_DISABLED, 2 = NFC_BLOCKED
        button_data = [ButtonOption("NFC Enabled"), ButtonOption("NFC Disabled"), ButtonOption("NFC Blocked")]

        nfc_policy = self.run_screen(
            ButtonListScreen,
            title="NFC Policy",
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )

        if nfc_policy == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        logger.info("Selected" + str(button_data[nfc_policy]) + " " + str(nfc_policy))    

        if (nfc_policy == 2):
            ret = self.run_screen(
                WarningScreen,
                title="Warning",
                status_headline=None,
                text="Once blocked, NFC can only be re-enabled via Factory Reset",
                show_back_button=True,
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
        
        (response, sw1, sw2) = Satochip_Connector.card_set_nfc_policy(nfc_policy)

        if sw1 == 0x90 and sw2 == 0x00:
            logger.info("Success: NFC Policy Changed")
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"NFC policy applied successfully!",
                show_back_button=False,
            )
            return Destination(MainMenuView)
    
        else:
            error_messages = {
                0x9C48: "Cannot set the NFC policy through the NFC interface, use contact interface instead",
                0x9C49: "Cannot set the NFC policy: NFC interface is BLOCKED, a factory reset is required to reenable NFC!",
            }

            status_word = (sw1 << 8) | sw2
            failed_string = error_messages.get(status_word, format_sw_error(sw1, sw2))

            logger.info(
                "Failure: NFC Change Failed with status word %s",
                hex(status_word),
            )
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=failed_string,
                show_back_button=True,
            )
        return Destination(MainMenuView)

class ToolsSatochipFactoryResetView(View):
    def run(self):
        resetStatus = False

        ret = self.run_screen(
                DireWarningScreen,
                title="Warning",
                status_headline=None,
                text="FACTORY RESET WITHOUT A WORKING BACKUP WILL LEAD TO UNRECOVERABLE LOSS OF FUNDS",
                show_back_button=True,
            )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        """Initiate the card Factory Reset Process using the legacy or new approach based on card type and version

        factory reset support:
        SeedKeeper: all versions support factory reset
        Satodime: no factory reset support (simply reset all vaults on the card)
        Satochip: factory reset introduced in v0.12-0.4
        
        new version currently only implemented on SeedKeeper v0.2 and higher
        """
        allowed = ["satochip", "seedkeeper"]
        card_filter = self.controller.tools_common_card_filter or ["satochip", "seedkeeper", "satodime"]
        card_filter = [c for c in card_filter if c in allowed]

        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=card_filter, require_pin = False)

        if not Satochip_Connector:
            return Destination(BackStackView)

        if Satochip_Connector.card_type == "SeedKeeper":
            # get version
            (response, sw1, sw2, d) = Satochip_Connector.card_get_status()
            version = d["protocol_version"]
            if (version >= 2):
                print("This SeedKeeper supports factory reset (new version)!")
                resetStatus = self.common_reset_factory_new(Satochip_Connector)
            else: 
                print("This SeedKeeper supports factory reset (legacy)!")
                resetStatus = self.common_reset_factory_legacy(Satochip_Connector)
        
        elif Satochip_Connector.card_type == "Satodime":
            print("Satodime does not support factory reset!")

        elif Satochip_Connector.card_type == "Satochip":
            # get version
            (response, sw1, sw2, d) = Satochip_Connector.card_get_status()
            version = ((d["protocol_major_version"]<<24)
                        + (d["protocol_minor_version"]<<16)
                        + (d["applet_major_version"]<<8)
                        + (d["applet_minor_version"]))
            version_min = (12<<16)+4 # v0.12-0.4
            if (version >= version_min):
                print("This Satochip supports factory reset (legacy)!")
                resetStatus = self.common_reset_factory_legacy(Satochip_Connector) 
            else:
                print("Satochip below version v0.12-0.4 do not support factory reset!")
                ret = self.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text="Satochip below version v0.12-0.4 do not support factory reset!",
                    show_back_button=True,
                )

        else:
            print(f"Unsupported card type: {Satochip_Connector.card_type}")
            ret = self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=f"Unsupported card type: {Satochip_Connector.card_type} (Try again)",
                show_back_button=True,
            )

        if resetStatus:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Card Factory Reset",
                show_back_button=False,
            )
        else:
            ret = self.run_screen(
                WarningScreen,
                title="Aborted",
                status_headline=None,
                text="Factory Reset Aborted",
                show_back_button=True,
            )

        return Destination(BackStackView)
        
    def common_reset_factory_legacy(self, Satochip_Connector):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        """Initiate the Factory Reset Process
        Legacy approach based on sending a specifi APDU a certain number of times
        """    

        resetStatus = False

        print("WARNING: FACTORY RESET WITHOUT A WORKING BACKUP WILL LEAD TO UNRECOVERABLE LOSS OF FUNDS")
        logger.info("In common_reset_factory_legacy")

        # If other smartcard workflows have previously interacted with the
        # connector, it may still have an active connection which interferes
        # with card removal detection during the factory reset sequence. Start
        # from a clean state so that each removal/reinsertion is picked up
        # correctly.
        Satochip_Connector.card_disconnect()

        # Purge all card observers and any lingering PCSC context so that no
        # background task can automatically exchange APDUs with the card when
        # it is reinserted. Any unexpected APDU would reset the legacy counter
        # and prevent the factory reset sequence from completing. This also
        # effectively disables the automatic card monitor for the duration of
        # the legacy reset workflow.
        try:
            # deleteObservers() clears every registered observer on the
            # underlying CardMonitor singleton.  Our previous approach of
            # iterating over a non-existent "observers" attribute left the
            # RemovalObserver active, which continued to automatically talk to
            # the card on reinsertion and prevented the legacy reset counter
            # from decrementing.  Explicitly drop all observers so no
            # background APDUs are sent during the reset workflow.
            Satochip_Connector.cardmonitor.deleteObservers()
        except Exception:
            pass
        try:
            from smartcard import scard
            hresult, hcontext = scard.SCardEstablishContext(scard.SCARD_SCOPE_SYSTEM)
            if hresult == scard.SCARD_S_SUCCESS:
                scard.SCardReleaseContext(hcontext)
        except Exception:
            pass

        # Enter the special factory reset mode only after ensuring we are in a
        # clean, disconnected state.  This prevents any lingering connection
        # from previous smartcard operations from automatically communicating
        # with the card when it is re-inserted, which would otherwise keep the
        # reset counter from decrementing.
        Satochip_Connector.set_mode_factory_reset(True)

        remaining_string = ""
        try:
            while(True):
                self.loading_screen = LoadingScreenThread(text="Sending Command")
                ret = self.run_screen(
                    DireWarningScreen,
                    title="Warning",
                    status_headline=None,
                    text="Remove and re-insert the smartcard to continue factory reset." + remaining_string,
                    show_back_button=True,
                    button_data=[ButtonOption("Card Re-Inserted")]
                )
                if ret == RET_CODE__BACK_BUTTON:
                    return resetStatus
                else:
                    self.loading_screen.start()
                    try:
                        time.sleep(3)  # give some time to initialize reader after card insertion... (Takes a while on Pi0)

                        # Establish a fresh connection to the newly inserted
                        # card.  Since the automatic card monitor is disabled
                        # we must explicitly wait for and connect to the card
                        # ourselves before selecting it.
                        Satochip_Connector.cardservice = (
                            Satochip_Connector.cardrequest.waitforcard()
                        )
                        Satochip_Connector.cardservice.connection.connect()

                        # Manually select the card's applet without using the
                        # higher-level helpers which may issue additional
                        # APDUs such as secure-channel setup. Extra commands
                        # would reset the legacy counter.
                        apdu = [0x00, 0xA4, 0x04, 0x00, len(CardConnector.SATOCHIP_AID)] + CardConnector.SATOCHIP_AID
                        (response, sw1, sw2) = Satochip_Connector.cardservice.connection.transmit(apdu)
                        if not (sw1 == 0x90 and sw2 == 0x00):
                            apdu = [0x00, 0xA4, 0x04, 0x00, len(CardConnector.SEEDKEEPER_AID)] + CardConnector.SEEDKEEPER_AID
                            (response, sw1, sw2) = Satochip_Connector.cardservice.connection.transmit(apdu)
                            if not (sw1 == 0x90 and sw2 == 0x00):
                                raise Exception("Card select failed")

                        # Send the legacy factory-reset signal directly to
                        # avoid any automatic retries or secure-channel
                        # negotiation.
                        apdu_reset = [0xB0, 0xFF, 0x00, 0x00, 0x00]
                        (response, sw1, sw2) = Satochip_Connector.cardservice.connection.transmit(apdu_reset)
                        self.loading_screen.stop()
                    except Exception as e:
                        print("Exception:", str(e))
                        self.loading_screen.stop()
                        self.run_screen(
                            WarningScreen,
                            title="Exception",
                            status_headline=None,
                            text=str(e)[:100],
                            show_back_button=True,
                        )
                        break # Just bail out of the workflow if there was an IO error

                    if sw1 == 0x9c and sw2 == 0x04:
                        print("Factory Reset Failed (setup not done)")
                        self.run_screen(
                            WarningScreen,
                            title="Failure",
                            status_headline=None,
                            text="Factory Reset Failed (setup not done)",
                            show_back_button=True,
                        )
                        #print("In addition to the factory-reset command, you also need to add the '--enablefactoryreset' argument to enable it")
                        break
                    if sw1 == 0x00 and sw2 == 0x00:
                        print("Card not found, retrying...")
                        Satochip_Connector.card_disconnect()
                        remaining_string = "\nCard not found. Please re-insert and try again."
                        continue
                    if sw1 == 0xFF and sw2 == 0x00:
                        Satochip_Connector.card_disconnect()
                        print("CARD HAS BEEN RESET TO FACTORY!")
                        resetStatus = True
                        break
                    elif sw1 == 0xFF and sw2 == 0xFF:
                        print("RESET ABORTED: you must remove card after each reset!")
                        self.run_screen(
                            WarningScreen,
                            title="Failure",
                            status_headline=None,
                            text="RESET ABORTED: you must remove card after each reset!",
                            show_back_button=True,
                        )
                        break
                    elif sw1 == 0xFF and sw2 > 0x00:
                        remaining_string = "\nREMAINING COUNTER: " + str(sw2)
                        print("Remaining counter: " + str(sw2))
                        print("Please remove and reinsert card, then confirm that you want to continue...")
                        Satochip_Connector.card_disconnect()
                    elif sw1 == 0x6F and sw2 == 0x00:
                        print("The factory reset failed")
                        print("Unknown error" + str(hex(256 * sw1 + sw2)))
                        self.run_screen(
                            WarningScreen,
                            title="Failure",
                            status_headline=None,
                            text="Unknown error" + str(hex(256 * sw1 + sw2)),
                            show_back_button=True,
                        )
                        break
                    elif sw1 == 0x6D and sw2 == 0x00:
                        print("The factory reset failed")
                        print("Instruction not supported - error code: " + str(hex(256 * sw1 + sw2)))
                        self.run_screen(
                            WarningScreen,
                            title="Failure",
                            status_headline=None,
                            text="Instruction not supported - error code: " + str(hex(256 * sw1 + sw2)),
                            show_back_button=True,
                        )
                        break
                    else:
                        print("The factory reset has been cancelled")
                        break
        finally:
            # Always reset the mode and disconnect to return the connector to a
            # normal operating state for any subsequent smartcard operations.
            Satochip_Connector.set_mode_factory_reset(False)
            Satochip_Connector.card_disconnect()

            # Re-enable the automatic card monitor for normal operations.
            try:
                Satochip_Connector.cardmonitor.addObserver(
                    Satochip_Connector.cardobserver
                )
            except Exception:
                pass

        return resetStatus

    def common_reset_factory_new(self, Satochip_Connector):
        from pysatochip.CardConnector import IdentityBlockedError, WrongPinError, CardResetToFactoryError
        """Initiate the Factory Reset Process
        New approach where reset to factory is trigerred when PIN and PUK is blocked (the card is basically unusable in this state)
        """ 
        logger.info("In common_reset_factory_new")
        resetStatus = False

        pinRemaining = -1
        ret = self.run_screen(
                DireWarningScreen,
                title="Warning",
                status_headline=None,
                text="Are you sure that you want to perform a factory reset?",
                show_back_button=True,
                button_data=[ButtonOption("Yes")]
            )
        if ret == RET_CODE__BACK_BUTTON:
            return resetStatus
        else:
            doReset = True
        
        # Block PIN
        remaining_string = ""
        while(doReset):
            ret = self.run_screen(
                DireWarningScreen,
                title="Factory Reset",
                status_headline=None,
                text="Enter wrong PIN multiple times to continue Factory Reset." + remaining_string,
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return resetStatus

            pin = seedkeeper_utils.prompt_for_pin(self, "Enter PIN")

            if pin is None:
                return Destination(ToolsSmartcardMenuView)

            try:
                (response, sw1, sw2)= Satochip_Connector.card_verify_PIN(pin)
                if sw1 == 0x90 and sw2 == 0x00:
                    print("You have entered a correct PIN, factory reset is aborted")
                    doReset = False
                    pinRemaining = -1
                    break
            except IdentityBlockedError as ex:
                # PIN blocked, PUK next
                #print(ex)
                print("PIN code is blocked!")
                pinRemaining = 0
                break
            except WrongPinError as ex:
                remaining_string = f"\n{ex.pin_left} TRIES REMAINING!"
                print(ex)
                print(f"pinRemaining: {ex.pin_left}")
            except Exception as ex:
                print(ex)

        # Block PUK
        pukRemaining = -1
        remaining_string = ""
        while(doReset):
            ret = self.run_screen(
                DireWarningScreen,
                title="Factory Reset",
                status_headline=None,
                text="Enter wrong PUK to continue Factory Reset." + remaining_string,
                show_back_button=True,
            )
            if ret == RET_CODE__BACK_BUTTON:
                return resetStatus

            puk = seed_screens.SeedAddPassphraseScreen(title="Enter PUK").display()

            if "is_back_button" in puk:
                return resetStatus
            
            puk = puk['passphrase']
            
            puk_list = list(puk.encode('utf-8'))
            if len(puk_list)<4:
                print("PUK code too short, factory reset is aborted")
                doReset = False
                break

            try:
                (response, sw1, sw2)= Satochip_Connector.card_unblock_PIN(0, puk_list)
                if sw1 == 0x90 and sw2 == 0x00:
                    print("You have entered a correct PUK, factory reset is aborted, PIN is unblocked")
                    doReset = False
                    pinRemaining = -1
                    pukRemaining = -1
                    break
            except IdentityBlockedError as ex:
                # PUK blocked (Shouldn't happen, as factory reset triggers before this)
                #print(ex)
                print("PUK code is blocked!")
                pukRemaining = 0
                break

            except WrongPinError as ex:
                remaining_string = f"\n{ex.pin_left} TRIES REMAINING!"
                pukRemaining = ex.pin_left
                print(ex)
                print(f"pinRemaining: {ex.pin_left}")

            except CardResetToFactoryError as ex:
                # Card reset to factory
                pinRemaining = -1
                pukRemaining = -1
                print(f"CARD RESET TO FACTORY!")
                resetStatus = True
                break    
            
        return resetStatus

class ToolsSatochipChangeLabelView(View):
    def run(self):

        allowed = ["satochip", "seedkeeper"]
        card_filter = self.controller.tools_common_card_filter or ["satochip", "seedkeeper", "satodime"]
        card_filter = [c for c in card_filter if c in allowed]

        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=card_filter)

        if not Satochip_Connector:
            return Destination(BackStackView)

        NewLabel = seed_screens.SeedAddPassphraseScreen(title="New Label").display()

        if "is_back_button" in NewLabel:
            return Destination(BackStackView)

        """Sets a plain text label for the card (Optional)"""
        try:
            (response, sw1, sw2) = Satochip_Connector.card_set_label(NewLabel['passphrase'])
            if sw1 != 0x90 or sw2 != 0x00:
                logger.info("ERROR: Set Label Failed")
                self.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text=f"Set Label Failed...",
                    show_back_button=True,
                )
            else:
                logger.info("Device Label Updated")
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text=f"Label Updated",
                    show_back_button=False,
                )
        except Exception as e:
            self.loading_screen.stop()
            logger.info("Set Label Failed:", str(e))
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=str(e)[:100],
                show_back_button=True,
            )

        return Destination(MainMenuView)

class ToolsSeedkeeperView(View):
    VIEW_FREE_SPACE = ButtonOption("View Free Space")
    VIEW_SECRETS = ButtonOption("View Secrets on Card")
    IMPORT_PASSWORD = ButtonOption("Save Password to Card")
    DELETE_SECRET = ButtonOption("Delete Secret from Card")
    LOAD_DESCRIPTOR = ButtonOption("Load MultiSig Descriptor")
    SAVE_DESCRIPTOR = ButtonOption("Save MultiSig Descriptor")
    CLONE_SECRETS = ButtonOption("Clone Card Secrets")

    def run(self):
        button_data = [
            self.VIEW_SECRETS,
            self.IMPORT_PASSWORD,
            self.DELETE_SECRET,
            self.LOAD_DESCRIPTOR,
            self.SAVE_DESCRIPTOR,
            self.CLONE_SECRETS,
            self.VIEW_FREE_SPACE,
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="SeedKeeper",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.VIEW_SECRETS:
            return Destination(ToolsSeedkeeperViewSecretsView)

        elif button_data[selected_menu_num] == self.IMPORT_PASSWORD:
            return Destination(ToolsSeedkeeperImportPasswordView)

        elif button_data[selected_menu_num] == self.DELETE_SECRET:
            return Destination(ToolsSeedkeeperDeleteSecretView)

        elif button_data[selected_menu_num] == self.LOAD_DESCRIPTOR:
            return Destination(ToolsSeedkeeperLoadDescriptorView)
        
        elif button_data[selected_menu_num] == self.SAVE_DESCRIPTOR:
            return Destination(ToolsSeedkeeperSaveDescriptorView)

        elif button_data[selected_menu_num] == self.VIEW_FREE_SPACE:
            return Destination(ToolsSeedkeeperFreeSpaceView)

        elif button_data[selected_menu_num] == self.CLONE_SECRETS:
            return Destination(ToolsSeedkeeperCloneSecretsView)


class ToolsSeedkeeperFreeSpaceView(View):

    def run(self):
        connector = None
        try:
            connector = seedkeeper_utils.init_satochip(
                self,
                init_card_filter=["seedkeeper"],
                require_pin=True,
            )

            if not connector:
                return Destination(BackStackView)

            try:
                free_bytes = seedkeeper_utils.get_seedkeeper_free_memory(connector)
            except Exception as exc:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=str(exc),
                    show_back_button=True,
                )
                return Destination(BackStackView)

            free_kib = free_bytes / 1024
            text = f"{free_bytes} bytes free\n({free_kib:.1f} KiB)"

            self.run_screen(
                LargeIconStatusScreen,
                title="Seedkeeper Free Space",
                status_headline=None,
                text=text,
                show_back_button=True,
            )
            return Destination(BackStackView)

        except Exception as exc:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(exc),
                show_back_button=True,
            )
            return Destination(BackStackView)

        finally:
            if connector:
                seedkeeper_utils.disconnect_smartcard_connections(self.controller)


class ToolsSeedkeeperCloneSecretsView(View):
    def _collect_exportable_secrets(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread

        connector = None
        loading_screen = None
        try:
            insert_prompt = self.run_screen(
                LargeIconStatusScreen,
                title="Insert Source Card",
                status_headline=None,
                text=(
                    "Insert the source Seedkeeper card to copy secrets from, "
                    "then press Continue."
                ),
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )

            if insert_prompt == RET_CODE__BACK_BUTTON:
                return None

            connector = seedkeeper_utils.init_satochip(
                self,
                init_card_filter=["seedkeeper"],
                require_pin=True,
            )

            if not connector:
                return None

            loading_screen = LoadingScreenThread(text="Reading Source Card\n\n\n\n\n\n")
            loading_screen.start()

            headers = connector.seedkeeper_list_secret_headers()

            exportable_secrets = []
            skipped_unexportable = 0

            for header in headers:
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(
                    header.get("export_rights"), header.get("export_rights")
                )

                if export_rights != "Plaintext export allowed":
                    skipped_unexportable += 1
                    continue

                try:
                    secret = connector.seedkeeper_export_secret(header["id"], None)
                except Exception:
                    skipped_unexportable += 1
                    continue

                exportable_secrets.append({
                    "header": header,
                    "secret": secret,
                })

            loading_screen.stop()

            if not exportable_secrets:
                self.run_screen(
                    WarningScreen,
                    title="No Exportable Secrets",
                    status_headline=None,
                    text="Source card has no secrets that can be cloned.",
                    show_back_button=False,
                )
                return None

            summary_lines = [f"Secrets ready: {len(exportable_secrets)}"]
            if skipped_unexportable:
                summary_lines.append(f"Skipped (locked): {skipped_unexportable}")

            self.run_screen(
                LargeIconStatusScreen,
                title="Source Ready",
                status_headline=None,
                text="\n".join(summary_lines),
                show_back_button=False,
            )

            return exportable_secrets

        except Exception as exc:
            if loading_screen:
                loading_screen.stop()
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(exc),
                show_back_button=True,
            )
            return None

        finally:
            if loading_screen:
                loading_screen.stop()
            if connector:
                seedkeeper_utils.disconnect_smartcard_connections(self.controller)

    def _clone_to_destination(self, secrets_to_clone):
        from seedsigner.gui.screens.screen import LoadingScreenThread

        connector = None
        loading_screen = None
        try:
            insert_prompt = self.run_screen(
                LargeIconStatusScreen,
                title="Insert Destination Card",
                status_headline=None,
                text=(
                    "Insert the destination Seedkeeper card to copy secrets to, "
                    "then press Continue."
                ),
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )

            if insert_prompt == RET_CODE__BACK_BUTTON:
                return None, None

            connector = seedkeeper_utils.init_satochip(
                self,
                init_card_filter=["seedkeeper"],
                require_pin=True,
            )

            if not connector:
                return False, (
                    "Destination Seedkeeper applet not found. "
                    "Re-insert a Seedkeeper card to retry."
                )

            loading_screen = LoadingScreenThread(text="Writing Destination Card\n\n\n\n\n\n")
            loading_screen.start()

            dest_headers = connector.seedkeeper_list_secret_headers()
            existing_fingerprints = {
                header.get("fingerprint")
                for header in dest_headers
                if header.get("fingerprint") is not None
            }

            imported = 0
            skipped_existing = 0
            skipped_unsupported = 0

            for entry in secrets_to_clone:
                header = entry.get("header", {})
                secret = entry.get("secret", {})

                fingerprint = header.get("fingerprint")
                if fingerprint is not None and fingerprint in existing_fingerprints:
                    skipped_existing += 1
                    continue

                secret_type = SEEDKEEPER_DIC_TYPE.get(header.get("type"))
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header.get("export_rights"))
                label = header.get("label", "")
                subtype = header.get("subtype")

                if not secret_type or not export_rights:
                    skipped_unsupported += 1
                    continue

                try:
                    if subtype is None:
                        new_header = connector.make_header(secret_type, export_rights, label)
                    else:
                        new_header = connector.make_header(
                            secret_type, export_rights, label, subtype=subtype
                        )
                except Exception:
                    skipped_unsupported += 1
                    continue

                if secret.get("secret_list") is not None:
                    secret_dic = {
                        "header": new_header,
                        "secret_list": secret["secret_list"],
                    }
                elif secret.get("secret_encrypted") is not None:
                    secret_dic = {
                        "header": new_header,
                        "secret_encrypted": secret["secret_encrypted"],
                    }
                else:
                    skipped_unsupported += 1
                    continue

                try:
                    fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
                        connector, secret_dic
                    )
                except Exception as exc:
                    loading_screen.stop()
                    return False, str(exc)

                if not fits:
                    loading_screen.stop()
                    return False, seedkeeper_utils.format_seedkeeper_space_error(
                        required_bytes, free_bytes
                    )

                connector.seedkeeper_import_secret(secret_dic)
                imported += 1

                if fingerprint is not None:
                    existing_fingerprints.add(fingerprint)

            loading_screen.stop()

            self.run_screen(
                LargeIconStatusScreen,
                title="Clone Complete",
                status_headline=None,
                text=(
                    f"Imported: {imported}\n"
                    f"Skipped Existing: {skipped_existing}\n"
                    f"Skipped Unsupported: {skipped_unsupported}"
                ),
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )

            return True, None

        except Exception as exc:
            if loading_screen:
                loading_screen.stop()
            return False, str(exc)

        finally:
            if loading_screen:
                loading_screen.stop()
            if connector:
                seedkeeper_utils.disconnect_smartcard_connections(self.controller)

    def run(self):
        secrets_to_clone = self._collect_exportable_secrets()

        if not secrets_to_clone:
            return Destination(BackStackView)

        while True:
            result, error_message = self._clone_to_destination(secrets_to_clone)

            if result is False:
                retry_choice = self.run_screen(
                    WarningScreen,
                    title="Clone Failed",
                    status_headline=None,
                    text=error_message or "Unable to write to destination card.",
                    show_back_button=False,
                    button_data=[ButtonOption("Try Again"), ButtonOption("Exit to Home")],
                )

                if retry_choice == 0:
                    continue

                return Destination(MainMenuView)

            if result is not True:
                return Destination(BackStackView)

            choice = self.run_screen(
                ButtonListScreen,
                title="Clone Another Card?",
                is_button_text_centered=False,
                button_data=[ButtonOption("Yes"), ButtonOption("No")],
                show_back_button=True,
            )

            if choice != 0:
                return Destination(BackStackView)

class ToolsSeedkeeperViewSecretsView(View):

    def entropy_to_mnemonic(self, entropy_bytes, wordlist):
        from mnemonic import Mnemonic
        logger.info(f"Worldlist: {wordlist}")

        mnemonic_obj = Mnemonic(wordlist)
        mnemonic = mnemonic_obj.to_mnemonic(entropy_bytes)

        return mnemonic # str

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        try:
            Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
            
            if not Satochip_Connector:
                return Destination(BackStackView)

            self.loading_screen = LoadingScreenThread(text="Listing Secrets\n\n\n\n\n\n")
            self.loading_screen.start()

            headers = Satochip_Connector.seedkeeper_list_secret_headers()

            self.loading_screen.stop()

            headers_parsed = []
            button_data = []
            for header in headers:
                sid = header['id']
                stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))  # hex(header['type'])
                subtype = header['subtype']
                label = stype
                if stype == "Password":
                    label = "Pass:" + header['label']
                elif stype == "BIP39 mnemonic": # Older Seedkeeper v1 BIP39 seeds
                    label = "Seed:" + header['label']
                elif stype == 'Masterseed' and subtype==0x01: # Newer SeedKeeper V2 Seeds
                    label = "Seed:" + header['label']
                elif stype == "2FA secret":
                    label = "2FA:" + header['label']
                elif stype == "Descriptor":
                    label = "Descriptor:" + header['label']
                elif stype == "Data":
                    label = "Data:" + header['label']
                else: 
                    label = header['label']
                origin = SEEDKEEPER_DIC_ORIGIN.get(header['origin'], hex(header['origin']))  # hex(header['origin'])
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header['export_rights'],
                                                                 hex(header[
                                                                         'export_rights']))  # str(header['export_rights'])
                export_nbplain = str(header['export_nbplain'])
                export_nbsecure = str(header['export_nbsecure'])
                export_nbcounter = str(header['export_counter']) if header['type'] == 0x70 else 'N/A'
                fingerprint = header['fingerprint']

                if export_rights == 'Plaintext export allowed':
                    if len(label) == 0: label = "Unnamed Secret"
                    headers_parsed.append((sid, label))
                    button_data.append(ButtonOption(label))

            logger.debug("headers_parsed: %s", headers_parsed)
            if len(headers_parsed) < 1:
                self.run_screen(
                WarningScreen,
                title="No Secrets to Load",
                status_headline=None,
                text=f"No Secrets to Load from Seedkeeper",
                show_back_button=False,
                )   
                return Destination(BackStackView)

            selected_menu_num = self.run_screen(
                ButtonListScreen,
                title="Select Secret",
                is_button_text_centered=False,
                button_data=button_data,
                show_back_button=True,
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            self.loading_screen = LoadingScreenThread(text="Loading Secret\n\n\n\n\n\n")
            self.loading_screen.start()

            secret_dict = Satochip_Connector.seedkeeper_export_secret(headers_parsed[selected_menu_num][0], None)

            self.loading_screen.stop()

            stype = SEEDKEEPER_DIC_TYPE.get(secret_dict['type'], hex(secret_dict['type']))  # hex(header['type'])

            if 'mnemonic' in stype:
                secret_dict['secret'] = unhexlify(secret_dict['secret'])[1:].decode().rstrip("\x00")

                bip39_secret = secret_dict['secret']

                secret_size = secret_dict['secret_list'][0]
                secret_mnemonic = bip39_secret[:secret_size]
                secret_passphrase = bip39_secret[secret_size + 1:]

                secret_dict['secret'] = "Mnemonic:" + secret_mnemonic + " Passphrase:" + secret_passphrase

            #elif stype == 'BIP39 mnemonic v2':
            elif stype == 'Masterseed' and subtype==0x01:

                # this format is backward compatible with Masterseed (BIP39 info appended after Masterseed)
                # mnemonic in compressed format using entropy (16-32 bytes)
                secret_raw_hex = secret_dict['secret']
                secret_raw_bytes = bytes.fromhex(secret_raw_hex)
                
                offset = 0
                masterseed_size = secret_raw_bytes[offset]
                offset+=1

                masterseed_bytes= secret_raw_bytes[offset: (offset+masterseed_size)]
                offset+=masterseed_size
                masterseed_hex= masterseed_bytes.hex()

                wordlist_byte = secret_raw_bytes[offset]
                offset+=1
                wordlist = BIP39_WORDLIST_DIC.get(wordlist_byte)
                if wordlist is None:
                    logger.info("Error: unsupported BIP39 wordlist identifier encountered")
                    exit()
                
                entropy_size = secret_raw_bytes[offset]
                offset+=1

                entropy_bytes = secret_raw_bytes[offset:(offset+entropy_size)]
                offset+=entropy_size
                try:
                    bip39_mnemonic = self.entropy_to_mnemonic(entropy_bytes, wordlist)

                except Exception as ex:
                    logger.info(f"Error during entropy conversion: {ex}")
                    bip39_mnemonic = f"failed to convert entropy: {entropy_bytes.hex()}"

                passphrase_size= secret_raw_bytes[offset]
                offset+=1

                passphrase_bytes= secret_raw_bytes[offset: (offset+passphrase_size)]
                offset+=passphrase_size
                try:
                    passphrase = passphrase_bytes.decode("utf-8")
                except Exception as ex:
                    logger.info(f"Error during passphrase decoding: {ex}")
                    passphrase = f"failed to decode passphrase bytes: {passphrase_bytes.hex()}"

                secret_dict['secret']= f'BIP39 mnemonic: "{bip39_mnemonic}" \nPassphrase: "{passphrase}"'  

            elif stype == 'Password':
                
                password_length = secret_dict['secret_list'][0]
                try:
                    login_length = secret_dict['secret_list'][password_length + 1]
                    url_length = secret_dict['secret_list'][password_length + login_length + 2]
                except IndexError: # Older Seedkeeper software didn't include these optional fields
                    login_length = 0
                    url_length = 0

                secret_string = ""

                # Password is always present, so no need to test for this
                password_text = binascii.unhexlify(secret_dict['secret'])[1:password_length+1].decode()
                secret_string += " Password:" + "\"" + password_text + "\""

                if login_length > 0:
                    login_text = binascii.unhexlify(secret_dict['secret'])[
                                    password_length + 2: password_length + login_length + 2].decode()
                    secret_string += " Login:" + "\"" + login_text + "\""

                if url_length > 0:
                    url_text = binascii.unhexlify(secret_dict['secret'])[-url_length:].decode()
                    secret_string += " URL:" + "\"" + url_text + "\""

                secret_dict['secret'] = secret_string


            elif stype in ('Descriptor', 'Data', 'Public Key'):
                secret_dict['secret'] = unhexlify(secret_dict['secret'])[2:].decode()
                
            else:
                secret_dict['secret'] =  secret_dict['secret'][2:]

            selected_menu_num = self.run_screen(
                LargeIconStatusScreen,
                title=secret_dict['label'],
                status_headline=None,
                text = secret_dict['secret'],
                status_icon_size=0,
                show_back_button=True,
                allow_text_overflow=True,
                button_data=[ButtonOption("Show as QR")],
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            else:
                from seedsigner.gui.screens.screen import QRDisplayScreen
                from seedsigner.models.encode_qr import GenericStaticQrEncoder

                qr_encoder = GenericStaticQrEncoder(data=secret_dict['secret'])
                self.run_screen(
                    QRDisplayScreen,
                    qr_encoder=qr_encoder,
                )

            return Destination(BackStackView)
            
        except Exception as e:
            logger.info(e)
            self.loading_screen.stop()
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=True,
                button_data=[ButtonOption("Show as QR")],
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            else:
                from seedsigner.gui.screens.screen import QRDisplayScreen
                from seedsigner.models.encode_qr import GenericStaticQrEncoder

                qr_encoder = GenericStaticQrEncoder(data=secret_dict['secret'])
                self.run_screen(
                    QRDisplayScreen,
                    qr_encoder=qr_encoder,
                )

            return Destination(BackStackView)



class ToolsSeedkeeperImportPasswordView(View):
    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread

        secret_label = seed_screens.SeedAddPassphraseScreen(title="Secret Label").display()
        if "is_back_button" in secret_label:
            return Destination(BackStackView)

        secret_text = seed_screens.SeedAddPassphraseScreen(title="Secret Text").display()
        if "is_back_button" in secret_text:
            return Destination(BackStackView)

        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
        if not Satochip_Connector:
            return Destination(BackStackView)
        
        header = Satochip_Connector.make_header("Password", "Plaintext export allowed", secret_label['passphrase'])
        secret_text_list = list(bytes(secret_text['passphrase'], 'utf-8'))
        secret_list = [len(secret_text_list)] + secret_text_list
        secret_dic = {'header': header, 'secret_list': secret_list}

        try:
            fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
                Satochip_Connector, secret_dic
            )
        except Exception as e:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        if not fits:
            self.run_screen(
                WarningScreen,
                title="Not Enough Space",
                status_headline=None,
                text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        try:
            self.loading_screen = LoadingScreenThread(text="Saving Secret\n\n\n\n\n\n")
            self.loading_screen.start()

            (sid, fingerprint) = Satochip_Connector.seedkeeper_import_secret(secret_dic)

            self.loading_screen.stop()

            logger.info("Imported - SID:", sid, " Fingerprint:", fingerprint)
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Password Imported",
                show_back_button=False,
            )
        except Exception as e:
            logger.info(e)
            self.loading_screen.stop()
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=f"Password Import Failed",
                show_back_button=False,
            )
        
        return Destination(BackStackView)

class ToolsSeedkeeperDeleteSecretView(View):

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        try:
            Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
            
            if not Satochip_Connector:
                return Destination(BackStackView)

            # for v1, secret deletion is not supported
            status = Satochip_Connector.card_get_status()[3]
            if status['protocol_minor_version'] == 1:
                raise ValueError("Secret deletion is not supported on Seedkeeper v1")

            self.loading_screen = LoadingScreenThread(text="Listing Secrets\n\n\n\n\n\n")
            self.loading_screen.start()

            headers = Satochip_Connector.seedkeeper_list_secret_headers()

            self.loading_screen.stop()

            headers_parsed = []
            button_data = []
            for header in headers:
                sid = header['id']
                stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))  # hex(header['type'])
                subtype = header['subtype']
                label = stype
                if stype == "Password":
                    label = "Pass:" + header['label']
                elif stype == "BIP39 mnemonic": # Older Seedkeeper v1 BIP39 seeds
                    label = "Seed:" + header['label']
                elif stype == 'Masterseed' and subtype==0x01: # Newer SeedKeeper V2 Seeds
                    label = "Seed:" + header['label']
                elif stype == "2FA secret":
                    label = "2FA:" + header['label']
                elif stype == "Descriptor":
                    label = "Descriptor:" + header['label']
                elif stype == "Data":
                    label = "Data:" + header['label']
                else: 
                    label = header['label']
                origin = SEEDKEEPER_DIC_ORIGIN.get(header['origin'], hex(header['origin']))  # hex(header['origin'])
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header['export_rights'],
                                                                 hex(header[
                                                                         'export_rights']))  # str(header['export_rights'])
                export_nbplain = str(header['export_nbplain'])
                export_nbsecure = str(header['export_nbsecure'])
                export_nbcounter = str(header['export_counter']) if header['type'] == 0x70 else 'N/A'
                fingerprint = header['fingerprint']

                if export_rights == 'Plaintext export allowed':
                    if len(label) == 0: label = "Unnamed Secret"
                    headers_parsed.append((sid, label))
                    button_data.append(ButtonOption(label))

            logger.debug("headers_parsed: %s", headers_parsed)
            if len(headers_parsed) < 1:
                self.run_screen(
                WarningScreen,
                title="No Secrets to Load",
                status_headline=None,
                text=f"No Secrets to Load from Seedkeeper",
                show_back_button=False,
                )   
                return Destination(BackStackView)

            selected_menu_num = self.run_screen(
                ButtonListScreen,
                title="Select Secret",
                is_button_text_centered=False,
                button_data=button_data,
                show_back_button=True,
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            warning_screen_num = DireWarningScreen(
                status_headline="Delete Confirmation",
                text="This will delete this secret, this cannot be un-done",
            ).display()

            if warning_screen_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            self.loading_screen = LoadingScreenThread(text="Deleting Secret\n\n\n\n\n\n")
            self.loading_screen.start()

            result = Satochip_Connector.seedkeeper_reset_secret(headers_parsed[selected_menu_num][0])

            self.loading_screen.stop()

            LargeIconStatusScreen(
                text="Secret Deleted",
            ).display()

            return Destination(BackStackView)
            
        except Exception as e:
            logger.info(e)
            self.loading_screen.stop()
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=True,
            )
            return Destination(BackStackView)

class ToolsSeedkeeperLoadDescriptorView(View):
    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.views.seed_views import MultisigWalletDescriptorView
        try:
            Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
            
            if not Satochip_Connector:
                return Destination(BackStackView)

            self.loading_screen = LoadingScreenThread(text="Retrieving List of Secrets\n\n\n\n\n\n")
            self.loading_screen.start()

            headers = Satochip_Connector.seedkeeper_list_secret_headers()

            multisig_descriptor_secrets = []
            xpub_secrets = []
            button_data = []
            for header in headers:
                sid = header['id']
                stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))  # hex(header['type'])
                subtype = header['subtype']
                label = header['label']
                origin = SEEDKEEPER_DIC_ORIGIN.get(header['origin'], hex(header['origin']))  # hex(header['origin'])
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header['export_rights'],
                                                                 hex(header[
                                                                         'export_rights']))  # str(header['export_rights'])
                export_nbplain = str(header['export_nbplain'])
                export_nbsecure = str(header['export_nbsecure'])
                export_nbcounter = str(header['export_counter']) if header['type'] == 0x70 else 'N/A'
                fingerprint = header['fingerprint']

                if export_rights == 'Plaintext export allowed':
                    # Check for Seedkeeper V1 style Descriptors
                    if "msig_desc_" in label:
                        multisig_descriptor_secrets.append((sid, label.replace("msig_desc_", "")))
                        button_data.append(ButtonOption(label.replace("msig_desc_", "")))

                    if "xpub_" in label:
                        xpub_secrets.append((sid, label))

                    # Check for Seedkeeper V2 Style Descriptors
                    if stype == "Descriptor": 
                        multisig_descriptor_secrets.append((sid, label))
                        button_data.append(ButtonOption(label))

            logger.debug("Found %d multisig descriptor secrets", len(multisig_descriptor_secrets))
            logger.debug("Found %d xpub secrets", len(xpub_secrets))

            self.loading_screen.stop()

            if len(multisig_descriptor_secrets) < 1:
                self.run_screen(
                WarningScreen,
                title="No Descriptors",
                status_headline=None,
                text=f"No Multisig Descriptors to Load from Seedkeeper",
                show_back_button=False,
                )   
                return Destination(BackStackView)

            selected_menu_num = self.run_screen(
                ButtonListScreen,
                title="Select Descriptor",
                is_button_text_centered=False,
                button_data=button_data,
                show_back_button=True,
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            
            self.loading_screen = LoadingScreenThread(text="Loading Descriptor\n\n\n\n\n\n")
            self.loading_screen.start()

            secret_dict = Satochip_Connector.seedkeeper_export_secret(multisig_descriptor_secrets[selected_menu_num][0], None)

            stype = SEEDKEEPER_DIC_TYPE.get(secret_dict['type'], hex(secret_dict['type']))  # hex(header['type'])

            if stype == "Descriptor": # Seedkeeper V2 
                secret_template = unhexlify(secret_dict['secret'])[2:].decode()
            else:
                secret_dict['secret'] = unhexlify(secret_dict['secret'])[1:].decode()
                secret_template = secret_dict['secret']

                for idx, (xpub_secret_id, xpub_secret_label) in enumerate(xpub_secrets):
                    if xpub_secret_label in secret_template:
                        logger.debug("Matched on an xpub secret label at index %d", idx)
                        secret_dict = Satochip_Connector.seedkeeper_export_secret(xpub_secret_id, None)
                        secret_dict['secret'] = unhexlify(secret_dict['secret'])[1:].decode()
                        secret_template = secret_template.replace(xpub_secret_label, secret_dict['secret'])
                
            # Depending on where the descriptor came from whem imported into the SeedKeeper, it may need some characters swapped to work with Embit
            secret_template = secret_template.replace("<","{").replace(">","}").replace(";",",")

            self.controller.multisig_wallet_descriptor = Descriptor.from_string(secret_template)
            
            self.loading_screen.stop()

            return Destination(MultisigWalletDescriptorView, skip_current_view=True)
            

        except Exception as e:
            self.loading_screen.stop()
            logger.info(e)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=True,
            )
            return Destination(BackStackView)


class ToolsSeedkeeperSaveDescriptorView(View):
    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        try:
            # Load
            descriptor = self.controller.multisig_wallet_descriptor

            if descriptor == None:
                # No descriptor loaded, can't proceed further
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline="No Multisig Descriptor Loaded",
                    text="Nothing to save...",
                    show_back_button=True,
                )
        
                return Destination(BackStackView)

            # Break up the descriptor for efficient storage on SeedKeeper Cards
            descriptor_string = descriptor.to_string()

            logger.debug("descriptor_string: %s", descriptor_string)

            # Prompt for Descriptor Name
            ret = seed_screens.SeedAddPassphraseScreen(title="Descriptor Label").display()

            if "is_back_button" in ret:
                return Destination(BackStackView)

            # Set up our connection to the card
            Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])

            if not Satochip_Connector:
                return Destination(BackStackView)
            
            self.loading_screen = LoadingScreenThread(text="Saving Secrets\n\n\n\n\n\n")
            self.loading_screen.start()

            status = Satochip_Connector.card_get_status()[3]
            secrets_imported = 0
            secrets_skipped = 0

            key_strings = []

            if status['protocol_minor_version'] == 1: # Format needed for Seedkeeper v1 cards
                secret_type = "Password"
                # Split up the descriptor into smaller strings (needed for SeedKeeper v1)
                for key in descriptor.keys:
                    key_string = key.to_string()
                    key_name = "xpub_" + hexlify(key.fingerprint).decode()
                    
                    descriptor_string = descriptor_string.replace(key_string, key_name)
                    key_strings.append((key_name, key_string))

                key_strings.append(("msig_desc_" + ret['passphrase'], descriptor_string))
            
            else: # For Seedkeeper V2, we can just store the whole descriptor as-is
                secret_type = "Descriptor"
                key_strings.append((ret['passphrase'], descriptor_string))

            # Check for existing secrets on the Seedkeeper (Related to this descriptor)
            headers = Satochip_Connector.seedkeeper_list_secret_headers()

            multisig_descriptor_secrets = []
            xpub_labels = []
            button_data = []
            for header in headers:
                sid = header['id']
                stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))  # hex(header['type'])
                label = header['label']
                origin = SEEDKEEPER_DIC_ORIGIN.get(header['origin'], hex(header['origin']))  # hex(header['origin'])
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header['export_rights'],
                                                                    hex(header[
                                                                            'export_rights']))  # str(header['export_rights'])
                export_nbplain = str(header['export_nbplain'])
                export_nbsecure = str(header['export_nbsecure'])
                export_nbcounter = str(header['export_counter']) if header['type'] == 0x70 else 'N/A'
                fingerprint = header['fingerprint']

                if export_rights == 'Plaintext export allowed':
                    if "msig_desc_" in label:
                        multisig_descriptor_secrets.append((sid, label.replace("msig_desc_", "")))
                        button_data.append(ButtonOption(label.replace("msig_desc_", "")))

                    if "xpub_" in label:
                        xpub_labels.append(ButtonOption(label))

                    # Check for Seedkeeper V2 Style Descriptors
                    if stype == "Descriptor": 
                        multisig_descriptor_secrets.append((sid, label))

            logger.debug("Found %d multisig descriptor secrets", len(multisig_descriptor_secrets))
            logger.debug("Found %d xpub labels", len(xpub_labels))

            multisig_descriptor_templates = []

            for secret_id, secret_label in multisig_descriptor_secrets:
                secret_dict = Satochip_Connector.seedkeeper_export_secret(secret_id, None)

                secret_dict['secret'] = unhexlify(secret_dict['secret'])[1:].decode()

                multisig_descriptor_templates.append(secret_dict['secret'])

            logger.debug("Loaded %d multisig descriptor templates from Seedkeeper", len(multisig_descriptor_templates))

            # Do not log key_strings directly, as it may contain sensitive descriptor labels or passphrases
            logger.debug("Prepared %d key strings for Seedkeeper import", len(key_strings))

            # Add required secrets to seedkeeper
            for idx, (secret_label, secret_text) in enumerate(key_strings):
                if secret_text in multisig_descriptor_templates or secret_label in xpub_labels:
                    # Do not log secret labels directly, as they may contain sensitive information
                    logger.debug("Matched existing secret at index %d; skipping import", idx)
                    secrets_skipped += 1
                    continue
                header = Satochip_Connector.make_header(secret_type, "Plaintext export allowed", secret_label)
                if secret_type == "Password":
                    secret_text_list = list(bytes(secret_text, 'utf-8'))
                    secret_list = [len(secret_text_list)] + secret_text_list
                else:
                    secret_text_list = list(bytes(secret_text, 'utf-8'))
                    secret_list = list(len(secret_text_list).to_bytes(2,"big")) + secret_text_list
                secret_dic = {'header': header, 'secret_list': secret_list}
                try:
                    fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
                        Satochip_Connector, secret_dic
                    )
                except Exception as e:
                    self.loading_screen.stop()
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text=str(e),
                        show_back_button=True,
                    )
                    return Destination(BackStackView)

                if not fits:
                    self.loading_screen.stop()
                    self.run_screen(
                        WarningScreen,
                        title="Not Enough Space",
                        status_headline=None,
                        text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
                        show_back_button=True,
                    )
                    return Destination(BackStackView)
                (sid, fingerprint) = Satochip_Connector.seedkeeper_import_secret(secret_dic)
                logger.info("Imported - SID:", sid, " Fingerprint:", fingerprint)
                secrets_imported += 1

            self.loading_screen.stop()

            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="Multisig Descriptor Exported." + "\nExported:" + str(secrets_imported) + "\nSkipped:" + str(secrets_skipped),
                show_back_button=False,
            )

        except Exception as e:
            self.loading_screen.stop()
            logger.info(e)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=True,
            )
        
        return Destination(BackStackView)

class ToolsSatochipView(View):
    IMPORT_SEED = ButtonOption("Initialise with Seed")
    EXPORT_XPUB = ButtonOption("Export Xpub")
    LOAD_DESCRIPTOR = ButtonOption("Load as Descriptor")
    LOAD_PSBT = ButtonOption("Load PSBT")
    ADVANCED = ButtonOption("Advanced")

    def run(self):
        button_data = [
            self.IMPORT_SEED,
            self.EXPORT_XPUB,
            self.LOAD_DESCRIPTOR,
            self.LOAD_PSBT,
            self.ADVANCED,
        ]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Satochip",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.IMPORT_SEED:
            return Destination(ToolsSatochipImportSeedView)

        elif button_data[selected_menu_num] == self.EXPORT_XPUB:
            return Destination(SatochipExportXpubSigTypeView)

        elif button_data[selected_menu_num] == self.LOAD_DESCRIPTOR:
            return Destination(SatochipLoadDescriptorScriptTypeView)
        elif button_data[selected_menu_num] == self.LOAD_PSBT:
            return Destination(ToolsSatochipLoadPsbtView)
        elif button_data[selected_menu_num] == self.ADVANCED:
            return Destination(ToolsSatochipAdvancedView)


class ToolsSatochipLoadPsbtView(View):
    def run(self):
        from seedsigner.views.psbt_views import PSBTSelectSeedView

        # Reset microSD PSBT context before prompting the user.
        self.controller.psbt_from_microsd = False
        self.controller.psbt_microsd_save_path = None
        self.controller.psbt_microsd_seed_warning_shown = False

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            self.controller.psbt_microsd_seed_warning_shown = True

        psbt_dir = MicroSD.get_microsd_dir() / "psbt"
        try:
            psbt_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.exception("Failed to access PSBT directory", exc_info=e)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        psbt_files = sorted(
            [
                p
                for p in psbt_dir.iterdir()
                if p.is_file() and not p.name.startswith(".") and p.suffix.lower() == ".psbt"
            ],
            key=lambda p: p.name.lower(),
        )

        if not psbt_files:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No PSBT files found in psbt/.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        button_data = [ButtonOption(path.name) for path in psbt_files]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select PSBT",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        selected_path = psbt_files[selected]
        try:
            psbt_data = selected_path.read_bytes()
            psbt = PSBT.parse(psbt_data)
        except Exception as e:
            logger.exception("Failed to load PSBT from microSD", exc_info=e)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(ToolsSatochipLoadPsbtView)

        self.controller.psbt = psbt
        self.controller.psbt_parser = None
        self.controller.psbt_seed = None
        self.controller.psbt_sign_with_satochip = False
        self.controller.psbt_from_microsd = True
        self.controller.psbt_microsd_save_path = selected_path

        return Destination(PSBTSelectSeedView, skip_current_view=True)

class ToolsSatochipAdvancedView(View):
    ENABLE_2FA = ButtonOption("Enable 2FA")
    BENCHMARK = ButtonOption("Benchmark Signing")
    BENCHMARK_MESSAGE = ButtonOption("Benchmark Message Signing")
    BIAS_TEST = ButtonOption("Check signing bias")

    def run(self):
        button_data = [self.ENABLE_2FA, self.BENCHMARK, self.BENCHMARK_MESSAGE, self.BIAS_TEST]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Satochip Advanced",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.ENABLE_2FA:
            return Destination(ToolsSatochipEnable2FAView)

        elif button_data[selected_menu_num] == self.BENCHMARK:
            return Destination(ToolsSatochipBenchmarkSignView)

        elif button_data[selected_menu_num] == self.BENCHMARK_MESSAGE:
            return Destination(ToolsSatochipBenchmarkMessageSignView)

        elif button_data[selected_menu_num] == self.BIAS_TEST:
            return Destination(ToolsSatochipBiasCheckView)

class ToolsSatochipBenchmarkSignView(View):
    """Benchmark Satochip signing performance."""

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread

        connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip"])
        if not connector:
            return Destination(BackStackView)

        timeout = 5.0
        durations: list[float] = []
        loading = LoadingScreenThread(text="Benchmarking\n\n\n\n\n\n")
        loading.start()
        for _ in range(20):
            tx_hash = os.urandom(32)
            start = time.monotonic()
            try:
                _call_with_timeout(
                    connector.card_sign_transaction_hash,
                    timeout,
                    0xFF,
                    list(tx_hash),
                    None,
                )
                durations.append(time.monotonic() - start)
            except Exception as e:
                logger.warning("Benchmark signing failed: %s", e)
        loading.stop()

        if durations:
            avg = sum(durations) / len(durations)
            min_time = min(durations)
            max_time = max(durations)
            logger.info(
                "Benchmark signing results: min=%.3fs avg=%.3fs max=%.3fs over %d signatures",
                min_time,
                avg,
                max_time,
                len(durations),
            )
            text = (
                "Min: {min_time:.3f}s\n"
                "Avg: {avg:.3f}s\n"
                "Max: {max_time:.3f}s"
            ).format(min_time=min_time, avg=avg, max_time=max_time)
        else:
            text = "Benchmark signing failed"

        self.run_screen(
            LargeIconStatusScreen,
            title="Benchmark",
            status_headline=None,
            text=text,
            show_back_button=False,
        )
        return Destination(MainMenuView)


class ToolsSatochipBenchmarkMessageSignView(View):
    """Benchmark Satochip message signing performance."""

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread

        connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip"])
        if not connector:
            return Destination(BackStackView)

        timeout = 5.0
        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        coin_type = "0" if network == SettingsConstants.MAINNET else "1"
        derivation_path = f"m/84'/{coin_type}'/0'/0/0"
        path = format_path_string(derivation_path)

        durations: list[float] = []
        error: str | None = None
        loading = LoadingScreenThread(text="Benchmarking\n\n\n\n\n\n")
        loading.start()
        try:
            try:
                key, _ = _get_extended_key(connector, path)
            except Exception as exc:
                logger.warning("Benchmark message signing failed: %s", exc)
                error = str(exc)
            else:
                for _ in range(20):
                    message = os.urandom(16).hex()
                    start = time.monotonic()
                    try:
                        _call_with_timeout(
                            connector.card_sign_message,
                            timeout,
                            0xFF,
                            key,
                            message,
                        )
                    except Exception as exc:
                        logger.warning("Benchmark message signing failed: %s", exc)
                        error = str(exc)
                        break
                    else:
                        durations.append(time.monotonic() - start)
        finally:
            loading.stop()

        if durations:
            avg = sum(durations) / len(durations)
            min_time = min(durations)
            max_time = max(durations)
            logger.info(
                "Benchmark message signing results: min=%.3fs avg=%.3fs max=%.3fs over %d signatures",
                min_time,
                avg,
                max_time,
                len(durations),
            )
            text = (
                "Min: {min_time:.3f}s\n"
                "Avg: {avg:.3f}s\n"
                "Max: {max_time:.3f}s"
            ).format(min_time=min_time, avg=avg, max_time=max_time)
        else:
            text = error or "Benchmark signing failed"

        self.run_screen(
            LargeIconStatusScreen,
            title="Benchmark",
            status_headline=None,
            text=text,
            show_back_button=False,
        )
        return Destination(MainMenuView)


class ToolsSatochipImportSeedView(View):
    SCAN_SEED = ButtonOption("Scan a seed", SeedSignerIconConstants.QRCODE)
    TYPE_12WORD = ButtonOption("Enter 12-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=12)
    TYPE_15WORD = ButtonOption("Enter 15-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=15)
    TYPE_18WORD = ButtonOption("Enter 18-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=18)
    TYPE_21WORD = ButtonOption("Enter 21-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=21)
    TYPE_24WORD = ButtonOption("Enter 24-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=24)
    TYPE_ELECTRUM = ButtonOption("Enter Electrum seed", FontAwesomeIconConstants.KEYBOARD)
    TYPE_SLIP39 = ButtonOption("SLIP-39 Shares", FontAwesomeIconConstants.KEYBOARD)
    IMPORT_SEEDKEEPER = ButtonOption("From SeedKeeper", FontAwesomeIconConstants.LOCK)
    CREATE = ButtonOption(" Create a seed", SeedSignerIconConstants.PLUS)

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip"])

        if not Satochip_Connector:
            return Destination(BackStackView)

        # Prevent reseeding an already-initialized card. Attempting to import a new
        # seed into a seeded Satochip results in a generic failure. Instead, check
        # the card's status up front and inform the user so they can take
        # appropriate action (like resetting the card) before proceeding.
        _resp, _sw1, _sw2, status = Satochip_Connector.card_get_status()
        if status.get("is_seeded"):
            self.run_screen(
                WarningScreen,
                title=_("Already Seeded"),
                status_headline=None,
                text=_("Satochip card already contains a seed."),
                show_back_button=False,
            )
            return Destination(MainMenuView)

        seeds = self.controller.storage.seeds
        button_data = []
        for seed in seeds:
            button_str = seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
            button_data.append(ButtonOption(button_str, SeedSignerIconConstants.FINGERPRINT))
        
        seed_lengths = self.settings.get_value(SettingsConstants.SETTING__SEED_WORD_LENGTHS)
        options = {
            12: self.TYPE_12WORD,
            15: self.TYPE_15WORD,
            18: self.TYPE_18WORD,
            21: self.TYPE_21WORD,
            24: self.TYPE_24WORD,
        }
        button_data = button_data + [self.SCAN_SEED] + [options[l] for l in seed_lengths]
        if self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_SUPPORT) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.IMPORT_SEEDKEEPER)
        if self.settings.get_value(SettingsConstants.SETTING__SLIP39_SEEDS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TYPE_SLIP39)
        button_data.append(self.CREATE)
        if self.settings.get_value(SettingsConstants.SETTING__ELECTRUM_SEEDS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TYPE_ELECTRUM)
        
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Seed to Import",
            button_data=button_data,
            is_button_text_centered=False,
            is_bottom_list=True,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Most of the options require us to go through a side flow(s) before we can
        # continue to the address explorer. Set the Controller-level flow so that it
        # knows to re-route us once the side flow is complete.        
        # self.controller.resume_main_flow = Controller.FLOW__SATOCHIP_IMPORT_SEED

        if len(seeds) > 0 and selected_menu_num < len(seeds):
            # User selected one of the n seeds
            if isinstance(seeds[selected_menu_num], XprvSeed):
                self.run_screen(
                    WarningScreen,
                    title="Unsupported",
                    status_headline=None,
                    text=_("xprv cannot init Satochip.\nUse BIP39, SLIP39, or Electrum."),
                    show_back_button=False,
                )
                return Destination(BackStackView)

            try:
                self.loading_screen = LoadingScreenThread(text="Importing Secret\n\n\n\n\n\n")
                self.loading_screen.start()

                Satochip_Connector.card_bip32_import_seed(seeds[selected_menu_num].seed_bytes)

                self.loading_screen.stop()

                logger.info("Seed Successfully Imported")
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text=f"Seed Imported",
                    show_back_button=False,
                )
            except Exception as e:
                self.loading_screen.stop()
                logger.info("Satochip Import Failed:",str(e))
                self.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text=f"Seed Import Failed",
                    show_back_button=False,
                )

        elif button_data[selected_menu_num] == self.SCAN_SEED:
            from seedsigner.views.scan_views import ScanSeedQRView
            return Destination(ScanSeedQRView)

        elif button_data[selected_menu_num] in [self.TYPE_12WORD, self.TYPE_15WORD, self.TYPE_18WORD, self.TYPE_21WORD, self.TYPE_24WORD]:
            from seedsigner.views.seed_views import SeedMnemonicEntryView
            self.controller.storage.init_pending_mnemonic(num_words=button_data[selected_menu_num].return_data)
            return Destination(SeedMnemonicEntryView)
        elif button_data[selected_menu_num] == self.IMPORT_SEEDKEEPER:
            return Destination(SeedKeeperSelectView)
        elif button_data[selected_menu_num] == self.TYPE_SLIP39:
            return Destination(SeedSlip39MnemonicStartView)
        elif button_data[selected_menu_num] == self.CREATE:
            return Destination(ToolsMenuView, view_args={"include_password_generator": False})
        elif button_data[selected_menu_num] == self.TYPE_ELECTRUM:
            return Destination(SeedElectrumMnemonicStartView)
        
        return Destination(MainMenuView)

class ToolsSatochipEnable2FAView(View):
    def run(self):
        from os import urandom
        import binascii
        from seedsigner.gui.screens.screen import LoadingScreenThread
        key = urandom(20)
        # Avoid logging the 2FA key value
        logger.info("2FA key generated")

        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip"])

        if not Satochip_Connector:
            return Destination(BackStackView)
        
        try:
            self.run_screen(
                WarningScreen,
                title="Warning",
                status_headline=None,
                text=f"Scan the following QR code with the Satochip 2FA app before proceeding (You will not see this code again...)",
                show_back_button=False,
            )
            from seedsigner.gui.screens.screen import QRDisplayScreen
            from seedsigner.models.encode_qr import GenericStaticQrEncoder

            qr_encoder = GenericStaticQrEncoder(data=binascii.hexlify(key).decode())

            self.run_screen(
                QRDisplayScreen,
                qr_encoder=qr_encoder,
            )

            self.loading_screen = LoadingScreenThread(text="Enabling 2FA\n\n\n\n\n\n")
            self.loading_screen.start()

            Satochip_Connector.card_set_2FA_key(key, 0)

            self.loading_screen.stop()

            logger.info("Success: 2FA Key Imported and Enabled")
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"2FA Enabled",
                show_back_button=False,
            )
        except Exception as e:
            self.loading_screen.stop()
            logger.info("Enable 2fa failed:", str(e))
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=f"Enable 2FA Failed",
                show_back_button=False,
            )

        return Destination(MainMenuView)


class SatochipExportXpubSigTypeView(View):
    SINGLE_SIG = ButtonOption(_("Single Sig"), return_data=SettingsConstants.SINGLE_SIG)
    MULTISIG = ButtonOption(_("Multisig"), return_data=SettingsConstants.MULTISIG)

    def run(self):
        sig_types = self.settings.get_value(SettingsConstants.SETTING__SIG_TYPES)
        if len(sig_types) == 1:
            return Destination(
                SatochipExportXpubScriptTypeView,
                view_args=dict(sig_type=sig_types[0]),
                skip_current_view=True,
            )

        button_data = [self.SINGLE_SIG, self.MULTISIG]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Export Xpub"),
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            SatochipExportXpubScriptTypeView,
            view_args=dict(sig_type=button_data[selected_menu_num].return_data),
        )


class SatochipExportXpubScriptTypeView(View):
    def __init__(self, sig_type: str, script_type: str = None):
        super().__init__()
        self.sig_type = sig_type
        self.script_type = script_type

    def run(self):
        Satochip_Connector = seedkeeper_utils.init_satochip(
            self, init_card_filter=["satochip"], require_pin=False
        )
        if not Satochip_Connector:
            return Destination(BackStackView)

        status = Satochip_Connector.card_get_status()[3]
        schnorr_supported = status.get("feature_schnorr_policy") == 0

        button_data = []
        for script_type, display_name in SettingsConstants.ALL_SCRIPT_TYPES:
            if script_type in self.settings.get_value(SettingsConstants.SETTING__SCRIPT_TYPES):
                if script_type == SettingsConstants.TAPROOT and not schnorr_supported:
                    continue
                button_data.append(ButtonOption(display_name, return_data=script_type))

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Export Xpub",
            is_button_text_centered=False,
            button_data=button_data,
            is_bottom_list=True,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        script_type = button_data[selected_menu_num].return_data
        if script_type == SettingsConstants.CUSTOM_DERIVATION:
            return Destination(
                SatochipExportXpubCustomDerivationView,
                view_args=dict(sig_type=self.sig_type, script_type=script_type),
            )
        if (
            self.settings.get_value(SettingsConstants.SETTING__ACCOUNT_PROMPT)
            == SettingsConstants.OPTION__ENABLED
        ):
            return Destination(
                AccountNumberView,
                view_args=dict(next_view_cls=SatochipExportXpubCoordinatorView, next_view_args=dict(sig_type=self.sig_type, script_type=script_type)),
            )
        return Destination(
            SatochipExportXpubCoordinatorView,
            view_args=dict(sig_type=self.sig_type, script_type=script_type),
        )


class SatochipExportXpubCustomDerivationView(View):
    def __init__(self, sig_type: str, script_type: str):
        super().__init__()
        self.sig_type = sig_type
        self.script_type = script_type
        self.custom_derivation_path = "m/"

    def run(self):
        ret = self.run_screen(
            seed_screens.SeedExportXpubCustomDerivationScreen,
            initial_value=self.custom_derivation_path,
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            SatochipExportXpubCoordinatorView,
            view_args=dict(sig_type=self.sig_type, script_type=self.script_type, custom_derivation=ret),
        )


class SatochipExportXpubCoordinatorView(View):
    def __init__(self, sig_type: str, script_type: str, custom_derivation: str = "", account: int = 0):
        super().__init__()
        self.sig_type = sig_type
        self.script_type = script_type
        self.custom_derivation = custom_derivation
        self.account = account

    def run(self):
        button_data = []
        for coord, display_name in SettingsConstants.ALL_COORDINATORS:
            if coord in self.settings.get_value(SettingsConstants.SETTING__COORDINATORS):
                button_data.append(ButtonOption(display_name, return_data=coord))

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Coordinator",
            is_button_text_centered=False,
            button_data=button_data,
            is_bottom_list=True,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        coordinator = button_data[selected_menu_num].return_data
        coordinator_label = button_data[selected_menu_num].button_label
        return Destination(
            SatochipExportXpubWarningView,
            view_args=dict(
                sig_type=self.sig_type,
                script_type=self.script_type,
                coordinator=coordinator,
                custom_derivation=self.custom_derivation,
                coordinator_label=coordinator_label,
                account=self.account,
            ),
        )


class SatochipExportXpubWarningView(View):
    def __init__(self, sig_type: str, script_type: str, coordinator: str, custom_derivation: str, coordinator_label: str, account: int = 0):
        super().__init__()
        self.sig_type = sig_type
        self.script_type = script_type
        self.coordinator = coordinator
        self.custom_derivation = custom_derivation
        self.coordinator_label = coordinator_label
        self.account = account

    def run(self):
        destination = Destination(
            SatochipExportXpubDetailsView,
            view_args=dict(
                sig_type=self.sig_type,
                script_type=self.script_type,
                coordinator=self.coordinator,
                custom_derivation=self.custom_derivation,
                coordinator_label=self.coordinator_label,
                account=self.account,
            ),
            skip_current_view=True,
        )

        if self.settings.get_value(SettingsConstants.SETTING__PRIVACY_WARNINGS) == SettingsConstants.OPTION__DISABLED:
            return destination

        selected_menu_num = self.run_screen(
            WarningScreen,
            status_headline=_("Privacy Leak!"),
            text=_("Xpub can be used to view all future transactions."),
        )

        if selected_menu_num == 0:
            return destination

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)


class SatochipExportXpubDetailsView(View):
    def __init__(self, sig_type: str, script_type: str, coordinator: str, custom_derivation: str, coordinator_label: str, account: int = 0):
        super().__init__()
        self.sig_type = sig_type
        self.script_type = script_type
        self.coordinator = coordinator
        self.custom_derivation = custom_derivation
        self.coordinator_label = coordinator_label
        self.account = account

    def run(self):
        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip"])
        if not Satochip_Connector:
            return Destination(BackStackView)

        if self.script_type == SettingsConstants.CUSTOM_DERIVATION:
            derivation_path = self.custom_derivation
        else:
            derivation_path = embit_utils.get_standard_derivation_path(
                network=self.settings.get_value(SettingsConstants.SETTING__NETWORK),
                wallet_type=self.sig_type,
                script_type=self.script_type,
                account=self.account,
            )

        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        is_mainnet = network == SettingsConstants.MAINNET

        if self.sig_type == SettingsConstants.MULTISIG:
            if self.script_type == SettingsConstants.NATIVE_SEGWIT:
                xtype = "p2wsh"
            elif self.script_type == SettingsConstants.NESTED_SEGWIT:
                xtype = "p2wsh-p2sh"
            elif self.script_type == SettingsConstants.LEGACY_P2PKH:
                xtype = "standard"
            else:
                xtype = "p2wsh"
        else:
            if self.script_type == SettingsConstants.NATIVE_SEGWIT:
                xtype = "p2wpkh"
            elif self.script_type == SettingsConstants.NESTED_SEGWIT:
                xtype = "p2wpkh-p2sh"
            elif self.script_type == SettingsConstants.LEGACY_P2PKH:
                xtype = "standard"
            elif self.script_type == SettingsConstants.TAPROOT:
                xtype = "standard"
            else:
                xtype = "p2wpkh"
        from seedsigner.gui.screens.screen import LoadingScreenThread
        loading = LoadingScreenThread(text=_("Exporting xpub..."))
        loading.start()
        try:
            xpub_base58 = Satochip_Connector.card_bip32_get_xpub(derivation_path, xtype, is_mainnet)
            master_xpub = Satochip_Connector.card_bip32_get_xpub("", xtype, is_mainnet)
        except Exception as e:
            loading.stop()
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=str(e),
            )
            return Destination(BackStackView)
        finally:
            loading.stop()

        fingerprint = HDKey.from_string(master_xpub).my_fingerprint
        fingerprint_hex = hexlify(fingerprint).decode("utf-8")

        if self.sig_type == SettingsConstants.SINGLE_SIG:
            # Build descriptor and store for address explorer
            if self.script_type == SettingsConstants.NATIVE_SEGWIT:
                desc_str = f"wpkh({xpub_base58}/{{0,1}}/*)"
            elif self.script_type == SettingsConstants.NESTED_SEGWIT:
                desc_str = f"sh(wpkh({xpub_base58}/{{0,1}}/*))"
            elif self.script_type == SettingsConstants.LEGACY_P2PKH:
                desc_str = f"pkh({xpub_base58}/{{0,1}}/*)"
            elif self.script_type == SettingsConstants.TAPROOT:
                desc_str = f"tr({xpub_base58}/{{0,1}}/*)"
            else:
                desc_str = f"wpkh({xpub_base58}/{{0,1}}/*)"

            self.controller.multisig_wallet_descriptor = Descriptor.from_string(desc_str)

        selected_menu_num = self.run_screen(
            seed_screens.SeedExportXpubDetailsScreen,
            fingerprint=fingerprint_hex,
            has_passphrase=False,
            derivation_path=derivation_path,
            xpub=xpub_base58,
        )

        if selected_menu_num != 0:
            return Destination(BackStackView)

        return Destination(
            SatochipExportXpubQRDisplayView,
            view_args=dict(
                xpub=xpub_base58,
                derivation_path=derivation_path,
                script_type=self.script_type,
                coordinator=self.coordinator,
                coordinator_label=self.coordinator_label,
                fingerprint=fingerprint_hex,
                sig_type=self.sig_type,
            ),
        )


class SatochipExportXpubQRDisplayView(View):
    def __init__(
        self,
        xpub: str,
        derivation_path: str,
        script_type: str,
        coordinator: str,
        coordinator_label: str = "",
        fingerprint: str = "",
        sig_type: str = SettingsConstants.SINGLE_SIG,
    ):
        super().__init__()
        self.xpub = xpub
        self.derivation_path = derivation_path
        self.script_type = script_type
        self.coordinator = coordinator
        self.coordinator_label = coordinator_label
        self.fingerprint = fingerprint
        self.sig_type = sig_type

    class _SpecterEncoder:
        def __init__(self, xpubstring: str, qr_density: str):
            density_mapping = {
                SettingsConstants.DENSITY__LOW: 40,
                SettingsConstants.DENSITY__MEDIUM: 65,
                SettingsConstants.DENSITY__HIGH: 90,
            }
            self.qr_max_fragment_size = density_mapping.get(qr_density, 65)
            self.parts = []
            start = 0
            stop = self.qr_max_fragment_size
            qr_cnt = ((len(xpubstring) - 1) // self.qr_max_fragment_size) + 1
            if qr_cnt == 1:
                self.parts.append(xpubstring[start:stop])
            cnt = 0
            while cnt < qr_cnt and qr_cnt != 1:
                part = "p" + str(cnt + 1) + "of" + str(qr_cnt) + " " + xpubstring[start:stop]
                self.parts.append(part)
                start = start + self.qr_max_fragment_size
                stop = stop + self.qr_max_fragment_size
                if stop > len(xpubstring):
                    stop = len(xpubstring)
                cnt += 1
            self.part_num_sent = 0

        def next_part(self):
            if self.part_num_sent > (len(self.parts) - 1):
                self.part_num_sent = 0
            part = self.parts[self.part_num_sent]
            self.part_num_sent += 1
            return part

        def cur_part(self):
            if self.part_num_sent == 0:
                self.part_num_sent = len(self.parts) - 1
            else:
                self.part_num_sent -= 1
            return self.next_part()

        def restart(self):
            self.part_num_sent = 0

        def is_complete(self):
            return len(self.parts) == 1

        def seq_len(self):
            return len(self.parts)

    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        xpubstring = f"[{self.fingerprint}{self.derivation_path[1:]}]{self.xpub}"

        if self.coordinator == SettingsConstants.COORDINATOR__SPECTER_DESKTOP:
            encoder = self._SpecterEncoder(xpubstring, self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY))
        else:
            encoder = GenericStaticQrEncoder(data=xpubstring)

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=encoder,
        )

        if self.sig_type == SettingsConstants.SINGLE_SIG:
            return Destination(
                SeedExportXpubVerifyAddressView,
                view_args=dict(
                    seed_num=None,
                    derivation_path=self.derivation_path,
                    script_type=self.script_type,
                    sig_type=self.sig_type,
                    coordinator_label=self.coordinator_label,
                ),
                skip_current_view=True,
            )

        return Destination(MainMenuView)


class SatochipLoadDescriptorScriptTypeView(View):
    def __init__(self, script_type: str = None):
        super().__init__()
        self.script_type = script_type

    def run(self):
        Satochip_Connector = seedkeeper_utils.init_satochip(
            self, init_card_filter=["satochip"], require_pin=False
        )
        if not Satochip_Connector:
            return Destination(BackStackView)

        status = Satochip_Connector.card_get_status()[3]
        schnorr_supported = status.get("feature_schnorr_policy") == 0

        button_data = []
        for script_type, display_name in SettingsConstants.ALL_SCRIPT_TYPES:
            if script_type in self.settings.get_value(SettingsConstants.SETTING__SCRIPT_TYPES):
                if script_type == SettingsConstants.TAPROOT and not schnorr_supported:
                    continue
                button_data.append(ButtonOption(display_name, return_data=script_type))

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Load Descriptor",
            is_button_text_centered=False,
            button_data=button_data,
            is_bottom_list=True,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        script_type = button_data[selected_menu_num].return_data
        if script_type == SettingsConstants.CUSTOM_DERIVATION:
            return Destination(SatochipLoadDescriptorCustomDerivationView, view_args=dict(script_type=script_type))
        if self.settings.get_value(SettingsConstants.SETTING__ACCOUNT_PROMPT) == SettingsConstants.OPTION__ENABLED:
            return Destination(AccountNumberView, view_args=dict(next_view_cls=SatochipLoadDescriptorDetailsView, next_view_args=dict(script_type=script_type)))
        return Destination(SatochipLoadDescriptorDetailsView, view_args=dict(script_type=script_type))


class SatochipLoadDescriptorCustomDerivationView(View):
    def __init__(self, script_type: str):
        super().__init__()
        self.script_type = script_type
        self.custom_derivation_path = "m/"

    def run(self):
        ret = self.run_screen(
            seed_screens.SeedExportXpubCustomDerivationScreen,
            initial_value=self.custom_derivation_path,
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            SatochipLoadDescriptorDetailsView,
            view_args=dict(script_type=self.script_type, custom_derivation=ret),
        )


class SatochipLoadDescriptorDetailsView(View):
    def __init__(self, script_type: str, custom_derivation: str = "", account: int = 0):
        super().__init__()
        self.script_type = script_type
        self.custom_derivation = custom_derivation
        self.account = account

    def run(self):
        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip"])
        if not Satochip_Connector:
            return Destination(BackStackView)

        if self.script_type == SettingsConstants.CUSTOM_DERIVATION:
            derivation_path = self.custom_derivation
        else:
            derivation_path = embit_utils.get_standard_derivation_path(
                network=self.settings.get_value(SettingsConstants.SETTING__NETWORK),
                wallet_type=SettingsConstants.SINGLE_SIG,
                script_type=self.script_type,
                account=self.account,
            )

        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        is_mainnet = network == SettingsConstants.MAINNET
        if self.script_type == SettingsConstants.NATIVE_SEGWIT:
            xtype = "p2wpkh"
        elif self.script_type == SettingsConstants.NESTED_SEGWIT:
            xtype = "p2wpkh-p2sh"
        elif self.script_type == SettingsConstants.LEGACY_P2PKH:
            xtype = "standard"
        elif self.script_type == SettingsConstants.TAPROOT:
            xtype = "standard"
        else:
            xtype = "p2wpkh"
        from seedsigner.gui.screens.screen import LoadingScreenThread
        loading = LoadingScreenThread(text=_("Exporting xpub..."))
        loading.start()
        try:
            xpub_base58 = Satochip_Connector.card_bip32_get_xpub(derivation_path, xtype, is_mainnet)
            master_xpub = Satochip_Connector.card_bip32_get_xpub("", xtype, is_mainnet)
        except Exception as e:
            loading.stop()
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=str(e),
            )
            return Destination(BackStackView)
        finally:
            loading.stop()

        fingerprint = HDKey.from_string(master_xpub).my_fingerprint
        fingerprint_hex = hexlify(fingerprint).decode("utf-8")
        if derivation_path.startswith("m/"):
            origin_path = derivation_path[2:]
        else:
            origin_path = derivation_path

        if self.script_type == SettingsConstants.NATIVE_SEGWIT:
            desc_str = f"wpkh([{fingerprint_hex}/{origin_path}]{xpub_base58}/{{0,1}}/*)"
        elif self.script_type == SettingsConstants.NESTED_SEGWIT:
            desc_str = f"sh(wpkh([{fingerprint_hex}/{origin_path}]{xpub_base58}/{{0,1}}/*))"
        elif self.script_type == SettingsConstants.LEGACY_P2PKH:
            desc_str = f"pkh([{fingerprint_hex}/{origin_path}]{xpub_base58}/{{0,1}}/*)"
        elif self.script_type == SettingsConstants.TAPROOT:
            desc_str = f"tr([{fingerprint_hex}/{origin_path}]{xpub_base58}/{{0,1}}/*)"
        else:
            desc_str = f"wpkh([{fingerprint_hex}/{origin_path}]{xpub_base58}/{{0,1}}/*)"

        descriptor = Descriptor.from_string(desc_str)

        selected_menu_num = self.run_screen(
            seed_screens.SeedExportXpubDetailsScreen,
            fingerprint=fingerprint_hex,
            has_passphrase=False,
            derivation_path=derivation_path,
            xpub=xpub_base58,
            button_label="Confirm",
        )

        if selected_menu_num != 0:
            return Destination(BackStackView)

        self.controller.multisig_wallet_descriptor = descriptor
        from seedsigner.controller import Controller
        if self.controller.resume_main_flow == Controller.FLOW__ADDRESS_EXPLORER:
            from seedsigner.views.seed_views import MultisigWalletDescriptorView
            return Destination(MultisigWalletDescriptorView, skip_current_view=True)
        elif self.controller.resume_main_flow == Controller.FLOW__VERIFY_SINGLESIG_ADDR:
            from seedsigner.views.seed_views import SeedAddressVerificationView
            self.controller.resume_main_flow = None
            return Destination(SeedAddressVerificationView, skip_current_view=True)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Descriptor Loaded",
            show_back_button=False,
        )

        return Destination(MainMenuView)

class ToolsSatochipDIYView(View):
    MANAGE_KEYS = ButtonOption("Card Keys")
    BUILD_APPLETS = ButtonOption("Build Applets")
    INSTALL_APPLET = ButtonOption("Install Applet")
    UNINSTALL_APPLET = ButtonOption("Uninstall Applet")

    def run(self):
        # Check if GlobalPlatoform is available as a way of checking if the DIY tools we need are available
        from pathlib import Path
        from seedsigner.models.settings import Settings

        if Settings.HOSTNAME == Settings.SEEDSIGNER_OS:
            global_platform_path = "/mnt/diy/Satochip-DIY/gp.jar"
        elif os.path.exists("/home/pi"):
            global_platform_path = "/home/pi/Satochip-DIY/gp.jar"
        else:
            global_platform_path = str(Path.home() / "Satochip-DIY/gp.jar")

        if os.path.exists(global_platform_path):
            pass
        else:
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text="MicroSD with SeedSigner+Satochip Required...",
                show_back_button=False,
            )

        button_data = [
            self.BUILD_APPLETS,
            self.INSTALL_APPLET,
            self.UNINSTALL_APPLET,
            self.MANAGE_KEYS,
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Javacard DIY",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
          
        elif button_data[selected_menu_num] == self.BUILD_APPLETS:
            return Destination(ToolsDIYBuildAppletsView)

        elif button_data[selected_menu_num] == self.INSTALL_APPLET:
            return Destination(ToolsDIYInstallAppletView)

        elif button_data[selected_menu_num] == self.UNINSTALL_APPLET:
            return Destination(ToolsDIYUninstallAppletView)

        elif button_data[selected_menu_num] == self.MANAGE_KEYS:
            return Destination(ToolsJavacardKeysView)


JAVACARD_KEYS_MICROSD_FILENAME = "javacard-keys.txt"
JAVACARD_KEYS_SEEDKEEPER_PREFIX = "jc_keys_"


def _normalize_javacard_key(value: str) -> str:
    cleaned = re.sub(r"\s+", "", value or "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 32:
        raise ValueError("Key must be 32 hex characters")
    if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise ValueError("Key must be 32 hex characters")
    return cleaned.upper()


def _parse_javacard_keys(text: str) -> dict:
    if not text:
        raise ValueError("No key data provided")

    labels = {
        "key": "key",
        "single": "key",
        "enc": "enc",
        "key-enc": "enc",
        "key_enc": "enc",
        "mac": "mac",
        "key-mac": "mac",
        "key_mac": "mac",
        "dek": "dek",
        "key-dek": "dek",
        "key_dek": "dek",
    }

    labeled = {}
    tokens = []

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        match = re.match(r"^([A-Za-z0-9_-]+)\s*[:=]\s*(.+)$", line)
        if match:
            label = match.group(1).strip().lower()
            if label in labels:
                labeled[labels[label]] = _normalize_javacard_key(match.group(2))
                continue

        parts = line.split()
        if len(parts) == 2 and parts[0].lower() in labels:
            labeled[labels[parts[0].lower()]] = _normalize_javacard_key(parts[1])
        else:
            tokens.extend(parts)

    if labeled:
        if "key" in labeled:
            if any(k in labeled for k in ("enc", "mac", "dek")):
                raise ValueError("Single key cannot be mixed with key set")
            return {"type": "single", "key": labeled["key"]}
        missing = [k for k in ("enc", "mac", "dek") if k not in labeled]
        if missing:
            raise ValueError("Key set requires ENC, MAC, and DEK")
        return {
            "type": "set",
            "enc": labeled["enc"],
            "mac": labeled["mac"],
            "dek": labeled["dek"],
        }

    if len(tokens) == 1:
        return {"type": "single", "key": _normalize_javacard_key(tokens[0])}
    if len(tokens) == 3:
        return {
            "type": "set",
            "enc": _normalize_javacard_key(tokens[0]),
            "mac": _normalize_javacard_key(tokens[1]),
            "dek": _normalize_javacard_key(tokens[2]),
        }

    raise ValueError("Unrecognized key format")


def _format_javacard_keys(keys: dict) -> str:
    if keys["type"] == "single":
        return f"{keys['key']}\n"
    return f"ENC={keys['enc']}\nMAC={keys['mac']}\nDEK={keys['dek']}\n"


def _format_gp_key_args(keys: dict, flag: str) -> str:
    if keys["type"] == "single":
        return f"{flag} {keys['key']}"
    return (
        f"{flag}-enc {keys['enc']} "
        f"{flag}-mac {keys['mac']} "
        f"{flag}-dek {keys['dek']}"
    )


def _decode_seedkeeper_text(secret_dict: dict) -> str:
    raw = binascii.unhexlify(secret_dict["secret"])
    if len(raw) >= 2 and int.from_bytes(raw[:2], "big") == len(raw[2:]):
        data = raw[2:]
    elif len(raw) >= 1 and raw[0] == len(raw[1:]):
        data = raw[1:]
    else:
        data = raw
    return data.decode("utf-8")


class ToolsJavacardKeysView(View):
    LOAD_KEYS = ButtonOption("Load Keys")
    SAVE_KEYS = ButtonOption("Save Keys")
    UNLOCK_CARD = ButtonOption("Unlock Card")
    LOCK_CARD = ButtonOption("Lock Card")
    CLEAR_KEYS = ButtonOption("Clear Loaded Keys")

    def run(self):
        button_data = [
            self.LOAD_KEYS,
            self.SAVE_KEYS,
            self.UNLOCK_CARD,
            self.LOCK_CARD,
            self.CLEAR_KEYS,
        ]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Javacard Keys",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        choice = button_data[selected_menu_num]
        if choice == self.LOAD_KEYS:
            return Destination(ToolsJavacardLoadKeysView)
        if choice == self.SAVE_KEYS:
            return Destination(ToolsJavacardSaveKeysView)
        if choice == self.UNLOCK_CARD:
            return Destination(ToolsJavacardUnlockCardView)
        if choice == self.LOCK_CARD:
            return Destination(ToolsJavacardLockCardView)
        return Destination(ToolsJavacardClearKeysView)


class ToolsJavacardLoadKeysView(View):
    ENTER_SINGLE = ButtonOption("Enter Single Key")
    ENTER_SET = ButtonOption("Enter Key Set")
    FROM_MICROSD = ButtonOption("From MicroSD")
    FROM_SEEDKEEPER = ButtonOption("From Seedkeeper")
    GENERATE_SINGLE = ButtonOption("Generate Single Key")
    GENERATE_SET = ButtonOption("Generate Key Set")

    def _show_loaded(self, key_type: str):
        self.run_screen(
            LargeIconStatusScreen,
            title="Keys Loaded",
            status_headline=None,
            text=key_type,
            show_back_button=False,
        )

    def _prompt_key(self, title: str) -> str | None:
        ret_dict = ToolsTextQRTextEntryScreen(textToEncode="", title=title).display()
        if "is_back_button" in ret_dict:
            return None
        try:
            return _normalize_javacard_key(ret_dict["textToEncode"])
        except ValueError as exc:
            self.run_screen(
                WarningScreen,
                title="Invalid Key",
                status_headline=None,
                text=str(exc),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return None

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        import secrets

        if self.controller.javacard_keys:
            self.run_screen(
                WarningScreen,
                title="Keys Already Loaded",
                status_headline=None,
                text=(
                    "Loading a key will overwrite the currently loaded key. "
                    "Ensure it is backed up if you used it to lock cards."
                ),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )

        button_data = [
            self.FROM_MICROSD,
            self.FROM_SEEDKEEPER,
            self.GENERATE_SINGLE,
            self.GENERATE_SET,
            self.ENTER_SINGLE,
            self.ENTER_SET,
        ]
        selected = self.run_screen(
            ButtonListScreen,
            title="Load Keys",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        choice = button_data[selected]
        if choice == self.ENTER_SINGLE:
            key = self._prompt_key("Single Key")
            if key is None:
                return Destination(BackStackView)
            self.controller.javacard_keys = {"type": "single", "key": key}
            self._show_loaded("Single key loaded")
            return Destination(BackStackView)

        if choice == self.ENTER_SET:
            enc = self._prompt_key("ENC Key")
            if enc is None:
                return Destination(BackStackView)
            mac = self._prompt_key("MAC Key")
            if mac is None:
                return Destination(BackStackView)
            dek = self._prompt_key("DEK Key")
            if dek is None:
                return Destination(BackStackView)
            self.controller.javacard_keys = {"type": "set", "enc": enc, "mac": mac, "dek": dek}
            self._show_loaded("Key set loaded")
            return Destination(BackStackView)

        if choice == self.FROM_MICROSD:
            key_path = MicroSD.get_microsd_dir() / JAVACARD_KEYS_MICROSD_FILENAME
            if not key_path.exists():
                self.run_screen(
                    WarningScreen,
                    title="Missing File",
                    status_headline=None,
                    text=f"{JAVACARD_KEYS_MICROSD_FILENAME} not found on MicroSD",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            try:
                keys = _parse_javacard_keys(key_path.read_text())
            except Exception as exc:
                self.run_screen(
                    WarningScreen,
                    title="Invalid File",
                    status_headline=None,
                    text=str(exc),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            self.controller.javacard_keys = keys
            self._show_loaded("Keys loaded from MicroSD")
            return Destination(BackStackView)

        if choice == self.FROM_SEEDKEEPER:
            Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
            if not Satochip_Connector:
                return Destination(BackStackView)
            loading = LoadingScreenThread(text="Listing Secrets\n\n\n\n\n\n")
            loading.start()
            headers = Satochip_Connector.seedkeeper_list_secret_headers()
            loading.stop()

            entries = []
            buttons = []
            for header in headers:
                stype = SEEDKEEPER_DIC_TYPE.get(header["type"], hex(header["type"]))
                rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header["export_rights"], hex(header["export_rights"]))
                label = header["label"]
                if (
                    stype == "Data"
                    and rights == "Plaintext export allowed"
                    and label.startswith(JAVACARD_KEYS_SEEDKEEPER_PREFIX)
                ):
                    entries.append(header)
                    display_label = label[len(JAVACARD_KEYS_SEEDKEEPER_PREFIX):] or label
                    buttons.append(ButtonOption(display_label))

            if not entries:
                self.run_screen(
                    WarningScreen,
                    title="No Keys Found",
                    status_headline=None,
                    text="No javacard keys stored on Seedkeeper",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            selected = self.run_screen(
                ButtonListScreen,
                title="Select Keys",
                is_button_text_centered=False,
                button_data=buttons,
                show_back_button=True,
            )
            if selected == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            loading = LoadingScreenThread(text="Loading Keys\n\n\n\n\n\n")
            loading.start()
            secret_dict = Satochip_Connector.seedkeeper_export_secret(entries[selected]["id"], None)
            loading.stop()
            try:
                keys_text = _decode_seedkeeper_text(secret_dict)
                keys = _parse_javacard_keys(keys_text)
            except Exception as exc:
                self.run_screen(
                    WarningScreen,
                    title="Invalid Keys",
                    status_headline=None,
                    text=str(exc),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            self.controller.javacard_keys = keys
            self._show_loaded("Keys loaded from Seedkeeper")
            return Destination(BackStackView)

        if choice == self.GENERATE_SINGLE:
            key = secrets.token_bytes(16).hex().upper()
            self.controller.javacard_keys = {"type": "single", "key": key}
            self._show_loaded("Single key generated")
            return Destination(BackStackView)

        keys = {
            "type": "set",
            "enc": secrets.token_bytes(16).hex().upper(),
            "mac": secrets.token_bytes(16).hex().upper(),
            "dek": secrets.token_bytes(16).hex().upper(),
        }
        self.controller.javacard_keys = keys
        self._show_loaded("Key set generated")
        return Destination(BackStackView)


class ToolsJavacardSaveKeysView(View):
    TO_MICROSD = ButtonOption("To MicroSD")
    TO_SEEDKEEPER = ButtonOption("To Seedkeeper")

    def _require_keys(self):
        if not self.controller.javacard_keys:
            self.run_screen(
                WarningScreen,
                title="No Keys Loaded",
                status_headline=None,
                text="Load keys before saving.",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return False
        return True

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread

        if not self._require_keys():
            return Destination(BackStackView)

        button_data = [self.TO_MICROSD, self.TO_SEEDKEEPER]
        selected = self.run_screen(
            ButtonListScreen,
            title="Save Keys",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        keys_text = _format_javacard_keys(self.controller.javacard_keys)
        choice = button_data[selected]

        if choice == self.TO_MICROSD:
            key_path = MicroSD.get_microsd_dir() / JAVACARD_KEYS_MICROSD_FILENAME
            try:
                key_path.write_text(keys_text)
            except Exception as exc:
                self.run_screen(
                    WarningScreen,
                    title="Save Failed",
                    status_headline=None,
                    text=str(exc),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            self.run_screen(
                LargeIconStatusScreen,
                title="Saved",
                status_headline=None,
                text=f"Saved to {JAVACARD_KEYS_MICROSD_FILENAME}",
                show_back_button=False,
            )
            return Destination(BackStackView)

        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
        if not Satochip_Connector:
            return Destination(BackStackView)

        data_bytes = keys_text.encode("utf-8")
        status = Satochip_Connector.card_get_status()[3]
        if status["protocol_minor_version"] == 1:
            if len(data_bytes) > 255:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Key data too large for Seedkeeper v1",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            secret_list = [len(data_bytes)] + list(data_bytes)
        else:
            secret_list = list(len(data_bytes).to_bytes(2, "big")) + list(data_bytes)

        ret_dict = ToolsTextQRTextEntryScreen(textToEncode="", title="Secret Name").display()
        if "is_back_button" in ret_dict:
            return Destination(BackStackView)
        entered_name = ret_dict["textToEncode"].strip()
        if not entered_name:
            self.run_screen(
                WarningScreen,
                title="Invalid Name",
                status_headline=None,
                text="Secret name cannot be empty.",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        label = f"{JAVACARD_KEYS_SEEDKEEPER_PREFIX}{entered_name}"
        header = Satochip_Connector.make_header(
            "Data", "Plaintext export allowed", label
        )
        secret_dic = {"header": header, "secret_list": secret_list}

        try:
            fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
                Satochip_Connector, secret_dic
            )
        except Exception as exc:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(exc),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        if not fits:
            self.run_screen(
                WarningScreen,
                title="Not Enough Space",
                status_headline=None,
                text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        try:
            loading = LoadingScreenThread(text="Saving Keys\n\n\n\n\n\n")
            loading.start()
            Satochip_Connector.seedkeeper_import_secret(secret_dic)
            loading.stop()
            screen = LargeIconStatusScreen
            msg = "Keys saved to Seedkeeper"
        except UnexpectedSW12Error as exc:
            loading.stop()
            if exc.sw1 == 0x6A and exc.sw2 == 0x84:
                err_text = "Not enough space on Seedkeeper"
            else:
                err_text = format_sw_error(exc.sw1, exc.sw2)
            screen = WarningScreen
            msg = err_text
        except Exception:
            loading.stop()
            screen = WarningScreen
            msg = "Failed to save keys"

        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(BackStackView)


class ToolsJavacardUnlockCardView(View):
    def run(self):
        keys = self.controller.javacard_keys
        if not keys:
            self.run_screen(
                WarningScreen,
                title="No Keys Loaded",
                status_headline=None,
                text="Load keys before unlocking.",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        confirm = self.run_screen(
            WarningScreen,
            title="Unlock Card",
            status_headline=None,
            text="This will set the card back to the default dev key.",
            show_back_button=True,
            button_data=[ButtonOption("Continue")],
        )
        if confirm == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        command = f"{_format_gp_key_args(keys, '--key')} --unlock"
        seedkeeper_utils.run_globalplatform(
            self,
            command,
            "Unlocking Card",
            "Card Unlocked",
        )
        return Destination(BackStackView)


class ToolsJavacardLockCardView(View):
    def run(self):
        keys = self.controller.javacard_keys
        if not keys:
            self.run_screen(
                WarningScreen,
                title="No Keys Loaded",
                status_headline=None,
                text="Load keys before locking.",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        confirm = self.run_screen(
            WarningScreen,
            title="Lock Card",
            status_headline=None,
            text="Make sure you have saved these keys before locking.",
            show_back_button=True,
            button_data=[ButtonOption("Continue")],
        )
        if confirm == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        command = f"--key default {_format_gp_key_args(keys, '--lock')}"
        seedkeeper_utils.run_globalplatform(
            self,
            command,
            "Locking Card",
            "Card Locked",
        )
        return Destination(BackStackView)


class ToolsJavacardClearKeysView(View):
    def run(self):
        if not self.controller.javacard_keys:
            self.run_screen(
                WarningScreen,
                title="No Keys Loaded",
                status_headline=None,
                text="No keys are currently loaded.",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        confirm = self.run_screen(
            WarningScreen,
            title="Clear Loaded Keys",
            status_headline=None,
            text="Ensure any keys used to lock a card are saved before clearing.",
            show_back_button=True,
            button_data=[ButtonOption("Continue")],
        )
        if confirm == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        self.controller.javacard_keys = None
        self.run_screen(
            LargeIconStatusScreen,
            title="Cleared",
            status_headline=None,
            text="Loaded keys cleared.",
            show_back_button=False,
        )
        return Destination(BackStackView)


class ToolsDIYBuildAppletsView(View):
    def run(self):
        from subprocess import run
        import os
        import shutil
        from pathlib import Path
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.hardware.microsd import MicroSD
        from seedsigner.models.settings import Settings

        self.loading_screen = LoadingScreenThread(text="Building Applets\n\n\n\n\n\n(This takes a while)")
        self.loading_screen.start()

        microsd_dir = MicroSD.get_microsd_dir()
        repo_root = Path(__file__).resolve().parents[3]

        if Settings.HOSTNAME == Settings.SEEDSIGNER_OS:
            if not os.path.exists(microsd_dir / "javacard-build.xml"):
                os.system(f"cp /opt/tools/javacard-build.xml.seedsigneros {microsd_dir}/javacard-build.xml")

            if not os.path.exists(microsd_dir / "javacard-cap/"):
                os.makedirs(microsd_dir / "javacard-cap/", exist_ok=True)

            os.environ["JAVA_HOME"] = "/mnt/diy/jdk"
            commandString = ["/mnt/diy/ant/bin/ant", "-f", str(microsd_dir / "javacard-build.xml")]
        elif os.path.exists("/home/pi"):
            if not os.path.exists(microsd_dir / "javacard-build.xml"):
                run(["sudo", "cp", str(repo_root / "tools" / "javacard-build.xml.manual"), str(microsd_dir / "javacard-build.xml")], check=False)

            if not os.path.exists(microsd_dir / "javacard-cap/"):
                run(["sudo", "mkdir", "-p", str(microsd_dir / "javacard-cap/")], check=False)

            commandString = ["sudo", "ant", "-f", str(microsd_dir / "javacard-build.xml")]
        else:
            build_xml = microsd_dir / "javacard-build.xml"
            if not build_xml.exists():
                shutil.copy(repo_root / "tools" / "javacard-build.xml.manual", build_xml)

            cap_dir = microsd_dir / "javacard-cap"
            if not cap_dir.exists():
                os.makedirs(cap_dir)

            commandString = ["ant", "-f", str(build_xml)]

        data = run(commandString, capture_output=True, text=True)

        logger.info(data)

        self.loading_screen.stop()

        if "BUILD SUCCESSFUL" in data.stdout:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Applets Built",
                show_back_button=False,
            )
        else:
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=data.stderr.replace("\n", " "),
                show_back_button=False,
            )


        return Destination(MainMenuView)

class ToolsDIYInstallAppletView(View):
    def run(self):
        from subprocess import run
        import os
        import secrets
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.hardware.microsd import MicroSD

        cap_dir = MicroSD.get_microsd_dir() / "javacard-cap"
        cap_files = os.listdir(cap_dir)

        cap_file_buttons = []
        for file in cap_files:
            cap_file_buttons.append(ButtonOption(file))

        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select Applet",
            is_button_text_centered=False,
            button_data=cap_file_buttons
        )

        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        applet_file = cap_files[selected_file_num]
        logger.info("Selected:", applet_file)

        if "smartpgp" in applet_file.lower():
            serial_hex = secrets.token_bytes(4).hex().upper()
            aid = f"D276000124010304C0FE{serial_hex}0000"
            logger.info("SmartPGP AID: %s", aid)
            installed_applets = seedkeeper_utils.run_globalplatform(
                self,
                f"--install {cap_dir}/{applet_file} --create {aid}",
                "Installing Applet",
                f"Applet Installed\nSerial: {serial_hex}",
            )
        elif "seedkeeper" in applet_file.lower():
            storage_options = [
                ButtonOption("4 KB", return_data="0FFF"),
                ButtonOption("8 KB (default)", return_data="1FFF"),
                ButtonOption("16 KB", return_data="3FFF"),
                ButtonOption("32 KB", return_data="7FFF"),
                ButtonOption("64 KB", return_data="FFFF"),
            ]

            selected_storage_num = self.run_screen(
                ButtonListScreen,
                title="Select Storage",
                is_button_text_centered=False,
                button_data=storage_options,
                selected_button=1,
            )

            if selected_storage_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            selected_option = storage_options[selected_storage_num]
            storage_param = selected_option.return_data or "1FFF"

            installed_applets = seedkeeper_utils.run_globalplatform(
                self,
                f"--install {cap_dir}/{applet_file} --params {storage_param}",
                "Installing Applet",
                "Applet Installed",
            )
        else:
            installed_applets = seedkeeper_utils.run_globalplatform(
                self,
                f"--install {cap_dir}/{applet_file}",
                "Installing Applet",
                "Applet Installed",
            )

        # This process often kills IFD-NFC, so restart it if required
        scinterface = self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_INTERFACES)
        if "pn532" in scinterface:
            os.system("ifdnfc-activate no")
            time.sleep(1)
            os.system("ifdnfc-activate yes")

        return Destination(MainMenuView)

class ToolsDIYUninstallAppletView(View):
    def run(self):
        from subprocess import run
        import os
        from seedsigner.gui.screens.screen import LoadingScreenThread

        ret = self.run_screen(
            WarningScreen,
            title="Warning",
            status_headline=None,
            text="Uninstalling an applet will wipe ALL data associated with it. (This cannot be undone)",
            show_back_button=True,
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        installed_applets = seedkeeper_utils.run_globalplatform(self,"-l -v", "Checking Installed Applets", None)

        if installed_applets:
            installed_applets = installed_applets.split('\n')

            installed_applets_aids = []
            installed_applets_list = []

            for line in installed_applets:
                if "PKG: " in line:
                    package_info = line.split()
                    logger.info(package_info)
                    # Ignore system packages
                    if package_info[1] in ['A0000001515350', 'A00000016443446F634C697465', 'A0000000620204', 'A0000000620202','D00000000002','4B4D313031']:
                        continue
                    
                    # Give some known applets a more human readable package name
                    if package_info[1] == 'A00000052721010141504558': package_info[3]="(|Apex TOTP|)"
                    if package_info[1] == 'D27600012401': package_info[3]="(|SmartPGP|)"
                    if package_info[1] == 'B00B5111CB': package_info[3]="(|SpecterDIY|)"

                    installed_applets_list.append(ButtonOption(package_info[3][2:-2]))
                    installed_applets_aids.append(package_info[1])

            if len(installed_applets_list) > 0:
                selected_applet_num = self.run_screen(
                    ButtonListScreen,
                    title="Select Applet",
                    is_button_text_centered=False,
                    button_data=installed_applets_list
                )

                if selected_applet_num == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)

                applet_aid = installed_applets_aids[selected_applet_num]

                seedkeeper_utils.run_globalplatform(self,"--delete " + applet_aid + " -force", "Uninstalling Applet", "Applet Uninstalled")

            else:
                self.run_screen(
                    WarningScreen,
                    title="Notice",
                    status_headline=None,
                    text="No Applets to Uninstall",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")]
                )

                # This process often kills IFD-NFC, so restart it if required
        scinterface = self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_INTERFACES)
        if "pn532" in scinterface:
            os.system("ifdnfc-activate no")
            time.sleep(1)
            os.system("ifdnfc-activate yes")

        return Destination(MainMenuView)

"""****************************************************************************
    MicroSD Views
****************************************************************************"""
def find_sd_card_device():
    import re
    for device in os.listdir("/sys/block"):
        if device.startswith("mmcblk") and re.fullmatch(r'mmcblk\d+', device):
            partitions = os.listdir(f"/sys/block/{device}")
            # Only consider devices with partitions (e.g., mmcblk1p1)
            if any(p.startswith(device + "p") for p in partitions):
                return f"/dev/{device}"
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

        # All MicroSD operations require hardware access; block in desktop mode
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
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.hardware.microsd import MicroSD
        from seedsigner.hardware.microsd import MicroSD
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

            # Zero the MicroSD first (Makes sure that the verification step works correctly later)
            # Seedsigner images are currently 26MB or smaller
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
                    text=f"MicroSD Flashed",
                    show_back_button=False,
                    button_data=[ButtonOption("Verify"),ButtonOption("Skip Verification")]
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

# The process here only checks the first 26mb of the MicroSD card which is genreally fine, as the SeedSigner images
# at most 26MB (And for images below 26MB, the hash is the same as the release hashes as long as the sectors immediatly
# following the image have been zero'd first)
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
        import os
        from seedsigner.gui.screens.screen import LoadingScreenThread

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
            image_name = self.known_checksums[checksum]
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline="Matched Checksum",
                text=image_name[:20] + "\n" + image_name[20:40] + "\n" + image_name[40:60], #Split for images where the filename is too long to fit on the screen
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
        import hashlib, shutil
        from seedsigner.gui.screens.screen import LoadingScreenThread

        microsd_dev = find_sd_card_device()

        button_data=[self.WIPE_64MB, self.WIPE_256MB, self.WIPE_ALL]

        wipe_selection = self.run_screen(
                LargeIconStatusScreen,
                title="Wipe MicroSD",
                status_headline=None,
                text = "Select amount to wipe (Larger takes longer)",
                status_icon_size=0,
                show_back_button=True,
                button_data=button_data,
            )
        
        if wipe_selection == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        wipesize_cmd_string = "" # Default to wiping the whole card
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
                text=f"MicroSD Wiped",
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
        from seedsigner.gui.screens.screen import LoadingScreenThread

        microsd_dev = find_sd_card_device()

        button_data=[self.WIPE_64MB, self.WIPE_256MB, self.WIPE_ALL]

        wipe_selection = self.run_screen(
                LargeIconStatusScreen,
                title="Wipe MicroSD",
                status_headline=None,
                text = "Select amount to wipe (Larger takes longer)",
                status_icon_size=0,
                show_back_button=True,
                button_data=button_data,
            )
        
        if wipe_selection == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        wipesize_cmd_string = "" # Default to wiping the whole card
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
                text=f"MicroSD Wiped",
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )

        return Destination(MainMenuView)


"""****************************************************************************
    GPG Views
****************************************************************************"""


def parse_secret_key_list(colon_output: str):
    """Parse `gpg --list-secret-keys --with-colons` output."""
    keys = []
    cur = None
    for line in colon_output.splitlines():
        parts = line.split(":")
        if parts[0] == "sec":
            created = int(parts[5]) if len(parts) > 5 and parts[5] else None
            cur = {"fpr": None, "uid": None, "created": created}
            keys.append(cur)
        elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
            cur["fpr"] = parts[9]
        elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
            cur["uid"] = parts[9]
    return keys


def parse_subkey_list(colon_output: str):
    """Parse `gpg --list-secret-keys --with-colons` subkey data."""
    subkeys = []
    cur = None
    idx = 0
    for line in colon_output.splitlines():
        parts = line.split(":")
        if parts[0] == "ssb":
            idx += 1
            bits = parts[2]
            algo = parts[3] if len(parts) > 3 else ""
            curve = parts[16].lower() if len(parts) > 16 else ""
            created = int(parts[5]) if len(parts) > 5 and parts[5] else None
            cur = {
                "fpr": None,
                "caps": parts[11].lower(),
                "idx": idx,
                "algo": algo,
                "bits": bits,
                "curve": curve,
                "created": created,
            }
            subkeys.append(cur)
        elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
            cur["fpr"] = parts[9]
    return subkeys


# Bitcoin genesis block time: 2009-01-03 18:15:05 UTC.
# NOTE: As of 2025-09-15, BIP85 on GitHub lists this timestamp with a
# human-readable typo of "2009-01-03 18:05:05" UTC, which has propagated elsewhere.
BIP85_GPG_CREATED_TS = 1231006505

# BIP85 application numbers for supported GPG key types
BIP85_GPG_APP_RSA = 828365
BIP85_GPG_APP_CURVE25519 = 828366
BIP85_GPG_APP_SECP256K1 = 828367
BIP85_GPG_APP_NIST_P256 = 828368
BIP85_GPG_APP_BRAINPOOL_P256 = 828369

BIP85_GPG_ECC_KEY_BITS = 256

# In-memory registry of BIP85-derived keys
BIP85_DATA = {}


def bip85_export_json():
    import json

    return json.dumps(list(BIP85_DATA.values()), indent=2)


def bip85_import_json(data: str, *, clear: bool = True):
    import json

    entries = json.loads(data)
    if isinstance(entries, dict):
        entries = [entries]
    if clear:
        BIP85_DATA.clear()
    for entry in entries:
        if "primary_fpr" in entry:
            uids = entry.get("uids", [])
            primary = entry.get("primary_uid")
            if primary and primary in uids:
                uids = [primary] + [u for u in uids if u != primary]
                entry["uids"] = uids
            BIP85_DATA[entry["primary_fpr"]] = entry


def bip85_save_data(path):
    from pathlib import Path
    import json

    p = Path(path)
    if p.is_dir():
        for entry in BIP85_DATA.values():
            fname = p / f"BIP85_{entry['seed_fpr']}.json"
            with open(fname, "w", encoding="utf-8") as f:
                json.dump(entry, f, indent=2)
    else:
        with open(p, "w", encoding="utf-8") as f:
            f.write(bip85_export_json())


def bip85_load_data(path):
    from pathlib import Path
    import json

    p = Path(path)
    if p.is_dir():
        entries = []
        for file in p.glob("*.json"):
            try:
                with open(file, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    entries.extend(data)
                else:
                    entries.append(data)
            except Exception:
                continue
        bip85_import_json(json.dumps(entries))
    else:
        with open(p, encoding="utf-8") as f:
            bip85_import_json(f.read())


def parse_uid_list(colon_output: str):
    """Parse `gpg --list-secret-keys --with-colons` UID data."""
    uids = []
    idx = 0
    for line in colon_output.splitlines():
        parts = line.split(":")
        if parts[0] == "uid":
            idx += 1
            uids.append({"uid": parts[9], "idx": idx})
    return uids


def filter_deletable_subkeys(primary_fpr: str, subkeys):
    bip85 = primary_fpr in BIP85_DATA
    logger.info(
        "filter_deletable_subkeys: bip85=%s subkey_count=%s",
        bip85,
        len(subkeys),
    )
    if bip85 and subkeys:
        max_idx = max(sk["idx"] for sk in subkeys)
        logger.info("BIP85 key detected; allowing deletion of index %s only", max_idx)
        return [sk for sk in subkeys if sk["idx"] == max_idx]
    logger.info("Non-BIP85 key or no subkeys; returning all subkeys")
    return subkeys


def _select_import_algo(primary_algo: str, primary_curve: str, subkeys, selected_fprs):
    """Determine the algorithm/curve for card import based on selected subkeys."""
    if selected_fprs:
        fprs = selected_fprs.values() if isinstance(selected_fprs, dict) else selected_fprs
        selected = [sk for sk in subkeys if sk["fpr"] in fprs]
        if not selected:
            return primary_algo, primary_curve
        algos = {sk["algo"] for sk in selected}
        if len(algos) != 1:
            raise ValueError("Selected subkeys use different key types")
        algo = algos.pop()
        curve = ""
        if algo not in ("1", "2", "3"):
            curves = {sk["curve"] for sk in selected}
            if len(curves) != 1:
                raise ValueError("Selected subkeys use different key curves")
            curve = curves.pop()
        return algo, curve
    return primary_algo, primary_curve


class ToolsGPGMenuView(View):
    FILE_OPS = ButtonOption("File Operations")
    IMPORT = ButtonOption("Import Keys")
    EXPORT = ButtonOption("Export Keys")
    MESSAGE = ButtonOption("Secure Messaging")
    SMART_GPG = ButtonOption("SmartGPG")
    ADVANCED = ButtonOption("Advanced")

    def run(self):
        from seedsigner.controller import Controller

        if self.controller.resume_main_flow == Controller.FLOW__GPG_MESSAGE:
            self.controller.resume_main_flow = None
            return Destination(ToolsGPGDecryptMessageView, skip_current_view=True)

        button_data = [
            self.FILE_OPS,
            self.IMPORT,
            self.EXPORT,
            self.MESSAGE,
            self.SMART_GPG,
            self.ADVANCED,
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="GPG Tools",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.FILE_OPS:
            return Destination(ToolsGPGFileOpsMenuView)

        elif button_data[selected_menu_num] == self.IMPORT:
            return Destination(ToolsGPGImportMenuView)
        elif button_data[selected_menu_num] == self.EXPORT:
            return Destination(ToolsGPGExportMenuView)
        elif button_data[selected_menu_num] == self.MESSAGE:
            return Destination(ToolsGPGMessageMenuView)
        elif button_data[selected_menu_num] == self.SMART_GPG:
            return Destination(ToolsGPGSmartMenuView)
        elif button_data[selected_menu_num] == self.ADVANCED:
            return Destination(ToolsGPGAdvancedMenuView)


class ToolsGPGAdvancedMenuView(View):
    SUBKEY_OPS = ButtonOption("Subkey Operations")
    UID_OPS = ButtonOption("User ID Operations")
    CROSS_CERTIFY = ButtonOption("Cross Certify Keys")
    EXPORT_BUNDLE = ButtonOption("Export Public Key Bundle")
    BIP85_META = ButtonOption("BIP85 Metadata")

    def run(self):
        button_data = [
            self.SUBKEY_OPS,
            self.UID_OPS,
            self.CROSS_CERTIFY,
            self.EXPORT_BUNDLE,
            self.BIP85_META,
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Advanced",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        choice = button_data[selected_menu_num]
        if choice == self.SUBKEY_OPS:
            return Destination(ToolsGPGSubkeyMenuView)
        if choice == self.UID_OPS:
            return Destination(ToolsGPGUidMenuView)
        if choice == self.CROSS_CERTIFY:
            return Destination(ToolsGPGCrossCertifyView)
        if choice == self.EXPORT_BUNDLE:
            return Destination(ToolsGPGExportBundleView)
        if choice == self.BIP85_META:
            return Destination(ToolsGPGBip85MetadataMenuView)
        return Destination(ToolsGPGMenuView)


class ToolsGPGCrossCertifyView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
        )

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)

        if len(keys) < 2:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="At least two keys required",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        key_buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        signer_sel = self.run_screen(
            ButtonListScreen,
            title="Signing Key",
            is_button_text_centered=False,
            button_data=key_buttons,
        )
        if signer_sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        signer = keys[signer_sel]

        target_keys = [k for idx, k in enumerate(keys) if idx != signer_sel]
        target_buttons = [
            ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in target_keys
        ]
        target_sel = self.run_screen(
            ButtonListScreen,
            title="Target Key",
            is_button_text_centered=False,
            button_data=target_buttons,
        )
        if target_sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        target = target_keys[target_sel]

        cmd = [
            "gpg",
            "--batch",
            "--yes",
            "--default-key",
            signer["fpr"],
            "--quick-sign-key",
            target["fpr"],
        ]
        result = run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="Key cross certified",
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
            return Destination(ToolsGPGMenuView)

        logger.error("Cross certification failed: %s", result.stderr.strip())
        self.run_screen(
            WarningScreen,
            title="Error",
            status_headline=None,
            text="Failed to cross certify",
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )
        return Destination(BackStackView)


class ToolsGPGExportBundleView(View):
    def run(self):
        from subprocess import run
        import os
        import time
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            LoadingScreenThread,
            QRDisplayScreen,
        )
        from seedsigner.hardware.microsd import MicroSD
        from seedsigner.models.encode_qr import UrBytesQrEncoder

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        export_option = ButtonOption("Export Bundle")
        cancel_option = ButtonOption("Cancel")
        selected = set()

        while True:
            button_data = []
            for key in keys:
                label = key["uid"] if key["uid"] else key["fpr"][-8:]
                if key["fpr"] in selected:
                    label = "* " + label
                button_data.append(ButtonOption(label))
            button_data.extend([export_option, cancel_option])

            sel = self.run_screen(
                ButtonListScreen,
                title="Select Keys",
                is_button_text_centered=False,
                button_data=button_data,
            )

            if sel == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            if sel < len(keys):
                fpr = keys[sel]["fpr"]
                if fpr in selected:
                    selected.remove(fpr)
                else:
                    selected.add(fpr)
                continue

            choice = button_data[sel]
            if choice is cancel_option:
                return Destination(BackStackView)
            if choice is export_option:
                if len(selected) < 2:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Select at least two keys",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    continue
                break

        fingerprints = [k["fpr"] for k in keys if k["fpr"] in selected]

        exported = run(["gpg", "--armor", "--export", *fingerprints], capture_output=True, text=True)
        if exported.returncode != 0:
            logger.error("Bundle export failed: %s", exported.stderr.strip())
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to export keys",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        dest_buttons = [ButtonOption("microSD"), ButtonOption("Animated QR")]
        dest_sel = self.run_screen(
            ButtonListScreen,
            title="Export to",
            is_button_text_centered=False,
            button_data=dest_buttons,
        )
        if dest_sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if dest_sel == 0:
            if len(self.controller.storage.seeds) > 0:
                ret = self.run_screen(
                    WarningScreen,
                    title="WARNING",
                    status_headline=None,
                    text="These tools write data to the microSD card and may expose loaded secrets.",
                    show_back_button=True,
                    button_data=[ButtonOption("Continue")],
                )
                if ret == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)

            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            os.makedirs(file_list_path, exist_ok=True)

            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"gpg_bundle_{timestamp}.asc"
            filepath = os.path.join(file_list_path, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(exported.stdout)

            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Saved as {filename}",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(MainMenuView)

        loading = LoadingScreenThread(text="Encoding...")
        loading.start()
        try:
            qr_encoder = UrBytesQrEncoder(
                data=exported.stdout.encode("utf-8"),
                qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
            )
        finally:
            loading.stop()

        num_codes = qr_encoder.seq_len()
        ret = self.run_screen(
            WarningScreen,
            title="Animated QR",
            status_headline=None,
            text=f"This export requires {num_codes} QR code{'s' if num_codes > 1 else ''}.",
            show_back_button=True,
            button_data=[ButtonOption("Start")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)
        return Destination(MainMenuView)


class ToolsGPGBip85MetadataMenuView(View):
    SAVE = ButtonOption("Save BIP85 Data")
    LOAD = ButtonOption("Load BIP85 Data")
    REBUILD = ButtonOption("Rebuild BIP85 Key")

    def run(self):
        button_data = [self.SAVE, self.LOAD, self.REBUILD]
        selected = self.run_screen(
            ButtonListScreen,
            title="BIP85 Metadata",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        choice = button_data[selected]
        if choice == self.SAVE:
            return Destination(ToolsGPGSaveBip85DataView)
        if choice == self.LOAD:
            return Destination(ToolsGPGLoadBip85DataView)
        return Destination(ToolsGPGRebuildBip85KeyView)


class ToolsGPGSaveBip85DataView(View):
    TO_MICROSD = ButtonOption("To MicroSD")
    TO_QR = ButtonOption("To QR")
    TO_SEEDKEEPER = ButtonOption("To Seedkeeper")

    def run(self):
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            QRDisplayScreen,
            LargeIconStatusScreen,
            WarningScreen,
            LoadingScreenThread,
        )
        from seedsigner.models.encode_qr import UrBytesQrEncoder
        from seedsigner.helpers import seedkeeper_utils
        from pysatochip.CardConnector import UnexpectedSW12Error
        from seedsigner.helpers.iso7816 import format_sw_error
        import time

        button_data = [self.TO_MICROSD, self.TO_QR, self.TO_SEEDKEEPER]
        selected = self.run_screen(
            ButtonListScreen,
            title="Save BIP85 Data",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        choice = button_data[selected]
        if choice == self.TO_MICROSD:
            from seedsigner.gui.screens import LargeIconStatusScreen, WarningScreen
            from seedsigner.hardware.microsd import MicroSD
            import os

            if len(self.controller.storage.seeds) > 0:
                ret = self.run_screen(
                    WarningScreen,
                    title="WARNING",
                    status_headline=None,
                    text="These tools write data to the microSD card and may expose loaded secrets.",
                    show_back_button=True,
                    button_data=[ButtonOption("Continue")],
                )
                if ret == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)

            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            os.makedirs(file_list_path, exist_ok=True)
            try:
                bip85_save_data(file_list_path)
                logger.info("BIP85 data saved to %s", os.path.abspath(file_list_path))
                screen = LargeIconStatusScreen
                msg = "BIP85 data saved"
            except Exception:
                screen = WarningScreen
                msg = "Failed to save BIP85 data"
            self.run_screen(
                screen,
                title="Result",
                status_headline=None,
                text=msg,
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
            return Destination(ToolsGPGMenuView)

        if choice == self.TO_QR:
            data = bip85_export_json().encode("utf-8")
            loading = LoadingScreenThread(text="Encoding...")
            loading.start()
            try:
                qr_encoder = UrBytesQrEncoder(
                    data=data,
                    qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
                )
            finally:
                loading.stop()

            num_codes = qr_encoder.seq_len()
            ret = self.run_screen(
                WarningScreen,
                title="Animated QR",
                status_headline=None,
                text=f"This export requires {num_codes} QR code{'s' if num_codes > 1 else ''}.",
                show_back_button=True,
                button_data=[ButtonOption("Start")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)
            return Destination(ToolsGPGMenuView)

        # Seedkeeper export
        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
        if not Satochip_Connector:
            return Destination(BackStackView)

        data_bytes = bip85_export_json().encode("utf-8")
        status = Satochip_Connector.card_get_status()[3]
        if status["protocol_minor_version"] == 1:
            if len(data_bytes) > 255:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="BIP85 data too large for Seedkeeper v1",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            secret_list = [len(data_bytes)] + list(data_bytes)
        else:
            secret_list = list(len(data_bytes).to_bytes(2, "big")) + list(data_bytes)

        label = f"BIP85-GPG-{int(time.time())}"
        header = Satochip_Connector.make_header(
            "Data", "Plaintext export allowed", label
        )
        secret_dic = {"header": header, "secret_list": secret_list}

        try:
            fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
                Satochip_Connector, secret_dic
            )
        except Exception as e:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        if not fits:
            self.run_screen(
                WarningScreen,
                title="Not Enough Space",
                status_headline=None,
                text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        try:
            loading = LoadingScreenThread(text="Saving Secret\n\n\n\n\n\n")
            loading.start()
            Satochip_Connector.seedkeeper_import_secret(secret_dic)
            loading.stop()
            screen = LargeIconStatusScreen
            msg = "BIP85 data saved"
        except UnexpectedSW12Error as e:
            loading.stop()
            if e.sw1 == 0x6A and e.sw2 == 0x84:
                err_text = "Not enough space on Seedkeeper"
            else:
                err_text = format_sw_error(e.sw1, e.sw2)
            screen = WarningScreen
            msg = err_text
        except Exception:
            loading.stop()
            screen = WarningScreen
            msg = "Failed to save BIP85 data"

        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGLoadBip85DataView(View):
    FROM_MICROSD = ButtonOption("From MicroSD")
    FROM_QR = ButtonOption("From QR")
    FROM_SEEDKEEPER = ButtonOption("From Seedkeeper")

    def run(self):
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            QRDisplayScreen,
            WarningScreen,
            LargeIconStatusScreen,
            LoadingScreenThread,
        )
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.models.decode_qr import DecodeQR, QRType
        from seedsigner.helpers import seedkeeper_utils
        from urtypes.bytes import Bytes
        import time, binascii

        button_data = [self.FROM_MICROSD, self.FROM_QR, self.FROM_SEEDKEEPER]
        selected = self.run_screen(
            ButtonListScreen,
            title="Load BIP85 Data",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        choice = button_data[selected]
        if choice == self.FROM_MICROSD:
            from seedsigner.gui.screens import LargeIconStatusScreen, WarningScreen
            from seedsigner.hardware.microsd import MicroSD
            import os

            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            try:
                bip85_load_data(file_list_path)
                logger.info("BIP85 data loaded from %s", os.path.abspath(file_list_path))
                screen = LargeIconStatusScreen
                msg = "BIP85 data loaded"
            except Exception:
                screen = WarningScreen
                msg = "Failed to load BIP85 data"
            self.run_screen(
                screen,
                title="Result",
                status_headline=None,
                text=msg,
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
            return Destination(ToolsGPGMenuView)

        if choice == self.FROM_QR:
            decoder = DecodeQR()
            ScanScreen(decoder=decoder, instructions_text="Scan BIP85 data").display()
            self.controller.reset_screensaver_timeout()
            time.sleep(0.1)
            if not decoder.is_complete:
                return Destination(BackStackView)
            if decoder.qr_type == QRType.BYTES__UR:
                raw = Bytes.from_cbor(decoder.decoder.result_message().cbor).data
                if isinstance(raw, memoryview):
                    raw = raw.tobytes()
                data_str = raw.decode("utf-8")
            elif decoder.qr_type == QRType.TEXT:
                data_str = decoder.get_text()
            else:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Unsupported QR format",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            bip85_import_json(data_str)
            self.run_screen(
                LargeIconStatusScreen,
                title="Result",
                status_headline=None,
                text="BIP85 data loaded",
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
            return Destination(ToolsGPGMenuView)

        # Seedkeeper import
        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
        if not Satochip_Connector:
            return Destination(BackStackView)

        loading = LoadingScreenThread(text="Listing Secrets\n\n\n\n\n\n")
        loading.start()
        headers = Satochip_Connector.seedkeeper_list_secret_headers()
        loading.stop()

        entries = []
        buttons = []
        for header in headers:
            stype = SEEDKEEPER_DIC_TYPE.get(header["type"], hex(header["type"]))
            rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header["export_rights"], hex(header["export_rights"]))
            label = header["label"]
            if (
                stype == "Data"
                and rights == "Plaintext export allowed"
                and label.startswith("BIP85-GPG-")
            ):
                entries.append(header)
                buttons.append(ButtonOption(label))

        if not entries:
            self.run_screen(
                WarningScreen,
                title="No BIP85 Data",
                status_headline=None,
                text="No BIP85 data on Seedkeeper",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        selected = self.run_screen(
            ButtonListScreen,
            title="Select BIP85 Data",
            is_button_text_centered=False,
            button_data=buttons,
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        loading = LoadingScreenThread(text="Loading BIP85 Data\n\n\n\n\n\n")
        loading.start()
        secret_dict = Satochip_Connector.seedkeeper_export_secret(entries[selected]["id"], None)
        loading.stop()

        data_bytes = binascii.unhexlify(secret_dict["secret"])[2:]
        bip85_import_json(data_bytes.decode())
        self.run_screen(
            LargeIconStatusScreen,
            title="Result",
            status_headline=None,
            text="BIP85 data loaded",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGRebuildBip85KeyView(View):
    def run(self):
        from embit import bip32
        from pgpy import PGPKey, PGPUID
        from pgpy.constants import (
            PubKeyAlgorithm,
            KeyFlags,
            HashAlgorithm,
            SymmetricKeyAlgorithm,
            CompressionAlgorithm,
        )
        from pgpy.pgp import PrivKeyV4, PrivSubKeyV4
        from pgpy.packet import fields
        from pgpy.packet.types import MPI
        from datetime import datetime, timezone, date
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.gui.screens import LargeIconStatusScreen, WarningScreen
        import re

        if not BIP85_DATA:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No BIP85 data loaded",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        entries = []
        buttons = []
        for entry in BIP85_DATA.values():
            for seed in self.controller.storage.seeds:
                fpr = seed.get_fingerprint(
                    self.settings.get_value(SettingsConstants.SETTING__NETWORK)
                )
                if fpr == entry["seed_fpr"]:
                    entries.append((entry, seed))
                    label = entry["uids"][0] if entry.get("uids") else entry["primary_fpr"]
                    buttons.append(ButtonOption(label))
                    break

        if not entries:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No matching seeds",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        selected = self.run_screen(
            ButtonListScreen,
            title="Rebuild BIP85 Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        entry, seed = entries[selected]

        key_index = entry["index"]
        key_type_label = entry["key_type"]
        key_type_lookup = dict(_bip85_key_type_choices(True))
        key_type = key_type_lookup[key_type_label]

        uid_list = entry.get("uids", [])
        if not uid_list:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="BIP85 data missing UIDs",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        primary_uid = entry.get("primary_uid", uid_list[0])

        def parse_uid(uid_str):
            m = re.match(r"^(.*?)(?:\s*<([^>]+)>)?$", uid_str)
            name = m.group(1).strip()
            email = m.group(2)
            return name, email

        created = datetime.fromtimestamp(BIP85_GPG_CREATED_TS, tz=timezone.utc)
        if key_type == "rsa2048":
            expiration_dt = datetime(2029, 12, 31, tzinfo=timezone.utc)
        else:
            expiration_dt = datetime(2035, 12, 31, tzinfo=timezone.utc)
        expires = expiration_dt - created

        # Map primary key type to algorithm details for verification
        algo_map = {
            "ed25519": ("22", "", "ed25519"),
            "secp256k1": ("19", "", "secp256k1"),
            "p256": ("19", "", "nistp256"),
            "brainpoolp256r1": ("19", "", "brainpoolp256r1"),
            "rsa2048": ("1", "2048", ""),
            "rsa3072": ("1", "3072", ""),
            "rsa4096": ("1", "4096", ""),
        }
        primary_algo, primary_bits, primary_curve = algo_map[key_type]

        # Build subkey info for verification
        verify_subkeys = []
        curve_map = {
            "nist p-256": "nistp256",
            "brainpool p-256": "brainpoolp256r1",
            "secp256k1": "secp256k1",
            "ed25519": "ed25519",
        }
        for sk in entry.get("subkeys", []):
            g_idx = sk["index"]
            parts = sk["type"].split()
            if parts[0] == "RSA":
                algo = "1"
                bits = parts[1]
                curve = ""
            else:
                algo = {"ECDH": "18", "ECDSA": "19", "EdDSA": "22"}[parts[0]]
                curve_label = " ".join(parts[1:])
                if curve_label.startswith("ECC "):
                    curve_label = curve_label[4:]
                curve_label_lc = curve_label.lower()
                curve = curve_map.get(curve_label_lc, curve_label_lc)
                if parts[0] == "ECDH" and curve_label_lc == "ed25519":
                    curve = "cv25519"
                bits = ""
            verify_subkeys.append(
                {
                    "idx": g_idx + 1,
                    "algo": algo,
                    "bits": bits,
                    "curve": curve,
                    "fpr": sk.get("fingerprint", ""),
                }
            )

        logger.info(
            "Verifying BIP85 data for %s idx=%s", entry["primary_fpr"], key_index
        )
        if not bip85_verify_existing(
            seed,
            entry["primary_fpr"],
            key_index,
            BIP85_GPG_CREATED_TS,
            primary_algo,
            primary_bits,
            primary_curve,
            verify_subkeys,
        ):
            logger.warning(
                "BIP85 verification failed for %s", entry["primary_fpr"]
            )
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Selected seed/index failed validation",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        root = seed.get_root(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
        KEY_BITS = (
            2048
            if key_type == "rsa2048"
            else 3072
            if key_type == "rsa3072"
            else 4096
            if key_type == "rsa4096"
            else None
        )

        def rsa_to_privpacket(rsa_key):
            priv = fields.RSAPriv()
            priv.n = MPI(rsa_key.n)
            priv.e = MPI(rsa_key.e)
            priv.d = MPI(rsa_key.d)
            priv.p = MPI(rsa_key.p)
            priv.q = MPI(rsa_key.q)
            priv.u = MPI(pow(rsa_key.p, -1, rsa_key.q))
            priv._compute_chksum()
            return priv

        loading = LoadingScreenThread(text="Rebuilding BIP85 GPG key\n\n\n\n\n\n")
        loading.start()
        try:
            pk = PrivKeyV4()
            if key_type == "secp256k1":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_secp256k1_from_root(root, key_index)
            elif key_type == "p256":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_p256_from_root(root, key_index)
            elif key_type == "brainpoolp256r1":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_brainpoolp256r1_from_root(root, key_index)
            elif key_type == "ed25519":
                pk.pkalg = PubKeyAlgorithm.EdDSA
                pk.keymaterial = bip85_ed25519_from_root(root, key_index)
            else:
                rsa_main = bip85_rsa_from_root(root, KEY_BITS, key_index)
                pk.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
                pk.keymaterial = rsa_to_privpacket(rsa_main)
            pk.created = created
            pk.update_hlen()

            pgp_key = PGPKey()
            pgp_key._key = pk

            for uid_str in uid_list:
                name, email = parse_uid(uid_str)
                uid = PGPUID.new(name, email=email)
                pgp_key.add_uid(
                    uid,
                    usage={KeyFlags.Certify, KeyFlags.Sign},
                    hashes=[HashAlgorithm.SHA256],
                    ciphers=[SymmetricKeyAlgorithm.AES256],
                    compression=[CompressionAlgorithm.ZLIB],
                    expires=expires,
                    created=created,
                    primary=(uid_str == primary_uid),
                )

            for sub in entry.get("subkeys", _bip85_subkey_specs("rsa")):
                if isinstance(sub, int):
                    g_idx = sub
                    group_idx = g_idx // 3
                    idx = g_idx % 3
                    specs = _bip85_subkey_specs(
                        {
                            "p256": "nistp256",
                            "brainpoolp256r1": "brainpoolP256r1",
                            "secp256k1": "secp256k1",
                            "ed25519": "ed25519",
                        }.get(key_type, "rsa")
                    )
                    _, pkalg, usage, *alg = specs[idx]
                    func_map = {
                        "secp256k1": bip85_secp256k1_from_root,
                        "p256": bip85_p256_from_root,
                        "brainpoolp256r1": bip85_brainpoolp256r1_from_root,
                        "ed25519": bip85_ed25519_from_root,
                    }
                    subpkt = PrivSubKeyV4()
                    subpkt.pkalg = pkalg
                    if key_type in func_map:
                        subpkt.keymaterial = func_map[key_type](
                            root, group_idx, idx, alg[0]
                        )
                    else:
                        rsa_sub = bip85_rsa_from_root(root, KEY_BITS, group_idx, idx)
                        subpkt.keymaterial = rsa_to_privpacket(rsa_sub)
                else:
                    g_idx = sub.get("index", 0)
                    group_idx = g_idx // 3
                    idx = g_idx % 3
                    usage = (
                        {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}
                        if idx == 0
                        else {KeyFlags.Authentication}
                        if idx == 1
                        else {KeyFlags.Sign}
                    )
                    parts = sub.get("type", key_type_label).split()
                    subpkt = PrivSubKeyV4()
                    if parts[0] == "RSA":
                        bits = int(parts[1])
                        subpkt.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
                        rsa_sub = bip85_rsa_from_root(root, bits, group_idx, idx)
                        subpkt.keymaterial = rsa_to_privpacket(rsa_sub)
                    else:
                        alg_name = parts[0]
                        curve_label = " ".join(parts[1:])
                        if curve_label.startswith("ECC "):
                            curve_label = curve_label[4:]
                        curve_label_lc = curve_label.lower()
                        func_map = {
                            "secp256k1": bip85_secp256k1_from_root,
                            "nist p-256": bip85_p256_from_root,
                            "brainpool p-256": bip85_brainpoolp256r1_from_root,
                            "ed25519": bip85_ed25519_from_root,
                        }
                        pkalg_map = {
                            "ECDH": PubKeyAlgorithm.ECDH,
                            "ECDSA": PubKeyAlgorithm.ECDSA,
                            "EdDSA": PubKeyAlgorithm.EdDSA,
                        }
                        subpkt.pkalg = pkalg_map[parts[0]]
                        func = func_map[curve_label_lc]
                        subpkt.keymaterial = func(root, group_idx, idx, alg_name)
                    subpkt.created = created
                    subpkt.update_hlen()
                    subkey = PGPKey()
                    subkey._key = subpkt
                    exp_fpr = sub.get("fingerprint")
                    logger.info(
                        "Derived subkey idx=%s fpr=%s expected=%s",
                        g_idx,
                        subkey.fingerprint,
                        exp_fpr,
                    )
                    if exp_fpr and subkey.fingerprint != exp_fpr:
                        logger.warning(
                            "Subkey fingerprint mismatch at idx=%s: expected %s got %s",
                            g_idx,
                            exp_fpr,
                            subkey.fingerprint,
                        )
                    pgp_key.add_subkey(
                        subkey,
                        usage=usage,
                        hashes=[HashAlgorithm.SHA256],
                        ciphers=[SymmetricKeyAlgorithm.AES256],
                        compression=[CompressionAlgorithm.ZLIB],
                        expires=expires,
                        created=created,
                    )
                    continue

                subpkt.created = created
                subpkt.update_hlen()
                subkey = PGPKey()
                subkey._key = subpkt
                exp_fpr = sub.get("fingerprint") if isinstance(sub, dict) else None
                logger.info(
                    "Derived subkey idx=%s fpr=%s expected=%s",
                    g_idx,
                    subkey.fingerprint,
                    exp_fpr,
                )
                if exp_fpr and subkey.fingerprint != exp_fpr:
                    logger.warning(
                        "Subkey fingerprint mismatch at idx=%s: expected %s got %s",
                        g_idx,
                        exp_fpr,
                        subkey.fingerprint,
                    )
                pgp_key.add_subkey(
                    subkey,
                    usage=usage,
                    hashes=[HashAlgorithm.SHA256],
                    ciphers=[SymmetricKeyAlgorithm.AES256],
                    compression=[CompressionAlgorithm.ZLIB],
                    expires=expires,
                    created=created,
                )

            armored = str(pgp_key)
            result = run(["gpg", "--batch", "--import"], input=armored.encode(), capture_output=True)
        finally:
            loading.stop()

        if result.returncode == 0:
            self.run_screen(
                LargeIconStatusScreen,
                title="Result",
                status_headline=None,
                text="BIP85 key rebuilt",
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
        else:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
        return Destination(ToolsGPGMenuView)


class ToolsGPGSubkeyMenuView(View):
    ADD_SUBKEYS = ButtonOption("Add Subkeys")
    REVOKE_SUBKEYS = ButtonOption("Revoke Subkeys")
    DELETE_SUBKEYS = ButtonOption("Delete Subkeys")
    CHANGE_EXPIRY = ButtonOption("Change Expiry")
    EXPORT_SUBKEY_SECRETS = ButtonOption("Export Subkey Secrets")

    def run(self):
        button_data = [
            self.ADD_SUBKEYS,
            self.REVOKE_SUBKEYS,
            self.DELETE_SUBKEYS,
            self.CHANGE_EXPIRY,
            self.EXPORT_SUBKEY_SECRETS,
        ]

        selected = self.run_screen(
            ButtonListScreen,
            title="Subkey Operations",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        choice = button_data[selected]
        if choice == self.ADD_SUBKEYS:
            return Destination(ToolsGPGAddSubkeysView)
        if choice == self.REVOKE_SUBKEYS:
            return Destination(ToolsGPGRevokeSubkeysView)
        if choice == self.DELETE_SUBKEYS:
            return Destination(ToolsGPGDeleteSubkeysView)
        if choice == self.CHANGE_EXPIRY:
            return Destination(ToolsGPGChangeExpiryView)
        return Destination(ToolsGPGExportSubkeySecretsView)


class ToolsGPGRevokeSubkeysView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import ButtonListScreen, LargeIconStatusScreen, WarningScreen

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
            fingerprint,
        ], capture_output=True, text=True)
        subkeys = parse_subkey_list(result.stdout)
        if not subkeys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No subkeys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        while subkeys:
            sk_buttons = [ButtonOption(f"{sk['fpr'][-8:]} [{sk['caps']}]") for sk in subkeys]
            sk_buttons.append(ButtonOption("Done"))
            sel = self.run_screen(
                ButtonListScreen,
                title="Revoke Subkeys",
                is_button_text_centered=False,
                button_data=sk_buttons,
            )
            if sel == RET_CODE__BACK_BUTTON or sk_buttons[sel] == sk_buttons[-1]:
                break
            sub = subkeys[sel]
            r = gpg_edit_subkey(fingerprint, sub["idx"], "revkey")
            if r.returncode == 0 and fingerprint in BIP85_DATA:
                BIP85_DATA[fingerprint]["revocations"].append(sub["fpr"])
            screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
            msg = "Subkey revoked" if r.returncode == 0 else "Failed to revoke"
            self.run_screen(
                screen,
                title="Result",
                status_headline=None,
                text=msg,
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            result = run([
                "gpg",
                "--list-secret-keys",
                "--with-colons",
                fingerprint,
            ], capture_output=True, text=True)
            subkeys = parse_subkey_list(result.stdout)
        return Destination(ToolsGPGMenuView)


class ToolsGPGDeleteSubkeysView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import ButtonListScreen, LargeIconStatusScreen, WarningScreen

        ret = self.run_screen(
            WarningScreen,
            title="WARNING",
            status_headline=None,
            text="Revoking subkeys is usually preferred\nover deleting them.",
            show_back_button=True,
            button_data=[ButtonOption("I Understand")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
            fingerprint,
        ], capture_output=True, text=True)
        subkeys = parse_subkey_list(result.stdout)
        subkeys = filter_deletable_subkeys(fingerprint, subkeys)
        if not subkeys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No subkeys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        while subkeys:
            sk_buttons = [ButtonOption(f"{sk['fpr'][-8:]} [{sk['caps']}]") for sk in subkeys]
            sk_buttons.append(ButtonOption("Done"))
            sel = self.run_screen(
                ButtonListScreen,
                title="Delete Subkeys",
                is_button_text_centered=False,
                button_data=sk_buttons,
            )
            if sel == RET_CODE__BACK_BUTTON or sk_buttons[sel] == sk_buttons[-1]:
                break
            sub = subkeys[sel]
            r = gpg_edit_subkey(fingerprint, sub["idx"], "delkey")
            screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
            msg = "Subkey deleted" if r.returncode == 0 else "Failed to delete"
            self.run_screen(
                screen,
                title="Result",
                status_headline=None,
                text=msg,
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            result = run([
                "gpg",
                "--list-secret-keys",
                "--with-colons",
                fingerprint,
            ], capture_output=True, text=True)
            if r.returncode == 0 and fingerprint in BIP85_DATA:
                entry = BIP85_DATA[fingerprint]
                entry["subkeys"] = [
                    sk for sk in entry["subkeys"] if sk["fingerprint"] != sub["fpr"]
                ]
            subkeys = parse_subkey_list(result.stdout)
            subkeys = filter_deletable_subkeys(fingerprint, subkeys)
        return Destination(ToolsGPGMenuView)


class ToolsGPGChangeExpiryView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import ButtonListScreen, LargeIconStatusScreen, WarningScreen

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
            fingerprint,
        ], capture_output=True, text=True)
        subkeys = parse_subkey_list(result.stdout)
        if not subkeys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No subkeys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        sk_buttons = [ButtonOption(f"{sk['fpr'][-8:]} [{sk['caps']}]") for sk in subkeys]
        sel = self.run_screen(
            ButtonListScreen,
            title="Select Subkey",
            is_button_text_centered=False,
            button_data=sk_buttons,
        )
        if sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        sub_fpr = subkeys[sel]["fpr"]

        exp_buttons = [
            ButtonOption("1 year"),
            ButtonOption("2 years"),
            ButtonOption("5 years"),
            ButtonOption("Never"),
        ]
        exp_vals = ["1y", "2y", "5y", "0"]
        exp_sel = self.run_screen(
            ButtonListScreen,
            title="Set Expiry",
            is_button_text_centered=False,
            button_data=exp_buttons,
        )
        if exp_sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        expire = exp_vals[exp_sel]
        r = run([
            "gpg",
            "--batch",
            "--yes",
            "--quick-set-expire",
            fingerprint,
            expire,
            sub_fpr,
        ])
        screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
        msg = "Expiry changed" if r.returncode == 0 else "Failed to change expiry"
        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGExportSubkeySecretsView(View):
    def run(self):
        from subprocess import run
        import os
        import logging
        from seedsigner.hardware.microsd import MicroSD
        from seedsigner.models.encode_qr import UrBytesQrEncoder
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            LoadingScreenThread,
            QRDisplayScreen,
        )

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
            fingerprint,
        ], capture_output=True, text=True)
        subkeys = parse_subkey_list(result.stdout)
        if not subkeys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No subkeys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        selected_fprs: dict[str, str] = {}
        for label, flag in [("Signing", "s"), ("Encryption", "e"), ("Auth", "a")]:
            candidates = [
                sk for sk in subkeys if flag in sk["caps"] and sk["fpr"] not in selected_fprs.values()
            ]
            if not candidates:
                continue
            sk_buttons = [ButtonOption(sk["fpr"][-8:]) for sk in candidates]
            sk_buttons.append(ButtonOption("Skip"))
            sel = self.run_screen(
                ButtonListScreen,
                title=f"{label} Subkey",
                is_button_text_centered=False,
                button_data=sk_buttons,
            )
            if sel == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            if sk_buttons[sel].button_label != "Skip":
                selected_fprs[flag] = candidates[sel]["fpr"]

        if not selected_fprs:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No subkeys selected",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        dest_buttons = [
            ButtonOption("File"),
            ButtonOption("QR"),
            ButtonOption("Smartcard"),
        ]
        dest_sel = self.run_screen(
            ButtonListScreen,
            title="Export As",
            is_button_text_centered=False,
            button_data=dest_buttons,
        )
        if dest_sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        if dest_buttons[dest_sel].button_label == "Smartcard":
            return Destination(
                ToolsGPGImportKeyToCardView,
                view_args={"fingerprint": fingerprint, "selected_subkeys": selected_fprs},
            )

        exported = gpg_export_selected_subkeys(fingerprint, list(selected_fprs.values()))
        if exported.returncode != 0:
            logging.getLogger(__name__).error(
                "gpg export failed: %s", exported.stderr.strip()
            )
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to export",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        from seedsigner.gui.screens import tools_screens

        ret_dict = tools_screens.ToolsTextQRTextEntryScreen(
            textToEncode="", title="Passphrase"
        ).display()
        if "is_back_button" in ret_dict:
            return Destination(BackStackView)
        try:
            import re

            passphrase = bytes(
                re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                encoding="raw_unicode_escape",
            ).decode("unicode_escape")
        except UnicodeDecodeError:
            passphrase = ret_dict["textToEncode"]

        protected = run(
            [
                "gpg",
                "--armor",
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                passphrase,
                "--symmetric",
                "--cipher-algo",
                "AES256",
            ],
            input=exported.stdout,
            capture_output=True,
            text=True,
        )
        if protected.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to protect export",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        armored = protected.stdout

        if dest_buttons[dest_sel].button_label == "File":
            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            os.makedirs(file_list_path, exist_ok=True)
            filename = fingerprint + "_subkey_secrets.asc"
            filepath = os.path.join(file_list_path, filename)
            with open(filepath, "w") as f:
                f.write(armored)
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Saved as {filename}",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(ToolsGPGMenuView)
        if dest_buttons[dest_sel].button_label == "QR":
            loading = LoadingScreenThread(text="Encoding...")
            loading.start()
            try:
                qr_encoder = UrBytesQrEncoder(
                    data=armored,
                    qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
                )
            finally:
                loading.stop()
            num_codes = qr_encoder.seq_len()
            ret = self.run_screen(
                WarningScreen,
                title="Animated QR",
                status_headline=None,
                text=f"This export requires {num_codes} QR code{'s' if num_codes > 1 else ''}.",
                show_back_button=True,
                button_data=[ButtonOption("Start")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)
            return Destination(ToolsGPGMenuView)
        return Destination(BackStackView)


class ToolsGPGUidMenuView(View):
    ADD_UID = ButtonOption("Add User ID")
    EDIT_UID = ButtonOption("Edit User IDs")
    SET_PRIMARY_UID = ButtonOption("Set Primary User ID")
    REVOKE_UID = ButtonOption("Revoke User ID")
    DELETE_UID = ButtonOption("Delete User ID")

    def run(self):
        button_data = [
            self.ADD_UID,
            self.EDIT_UID,
            self.SET_PRIMARY_UID,
            self.REVOKE_UID,
            self.DELETE_UID,
        ]
        selected = self.run_screen(
            ButtonListScreen,
            title="User ID Operations",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        choice = button_data[selected]
        if choice == self.ADD_UID:
            return Destination(ToolsGPGAddUidView)
        if choice == self.EDIT_UID:
            return Destination(ToolsGPGEditUidView)
        if choice == self.SET_PRIMARY_UID:
            return Destination(ToolsGPGSetPrimaryUidView)
        if choice == self.REVOKE_UID:
            return Destination(ToolsGPGRevokeUidView)
        return Destination(ToolsGPGDeleteUidView)


class ToolsGPGAddUidView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            tools_screens,
        )

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]

        # Preserve the key's original primary UID so that adding an
        # additional UID does not change which one is displayed as primary.
        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
            fingerprint,
        ], capture_output=True, text=True)
        uids = parse_uid_list(result.stdout)
        primary_uid = uids[0]["uid"] if uids else None

        def prompt_text(title: str):
            ret_dict = tools_screens.ToolsTextQRTextEntryScreen(textToEncode="", title=title).display()
            if "is_back_button" in ret_dict:
                return None
            try:
                import re

                return bytes(
                    re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                    encoding="raw_unicode_escape",
                ).decode("unicode_escape")
            except UnicodeDecodeError:
                return ret_dict["textToEncode"]

        name = prompt_text("Name")
        if name is None:
            return Destination(BackStackView)
        email = prompt_text("Email")
        if email is None:
            return Destination(BackStackView)
        uid_str = f"{name} <{email}>" if email else name

        r = run(["gpg", "--batch", "--quick-add-uid", fingerprint, uid_str])
        if r.returncode == 0 and primary_uid:
            run([
                "gpg",
                "--batch",
                "--quick-set-primary-uid",
                fingerprint,
                primary_uid,
            ])
        if r.returncode == 0 and fingerprint in BIP85_DATA:
            entry = BIP85_DATA[fingerprint]
            entry.setdefault("primary_uid", primary_uid)
            entry["uids"].append(uid_str)
        screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
        msg = "User ID added" if r.returncode == 0 else "Failed to add User ID"
        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGEditUidView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            tools_screens,
        )

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run(["gpg", "--list-secret-keys", "--with-colons", fingerprint], capture_output=True, text=True)
        uids = parse_uid_list(result.stdout)
        if not uids:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No user IDs found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        uid_buttons = [ButtonOption(u["uid"]) for u in uids]
        sel = self.run_screen(
            ButtonListScreen,
            title="Select User ID",
            is_button_text_centered=False,
            button_data=uid_buttons,
        )
        if sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        old_uid = uids[sel]["uid"]

        def prompt_text(title: str, default: str = ""):
            ret_dict = tools_screens.ToolsTextQRTextEntryScreen(textToEncode=default, title=title).display()
            if "is_back_button" in ret_dict:
                return None
            try:
                import re

                return bytes(
                    re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                    encoding="raw_unicode_escape",
                ).decode("unicode_escape")
            except UnicodeDecodeError:
                return ret_dict["textToEncode"]

        name = prompt_text("Name")
        if name is None:
            return Destination(BackStackView)
        email = prompt_text("Email")
        if email is None:
            return Destination(BackStackView)
        new_uid = f"{name} <{email}>" if email else name

        r = run(["gpg", "--batch", "--quick-add-uid", fingerprint, new_uid])
        success = r.returncode == 0
        if success:
            run(["gpg", "--batch", "--quick-set-primary-uid", fingerprint, new_uid])
            run(["gpg", "--batch", "--quick-revoke-uid", fingerprint, old_uid])
        screen = LargeIconStatusScreen if success else WarningScreen
        msg = "User ID updated" if success else "Failed to update User ID"
        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGSetPrimaryUidView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            seed_screens,
        )

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run(["gpg", "--list-secret-keys", "--with-colons", fingerprint], capture_output=True, text=True)
        uids = parse_uid_list(result.stdout)
        if not uids:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No user IDs found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        uid_buttons = [ButtonOption(u["uid"]) for u in uids]
        sel = self.run_screen(
            ButtonListScreen,
            title="Set Primary User ID",
            is_button_text_centered=False,
            button_data=uid_buttons,
        )
        if sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        uid = uids[sel]["uid"]

        r = run(["gpg", "--batch", "--quick-set-primary-uid", fingerprint, uid])
        if r.returncode == 0 and fingerprint in BIP85_DATA:
            entry = BIP85_DATA[fingerprint]
            entry["primary_uid"] = uid
            ulist = entry.get("uids", [])
            if uid in ulist:
                ulist.remove(uid)
                ulist.insert(0, uid)
        screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
        msg = "Primary UID set" if r.returncode == 0 else "Failed to set primary UID"
        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGRevokeUidView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
        )

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run(["gpg", "--list-secret-keys", "--with-colons", fingerprint], capture_output=True, text=True)
        uids = parse_uid_list(result.stdout)
        if not uids:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No user IDs found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        uid_buttons = [ButtonOption(u["uid"]) for u in uids]
        sel = self.run_screen(
            ButtonListScreen,
            title="Revoke User ID",
            is_button_text_centered=False,
            button_data=uid_buttons,
        )
        if sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        uid = uids[sel]["uid"]

        r = run(["gpg", "--batch", "--quick-revoke-uid", fingerprint, uid])
        screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
        msg = "User ID revoked" if r.returncode == 0 else "Failed to revoke User ID"
        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGDeleteUidView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
        )

        ret = self.run_screen(
            WarningScreen,
            title="WARNING",
            status_headline=None,
            text="Revocation is almost always\npreferable to deleting.",
            show_back_button=True,
            button_data=[ButtonOption("I Understand")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run(["gpg", "--list-secret-keys", "--with-colons", fingerprint], capture_output=True, text=True)
        uids = parse_uid_list(result.stdout)
        if not uids:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No user IDs found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        uid_buttons = [ButtonOption(u["uid"]) for u in uids]
        sel = self.run_screen(
            ButtonListScreen,
            title="Delete User ID",
            is_button_text_centered=False,
            button_data=uid_buttons,
        )
        if sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        uid_str = uids[sel]["uid"]
        idx = uids[sel]["idx"]

        r = gpg_edit_uid(fingerprint, idx, "deluid")
        if r.returncode == 0 and fingerprint in BIP85_DATA:
            entry = BIP85_DATA[fingerprint]
            entry["uids"] = [u for u in entry.get("uids", []) if u != uid_str]
            if entry.get("primary_uid") == uid_str:
                entry["primary_uid"] = entry["uids"][0] if entry["uids"] else None
        screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
        msg = "User ID deleted" if r.returncode == 0 else "Failed to delete User ID"
        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGFileOpsMenuView(View):
    ENCRYPT = ButtonOption("Encrypt")
    DECRYPT = ButtonOption("Decrypt")
    SIGN = ButtonOption("Sign")
    VERIFY = ButtonOption("Verify Signature")

    def run(self):
        button_data = [self.ENCRYPT, self.DECRYPT, self.SIGN, self.VERIFY]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="File Operations",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        selected = button_data[selected_menu_num]
        if selected == self.ENCRYPT:
            return Destination(ToolsGPGEncryptFileView)
        if selected == self.DECRYPT:
            return Destination(ToolsGPGDecryptFileView)
        if selected == self.SIGN:
            return Destination(ToolsGPGSignMenuView)
        return Destination(ToolsGPGVerifyFileView)


class ToolsGPGMessageMenuView(View):
    ENCRYPT = ButtonOption("Create Message")
    DECRYPT = ButtonOption("Load Message")

    def run(self):
        button_data = [self.ENCRYPT, self.DECRYPT]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Secure Messaging",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.ENCRYPT:
            return Destination(ToolsGPGEncryptMessageView)
        return Destination(ToolsGPGDecryptMessageView)


class ToolsGPGSignMenuView(View):
    FILE = ButtonOption("File")
    MANIFEST = ButtonOption("Manifest")

    def run(self):
        button_data = [self.FILE, self.MANIFEST]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Sign",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.FILE:
            return Destination(ToolsGPGSignFileView)
        return Destination(ToolsGPGSignManifestView)


class ToolsGPGEncryptMessageView(View):
    def run(self):
        from subprocess import run
        import time
        from seedsigner.helpers import seedkeeper_utils
        from seedsigner.helpers.gpg_message import encrypt_message
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            WarningScreen,
            LoadingScreenThread,
            QRDisplayScreen,
        )
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.gui.screens.tools_screens import ToolsTextQRTextEntryScreen
        from seedsigner.models.decode_qr import DecodeQR
        from seedsigner.models.encode_qr import UrBytesQrEncoder

        result = run([
            "gpg",
            "--list-keys",
            "--with-colons",
        ], capture_output=True, text=True)

        keys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "pub":
                cur = {"fpr": None, "uid": None}
                keys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        SKIP = ButtonOption("Skip")
        buttons = [SKIP]
        for key in keys:
            label = key["uid"] if key["uid"] else key["fpr"][-8:]
            buttons.append(ButtonOption(label))

        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if buttons[selected] is SKIP:
            key = None
        else:
            key = keys[selected - 1]

        SRC_TYPE = ButtonOption("Type Message")
        SRC_SEEDKEEPER = ButtonOption("Load Seedkeeper")
        SRC_SCAN = ButtonOption("Scan QR")
        src_buttons = [SRC_TYPE, SRC_SEEDKEEPER, SRC_SCAN]

        src_selected = self.run_screen(
            ButtonListScreen,
            title="Message Source",
            is_button_text_centered=False,
            button_data=src_buttons,
        )

        if src_selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if src_buttons[src_selected] == SRC_TYPE:
            ret_dict = ToolsTextQRTextEntryScreen(textToEncode="", title="Message").display()
            if "is_back_button" in ret_dict:
                return Destination(BackStackView)
            message = ret_dict["textToEncode"]
        elif src_buttons[src_selected] == SRC_SCAN:
            decoder = DecodeQR(is_text=True)
            ScanScreen(decoder=decoder, instructions_text="Scan message").display()
            self.controller.reset_screensaver_timeout()
            time.sleep(0.1)
            if not decoder.is_complete:
                return Destination(BackStackView)
            message = decoder.get_text()
        else:
            Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
            if not Satochip_Connector:
                return Destination(BackStackView)

            loading = LoadingScreenThread(text="Listing Secrets\n\n\n\n\n\n")
            loading.start()
            headers = Satochip_Connector.seedkeeper_list_secret_headers()
            loading.stop()

            headers_parsed = []
            buttons = []
            for header in headers:
                stype = SEEDKEEPER_DIC_TYPE.get(header["type"], hex(header["type"]))
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header["export_rights"], hex(header["export_rights"]))
                if stype == "Data" and export_rights == "Plaintext export allowed":
                    label = header["label"] or "Unnamed"
                    headers_parsed.append((header["id"], label))
                    buttons.append(ButtonOption(label))

            if not headers_parsed:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="No messages found",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            selected_msg = self.run_screen(
                ButtonListScreen,
                title="Select Message",
                is_button_text_centered=False,
                button_data=buttons,
            )
            if selected_msg == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            loading = LoadingScreenThread(text="Loading Secret\n\n\n\n\n\n")
            loading.start()
            secret_dict = Satochip_Connector.seedkeeper_export_secret(headers_parsed[selected_msg][0], None)
            loading.stop()

            secret_list = secret_dict["secret_list"]
            status = Satochip_Connector.card_get_status()[3]
            if status["protocol_minor_version"] == 1:
                length = secret_list[0]
                msg_bytes = bytes(secret_list[1:1 + length])
            else:
                length = (secret_list[0] << 8) + secret_list[1]
                msg_bytes = bytes(secret_list[2:2 + length])
            message = msg_bytes.decode("utf-8")
        signkey_blob = None
        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
        ], capture_output=True, text=True)

        sign_keys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                cur = {"fpr": None, "uid": None}
                sign_keys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        if sign_keys:
            sign_buttons = [ButtonOption("Skip")]
            for sk in sign_keys:
                label = sk["uid"] if sk["uid"] else sk["fpr"][-8:]
                sign_buttons.append(ButtonOption(label))

            selected_sign = self.run_screen(
                ButtonListScreen,
                title="Signing Key",
                is_button_text_centered=False,
                button_data=sign_buttons,
            )

            if selected_sign == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            if selected_sign > 0:
                sign_key = sign_keys[selected_sign - 1]
                exported_sign = run([
                    "gpg",
                    "--armor",
                    "--export-secret-keys",
                    sign_key["fpr"],
                ], capture_output=True, text=True)
                if exported_sign.returncode != 0:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Failed to export signing key",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
                signkey_blob = exported_sign.stdout

        if key is not None:
            exported = run([
                "gpg",
                "--armor",
                "--export",
                key["fpr"],
            ], capture_output=True, text=True)
            if exported.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            pub_blob = exported.stdout
        else:
            pub_blob = None

        try:
            ciphertext = encrypt_message(pub_blob, message, signkey_blob=signkey_blob)
        except ValueError:
            ret_dict = ToolsTextQRTextEntryScreen(textToEncode="", title="Passphrase").display()
            if "is_back_button" in ret_dict:
                return Destination(BackStackView)
            passphrase = ret_dict["textToEncode"]
            ciphertext = encrypt_message(
                pub_blob,
                message,
                signkey_blob=signkey_blob,
                signkey_passphrase=passphrase,
            )
        except Exception:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to encrypt message",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        DEST_QR = ButtonOption("Animated QR")
        DEST_FILE = ButtonOption("microSD")
        dest_buttons = [DEST_QR, DEST_FILE]

        dest_selected = self.run_screen(
            ButtonListScreen,
            title="Export to",
            is_button_text_centered=False,
            button_data=dest_buttons,
        )

        if dest_selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if dest_buttons[dest_selected] == DEST_FILE:
            import os
            from datetime import datetime

            if len(self.controller.storage.seeds) > 0:
                ret = self.run_screen(
                    WarningScreen,
                    title="WARNING",
                    status_headline=None,
                    text="These tools write data to the microSD card and may expose loaded secrets.",
                    show_back_button=True,
                    button_data=[ButtonOption("Continue")],
                )
                if ret == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)

            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            os.makedirs(file_list_path, exist_ok=True)
            filename = f"gpgmsg_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath = os.path.join(file_list_path, filename)
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(ciphertext)
            except Exception:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to save file",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Saved as {filename}",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(MainMenuView)

        loading = LoadingScreenThread(text="Encoding...")
        loading.start()
        try:
            qr_encoder = UrBytesQrEncoder(
                data=ciphertext.encode("utf-8"),
                qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
            )
        finally:
            loading.stop()

        num_codes = qr_encoder.seq_len()
        ret = self.run_screen(
            WarningScreen,
            title="Animated QR",
            status_headline=None,
            text=f"This export requires {num_codes} QR code{'s' if num_codes > 1 else ''}.",
            show_back_button=True,
            button_data=[ButtonOption("Start")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)
        return Destination(MainMenuView)


class ToolsGPGDecryptMessageView(View):
    def run(self):
        from subprocess import run
        from seedsigner.helpers.gpg_message import decrypt_message
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            WarningScreen,
            LargeIconStatusScreen,
            LoadingScreenThread,
            QRDisplayScreen,
        )
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.gui.screens.tools_screens import (
            ToolsTextQRTextEntryScreen,
            ToolsTextQRReviewTextScreen,
        )
        from seedsigner.models.decode_qr import DecodeQR, QRType
        from seedsigner.models.encode_qr import GenericStaticQrEncoder
        from urtypes.bytes import Bytes
        import time

        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
        ], capture_output=True, text=True)

        keys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                cur = {"fpr": None, "uid": None}
                keys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        ciphertext = self.controller.gpg_pending_message
        if ciphertext:
            self.controller.gpg_pending_message = None
        else:
            SRC_SCAN = ButtonOption("Scan QR")
            SRC_FILE = ButtonOption("Load File")
            src_buttons = [SRC_SCAN, SRC_FILE]
            src_selected = self.run_screen(
                ButtonListScreen,
                title="Message Source",
                is_button_text_centered=False,
                button_data=src_buttons,
            )
            if src_selected == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            if src_buttons[src_selected] == SRC_FILE:
                import os
                if len(self.controller.storage.seeds) > 0:
                    ret = self.run_screen(
                        WarningScreen,
                        title="WARNING",
                        status_headline=None,
                        text="These tools load data from the microSD card and may expose loaded secrets.",
                        show_back_button=True,
                        button_data=[ButtonOption("Continue")],
                    )
                    if ret == RET_CODE__BACK_BUTTON:
                        return Destination(BackStackView)

                file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
                os.makedirs(file_list_path, exist_ok=True)
                file_list = [
                    f
                    for f in os.listdir(file_list_path)
                    if (
                        not f.startswith('.')
                        and f != '__MACOSX'
                        and os.path.isfile(os.path.join(file_list_path, f))
                    )
                ]
                buttons = [ButtonOption(file) for file in file_list]
                if not buttons:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="No files found in microsd-images.",
                        show_back_button=False,
                        button_data=[ButtonOption("OK")],
                    )
                    return Destination(BackStackView)
                selected_file_num = self.run_screen(
                    ButtonListScreen,
                    title="Select File",
                    is_button_text_centered=False,
                    button_data=buttons,
                )
                if selected_file_num == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)
                filename = file_list[selected_file_num]
                filepath = os.path.join(file_list_path, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        ciphertext = f.read()
                except Exception:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Failed to load file",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
            else:
                decoder = DecodeQR()
                ScanScreen(decoder=decoder, instructions_text="Scan secure message").display()
                self.controller.reset_screensaver_timeout()
                time.sleep(0.1)
                if not decoder.is_complete:
                    return Destination(BackStackView)

                if decoder.qr_type == QRType.BYTES__UR:
                    raw = Bytes.from_cbor(
                        decoder.decoder.result_message().cbor
                    ).data
                    if isinstance(raw, memoryview):
                        raw = raw.tobytes()
                    if isinstance(raw, (bytes, bytearray)):
                        ciphertext = raw.decode("utf-8")
                    else:
                        ciphertext = raw
                elif decoder.qr_type == QRType.TEXT:
                    ciphertext = decoder.get_text()
                else:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Unsupported QR format",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)

        # gather public keys for signature verification
        pub_result = run([
            "gpg",
            "--list-keys",
            "--with-colons",
        ], capture_output=True, text=True)

        pubkeys = []
        cur = None
        for line in pub_result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "pub":
                cur = {"fpr": None, "uid": None}
                pubkeys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        for pk in pubkeys:
            exp = run([
                "gpg",
                "--armor",
                "--export",
                pk["fpr"],
            ], capture_output=True, text=True)
            pk["blob"] = exp.stdout

        # try without a private key first in case message is unencrypted
        dec_key = None
        try:
            plaintext, signer_fpr, verified = decrypt_message(
                None,
                ciphertext,
                pubkey_blobs=[pk["blob"] for pk in pubkeys],
            )
        except ValueError:
            # message is encrypted; try each available private key
            decrypted = False
            for key in keys:
                exported = run([
                    "gpg",
                    "--armor",
                    "--export-secret-keys",
                    key["fpr"],
                ], capture_output=True, text=True)
                if exported.returncode != 0:
                    continue
                try:
                    plaintext, signer_fpr, verified = decrypt_message(
                        exported.stdout,
                        ciphertext,
                        pubkey_blobs=[pk["blob"] for pk in pubkeys],
                    )
                    dec_key = key
                    decrypted = True
                    break
                except ValueError as e:
                    if "Passphrase required" in str(e):
                        ret_dict = ToolsTextQRTextEntryScreen(
                            textToEncode="", title="Passphrase"
                        ).display()
                        if "is_back_button" in ret_dict:
                            return Destination(BackStackView)
                        passphrase = ret_dict["textToEncode"]
                        try:
                            plaintext, signer_fpr, verified = decrypt_message(
                                exported.stdout,
                                ciphertext,
                                passphrase=passphrase,
                                pubkey_blobs=[pk["blob"] for pk in pubkeys],
                            )
                            dec_key = key
                            decrypted = True
                            break
                        except Exception:
                            continue
                    else:
                        continue
                except Exception:
                    continue

            if not decrypted:
                err_text = (
                    "No private keys found" if not keys else "Failed to decrypt message"
                )
                load = ButtonOption("Load Key")
                cont = ButtonOption("Continue")
                selected = self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=err_text,
                    show_back_button=False,
                    button_data=[load, cont],
                )
                if selected == 0:
                    from seedsigner.controller import Controller
                    self.controller.gpg_pending_message = ciphertext
                    self.controller.resume_main_flow = Controller.FLOW__GPG_MESSAGE
                    return Destination(ToolsGPGImportPrivkeyMenuView)
                return Destination(BackStackView)

        if isinstance(plaintext, (bytes, bytearray, memoryview)):
            plaintext = plaintext.decode("utf-8")

        # normalize line endings to avoid display issues on carriage returns
        plaintext = plaintext.replace("\r\n", "\n").replace("\r", "\n")

        if signer_fpr:
            label = signer_fpr[-8:]
            have_pub = False
            for pk in pubkeys:
                if pk["fpr"] == signer_fpr:
                    have_pub = True
                    label = pk["uid"] if pk["uid"] else pk["fpr"][-8:]
                    break
            if not verified and not have_pub:
                load = ButtonOption("Load Key")
                cont = ButtonOption("Continue")
                selected = self.run_screen(
                    WarningScreen,
                    title="Warning",
                    status_headline=None,
                    text="Missing public key to verify signature",
                    show_back_button=False,
                    button_data=[load, cont],
                )
                if selected == 0:
                    from seedsigner.controller import Controller
                    self.controller.gpg_pending_message = ciphertext
                    self.controller.resume_main_flow = Controller.FLOW__GPG_MESSAGE
                    return Destination(ToolsGPGImportPubkeyMenuView)
            if verified:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text=f"Valid Signature from\n{label}",
                    show_back_button=False,
                    button_data=[ButtonOption("Next")],
                )
            else:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Warning",
                    status_icon_name=SeedSignerIconConstants.WARNING,
                    status_color=GUIConstants.WARNING_COLOR,
                    status_headline=None,
                    text=f"Unverified Signature from\n{label}",
                    show_back_button=False,
                    button_data=[ButtonOption("Next")],
                )

        next_button = ButtonOption("Next")
        self.run_screen(
            ToolsTextQRReviewTextScreen,
            textToEncode=plaintext,
            title="Decrypted Message",
            button_data=[next_button],
            show_back_button=False,
        )

        SAVE = ButtonOption("Save to Seedkeeper")
        SHOW = ButtonOption("Show as QR")
        DONE = ButtonOption("Done")
        button_data = [SAVE, SHOW, DONE]
        selected_option = self.run_screen(
            ButtonListScreen,
            title="Decrypted Message",
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=False,
        )

        if selected_option == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_option] == SAVE:
            Satochip_Connector = seedkeeper_utils.init_satochip(
                self, init_card_filter=["seedkeeper"]
            )
            if not Satochip_Connector:
                return Destination(BackStackView)

            msg_bytes = plaintext.encode("utf-8")
            status = Satochip_Connector.card_get_status()[3]
            if status['protocol_minor_version'] == 1:
                if len(msg_bytes) > 255:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Message too large for Seedkeeper v1",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
                secret_list = [len(msg_bytes)] + list(msg_bytes)
            else:
                secret_list = list(len(msg_bytes).to_bytes(2, "big")) + list(msg_bytes)

            label = f"GPGMsg:{dec_key['fpr'][-8:]}" if dec_key else "GPGMsg"
            header = Satochip_Connector.make_header(
                "Data", "Plaintext export allowed", label
            )
            secret_dic = {"header": header, "secret_list": secret_list}

            try:
                fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
                    Satochip_Connector, secret_dic
                )
            except Exception as e:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=str(e),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            if not fits:
                self.run_screen(
                    WarningScreen,
                    title="Not Enough Space",
                    status_headline=None,
                    text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            try:
                loading = LoadingScreenThread(text="Saving Secret\n\n\n\n\n\n")
                loading.start()
                Satochip_Connector.seedkeeper_import_secret(secret_dic)
                loading.stop()
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text="Message saved to Seedkeeper",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
            except UnexpectedSW12Error as e:
                loading.stop()
                if e.sw1 == 0x6A and e.sw2 == 0x84:
                    err_text = "Not enough space on Seedkeeper for message"
                else:
                    err_text = format_sw_error(e.sw1, e.sw2)
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=err_text,
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
            except Exception:
                loading.stop()
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to save message",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
            return Destination(MainMenuView)

        if button_data[selected_option] == SHOW:
            encoder = GenericStaticQrEncoder(data=plaintext)
            self.run_screen(QRDisplayScreen, qr_encoder=encoder)
            return Destination(MainMenuView)

        return Destination(MainMenuView)


class ToolsGPGImportMenuView(View):
    PUBKEY = ButtonOption("Public Key")
    PRIVKEY = ButtonOption("Private Key")

    def run(self):
        button_data = [self.PUBKEY, self.PRIVKEY]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Import",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.PUBKEY:
            return Destination(ToolsGPGImportPubkeyMenuView)
        return Destination(ToolsGPGImportPrivkeyMenuView)


class ToolsGPGExportMenuView(View):
    PUBKEY = ButtonOption("Public Key")
    PRIVKEY = ButtonOption("Private Key")

    def run(self):
        button_data = [self.PUBKEY, self.PRIVKEY]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Export",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.PUBKEY:
            return Destination(ToolsGPGExportPubkeyView)
        return Destination(ToolsGPGExportPrivkeyView)


class ToolsGPGSmartMenuView(View):
    CARD_INFO = ButtonOption("View Card Info")
    GENERATE_ON_CARD = ButtonOption("Generate On-Card Key")
    CHANGE_ADMIN_PIN = ButtonOption("Change Admin PIN")
    CHANGE_USER_PIN = ButtonOption("Change User PIN")

    def run(self):
        button_data = [
            self.CARD_INFO,
            self.GENERATE_ON_CARD,
            self.CHANGE_ADMIN_PIN,
            self.CHANGE_USER_PIN,
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="SmartGPG",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        selected = button_data[selected_menu_num]
        if selected == self.CARD_INFO:
            return Destination(ToolsGPGCardInfoView)
        elif selected == self.GENERATE_ON_CARD:
            return Destination(ToolsGPGGenerateKeyOnCardView)
        elif selected == self.CHANGE_ADMIN_PIN:
            return Destination(ToolsGPGChangeAdminPinView)
        elif selected == self.CHANGE_USER_PIN:
            return Destination(ToolsGPGChangeUserPinView)


class ToolsGPGCardInfoView(View):
    def run(self):
        from subprocess import run

        data = run(["gpg", "--card-status"], capture_output=True, text=True)
        text = data.stdout or data.stderr or "No card info"
        self.run_screen(
            LargeIconStatusScreen,
            title="Card Info",
            status_headline=None,
            text=text[:400],
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        return Destination(BackStackView)


class ToolsGPGGenerateKeyOnCardView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        self.loading_screen = LoadingScreenThread(text="Generating key\n\n\n(May take a while)")
        self.loading_screen.start()
        run(
            ["gpg", "--batch", "--pinentry-mode", "loopback", "--status-fd", "1", "--command-fd", "0", "--edit-card"],
            input="admin\ngenerate\ny\n",
            text=True,
        )
        self.loading_screen.stop()
        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Key generated on card",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        return Destination(MainMenuView)


class ToolsGPGChangeAdminPinView(View):
    def run(self):
        from subprocess import run
        from seedsigner.helpers import seedkeeper_utils

        seedkeeper_utils.disconnect_smartcard_connections(self.controller)
        run(["gpgconf", "--reload", "scdaemon"])

        ret = self.run_screen(
            WarningScreen,
            title="Admin PIN Required",
            status_headline=None,
            text="Admin PIN is needed for changing keys and editing card settings.",
            show_back_button=True,
            button_data=[ButtonOption("Continue")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        old_pin = seedkeeper_utils.prompt_for_pin(self, "Current Admin PIN")
        if old_pin is None:
            return Destination(BackStackView)
        new_pin = seedkeeper_utils.prompt_for_pin(self, "New Admin PIN")
        if new_pin is None:
            return Destination(BackStackView)
        cmds = f"3\n{old_pin}\n{new_pin}\n{new_pin}\nQ\n"
        result = run(
            [
                "gpg",
                "--pinentry-mode",
                "loopback",
                "--status-fd",
                "1",
                "--command-fd",
                "0",
                "--change-pin",
            ],
            input=cmds,
            capture_output=True,
            text=True,
        )
        output = (result.stdout or "") + (result.stderr or "")
        success = "PIN changed" in output or "SC_OP_SUCCESS" in result.stdout
        failed = "SC_OP_FAILURE" in result.stdout or not success
        if failed:
            self.run_screen(
                LargeIconStatusScreen,
                title="Failed",
                status_headline=None,
                text="Admin PIN change failed",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(MainMenuView)
        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="PIN updated. Please remove and re-insert the card.",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        return Destination(MainMenuView)


class ToolsGPGChangeUserPinView(View):
    def run(self):
        from subprocess import run
        from seedsigner.helpers import seedkeeper_utils

        seedkeeper_utils.disconnect_smartcard_connections(self.controller)

        ret = self.run_screen(
            WarningScreen,
            title="Insert Card",
            status_headline=None,
            text="Remove and re-insert the smartcard, then press Continue.",
            show_back_button=True,
            button_data=[ButtonOption("Continue")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        run(["gpgconf", "--reload", "scdaemon"])

        ret = self.run_screen(
            WarningScreen,
            title="User PIN Required",
            status_headline=None,
            text="User PIN is needed for signing and using on-card keys.",
            show_back_button=True,
            button_data=[ButtonOption("Continue")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        old_pin = seedkeeper_utils.prompt_for_pin(self, "Current User PIN")
        if old_pin is None:
            return Destination(BackStackView)
        new_pin = seedkeeper_utils.prompt_for_pin(self, "New User PIN")
        if new_pin is None:
            return Destination(BackStackView)
        cmds = f"1\n{old_pin}\n{new_pin}\n{new_pin}\nQ\n"
        result = run(
            [
                "gpg",
                "--pinentry-mode",
                "loopback",
                "--status-fd",
                "1",
                "--command-fd",
                "0",
                "--change-pin",
            ],
            input=cmds,
            capture_output=True,
            text=True,
        )
        output = (result.stdout or "") + (result.stderr or "")
        success = "PIN changed" in output or "SC_OP_SUCCESS" in result.stdout
        failed = "SC_OP_FAILURE" in result.stdout or not success
        if failed:
            self.run_screen(
                LargeIconStatusScreen,
                title="Failed",
                status_headline=None,
                text="User PIN change failed",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(MainMenuView)
        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="PIN updated. Please remove and re-insert the card.",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        return Destination(MainMenuView)


class ToolsGPGEncryptFileView(View):
    def run(self):
        from subprocess import run
        import os
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            WarningScreen,
            LargeIconStatusScreen,
            LoadingScreenThread,
        )
        from seedsigner.gui.screens.tools_screens import ToolsTextQRTextEntryScreen

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)
        file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                not f.startswith('.')
                and f != '__MACOSX'
                and os.path.isfile(os.path.join(file_list_path, f))
            )
        ]
        buttons = [ButtonOption(file) for file in file_list]
        if not buttons:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        selected_file = self.run_screen(
            ButtonListScreen,
            title="Select File",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected_file == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        filename = file_list[selected_file]
        filepath = os.path.join(file_list_path, filename)
        try:
            # Sanity-check that the file is readable before invoking gpg
            with open(filepath, "rb"):
                pass
        except Exception as e:
            logger.exception("Failed to load file %s", filepath)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=f"Failed to load file:\n{e}",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        result = run([
            "gpg",
            "--list-keys",
            "--with-colons",
        ], capture_output=True, text=True)
        keys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "pub":
                cur = {"fpr": None, "uid": None}
                keys.append(cur)
            elif parts[0] == "fpr" and cur is not None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No public keys found",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)
        key_buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected_key = self.run_screen(
            ButtonListScreen,
            title="Select Recipient",
            is_button_text_centered=False,
            button_data=key_buttons,
        )
        if selected_key == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        rec_key = keys[selected_key]

        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
        ], capture_output=True, text=True)
        skeys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                cur = {"fpr": None, "uid": None}
                skeys.append(cur)
            elif parts[0] == "fpr" and cur is not None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]
        SKIP = ButtonOption("Skip")
        sign_buttons = [SKIP]
        for k in skeys:
            label = k["uid"] if k["uid"] else k["fpr"][-8:]
            sign_buttons.append(ButtonOption(label))
        selected_sign = self.run_screen(
            ButtonListScreen,
            title="Sign with",
            is_button_text_centered=False,
            button_data=sign_buttons,
        )
        if selected_sign == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        sign_key = None
        if sign_buttons[selected_sign] is not SKIP:
            sign_key = skeys[selected_sign - 1]

        outname = f"{filename}.gpg"

        def gpg_encrypt(passphrase: str | None = None):
            self.loading_screen = LoadingScreenThread(
                text=_("Encrypting File") + "\n\n\n\n\n\n" + _("(May take a while)")
            )
            self.loading_screen.start()
            cmd = [
                "gpg",
                "--batch",
                "--yes",
                "--trust-model",
                "always",
                "--output",
                outname,
                "--armor",
            ]
            if passphrase is not None:
                cmd.extend(["--pinentry-mode", "loopback", "--passphrase", passphrase])
            if sign_key is not None:
                cmd.extend(["--local-user", sign_key["fpr"], "--sign"])
            cmd.extend(["--recipient", rec_key["fpr"], "--encrypt", filename])
            result = run(cmd, capture_output=True, text=True, cwd=file_list_path)
            self.loading_screen.stop()
            return result

        result = gpg_encrypt()
        if result.returncode != 0 and sign_key is not None:
            # Likely needs a passphrase for the signing key
            ret_dict = ToolsTextQRTextEntryScreen(textToEncode="", title="Passphrase").display()
            if "is_back_button" in ret_dict:
                return Destination(BackStackView)
            passphrase = ret_dict["textToEncode"]
            result = gpg_encrypt(passphrase)

        if result.returncode != 0:
            logger.warning("gpg encrypt failed: %s", result.stderr)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to encrypt file",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text=f"Saved as {outname}",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(MainMenuView)


class ToolsGPGDecryptFileView(View):
    def run(self):
        from subprocess import run
        import os
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            WarningScreen,
            LargeIconStatusScreen,
            LoadingScreenThread,
        )
        from seedsigner.gui.screens.tools_screens import ToolsTextQRTextEntryScreen

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)
        file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                not f.startswith('.')
                and f != '__MACOSX'
                and os.path.isfile(os.path.join(file_list_path, f))
            )
        ]
        buttons = [ButtonOption(file) for file in file_list]
        if not buttons:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)
        selected_file = self.run_screen(
            ButtonListScreen,
            title="Select File",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected_file == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        filename = file_list[selected_file]
        filepath = os.path.join(file_list_path, filename)
        try:
            with open(filepath, "rb"):
                pass
        except Exception as e:
            logger.exception("Failed to load file %s", filepath)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=f"Failed to load file:\n{e}",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        outname = f"{filename}.dec"

        def gpg_decrypt(passphrase: str | None = None):
            self.loading_screen = LoadingScreenThread(
                text=_("Decrypting File") + "\n\n\n\n\n\n" + _("(May take a while)")
            )
            self.loading_screen.start()
            cmd = [
                "gpg",
                "--batch",
                "--yes",
                "--output",
                outname,
                "--decrypt",
                "--status-fd",
                "1",
            ]
            if passphrase is not None:
                cmd.extend(["--pinentry-mode", "loopback", "--passphrase", passphrase])
            cmd.append(filename)
            result = run(cmd, capture_output=True, text=True, cwd=file_list_path)
            self.loading_screen.stop()
            return result

        def parse_status(output: str):
            need_passphrase = False
            missing_priv = False
            signer_fpr = None
            verified = False
            missing_pub = False
            for line in output.splitlines():
                if not line.startswith("[GNUPG:]"):
                    continue
                parts = line[9:].split()
                tag = parts[0]
                if tag in {"NEED_PASSPHRASE", "MISSING_PASSPHRASE", "BAD_PASSPHRASE"}:
                    need_passphrase = True
                elif tag == "NO_SECKEY":
                    missing_priv = True
                elif tag == "NO_PUBKEY":
                    missing_pub = True
                    if len(parts) > 1:
                        signer_fpr = parts[1]
                elif tag == "BADSIG":
                    signer_fpr = parts[1]
                    verified = False
                elif tag == "VALIDSIG":
                    signer_fpr = parts[1]
                    verified = True
            return need_passphrase, missing_priv, signer_fpr, verified, missing_pub

        result = gpg_decrypt()
        need_pw, missing_priv, signer_fpr, verified, missing_pub = parse_status(result.stdout)

        if result.returncode != 0 and need_pw:
            ret_dict = ToolsTextQRTextEntryScreen(textToEncode="", title="Passphrase").display()
            if "is_back_button" in ret_dict:
                return Destination(BackStackView)
            passphrase = ret_dict["textToEncode"]
            result = gpg_decrypt(passphrase)
            need_pw, missing_priv, signer_fpr, verified, missing_pub = parse_status(result.stdout)

        if result.returncode != 0:
            if missing_priv:
                load = ButtonOption("Load Key")
                cont = ButtonOption("Continue")
                selected = self.run_screen(
                    WarningScreen,
                    title="Warning",
                    status_headline=None,
                    text="Missing private key to decrypt",
                    show_back_button=False,
                    button_data=[load, cont],
                )
                if selected == 0:
                    return Destination(ToolsGPGImportPrivkeyMenuView)
            logger.warning("gpg decrypt failed: %s", result.stderr)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to decrypt file",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        if signer_fpr:
            pub_result = run([
                "gpg",
                "--list-keys",
                "--with-colons",
            ], capture_output=True, text=True)
            pubkeys = []
            cur = None
            for line in pub_result.stdout.splitlines():
                parts = line.split(":")
                if parts[0] == "pub":
                    cur = {"fpr": None, "uid": None}
                    pubkeys.append(cur)
                elif parts[0] == "fpr" and cur is not None:
                    cur["fpr"] = parts[9]
                elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                    cur["uid"] = parts[9]
            label = signer_fpr[-8:]
            have_pub = False
            for pk in pubkeys:
                if pk["fpr"] == signer_fpr:
                    have_pub = True
                    label = pk["uid"] if pk["uid"] else pk["fpr"][-8:]
                    break
            if (not verified or missing_pub) and not have_pub:
                load = ButtonOption("Load Key")
                cont = ButtonOption("Continue")
                selected = self.run_screen(
                    WarningScreen,
                    title="Warning",
                    status_headline=None,
                    text="Missing public key to verify signature",
                    show_back_button=False,
                    button_data=[load, cont],
                )
                if selected == 0:
                    return Destination(ToolsGPGImportPubkeyMenuView)
            if verified:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text=f"Valid Signature from\n{label}",
                    show_back_button=False,
                    button_data=[ButtonOption("Next")],
                )
            else:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Warning",
                    status_icon_name=SeedSignerIconConstants.WARNING,
                    status_color=GUIConstants.WARNING_COLOR,
                    status_headline=None,
                    text=f"Unverified Signature from\n{label}",
                    show_back_button=False,
                    button_data=[ButtonOption("Next")],
                )

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text=f"Saved as {outname}",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(MainMenuView)


class ToolsGPGVerifyFileView(View):
    CHECK_SHA256 = ButtonOption("Check SHA256Sum")
    def run(self):
        from subprocess import run
        import hashlib, shutil
        from pathlib import Path
        from seedsigner.gui.screens.screen import LoadingScreenThread

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")]
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        if not self.controller.gpg_keys_imported:
            gpg_dir = Path(__file__).resolve().parent.parent.parent.parent / "gpg_keys"
            self.loading_screen = LoadingScreenThread(text="Importing GPG Keys\n\n\n\n\n\n(May take a while)")
            self.loading_screen.start()
            key_files = [str(p) for p in gpg_dir.glob("*.asc")]
            if key_files:
                run(["gpg", "--import", *key_files])
            self.loading_screen.stop()
            self.controller.gpg_keys_imported = True

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)

        # Get only the visible, valid files
        visible_file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                    not f.startswith('.') and  # Ignore hidden files (like .DS_Store)
                    f != '__MACOSX' and  # Ignore specific macOS metadata folder
                    os.path.isfile(os.path.join(file_list_path, f))  # Only include actual files
            )
        ]

        # Build button options
        verify_file_buttons = [ButtonOption(f) for f in visible_file_list]

        if not verify_file_buttons:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        # Show selection screen
        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select File",
            is_button_text_centered=False,
            button_data=verify_file_buttons
        )

        # Handle cancel
        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Use the same filtered list to get the selected filename
        verify_file_name = visible_file_list[selected_file_num]
        logger.info("Selected: %s", verify_file_name)
        filechecked = verify_file_name[:-4] if verify_file_name.endswith(".sig") else verify_file_name

        self.loading_screen = LoadingScreenThread(
            text="Checking Signature\n\n\n\n\n\n(May take a while)"
        )
        self.loading_screen.start()

        cmd = ["gpg", "--verify"]
        if verify_file_name.endswith(".sig"):
            cmd.append(verify_file_name)
            if (file_list_path / filechecked).exists():
                cmd.append(filechecked)
        else:
            sig_candidate = verify_file_name + ".sig"
            if (file_list_path / sig_candidate).exists():
                cmd.extend([sig_candidate, verify_file_name])
            else:
                cmd.append(verify_file_name)

        try:
            data = run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(file_list_path),
            )
        except FileNotFoundError as exc:
            self.loading_screen.stop()
            logger.warning("gpg verify failed: %s", exc)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="GPG not found",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        self.loading_screen.stop()

        result = data.stderr.split("\n")

        valid_sig = False
        failed_reason = "Check Failed"
        valid_sig_keyid = ""
        for line in result:
            if "gpg: assuming signed data in " in line:
                filechecked = line[30:-1]
            elif "Primary key fingerprint:" in line:
                valid_sig_keyid += "\n" + line[-20:]
            elif "Good signature from" in line:
                valid_sig = True
            elif "gpg: no signature found" in line:
                failed_reason = "No GPG signature found in file"
            elif "BAD signature from" in line:
                valid_sig = False
                failed_reason = "Invalid Signature\nfor file..."
                break
            elif "can't hash datafile: No data" in line:
                valid_sig = False
                failed_reason = "Can't find\ncorresponding file for\nthis signature..."

        if valid_sig:
            button_data = []
            # There are a bunch of different naming conventions that different projects use...
            manifest_filenames = ["manifest", # Sparrow uses this
                                  "sha256", # Seedsigner uses this
                                  "shasums"] # Liana uses this naming convention
            if any(manifest_filename in verify_file_name for manifest_filename in manifest_filenames):
                button_data.append(self.CHECK_SHA256)

            button_data.append(ButtonOption("Done"))

            ret = self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text="Valid Signature(s) from" + valid_sig_keyid,
                    show_back_button=False,
                    button_data=button_data
                )
            
            if button_data[ret] == self.CHECK_SHA256:
                verified_files = []
                failed_files = []
                missing_files = []

                if shutil.which("sha256sum"):
                    from seedsigner.models.settings import Settings

                    if Settings.HOSTNAME == Settings.SEEDSIGNER_OS:
                        sha256_cmd = ["sha256sum", "-c", filechecked]
                    else:
                        sha256_cmd = ["sha256sum", "--check", filechecked, "--ignore-missing"]

                    self.loading_screen = LoadingScreenThread(
                        text="Checking SHA256\n\n\n\n\n\n(This takes a while)"
                    )
                    self.loading_screen.start()

                    data = run(
                        sha256_cmd,
                        capture_output=True,
                        text=True,
                        cwd=file_list_path,
                    )

                    self.loading_screen.stop()

                    result_stdout = data.stdout.split("\n")
                    result_stderr = data.stderr.split("\n")
                    for line in result_stdout:
                        if ": OK" in line:
                            verified_files.append(line[:-4])
                        elif ": FAILED" in line:
                            failed_files.append(line[:-8])

                    for line in result_stderr:
                        if "No such file or directory" in line:
                            missing_files.append(line[23:-28])
                else:
                    self.loading_screen = LoadingScreenThread(text="Checking SHA256\n\n\n\n\n\n(This takes a while)")
                    self.loading_screen.start()
                    manifest_path = file_list_path / filechecked
                    with open(manifest_path, "r") as mf:
                        for line in mf:
                            line = line.strip()
                            if not line:
                                continue
                            parts = line.split()
                            if len(parts) < 2:
                                continue
                            checksum, name = parts[0], parts[-1].lstrip("*")
                            file_path = file_list_path / name
                            if file_path.exists():
                                h = hashlib.sha256()
                                with open(file_path, "rb") as f:
                                    for chunk in iter(lambda: f.read(65536), b""):
                                        h.update(chunk)
                                if h.hexdigest().lower() == checksum.lower():
                                    verified_files.append(name)
                                else:
                                    failed_files.append(name)
                            else:
                                missing_files.append(name)
                    self.loading_screen.stop()

                for file in missing_files:
                    try:
                        failed_files.remove(file)
                    except ValueError:
                        pass

                if len(failed_files) > 0:
                    failed_files_string = "\n".join(str(x) for x in failed_files)
                    self.run_screen(
                        WarningScreen,
                        title="WARNING",
                        status_headline=None,
                        text="Incorrect SHA256 for " + failed_files_string,
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")]
                    )
                elif len(verified_files) > 0:
                    verified_files_string = "\n".join(str(x) for x in verified_files)
                    self.run_screen(
                        LargeIconStatusScreen,
                        title="Success",
                        status_headline=None,
                        text="Matched SHA256 for " + verified_files_string,
                        show_back_button=False,
                        button_data=[ButtonOption("Done")]
                    )
                else:
                    self.run_screen(
                        WarningScreen,
                        title="WARNING",
                        status_headline=None,
                        text="No files from this checksum list found...",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")]
                    )
        else:

            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=failed_reason,
                show_back_button=True,
            )


        return Destination(MainMenuView)


class ToolsGPGSignFileView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)

        file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                not f.startswith('.')
                and f != '__MACOSX'
                and os.path.isfile(os.path.join(file_list_path, f))
            )
        ]

        buttons = [ButtonOption(file) for file in file_list]

        if not buttons:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select File",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        filename = file_list[selected_file_num]

        # Gather available private keys for signing
        result = run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
        )
        keys = parse_secret_key_list(result.stdout)

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        key_buttons = []
        for key in keys:
            label = key["uid"] if key["uid"] else key["fpr"][-8:]
            key_buttons.append(ButtonOption(label))

        selected_key = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=key_buttons,
        )

        if selected_key == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        key = keys[selected_key]

        self.loading_screen = LoadingScreenThread(text="Signing File\n\n\n\n\n\n(May take a while)")
        self.loading_screen.start()
        result = run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--local-user",
                key["fpr"],
                "--output",
                f"{filename}.sig",
                "--armor",
                "--detach-sign",
                filename,
            ],
            cwd=file_list_path,
            capture_output=True,
            text=True,
        )
        self.loading_screen.stop()

        if result.returncode != 0:
            logger.warning("gpg sign failed: %s", result.stderr)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to sign file",
                show_back_button=False,
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text=f"Signature saved as {filename}.sig",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )

        return Destination(MainMenuView)


class ToolsGPGSignManifestView(View):
    def run(self):
        from subprocess import run
        import hashlib, shutil
        from seedsigner.gui.screens.screen import LoadingScreenThread

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)

        manifest_name = "sha256.txt"

        file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                not f.startswith('.')
                and f != '__MACOSX'
                and os.path.isfile(os.path.join(file_list_path, f))
                and not f.endswith('.sig')
                and f != manifest_name
            )
        ]

        file_list.sort()

        if not file_list:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        self.loading_screen = LoadingScreenThread(text="Generating Manifest\n\n\n\n\n\n(May take a while)")
        self.loading_screen.start()

        if shutil.which("sha256sum"):
            result = run(
                ["sha256sum", *file_list],
                cwd=file_list_path,
                capture_output=True,
                text=True,
            )
            manifest_content = result.stdout
        else:
            lines = []
            for fname in file_list:
                h = hashlib.sha256()
                with open(file_list_path / fname, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                lines.append(f"{h.hexdigest()}  {fname}")
            manifest_content = "\n".join(lines) + "\n"

        (file_list_path / manifest_name).write_text(manifest_content)
        self.loading_screen.stop()

        key_result = run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
        )
        keys = []
        cur = None
        for line in key_result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                cur = {"fpr": None, "uid": None}
                keys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        key_buttons = []
        for key in keys:
            label = key["uid"] if key["uid"] else key["fpr"][-8:]
            key_buttons.append(ButtonOption(label))

        selected_key = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=key_buttons,
        )

        if selected_key == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        key = keys[selected_key]

        self.loading_screen = LoadingScreenThread(text="Signing File\n\n\n\n\n\n(May take a while)")
        self.loading_screen.start()
        result = run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--local-user",
                key["fpr"],
                "--output",
                f"{manifest_name}.sig",
                "--armor",
                "--detach-sign",
                manifest_name,
            ],
            cwd=file_list_path,
            capture_output=True,
            text=True,
        )
        self.loading_screen.stop()

        if result.returncode != 0:
            logger.warning("gpg sign failed: %s", result.stderr)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to sign manifest",
                show_back_button=False,
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text=f"Manifest saved as {manifest_name} and {manifest_name}.sig",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )

        return Destination(MainMenuView)


def _check_future_key_creation(view, key_blob: str) -> None:
    """Warn if the key's creation date is in the future and offer to set system time."""
    from subprocess import run
    from pgpy import PGPKey

    try:
        key, _ = PGPKey.from_blob(key_blob)
    except Exception:
        return

    import time

    if key.created and key.created.timestamp() > time.time():
        formatted = key.created.strftime("%Y-%m-%d %H:%M:%S")
        ret = view.run_screen(
            WarningScreen,
            title="Future Date",
            status_headline=None,
            text=f"Key date {formatted} is in the future.\nUpdate system time?",
            show_back_button=False,
            button_data=[ButtonOption("Update"), ButtonOption("Skip")],
        )
        if ret == 0:
            run(["date", "-s", formatted], capture_output=True)
            # Reset activity-based timers since system time changed
            view.controller.reset_screensaver_timeout()

class ToolsGPGImportPubkeyMenuView(View):
    LOAD_QR = ButtonOption("From QR")
    LOAD_FILE = ButtonOption("From File")
    LOAD_SEEDKEEPER = ButtonOption("From Seedkeeper")

    def run(self):
        button_data = [self.LOAD_QR, self.LOAD_FILE, self.LOAD_SEEDKEEPER]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Import GPG Pubkey",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.LOAD_QR:
            return Destination(ToolsGPGLoadPubkeyQRView)
        if button_data[selected_menu_num] == self.LOAD_FILE:
            return Destination(ToolsGPGImportPubkeyFileView)
        if button_data[selected_menu_num] == self.LOAD_SEEDKEEPER:
            return Destination(ToolsGPGImportPubkeySeedkeeperView)


class ToolsGPGLoadPubkeyQRView(View):
    def run(self):
        from subprocess import run
        from urtypes.bytes import Bytes
        from seedsigner.gui.screens.screen import WarningScreen, LargeIconStatusScreen
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.models.decode_qr import DecodeQR, QRType
        import time

        decoder = DecodeQR()
        ScanScreen(decoder=decoder, instructions_text="Scan public key").display()
        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)
        if not decoder.is_complete:
            return Destination(BackStackView)

        if decoder.qr_type == QRType.BYTES__UR:
            raw = Bytes.from_cbor(decoder.decoder.result_message().cbor).data
            if isinstance(raw, memoryview):
                raw = raw.tobytes()
            if isinstance(raw, (bytes, bytearray)):
                key_blob = raw.decode("utf-8")
            else:
                key_blob = raw
        elif decoder.qr_type == QRType.TEXT:
            key_blob = decoder.get_text()
        else:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Unsupported QR format",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        _check_future_key_creation(self, key_blob)

        imported = run(["gpg", "--import"], input=key_blob, capture_output=True, text=True)
        if imported.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Pubkey imported",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )

        return Destination(ToolsGPGMenuView)


class ToolsGPGImportPubkeyFileView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")]
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)

        verify_file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                not f.startswith('.')
                and f != '__MACOSX'
                and os.path.isfile(os.path.join(file_list_path, f))
            )
        ]

        verify_file_buttons = [ButtonOption(file) for file in verify_file_list]

        if not verify_file_buttons:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select File",
            is_button_text_centered=False,
            button_data=verify_file_buttons
        )

        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        verify_file_name = verify_file_list[selected_file_num]
        logger.info("Selected: %s", verify_file_name)
        filepath = os.path.join(file_list_path, verify_file_name)
        with open(filepath, "r") as f:
            key_blob = f.read()

        _check_future_key_creation(self, key_blob)

        data = run(["gpg", "--import", filepath], capture_output=True, text=True)

        result = data.stderr.split("\n")
        certs_not_changed = 0
        certs_imported = 0
        certs_processed = 0
        for line in result:
            if "not changed" in line:
                certs_not_changed += 1
                certs_processed += 1
            elif " imported" in line:
                certs_imported += 1
                certs_processed += 1

        self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="Imported:" + str(certs_imported) + "\nNot Changed:" + str(certs_not_changed),
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )

        return Destination(ToolsGPGMenuView)


class ToolsGPGImportPubkeySeedkeeperView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        Satochip_Connector = seedkeeper_utils.init_satochip(
            self, init_card_filter=["seedkeeper"]
        )
        if not Satochip_Connector:
            return Destination(BackStackView)

        self.loading_screen = LoadingScreenThread(text="Listing Keys\n\n\n\n\n\n")
        self.loading_screen.start()
        headers = Satochip_Connector.seedkeeper_list_secret_headers()
        self.loading_screen.stop()

        status = Satochip_Connector.card_get_status()[3]

        secret_ids = []
        buttons = []
        for header in headers:
            stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))
            label = header.get('label', '')
            if stype == "Data" and label.startswith("GPGPub:"):
                display_label = label[len("GPGPub:") :]
                secret_ids.append(header['id'])
                buttons.append(ButtonOption(display_label))

        if not buttons:
            self.run_screen(
                WarningScreen,
                title="No Keys",
                status_headline=None,
                text="No GPG public keys on Seedkeeper",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        sid = secret_ids[selected]

        self.loading_screen = LoadingScreenThread(text="Loading Key\n\n\n\n\n\n")
        self.loading_screen.start()
        secret_dict = Satochip_Connector.seedkeeper_export_secret(sid, None)
        self.loading_screen.stop()

        raw = secret_dict['secret_list']
        if status['protocol_minor_version'] == 1:
            length = raw[0]
            key_bytes = bytes(raw[1:1 + length])
        else:
            length = (raw[0] << 8) + raw[1]
            key_bytes = bytes(raw[2:2 + length])
        pubkey = key_bytes.decode("utf-8")

        _check_future_key_creation(self, pubkey)

        imported = run(
            ["gpg", "--import"],
            input=pubkey,
            capture_output=True,
            text=True,
        )
        if imported.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Pubkey imported",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )

        return Destination(ToolsGPGMenuView)


class ToolsGPGImportPrivkeyMenuView(View):
    GENERATE_NEW = ButtonOption("Generate New")
    LOAD_BIP85_KEY = ButtonOption("Derive BIP85")
    LOAD_QR = ButtonOption("From QR")
    LOAD_FILE = ButtonOption("From File")
    LOAD_SEEDKEEPER = ButtonOption("From Seedkeeper")

    def run(self):
        button_data = [
            self.GENERATE_NEW,
            self.LOAD_BIP85_KEY,
            self.LOAD_QR,
            self.LOAD_FILE,
            self.LOAD_SEEDKEEPER,
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Import GPG Privkey",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.GENERATE_NEW:
            return Destination(ToolsGPGGenerateKeyView)
        if button_data[selected_menu_num] == self.LOAD_BIP85_KEY:
            return Destination(ToolsGPGLoadBIP85KeyView)
        if button_data[selected_menu_num] == self.LOAD_QR:
            return Destination(ToolsGPGLoadPrivkeyQRView)
        if button_data[selected_menu_num] == self.LOAD_FILE:
            return Destination(ToolsGPGLoadPrivkeyFileView)
        if button_data[selected_menu_num] == self.LOAD_SEEDKEEPER:
            return Destination(ToolsGPGLoadPrivkeySeedkeeperView)


class ToolsGPGLoadPrivkeyQRView(View):
    def run(self):
        from subprocess import run
        from urtypes.bytes import Bytes
        from seedsigner.gui.screens.screen import WarningScreen, LargeIconStatusScreen
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.models.decode_qr import DecodeQR, QRType
        import time

        decoder = DecodeQR()
        ScanScreen(decoder=decoder, instructions_text="Scan private key").display()
        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)
        if not decoder.is_complete:
            return Destination(BackStackView)

        if decoder.qr_type == QRType.BYTES__UR:
            raw = Bytes.from_cbor(decoder.decoder.result_message().cbor).data
            if isinstance(raw, memoryview):
                raw = raw.tobytes()
            if isinstance(raw, (bytes, bytearray)):
                key_blob = raw.decode("utf-8")
            else:
                key_blob = raw
        elif decoder.qr_type == QRType.TEXT:
            key_blob = decoder.get_text()
        else:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Unsupported QR format",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        _check_future_key_creation(self, key_blob)

        imported = run(["gpg", "--import"], input=key_blob, capture_output=True, text=True)
        if imported.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Privkey imported",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )

        return Destination(ToolsGPGMenuView)


class ToolsGPGLoadPrivkeyFileView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import tools_screens

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)

        file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                not f.startswith('.')
                and f != '__MACOSX'
                and os.path.isfile(os.path.join(file_list_path, f))
            )
        ]

        buttons = [ButtonOption(file) for file in file_list]

        if not buttons:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select File",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        filename = file_list[selected_file_num]
        filepath = os.path.join(file_list_path, filename)

        ret_dict = tools_screens.ToolsTextQRTextEntryScreen(
            textToEncode="", title="Passphrase"
        ).display()
        if "is_back_button" in ret_dict:
            return Destination(BackStackView)

        try:
            import re

            passphrase = bytes(
                re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                encoding="raw_unicode_escape",
            ).decode("unicode_escape")
        except UnicodeDecodeError:
            passphrase = ret_dict["textToEncode"]

        decrypted = run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                passphrase,
                "--decrypt",
                filepath,
            ],
            capture_output=True,
            text=True,
        )
        if decrypted.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to decrypt key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        _check_future_key_creation(self, decrypted.stdout)

        imported = run(
            ["gpg", "--import"],
            input=decrypted.stdout,
            capture_output=True,
            text=True,
        )
        if imported.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Privkey imported",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )

        return Destination(ToolsGPGMenuView)


class ToolsGPGLoadPrivkeySeedkeeperView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        Satochip_Connector = seedkeeper_utils.init_satochip(
            self, init_card_filter=["seedkeeper"]
        )
        if not Satochip_Connector:
            return Destination(BackStackView)

        self.loading_screen = LoadingScreenThread(text="Listing Keys\n\n\n\n\n\n")
        self.loading_screen.start()
        headers = Satochip_Connector.seedkeeper_list_secret_headers()
        self.loading_screen.stop()

        status = Satochip_Connector.card_get_status()[3]

        secret_ids = []
        buttons = []
        for header in headers:
            stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))
            label = header.get('label', '')
            if stype == "Data" and label.startswith("GPGPriv:"):
                display_label = label[len("GPGPriv:") :]
                secret_ids.append(header['id'])
                buttons.append(ButtonOption(display_label))

        if not buttons:
            self.run_screen(
                WarningScreen,
                title="No Keys",
                status_headline=None,
                text="No GPG private keys on Seedkeeper",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        sid = secret_ids[selected]

        self.loading_screen = LoadingScreenThread(text="Loading Key\n\n\n\n\n\n")
        self.loading_screen.start()
        secret_dict = Satochip_Connector.seedkeeper_export_secret(sid, None)
        self.loading_screen.stop()

        raw = secret_dict['secret_list']
        if status['protocol_minor_version'] == 1:
            length = raw[0]
            key_bytes = bytes(raw[1:1 + length])
        else:
            length = (raw[0] << 8) + raw[1]
            key_bytes = bytes(raw[2:2 + length])
        privkey = key_bytes.decode("utf-8")

        _check_future_key_creation(self, privkey)

        imported = run(
            ["gpg", "--import"],
            input=privkey,
            capture_output=True,
            text=True,
        )
        if imported.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Privkey imported",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )

        return Destination(ToolsGPGMenuView)


def bip85_rsa_from_root(root, bits: int, index: int, sub_index: int | None = None):
    from embit import bip85
    from Cryptodome.PublicKey import RSA
    from seedsigner.helpers.bip85_drng import BIP85DRNG

    # Enforce a minimum RSA key size to avoid weak keys.
    if bits < MIN_RSA_KEY_BITS:
        bits = MIN_RSA_KEY_BITS

    path = [bits, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP_RSA, path)
    drng = BIP85DRNG.new(entropy)
    return RSA.generate(bits, randfunc=drng.read)


def bip85_ed25519_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "EdDSA"
):
    from embit import bip85
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives import serialization
    from pgpy.constants import EllipticCurveOID
    from pgpy.packet import fields

    path = [BIP85_GPG_ECC_KEY_BITS, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP_CURVE25519, path)
    d_bytes = entropy[:32]
    if alg == "EdDSA":
        priv = fields.EdDSAPriv()
        priv.oid = EllipticCurveOID.Ed25519
        pub_bytes = (
            ed25519.Ed25519PrivateKey.from_private_bytes(d_bytes)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        priv.p = fields.ECPoint.from_values(
            priv.oid.key_size,
            fields.ECPointFormat.Native,
            pub_bytes,
        )
        priv.s = fields.MPI(int.from_bytes(d_bytes, "big"))
    else:
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.Curve25519
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
        pub_bytes = (
            x25519.X25519PrivateKey.from_private_bytes(d_bytes)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        priv.p = fields.ECPoint.from_values(
            priv.oid.key_size,
            fields.ECPointFormat.Native,
            pub_bytes,
        )
        priv.s = fields.MPI(int.from_bytes(d_bytes, "big"))
    priv._compute_chksum()
    return priv


def gpg_quick_addkey(fingerprint: str, alg: str, usage: str):
    cmd = [
        "gpg",
        "--batch",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--quick-addkey",
        fingerprint,
        alg,
        usage,
    ]
    return subprocess.run(cmd)


def gpg_edit_subkey(fingerprint: str, idx: int, action: str):
    cmd = [
        "gpg",
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--command-fd",
        "0",
        "--status-fd",
        "2",
        "--edit-key",
        fingerprint,
    ]
    if action == "revkey":
        # Confirm revocation, supply a default reason code of 0 (no reason),
        # send an empty description, confirm the summary, then save.
        script = f"key {idx}\nrevkey\ny\n0\n\ny\nsave\n"
    else:
        script = f"key {idx}\n{action}\ny\nsave\n"
    return subprocess.run(cmd, input=script, text=True)


def gpg_edit_uid(fingerprint: str, idx: int, action: str):
    cmd = [
        "gpg",
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--command-fd",
        "0",
        "--status-fd",
        "2",
        "--edit-key",
        fingerprint,
    ]
    script = f"uid {idx}\n{action}\ny\nsave\n"
    return subprocess.run(cmd, input=script, text=True)


def gpg_export_selected_subkeys(fingerprint: str, sub_fprs: list[str]):
    """Export selected secret subkeys with a stubbed primary key.

    ``gpg --export-secret-subkeys`` strips the primary secret key material while
    including the full secret data for the requested subkeys.  Older GPG
    releases may not support the ``keep-subkey`` filter, but individual subkeys
    can still be targeted by appending ``!`` to each desired key ID.  This
    helper builds that command and returns the completed process.
    """

    keyids = [f[-16:] + "!" for f in sub_fprs]
    cmd = [
        "gpg",
        "--armor",
        "--export-options=export-minimal",
        "--export-secret-subkeys",
        fingerprint,
        *keyids,
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def _normalize_bip85_alg(alg: str) -> str:
    """Map user-facing algorithm identifiers to canonical values."""

    if not alg:
        return alg
    alias = {
        "p256": "nistp256",
    }
    alg_lower = alg.lower()
    return alias.get(alg_lower, alg_lower)


def _bip85_subkey_specs(alg):
    from pgpy.constants import PubKeyAlgorithm, KeyFlags

    alg = _normalize_bip85_alg(alg)
    if alg == "ed25519":
        return [
            (0, PubKeyAlgorithm.ECDH, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, "ECDH"),
            (1, PubKeyAlgorithm.EdDSA, {KeyFlags.Authentication, KeyFlags.Sign}, "EdDSA"),
            (2, PubKeyAlgorithm.EdDSA, {KeyFlags.Sign}, "EdDSA"),
        ]
    if alg in ["secp256k1", "nistp256", "brainpoolp256r1"]:
        return [
            (0, PubKeyAlgorithm.ECDH, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, "ECDH"),
            (1, PubKeyAlgorithm.ECDSA, {KeyFlags.Authentication, KeyFlags.Sign}, "ECDSA"),
            (2, PubKeyAlgorithm.ECDSA, {KeyFlags.Sign}, "ECDSA"),
        ]
    return [
        (0, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}),
        (1, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Authentication, KeyFlags.Sign}),
        (2, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Sign}),
    ]


def bip85_verify_existing(
    seed,
    fingerprint: str,
    key_index: int,
    created_ts: int,
    primary_algo: str,
    primary_bits: str,
    primary_curve: str,
    subkeys,
) -> bool:
    from embit import bip32
    from pgpy import PGPKey
    from pgpy.pgp import PrivKeyV4, PrivSubKeyV4
    from pgpy.constants import PubKeyAlgorithm
    from pgpy.packet import fields
    from pgpy.packet.types import MPI
    from Cryptodome.PublicKey import RSA
    from datetime import datetime, timezone

    logger.info(
        "bip85_verify_existing: fpr(last8)=%s index=%s",
        "redacted" if fingerprint else "None",
        key_index,
    )
    if hasattr(seed, "get_root"):
        root = seed.get_root()
    else:
        root = bip32.HDKey.from_seed(seed.seed_bytes)
    created = datetime.fromtimestamp(created_ts, tz=timezone.utc)
    primary_curve = _normalize_bip85_alg(primary_curve)

    def rsa_to_privpacket(rsa_key: RSA.RsaKey) -> fields.RSAPriv:
        priv = fields.RSAPriv()
        priv.n = MPI(rsa_key.n)
        priv.e = MPI(rsa_key.e)
        priv.d = MPI(rsa_key.d)
        priv.p = MPI(rsa_key.p)
        priv.q = MPI(rsa_key.q)
        priv.u = MPI(pow(rsa_key.p, -1, rsa_key.q))
        priv._compute_chksum()
        return priv

    pk = PrivKeyV4()
    if primary_algo in ("1", "2", "3"):
        pk.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
        try:
            bits = int(primary_bits) if primary_bits else MIN_RSA_KEY_BITS
        except (TypeError, ValueError):
            bits = MIN_RSA_KEY_BITS
        if bits < MIN_RSA_KEY_BITS:
            bits = MIN_RSA_KEY_BITS
        rsa_main = bip85_rsa_from_root(root, bits, key_index)
        pk.keymaterial = rsa_to_privpacket(rsa_main)
    elif primary_curve == "secp256k1":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_secp256k1_from_root(root, key_index)
    elif primary_curve == "nistp256":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_p256_from_root(root, key_index)
    elif primary_curve == "brainpoolp256r1":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_brainpoolp256r1_from_root(root, key_index)
    elif primary_curve == "ed25519":
        pk.pkalg = PubKeyAlgorithm.EdDSA
        pk.keymaterial = bip85_ed25519_from_root(root, key_index)
    else:
        logger.warning(
            "Unsupported primary key params: algo=%s bits=%s curve=%s",
            primary_algo,
            primary_bits,
            primary_curve,
        )
        return False
    pk.created = created
    pk.update_hlen()
    primary = PGPKey()
    primary._key = pk
    if primary.fingerprint != fingerprint:
        logger.warning(
            "Primary key fingerprint mismatch during BIP85 verification"
        )
        return False

    for sk in subkeys:
        logger.info("Validating subkey idx=%s fpr=%s", sk["idx"], sk["fpr"])
        j = sk["idx"] - 1
        group_idx = j // 3
        sub_index = j % 3
        subpkt = PrivSubKeyV4()
        algo = sk["algo"]
        curve = _normalize_bip85_alg(sk["curve"])
        bits = int(sk.get("bits", "0") or "0")
        if algo in ("1", "2", "3"):
            subpkt.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
            rsa_sub = bip85_rsa_from_root(root, bits, group_idx, sub_index)
            subpkt.keymaterial = rsa_to_privpacket(rsa_sub)
        elif curve == "secp256k1":
            subpkt.pkalg = PubKeyAlgorithm.ECDH if algo == "18" else PubKeyAlgorithm.ECDSA
            alg_name = "ECDH" if algo == "18" else "ECDSA"
            subpkt.keymaterial = bip85_secp256k1_from_root(root, group_idx, sub_index, alg_name)
        elif curve == "nistp256":
            subpkt.pkalg = PubKeyAlgorithm.ECDH if algo == "18" else PubKeyAlgorithm.ECDSA
            alg_name = "ECDH" if algo == "18" else "ECDSA"
            subpkt.keymaterial = bip85_p256_from_root(root, group_idx, sub_index, alg_name)
        elif curve == "brainpoolp256r1":
            subpkt.pkalg = PubKeyAlgorithm.ECDH if algo == "18" else PubKeyAlgorithm.ECDSA
            alg_name = "ECDH" if algo == "18" else "ECDSA"
            subpkt.keymaterial = bip85_brainpoolp256r1_from_root(root, group_idx, sub_index, alg_name)
        elif curve == "cv25519":
            if algo != "18":
                logger.warning(
                    "Unsupported subkey params at idx=%s: algo=%s curve=%s bits=%s",
                    sk["idx"],
                    algo,
                    curve,
                    bits,
                )
                return False
            subpkt.pkalg = PubKeyAlgorithm.ECDH
            subpkt.keymaterial = bip85_ed25519_from_root(root, group_idx, sub_index, "ECDH")
        elif curve == "ed25519":
            subpkt.pkalg = PubKeyAlgorithm.EdDSA if algo == "22" else PubKeyAlgorithm.ECDH
            alg_name = "EdDSA" if algo == "22" else "ECDH"
            subpkt.keymaterial = bip85_ed25519_from_root(root, group_idx, sub_index, alg_name)
        else:
            logger.warning(
                "Unsupported subkey params at idx=%s: algo=%s curve=%s bits=%s",
                sk["idx"],
                algo,
                curve,
                bits,
            )
            return False
        subpkt.created = created
        subpkt.update_hlen()
        subkey = PGPKey()
        subkey._key = subpkt
        if subkey.fingerprint != sk["fpr"]:
            logger.warning(
                "Subkey fingerprint mismatch at idx=%s: expected %s got %s",
                sk["idx"],
                sk["fpr"],
                subkey.fingerprint,
            )
            return False
    logger.info("Primary and subkeys validated successfully")
    return True


from typing import Optional, List, Dict


def bip85_add_subkeys(
    fingerprint: str, alg: str, key_index: int, start_index: int, seed
) -> Optional[List[Dict]]:
    from subprocess import run
    from embit import bip32
    from pgpy import PGPKey
    from pgpy.constants import (
        HashAlgorithm,
        SymmetricKeyAlgorithm,
        CompressionAlgorithm,
    )
    from pgpy.pgp import PrivSubKeyV4
    from pgpy.packet import fields
    from pgpy.packet.types import MPI
    from Cryptodome.PublicKey import RSA

    logger.debug(
        "bip85_add_subkeys: alg=%s key_index=%s start_index=%s",
        alg,
        key_index,
        start_index,
    )
    root = bip32.HDKey.from_seed(seed.seed_bytes)

    export = run(
        ["gpg", "--armor", "--export-secret-keys", fingerprint],
        capture_output=True,
        text=True,
    )
    pgp_key, _ = PGPKey.from_blob(export.stdout)
    created = pgp_key._key.created
    expires = pgp_key.expires_at

    KEY_BITS = (
        2048
        if alg == "rsa2048"
        else 3072
        if alg == "rsa3072"
        else 4096
        if alg == "rsa4096"
        else None
    )

    def rsa_to_privpacket(rsa_key: RSA.RsaKey) -> fields.RSAPriv:
        priv = fields.RSAPriv()
        priv.n = MPI(rsa_key.n)
        priv.e = MPI(rsa_key.e)
        priv.d = MPI(rsa_key.d)
        priv.p = MPI(rsa_key.p)
        priv.q = MPI(rsa_key.q)
        priv.u = MPI(pow(rsa_key.p, -1, rsa_key.q))
        priv._compute_chksum()
        return priv

    alg_canon = _normalize_bip85_alg(alg)
    subkey_specs = _bip85_subkey_specs(alg)
    type_map = {
        "nistp256": "ECC NIST P-256",
        "p256": "ECC NIST P-256",
        "brainpoolp256r1": "ECC Brainpool P-256",
        "brainpoolP256r1": "ECC Brainpool P-256",
        "secp256k1": "ECC secp256k1",
        "ed25519": "ECC Ed25519",
        "rsa2048": "RSA 2048",
        "rsa3072": "RSA 3072",
        "rsa4096": "RSA 4096",
    }
    alg_label = type_map.get(alg_canon, type_map.get(alg, alg))

    added = []
    for offset, pkalg, usage, *alg_name in subkey_specs:
        sub_index = (start_index % 3) + offset
        global_index = start_index + offset
        subpkt = PrivSubKeyV4()
        subpkt.pkalg = pkalg
        if alg_canon == "secp256k1":
            subpkt.keymaterial = bip85_secp256k1_from_root(root, key_index, sub_index, alg_name[0])
        elif alg_canon == "nistp256":
            subpkt.keymaterial = bip85_p256_from_root(root, key_index, sub_index, alg_name[0])
        elif alg_canon == "brainpoolp256r1":
            subpkt.keymaterial = bip85_brainpoolp256r1_from_root(root, key_index, sub_index, alg_name[0])
        elif alg_canon == "ed25519":
            subpkt.keymaterial = bip85_ed25519_from_root(root, key_index, sub_index, alg_name[0])
        else:
            rsa_sub = bip85_rsa_from_root(root, KEY_BITS, key_index, sub_index)
            subpkt.keymaterial = rsa_to_privpacket(rsa_sub)
        subpkt.created = created
        subpkt.update_hlen()
        subkey = PGPKey()
        subkey._key = subpkt
        pgp_key.add_subkey(
            subkey,
            usage=usage,
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB],
            expires=expires,
        )
        alg_name_str = alg_name[0] if alg_name else pkalg.name
        sub_type = alg_label if alg_canon.startswith("rsa") else f"{alg_name_str} {alg_label}"
        added.append({"index": global_index, "type": sub_type, "fingerprint": subkey.fingerprint})

    armored = str(pgp_key)
    r = run(
        ["gpg", "--batch", "--import-options", "merge-only", "--import"],
        input=armored.encode(),
        capture_output=True,
    )
    return added if r.returncode == 0 else None


def loose_add_subkeys(fingerprint: str, alg: str) -> bool:
    """Generate and merge random subkeys for algorithms unsupported by GPG."""
    from subprocess import run
    from contextlib import nullcontext
    from pgpy import PGPKey
    from pgpy.constants import (
        HashAlgorithm,
        SymmetricKeyAlgorithm,
        CompressionAlgorithm,
        EllipticCurveOID,
    )

    alg_canon = _normalize_bip85_alg(alg)
    curve_map = {
        "secp256k1": EllipticCurveOID.SECP256K1,
        "nistp256": EllipticCurveOID.NIST_P256,
        "brainpoolp256r1": EllipticCurveOID.Brainpool_P256,
    }
    curve = curve_map[alg_canon]

    export = run(
        ["gpg", "--armor", "--export-secret-keys", fingerprint],
        capture_output=True,
        text=True,
    )
    pgp_key, _ = PGPKey.from_blob(export.stdout)
    created = pgp_key._key.created
    expires = pgp_key.expires_at

    subkey_specs = _bip85_subkey_specs(alg)
    ctx = pgp_key.unlock("") if pgp_key.is_protected else nullcontext()
    with ctx:
        for _, pkalg, usage, *rest in subkey_specs:
            subkey = PGPKey.new(pkalg, curve)
            subkey._key.created = created
            subkey._key.update_hlen()
            pgp_key.add_subkey(
                subkey,
                usage=usage,
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB],
                expires=expires,
            )

    armored = str(pgp_key)
    r = run(
        ["gpg", "--batch", "--import-options", "merge-only", "--import"],
        input=armored.encode(),
        capture_output=True,
    )
    return r.returncode == 0

def bip85_secp256k1_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "ECDSA"
):
    from embit import bip85
    from cryptography.hazmat.primitives.asymmetric import ec
    from pgpy.constants import EllipticCurveOID
    from pgpy.packet import fields

    path = [BIP85_GPG_ECC_KEY_BITS, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP_SECP256K1, path)
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    d = int.from_bytes(entropy[:32], "big") % order
    if d == 0:
        d = 1
    pn = ec.derive_private_key(d, ec.SECP256K1()).public_key().public_numbers()
    if alg == "ECDH":
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.SECP256K1
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
    else:
        priv = fields.ECDSAPriv()
        priv.oid = EllipticCurveOID.SECP256K1
    priv.p = fields.ECPoint.from_values(
        priv.oid.key_size,
        fields.ECPointFormat.Standard,
        fields.MPI(pn.x),
        fields.MPI(pn.y),
    )
    priv.s = fields.MPI(d)
    priv._compute_chksum()
    return priv


def bip85_p256_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "ECDSA"
):
    from embit import bip85
    from cryptography.hazmat.primitives.asymmetric import ec
    from pgpy.constants import EllipticCurveOID
    from pgpy.packet import fields

    path = [BIP85_GPG_ECC_KEY_BITS, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP_NIST_P256, path)
    # Avoid relying on cryptography's ``group_order`` attribute since
    # some versions (such as those bundled with seedsigner-os) do not
    # expose it. Instead, use the well-known group order for P-256.
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    d = int.from_bytes(entropy[:32], "big") % order
    if d == 0:
        d = 1
    pn = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_numbers()
    if alg == "ECDH":
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.NIST_P256
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
    else:
        priv = fields.ECDSAPriv()
        priv.oid = EllipticCurveOID.NIST_P256
    priv.p = fields.ECPoint.from_values(
        priv.oid.key_size,
        fields.ECPointFormat.Standard,
        fields.MPI(pn.x),
        fields.MPI(pn.y),
    )
    priv.s = fields.MPI(d)
    priv._compute_chksum()
    return priv


def bip85_brainpoolp256r1_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "ECDSA",
):
    from embit import bip85
    from cryptography.hazmat.primitives.asymmetric import ec
    from pgpy.constants import EllipticCurveOID
    from pgpy.packet import fields

    path = [BIP85_GPG_ECC_KEY_BITS, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP_BRAINPOOL_P256, path)
    # Hardcode BrainpoolP256r1 group order to avoid relying on attributes
    # that may be missing in some cryptography builds.
    order = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
    d = int.from_bytes(entropy[:32], "big") % order
    if d == 0:
        d = 1
    pn = ec.derive_private_key(d, ec.BrainpoolP256R1()).public_key().public_numbers()
    if alg == "ECDH":
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.Brainpool_P256
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
    else:
        priv = fields.ECDSAPriv()
        priv.oid = EllipticCurveOID.Brainpool_P256
    priv.p = fields.ECPoint.from_values(
        priv.oid.key_size,
        fields.ECPointFormat.Standard,
        fields.MPI(pn.x),
        fields.MPI(pn.y),
    )
    priv.s = fields.MPI(d)
    priv._compute_chksum()
    return priv


def _bip85_key_type_choices(include_ecc: bool) -> list[tuple[str, str]]:
    """Return available key type labels and identifiers for BIP85 GPG keys."""

    choices: list[tuple[str, str]] = []
    if include_ecc:
        choices.extend(
            [
                ("ECC Ed25519", "ed25519"),
                ("ECC NIST P-256", "p256"),
                ("ECC Brainpool P-256", "brainpoolp256r1"),
            ]
        )
    choices.extend(
        [
            ("RSA 2048", "rsa2048"),
            ("RSA 3072", "rsa3072"),
            ("RSA 4096", "rsa4096"),
        ]
    )
    if include_ecc:
        choices.append(("ECC secp256k1", "secp256k1"))
    return choices


class ToolsGPGLoadBIP85KeyView(View):
    def run(self):
        from embit import bip32
        from pgpy import PGPKey, PGPUID
        from Cryptodome.PublicKey import RSA
        from pgpy.constants import (
            PubKeyAlgorithm,
            KeyFlags,
            HashAlgorithm,
            SymmetricKeyAlgorithm,
            CompressionAlgorithm,
        )
        from pgpy.pgp import PrivKeyV4, PrivSubKeyV4
        from pgpy.packet import fields
        from pgpy.packet.types import MPI
        from datetime import datetime, timezone, date
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.gui.screens import LargeIconStatusScreen, WarningScreen
        from seedsigner.gui.screens import seed_screens, tools_screens

        if len(self.controller.storage.seeds) == 0:
            self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="Load a seed before using\nBIP85 GPG tools.",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        ecc_enabled = (
            self.settings.get_value(SettingsConstants.SETTING__BIP85_ECC_KEYS)
            == SettingsConstants.OPTION__ENABLED
        )

        if ecc_enabled:
            self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text=(
                    "ECC Curves extend beyond current BIP85 spec..\n"
                    "Record your SeedSigner Version."
                ),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )

        if len(self.controller.storage.seeds) > 1:
            seed_buttons = []
            for seed in self.controller.storage.seeds:
                button_str = seed.get_fingerprint(
                    self.settings.get_value(SettingsConstants.SETTING__NETWORK)
                )
                seed_buttons.append(
                    ButtonOption(
                        button_str,
                        SeedSignerIconConstants.FINGERPRINT,
                        icon_color="blue",
                    )
                )
            selected_seed = self.run_screen(
                seed_screens.SeedSelectSeedScreen,
                title="Select Seed",
                text="Choose seed for BIP85 key",
                is_button_text_centered=False,
                button_data=seed_buttons,
            )
            if selected_seed == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            seed = self.controller.get_seed(selected_seed)
        else:
            seed = self.controller.get_seed(0)

        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title="Key Index").display()
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        key_index = int(ret)

        keytype_choices = _bip85_key_type_choices(ecc_enabled)
        keytype_buttons = [ButtonOption(label) for label, _ in keytype_choices]
        selected_type = self.run_screen(
            ButtonListScreen,
            title="Key Type",
            is_button_text_centered=False,
            button_data=keytype_buttons,
        )
        if selected_type == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        key_type_label = keytype_buttons[selected_type].button_label
        key_type = keytype_choices[selected_type][1]

        if key_type in ["secp256k1", "ed25519"]:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="This key type can't be exported to SmartPGP cards.",
                show_back_button=True,
                button_data=[ButtonOption("I Understand")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        if key_type.startswith("rsa"):
            warn_text = {
                "rsa2048": "Generating an RSA 2048 key can take around 3 minutes on a Pi Zero.\nNIST or Brainpool keys are faster and smaller.",
                "rsa3072": "Generating an RSA 3072 key can take around 15 minutes on a Pi Zero.\nNIST or Brainpool keys are faster and smaller.",
                "rsa4096": "Generating an RSA 4096 key can take around an hour on a Pi Zero.\nNIST or Brainpool keys are faster and smaller.",
            }[key_type]
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text=warn_text,
                show_back_button=True,
                button_data=[ButtonOption("I Understand")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        def prompt_text(title: str, default: str = ""):
            ret_dict = tools_screens.ToolsTextQRTextEntryScreen(
                textToEncode=default, title=title
            ).display()
            if "is_back_button" in ret_dict:
                return None
            try:
                import re
                return bytes(
                    re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                    encoding="raw_unicode_escape",
                ).decode("unicode_escape")
            except UnicodeDecodeError:
                return ret_dict["textToEncode"]

        name = prompt_text("Name")
        if name is None:
            return Destination(BackStackView)

        email = prompt_text("Email")
        if email is None:
            return Destination(BackStackView)

        created = datetime.fromtimestamp(BIP85_GPG_CREATED_TS, tz=timezone.utc)
        if key_type == "rsa2048":
            default_expiration = date(2029, 12, 31)
        else:
            default_expiration = date(2035, 12, 31)
        expiration_str = prompt_text(
            "Expiration YYYY-MM-DD", default_expiration.isoformat()
        )
        if expiration_str is None:
            return Destination(BackStackView)
        try:
            if expiration_str == "":
                expiration_dt = datetime.combine(
                    default_expiration, datetime.min.time(), tzinfo=timezone.utc
                )
            else:
                expiration_dt = datetime.strptime(
                    expiration_str, "%Y-%m-%d"
                ).replace(tzinfo=timezone.utc)
            if expiration_dt <= created:
                raise ValueError
            expires = expiration_dt - created
        except ValueError:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Invalid expiration date",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        root = bip32.HDKey.from_seed(seed.seed_bytes)
        KEY_BITS = (
            2048
            if key_type == "rsa2048"
            else 3072
            if key_type == "rsa3072"
            else 4096
            if key_type == "rsa4096"
            else None
        )

        def rsa_to_privpacket(rsa_key: RSA.RsaKey) -> fields.RSAPriv:
            priv = fields.RSAPriv()
            priv.n = MPI(rsa_key.n)
            priv.e = MPI(rsa_key.e)
            priv.d = MPI(rsa_key.d)
            priv.p = MPI(rsa_key.p)
            priv.q = MPI(rsa_key.q)
            priv.u = MPI(pow(rsa_key.p, -1, rsa_key.q))
            priv._compute_chksum()
            return priv

        self.loading_screen = LoadingScreenThread(text="Generating BIP85 GPG key\n\n\n\n\n\n(This takes a while)")
        self.loading_screen.start()
        try:
            pk = PrivKeyV4()
            if key_type == "secp256k1":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_secp256k1_from_root(root, key_index)
            elif key_type == "p256":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_p256_from_root(root, key_index)
            elif key_type == "brainpoolp256r1":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_brainpoolp256r1_from_root(root, key_index)
            elif key_type == "ed25519":
                pk.pkalg = PubKeyAlgorithm.EdDSA
                pk.keymaterial = bip85_ed25519_from_root(root, key_index)
            else:
                rsa_main = bip85_rsa_from_root(root, KEY_BITS, key_index)
                pk.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
                pk.keymaterial = rsa_to_privpacket(rsa_main)
            pk.created = created
            pk.update_hlen()

            pgp_key = PGPKey()
            pgp_key._key = pk

            uid = PGPUID.new(name, email=email)
            uid_str = uid.userid
            pgp_key.add_uid(
                uid,
                usage={KeyFlags.Certify, KeyFlags.Sign},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB],
                expires=expires,
                created=created,
            )

            if key_type == "ed25519":
                subkey_specs = [
                    (0, PubKeyAlgorithm.ECDH, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, "ECDH"),
                    (1, PubKeyAlgorithm.EdDSA, {KeyFlags.Authentication}, "EdDSA"),
                    (2, PubKeyAlgorithm.EdDSA, {KeyFlags.Sign}, "EdDSA"),
                ]
            elif key_type in ["secp256k1", "p256", "brainpoolp256r1"]:
                subkey_specs = [
                    (0, PubKeyAlgorithm.ECDH, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, "ECDH"),
                    (1, PubKeyAlgorithm.ECDSA, {KeyFlags.Authentication}, "ECDSA"),
                    (2, PubKeyAlgorithm.ECDSA, {KeyFlags.Sign}, "ECDSA"),
                ]
            else:
                subkey_specs = [
                    (0, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}),
                    (1, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Authentication}),
                    (2, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Sign}),
                ]

            subkey_info_list = []
            for spec in subkey_specs:
                sub_index, pkalg, usage, *alg = spec
                subpkt = PrivSubKeyV4()
                subpkt.pkalg = pkalg
                if key_type == "secp256k1":
                    subpkt.keymaterial = bip85_secp256k1_from_root(root, key_index, sub_index, alg[0])
                elif key_type == "p256":
                    subpkt.keymaterial = bip85_p256_from_root(root, key_index, sub_index, alg[0])
                elif key_type == "brainpoolp256r1":
                    subpkt.keymaterial = bip85_brainpoolp256r1_from_root(root, key_index, sub_index, alg[0])
                elif key_type == "ed25519":
                    subpkt.keymaterial = bip85_ed25519_from_root(root, key_index, sub_index, alg[0])
                else:
                    rsa_sub = bip85_rsa_from_root(root, KEY_BITS, key_index, sub_index)
                    subpkt.keymaterial = rsa_to_privpacket(rsa_sub)
                subpkt.created = created
                subpkt.update_hlen()
                subkey = PGPKey()
                subkey._key = subpkt
                pgp_key.add_subkey(
                    subkey,
                    usage=usage,
                    hashes=[HashAlgorithm.SHA256],
                    ciphers=[SymmetricKeyAlgorithm.AES256],
                    compression=[CompressionAlgorithm.ZLIB],
                    expires=expires,
                    created=created,
                )
                alg_name = alg[0] if alg else pkalg.name
                sub_type = (
                    key_type_label if key_type.startswith("rsa") else f"{alg_name} {key_type_label}"
                )
                subkey_info_list.append(
                    {
                        "index": sub_index,
                        "type": sub_type,
                        "fingerprint": subkey.fingerprint,
                    }
                )

            armored = str(pgp_key)

            result = run(["gpg", "--batch", "--import"], input=armored.encode(), capture_output=True)
        finally:
            self.loading_screen.stop()

        if result.returncode == 0:
            seed_fpr = seed.get_fingerprint(
                self.settings.get_value(SettingsConstants.SETTING__NETWORK)
            )
            BIP85_DATA[pgp_key.fingerprint] = {
                "primary_fpr": pgp_key.fingerprint,
                "seed_fpr": seed_fpr,
                "index": key_index,
                "key_type": key_type_label,
                "ss_version": self.controller.VERSION,
                "uids": [uid_str],
                "primary_uid": uid_str,
                "subkeys": subkey_info_list,
                "revocations": [],
            }
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="BIP85 GPG key imported",
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
        else:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )

        return Destination(ToolsGPGMenuView)




class ToolsGPGAddSubkeysView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.gui.screens import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
        )

        result = run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
        )
        keys = parse_secret_key_list(result.stdout)

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = []
        for key in keys:
            label = key["uid"] if key["uid"] else key["fpr"][-8:]
            buttons.append(ButtonOption(label))

        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]

        result = run(
            ["gpg", "--list-secret-keys", "--with-colons", fingerprint],
            capture_output=True,
            text=True,
        )
        start_index = sum(1 for line in result.stdout.splitlines() if line.startswith("ssb"))
        created_ts = keys[selected]["created"]
        entry = BIP85_DATA.get(fingerprint)
        bip85 = entry is not None
        fingerprint_suffix = fingerprint[-4:] if isinstance(fingerprint, str) and len(fingerprint) >= 4 else fingerprint
        logger.debug(
            "AddSubkeysView: fpr_suffix=%s bip85=%s start_index=%s",
            fingerprint_suffix,
            bip85,
            start_index,
        )
        sec_line = next(l for l in result.stdout.splitlines() if l.startswith("sec"))
        sec_parts = sec_line.split(":")
        primary_bits = sec_parts[2] if len(sec_parts) > 2 else ""
        primary_algo = sec_parts[3] if len(sec_parts) > 3 else ""
        primary_curve = sec_parts[16].lower() if len(sec_parts) > 16 else ""
        subkeys = parse_subkey_list(result.stdout)

        seed = None
        base_index = None
        if bip85:
            logger.debug(
                "BIP85 key detected; searching for seed fingerprint suffix=%s",
                entry["seed_fpr"][-4:] if isinstance(entry["seed_fpr"], str) and len(entry["seed_fpr"]) >= 4 else entry["seed_fpr"],
            )
            network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
            seed = None
            seed_index = None
            for idx, seed_obj in enumerate(self.controller.storage.seeds):
                if seed_obj.get_fingerprint(network) == entry["seed_fpr"]:
                    seed = seed_obj
                    seed_index = idx
                    break
            if seed is None:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Required seed not loaded",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            logger.debug("Seed matched at index=%s", seed_index)
            base_index = entry["index"]
            if not bip85_verify_existing(
                seed,
                fingerprint,
                base_index,
                created_ts,
                primary_algo,
                primary_bits,
                primary_curve,
                subkeys,
            ):
                logger.debug(
                    "Selected seed/index failed validation (base_index=%s)",
                    base_index,
                )
                corrected = None
                for i in range(base_index - 1, -1, -1):
                    if bip85_verify_existing(
                        seed,
                        fingerprint,
                        i,
                        created_ts,
                        primary_algo,
                        primary_bits,
                        primary_curve,
                        subkeys,
                    ):
                        corrected = i
                        break
                if corrected is None:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Selected seed/index mismatch",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
                logger.warning(
                    "Registry index %s mismatched; corrected to %s",
                    base_index,
                    corrected,
                )
                BIP85_DATA[fingerprint]["index"] = corrected
                base_index = corrected
            logger.info("Existing key validated successfully at index %s", base_index)

        key_index = base_index + (start_index // 3) if bip85 else None
        if bip85:
            logger.info(
                "AddSubkeysView: validated base_index=%s resulting key_index=%s",
                base_index,
                key_index,
            )
        ecc_enabled = (
            self.settings.get_value(SettingsConstants.SETTING__BIP85_ECC_KEYS)
            == SettingsConstants.OPTION__ENABLED
        )
        keytype_choices = _bip85_key_type_choices(ecc_enabled)
        keytype_buttons = [ButtonOption(label) for label, _ in keytype_choices]
        selected_type = self.run_screen(
            ButtonListScreen,
            title="Key Type",
            is_button_text_centered=False,
            button_data=keytype_buttons,
        )
        if selected_type == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        _, alg = keytype_choices[selected_type]

        if alg in ["secp256k1", "ed25519"]:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="This key type can't be exported to SmartPGP cards.",
                show_back_button=True,
                button_data=[ButtonOption("I Understand")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        self.loading_screen = LoadingScreenThread(
            text="Generating subkeys\n\n\n\n\n(This takes a while)"
        )
        self.loading_screen.start()
        success = True
        added_info = None
        try:
            if bip85:
                added_info = bip85_add_subkeys(
                    fingerprint, alg, key_index, start_index, seed
                )
                success = added_info is not None
            elif alg.startswith("rsa"):
                for usage in ["encrypt", "sign,auth", "sign"]:
                    r = gpg_quick_addkey(fingerprint, alg, usage)
                    if r.returncode != 0:
                        success = False
                        break
            elif alg == "ed25519":
                cmds = [
                    ("cv25519", "encrypt"),
                    ("ed25519", "sign,auth"),
                    ("ed25519", "sign"),
                ]
                for sub_alg, usage in cmds:
                    r = gpg_quick_addkey(fingerprint, sub_alg, usage)
                    if r.returncode != 0:
                        success = False
                        break
            else:
                success = loose_add_subkeys(fingerprint, alg)
        finally:
            self.loading_screen.stop()

        if success:
            if bip85 and added_info is not None:
                BIP85_DATA[fingerprint]["subkeys"].extend(added_info)
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="Subkeys added",
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
        else:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to add subkeys",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )

        return Destination(ToolsGPGMenuView)


class ToolsGPGGenerateKeyView(View):
    def run(self):
        from pgpy import PGPKey, PGPUID
        from pgpy.constants import (
            PubKeyAlgorithm,
            KeyFlags,
            HashAlgorithm,
            SymmetricKeyAlgorithm,
            CompressionAlgorithm,
            EllipticCurveOID,
        )
        from datetime import datetime, timezone, date
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.gui.screens import (
            LargeIconStatusScreen,
            WarningScreen,
            tools_screens,
        )

        keytype_data = [
            (
                "ECC Ed25519",
                (PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519),
                True,
            ),
            (
                "ECC NIST P-256",
                (PubKeyAlgorithm.ECDSA, EllipticCurveOID.NIST_P256),
                False,
            ),
            (
                "ECC Brainpool P-256",
                (PubKeyAlgorithm.ECDSA, EllipticCurveOID.Brainpool_P256),
                False,
            ),
            (
                "RSA 2048",
                (PubKeyAlgorithm.RSAEncryptOrSign, 2048),
                False,
            ),
            (
                "RSA 3072",
                (PubKeyAlgorithm.RSAEncryptOrSign, 3072),
                False,
            ),
            (
                "RSA 4096",
                (PubKeyAlgorithm.RSAEncryptOrSign, 4096),
                False,
            ),
            (
                "ECC secp256k1",
                (PubKeyAlgorithm.ECDSA, EllipticCurveOID.SECP256K1),
                True,
            ),
        ]
        keytype_buttons = [ButtonOption(label) for label, _, _ in keytype_data]
        selected_type = self.run_screen(
            ButtonListScreen,
            title="Key Type",
            is_button_text_centered=False,
            button_data=keytype_buttons,
        )
        if selected_type == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        _, (alg, param), warn_export_blocked = keytype_data[selected_type]

        if warn_export_blocked:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="This key type can't be exported to SmartPGP cards.",
                show_back_button=True,
                button_data=[ButtonOption("I Understand")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        if alg == PubKeyAlgorithm.RSAEncryptOrSign:
            warn_text = {
                2048: "Generating an RSA 2048 key can take around 3 minutes on a Pi Zero.\nNIST or Brainpool keys are faster and smaller.",
                3072: "Generating an RSA 3072 key can take around 15 minutes on a Pi Zero.\nNIST or Brainpool keys are faster and smaller.",
                4096: "Generating an RSA 4096 key can take around an hour on a Pi Zero.\nNIST or Brainpool keys are faster and smaller.",
            }[param]
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text=warn_text,
                show_back_button=True,
                button_data=[ButtonOption("I Understand")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        def prompt_text(title: str, default: str = ""):
            ret_dict = tools_screens.ToolsTextQRTextEntryScreen(
                textToEncode=default, title=title
            ).display()
            if "is_back_button" in ret_dict:
                return None
            try:
                import re

                return bytes(
                    re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                    encoding="raw_unicode_escape",
                ).decode("unicode_escape")
            except UnicodeDecodeError:
                return ret_dict["textToEncode"]

        name = prompt_text("Name")
        if name is None:
            return Destination(BackStackView)

        email = prompt_text("Email")
        if email is None:
            return Destination(BackStackView)

        created = datetime.now(timezone.utc)
        if alg == PubKeyAlgorithm.RSAEncryptOrSign and param == 2048:
            default_expiration = date(2029, 12, 31)
        else:
            default_expiration = date(2035, 12, 31)
        expiration_str = prompt_text(
            "Expiration YYYY-MM-DD", default_expiration.isoformat()
        )
        if expiration_str is None:
            return Destination(BackStackView)
        try:
            if expiration_str == "":
                expiration_dt = datetime.combine(
                    default_expiration, datetime.min.time(), tzinfo=timezone.utc
                )
            else:
                expiration_dt = datetime.strptime(
                    expiration_str, "%Y-%m-%d"
                ).replace(tzinfo=timezone.utc)
            if expiration_dt <= created:
                raise ValueError
            expires = expiration_dt - created
        except ValueError:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Invalid expiration date",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.loading_screen = LoadingScreenThread(
            text="Generating GPG key\n\n\n\n\n\n(This takes a while)"
        )
        self.loading_screen.start()
        try:
            # PGPKey.new leverages the OS CSPRNG for secure entropy
            master_key = PGPKey.new(alg, param)

            uid = PGPUID.new(name, email=email)
            master_key.add_uid(
                uid,
                usage={KeyFlags.Certify, KeyFlags.Sign},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB],
                expires=expires,
            )

            if alg == PubKeyAlgorithm.RSAEncryptOrSign:
                sub_enc = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, param)
                sub_auth = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, param)
                sub_sign = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, param)
            elif alg == PubKeyAlgorithm.EdDSA:
                sub_enc = PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519)
                sub_auth = PGPKey.new(PubKeyAlgorithm.EdDSA, param)
                sub_sign = PGPKey.new(PubKeyAlgorithm.EdDSA, param)
            else:
                curve = param
                sub_enc = PGPKey.new(PubKeyAlgorithm.ECDH, curve)
                sub_auth = PGPKey.new(PubKeyAlgorithm.ECDSA, curve)
                sub_sign = PGPKey.new(PubKeyAlgorithm.ECDSA, curve)

            master_key.add_subkey(
                sub_enc,
                usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB],
                expires=expires,
            )
            master_key.add_subkey(
                sub_auth,
                usage={KeyFlags.Authentication},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB],
                expires=expires,
            )
            master_key.add_subkey(
                sub_sign,
                usage={KeyFlags.Sign},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB],
                expires=expires,
            )

            armored = str(master_key)
            result = run(
                ["gpg", "--batch", "--import"],
                input=armored.encode(),
                capture_output=True,
            )
        finally:
            self.loading_screen.stop()

        if result.returncode == 0:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="GPG key generated",
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
        else:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )

        return Destination(MainMenuView)


class ToolsGPGExportPubkeyView(View):
    def run(self):
        from subprocess import run
        import os
        import platform
        from seedsigner.models.encode_qr import UrBytesQrEncoder
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            LoadingScreenThread,
            QRDisplayScreen,
        )

        result = run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
        )
        keys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                cur = {"fpr": None, "uid": None}
                keys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = []
        for key in keys:
            label = key["uid"] if key["uid"] else key["fpr"][-8:]
            buttons.append(ButtonOption(label))

        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        key = keys[selected]
        base_label = key["uid"] if key["uid"] else key["fpr"][-8:]

        dest_buttons = [
            ButtonOption("microSD"),
            ButtonOption("Animated QR"),
            ButtonOption("Seedkeeper"),
            ButtonOption("OpenGPG Card"),
        ]
        dest_selected = self.run_screen(
            ButtonListScreen,
            title="Export to",
            is_button_text_centered=False,
            button_data=dest_buttons,
        )

        if dest_selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if dest_selected == 0:
            if len(self.controller.storage.seeds) > 0:
                ret = self.run_screen(
                    WarningScreen,
                    title="WARNING",
                    status_headline=None,
                    text="These tools write data to the microSD card and may expose loaded secrets.",
                    show_back_button=True,
                    button_data=[ButtonOption("Continue")],
                )
                if ret == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)

            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            os.makedirs(file_list_path, exist_ok=True)

            filename = key["fpr"] + ".asc"
            filepath = os.path.join(file_list_path, filename)
            exported = run(
                ["gpg", "--armor", "--output", filepath, "--export", key["fpr"]],
                capture_output=True,
                text=True,
            )
            if exported.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Saved as {filename}",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(MainMenuView)
        elif dest_selected == 1:
            exported = run(
                ["gpg", "--armor", "--export", key["fpr"]],
                capture_output=True,
            )
            if exported.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            loading = LoadingScreenThread(text="Encoding...")
            loading.start()
            try:
                qr_encoder = UrBytesQrEncoder(
                    data=exported.stdout,
                    qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
                )
            finally:
                loading.stop()

            num_codes = qr_encoder.seq_len()
            ret = self.run_screen(
                WarningScreen,
                title="Animated QR",
                status_headline=None,
                text=f"This export requires {num_codes} QR code{'s' if num_codes > 1 else ''}.",
                show_back_button=True,
                button_data=[ButtonOption("Start")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)
            return Destination(MainMenuView)
        else:
            exported = run(
                ["gpg", "--armor", "--export", key["fpr"]],
                capture_output=True,
                text=True,
            )
            if exported.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            Satochip_Connector = seedkeeper_utils.init_satochip(
                self, init_card_filter=["seedkeeper"]
            )
            if not Satochip_Connector:
                return Destination(BackStackView)

            pubkey_bytes = exported.stdout.encode("utf-8")
            label = f"GPGPub:{base_label}"
            status = Satochip_Connector.card_get_status()[3]
            if status['protocol_minor_version'] == 1:
                if len(pubkey_bytes) > 255:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Pubkey too large for Seedkeeper v1",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
                secret_list = [len(pubkey_bytes)] + list(pubkey_bytes)
            else:
                secret_list = list(len(pubkey_bytes).to_bytes(2, "big")) + list(pubkey_bytes)

            header = Satochip_Connector.make_header(
                "Data", "Plaintext export allowed", label
            )
            secret_dic = {"header": header, "secret_list": secret_list}

            try:
                fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
                    Satochip_Connector, secret_dic
                )
            except Exception as e:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=str(e),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            if not fits:
                self.run_screen(
                    WarningScreen,
                    title="Not Enough Space",
                    status_headline=None,
                    text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            try:
                self.loading_screen = LoadingScreenThread(
                    text="Saving Secret\n\n\n\n\n\n",
                )
                self.loading_screen.start()
                Satochip_Connector.seedkeeper_import_secret(secret_dic)
                self.loading_screen.stop()
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text="Pubkey saved to Seedkeeper",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(MainMenuView)
            except UnexpectedSW12Error as e:
                self.loading_screen.stop()
                if e.sw1 == 0x6A and e.sw2 == 0x84:
                    error_text = "Not enough space on Seedkeeper for key"
                else:
                    error_text = format_sw_error(e.sw1, e.sw2)
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=error_text,
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            except Exception:
                self.loading_screen.stop()
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)


class ToolsGPGExportPrivkeyView(View):
    def run(self):
        from subprocess import run
        import os
        import platform
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            LoadingScreenThread,
        )
        from seedsigner.gui.screens import tools_screens

        result = run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
        )
        keys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                cur = {"fpr": None, "uid": None}
                keys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = []
        for key in keys:
            label = key["uid"] if key["uid"] else key["fpr"][-8:]
            buttons.append(ButtonOption(label))

        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        key = keys[selected]
        base_label = key["uid"] if key["uid"] else key["fpr"][-8:]

        dest_buttons = [
            ButtonOption("microSD"),
            ButtonOption("Seedkeeper"),
            ButtonOption("OpenGPG Card"),
        ]
        dest_selected = self.run_screen(
            ButtonListScreen,
            title="Export to",
            is_button_text_centered=False,
            button_data=dest_buttons,
        )

        if dest_selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if dest_selected == 0:
            if len(self.controller.storage.seeds) > 0:
                ret = self.run_screen(
                    WarningScreen,
                    title="WARNING",
                    status_headline=None,
                    text="These tools write data to the microSD card and may expose loaded secrets.",
                    show_back_button=True,
                    button_data=[ButtonOption("Continue")],
                )
                if ret == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)

            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            os.makedirs(file_list_path, exist_ok=True)

            ret_dict = tools_screens.ToolsTextQRTextEntryScreen(
                textToEncode="", title="Passphrase"
            ).display()
            if "is_back_button" in ret_dict:
                return Destination(BackStackView)
            try:
                import re

                passphrase = bytes(
                    re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                    encoding="raw_unicode_escape",
                ).decode("unicode_escape")
            except UnicodeDecodeError:
                passphrase = ret_dict["textToEncode"]

            filename = key["fpr"] + "_private.gpg"
            filepath = os.path.join(file_list_path, filename)
            exported = run(
                ["gpg", "--armor", "--export-secret-keys", key["fpr"]],
                capture_output=True,
                text=True,
            )
            if exported.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            protected = run(
                [
                    "gpg",
                    "--armor",
                    "--batch",
                    "--yes",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    passphrase,
                    "--symmetric",
                    "--cipher-algo",
                    "AES256",
                    "--output",
                    filepath,
                ],
                input=exported.stdout,
                capture_output=True,
                text=True,
            )
            if protected.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to protect key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Saved as {filename}",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(MainMenuView)
        elif dest_selected == 1:
            exported = run(
                ["gpg", "--armor", "--export-secret-keys", key["fpr"]],
                capture_output=True,
                text=True,
            )
            if exported.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            Satochip_Connector = seedkeeper_utils.init_satochip(
                self, init_card_filter=["seedkeeper"]
            )
            if not Satochip_Connector:
                return Destination(BackStackView)

            privkey_bytes = exported.stdout.encode("utf-8")
            label = f"GPGPriv:{base_label}"
            status = Satochip_Connector.card_get_status()[3]
            if status['protocol_minor_version'] == 1:
                if len(privkey_bytes) > 255:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Privkey too large for Seedkeeper v1",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
                secret_list = [len(privkey_bytes)] + list(privkey_bytes)
            else:
                secret_list = list(len(privkey_bytes).to_bytes(2, "big")) + list(privkey_bytes)

            header = Satochip_Connector.make_header(
                "Data", "Plaintext export allowed", label
            )
            secret_dic = {"header": header, "secret_list": secret_list}

            try:
                fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
                    Satochip_Connector, secret_dic
                )
            except Exception as e:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=str(e),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            if not fits:
                self.run_screen(
                    WarningScreen,
                    title="Not Enough Space",
                    status_headline=None,
                    text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            try:
                self.loading_screen = LoadingScreenThread(
                    text="Saving Secret\n\n\n\n\n\n",
                )
                self.loading_screen.start()
                Satochip_Connector.seedkeeper_import_secret(secret_dic)
                self.loading_screen.stop()
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text="Privkey saved to Seedkeeper",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(MainMenuView)
            except UnexpectedSW12Error as e:
                self.loading_screen.stop()
                if e.sw1 == 0x6A and e.sw2 == 0x84:
                    error_text = "Not enough space on Seedkeeper for key"
                else:
                    error_text = format_sw_error(e.sw1, e.sw2)
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=error_text,
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            except Exception:
                self.loading_screen.stop()
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
        else:
            return Destination(
                ToolsGPGImportKeyToCardView,
                view_args={"fingerprint": key["fpr"]},
            )


class ToolsGPGImportKeyToCardView(View):
    def __init__(self, fingerprint: str, selected_subkeys=None):
        super().__init__()
        self.fingerprint = fingerprint
        self.selected_subkeys = selected_subkeys
        self.loading_screen = None

    def _stop_loading_screen(self):
        loading = getattr(self, "loading_screen", None)
        if loading:
            try:
                loading.stop()
            finally:
                self.loading_screen = None

    def _clear_cached_admin_pin(self):
        controller = getattr(self, "controller", None)
        if not controller:
            return
        if hasattr(controller, "GPG_Admin_PIN"):
            controller.GPG_Admin_PIN = None
        try:
            seedkeeper_utils.disconnect_smartcard_connections(controller)
        except Exception:
            logger.debug("Failed to reset smartcard connections after admin PIN error", exc_info=True)

    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.helpers import seedkeeper_utils

        seedkeeper_utils.disconnect_smartcard_connections(self.controller)
        run(["gpgconf", "--reload", "scdaemon"])

        card_status = run(["gpg", "--card-status"], capture_output=True, text=True)
        status_out = (card_status.stdout or "") + (card_status.stderr or "")
        admin_pin = self.controller.GPG_Admin_PIN
        if "[none]" in status_out:
            ret = self.run_screen(
                WarningScreen,
                title="Default PINs",
                status_headline=None,
                text="Card uses default PINs. You'll set new Admin and User PINs before import.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            ret = self.run_screen(
                WarningScreen,
                title="Admin PIN Required",
                status_headline=None,
                text="Admin PIN is needed for changing keys and editing card settings.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            new_admin = seedkeeper_utils.prompt_for_pin(self, "New Admin PIN")
            if new_admin is None:
                return Destination(BackStackView)
            admin_cmds = f"3\n12345678\n{new_admin}\n{new_admin}\nQ\n"
            admin_res = run(
                [
                    "gpg",
                    "--pinentry-mode",
                    "loopback",
                    "--status-fd",
                    "1",
                    "--command-fd",
                    "0",
                    "--change-pin",
                ],
                input=admin_cmds,
                capture_output=True,
                text=True,
            )
            out = (admin_res.stdout or "") + (admin_res.stderr or "")
            success = "PIN changed" in out or "SC_OP_SUCCESS" in admin_res.stdout
            if "SC_OP_FAILURE" in admin_res.stdout or not success:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Failed",
                    status_headline=None,
                    text="Admin PIN change failed",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(BackStackView)
            self.controller.GPG_Admin_PIN = new_admin
            admin_pin = new_admin

            ret = self.run_screen(
                WarningScreen,
                title="User PIN Required",
                status_headline=None,
                text="User PIN is needed for signing and using on-card keys.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            new_user = seedkeeper_utils.prompt_for_pin(self, "New User PIN")
            if new_user is None:
                return Destination(BackStackView)
            user_cmds = f"1\n123456\n{new_user}\n{new_user}\nQ\n"
            user_res = run(
                [
                    "gpg",
                    "--pinentry-mode",
                    "loopback",
                    "--status-fd",
                    "1",
                    "--command-fd",
                    "0",
                    "--change-pin",
                ],
                input=user_cmds,
                capture_output=True,
                text=True,
            )
            out = (user_res.stdout or "") + (user_res.stderr or "")
            success = "PIN changed" in out or "SC_OP_SUCCESS" in user_res.stdout
            if "SC_OP_FAILURE" in user_res.stdout or not success:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Failed",
                    status_headline=None,
                    text="User PIN change failed",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(BackStackView)

            run(["gpgconf", "--reload", "scdaemon"])

        if admin_pin is None:
            ret = self.run_screen(
                WarningScreen,
                title="Admin PIN Required",
                status_headline=None,
                text="Admin PIN is needed for changing keys and editing card settings.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            admin_pin = seedkeeper_utils.prompt_for_pin(self, "Admin PIN")
            if admin_pin is None:
                return Destination(BackStackView)
            self.controller.GPG_Admin_PIN = admin_pin

        result = run(
            ["gpg", "--list-secret-keys", "--with-colons", self.fingerprint],
            capture_output=True,
            text=True,
        )
        primary_caps = ""
        subkeys = []
        cur = None
        algo = ""
        primary_bits = ""
        curve = ""
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                primary_caps = parts[11].lower()
                primary_bits = parts[2] if len(parts) > 2 else ""
                algo = parts[3] if len(parts) > 3 else ""
                if len(parts) > 16:
                    curve = parts[16].lower()
            elif parts[0] == "ssb":
                bits = parts[2] if len(parts) > 2 else ""
                cur = {
                    "caps": parts[11].lower(),
                    "fpr": None,
                    "algo": parts[3] if len(parts) > 3 else "",
                    "bits": bits,
                    "curve": parts[16].lower() if len(parts) > 16 else "",
                }
                subkeys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur["fpr"] is None:
                cur["fpr"] = parts[9]

        try:
            algo_to_check, curve_to_check = _select_import_algo(
                algo, curve, subkeys, self.selected_subkeys
            )
        except ValueError as e:
            self.run_screen(
                LargeIconStatusScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(BackStackView)

        logger.info(
            "SmartPGP import selection: primary algo=%s bits=%s curve=%s -> %s/%s",
            algo,
            primary_bits,
            curve,
            algo_to_check,
            curve_to_check,
        )

        if algo_to_check not in ("1", "2", "3"):
            curve_map = {
                "nistp256": "p256",
                "nistp384": "p384",
                "nistp521": "p521",
                "brainpoolp256r1": "bp256",
                "brainpoolp384r1": "bp384",
                "brainpoolp512r1": "bp512",
            }
            cmd_suffix = curve_map.get(curve_to_check)
            if not cmd_suffix:
                logger.error(
                    "Unsupported SmartPGP key curve '%s' for algo %s", curve_to_check, algo_to_check
                )
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Error",
                    status_headline=None,
                    text="Unsupported key type",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(BackStackView)
            try:
                from seedsigner.helpers.smartpgp.highlevel import (
                    CardConnectionContext,
                    AdminPINFailed,
                )

                try:
                    ctx = CardConnectionContext()
                    ctx.admin_pin = admin_pin
                    logger.info(
                        "Verifying SmartPGP admin PIN before switching to %s (%s)",
                        cmd_suffix,
                        curve_to_check,
                    )
                    ctx.connect()
                    ctx.verify_admin_pin()
                except AdminPINFailed:
                    logger.warning("SmartPGP card rejected admin PIN during verification")
                    self._stop_loading_screen()
                    self._clear_cached_admin_pin()
                    self.run_screen(
                        LargeIconStatusScreen,
                        title="Error",
                        status_headline=None,
                        text="Incorrect admin PIN",
                        show_back_button=False,
                        button_data=[ButtonOption("Continue")],
                    )
                    return Destination(BackStackView)
                except Exception as e:
                    logger.exception("SmartPGP admin PIN pre-check failed: %s", e)
                    self._stop_loading_screen()
                    self.run_screen(
                        LargeIconStatusScreen,
                        title="Error",
                        status_headline=None,
                        text="Failed to set card key type",
                        show_back_button=False,
                        button_data=[ButtonOption("Continue")],
                    )
                    return Destination(BackStackView)

                logger.info(
                    "Attempting to switch SmartPGP card to %s (%s)", cmd_suffix, curve_to_check
                )
                getattr(ctx, f"cmd_switch_{cmd_suffix}")()
            except AdminPINFailed:
                logger.warning("SmartPGP card rejected admin PIN during switch")
                self._stop_loading_screen()
                self._clear_cached_admin_pin()
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Error",
                    status_headline=None,
                    text="Incorrect admin PIN",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(BackStackView)
            except Exception as e:
                logger.exception("SmartPGP switch failed: %s", e)
                self._stop_loading_screen()
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to set card key type",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(BackStackView)
            run(["gpgconf", "--reload", "scdaemon"])

        slot_map = {"s": "1", "e": "2", "a": "3"}
        cmds = ["toggle\n"]
        if isinstance(self.selected_subkeys, dict):
            for flag in ("s", "e", "a"):
                fpr = self.selected_subkeys.get(flag)
                if not fpr:
                    continue
                idx = next(
                    (i for i, sk in enumerate(subkeys, start=1) if sk["fpr"] == fpr),
                    None,
                )
                if idx is None:
                    continue
                cmds.append(f"key {idx}\nkeytocard\n{slot_map[flag]}\nkey {idx}\n")
        else:
            used_slots = set()
            sign_idx = next(
                (
                    i
                    for i, sk in enumerate(subkeys, start=1)
                    if "s" in sk["caps"]
                    and (not self.selected_subkeys or sk["fpr"] in self.selected_subkeys)
                ),
                None,
            )
            if sign_idx is not None:
                cmds.append(f"key {sign_idx}\nkeytocard\n1\nkey {sign_idx}\n")
                used_slots.add("1")
            elif "s" in primary_caps:
                cmds.extend(["keytocard\n", "y\n", "1\n"])
                used_slots.add("1")
            for idx, sk in enumerate(subkeys, start=1):
                caps = sk["caps"]
                if idx == sign_idx:
                    continue
                if self.selected_subkeys and sk["fpr"] not in self.selected_subkeys:
                    continue
                slot = next(
                    (
                        slot_map[c]
                        for c in "sea"
                        if c in caps and slot_map[c] not in used_slots
                    ),
                    None,
                )
                if slot:
                    cmds.append(f"key {idx}\nkeytocard\n{slot}\nkey {idx}\n")
                    used_slots.add(slot)
        cmds.append("quit\ny\n")
        edit_commands = "".join(cmds)
        logger.info("GPG edit commands:\n%s", edit_commands)

        self.loading_screen = LoadingScreenThread(
            text="Importing key to card\n\n\n(May take a while)",
        )
        self.loading_screen.start()

        result = run(
            [
                "gpg",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                admin_pin,
                "--command-fd",
                "0",
                "--status-fd",
                "1",
                "--expert",
                "--edit-key",
                self.fingerprint,
            ],
            input=edit_commands,
            capture_output=True,
            text=True,
        )
        logger.info("GPG edit-key import exited with code %s", result.returncode)
        if result.stderr:
            logger.debug("GPG stderr: %s", result.stderr)
        if result.returncode != 0:
            from seedsigner.helpers.smartpgp_import import (
                import_keys_with_smartpgp,
                SmartPGPAdminPinError,
            )

            logger.info(
                "Falling back to SmartPGP importer for %s", self.fingerprint
            )
            try:
                if import_keys_with_smartpgp(
                    self.fingerprint, admin_pin, self.selected_subkeys
                ):
                    self._stop_loading_screen()
                    self.run_screen(
                        LargeIconStatusScreen,
                        title="Success",
                        status_headline=None,
                        text="Key imported to card",
                        show_back_button=False,
                        button_data=[ButtonOption("Continue")],
                    )
                    return Destination(ToolsGPGMenuView)
            except SmartPGPAdminPinError:
                self._stop_loading_screen()
                self._clear_cached_admin_pin()
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Error",
                    status_headline=None,
                    text="Incorrect admin PIN",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(BackStackView)
            except Exception as e:
                logger.exception("SmartPGP fallback failed: %s", e)
            self._stop_loading_screen()
            self.run_screen(
                LargeIconStatusScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(BackStackView)

        self._stop_loading_screen()
        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Key imported to card",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )

        return Destination(ToolsGPGMenuView)

class ToolsTextQRTextEntryView(View):
    def __init__(self, textToEncode: str = ""):
        super().__init__()
        self.textToEncode = textToEncode


    def run(self):
        ret_dict = ToolsTextQRTextEntryScreen(textToEncode=self.textToEncode, title=_("Text to Encode")).display()

        try:
            import re
            self.textToEncode = bytes(
                re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                encoding="raw_unicode_escape"
            ).decode("unicode_escape")

        except UnicodeDecodeError:
            self.textToEncode = ret_dict["textToEncode"]

        if "is_back_button" in ret_dict:
            if len(self.textToEncode) > 0:
                return Destination(
                    ToolsTextQRTextEntryExitDialogView,
                    view_args=dict(text=self.textToEncode),
                    skip_current_view=True
                )
            else:
                return Destination(BackStackView)

        else:
            return Destination(
                ToolsTextQRReviewTextView,
                view_args=dict(text=self.textToEncode),
                skip_current_view=True
            )



class ToolsTextQRTextEntryExitDialogView(View):
    EDIT = ButtonOption("Edit text")
    DISCARD = ButtonOption("Discard text", button_label_color="red")

    def __init__(self, text: str):
        super().__init__()
        self.text = text


    def run(self):
        button_data = [self.EDIT, self.DISCARD]
        
        selected_menu_num = self.run_screen(
            WarningScreen,
            title=_("Discard text?"),
            status_headline=None,
            text=f"Your current text entry will be erased",
            show_back_button=False,
            button_data=button_data
        )

        if button_data[selected_menu_num] == self.EDIT:
            return Destination(
                ToolsTextQRTextEntryView,
                view_args=dict(textToEncode=self.text),
                skip_current_view=True
            )

        elif button_data[selected_menu_num] == self.DISCARD:
            return Destination(BackStackView)


class ToolsTextQRReviewTextView(View):
    def __init__(self, text: str):
        super().__init__()
        self.text = text


    def run(self):
        ENCODE = ButtonOption("Generate QR code")
        EDIT = ButtonOption("Edit text")

        button_data = [ENCODE, EDIT]

        selected_menu_num = self.run_screen(
            ToolsTextQRReviewTextScreen,
            textToEncode=self.text,
            title=_("Text to Encode"),
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == ENCODE:
            from seedsigner.helpers.qr import QR
            num_modules = QR().qrsize(data=self.text)
            if num_modules <= 33:
                return Destination(
                    ToolsTextQRTranscribeModePromptView,
                    view_args=dict(text=self.text, num_modules=num_modules)
                )
            else:
                return Destination(
                    ToolsTextQRFullScreenModeView,
                    view_args=dict(text=self.text)
                )

        elif button_data[selected_menu_num] == EDIT:
            return Destination(
                ToolsTextQRTextEntryView,
                view_args=dict(textToEncode=self.text),
                skip_current_view=True
            )



def _text_qr_done_destination(return_to_home: bool = False) -> Destination:
    if return_to_home:
        return Destination(ToolsMenuView, clear_history=True)
    return Destination(ToolsTextQRView, clear_history=True)


class ToolsTextQRTranscribeModePromptView(View):
    def __init__(self, text: str, num_modules: int, return_to_home: bool = False):
        super().__init__()
        self.text = text
        self.num_modules = num_modules
        self.return_to_home = return_to_home


    def run(self):
        TRANSCRIBE = ButtonOption("Transcribe mode")
        FULLSCREEN = ButtonOption("FullScreen mode")

        button_data = [TRANSCRIBE, FULLSCREEN]

        selected_menu_num = self.run_screen(
            ToolsTextQRTranscribeModePromptScreen,
            title=_("Transcribe Mode ?"),
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == TRANSCRIBE:
            return Destination(
                ToolsTextQRTranscribeModeView,
                view_args=dict(text=self.text, num_modules=self.num_modules, return_to_home=self.return_to_home)
            )

        elif button_data[selected_menu_num] == FULLSCREEN:
            return Destination(
                ToolsTextQRFullScreenModeView,
                view_args=dict(text=self.text, return_to_home=self.return_to_home)
            )



class ToolsTextQRTranscribeModeView(View):
    def __init__(self, text: str, num_modules: int, return_to_home: bool = False):
        super().__init__()
        self.text = text
        self.num_modules = num_modules
        self.return_to_home = return_to_home


    def run(self):
        ret = ToolsTranscribeTextQRWholeQRScreen(
            qr_data=self.text,
            num_modules=self.num_modules
        ).display()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        else:
            return Destination(
                ToolsTranscribeTextQRZoomedInView,
                view_args=dict(text=self.text, num_modules=self.num_modules, return_to_home=self.return_to_home)
            )



class ToolsTextQRFullScreenModeView(View):
    def __init__(self, text: str, return_to_home: bool = False):
        super().__init__()
        self.text = text
        self.return_to_home = return_to_home

    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        encoder_args = dict(data=self.text)
        e = GenericStaticQrEncoder(**encoder_args)
        QRDisplayScreen(qr_encoder=e).display()
        return _text_qr_done_destination(self.return_to_home)



class ToolsTranscribeTextQRZoomedInView(View):
    def __init__(self, text: str, num_modules: int, return_to_home: bool = False):
        super().__init__()
        self.text = text
        self.num_modules = num_modules
        self.return_to_home = return_to_home


    def run(self):

        ToolsTranscribeTextQRZoomedInScreen(
            qr_data=self.text,
            num_modules=self.num_modules
        ).display()

        return Destination(
            ToolsTranscribeTextQRConfirmQRPromptView,
            view_args=dict(text=self.text, return_to_home=self.return_to_home)
        )



class ToolsTranscribeTextQRConfirmQRPromptView(View):
    def __init__(self, text: str, return_to_home: bool = False):
        super().__init__()
        self.text = text
        self.return_to_home = return_to_home


    def run(self):
        SCAN = ButtonOption("Confirm text QR code")
        DONE = ButtonOption("Done")
        button_data = [SCAN, DONE]

        selected_menu_option = ToolsTranscribeTextQRConfirmQRPromptScreen(
            title=_("Confirm Text QR ?"),
            button_data=button_data
        ).display()

        if selected_menu_option == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_option] == SCAN:
            return Destination(ToolsTranscribeTextQRConfirmScanView, view_args=dict(text=self.text, return_to_home=self.return_to_home))

        elif button_data[selected_menu_option] == DONE:
            return _text_qr_done_destination(self.return_to_home)



class ToolsTranscribeTextQRConfirmScanView(View):
    def __init__(self, text: str, return_to_home: bool = False):
        super().__init__()
        self.text = text
        self.return_to_home = return_to_home


    def run(self):
        decoder = DecodeQR(is_text=True)
        ScanScreen(
            instructions_text=_("Scan text QR code"),
            decoder=decoder
        ).display()

        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)

        if decoder.is_complete:
            if decoder.get_text() != self.text:
                DireWarningScreen(
                    title=_("Confirm Text QR Code"),
                    status_headline=_("Error!"),
                    text=_("Your transcribed text QR code does not match your original text!"),
                    show_back_button=False,
                    button_data=[ButtonOption("Review text QR code")],
                ).display()

                return Destination(BackStackView)
            
            else:
                LargeIconStatusScreen(
                    title=_("Confirm Text QR Code"),
                    status_headline=_("Success!"),
                    text=_("Your transcribed text QR code successfully scanned and yielded the same text."),
                    show_back_button=False,
                    button_data=[ButtonOption("OK")],
                ).display()

                return _text_qr_done_destination(self.return_to_home)

        else:
            DireWarningScreen(
                title=_("Confirm Text QR"),
                status_headline=_("Error!"),
                text=_("Your transcribed text QR code could not be read!"),
                show_back_button=False,
                button_data=[ButtonOption("Review text QR code")],
            ).display()

            return Destination(BackStackView)



class ToolsTextQRScanQRCodeView(View):
    def run(self):

        decoder = DecodeQR(is_text=True)
        ScanScreen(decoder=decoder, instructions_text=_("Scan text QR code")).display()

        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)

        if decoder.is_complete:
            return Destination(
                ToolsTextQRReviewTextView2,
                view_args=dict(text=decoder.get_text()),
                skip_current_view=True
            )

        elif decoder.is_nonUTF8:
            DireWarningScreen(
                title=_("Error!"),
                show_back_button=False,
                status_headline="Invalid Text QR Code",
                text=f"Non UTF-8 data detected."
            ).display()
            return Destination(BackStackView)

        else:
            return Destination(BackStackView)



class ToolsTextQRReviewTextView2(View):
    def __init__(self, text: str):
        super().__init__()
        self.text = text


    def run(self):
        EDIT = ButtonOption("Edit & Generate QR code")
        DONE = ButtonOption("Done")

        button_data = [EDIT, DONE]

        selected_menu_num = self.run_screen(
            ToolsTextQRReviewTextScreen,
            textToEncode=self.text,
            title=_("Decoded Text"),
            button_data=button_data,
            show_back_button=False,
        )

        if button_data[selected_menu_num] == EDIT:
            return Destination(
                ToolsTextQRTextEntryView,
                view_args=dict(textToEncode=self.text)
            )

        elif button_data[selected_menu_num] == DONE:
            return Destination(BackStackView)


"""****************************************************************************
    Password Generator Views
****************************************************************************"""
class ToolsPasswordGeneratorTypeView(View):
    def run(self):
        options = [
            (ButtonOption("Custom"), PASSWORD_TYPE_RANDOM),
            (ButtonOption("Diceware-EFF Short"), PASSWORD_TYPE_DICEWARE_EFF_SHORT),
            (ButtonOption("Diceware-EFF Long"), PASSWORD_TYPE_DICEWARE_EFF_LONG),
            (ButtonOption("Diceware-BIP39"), PASSWORD_TYPE_DICEWARE_BIP39),
            (ButtonOption("Base85"), PASSWORD_TYPE_BASE85),
            (ButtonOption("Base64"), PASSWORD_TYPE_BASE64),
            (ButtonOption("Hex"), PASSWORD_TYPE_HEX),
            (ButtonOption("Dice Rolls"), PASSWORD_TYPE_DICE_ROLLS),
        ]
        button_data = [button for button, _ in options]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Password Type"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        password_type = options[selected_menu_num][1]
        if password_type == PASSWORD_TYPE_DICE_ROLLS:
            return Destination(
                ToolsPasswordDiceRollCountView,
                view_args=dict(
                    password_type=password_type,
                    strength_bits=64,
                    entropy_source=None,
                ),
            )
        return Destination(
            ToolsPasswordStrengthView,
            view_args=dict(password_type=password_type),
        )


class ToolsPasswordStrengthView(View):
    def __init__(self, password_type: str):
        super().__init__()
        self.password_type = password_type

    def run(self):
        options = [
            ButtonOption("64 bits", return_data=64),
            ButtonOption("128 bits", return_data=128),
            ButtonOption("256 bits", return_data=256),
        ]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Password Strength"),
            is_button_text_centered=False,
            selected_button=1,
            button_data=options,
        )
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        strength_bits = options[selected_menu_num].return_data
        if self.password_type == PASSWORD_TYPE_RANDOM:
            return Destination(
                ToolsPasswordRandomOptionsView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=strength_bits,
                ),
            )
        return Destination(
            ToolsPasswordEntropySourceView,
            view_args=dict(
                password_type=self.password_type,
                strength_bits=strength_bits,
            ),
        )


class ToolsPasswordRandomOptionsView(View):
    def __init__(self, password_type: str, strength_bits: int):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits

    def _prompt_choice(self, title: str) -> bool | None:
        yes = ButtonOption("Yes")
        no = ButtonOption("No")
        selected = self.run_screen(
            ButtonListScreen,
            title=title,
            is_button_text_centered=True,
            button_data=[yes, no],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return None
        return selected == 0

    def run(self):
        while True:
            lower = self._prompt_choice("Lowercase?")
            if lower is None:
                return Destination(BackStackView)
            upper = self._prompt_choice("Uppercase?")
            if upper is None:
                return Destination(BackStackView)
            digits = self._prompt_choice("Numbers?")
            if digits is None:
                return Destination(BackStackView)
            special = self._prompt_choice("Specials?")
            if special is None:
                return Destination(BackStackView)
            random_options = {
                "lower": lower,
                "upper": upper,
                "digits": digits,
                "special": special,
            }
            if any(random_options.values()):
                return Destination(
                    ToolsPasswordEntropySourceView,
                    view_args=dict(
                        password_type=self.password_type,
                        strength_bits=self.strength_bits,
                        random_options=random_options,
                    ),
                )
            self.run_screen(
                WarningScreen,
                title=_("Select Options"),
                status_headline=None,
                text=_("Choose at least one character set."),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )


class ToolsPasswordEntropySourceView(View):
    def __init__(
        self,
        password_type: str,
        strength_bits: int,
        random_options: dict | None = None,
        dice_sides: int | None = None,
        roll_count: int | None = None,
    ):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.random_options = random_options or {}
        self.dice_sides = dice_sides
        self.roll_count = roll_count

    def _hardware_rng_available(self) -> bool:
        if self.controller.hardware_rng_is_healthy:
            return True
        reason = self.controller.hardware_rng_failure_reason or _("System RNG health check failed.")
        self.run_screen(
            WarningScreen,
            title=_("System RNG Error"),
            status_headline=None,
            text=reason,
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )
        return False

    def run(self):
        _clear_password_entropy_cache(self.controller)

        camera = ButtonOption("Camera")
        dice = ButtonOption("Dice")
        hardware_rng = ButtonOption("System RNG")
        bip85 = ButtonOption("BIP85")

        if self.password_type == PASSWORD_TYPE_DICE_ROLLS:
            button_data = [camera, hardware_rng, bip85]
        else:
            button_data = [camera, dice, hardware_rng, bip85]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Entropy Source"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        selected = button_data[selected_menu_num]
        if selected == bip85 and not _bip85_supported_password_type(self.password_type):
            self.run_screen(
                WarningScreen,
                title=_("Not Supported"),
                status_headline=None,
                text=_("BIP85 supports Diceware, Dice Rolls, Hex, Base64, and Base85."),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(
                ToolsPasswordEntropySourceView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                ),
            )

        if selected == camera:
            if self.password_type in {
                PASSWORD_TYPE_DICEWARE_EFF_SHORT,
                PASSWORD_TYPE_DICEWARE_EFF_LONG,
                PASSWORD_TYPE_DICEWARE_BIP39,
            }:
                return Destination(
                    ToolsImageEntropyLivePreviewView,
                    view_args=dict(
                        next_view=ToolsPasswordWordSeparatorView,
                        next_view_args=dict(
                            password_type=self.password_type,
                            strength_bits=self.strength_bits,
                            random_options=self.random_options,
                            entropy_source=PASSWORD_ENTROPY_CAMERA,
                        ),
                    ),
                )
            return Destination(
                ToolsImageEntropyLivePreviewView,
                view_args=dict(
                    next_view=ToolsPasswordGenerateView,
                    next_view_args=dict(
                        password_type=self.password_type,
                        strength_bits=self.strength_bits,
                        entropy_source=PASSWORD_ENTROPY_CAMERA,
                        random_options=self.random_options,
                        roll_count=self.roll_count,
                        dice_sides=self.dice_sides or 6,
                    ),
                ),
            )

        if selected == dice:
            if self.password_type == PASSWORD_TYPE_DICE_ROLLS and self.dice_sides is not None and self.roll_count is not None:
                return Destination(
                    ToolsPasswordDiceEntryView,
                    view_args=dict(
                        password_type=self.password_type,
                        random_options=self.random_options,
                        strength_bits=self.strength_bits,
                        total_rolls=self.roll_count,
                        word_count=None,
                        entropy_source=PASSWORD_ENTROPY_DICE,
                        dice_sides=self.dice_sides,
                    ),
                    skip_current_view=True,
                )
            return Destination(
                ToolsPasswordDiceRollCountView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    entropy_source=PASSWORD_ENTROPY_DICE,
                ),
            )

        if selected == hardware_rng:
            if not self._hardware_rng_available():
                return Destination(BackStackView)
            if _is_diceware_password_type(getattr(self, "password_type", None)):
                return Destination(
                    ToolsPasswordHardwareRngEntropyView,
                    view_args=dict(
                        password_type=self.password_type,
                        strength_bits=self.strength_bits,
                        random_options=self.random_options,
                    ),
                )
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=self.strength_bits,
                    entropy_source=PASSWORD_ENTROPY_HARDWARE_RNG,
                    random_options=self.random_options,
                    roll_count=self.roll_count,
                    dice_sides=self.dice_sides or 6,
                ),
            )

        return Destination(
            ToolsPasswordBIP85GenerateView,
            view_args=dict(
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                random_options=self.random_options,
                dice_sides=self.dice_sides,
                roll_count=self.roll_count,
            ),
        )


class ToolsPasswordHardwareRngEntropyView(View):
    def __init__(
        self,
        password_type: str,
        strength_bits: int,
        random_options: dict | None = None,
    ):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.random_options = random_options or {}

    def run(self):
        if not self.controller.hardware_rng_is_healthy:
            self.run_screen(
                WarningScreen,
                title=_("System RNG Error"),
                status_headline=None,
                text=self.controller.hardware_rng_failure_reason or _("System RNG health check failed."),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        entropy_bytes = _derive_hardware_rng_entropy_bytes()
        _cache_password_entropy(
            self.controller,
            password_type=self.password_type,
            strength_bits=self.strength_bits,
            entropy_source=PASSWORD_ENTROPY_HARDWARE_RNG,
            word_count=_diceware_word_count(self.password_type, self.strength_bits),
            roll_data=None,
            entropy_bytes=entropy_bytes,
        )
        return Destination(
            ToolsPasswordWordSeparatorView,
            view_args=dict(
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                random_options=self.random_options,
                entropy_source=PASSWORD_ENTROPY_HARDWARE_RNG,
            ),
            skip_current_view=True,
        )


class ToolsPasswordWordSeparatorView(View):
    def __init__(
        self,
        password_type: str,
        strength_bits: int,
        random_options: dict | None = None,
        entropy_source: str | None = PASSWORD_ENTROPY_DICE,
    ):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.random_options = random_options or {}
        self.entropy_source = entropy_source

    def run(self):
        cached_entropy = _get_password_entropy_cache(self.controller)

        separator_options = [
            (ButtonOption("None"), PASSWORD_WORD_SEPARATOR_NONE),
            (ButtonOption("Capitalise"), PASSWORD_WORD_SEPARATOR_CAPITALISE),
            (ButtonOption("Space"), PASSWORD_WORD_SEPARATOR_SPACE),
            (ButtonOption("."), PASSWORD_WORD_SEPARATOR_DOT),
        ]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Separator"),
            is_button_text_centered=False,
            selected_button=1,
            button_data=[button for button, _ in separator_options],
        )
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            _clear_password_entropy_cache(self.controller)
            return Destination(
                ToolsPasswordEntropySourceView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                ),
                skip_current_view=True,
            )

        word_separator = separator_options[selected_menu_num][1]

        if cached_entropy and cached_entropy.get("password_type") == self.password_type \
            and cached_entropy.get("strength_bits") == self.strength_bits \
            and cached_entropy.get("entropy_source") == self.entropy_source:
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=self.entropy_source,
                    random_options=self.random_options,
                    strength_bits=self.strength_bits,
                    word_count=cached_entropy.get("word_count"),
                    word_separator=word_separator,
                    roll_data=cached_entropy.get("roll_data"),
                    entropy_bytes_override=cached_entropy.get("entropy_bytes"),
                ),
                skip_current_view=True,
            )

        return Destination(
            ToolsPasswordDiceRollCountView,
            view_args=dict(
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                random_options=self.random_options,
                word_separator=word_separator,
                entropy_source=self.entropy_source,
            ),
        )


class ToolsPasswordDiceRollCountView(View):
    def __init__(
        self,
        password_type: str,
        strength_bits: int,
        random_options: dict | None = None,
        word_separator: str = PASSWORD_WORD_SEPARATOR_NONE,
        entropy_source: str = PASSWORD_ENTROPY_DICE,
    ):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.random_options = random_options or {}
        self.word_separator = word_separator
        self.entropy_source = entropy_source

    def _prompt_dice_sides(self) -> int | None:
        side_options = [
            ButtonOption("6 sides", return_data=6),
            ButtonOption("10 sides", return_data=10),
            ButtonOption("20 sides", return_data=20),
        ]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Dice Sides"),
            is_button_text_centered=False,
            selected_button=0,
            button_data=side_options,
        )
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return None
        return int(side_options[selected_menu_num].return_data)

    def _prompt_roll_count(self) -> int | None:
        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title=_("Number of Rolls")).display()
        if ret == RET_CODE__BACK_BUTTON:
            return None
        if not ret:
            return 0
        return int(ret)

    def run(self):
        if self.password_type in {
            PASSWORD_TYPE_DICEWARE_EFF_SHORT,
            PASSWORD_TYPE_DICEWARE_EFF_LONG,
            PASSWORD_TYPE_DICEWARE_BIP39,
        } and self.entropy_source in {
            PASSWORD_ENTROPY_CAMERA,
            PASSWORD_ENTROPY_HARDWARE_RNG,
        }:
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=self.entropy_source,
                    random_options=self.random_options,
                    strength_bits=self.strength_bits,
                    word_count=_diceware_word_count(self.password_type, self.strength_bits),
                    word_separator=self.word_separator,
                ),
                skip_current_view=True,
            )

        if self.password_type == PASSWORD_TYPE_DICE_ROLLS:
            dice_sides = self._prompt_dice_sides()
            if dice_sides is None:
                return Destination(BackStackView)

            roll_count = self._prompt_roll_count()
            if roll_count is None:
                return Destination(BackStackView)
            if roll_count < 1:
                self.run_screen(
                    WarningScreen,
                    title=_("Invalid Input"),
                    status_headline=None,
                    text=_("Number of rolls must be at least 1."),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            if self.entropy_source is None:
                return Destination(
                    ToolsPasswordEntropySourceView,
                    view_args=dict(
                        password_type=self.password_type,
                        strength_bits=self.strength_bits,
                        random_options=self.random_options,
                        dice_sides=dice_sides,
                        roll_count=roll_count,
                    ),
                    skip_current_view=True,
                )

            if self.entropy_source == PASSWORD_ENTROPY_DICE:
                return Destination(
                    ToolsPasswordDiceEntryView,
                    view_args=dict(
                        password_type=self.password_type,
                        random_options=self.random_options,
                        strength_bits=self.strength_bits,
                        total_rolls=roll_count,
                        word_count=None,
                        word_separator=self.word_separator,
                        entropy_source=PASSWORD_ENTROPY_DICE,
                        dice_sides=dice_sides,
                    ),
                    skip_current_view=True,
                )

            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=self.entropy_source,
                    random_options=self.random_options,
                    strength_bits=self.strength_bits,
                    roll_count=roll_count,
                    word_count=None,
                    word_separator=self.word_separator,
                    dice_sides=dice_sides,
                ),
                skip_current_view=True,
            )

        word_count = None
        if self.password_type in {
            PASSWORD_TYPE_DICEWARE_EFF_SHORT,
            PASSWORD_TYPE_DICEWARE_EFF_LONG,
            PASSWORD_TYPE_DICEWARE_BIP39,
        }:
            word_count = _diceware_word_count(self.password_type, self.strength_bits)
            if self.password_type == PASSWORD_TYPE_DICEWARE_EFF_SHORT:
                total_rolls = word_count * 4
            elif self.password_type == PASSWORD_TYPE_DICEWARE_EFF_LONG:
                total_rolls = word_count * 5
            else:
                total_rolls = max(1, math.ceil(word_count * 11 / math.log2(6)))
        else:
            total_rolls = _dice_rolls_for_strength(self.strength_bits)
        return Destination(
            ToolsPasswordDiceEntryView,
            view_args=dict(
                password_type=self.password_type,
                random_options=self.random_options,
                strength_bits=self.strength_bits,
                total_rolls=total_rolls,
                word_count=word_count,
                word_separator=self.word_separator,
                entropy_source=self.entropy_source,
            ),
            skip_current_view=True,
        )


class ToolsPasswordDiceEntryView(View):
    def __init__(
        self,
        password_type: str,
        strength_bits: int,
        total_rolls: int,
        random_options: dict | None = None,
        word_count: int | None = None,
        word_separator: str = PASSWORD_WORD_SEPARATOR_NONE,
        entropy_source: str = PASSWORD_ENTROPY_DICE,
        dice_sides: int = 6,
    ):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.total_rolls = total_rolls
        self.random_options = random_options or {}
        self.word_count = word_count
        self.word_separator = word_separator
        self.entropy_source = entropy_source
        self.dice_sides = dice_sides

    def run(self):
        ret = ToolsDiceEntropyEntryScreen(
            return_after_n_chars=self.total_rolls,
        ).display()

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

        if _is_diceware_password_type(getattr(self, "password_type", None)):
            _cache_password_entropy(
                self.controller,
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                entropy_source=self.entropy_source,
                word_count=self.word_count,
                roll_data=ret,
                entropy_bytes=None,
            )
            return Destination(
                ToolsPasswordWordSeparatorView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    entropy_source=self.entropy_source,
                ),
                skip_current_view=True,
            )

        return Destination(
            ToolsPasswordGenerateView,
            view_args=dict(
                password_type=self.password_type,
                entropy_source=self.entropy_source,
                random_options=self.random_options,
                strength_bits=self.strength_bits,
                roll_data=ret,
                roll_count=self.total_rolls,
                word_count=self.word_count,
                word_separator=self.word_separator,
                dice_sides=self.dice_sides,
            ),
        )


class ToolsPasswordGenerateView(View):
    def __init__(
        self,
        password_type: str,
        entropy_source: str,
        strength_bits: int,
        random_options: dict | None = None,
        roll_data: bytes | str | None = None,
        roll_count: int | None = None,
        word_count: int | None = None,
        word_separator: str = PASSWORD_WORD_SEPARATOR_NONE,
        entropy_bytes_override: bytes | None = None,
        dice_sides: int = 6,
    ):
        super().__init__()
        self.password_type = password_type
        self.entropy_source = entropy_source
        self.strength_bits = strength_bits
        self.random_options = random_options or {}
        self.roll_data = roll_data
        self.roll_count = roll_count
        self.word_count = word_count
        self.word_separator = word_separator
        self.entropy_bytes_override = entropy_bytes_override
        self.dice_sides = dice_sides

    def _bip39_words_from_entropy(self, seed: bytes, word_count: int) -> list[str]:
        wordlist = Seed.get_wordlist(
            self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
        )
        total_bits = word_count * 11
        num_bytes = math.ceil(total_bits / 8)
        data = password_generation.shake_stream(seed).read(num_bytes)
        bit_string = "".join(f"{byte:08b}" for byte in data)
        words = []
        for i in range(word_count):
            idx = int(bit_string[i * 11 : (i + 1) * 11], 2)
            words.append(wordlist[idx])
        return words

    def _dice_length_for_charset(self, alphabet_size: int) -> int:
        return _strength_to_length(self.strength_bits, alphabet_size)

    def _diceware_rolls_from_entropy(self, entropy_seed: bytes) -> str:
        if self.word_count is None:
            raise ValueError("Word count is required for diceware")
        if self.password_type == PASSWORD_TYPE_DICEWARE_EFF_SHORT:
            sides = 6
            rolls_per_word = 4
        elif self.password_type == PASSWORD_TYPE_DICEWARE_EFF_LONG:
            sides = 6
            rolls_per_word = 5
        else:
            sides = 2048
            rolls_per_word = 1
        roll_count = self.word_count * rolls_per_word
        return password_generation.dice_rolls_from_seed(entropy_seed, sides, roll_count)

    def _diceware_words(self, entropy_bytes: bytes | None = None) -> list[str]:
        if self.password_type == PASSWORD_TYPE_DICEWARE_BIP39 and self.entropy_source in {
            PASSWORD_ENTROPY_CAMERA,
            PASSWORD_ENTROPY_HARDWARE_RNG,
            PASSWORD_ENTROPY_BIP85,
        }:
            if self.word_count is None:
                raise ValueError("Word count is required for words")
            return self._bip39_words_from_entropy(entropy_bytes, self.word_count)

        roll_data = self.roll_data
        if self.password_type in {PASSWORD_TYPE_DICEWARE_EFF_SHORT, PASSWORD_TYPE_DICEWARE_EFF_LONG} and self.entropy_source in {
            PASSWORD_ENTROPY_CAMERA,
            PASSWORD_ENTROPY_HARDWARE_RNG,
            PASSWORD_ENTROPY_BIP85,
        }:
            if entropy_bytes is None:
                raise ValueError("Entropy is required for diceware")
            roll_data = self._diceware_rolls_from_entropy(entropy_bytes)

        if self.password_type == PASSWORD_TYPE_DICEWARE_EFF_SHORT:
            return diceware.diceware_words_from_rolls(
                roll_data, diceware.eff_short_map(), 4
            )
        if self.password_type == PASSWORD_TYPE_DICEWARE_EFF_LONG:
            return diceware.diceware_words_from_rolls(
                roll_data, diceware.eff_large_map(), 5
            )

        word_count = self.word_count
        if word_count is None:
            entropy_bits = password_generation.dice_roll_entropy_bits(self.roll_count)
            word_count = int(entropy_bits // 11)
        if word_count < 1:
            raise ValueError("Not enough entropy for words")
        entropy_seed = entropy_bytes if entropy_bytes is not None else mnemonic_generation._hash_dice_rolls(roll_data)
        return self._bip39_words_from_entropy(entropy_seed, word_count)

    def run(self):
        entropy_bytes_override = getattr(self, "entropy_bytes_override", None)
        if entropy_bytes_override is not None:
            entropy_bytes = entropy_bytes_override
        elif self.entropy_source == PASSWORD_ENTROPY_CAMERA:
            entropy_bytes = _derive_camera_entropy_bytes(
                self.controller.image_entropy_preview_frames,
                self.controller.image_entropy_final_image,
            )
            self.controller.image_entropy_preview_frames = None
            self.controller.image_entropy_final_image = None
            if entropy_bytes is None:
                self.run_screen(
                    ErrorScreen,
                    title=_("Poor Entropy"),
                    status_headline=None,
                    text=_("Camera entropy didn't appear random enough. Please try again."),
                )
                return Destination(BackStackView)
        elif self.entropy_source == PASSWORD_ENTROPY_HARDWARE_RNG:
            if not self.controller.hardware_rng_is_healthy:
                self.run_screen(
                    WarningScreen,
                    title=_("System RNG Error"),
                    status_headline=None,
                    text=self.controller.hardware_rng_failure_reason or _("System RNG health check failed."),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            entropy_bytes = _derive_hardware_rng_entropy_bytes()
        else:
            entropy_bytes = self.roll_data if self.entropy_source == PASSWORD_ENTROPY_BIP85 else mnemonic_generation._hash_dice_rolls(self.roll_data)

        if self.password_type in {
            PASSWORD_TYPE_DICEWARE_EFF_SHORT,
            PASSWORD_TYPE_DICEWARE_EFF_LONG,
            PASSWORD_TYPE_DICEWARE_BIP39,
        }:
            _cache_password_entropy(
                self.controller,
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                entropy_source=self.entropy_source,
                word_count=self.word_count,
                roll_data=self.roll_data if self.entropy_source == PASSWORD_ENTROPY_DICE else None,
                entropy_bytes=entropy_bytes if self.entropy_source != PASSWORD_ENTROPY_DICE else None,
            )

        try:
            if self.password_type in {
                PASSWORD_TYPE_DICEWARE_EFF_SHORT,
                PASSWORD_TYPE_DICEWARE_EFF_LONG,
                PASSWORD_TYPE_DICEWARE_BIP39,
            }:
                words = self._diceware_words(entropy_bytes=entropy_bytes)
                password = _format_word_password(words, self.word_separator)
            elif self.password_type == PASSWORD_TYPE_RANDOM:
                charset = _random_charset(self.random_options)
                if self.entropy_source == PASSWORD_ENTROPY_DICE:
                    length = self._dice_length_for_charset(len(charset))
                else:
                    length = _strength_to_length(self.strength_bits, len(charset))
                password = password_generation.random_string_from_charset(
                    entropy_bytes, length, charset
                )
            elif self.password_type == PASSWORD_TYPE_DICE_ROLLS:
                if self.roll_count is None:
                    raise ValueError("Roll count is required")
                rolls = password_generation.dice_roll_values_from_seed(
                    entropy_bytes,
                    sides=self.dice_sides,
                    roll_count=self.roll_count,
                    base=0,
                )
                password = ",".join(str(roll) for roll in rolls)
            elif self.password_type == PASSWORD_TYPE_HEX:
                if self.entropy_source == PASSWORD_ENTROPY_DICE:
                    length = self._dice_length_for_charset(16)
                    password = password_generation.hex_password_from_seed(entropy_bytes, length)
                elif self.entropy_source == PASSWORD_ENTROPY_BIP85:
                    num_bytes = _strength_to_length(self.strength_bits, 256)
                    password = password_generation.bip85_hex_password(entropy_bytes, num_bytes)
                else:
                    length = _strength_to_length(self.strength_bits, 16)
                    password = password_generation.hex_password_from_seed(entropy_bytes, length)
            elif self.password_type == PASSWORD_TYPE_BASE64:
                if self.entropy_source == PASSWORD_ENTROPY_DICE:
                    length = self._dice_length_for_charset(64)
                    password = password_generation.base64_password_from_seed(
                        entropy_bytes, length
                    )
                elif self.entropy_source == PASSWORD_ENTROPY_BIP85:
                    length = _strength_to_length(self.strength_bits, 64)
                    password = password_generation.bip85_base64_password(
                        entropy_bytes, length
                    )
                else:
                    length = _strength_to_length(self.strength_bits, 64)
                    password = password_generation.base64_password_from_seed(
                        entropy_bytes, length
                    )
            else:
                if self.entropy_source == PASSWORD_ENTROPY_DICE:
                    length = self._dice_length_for_charset(85)
                    password = password_generation.base85_password_from_seed(
                        entropy_bytes, length
                    )
                elif self.entropy_source == PASSWORD_ENTROPY_BIP85:
                    length = _strength_to_length(self.strength_bits, 85)
                    password = password_generation.bip85_base85_password(
                        entropy_bytes, length
                    )
                else:
                    length = _strength_to_length(self.strength_bits, 85)
                    password = password_generation.base85_password_from_seed(
                        entropy_bytes, length
                    )
        except ValueError as exc:
            self.run_screen(
                WarningScreen,
                title=_("Invalid Input"),
                status_headline=None,
                text=str(exc),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        return Destination(
            ToolsPasswordReviewView,
            view_args=dict(
                password=password,
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                random_options=self.random_options,
                entropy_source=self.entropy_source,
            ),
            skip_current_view=True,
        )


class ToolsPasswordBIP85GenerateView(View):
    def __init__(
        self,
        password_type: str,
        strength_bits: int,
        random_options: dict | None = None,
        dice_sides: int | None = None,
        roll_count: int | None = None,
    ):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.random_options = random_options or {}
        self.dice_sides = dice_sides
        self.roll_count = roll_count

    def _prompt_dice_sides(self) -> int | None:
        side_options = [
            ButtonOption("6 sides", return_data=6),
            ButtonOption("10 sides", return_data=10),
            ButtonOption("20 sides", return_data=20),
        ]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Dice Sides"),
            is_button_text_centered=False,
            selected_button=0,
            button_data=side_options,
        )
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return None
        return int(side_options[selected_menu_num].return_data)

    def _prompt_roll_count(self) -> int | None:
        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title=_("Number of Rolls")).display()
        if ret == RET_CODE__BACK_BUTTON:
            return None
        if not ret:
            return 0
        return int(ret)

    def run(self):
        from embit import bip85

        if len(self.controller.storage.seeds) == 0:
            self.run_screen(
                WarningScreen,
                title=_("WARNING"),
                status_headline=None,
                text=_("Load a seed before using BIP85."),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        if len(self.controller.storage.seeds) > 1:
            seed_buttons = []
            for seed in self.controller.storage.seeds:
                button_str = seed.get_fingerprint(
                    self.settings.get_value(SettingsConstants.SETTING__NETWORK)
                )
                seed_buttons.append(
                    ButtonOption(
                        button_str,
                        SeedSignerIconConstants.FINGERPRINT,
                        icon_color="blue",
                    )
                )
            selected_seed = self.run_screen(
                seed_screens.SeedSelectSeedScreen,
                title=_("Select Seed"),
                text=_("Choose seed for BIP85"),
                is_button_text_centered=False,
                button_data=seed_buttons,
            )
            if selected_seed == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            seed = self.controller.get_seed(selected_seed)
        else:
            seed = self.controller.get_seed(0)

        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title=_("BIP85 Index")).display()
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        index = int(ret)

        root = seed.get_root(self.settings.get_value(SettingsConstants.SETTING__NETWORK))

        if self.password_type in {
            PASSWORD_TYPE_DICEWARE_EFF_SHORT,
            PASSWORD_TYPE_DICEWARE_EFF_LONG,
            PASSWORD_TYPE_DICEWARE_BIP39,
        }:
            if self.password_type == PASSWORD_TYPE_DICEWARE_BIP39:
                sides = 2048
                rolls = _diceware_word_count(self.password_type, self.strength_bits)
            elif self.password_type == PASSWORD_TYPE_DICEWARE_EFF_SHORT:
                sides = 6
                rolls = _diceware_word_count(self.password_type, self.strength_bits) * 4
            else:
                sides = 6
                rolls = _diceware_word_count(self.password_type, self.strength_bits) * 5
            entropy = bip85.derive_entropy(root, BIP85_APP_DICE, [sides, rolls, index])
            _cache_password_entropy(
                self.controller,
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                entropy_source=PASSWORD_ENTROPY_BIP85,
                word_count=_diceware_word_count(self.password_type, self.strength_bits),
                roll_data=None,
                entropy_bytes=entropy,
            )
            return Destination(
                ToolsPasswordWordSeparatorView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    entropy_source=PASSWORD_ENTROPY_BIP85,
                ),
            )


        if self.password_type == PASSWORD_TYPE_DICE_ROLLS:
            sides = getattr(self, "dice_sides", None)
            if sides is None:
                sides = self._prompt_dice_sides()
                if sides is None:
                    return Destination(BackStackView)
            rolls = getattr(self, "roll_count", None)
            if rolls is None:
                rolls = self._prompt_roll_count()
                if rolls is None:
                    return Destination(BackStackView)
            if rolls < 1:
                self.run_screen(
                    WarningScreen,
                    title=_("Invalid Input"),
                    status_headline=None,
                    text=_("Number of rolls must be at least 1."),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            entropy = bip85.derive_entropy(root, BIP85_APP_DICE, [sides, rolls, index])
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=PASSWORD_ENTROPY_BIP85,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    roll_data=entropy,
                    roll_count=rolls,
                    dice_sides=sides,
                ),
            )

        if self.password_type == PASSWORD_TYPE_HEX:
            num_bytes = _strength_to_length(self.strength_bits, 256)
            if num_bytes < 16 or num_bytes > 64:
                self.run_screen(
                    WarningScreen,
                    title=_("Invalid Length"),
                    status_headline=None,
                    text=_("BIP85 Hex supports 128 or 256 bits."),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            entropy = bip85.derive_entropy(root, BIP85_APP_HEX, [num_bytes, index])
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=PASSWORD_ENTROPY_BIP85,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    roll_data=entropy,
                ),
            )
        elif self.password_type == PASSWORD_TYPE_BASE64:
            length = _strength_to_length(self.strength_bits, 64)
            if length < 20 or length > 86:
                self.run_screen(
                    WarningScreen,
                    title=_("Invalid Length"),
                    status_headline=None,
                    text=_("BIP85 Base64 needs 120+ bits."),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            entropy = bip85.derive_entropy(root, BIP85_APP_BASE64, [length, index])
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=PASSWORD_ENTROPY_BIP85,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    roll_data=entropy,
                ),
            )
        else:
            length = _strength_to_length(self.strength_bits, 85)
            if length < 10 or length > 80:
                self.run_screen(
                    WarningScreen,
                    title=_("Invalid Length"),
                    status_headline=None,
                    text=_("BIP85 Base85 needs 64-512 bits."),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            entropy = bip85.derive_entropy(root, BIP85_APP_BASE85, [length, index])
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=PASSWORD_ENTROPY_BIP85,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    roll_data=entropy,
                ),
            )


def _save_password_to_seedkeeper(view: View, password: str) -> bool:
    from seedsigner.gui.screens.screen import LoadingScreenThread

    label = seed_screens.SeedAddPassphraseScreen(title=_("Password Name")).display()
    if "is_back_button" in label:
        return False

    Satochip_Connector = seedkeeper_utils.init_satochip(
        view, init_card_filter=["seedkeeper"]
    )
    if not Satochip_Connector:
        return False

    header = Satochip_Connector.make_header(
        "Password",
        "Plaintext export allowed",
        label["passphrase"],
    )
    secret_text_list = list(password.encode("utf-8"))
    secret_list = [len(secret_text_list)] + secret_text_list
    secret_dic = {"header": header, "secret_list": secret_list}

    try:
        fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
            Satochip_Connector, secret_dic
        )
    except Exception as e:
        view.run_screen(
            WarningScreen,
            title=_("Error"),
            status_headline=None,
            text=str(e),
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )
        return False

    if not fits:
        view.run_screen(
            WarningScreen,
            title=_("Not Enough Space"),
            status_headline=None,
            text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )
        return False

    try:
        loading = LoadingScreenThread(text=_("Saving Secret\n\n\n\n\n\n"))
        loading.start()
        Satochip_Connector.seedkeeper_import_secret(secret_dic)
        loading.stop()
        view.run_screen(
            LargeIconStatusScreen,
            title=_("Success"),
            status_headline=None,
            text=_("Password saved to Seedkeeper"),
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        return True
    except UnexpectedSW12Error as e:
        loading.stop()
        if e.sw1 == 0x6A and e.sw2 == 0x84:
            err_text = _("Not enough space on Seedkeeper for password")
        else:
            err_text = format_sw_error(e.sw1, e.sw2)
        view.run_screen(
            WarningScreen,
            title=_("Error"),
            status_headline=None,
            text=err_text,
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )
    except Exception as e:
        logger.info(e)
        loading.stop()
        view.run_screen(
            WarningScreen,
            title=_("Failed"),
            status_headline=None,
            text=_("Password save failed"),
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )
    return False


class ToolsPasswordReviewView(View):
    def __init__(
        self,
        password: str,
        password_type: str | None = None,
        strength_bits: int | None = None,
        random_options: dict | None = None,
        entropy_source: str | None = None,
    ):
        super().__init__()
        self.password = password
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.random_options = random_options or {}
        self.entropy_source = entropy_source

    def run(self):
        while True:
            edit = ButtonOption("Edit")
            next_button = ButtonOption("Next")
            button_data = [edit, next_button]
            selected_menu_num = self.run_screen(
                ToolsTextQRReviewTextScreen,
                textToEncode=self.password,
                title=_("Password"),
                button_data=button_data,
                show_back_button=True,
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                if _is_diceware_password_type(getattr(self, "password_type", None)):
                    return Destination(
                        ToolsPasswordWordSeparatorView,
                        view_args=dict(
                            password_type=self.password_type,
                            strength_bits=self.strength_bits,
                            random_options=self.random_options,
                            entropy_source=self.entropy_source,
                        ),
                        skip_current_view=True,
                    )
                return Destination(BackStackView)

            if button_data[selected_menu_num] == edit:
                ret_dict = ToolsTextQRTextEntryScreen(
                    textToEncode=self.password,
                    title=_("Password"),
                ).display()
                if "is_back_button" in ret_dict:
                    continue
                self.password = ret_dict["textToEncode"]
                continue

            return Destination(
                ToolsPasswordSaveView,
                view_args=dict(password=self.password),
            )


class ToolsPasswordSaveView(View):
    def __init__(self, password: str):
        super().__init__()
        self.password = password

    def run(self):
        show_qr = ButtonOption("Show as QR")
        seedkeeper = ButtonOption("Save to Seedkeeper")
        button_data = [show_qr, seedkeeper]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Save Password"),
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == show_qr:
            from seedsigner.helpers.qr import QR
            num_modules = QR().qrsize(data=self.password)
            if num_modules <= 33:
                return Destination(
                    ToolsTextQRTranscribeModePromptView,
                    view_args=dict(text=self.password, num_modules=num_modules, return_to_home=True),
                )
            return Destination(
                ToolsTextQRFullScreenModeView,
                view_args=dict(text=self.password, return_to_home=True),
            )

        if _save_password_to_seedkeeper(self, self.password):
            return Destination(MainMenuView)
        return Destination(BackStackView)
