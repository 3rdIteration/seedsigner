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
from seedsigner.gui.screens.tools_screens import (
    ToolsAddressExplorerAddressTypeScreen, ToolsTextQRTextEntryScreen, ToolsTextQRReviewTextScreen,
    ToolsTextQRTranscribeModePromptScreen, ToolsTranscribeTextQRWholeQRScreen, ToolsTranscribeTextQRZoomedInScreen,
    ToolsTranscribeTextQRConfirmQRPromptScreen, ToolsCommonFilterScreen, ToolsNetworkInfoScreen,
    ToolsBatteryCalibrationIntroScreen, ToolsBatteryCalibrationStartScreen, ToolsBatteryCalibrationRunningScreen)
from seedsigner.helpers import embit_utils
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

from seedsigner.hardware.microsd import MicroSD
from seedsigner.hardware.rng_monitor import HardwareRngHealthMonitor
from seedsigner.helpers import seedkeeper_utils
from seedsigner.gui.screens import seed_screens
logger = logging.getLogger(__name__)

# Minimum RSA key size in bits to avoid weak keys.
MIN_RSA_KEY_BITS = 2048

from pysatochip.JCconstants import SEEDKEEPER_DIC_TYPE, SEEDKEEPER_DIC_ORIGIN, SEEDKEEPER_DIC_EXPORT_RIGHTS, BIP39_WORDLIST_DIC
from pysatochip.CardConnector import CardConnector, UnexpectedSW12Error
from binascii import unhexlify, hexlify

class ToolsMenuView(View):
    SEEDS = ButtonOption("Seeds", SeedSignerIconConstants.SEEDS)
    ADDRESS_EXPLORER = ButtonOption("Address Explorer")
    VERIFY_ADDRESS = ButtonOption("Verify address")
    TEXTQRCODE = ButtonOption("Text QR Code")
    MICROSD = ButtonOption("MicroSD Tools")
    BATTERY_CALIBRATION = ButtonOption("Battery Calibration")
    CLEAR_DESCRIPTOR = ButtonOption("Clear Multisig Descriptor")
    NETWORK_INFO = ButtonOption("Network Info")
    STEALTH_BOOT = ButtonOption("Stealth boot")

    def run(self):
        button_data = [self.SEEDS]

        from seedsigner.hardware.battery_hat import BatteryHat
        battery_calibration_button = self.BATTERY_CALIBRATION if BatteryHat.get_instance().is_enabled() else None

        button_data.extend([
            self.ADDRESS_EXPLORER,
            self.VERIFY_ADDRESS,
            self.TEXTQRCODE,
            self.MICROSD,
            battery_calibration_button,
            self.NETWORK_INFO if Path("/usr/bin/network-info").is_file() else None,
            self.CLEAR_DESCRIPTOR,
            self.STEALTH_BOOT,
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

        elif button_data[selected_menu_num] == self.SEEDS:
            from seedsigner.views.seed_views import SeedsMenuView
            return Destination(SeedsMenuView)

        elif button_data[selected_menu_num] == self.ADDRESS_EXPLORER:
            return Destination(ToolsAddressExplorerSelectSourceView)

        elif button_data[selected_menu_num] == self.VERIFY_ADDRESS:
            from seedsigner.views.scan_views import ScanAddressView
            return Destination(ScanAddressView)

        elif button_data[selected_menu_num] == self.TEXTQRCODE:
            return Destination(ToolsTextQRView)

        elif button_data[selected_menu_num] == self.MICROSD:
            return Destination(ToolsMicroSDMenuView)

        elif button_data[selected_menu_num] == self.BATTERY_CALIBRATION:
            return Destination(ToolsBatteryCalibrationView)

        elif button_data[selected_menu_num] == self.NETWORK_INFO:
            return Destination(ToolsNetworkInfoView)

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

        elif button_data[selected_menu_num] == self.STEALTH_BOOT:
            from seedsigner.views.stealth_views import ToolsStealthBootView
            return Destination(ToolsStealthBootView)



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
                from seedsigner.views.view import CardsMenuView
                return Destination(CardsMenuView)

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

class ToolsSeedkeeperSetupView(View):
    """First-use wizard for an uninstantiated SeedKeeper applet.

    Reuses ``seedkeeper_utils.init_satochip`` whose ``setup_done==False``
    branch prompts for a new PIN and runs ``card_setup``. After a
    successful setup the user lands back on ``ToolsSeedkeeperView``
    which re-probes and shows the regular menu.
    """

    def run(self):
        connector = seedkeeper_utils.init_satochip(
            self, init_card_filter=["seedkeeper"], require_pin=True,
        )
        if connector is None:
            return Destination(BackStackView)
        return Destination(ToolsSeedkeeperView, skip_current_view=True)


class ToolsSatochipSetupView(View):
    """First-use wizard for an uninstantiated Satochip applet."""

    def run(self):
        connector = seedkeeper_utils.init_satochip(
            self, init_card_filter=["satochip"], require_pin=True,
        )
        if connector is None:
            return Destination(BackStackView)
        return Destination(ToolsSatochipView, skip_current_view=True)


class ToolsSeedkeeperView(View):
    VIEW_FREE_SPACE = ButtonOption("View Free Space")
    VIEW_SECRETS = ButtonOption("View Secrets on Card")
    IMPORT_PASSWORD = ButtonOption("Save Password to Card")
    DELETE_SECRET = ButtonOption("Delete Secret from Card")
    LOAD_DESCRIPTOR = ButtonOption("Load MultiSig Descriptor")
    SAVE_DESCRIPTOR = ButtonOption("Save MultiSig Descriptor")
    CLONE_SECRETS = ButtonOption("Clone Card Secrets")
    ADVANCED = ButtonOption("Advanced")

    def run(self):
        from seedsigner.helpers.card_probe import run_card_gate
        gate = run_card_gate(
            self, "seedkeeper", title="SeedKeeper",
            setup_view=ToolsSeedkeeperSetupView,
        )
        if gate is not None:
            return gate

        button_data = [
            self.VIEW_SECRETS,
            self.IMPORT_PASSWORD,
            self.DELETE_SECRET,
            self.LOAD_DESCRIPTOR,
            self.SAVE_DESCRIPTOR,
            self.CLONE_SECRETS,
            self.VIEW_FREE_SPACE,
            self.ADVANCED,
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

        elif button_data[selected_menu_num] == self.ADVANCED:
            return Destination(ToolsSeedkeeperAdvancedView)


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
        # SECRET_TYPE_PASSWORD layout per Seedkeeper-Applet Specifications.md:
        #   [pw_size(1b) | pw | login_size(1b) | login | url_size(1b) | url]
        # login and url are optional, but their length bytes are NOT. Omitting
        # them makes the iOS Satochip app's parser read past the buffer and
        # crash on reveal (and on the secret-list refresh that the app does
        # after change-PIN, which is why change-PIN also appears to crash).
        secret_list = (
            [len(secret_text_list)] + secret_text_list
            + [0x00]  # login_size = 0
            + [0x00]  # url_size   = 0
        )
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
        from seedsigner.helpers.card_probe import run_card_gate
        gate = run_card_gate(
            self, "satochip", title="Satochip",
            setup_view=ToolsSatochipSetupView,
        )
        if gate is not None:
            return gate

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
    UNINSTALL = ButtonOption("Uninstall applet")

    def run(self):
        button_data = [self.ENABLE_2FA, self.UNINSTALL]
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

        elif button_data[selected_menu_num] == self.UNINSTALL:
            return Destination(ToolsSatochipUninstallAppletView)


class ToolsSatochipUninstallAppletView(View):
    """Delete the Satochip applet via gp.jar (requires default ISD keys)."""

    def run(self):
        from seedsigner.gui.screens.screen import (
            DireWarningScreen, LargeIconStatusScreen, WarningScreen,
        )
        ret = self.run_screen(
            DireWarningScreen,
            title="Uninstall",
            status_headline=None,
            text="Delete the Satochip applet?\nUser data will be lost.",
            show_back_button=True,
            button_data=[ButtonOption("Delete")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        result = seedkeeper_utils.run_globalplatform(
            self, f"--delete 5361746f43686970 -force",
            "Deleting Satochip applet", None,
        )
        if result is None:
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Uninstall",
            status_headline=None,
            text="Satochip applet removed.",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        from seedsigner.views.view import CardsMenuView
        return Destination(CardsMenuView, skip_current_view=True)


class ToolsSeedkeeperAdvancedView(View):
    UNINSTALL = ButtonOption("Uninstall applet")

    def run(self):
        button_data = [self.UNINSTALL]
        selected = self.run_screen(
            ButtonListScreen,
            title="SeedKeeper Advanced",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        if button_data[selected] == self.UNINSTALL:
            return Destination(ToolsSeedkeeperUninstallAppletView)


class ToolsSeedkeeperUninstallAppletView(View):
    """Delete the SeedKeeper applet via gp.jar (requires default ISD keys)."""

    def run(self):
        from seedsigner.gui.screens.screen import (
            DireWarningScreen, LargeIconStatusScreen,
        )
        ret = self.run_screen(
            DireWarningScreen,
            title="Uninstall",
            status_headline=None,
            text="Delete the SeedKeeper applet?\nUser data will be lost.",
            show_back_button=True,
            button_data=[ButtonOption("Delete")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        result = seedkeeper_utils.run_globalplatform(
            self, f"--delete 536565644b6565706572 -force",
            "Deleting SeedKeeper applet", None,
        )
        if result is None:
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Uninstall",
            status_headline=None,
            text="SeedKeeper applet removed.",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        from seedsigner.views.view import CardsMenuView
        return Destination(CardsMenuView, skip_current_view=True)

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
                logger.exception("Satochip Import Failed: %s", e)
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
        elif "keycard" in applet_file.lower():
            # Status Keycard 3.2 cap contains Keycard + NDEF + Cash applets
            # in a single package. gp.jar accepts --install only once per
            # invocation, so we --load the package first, then create the
            # signing instance. We deliberately skip the NDEF and Cash
            # instances:
            #   - NDEF (`D2760000850101`) is the ISO/IEC 14443 Type-4
            #     NDEF AID, which iOS Core NFC auto-SELECTs on tap. Its
            #     presence breaks the Seedkeeper iOS app's reveal flow
            #     when SeedKeeper coexists on the same card.
            #   - Cash (Status Pay) is unused by every tool that targets
            #     this device.
            # Instance AID for the signing applet (A0000008040001010101)
            # is what keycard_views.py SELECTs by default — keep exact.
            cap_path = f"{cap_dir}/{applet_file}"
            keycard_steps = [
                (f"--load {cap_path}", "Loading Keycard package"),
                (
                    "--package A0000008040001 --applet A000000804000101 "
                    "--create A0000008040001010101",
                    "Creating Keycard instance",
                ),
            ]
            installed_applets = "ok"
            for command, label in keycard_steps:
                # successtext=None suppresses the per-step success screen.
                # Failure screens are still shown by run_globalplatform and
                # the loop bails out via None.
                step_result = seedkeeper_utils.run_globalplatform(
                    self, command, label, None,
                )
                if step_result is None:
                    installed_applets = None
                    break
            if installed_applets:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text="Keycard Applets Installed",
                    show_back_button=False,
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
                    if package_info[1] == 'A0000008040001': package_info[3]="(|Keycard|)"

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

        except UnicodeError:
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
