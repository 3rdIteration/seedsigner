"""****************************************************************************
    Smartcard Views
****************************************************************************"""
import base64
import binascii
from binascii import hexlify, unhexlify
import hashlib
import hmac
import json
import logging
import os
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from embit.bip32 import HDKey
from embit.descriptor import Descriptor
from gettext import gettext as _

from seedsigner.gui.components import (
    FontAwesomeIconConstants,
    GUIConstants,
    SeedSignerIconConstants,
)
from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    DireWarningScreen,
    LargeIconStatusScreen,
    WarningScreen,
    ErrorScreen,
    seed_screens,
)
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.hardware.microsd import MicroSD
from seedsigner.helpers import embit_utils, seedkeeper_utils
from seedsigner.helpers.satochip_signer import (
    _call_with_timeout,
    _get_extended_key,
    format_path_string,
    normalize_signature_der,
)
from seedsigner.models.seed import InvalidSeedException, Seed, XprvSeed
from seedsigner.models.settings_definition import SettingsConstants

try:
    from pysatochip import satochip
    from pysatochip.exception import UnexpectedSW12Error
    from pysatochip.satochip_protocol_helper import format_sw_error
except ImportError:
    pass

from .view import View, Destination, BackStackView, MainMenuView
from .seed_views import (
    AccountNumberView,
    MultisigWalletDescriptorView,
    SeedElectrumMnemonicStartView,
    SeedExportXpubVerifyAddressView,
    SeedFinalizeView,
    SeedSlip39MnemonicStartView,
)

logger = logging.getLogger(__name__)


class ToolsSmartcardMenuView(View):
    COMMON = ButtonOption("Common Functions")
    SATOCHIP = ButtonOption("Satochip Functions")
    KEYCARD = ButtonOption("KeyCard Functions")
    SEEDKEEPER = ButtonOption("SeedKeeper Functions")
    SPECTER_DIY = ButtonOption("Specter-DIY Functions")
    Satochip_DIY = ButtonOption("DIY Tools")

    def run(self):
        button_data = [self.COMMON, self.SEEDKEEPER]
        satochip_enabled = (
            self.settings.get_value(SettingsConstants.SETTING__SATOCHIP_SUPPORT)
            == SettingsConstants.OPTION__ENABLED
        )
        keycard_enabled = (
            self.settings.get_value(SettingsConstants.SETTING__KEYCARD_SUPPORT)
            == SettingsConstants.OPTION__ENABLED
        )
        specter_diy_enabled = (
            self.settings.get_value(SettingsConstants.SETTING__SPECTER_DIY_SUPPORT)
            == SettingsConstants.OPTION__ENABLED
        )
        if satochip_enabled:
            button_data.append(self.SATOCHIP)
        if keycard_enabled:
            button_data.append(self.KEYCARD)
        if specter_diy_enabled:
            button_data.append(self.SPECTER_DIY)
        button_data.append(self.Satochip_DIY)

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Smartcard Tools",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.COMMON:
            self.controller.smartcard_backend_preference = None
            return Destination(ToolsCommonView)
        
        elif button_data[selected_menu_num] == self.SATOCHIP:
            self.controller.smartcard_backend_preference = None
            return Destination(ToolsSatochipView)

        elif button_data[selected_menu_num] == self.KEYCARD:
            self.controller.smartcard_backend_preference = "keycard"
            return Destination(ToolsKeycardView)
        
        elif button_data[selected_menu_num] == self.SEEDKEEPER:
            self.controller.smartcard_backend_preference = None
            return Destination(ToolsSeedkeeperView)

        elif button_data[selected_menu_num] == self.SPECTER_DIY:
            return Destination(ToolsSpecterDIYView)

        elif button_data[selected_menu_num] == self.Satochip_DIY:
            self.controller.smartcard_backend_preference = None
            return Destination(ToolsSatochipDIYView)

class ToolsCommonView(View):
    FILTER = ButtonOption("Device Filter")
    INFO = ButtonOption("Card Info")
    GENUINE = ButtonOption("Genuine Check")
    CHANGE_PIN = ButtonOption("Change PIN")
    CHANGE_LABEL = ButtonOption("Change Label")
    CHANGE_NFC = ButtonOption("Change NFC Policy")
    CONFIGURE_NDEF = ButtonOption("Configure NDEF")
    FACTORY_RESET = ButtonOption("Factory Reset Card")

    def run(self):

        button_data = [
            self.FILTER,
            self.INFO,
            self.GENUINE,
            self.CHANGE_PIN,
            self.CHANGE_LABEL,
            self.CHANGE_NFC,
            self.CONFIGURE_NDEF,
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

        elif button_data[selected_menu_num] == self.CONFIGURE_NDEF:
            return Destination(ToolsCommonNdefView)

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

class ToolsCommonNdefView(View):
    VIEW_NDEF = ButtonOption("View NDEF")
    SET_SEEDKEEPER_NDEF = ButtonOption("Use Seedkeeper App Link")
    CLEAR_NDEF = ButtonOption("Clear NDEF")
    SET_CUSTOM_NDEF = ButtonOption("Set Custom NDEF")
    SAVE_NDEF_TO_SEEDKEEPER = ButtonOption("Save NDEF to SeedKeeper")
    LOAD_NDEF_FROM_SEEDKEEPER = ButtonOption("Load NDEF from SeedKeeper")

    _SEEDKEEPER_APP_NDEF_HEX = (
        "0029d40f17616e64726f69642e636f6d3a706b676f72672e7361746f636869702e736565646b6565706572"
    )
    _EMPTY_NDEF_HEX = "0003D00000"

    # NDEF Record type options
    RECORD_TYPE_TEXT = ButtonOption("Text Record")
    RECORD_TYPE_URI = ButtonOption("URI Record")
    RECORD_TYPE_ANDROID_APP = ButtonOption("Android App Launch")
    RECORD_TYPE_HEX = ButtonOption("Custom (HEX)")

    @staticmethod
    def _extract_ndef_payload(ndef_bytes: bytes) -> bytes:
        """Accept either raw payload or 2-byte length-prefixed NDEF and return payload bytes."""
        if not ndef_bytes:
            return b""

        if len(ndef_bytes) >= 2:
            declared_len = (ndef_bytes[0] << 8) | ndef_bytes[1]
            if declared_len == len(ndef_bytes) - 2:
                return ndef_bytes[2:]

        return ndef_bytes

    @staticmethod
    def _to_card_ndef_bytes(ndef_bytes: bytes) -> bytes:
        """Card APDU expects NDEF bytes with a 2-byte big-endian length prefix."""
        payload = ToolsCommonNdefView._extract_ndef_payload(ndef_bytes)
        return len(payload).to_bytes(2, "big") + payload

    def run(self):
        allowed = ["seedkeeper", "satodime"]
        card_filter = self.controller.tools_common_card_filter or allowed
        card_filter = [c for c in card_filter if c in allowed]

        connector = seedkeeper_utils.init_satochip(
            self,
            init_card_filter=card_filter,
            require_pin=True,
        )
        if not connector:
            return Destination(BackStackView)

        while True:
            button_data = [
                self.VIEW_NDEF,
                self.SET_SEEDKEEPER_NDEF,
                self.CLEAR_NDEF,
                self.SET_CUSTOM_NDEF,
                self.SAVE_NDEF_TO_SEEDKEEPER,
                self.LOAD_NDEF_FROM_SEEDKEEPER,
            ]

            selected_menu_num = self.run_screen(
                ButtonListScreen,
                title="NDEF Configuration",
                is_button_text_centered=False,
                button_data=button_data,
                show_back_button=True,
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            selected = button_data[selected_menu_num]

            if selected == self.VIEW_NDEF:
                return self._view_ndef(connector)

            if selected == self.SET_SEEDKEEPER_NDEF:
                return self._set_ndef(connector, self._SEEDKEEPER_APP_NDEF_HEX, "Seedkeeper app link set")

            if selected == self.CLEAR_NDEF:
                return self._set_ndef(connector, self._EMPTY_NDEF_HEX, "NDEF cleared")

            if selected == self.SET_CUSTOM_NDEF:
                return self._set_custom_ndef_flow(connector)
            
            if selected == self.SAVE_NDEF_TO_SEEDKEEPER:
                return self._save_ndef_to_seedkeeper(connector)
            
            if selected == self.LOAD_NDEF_FROM_SEEDKEEPER:
                return self._load_ndef_from_seedkeeper(connector)

    def _set_custom_ndef_flow(self, connector):
        """Handle the flow for setting custom NDEF records."""
        while True:
            button_data = [
                self.RECORD_TYPE_TEXT,
                self.RECORD_TYPE_URI,
                self.RECORD_TYPE_ANDROID_APP,
                self.RECORD_TYPE_HEX,
            ]

            selected_menu_num = self.run_screen(
                ButtonListScreen,
                title="NDEF Record Type",
                is_button_text_centered=False,
                button_data=button_data,
                show_back_button=True,
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(self.__class__)

            selected = button_data[selected_menu_num]

            if selected == self.RECORD_TYPE_TEXT:
                return self._create_text_record(connector)

            elif selected == self.RECORD_TYPE_URI:
                return self._create_uri_record(connector)

            elif selected == self.RECORD_TYPE_ANDROID_APP:
                return self._create_android_app_record(connector)

            elif selected == self.RECORD_TYPE_HEX:
                return self._set_ndef_hex(connector)

    def _create_text_record(self, connector):
        """Create and set a Text NDEF record."""
        # Get text content
        ret = seed_screens.SeedAddPassphraseScreen(title="Enter Text").display()
        if isinstance(ret, dict) and "is_back_button" in ret:
            return Destination(self.__class__)

        text = ret.get("passphrase", "").strip()
        if not text:
            self.run_screen(
                WarningScreen,
                title="Invalid Text",
                status_headline=None,
                text="Text cannot be empty",
                show_back_button=True,
            )
            return Destination(self.__class__)

        # Get language (optional, default to "en")
        ret = seed_screens.SeedAddPassphraseScreen(title="Language Code (e.g., en)").display()
        if isinstance(ret, dict) and "is_back_button" in ret:
            language = "en"
        else:
            language = ret.get("passphrase", "en").strip() or "en"

        try:
            ndef_bytes = ndef_helper.create_text_record(text, language)
            ndef_hex = ndef_bytes.hex().upper()
            return self._set_ndef(connector, ndef_hex, "Text record set")
        except Exception as e:
            self.run_screen(
                WarningScreen,
                title="Failed to Create Record",
                status_headline=None,
                text=str(e)[:100],
                show_back_button=True,
            )
            return Destination(self.__class__)

    def _create_uri_record(self, connector):
        """Create and set a URI NDEF record."""
        # Get URI
        ret = seed_screens.SeedAddPassphraseScreen(title="Enter URI").display()
        if isinstance(ret, dict) and "is_back_button" in ret:
            return Destination(self.__class__)

        uri = ret.get("passphrase", "").strip()
        if not uri:
            self.run_screen(
                WarningScreen,
                title="Invalid URI",
                status_headline=None,
                text="URI cannot be empty",
                show_back_button=True,
            )
            return Destination(self.__class__)

        try:
            ndef_bytes = ndef_helper.create_uri_record(uri)
            ndef_hex = ndef_bytes.hex().upper()
            return self._set_ndef(connector, ndef_hex, "URI record set")
        except Exception as e:
            self.run_screen(
                WarningScreen,
                title="Failed to Create Record",
                status_headline=None,
                text=str(e)[:100],
                show_back_button=True,
            )
            return Destination(self.__class__)

    def _create_android_app_record(self, connector):
        """Create and set an Android App Launch NDEF record."""
        # Get package name
        ret = seed_screens.SeedAddPassphraseScreen(title="Android Package Name").display()
        if isinstance(ret, dict) and "is_back_button" in ret:
            return Destination(self.__class__)

        package_name = ret.get("passphrase", "").strip()
        if not package_name:
            self.run_screen(
                WarningScreen,
                title="Invalid Package",
                status_headline=None,
                text="Package name cannot be empty",
                show_back_button=True,
            )
            return Destination(self.__class__)

        try:
            ndef_bytes = ndef_helper.create_android_app_record(package_name)
            ndef_hex = ndef_bytes.hex().upper()
            return self._set_ndef(connector, ndef_hex, "Android app record set")
        except Exception as e:
            self.run_screen(
                WarningScreen,
                title="Failed to Create Record",
                status_headline=None,
                text=str(e)[:100],
                show_back_button=True,
            )
            return Destination(self.__class__)

    def _set_ndef_hex(self, connector):
        """Set NDEF from raw hex input."""
        ret = seed_screens.SeedAddPassphraseScreen(title="NDEF HEX").display()
        if isinstance(ret, dict) and "is_back_button" in ret:
            return Destination(self.__class__)

        ndef_hex = ret.get("passphrase", "").strip()
        if not ndef_hex:
            self.run_screen(
                WarningScreen,
                title="Invalid NDEF",
                status_headline=None,
                text="Hex value required",
                show_back_button=True,
            )
            return Destination(self.__class__)

        return self._set_ndef(connector, ndef_hex, "NDEF updated")

    def _view_ndef(self, connector):
        try:
            card_type = getattr(connector, "card_type", "Unknown")
            
            # Auto-detect card type and use appropriate method
            if card_type == "Satodime":
                # Use card_get_ndef_v2 for Satodime to get policy data
                result = connector.card_get_ndef_v2()
                if len(result) == 5:
                    _, sw1, sw2, ndef_bytes, policy_data = result
                else:
                    _, sw1, sw2, ndef_bytes = result[:4]
                    policy_data = None
            else:
                # Use card_get_ndef for Seedkeeper
                _, sw1, sw2, ndef_bytes = connector.card_get_ndef()
                policy_data = None

            if sw1 != 0x90 or sw2 != 0x00:
                raise RuntimeError(format_sw_error(sw1, sw2))

            ndef_payload = self._extract_ndef_payload(ndef_bytes)
            ndef_hex = ndef_payload.hex().upper() if ndef_payload else "(empty)"

            # First screen: raw hex with explicit decode action.
            selected = self.run_screen(
                ToolsTextQRReviewTextScreen,
                title="NDEF HEX",
                textToEncode=ndef_hex,
                max_lines=6,
                visible_space=False,
                button_data=[ButtonOption("Decode NDEF")],
                show_back_button=True,
            )

            if selected == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            try:
                decoded_display = ndef_helper.decode_ndef_for_display(ndef_payload)
            except Exception:
                decoded_display = "Unable to decode NDEF payload"

            if policy_data and card_type == "Satodime":
                decoded_display = decoded_display + "\n\nPolicy:\n" + str(policy_data)

            # Second screen: decoded record details only.
            self.run_screen(
                LargeIconStatusScreen,
                title="Decoded NDEF",
                status_headline=None,
                text=decoded_display,
                status_icon_size=0,
                show_back_button=True,
            )
            return Destination(BackStackView)
        except Exception as e:
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=str(e)[:100],
                show_back_button=True,
            )
            return Destination(BackStackView)

    def _set_ndef(self, connector, ndef_hex: str, success_text: str):
        try:
            normalized = ndef_hex.replace(" ", "")
            ndef_bytes = bytes.fromhex(normalized)
        except ValueError:
            self.run_screen(
                WarningScreen,
                title="Invalid NDEF",
                status_headline=None,
                text="Invalid hex string",
                show_back_button=True,
            )
            return Destination(BackStackView)

        try:
            card_ndef_bytes = self._to_card_ndef_bytes(ndef_bytes)
            _, sw1, sw2 = connector.card_set_ndef(card_ndef_bytes)
            if sw1 != 0x90 or sw2 != 0x00:
                raise RuntimeError(format_sw_error(sw1, sw2))

            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=success_text,
                show_back_button=False,
            )
            return Destination(MainMenuView)
        except Exception as e:
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=str(e)[:100],
                show_back_button=True,
            )
            return Destination(BackStackView)

    def _save_ndef_to_seedkeeper(self, connector):
        """Save current NDEF from card to SeedKeeper."""
        from seedsigner.gui.screens.screen import LoadingScreenThread
        
        loading_screen = None
        try:
            # First, get the current NDEF from the card
            card_type = getattr(connector, "card_type", "Unknown")
            
            # Check that we're connected to Seedkeeper
            if card_type != "Seedkeeper":
                self.run_screen(
                    WarningScreen,
                    title="Wrong Card",
                    status_headline=None,
                    text="SeedKeeper required to save NDEF",
                    show_back_button=True,
                )
                return Destination(self.__class__)
            
            if card_type == "Satodime":
                result = connector.card_get_ndef_v2()
                if len(result) == 5:
                    _, sw1, sw2, ndef_bytes, policy_data = result
                else:
                    _, sw1, sw2, ndef_bytes = result[:4]
            else:
                _, sw1, sw2, ndef_bytes = connector.card_get_ndef()
            
            if sw1 != 0x90 or sw2 != 0x00:
                raise RuntimeError(format_sw_error(sw1, sw2))
            
            if not ndef_bytes or len(ndef_bytes) == 0:
                self.run_screen(
                    WarningScreen,
                    title="Empty NDEF",
                    status_headline=None,
                    text="No NDEF data to save",
                    show_back_button=True,
                )
                return Destination(self.__class__)
            
            # Prompt user for a label
            ret = seed_screens.SeedAddPassphraseScreen(
                title="Save NDEF Label",
                is_button_text_centered=True,
            ).display()
            
            if isinstance(ret, dict) and "is_back_button" in ret:
                return Destination(self.__class__)
            
            label = ret.get("passphrase", "NDEF Record").strip()
            if not label:
                label = "NDEF Record"
            
            # Create secret_list for capacity check
            if len(ndef_bytes) <= 255:
                secret_list = [len(ndef_bytes)] + list(ndef_bytes)
            else:
                secret_list = list(len(ndef_bytes).to_bytes(2, "big")) + list(ndef_bytes)
            
            # Create header for capacity check
            header = connector.make_header("Password", "Plaintext export allowed", f"NDEF_{label}")
            secret_dic = {"header": header, "secret_list": secret_list}
            
            # Check capacity before saving
            try:
                fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
                    connector, secret_dic
                )
            except Exception as e:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=str(e)[:100],
                    show_back_button=True,
                )
                return Destination(self.__class__)
            
            if not fits:
                self.run_screen(
                    WarningScreen,
                    title="Not Enough Space",
                    status_headline=None,
                    text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
                    show_back_button=True,
                )
                return Destination(self.__class__)
            
            # Save to SeedKeeper
            loading_screen = LoadingScreenThread(text="Saving NDEF to\nSeedKeeper\n\n\n\n")
            loading_screen.start()
            
            (sid, fingerprint) = ndef_helper.save_ndef_to_seedkeeper(
                connector, ndef_bytes, label
            )
            
            loading_screen.stop()
            
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"NDEF saved\nID: {sid}",
                show_back_button=False,
            )
            return Destination(self.__class__)
        
        except Exception as e:
            logger.exception("Save NDEF to SeedKeeper failed")
            if loading_screen:
                loading_screen.stop()
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=str(e)[:100],
                show_back_button=True,
            )
            return Destination(self.__class__)

    def _load_ndef_from_seedkeeper(self, connector):
        """Load NDEF from SeedKeeper and set it on the card."""
        from seedsigner.gui.screens.screen import LoadingScreenThread
        
        loading_screen = None
        try:
            card_type = getattr(connector, "card_type", "Unknown")
            
            # Check that we're connected to Seedkeeper to load from it
            if card_type != "Seedkeeper":
                self.run_screen(
                    WarningScreen,
                    title="Wrong Card",
                    status_headline=None,
                    text="Connect to SeedKeeper to load NDEF",
                    show_back_button=True,
                )
                return Destination(self.__class__)
            
            # Get list of NDEF secrets from SeedKeeper
            loading_screen = LoadingScreenThread(text="Reading SeedKeeper\nSecrets\n\n\n\n")
            loading_screen.start()
            
            (response, sw1, sw2, headers) = connector.seedkeeper_list_secrets()
            
            loading_screen.stop()
            loading_screen = None
            
            if sw1 != 0x90 or sw2 != 0x00:
                raise RuntimeError(format_sw_error(sw1, sw2))
            
            # Filter for NDEF_ secrets
            ndef_secrets = [h for h in headers if h.get("label", "").startswith("NDEF_")]
            
            if not ndef_secrets:
                self.run_screen(
                    WarningScreen,
                    title="No NDEF Secrets",
                    status_headline=None,
                    text="No NDEF_ prefixed secrets found",
                    show_back_button=True,
                )
                return Destination(self.__class__)
            
            # Create button list for selection
            button_data = [
                ButtonOption(h.get("label", f"Secret {h['id']}"))
                for h in ndef_secrets
            ]
            
            selected_num = self.run_screen(
                ButtonListScreen,
                title="Select NDEF",
                is_button_text_centered=False,
                button_data=button_data,
                show_back_button=True,
            )
            
            if selected_num == RET_CODE__BACK_BUTTON:
                return Destination(self.__class__)
            
            selected_secret = ndef_secrets[selected_num]
            secret_id = selected_secret["id"]
            
            # Load the secret
            loading_screen = LoadingScreenThread(text="Loading NDEF\nfrom SeedKeeper\n\n\n\n")
            loading_screen.start()
            
            ndef_bytes = ndef_helper.load_ndef_from_seedkeeper(connector, secret_id)
            
            loading_screen.stop()
            loading_screen = None
            
            # Convert to hex and set on card
            ndef_hex = ndef_bytes.hex().upper()
            return self._set_ndef(connector, ndef_hex, "NDEF loaded and set")
        
        except Exception as e:
            logger.exception("Load NDEF from SeedKeeper failed")
            if loading_screen:
                loading_screen.stop()
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=str(e)[:100],
                show_back_button=True,
            )
            return Destination(self.__class__)



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

        new_pin_str = seedkeeper_utils.prompt_for_new_pin(self, "New PIN")

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
                
            # Depending on where the descriptor came from when imported into the SeedKeeper, it may need some characters swapped to work with Embit
            secret_template = secret_template.replace("<","{").replace(">","}").replace(";",",")

            # Ensure keys include branch/index wildcards so the Address Explorer
            # derives distinct per-index addresses for receive and change.
            secret_template = embit_utils.normalize_descriptor_str(secret_template)

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


class ToolsKeycardView(View):
    IMPORT_SEED = ButtonOption("Initialise with Seed")
    EXPORT_XPUB = ButtonOption("Export Xpub")
    LOAD_DESCRIPTOR = ButtonOption("Load as Descriptor")
    LOAD_PSBT = ButtonOption("Load PSBT")
    CHANGE_PIN = ButtonOption("Change PIN")
    CHANGE_PUK = ButtonOption("Set PUK")
    UNBLOCK_PIN = ButtonOption("Unblock PIN with PUK")
    SET_NAME = ButtonOption("Set Name")
    REMOVE_SEED = ButtonOption("Remove Seed")
    FACTORY_RESET = ButtonOption("Factory Reset Card")
    ADVANCED = ButtonOption("Advanced")

    def run(self):
        self.controller.smartcard_backend_preference = "keycard"
        button_data = [
            self.IMPORT_SEED,
            self.EXPORT_XPUB,
            self.LOAD_DESCRIPTOR,
            self.LOAD_PSBT,
            self.CHANGE_PIN,
            self.CHANGE_PUK,
            self.UNBLOCK_PIN,
            self.SET_NAME,
            self.REMOVE_SEED,
            self.FACTORY_RESET,
            self.ADVANCED,
        ]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="KeyCard",
            is_button_text_centered=False,
            button_data=button_data,
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

        elif button_data[selected_menu_num] == self.CHANGE_PIN:
            return Destination(ToolsKeycardChangePinView)

        elif button_data[selected_menu_num] == self.CHANGE_PUK:
            return Destination(ToolsKeycardChangePukView)

        elif button_data[selected_menu_num] == self.UNBLOCK_PIN:
            return Destination(ToolsKeycardUnblockPinView)

        elif button_data[selected_menu_num] == self.SET_NAME:
            return Destination(ToolsKeycardSetNameView)

        elif button_data[selected_menu_num] == self.REMOVE_SEED:
            return Destination(ToolsKeycardRemoveSeedView)

        elif button_data[selected_menu_num] == self.FACTORY_RESET:
            return Destination(ToolsKeycardFactoryResetView)

        elif button_data[selected_menu_num] == self.ADVANCED:
            return Destination(ToolsKeycardAdvancedView)


class ToolsKeycardAdvancedView(View):
    BENCHMARK = ButtonOption("Benchmark Signing")
    BENCHMARK_MESSAGE = ButtonOption("Benchmark Message Signing")
    BIAS_TEST = ButtonOption("Check signing bias")

    def run(self):
        button_data = [self.BENCHMARK, self.BENCHMARK_MESSAGE, self.BIAS_TEST]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="KeyCard Advanced",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.BENCHMARK:
            return Destination(ToolsKeycardBenchmarkSignView)

        elif button_data[selected_menu_num] == self.BENCHMARK_MESSAGE:
            return Destination(ToolsKeycardBenchmarkMessageSignView)

        elif button_data[selected_menu_num] == self.BIAS_TEST:
            return Destination(ToolsKeycardBiasCheckView)


def _keycard_benchmark_pubkey(connector, derivation_path: str):
    """Get the signing pubkey from Keycard at the given leaf path.

    Uses card_bip32_get_extendedkey (like Satochip's _get_extended_key) so the
    benchmark verifies signatures against the same key the card actually uses.
    """
    from embit import ec

    path = format_path_string(derivation_path)
    key, _chaincode = connector.card_bip32_get_extendedkey(path)
    return ec.PublicKey.parse(key.get_public_key_bytes(compressed=True))


def _verify_der_signature(pubkey, sig_der: bytes, digest: bytes) -> bool:
    """Verify a DER-encoded ECDSA signature against ``pubkey`` and ``digest``.

    Tries the cryptography library first (most reliable), then falls back to
    pycryptodomex.  Both are standard project dependencies.
    """
    pubkey_sec = bytes(pubkey.sec())
    sig_der = bytes(sig_der)
    digest = bytes(digest)

    # --- Try cryptography library first -----------------------------------
    try:
        from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature

        pub_key = crypto_ec.EllipticCurvePublicKey.from_encoded_point(
            crypto_ec.SECP256K1(), pubkey_sec
        )
        pub_key.verify(sig_der, digest, crypto_ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("cryptography verify failed: %s", exc)

    # --- Fallback to pycryptodomex ----------------------------------------
    try:
        from Crypto.PublicKey import EC
        from Crypto.Signature import DSS

        ec_key = EC.from_encoded_point(pubkey_sec)
        verifier = DSS.new(ec_key, "fips-186-3")
        verifier.verify(digest, sig_der)
        return True
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("pycryptodomex verify failed: %s", exc)

    logger.warning("No working ECDSA verification library available")
    return False


class ToolsKeycardBenchmarkSignView(View):
    """Benchmark Keycard signing performance."""

    NUM_SAMPLES = 20

    ACCOUNT = 0

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread

        connector = seedkeeper_utils.init_satochip(
            self, init_card_filter=["satochip"], backend_preference="keycard"
        )
        if not connector:
            return Destination(BackStackView)

        timeout = 5.0
        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        coin_type = "0" if network == SettingsConstants.MAINNET else "1"
        derivation_path = f"m/84'/{coin_type}'/{self.ACCOUNT}'/0/0"
        path = format_path_string(derivation_path)

        # Get the pubkey from Keycard at the leaf path (same as Satochip signing).
        expected_pubkey = None
        try:
            expected_pubkey = _keycard_benchmark_pubkey(connector, derivation_path)
        except Exception as exc:
            logger.warning("Benchmark signing could not derive verification pubkey: %s", exc)

        # Set the derivation path for keynbr=0xFF routing.
        setattr(connector, "_last_path", path)

        durations: list[float] = []
        error: str | None = None
        sigs_verified = False
        loading = LoadingScreenThread(text="Benchmarking\n\n\n\n\n\n")
        loading.start()
        try:
            for i in range(self.NUM_SAMPLES):
                tx_hash = os.urandom(32)
                start = time.monotonic()
                try:
                    response, sw1, sw2 = _call_with_timeout(
                        connector.card_sign_transaction_hash,
                        timeout,
                        0xFF,
                        list(tx_hash),
                        None,
                    )
                except Exception as exc:
                    logger.warning("Benchmark signing failed at sample %d: %s", i, exc)
                    error = str(exc)
                    break
                durations.append(time.monotonic() - start)
                if sw1 != 0x90 or sw2 != 0x00:
                    error = format_sw_error(sw1, sw2)
                    break
                # Verification is best-effort; Keycard's internal key derivation
                # may not match the xpub we can export, so a mismatch does not
                # abort the benchmark — just log and continue timing.
                if expected_pubkey is not None:
                    verified = _verify_der_signature(expected_pubkey, response, tx_hash)
                    if i == 0:
                        sigs_verified = verified
        finally:
            loading.stop()

        if durations and not error:
            avg = sum(durations) / len(durations)
            min_time = min(durations)
            max_time = max(durations)
            logger.info(
                "Keycard benchmark signing results: min=%.3fs avg=%.3fs max=%.3fs over %d signatures",
                min_time,
                avg,
                max_time,
                len(durations),
            )
            verify_note = "sigs verified" if sigs_verified else "sigs NOT verified"
            text = (
                "Min: {min_time:.3f}s\n"
                "Avg: {avg:.3f}s\n"
                "Max: {max_time:.3f}s\n"
                "({verify_note})"
            ).format(
                min_time=min_time,
                avg=avg,
                max_time=max_time,
                verify_note=verify_note,
            )
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


class ToolsKeycardBenchmarkMessageSignView(View):
    """Benchmark Keycard message signing performance."""

    NUM_SAMPLES = 20
    ADDRESS_STEP = 5
    ACCOUNT = 0

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread

        connector = seedkeeper_utils.init_satochip(
            self, init_card_filter=["satochip"], backend_preference="keycard"
        )
        if not connector:
            return Destination(BackStackView)

        timeout = 5.0
        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        coin_type = "0" if network == SettingsConstants.MAINNET else "1"

        durations: list[float] = []
        error: str | None = None
        sigs_verified = False
        loading = LoadingScreenThread(text="Benchmarking\n\n\n\n\n\n")
        loading.start()
        try:
            for i in range(self.NUM_SAMPLES):
                address_index = i * self.ADDRESS_STEP
                derivation_path = f"m/84'/{coin_type}'/{self.ACCOUNT}'/0/{address_index}"
                path = format_path_string(derivation_path)

                # Get pubkey from Keycard at this leaf path for verification.
                expected_pubkey = None
                try:
                    expected_pubkey = _keycard_benchmark_pubkey(connector, derivation_path)
                except Exception as exc:
                    if i == 0:
                        logger.warning("Benchmark message signing could not derive verification pubkey: %s", exc)

                setattr(connector, "_last_path", path)
                digest = os.urandom(32)
                start = time.monotonic()
                try:
                    response, sw1, sw2, _compsig = _call_with_timeout(
                        connector.card_sign_message,
                        timeout,
                        0xFF,
                        None,
                        list(digest),
                    )
                except Exception as exc:
                    logger.warning("Benchmark message signing failed at index %d: %s", address_index, exc)
                    error = str(exc)
                    break
                durations.append(time.monotonic() - start)
                if sw1 != 0x90 or sw2 != 0x00:
                    error = format_sw_error(sw1, sw2)
                    break
                # Verification is best-effort; a mismatch does not abort the benchmark.
                if expected_pubkey is not None:
                    verified = _verify_der_signature(expected_pubkey, response, digest)
                    if i == 0:
                        sigs_verified = verified
        finally:
            loading.stop()

        if durations and not error:
            avg = sum(durations) / len(durations)
            min_time = min(durations)
            max_time = max(durations)
            logger.info(
                "Keycard benchmark message signing results: min=%.3fs avg=%.3fs max=%.3fs over %d signatures",
                min_time,
                avg,
                max_time,
                len(durations),
            )
            verify_note = "sigs verified" if sigs_verified else "sigs NOT verified"
            text = (
                "Min: {min_time:.3f}s\n"
                "Avg: {avg:.3f}s\n"
                "Max: {max_time:.3f}s\n"
                "(addr 0-{last_idx}, {verify_note})"
            ).format(
                min_time=min_time,
                avg=avg,
                max_time=max_time,
                last_idx=(len(durations) - 1) * self.ADDRESS_STEP,
                verify_note=verify_note,
            )
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


class ToolsKeycardChangePinView(View):
    def run(self):
        connector = seedkeeper_utils.init_satochip(
            self,
            init_card_filter=["satochip"],
            backend_preference="keycard",
        )
        if not connector:
            return Destination(BackStackView)

        new_pin_str = _prompt_keycard_new_pin(self, "New PIN")
        if new_pin_str is None:
            return Destination(BackStackView)

        new_pin = list(new_pin_str.encode("utf-8"))
        _response, sw1, sw2 = connector.card_change_PIN(0, connector.pin, new_pin)
        if sw1 == 0x90 and sw2 == 0x00:
            self.controller.Satochip_PIN = new_pin
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="PIN Updated",
                show_back_button=False,
            )
        else:
            if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
                seedkeeper_utils.show_incorrect_pin_warning(
                    self,
                    connector=connector,
                    sw1=sw1,
                    sw2=sw2,
                )
            else:
                self.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text="PIN update failed",
                    show_back_button=True,
                )
        return Destination(MainMenuView)


class ToolsKeycardChangePukView(View):
    def run(self):
        connector = seedkeeper_utils.init_satochip(
            self,
            init_card_filter=["satochip"],
            backend_preference="keycard",
        )
        if not connector:
            return Destination(BackStackView)

        # The Keycard applet rejects anything other than exactly 12 digits
        # with 0x6A80, so validate locally for a clear error message.
        new_puk_str = _prompt_keycard_new_puk(self, "New PUK")
        if new_puk_str is None:
            return Destination(BackStackView)

        _response, sw1, sw2 = connector.card_change_PUK(0, [], list(new_puk_str.encode("utf-8")))
        if sw1 == 0x90 and sw2 == 0x00:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="PUK Updated",
                show_back_button=False,
            )
        else:
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text="PUK update failed",
                show_back_button=True,
            )
        return Destination(MainMenuView)


class ToolsKeycardUnblockPinView(View):
    def run(self):
        connector = seedkeeper_utils.init_satochip(
            self,
            init_card_filter=["satochip"],
            require_pin=False,
            backend_preference="keycard",
        )
        if not connector:
            return Destination(BackStackView)

        puk_ret = seed_screens.SeedAddPassphraseScreen(
            title="PUK",
            initial_keyboard=seed_screens.SeedAddPassphraseScreen.KEYBOARD__DIGITS_BUTTON_TEXT,
        ).display()
        if "is_back_button" in puk_ret:
            return Destination(BackStackView)
        puk_str = puk_ret.get("passphrase", "")
        if len(puk_str) < 4:
            self.run_screen(
                WarningScreen,
                title="Invalid PUK",
                status_headline=None,
                text="PUK must be at least 4 chars",
                show_back_button=True,
            )
            return Destination(BackStackView)

        new_pin_str = _prompt_keycard_new_pin(self, "New PIN")
        if new_pin_str is None:
            return Destination(BackStackView)

        _response, sw1, sw2 = connector.card_unblock_PIN(
            0,
            list(puk_str.encode("utf-8")),
            list(new_pin_str.encode("utf-8")),
        )
        if sw1 == 0x90 and sw2 == 0x00:
            self.controller.Satochip_PIN = list(new_pin_str.encode("utf-8"))
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="PIN Unblocked",
                show_back_button=False,
            )
        else:
            if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
                seedkeeper_utils.show_incorrect_pin_warning(
                    self,
                    connector=connector,
                    sw1=sw1,
                    sw2=sw2,
                )
            else:
                self.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text="PIN unblock failed",
                    show_back_button=True,
                )
        return Destination(MainMenuView)


class ToolsKeycardSetNameView(View):
    def run(self):
        connector = seedkeeper_utils.init_satochip(
            self,
            init_card_filter=["satochip"],
            backend_preference="keycard",
        )
        if not connector:
            return Destination(BackStackView)

        ret = seed_screens.SeedAddPassphraseScreen(title="New Name").display()
        if "is_back_button" in ret:
            return Destination(BackStackView)
        label = ret.get("passphrase", "")

        _response, sw1, sw2 = connector.card_set_label(label)
        if sw1 == 0x90 and sw2 == 0x00:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="Name Updated",
                show_back_button=False,
            )
        else:
            if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
                seedkeeper_utils.show_incorrect_pin_warning(
                    self,
                    connector=connector,
                    sw1=sw1,
                    sw2=sw2,
                )
            else:
                self.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text="Name update failed",
                    show_back_button=True,
                )
        return Destination(MainMenuView)


class ToolsKeycardRemoveSeedView(View):
    def run(self):
        connector = seedkeeper_utils.init_satochip(
            self,
            init_card_filter=["satochip"],
            backend_preference="keycard",
        )
        if not connector:
            return Destination(BackStackView)

        ret = self.run_screen(
            DireWarningScreen,
            title="Warning",
            status_headline=None,
            text="Remove key from card?",
            show_back_button=True,
            button_data=[ButtonOption("Remove")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        _response, sw1, sw2 = connector.card_remove_key()
        if sw1 == 0x90 and sw2 == 0x00:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="Seed Removed",
                show_back_button=False,
            )
        else:
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text="Remove seed failed",
                show_back_button=True,
            )
        return Destination(MainMenuView)


class ToolsKeycardFactoryResetView(View):
    def run(self):
        connector = seedkeeper_utils.init_satochip(
            self,
            init_card_filter=["satochip"],
            backend_preference="keycard",
        )
        if not connector:
            return Destination(BackStackView)

        ret = self.run_screen(
            DireWarningScreen,
            title="Warning",
            status_headline=None,
            text="Factory reset without backup loses funds.",
            show_back_button=True,
            button_data=[ButtonOption("Reset")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        _response, sw1, sw2 = connector.card_reset_factory()
        if sw1 == 0x90 and sw2 == 0x00:
            self.controller.Satochip_PIN = None
            self.controller.Satochip_Connector = None
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="Card Factory Reset",
                show_back_button=False,
            )
        else:
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text="Factory reset failed",
                show_back_button=True,
            )
        return Destination(MainMenuView)


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
        backend_preference = getattr(self.controller, "smartcard_backend_preference", None)
        Satochip_Connector = seedkeeper_utils.init_satochip(
            self,
            init_card_filter=["satochip"],
            allow_unseeded=True,
            backend_preference=backend_preference,
        )

        if not Satochip_Connector:
            return Destination(BackStackView)

        # Prevent reseeding an already-initialized card. Attempting to import a new
        # seed into a seeded Satochip results in a generic failure. Instead, check
        # the card's status up front and inform the user so they can take
        # appropriate action (like resetting the card) before proceeding.
        _resp, _sw1, _sw2, status = Satochip_Connector.card_get_status()
        if status.get("is_seeded"):
            card_name = "Keycard" if getattr(Satochip_Connector, "is_keycard_backend", False) else "Satochip"
            self.run_screen(
                WarningScreen,
                title=_("Already Seeded"),
                status_headline=None,
                text=_(f"{card_name} card already contains a seed."),
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
        self.controller.resume_main_flow = self.controller.FLOW__SATOCHIP_IMPORT_SEED

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

                _resp, sw1, sw2 = Satochip_Connector.card_bip32_import_seed(seeds[selected_menu_num].seed_bytes)
                if (sw1, sw2) != (0x90, 0x00):
                    if (
                        getattr(Satochip_Connector, "is_keycard_backend", False)
                        and (sw1, sw2) == (0x69, 0x85)
                    ):
                        raise ValueError(
                            "Keycard blocked seed import (SW=6985).\n"
                            "Try Factory Reset Card, then retry import."
                        )
                    raise ValueError(f"Import failed with SW={sw1:02X}{sw2:02X}")

                _status_resp, status_sw1, status_sw2, post_status = Satochip_Connector.card_get_status()
                if (status_sw1, status_sw2) != (0x90, 0x00):
                    raise ValueError(f"Status check failed with SW={status_sw1:02X}{status_sw2:02X}")

                if not (post_status.get("is_seeded") or post_status.get("key_initialized")):
                    raise ValueError("Card did not report a seeded key after import")

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
                error_text = str(e) or "Seed Import Failed"
                if len(error_text) > 120:
                    error_text = error_text[:120]
                self.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text=error_text,
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
        from seedsigner.models.encode_qr import GenericStaticQrEncoder
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
        if self.controller.resume_main_flow == self.controller.FLOW__ADDRESS_EXPLORER:
            from seedsigner.views.seed_views import MultisigWalletDescriptorView
            return Destination(MultisigWalletDescriptorView, skip_current_view=True)
        elif self.controller.resume_main_flow == self.controller.FLOW__VERIFY_SINGLESIG_ADDR:
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


class ToolsSpecterDIYView(View):
    CHANGE_PIN = ButtonOption("Change Card PIN")
    LOAD_MNEMONIC = ButtonOption("Load Mnemonic")
    SAVE_MNEMONIC = ButtonOption("Save Mnemonic")
    WIPE_MNEMONIC = ButtonOption("Wipe Seed")

    def run(self):
        button_data = [self.CHANGE_PIN, self.LOAD_MNEMONIC, self.SAVE_MNEMONIC, self.WIPE_MNEMONIC]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Specter-DIY",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        choice = button_data[selected_menu_num]
        if choice == self.CHANGE_PIN:
            return Destination(ToolsSpecterDIYChangePinView)
        if choice == self.LOAD_MNEMONIC:
            return Destination(ToolsJavacardLoadMnemonicView)
        if choice == self.SAVE_MNEMONIC:
            return Destination(ToolsJavacardSaveMnemonicView)
        return Destination(ToolsJavacardWipeMnemonicView)


class ToolsJavacardWipeMnemonicView(View):
    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread

        conn = None
        secure_channel = None
        try:
            Card, MemoryCardApplet, SecureApplet = _get_specter_card_api()
            conn = Card(SPECTER_JAVACARD_DEFAULT_AID)
            conn.connect()
            secure_applet = SecureApplet(conn)
            memory_applet = MemoryCardApplet(conn)
            secure_channel = _open_specter_secure_channel(secure_applet)
            if not _unlock_specter_card_if_needed(self, secure_applet, secure_channel):
                return Destination(BackStackView)

            existing_data = memory_applet.get_data(secure_channel)
            if not existing_data:
                self.run_screen(
                    WarningScreen,
                    title="No Seed Found",
                    status_headline=None,
                    text="No seed data found on Specter Javacard.",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            confirm = self.run_screen(
                WarningScreen,
                title="Wipe Seed?",
                status_headline=None,
                text="Delete stored seed data from card?",
                show_back_button=False,
                button_data=[ButtonOption("Wipe Seed"), ButtonOption("Cancel")],
            )
            if confirm != 0:
                return Destination(BackStackView)

            loading = LoadingScreenThread(text="Wiping Seed\n\n\n\n\n\n")
            loading.start()
            memory_applet.store_data(secure_channel, b"")
            loading.stop()

            self.run_screen(
                LargeIconStatusScreen,
                title="Seed Wiped",
                status_headline=None,
                text="Seed data deleted from Specter Javacard",
                show_back_button=False,
            )
            return Destination(BackStackView)
        except Exception as exc:
            self.run_screen(
                WarningScreen,
                title="Wipe Failed",
                status_headline=None,
                text=str(exc),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        finally:
            if secure_channel is not None:
                try:
                    secure_channel.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.disconnect()
                except Exception:
                    pass


class ToolsSpecterDIYChangePinView(View):
    def run(self):
        conn = None
        secure_channel = None
        try:
            Card, MemoryCardApplet, SecureApplet = _get_specter_card_api()
            conn = Card(SPECTER_JAVACARD_DEFAULT_AID)
            conn.connect()
            secure_applet = SecureApplet(conn)
            secure_channel = _open_specter_secure_channel(secure_applet)

            status = secure_applet.pin_status(secure_channel)
            pin_status = status.get("status")

            if pin_status == "bricked":
                _show_specter_card_bricked_warning(self)
                return Destination(BackStackView)

            if pin_status in ("disabled", "no_pin"):
                # PIN is not set; prompt user to set a new PIN
                new_pin = _prompt_specter_new_pin(self, "Set New PIN")
                if new_pin is None:
                    return Destination(BackStackView)
                if not new_pin:
                    self.run_screen(
                        WarningScreen,
                        title="Invalid PIN",
                        status_headline=None,
                        text="PIN cannot be empty.",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
                secure_applet.set_pin(secure_channel, new_pin.encode("utf-8"))
                self.run_screen(
                    LargeIconStatusScreen,
                    title="PIN Set",
                    status_headline=None,
                    text="Card PIN has been set.",
                    show_back_button=False,
                )
                return Destination(BackStackView)

            # PIN is set; prompt for the current PIN once, then the new PIN.
            ret = seed_screens.SeedAddPassphraseScreen(
                title="Current PIN",
                initial_keyboard=seed_screens.SeedAddPassphraseScreen.KEYBOARD__DIGITS_BUTTON_TEXT,
            ).display()
            if isinstance(ret, dict) and "is_back_button" in ret:
                return Destination(BackStackView)
            old_pin = ret.get("passphrase", "")
            if not old_pin:
                self.run_screen(
                    WarningScreen,
                    title="Invalid PIN",
                    status_headline=None,
                    text="PIN cannot be empty.",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            new_pin = _prompt_specter_new_pin(self, "New PIN")
            if new_pin is None:
                return Destination(BackStackView)
            if not new_pin:
                self.run_screen(
                    WarningScreen,
                    title="Invalid PIN",
                    status_headline=None,
                    text="PIN cannot be empty.",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            try:
                secure_applet.change_pin(secure_channel, old_pin.encode("utf-8"), new_pin.encode("utf-8"))
            except Exception as exc:
                if _is_specter_pin_error(exc):
                    _show_specter_incorrect_pin_warning(self, secure_applet, secure_channel)
                    return Destination(BackStackView)
                raise
            self.run_screen(
                LargeIconStatusScreen,
                title="PIN Changed",
                status_headline=None,
                text="Card PIN has been changed.",
                show_back_button=False,
            )
            return Destination(BackStackView)
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
        finally:
            if secure_channel is not None:
                try:
                    secure_channel.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.disconnect()
                except Exception:
                    pass


class ToolsSatochipDIYView(View):
    MANAGE_KEYS = ButtonOption("Card Keys")
    BUILD_APPLETS = ButtonOption("Build Applets")
    INSTALL_APPLET = ButtonOption("Install Applet")
    UNINSTALL_APPLET = ButtonOption("Uninstall Applet")

    def run(self):
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
            # Check if ANT is available as a way of checking if the DIY tools we need are available
            from pathlib import Path
            from seedsigner.models.settings import Settings

            if Settings.HOSTNAME == Settings.SEEDSIGNER_OS:
                ant_path = "/mnt/diy/ant/bin/ant"
            elif os.path.exists("/home/pi"):
                ant_path = "/home/pi/Satochip-DIY/ant/bin/ant"
            else:
                ant_path = str(Path.home() / "Satochip-DIY/ant/bin/ant")

            if not os.path.exists(ant_path):
                self.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text="DIY tools filesystem not found.\n\nRequired to build applets.",
                    show_back_button=False,
                )
                return Destination(self.__class__)
            return Destination(ToolsDIYBuildAppletsView)

        elif button_data[selected_menu_num] == self.INSTALL_APPLET:
            return Destination(ToolsDIYInstallAppletView)

        elif button_data[selected_menu_num] == self.UNINSTALL_APPLET:
            return Destination(ToolsDIYUninstallAppletView)

        elif button_data[selected_menu_num] == self.MANAGE_KEYS:
            return Destination(ToolsJavacardKeysView)


JAVACARD_KEYS_MICROSD_FILENAME = "javacard-keys.txt"
JAVACARD_KEYS_SEEDKEEPER_PREFIX = "jc_keys_"
SPECTER_JAVACARD_DEFAULT_AID = "B00B5111CB01"


def _candidate_specter_card_paths() -> list[Path]:
    candidates: list[Path] = []
    env_path = (
        os.environ.get("SEEDSIGNER_SPECTER_CARD_PY_PATH")
        or os.environ.get("SEEDSIGNER_SPECTER_JAVACARD_PATH")
    )
    if env_path:
        candidates.append(Path(env_path).expanduser())

    repo_root = Path(__file__).resolve().parents[3]
    candidates.append(repo_root.parent / "specter-javacard" / "py")
    candidates.append(repo_root / "specter-javacard" / "py")
    return candidates


def _get_specter_card_api():
    try:
        from specter_card import Card, MemoryCardApplet, SecureApplet
        return Card, MemoryCardApplet, SecureApplet
    except Exception:
        pass

    for candidate in _candidate_specter_card_paths():
        try:
            if not candidate.exists() or not candidate.is_dir():
                continue
            candidate_str = str(candidate)
            if candidate_str not in sys.path:
                sys.path.insert(0, candidate_str)
            from specter_card import Card, MemoryCardApplet, SecureApplet
            return Card, MemoryCardApplet, SecureApplet
        except Exception:
            continue

    raise ImportError(
        "Unable to load specter_card module. Install specter-javacard py module or set SEEDSIGNER_SPECTER_CARD_PY_PATH."
    )


def _normalize_bip39_mnemonic_text(text: str) -> str:
    mnemonic = " ".join((text or "").strip().lower().split())
    if not mnemonic:
        raise ValueError("No mnemonic data found on card")
    words = mnemonic.split(" ")
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError("Stored data is not a 12/15/18/21/24-word mnemonic")
    return mnemonic


def _show_specter_card_bricked_warning(parent_view) -> None:
    parent_view.run_screen(
        WarningScreen,
        title="Card Locked",
        status_headline=None,
        text=(
            "PIN attempts exhausted. Reinstall Specter-DIY applet.\n"
            "No factory reset available."
        ),
        show_back_button=False,
        button_data=[ButtonOption("I Understand")],
    )


def _open_specter_secure_channel(secure_applet):
    last_error = None
    for mode in ("ee", "es", "ss"):
        try:
            return secure_applet.open_secure_channel(mode=mode)
        except TypeError:
            return secure_applet.open_secure_channel()
        except Exception as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    return secure_applet.open_secure_channel()


def _specter_compact_size(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def _specter_tagged_hash(tag: str, data: bytes) -> bytes:
    hashtag = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(hashtag + hashtag + data).digest()


def _specter_aead_encrypt(key: bytes, adata: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    aes_key = _specter_tagged_hash("aes", key)
    hmac_key = _specter_tagged_hash("hmac", key)

    body = _specter_compact_size(len(adata)) + adata
    if plaintext:
        iv = os.urandom(16)
        padded = plaintext + b"\x80"
        if len(padded) % 16 != 0:
            padded += b"\x00" * (16 - (len(padded) % 16))
        enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
        body += iv + enc.update(padded) + enc.finalize()

    mac = hmac.new(hmac_key, body, digestmod="sha256").digest()
    return body + mac


def _serialize_specter_plaintext_blob(entropy: bytes) -> bytes:
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("Invalid BIP39 entropy length")

    adata = b"sdiy\x00" + (b"\x00" * 4)
    key = b"\xcc" * 32
    tlv = b"\x02" + bytes([len(entropy)]) + entropy
    return _specter_aead_encrypt(key=key, adata=adata, plaintext=tlv)


def _is_specter_pin_error(exc: Exception) -> bool:
    err = str(exc).lower()
    return "0502" in err or "0503" in err


def _show_specter_incorrect_pin_warning(parent_view, secure_applet, secure_channel) -> None:
    attempts_left = None
    try:
        status = secure_applet.pin_status(secure_channel)
        if status.get("status") == "bricked":
            _show_specter_card_bricked_warning(parent_view)
            return
        attempts_left = status.get("attempts_left")
    except Exception:
        pass

    if isinstance(attempts_left, int):
        attempt_word = "attempt" if attempts_left == 1 else "attempts"
        text = f"PIN is incorrect.\n{attempts_left} {attempt_word} remaining."
    else:
        text = "PIN is incorrect."

    parent_view.run_screen(
        WarningScreen,
        title="Incorrect PIN",
        status_headline=None,
        text=text,
        show_back_button=False,
        button_data=[ButtonOption("I Understand")],
    )


def _prompt_specter_pin_once(parent_view, title: str) -> str | None:
    while True:
        ret = seed_screens.SeedAddPassphraseScreen(
            title=title,
            initial_keyboard=seed_screens.SeedAddPassphraseScreen.KEYBOARD__DIGITS_BUTTON_TEXT,
        ).display()
        if isinstance(ret, dict) and "is_back_button" in ret:
            return None

        pin = ret.get("passphrase", "")
        if all(ch in "0123456789" for ch in pin):
            return pin

        selected = parent_view.run_screen(
            WarningScreen,
            title="Non-Numeric PIN",
            status_headline=None,
            text=(
                "Specter-DIY hardware supports PIN digits 0-9.\n"
                "Use this PIN anyway?"
            ),
            show_back_button=False,
            button_data=[ButtonOption("Continue"), ButtonOption("Enter Different PIN")],
        )
        if selected == 0:
            return pin


def _prompt_specter_new_pin(parent_view, title: str) -> str | None:
    """Prompt for a new Specter-DIY PIN and require re-entry to confirm."""
    while True:
        pin = _prompt_specter_pin_once(parent_view, title)
        if pin is None:
            return None

        confirm = _prompt_specter_pin_once(parent_view, f"Confirm {title}")
        if confirm is None:
            return None

        if pin == confirm:
            return pin

        parent_view.run_screen(
            WarningScreen,
            title="PIN Mismatch",
            status_headline=None,
            text="PINs did not match.\nPlease try again.",
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )


def _prompt_keycard_digits_once(parent_view, title: str, *, length: int, label: str) -> str | None:
    while True:
        ret = seed_screens.SeedAddPassphraseScreen(
            title=title,
            initial_keyboard=seed_screens.SeedAddPassphraseScreen.KEYBOARD__DIGITS_BUTTON_TEXT,
        ).display()
        if isinstance(ret, dict) and "is_back_button" in ret:
            return None

        value = ret.get("passphrase", "")
        if all(ch in "0123456789" for ch in value):
            if len(value) == length:
                return value

            parent_view.run_screen(
                WarningScreen,
                title=f"Invalid {label} Length",
                status_headline=None,
                text=f"Keycard {label} must be exactly {length} digits.",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            continue

        parent_view.run_screen(
            WarningScreen,
            title=f"Non-Numeric {label}",
            status_headline=None,
            text=f"Keycard {label} must contain digits 0-9 only.",
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )


def _prompt_keycard_new_digits(parent_view, title: str, *, length: int, label: str) -> str | None:
    """Prompt for a new Keycard PIN/PUK and require re-entry to confirm."""
    while True:
        value = _prompt_keycard_digits_once(parent_view, title, length=length, label=label)
        if value is None:
            return None

        confirm = _prompt_keycard_digits_once(
            parent_view, f"Confirm {title}", length=length, label=label
        )
        if confirm is None:
            return None

        if value == confirm:
            return value

        parent_view.run_screen(
            WarningScreen,
            title=f"{label} Mismatch",
            status_headline=None,
            text=f"{label}s did not match.\nPlease try again.",
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )


def _prompt_keycard_new_pin(parent_view, title: str) -> str | None:
    return _prompt_keycard_new_digits(parent_view, title, length=6, label="PIN")


def _prompt_keycard_new_puk(parent_view, title: str) -> str | None:
    return _prompt_keycard_new_digits(parent_view, title, length=12, label="PUK")


def _unlock_specter_card_if_needed(parent_view, secure_applet, secure_channel) -> bool:
    status = secure_applet.pin_status(secure_channel)
    if status.get("status") == "bricked":
        _show_specter_card_bricked_warning(parent_view)
        return False
    if status.get("status") in ("disabled", "unlocked", "no_pin"):
        return True
    if status.get("status") != "locked":
        return True

    ret = seed_screens.SeedAddPassphraseScreen(
        title="Card PIN",
        initial_keyboard=seed_screens.SeedAddPassphraseScreen.KEYBOARD__DIGITS_BUTTON_TEXT,
    ).display()
    if isinstance(ret, dict) and "is_back_button" in ret:
        return False
    pin = ret.get("passphrase", "")
    if not pin:
        parent_view.run_screen(
            WarningScreen,
            title="Invalid PIN",
            status_headline=None,
            text="PIN cannot be empty.",
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )
        return False
    try:
        secure_applet.unlock(secure_channel, pin.encode("utf-8"))
        return True
    except Exception as exc:
        if _is_specter_pin_error(exc):
            _show_specter_incorrect_pin_warning(parent_view, secure_applet, secure_channel)
            return False
        raise


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
    LOAD_MNEMONIC = ButtonOption("Load Mnemonic")
    SAVE_MNEMONIC = ButtonOption("Save Mnemonic")
    UNLOCK_CARD = ButtonOption("Unlock Card")
    LOCK_CARD = ButtonOption("Lock Card")
    CLEAR_KEYS = ButtonOption("Clear Loaded Keys")

    def run(self):
        button_data = [
            self.LOAD_KEYS,
            self.SAVE_KEYS,
            self.LOAD_MNEMONIC,
            self.SAVE_MNEMONIC,
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
        if choice == self.LOAD_MNEMONIC:
            return Destination(ToolsJavacardLoadMnemonicView)
        if choice == self.SAVE_MNEMONIC:
            return Destination(ToolsJavacardSaveMnemonicView)
        if choice == self.UNLOCK_CARD:
            return Destination(ToolsJavacardUnlockCardView)
        if choice == self.LOCK_CARD:
            return Destination(ToolsJavacardLockCardView)
        return Destination(ToolsJavacardClearKeysView)


class ToolsJavacardLoadMnemonicView(View):
    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread

        conn = None
        secure_channel = None
        try:
            Card, MemoryCardApplet, SecureApplet = _get_specter_card_api()
            conn = Card(SPECTER_JAVACARD_DEFAULT_AID)
            conn.connect()
            secure_applet = SecureApplet(conn)
            memory_applet = MemoryCardApplet(conn)
            secure_channel = _open_specter_secure_channel(secure_applet)
            if not _unlock_specter_card_if_needed(self, secure_applet, secure_channel):
                return Destination(BackStackView)

            loading = LoadingScreenThread(text="Loading Mnemonic\n\n\n\n\n\n")
            loading.start()
            raw = memory_applet.get_data(secure_channel)
            loading.stop()
            if not raw:
                self.run_screen(
                    WarningScreen,
                    title="No Mnemonic Found",
                    status_headline=None,
                    text="No data found on Specter Javacard.",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            decoded = memory_applet.decode_diy_data(secure_channel)
            mnemonic_text = decoded.get("mnemonic")
            if not mnemonic_text:
                entropy = decoded.get("entropy")
                if entropy:
                    from embit import bip39
                    mnemonic_text = bip39.mnemonic_from_bytes(entropy)
            if not mnemonic_text:
                raise ValueError("Stored data could not be decoded as Specter-DIY mnemonic")

            mnemonic_text = _normalize_bip39_mnemonic_text(mnemonic_text)
            mnemonic_words = mnemonic_text.split(" ")
            self.controller.storage.init_pending_mnemonic(num_words=len(mnemonic_words))
            for i, word in enumerate(mnemonic_words):
                self.controller.storage.update_pending_mnemonic(word, i)
            self.controller.storage.convert_pending_mnemonic_to_pending_seed(
                wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE),
            )
            return Destination(SeedFinalizeView)
        except InvalidSeedException:
            self.run_screen(
                WarningScreen,
                title="Invalid Mnemonic",
                status_headline=None,
                text="Stored data is not a valid BIP39 mnemonic.",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        except Exception as exc:
            self.run_screen(
                WarningScreen,
                title="Load Failed",
                status_headline=None,
                text=str(exc),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        finally:
            if secure_channel is not None:
                try:
                    secure_channel.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.disconnect()
                except Exception:
                    pass


class ToolsJavacardSaveMnemonicView(View):
    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread

        bip39_seeds: list[tuple[int, Seed]] = []
        for i, seed in enumerate(self.controller.storage.seeds):
            if type(seed) is Seed:
                bip39_seeds.append((i, seed))

        if not bip39_seeds:
            self.run_screen(
                WarningScreen,
                title="No BIP39 Seed",
                status_headline=None,
                text="Load a BIP39 seed before saving.",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        selected_seed = bip39_seeds[0][1]
        if len(bip39_seeds) > 1:
            options = []
            for _, seed in bip39_seeds:
                fingerprint = seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
                options.append(ButtonOption(fingerprint, SeedSignerIconConstants.FINGERPRINT))
            selected = self.run_screen(
                ButtonListScreen,
                title="Select Seed",
                is_button_text_centered=False,
                button_data=options,
                show_back_button=True,
            )
            if selected == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            selected_seed = bip39_seeds[selected][1]

        mnemonic_text = " ".join(selected_seed.mnemonic_list).strip()
        conn = None
        secure_channel = None
        try:
            from embit import bip39

            Card, MemoryCardApplet, SecureApplet = _get_specter_card_api()
            conn = Card(SPECTER_JAVACARD_DEFAULT_AID)
            conn.connect()
            secure_applet = SecureApplet(conn)
            memory_applet = MemoryCardApplet(conn)
            secure_channel = _open_specter_secure_channel(secure_applet)
            if not _unlock_specter_card_if_needed(self, secure_applet, secure_channel):
                return Destination(BackStackView)

            status = secure_applet.pin_status(secure_channel)
            existing_data = memory_applet.get_data(secure_channel)

            if status.get("status") in ("disabled", "no_pin") and not existing_data:
                new_pin = _prompt_specter_new_pin(self, "Create PIN")
                if new_pin is None:
                    return Destination(BackStackView)
                if not new_pin:
                    self.run_screen(
                        WarningScreen,
                        title="Invalid PIN",
                        status_headline=None,
                        text="PIN cannot be empty.",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
                secure_applet.set_pin(secure_channel, new_pin.encode("utf-8"))

            if existing_data:
                overwrite = self.run_screen(
                    WarningScreen,
                    title="Overwrite Data?",
                    status_headline=None,
                    text="Card already has data. Overwrite it?",
                    show_back_button=False,
                    button_data=[ButtonOption("Overwrite"), ButtonOption("Abort Save")],
                )
                if overwrite != 0:
                    return Destination(BackStackView)

            entropy = bip39.mnemonic_to_bytes(mnemonic_text)
            payload = _serialize_specter_plaintext_blob(entropy)

            loading = LoadingScreenThread(text="Saving Mnemonic\n\n\n\n\n\n")
            loading.start()
            memory_applet.store_data(secure_channel, payload)
            loading.stop()

            self.run_screen(
                LargeIconStatusScreen,
                title="Saved",
                status_headline=None,
                text="Mnemonic saved to Specter Javacard",
                show_back_button=False,
            )
            return Destination(BackStackView)
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
        finally:
            if secure_channel is not None:
                try:
                    secure_channel.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.disconnect()
                except Exception:
                    pass


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
        from seedsigner.gui.screens.screen import LoadingScreenThread
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

        self.loading_screen = LoadingScreenThread(text="Unlocking Card")
        self.loading_screen.start()
        try:
            import pygp
            pygp.terminal()
            pygp.card()
            
            # Get the actual keys based on key type (single vs set)
            if keys.get("type") == "single":
                enc_key = keys.get('key')
                mac_key = keys.get('key')
                dek_key = keys.get('key')
            else:  # type == "set"
                enc_key = keys.get('enc')
                mac_key = keys.get('mac')
                dek_key = keys.get('dek')
            
            # Validate keys
            for key_name, key_value in [('enc', enc_key), ('mac', mac_key), ('dek', dek_key)]:
                if not key_value:
                    raise ValueError(f"Missing key: {key_name}")
                if not isinstance(key_value, str):
                    raise TypeError(f"Key {key_name} is not a string: {type(key_value)}")
                # Validate hex format
                try:
                    int(key_value, 16)
                except ValueError:
                    raise ValueError(f"Key {key_name} contains invalid hex characters")
            
            # Unlock: authenticate with the LOADED keys and set back to DEFAULT
            pygp.auth(enc_key=enc_key, mac_key=mac_key, dek_key=dek_key, keysetversion="00", securitylevel=pygp.SECURITY_LEVEL_C_DEC_C_MAC)
            DEFAULT_GP_KEY = "404142434445464748494A4B4C4D4E4F"
            pygp.set_key(f"01/1/DES/{DEFAULT_GP_KEY}")
            pygp.set_key(f"01/2/DES/{DEFAULT_GP_KEY}")
            pygp.set_key(f"01/3/DES/{DEFAULT_GP_KEY}")
            pygp.put_scp_key("01", replace=True)
            self.loading_screen.stop()
            self.run_screen(LargeIconStatusScreen, title="Success", status_headline=None, text="Card Unlocked", show_back_button=False)
        except Exception as e:
            self.loading_screen.stop()
            self.run_screen(WarningScreen, title="Failed", status_headline=None, text=seedkeeper_utils.pygp_format_error(e)[:100], show_back_button=False)
        finally:
            seedkeeper_utils.restart_pn532(self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_INTERFACES))

        return Destination(BackStackView)


class ToolsJavacardLockCardView(View):
    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
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

        self.loading_screen = LoadingScreenThread(text="Locking Card")
        self.loading_screen.start()
        try:
            import pygp
            pygp.terminal()
            pygp.card()
            
            # Get the actual keys based on key type (single vs set)
            if keys.get("type") == "single":
                enc_key = keys.get('key')
                mac_key = keys.get('key')
                dek_key = keys.get('key')
            else:  # type == "set"
                enc_key = keys.get('enc')
                mac_key = keys.get('mac')
                dek_key = keys.get('dek')
            
            # Validate keys
            for key_name, key_value in [('enc', enc_key), ('mac', mac_key), ('dek', dek_key)]:
                if not key_value:
                    raise ValueError(f"Missing key: {key_name}")
                if not isinstance(key_value, str):
                    raise TypeError(f"Key {key_name} is not a string: {type(key_value)}")
                # Validate hex format
                try:
                    int(key_value, 16)
                except ValueError:
                    raise ValueError(f"Key {key_name} contains invalid hex characters")
            
            # Lock: authenticate with DEFAULT keys and set to the LOADED keys
            DEFAULT_GP_KEY = "404142434445464748494A4B4C4D4E4F"
            pygp.auth(enc_key=DEFAULT_GP_KEY, mac_key=DEFAULT_GP_KEY, dek_key=DEFAULT_GP_KEY, keysetversion="00", securitylevel=pygp.SECURITY_LEVEL_C_DEC_C_MAC)
            pygp.set_key(f"01/1/DES/{enc_key.upper()}")
            pygp.set_key(f"01/2/DES/{mac_key.upper()}")
            pygp.set_key(f"01/3/DES/{dek_key.upper()}")
            pygp.put_scp_key("01", replace=True)
            self.loading_screen.stop()
            self.run_screen(LargeIconStatusScreen, title="Success", status_headline=None, text="Card Locked", show_back_button=False)
        except Exception as e:
            self.loading_screen.stop()
            self.run_screen(WarningScreen, title="Failed", status_headline=None, text=seedkeeper_utils.pygp_format_error(e)[:100], show_back_button=False)
        finally:
            seedkeeper_utils.restart_pn532(self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_INTERFACES))

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

def _get_internal_cap_dir() -> Path:
    """Return the internal javacard-cap directory. Extracted as a module-level
    function so tests can monkeypatch it to isolate from the real filesystem."""
    return Path(__file__).resolve().parents[3] / "javacard-cap"


class ToolsDIYInstallAppletView(View):
    """Install a .cap applet from either the internal repo folder or the MicroSD card.

    Searches both locations and merges the results. Files present in both
    locations are prefixed with ``(Internal)`` or ``(MicroSD)`` to disambiguate.
    If the MicroSD javacard-cap directory is absent the view falls back to the
    internal folder only.
    """

    def run(self):
        from subprocess import run
        import os
        import secrets
        from pathlib import Path
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.hardware.microsd import MicroSD

        internal_cap_dir = _get_internal_cap_dir()
        microsd_cap_dir = MicroSD.get_microsd_dir() / "javacard-cap"

        # Collect .cap files from each source
        internal_files = set()
        if internal_cap_dir.is_dir():
            for f in internal_cap_dir.iterdir():
                if f.is_file() and f.suffix.lower() == ".cap":
                    internal_files.add(f.name)

        microsd_files = set()
        if microsd_cap_dir.is_dir():
            try:
                for f in os.listdir(microsd_cap_dir):
                    if f.lower().endswith(".cap"):
                        microsd_files.add(f)
            except OSError:
                pass  # MicroSD absent or unreadable – silently skip

        # Build combined button list with prefixes for duplicates
        cap_entries = []  # list of (display_name, source_dir, filename)
        both = internal_files & microsd_files

        # Internal-only files first (alphabetical)
        for name in sorted(internal_files - microsd_files):
            cap_entries.append((name, str(internal_cap_dir), name))
        # Files in both sources – prefixed
        for name in sorted(both):
            cap_entries.append((f"(Internal) {name}", str(internal_cap_dir), name))
            cap_entries.append((f"(MicroSD) {name}", str(microsd_cap_dir), name))
        # MicroSD-only files last (alphabetical)
        for name in sorted(microsd_files - internal_files):
            cap_entries.append((name, str(microsd_cap_dir), name))

        if not cap_entries:
            self.run_screen(
                WarningScreen,
                title="No Applets Found",
                status_headline=None,
                text="No .cap files found.\n\nPlace .cap files in javacard-cap/ on the MicroSD card.",
                show_back_button=False,
            )
            return Destination(BackStackView)

        cap_file_buttons = [ButtonOption(entry[0]) for entry in cap_entries]

        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select Applet",
            is_button_text_centered=False,
            button_data=cap_file_buttons,
        )

        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        _display_name, cap_dir, applet_file = cap_entries[selected_file_num]
        logger.info("Selected: %s (from %s)", applet_file, cap_dir)

        if "seedkeeper" in applet_file.lower():
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

        self.loading_screen = LoadingScreenThread(text="Installing Applet")
        self.loading_screen.start()
        try:
            import pygp
            pygp.terminal()
            pygp.card()
            
            # Always establish secure channel, using provided keys or default test key
            DEFAULT_GP_KEY = "404142434445464748494A4B4C4D4E4F"
            try:
                if self.controller.javacard_keys:
                    keys = self.controller.javacard_keys
                    if keys.get("type") == "single":
                        pygp.auth(enc_key=keys.get('key'), mac_key=keys.get('key'), dek_key=keys.get('key'), keysetversion="00", securitylevel=pygp.SECURITY_LEVEL_C_MAC)
                    else:  # type == "set"
                        pygp.auth(enc_key=keys.get('enc'), mac_key=keys.get('mac'), dek_key=keys.get('dek'), keysetversion="00", securitylevel=pygp.SECURITY_LEVEL_C_MAC)
                    logger.info("Card authentication successful with custom keys")
                else:
                    # No custom keys provided, try default test key
                    pygp.auth(enc_key=DEFAULT_GP_KEY, mac_key=DEFAULT_GP_KEY, dek_key=DEFAULT_GP_KEY, keysetversion="00", securitylevel=pygp.SECURITY_LEVEL_C_MAC)
                    logger.info("Card authentication successful with default key")
            except Exception as e:
                logger.warning(f"Card authentication failed: {str(e)}, attempting install anyway")
            
            cap_path = f"{cap_dir}/{applet_file}"
            
            ndef_conflict_detected = False
            
            try:
                if "smartpgp" in applet_file.lower():
                    serial_hex = secrets.token_bytes(4).hex().upper()
                    aid = f"D276000124010304C0FE{serial_hex}0000"
                    logger.info("SmartPGP AID: %s", aid)
                    result = pygp.install_capfile(cap_path, instance_aids=[aid])
                    success_text = f"Applet Installed\nSerial: {serial_hex}"
                elif "seedkeeper" in applet_file.lower():
                    result = pygp.install_capfile(cap_path, application_specific_parameters=storage_param)
                    success_text = "Applet Installed"
                else:
                    result = pygp.install_capfile(cap_path)
                    success_text = "Applet Installed"
                
                # Handle both old return format (list) and new format (dict)
                if isinstance(result, dict):
                    ndef_conflict_detected = result.get('ndef_skipped', False)
                else:
                    # Fallback for older PyGP versions that return list
                    ndef_conflict_detected = False
            except Exception as e:
                # Re-raise to be caught by outer exception handler
                raise
                
            self.loading_screen.stop()
            
            # Inform user if PyGP reported NDEF conflict handling
            if ndef_conflict_detected:
                self.run_screen(
                    WarningScreen,
                    title="Info",
                    status_headline=None,
                    text="NDEF applet was automatically skipped to avoid conflicts.",
                    show_back_button=False,
                )
            
            self.run_screen(LargeIconStatusScreen, title="Success", status_headline=None, text=success_text, show_back_button=False)
            
        except Exception as e:
            self.loading_screen.stop()
            error_msg = seedkeeper_utils.pygp_format_error(e)[:100]
            logger.error(f"Install failed: {str(e)}")
            self.run_screen(WarningScreen, title="Failed", status_headline=None, text=error_msg, show_back_button=False)
            # Try to uninstall if it failed partially
            if "0x6444" in str(e) or "0x6F00" in str(e) or "SCARD_E_NOT_TRANSACTED" in str(e):
                self.loading_screen = LoadingScreenThread(text="Uninstalling Applet")
                self.loading_screen.start()
                try:
                    pkg_aid = pygp.get_cap_info(cap_path).get_aid()
                    pygp.delete_package(pkg_aid)
                    self.loading_screen.stop()
                    self.run_screen(WarningScreen, title="Failed", status_headline=None, text="Mis-Installed Applet Uninstalled", show_back_button=False)
                except Exception:
                    self.loading_screen.stop()

        finally:
            seedkeeper_utils.restart_pn532(self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_INTERFACES))

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

        self.loading_screen = LoadingScreenThread(text="Checking Installed Applets")
        self.loading_screen.start()
        
        package_aids = None
        error_message = None
        
        try:
            import pygp
            pygp.terminal()
            pygp.card()
            
            # Always try to establish secure channel first, like the CLI does
            # This is required for get_status() to return the full package list
            # Use provided keys or fall back to default test key
            DEFAULT_GP_KEY = "404142434445464748494A4B4C4D4E4F"
            try:
                if self.controller.javacard_keys:
                    keys = self.controller.javacard_keys
                    if keys.get("type") == "single":
                        pygp.auth(enc_key=keys.get('key'), mac_key=keys.get('key'), dek_key=keys.get('key'), keysetversion="00", securitylevel=pygp.SECURITY_LEVEL_C_MAC)
                    else:  # type == "set"
                        pygp.auth(enc_key=keys.get('enc'), mac_key=keys.get('mac'), dek_key=keys.get('dek'), keysetversion="00", securitylevel=pygp.SECURITY_LEVEL_C_MAC)
                    logger.info("Card authentication successful with custom keys")
                else:
                    # No custom keys provided, try default test key
                    pygp.auth(enc_key=DEFAULT_GP_KEY, mac_key=DEFAULT_GP_KEY, dek_key=DEFAULT_GP_KEY, keysetversion="00", securitylevel=pygp.SECURITY_LEVEL_C_MAC)
                    logger.info("Card authentication successful with default key")
            except Exception as e:
                # Authentication failed - log warning but continue
                # Some operations might still work without secure channel
                logger.warning(f"Card authentication failed: {str(e)}, attempting to list packages anyway")
            
            try:
                # Get the list of loaded package AIDs from pygp (public API)
                # Note: This requires secure channel to be established (via auth above)
                package_aids = pygp.get_loaded_package_aids()
                logger.info(f"Loaded package AIDs: {package_aids}")
            except Exception as e:
                logger.warning(f"Could not list packages: {str(e)}")
        except Exception as e:
            error_message = str(e)
            logger.error(f"Smartcard error: {error_message}")
        finally:
            self.loading_screen.stop()

        if error_message:
            self.run_screen(WarningScreen, title="Smartcard Error", status_headline=None, text=error_message[:100], show_back_button=False)
            return Destination(BackStackView)

        if package_aids is not None:
            installed_applets_aids = []
            installed_applets_list = []

            # Get module-to-package mapping
            try:
                module_map = pygp.get_package_module_map()
            except Exception as e:
                module_map = {}
                logger.warning(f"Could not get module map: {str(e)}")
            
            # Also get installed applications to verify NDEF is actually instantiated
            try:
                installed_apps = pygp.get_installed_application_aids()
            except Exception as e:
                installed_apps = []
                logger.warning(f"Could not get installed apps: {str(e)}")
            
            # The NDEF application AID (the actual instantiated app)
            NDEF_APP_AID = 'D2760000850101'
            ndef_is_active = NDEF_APP_AID in [aid.upper() for aid in installed_apps]
            
            # Known NDEF module AIDs - mark packages containing these with "+NDEF"
            ndef_module_aids = (
                'A000000804000102',      # Keycard NDEF
                '536565644B656570657201', # SeedKeeper NDEF
            )
            
            # If NDEF is active, identify all packages containing NDEF modules
            packages_with_ndef = set()
            if ndef_is_active:
                for ndef_module_aid in ndef_module_aids:
                    provider_pkg = module_map.get(ndef_module_aid.upper())
                    if provider_pkg:
                        packages_with_ndef.add(provider_pkg.upper())

            for aid in package_aids:
                # Ignore system packages
                if aid in ['A0000001515350', 'A00000016443446F634C697465', 'A0000000620204', 'A0000000620202','D00000000002','4B4D313031']:
                    continue
                
                name = aid
                if aid == 'A00000052721010141504558': name="Apex TOTP"
                if aid == 'D27600012401': name="SmartPGP"
                if aid == 'B00B5111CB': name="SpecterDIY"
                if aid == 'A0000008040001': 
                    name="Keycard"
                    # Show "+NDEF" if this package contains NDEF modules and NDEF is active
                    if aid.upper() in packages_with_ndef:
                        name = "Keycard+NDEF"
                if aid == 'A0000008040002': name="Keycard Math"
                if aid == 'A000000804000101': name="Keycard Applet"
                if aid == 'A000000804000102': name="Keycard NDEF"
                if aid == 'A000000804000103': name="Keycard Cash"
                if aid == 'A000000804000104': name="Keycard Ident"
                if aid == '536565644B6565706572': 
                    name="SeedKeeper"
                    # Show "+NDEF" if this package contains NDEF modules and NDEF is active
                    if aid.upper() in packages_with_ndef:
                        name = "SeedKeeper+NDEF"
                if aid == '536565644B656570657200': 
                    name="SeedKeeper"
                    # Show "+NDEF" if this package contains NDEF modules and NDEF is active
                    if aid.upper() in packages_with_ndef:
                        name = "SeedKeeper+NDEF"
                if aid == '536565644B656570657201': name="SeedKeeper NDEF"
                if aid == '5361746F43686970': name="Satochip"
                if aid == '5361746F44696D65': name="SatoDime"

                installed_applets_list.append(ButtonOption(name))
                installed_applets_aids.append(aid)

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

                self.loading_screen = LoadingScreenThread(text="Uninstalling Applet")
                self.loading_screen.start()
                try:
                    pygp.terminal()
                    pygp.card()
                    
                    # Always establish secure channel for delete operations
                    DEFAULT_GP_KEY = "404142434445464748494A4B4C4D4E4F"
                    try:
                        if self.controller.javacard_keys:
                            keys = self.controller.javacard_keys
                            if keys.get("type") == "single":
                                pygp.auth(enc_key=keys.get('key'), mac_key=keys.get('key'), dek_key=keys.get('key'), keysetversion="00", securitylevel=pygp.SECURITY_LEVEL_C_MAC)
                            else:  # type == "set"
                                pygp.auth(enc_key=keys.get('enc'), mac_key=keys.get('mac'), dek_key=keys.get('dek'), keysetversion="00", securitylevel=pygp.SECURITY_LEVEL_C_MAC)
                            logger.info("Card authentication successful with custom keys")
                        else:
                            # No custom keys provided, try default test key
                            pygp.auth(enc_key=DEFAULT_GP_KEY, mac_key=DEFAULT_GP_KEY, dek_key=DEFAULT_GP_KEY, keysetversion="00", securitylevel=pygp.SECURITY_LEVEL_C_MAC)
                            logger.info("Card authentication successful with default key")
                    except Exception as e:
                        logger.warning(f"Card authentication failed: {str(e)}, attempting delete anyway")
                    
                    pygp.delete_package(applet_aid)
                    self.loading_screen.stop()
                    self.run_screen(
                        LargeIconStatusScreen,
                        title="Success",
                        status_headline=None,
                        text="Applet Uninstalled",
                        show_back_button=False,
                    )
                except Exception as e:
                    self.loading_screen.stop()
                    self.run_screen(
                        WarningScreen,
                        title="Failed",
                        status_headline=None,
                        text=seedkeeper_utils.pygp_format_error(e)[:100],
                        show_back_button=False,
                    )

            else:
                self.run_screen(
                    WarningScreen,
                    title="Notice",
                    status_headline=None,
                    text="No Applets to Uninstall",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")]
                )

        seedkeeper_utils.restart_pn532(self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_INTERFACES))

        return Destination(ToolsSatochipDIYView)

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


