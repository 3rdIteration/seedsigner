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
    ToolsTextQRTextEntryScreen, ToolsTextQRReviewTextScreen,
    ToolsTextQRTranscribeModePromptScreen, ToolsTranscribeTextQRWholeQRScreen, ToolsTranscribeTextQRZoomedInScreen,
    ToolsTranscribeTextQRConfirmQRPromptScreen, ToolsNetworkInfoScreen,
    ToolsBatteryCalibrationIntroScreen, ToolsBatteryCalibrationStartScreen, ToolsBatteryCalibrationRunningScreen)
from seedsigner.helpers.iso7816 import format_sw_error
from seedsigner.models.decode_qr import DecodeQR
from seedsigner.models.encode_qr import GenericStaticQrEncoder
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.settings_definition import SettingsConstants

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
    TEXTQRCODE = ButtonOption("Text QR Code")
    MICROSD = ButtonOption("MicroSD Tools")
    BATTERY_CALIBRATION = ButtonOption("Battery Calibration")
    NETWORK_INFO = ButtonOption("Network Info")
    STEALTH_BOOT = ButtonOption("Stealth boot")

    def run(self):
        from seedsigner.hardware.battery_hat import BatteryHat
        battery_calibration_button = self.BATTERY_CALIBRATION if BatteryHat.get_instance().is_enabled() else None

        button_data = [
            self.TEXTQRCODE,
            self.MICROSD,
            battery_calibration_button,
            self.NETWORK_INFO if Path("/usr/bin/network-info").is_file() else None,
            self.STEALTH_BOOT,
        ]
        button_data = [button for button in button_data if button is not None]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Tools"),
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.TEXTQRCODE:
            return Destination(ToolsTextQRView)

        elif button_data[selected_menu_num] == self.MICROSD:
            return Destination(ToolsMicroSDMenuView)

        elif button_data[selected_menu_num] == self.BATTERY_CALIBRATION:
            return Destination(ToolsBatteryCalibrationView)

        elif button_data[selected_menu_num] == self.NETWORK_INFO:
            return Destination(ToolsNetworkInfoView)

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


class ToolsSeedkeeperView(View):
    VIEW_FREE_SPACE = ButtonOption("View Free Space")
    VIEW_SECRETS = ButtonOption("View Secrets on Card")
    IMPORT_PASSWORD = ButtonOption("Save Password to Card")
    DELETE_SECRET = ButtonOption("Delete Secret from Card")
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

JAVACARD_KEYS_MICROSD_FILENAME = "javacard-keys.txt"
JAVACARD_KEYS_SEEDKEEPER_PREFIX = "jc_keys_"


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
