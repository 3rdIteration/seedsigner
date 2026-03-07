import logging
import random
import time
import hashlib
import os
import binascii
from pathlib import Path

from binascii import hexlify
from gettext import gettext as _

from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from typing import List
from PIL import Image
from PIL.ImageOps import autocontrast
import shamir_mnemonic

from seedsigner.gui.components import FontAwesomeIconConstants, SeedSignerIconConstants
from seedsigner.gui.screens import (RET_CODE__BACK_BUTTON, ButtonListScreen,
    WarningScreen, DireWarningScreen, seed_screens, LargeIconStatusScreen)
from seedsigner.gui.screens.screen import ButtonOption, KeyboardScreen
from seedsigner.hardware.microsd import MicroSD
from seedsigner.helpers.bitbox02_backup import (
    Bitbox02BackupDetails,
    Bitbox02BackupError,
    decode_bitbox02_backup,
    format_timestamp,
)
from seedsigner.helpers.passport_backup import (
    PassportBackupDetails,
    PassportBackupError,
    decode_passport_backup,
)
from seedsigner.helpers.tapsigner_backup import (
    TapsignerBackupError,
    decode_tapsigner_backup,
)
from seedsigner.models.encode_qr import CompactSeedQrEncoder, GenericStaticQrEncoder, SeedQrEncoder, SpecterXPubQrEncoder, StaticXpubQrEncoder, UrXpubQrEncoder
from seedsigner.models.qr_type import QRType
from seedsigner.models.seed import Seed, Slip39Seed, ElectrumSeed, XprvSeed, InvalidSeedException, SeedWordsUnavailableException
from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.models.settings_definition import SettingsDefinition
from seedsigner.models.threads import BaseThread, ThreadsafeCounter
from seedsigner.views.view import NotYetImplementedView, OptionDisabledView, View, Destination, BackStackView, MainMenuView

from pysatochip.JCconstants import SEEDKEEPER_DIC_TYPE, SEEDKEEPER_DIC_ORIGIN, SEEDKEEPER_DIC_EXPORT_RIGHTS, BIP39_WORDLIST_DIC
from pysatochip.util import dict_swap_keys_values
from seedsigner.helpers import seedkeeper_utils
from binascii import unhexlify

logger = logging.getLogger(__name__)


class SeedsMenuView(View):
    LOAD = ButtonOption("Load a seed")

    def __init__(self):
        super().__init__()
        self.seeds = []
        for seed in self.controller.storage.seeds:
            self.seeds.append({
                "fingerprint": seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK)),
                "seed_type": self.get_seed_type_label(seed),
            })

    @staticmethod
    def get_seed_type_label(seed: Seed) -> str:
        if isinstance(seed, Slip39Seed):
            return "SLIP39"
        if isinstance(seed, XprvSeed):
            return "XPRV"
        if isinstance(seed, ElectrumSeed):
            return "ELEC"
        return "BIP39"


    def run(self):
        if not self.seeds:
            # Nothing to do here unless we have a seed loaded
            return Destination(LoadSeedView, clear_history=True)

        button_data = []
        for seed in self.seeds:
            button_data.append(
                ButtonOption(
                    f"{seed['fingerprint']} ({seed['seed_type']})",
                    SeedSignerIconConstants.FINGERPRINT,
                )
            )
        button_data.append(self.LOAD)

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("In-Memory Seeds"),
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif len(self.seeds) > 0 and selected_menu_num < len(self.seeds):
            return Destination(SeedOptionsView, view_args={"seed_num": selected_menu_num})

        elif button_data[selected_menu_num] == self.LOAD:
            return Destination(LoadSeedView)



class SeedSelectSeedView(View):
    """
    Reusable seed selection UI. Prompts the user to select amongst the already-loaded
    seeds OR to load a seed.

    * `flow`: indicates which user flow is in progress during seed selection (e.g.
                verify single sig addr or sign message).
    """
    SCAN_SEED = ButtonOption("Scan a seed", SeedSignerIconConstants.QRCODE)
    BITBOX_BACKUP = ButtonOption("BitBox02 backup", SeedSignerIconConstants.MICROSD)
    PASSPORT_BACKUP = ButtonOption("Passport backup", SeedSignerIconConstants.MICROSD)
    TAPSIGNER_BACKUP = ButtonOption("TAPSIGNER backup", SeedSignerIconConstants.MICROSD)
    SATOCHIP = ButtonOption("Use Satochip card", SeedSignerIconConstants.FINGERPRINT)
    TYPE_12WORD = ButtonOption("Enter 12-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=12)
    TYPE_15WORD = ButtonOption("Enter 15-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=15)
    TYPE_18WORD = ButtonOption("Enter 18-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=18)
    TYPE_21WORD = ButtonOption("Enter 21-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=21)
    TYPE_24WORD = ButtonOption("Enter 24-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=24)
    TYPE_ELECTRUM = ButtonOption("Enter Electrum seed", FontAwesomeIconConstants.KEYBOARD)
    TYPE_SLIP39 = ButtonOption("SLIP-39 Shares", FontAwesomeIconConstants.KEYBOARD)

    def __init__(self, flow: str):
        super().__init__()
        self.flow = flow

    def run(self):
        from seedsigner.controller import Controller
        seeds = self.controller.storage.seeds

        if self.flow == Controller.FLOW__VERIFY_SINGLESIG_ADDR:
            title = _("Verify Address")
            if not seeds:
                text = _("Load the seed to verify")
            else: 
                text = _("Select seed to verify")

        elif self.flow == Controller.FLOW__SIGN_MESSAGE:
            title = _("Sign Message")
            if not seeds:
                text = _("Load the seed to sign with")
            else:
                text = _("Select seed to sign with")

        else:
            raise Exception(f"Unsupported `flow` specified: {self.flow}")

        button_data = []
        for seed in seeds:
            button_str = seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
            button_data.append(ButtonOption(button_str, SeedSignerIconConstants.FINGERPRINT, icon_color="blue"))
        if self.flow in [Controller.FLOW__SIGN_MESSAGE, Controller.FLOW__VERIFY_SINGLESIG_ADDR]:
            button_data.append(self.SATOCHIP)

        button_data.append(self.SCAN_SEED)
        if self.settings.get_value(SettingsConstants.SETTING__BITBOX_BACKUP) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.BITBOX_BACKUP)
        if self.settings.get_value(SettingsConstants.SETTING__PASSPORT_BACKUP) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.PASSPORT_BACKUP)

        if self.settings.get_value(SettingsConstants.SETTING__TAPSIGNER_BACKUP) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TAPSIGNER_BACKUP)
        seed_lengths = self.settings.get_value(SettingsConstants.SETTING__SEED_WORD_LENGTHS)
        options = {
            12: self.TYPE_12WORD,
            15: self.TYPE_15WORD,
            18: self.TYPE_18WORD,
            21: self.TYPE_21WORD,
            24: self.TYPE_24WORD,
        }
        for l in seed_lengths:
            button_data.append(options[l])

        if self.settings.get_value(SettingsConstants.SETTING__ELECTRUM_SEEDS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TYPE_ELECTRUM)
        if self.settings.get_value(SettingsConstants.SETTING__SLIP39_SEEDS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TYPE_SLIP39)

        selected_menu_num = self.run_screen(
            seed_screens.SeedSelectSeedScreen,
            title=title,
            text=text,
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        if len(seeds) > 0 and selected_menu_num < len(seeds):
            # User selected one of the n seeds
            view_args = dict(seed_num=selected_menu_num)
            if self.flow == Controller.FLOW__VERIFY_SINGLESIG_ADDR:
                return Destination(SeedAddressVerificationView, view_args=view_args)

            elif self.flow == Controller.FLOW__SIGN_MESSAGE:
                self.controller.sign_message_data["seed_num"] = selected_menu_num
                return Destination(SeedSignMessageConfirmMessageView)

        self.controller.resume_main_flow = self.flow

        if self.flow == Controller.FLOW__VERIFY_SINGLESIG_ADDR and button_data[selected_menu_num] == self.SATOCHIP:
            from seedsigner.views.tools_views import SatochipLoadDescriptorScriptTypeView
            return Destination(SatochipLoadDescriptorScriptTypeView)

        if self.flow == Controller.FLOW__SIGN_MESSAGE and button_data[selected_menu_num] == self.SATOCHIP:
            connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip"])
            if not connector:
                return Destination(BackStackView)
            self.controller.sign_message_with_satochip = True
            self.controller.sign_message_data["seed_num"] = None
            return Destination(SeedSignMessageConfirmMessageView)

        if button_data[selected_menu_num] == self.SCAN_SEED:
            from seedsigner.views.scan_views import ScanView
            return Destination(ScanView)

        if button_data[selected_menu_num] == self.BITBOX_BACKUP:
            return Destination(SeedBitbox02BackupSelectView)

        if button_data[selected_menu_num] == self.PASSPORT_BACKUP:
            return Destination(SeedPassportBackupSelectView)

        if button_data[selected_menu_num] == self.TAPSIGNER_BACKUP:
            return Destination(SeedTapsignerBackupSelectView)

        elif button_data[selected_menu_num] in [self.TYPE_12WORD, self.TYPE_15WORD, self.TYPE_18WORD, self.TYPE_21WORD, self.TYPE_24WORD]:
            from seedsigner.views.seed_views import SeedMnemonicEntryView
            self.controller.storage.init_pending_mnemonic(num_words=button_data[selected_menu_num].return_data)
            return Destination(SeedMnemonicEntryView)

        elif button_data[selected_menu_num] == self.TYPE_ELECTRUM:
            return Destination(SeedElectrumMnemonicStartView)

        elif button_data[selected_menu_num] == self.TYPE_SLIP39:
            return Destination(SeedSlip39MnemonicStartView)



"""****************************************************************************
    Loading seeds, passphrases, etc
****************************************************************************"""
class LoadSeedView(View):
    SEED_QR = ButtonOption(" Scan a SeedQR", SeedSignerIconConstants.QRCODE)
    TYPE_12WORD = ButtonOption("Enter 12-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=12)
    TYPE_15WORD = ButtonOption("Enter 15-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=15)
    TYPE_18WORD = ButtonOption("Enter 18-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=18)
    TYPE_21WORD = ButtonOption("Enter 21-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=21)
    TYPE_24WORD = ButtonOption("Enter 24-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=24)
    TYPE_ELECTRUM = ButtonOption("Enter Electrum seed", FontAwesomeIconConstants.KEYBOARD)
    TYPE_SLIP39 = ButtonOption("SLIP-39 Shares", FontAwesomeIconConstants.KEYBOARD)
    IMPORT_SEEDKEEPER = ButtonOption("From SeedKeeper", FontAwesomeIconConstants.LOCK)
    BITBOX_BACKUP = ButtonOption("BitBox02 backup", SeedSignerIconConstants.MICROSD)
    PASSPORT_BACKUP = ButtonOption("Passport backup", SeedSignerIconConstants.MICROSD)
    TAPSIGNER_BACKUP = ButtonOption("TAPSIGNER backup", SeedSignerIconConstants.MICROSD)
    CREATE = ButtonOption(" Create a seed", SeedSignerIconConstants.PLUS)

    def run(self):
        seed_lengths = self.settings.get_value(SettingsConstants.SETTING__SEED_WORD_LENGTHS)
        options = {
            12: self.TYPE_12WORD,
            15: self.TYPE_15WORD,
            18: self.TYPE_18WORD,
            21: self.TYPE_21WORD,
            24: self.TYPE_24WORD,
        }

        # Start with the option to scan a SeedQR
        button_data = [self.SEED_QR]
        button_data.extend([options[l] for l in seed_lengths])

        if self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_SUPPORT) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.IMPORT_SEEDKEEPER)

        if self.settings.get_value(SettingsConstants.SETTING__SLIP39_SEEDS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TYPE_SLIP39)

        if self.settings.get_value(SettingsConstants.SETTING__BITBOX_BACKUP) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.BITBOX_BACKUP)

        if self.settings.get_value(SettingsConstants.SETTING__PASSPORT_BACKUP) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.PASSPORT_BACKUP)

        if self.settings.get_value(SettingsConstants.SETTING__TAPSIGNER_BACKUP) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TAPSIGNER_BACKUP)

        button_data.append(self.CREATE)

        if self.settings.get_value(SettingsConstants.SETTING__ELECTRUM_SEEDS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TYPE_ELECTRUM)

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Load A Seed"),
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.SEED_QR:
            from .scan_views import ScanSeedQRView
            return Destination(ScanSeedQRView)

        elif button_data[selected_menu_num] in [self.TYPE_12WORD, self.TYPE_15WORD, self.TYPE_18WORD, self.TYPE_21WORD, self.TYPE_24WORD]:
            self.controller.storage.init_pending_mnemonic(num_words=button_data[selected_menu_num].return_data)
            return Destination(SeedMnemonicEntryView)

        elif button_data[selected_menu_num] == self.IMPORT_SEEDKEEPER:
            return Destination(SeedKeeperSelectView)

        elif button_data[selected_menu_num] == self.TYPE_ELECTRUM:
            return Destination(SeedElectrumMnemonicStartView)

        elif button_data[selected_menu_num] == self.TYPE_SLIP39:
            return Destination(SeedSlip39MnemonicStartView)

        elif button_data[selected_menu_num] == self.BITBOX_BACKUP:
            return Destination(SeedBitbox02BackupSelectView)

        elif button_data[selected_menu_num] == self.PASSPORT_BACKUP:
            return Destination(SeedPassportBackupSelectView)

        elif button_data[selected_menu_num] == self.TAPSIGNER_BACKUP:
            return Destination(SeedTapsignerBackupSelectView)

        elif button_data[selected_menu_num] == self.CREATE:
            from .tools_views import ToolsMenuView
            return Destination(ToolsMenuView, view_args={"include_password_generator": False})
    
class SeedKeeperSelectView(View):
    def entropy_to_mnemonic(self, entropy_bytes, wordlist):
        from mnemonic import Mnemonic
        print(f"Worldlist: {wordlist}")

        mnemonic_obj = Mnemonic(wordlist)
        mnemonic = mnemonic_obj.to_mnemonic(entropy_bytes)

        return mnemonic # str

    @staticmethod
    def _decode_seedkeeper_text(secret_hex: str) -> str:
        """Decode a Seedkeeper UTF-8 payload with optional 1/2-byte length prefix."""
        raw = bytes.fromhex(secret_hex)
        if len(raw) >= 2 and int.from_bytes(raw[:2], "big") == len(raw[2:]):
            return raw[2:].decode("utf-8")
        if len(raw) >= 1 and raw[0] == len(raw[1:]):
            return raw[1:].decode("utf-8")
        return raw.decode("utf-8")

    @staticmethod
    def _extract_xprv_from_masterseed_secret(secret_hex: str) -> str:
        """Load legacy xprv payloads stored in a Masterseed subtype 0 secret."""
        secret_raw_bytes = bytes.fromhex(secret_hex)

        candidates: list[str] = []
        if secret_raw_bytes:
            size = secret_raw_bytes[0]
            if len(secret_raw_bytes) >= 1 + size:
                try:
                    candidates.append(secret_raw_bytes[1:1 + size].decode("utf-8"))
                except UnicodeDecodeError:
                    pass

        for decode_attempt in (
            lambda: SeedKeeperSelectView._decode_seedkeeper_text(secret_hex),
            lambda: secret_raw_bytes.decode("utf-8"),
        ):
            try:
                candidates.append(decode_attempt())
            except UnicodeDecodeError:
                continue

        for candidate in candidates:
            if candidate.startswith(("xprv", "tprv")):
                return candidate

        raise ValueError("Unsupported Masterseed subtype 0 payload")


    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        try:
            Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])

            if not Satochip_Connector:
                return Destination(BackStackView)

            self.loading_screen = LoadingScreenThread(text="Listing Seeds\n\n\n\n\n\n")
            self.loading_screen.start()

            headers = Satochip_Connector.seedkeeper_list_secret_headers()
            self.loading_screen.stop()

            headers_parsed = []
            button_data = []

            for header in headers:
                sid = header['id']
                label = header['label']
                stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))
                subtype = header['subtype']
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header['export_rights'], hex(header['export_rights']))

                if ((stype == "BIP39 mnemonic" and export_rights == 'Plaintext export allowed') or
                        (stype == 'Masterseed' and subtype == 0x01) or
                        (stype == 'Masterseed' and subtype == 0x00) or
                        (stype == 'Data' and label.startswith('XPRV:') and export_rights == 'Plaintext export allowed') or
                        (stype == 'Electrum mnemonic' and export_rights == 'Plaintext export allowed')):

                    if not label:
                        label = "Unnamed Secret"

                    headers_parsed.append({
                        "sid": sid,
                        "label": label,
                        "stype": stype,
                        "subtype": subtype
                    })
                    button_data.append(ButtonOption(label))

            if len(headers_parsed) < 1:
                self.run_screen(
                    WarningScreen,
                    title="No Secrets to Load",
                    text="No BIP39 Secrets to Load from Seedkeeper",
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

            selected_header = headers_parsed[selected_menu_num]
            sid = selected_header["sid"]
            stype = selected_header["stype"]
            subtype = selected_header["subtype"]

            self.loading_screen = LoadingScreenThread(text="Loading Seed\n\n\n\n\n\n")
            self.loading_screen.start()

            secret_dict = Satochip_Connector.seedkeeper_export_secret(sid, None)
            self.loading_screen.stop()

            assert stype == SEEDKEEPER_DIC_TYPE.get(secret_dict['type'], hex(secret_dict['type']))

            if stype == 'BIP39 mnemonic' or stype == 'Electrum mnemonic':
                secret_dict['secret'] = unhexlify(secret_dict['secret'])[1:].decode().rstrip("\x00")
                bip39_secret = secret_dict['secret']
                secret_size = secret_dict['secret_list'][0]
                secret_mnemonic = bip39_secret[:secret_size]
                secret_passphrase = bip39_secret[secret_size + 1:]

            elif stype == 'Masterseed' and subtype == 0x01:
                secret_raw_bytes = bytes.fromhex(secret_dict['secret'])
                offset = 0
                masterseed_size = secret_raw_bytes[offset]
                offset += 1
                masterseed_bytes = secret_raw_bytes[offset:offset + masterseed_size]
                offset += masterseed_size
                wordlist_byte = secret_raw_bytes[offset]
                offset += 1
                wordlist = BIP39_WORDLIST_DIC.get(wordlist_byte)
                entropy_size = secret_raw_bytes[offset]
                offset += 1
                entropy_bytes = secret_raw_bytes[offset:offset + entropy_size]
                offset += entropy_size
                bip39_mnemonic = self.entropy_to_mnemonic(entropy_bytes, wordlist)
                passphrase_size = secret_raw_bytes[offset]
                offset += 1
                passphrase_bytes = secret_raw_bytes[offset:offset + passphrase_size]
                offset += passphrase_size
                passphrase = passphrase_bytes.decode("utf-8")
                secret_mnemonic = bip39_mnemonic
                secret_passphrase = passphrase

            elif stype == 'Masterseed' and subtype == 0x00:
                xprv = self._extract_xprv_from_masterseed_secret(secret_dict['secret'])
                self.controller.storage.set_pending_seed(XprvSeed(xprv))
                return Destination(SeedFinalizeView)

            elif stype == 'Data':
                xprv = self._decode_seedkeeper_text(secret_dict['secret']).strip()
                if not xprv.startswith(("xprv", "tprv")):
                    raise ValueError("Selected Seedkeeper data entry is not an xprv")
                self.controller.storage.set_pending_seed(XprvSeed(xprv))
                return Destination(SeedFinalizeView)

            else:
                raise ValueError(f"Unsupported secret type: {stype}, subtype: {subtype}")

        except Exception as e:
            print("General Exception Loading Seed:", str(e))
            self.loading_screen.stop()
            time.sleep(0.1)
            self.run_screen(
                WarningScreen,
                title="Error",
                text=str(e),
                show_back_button=True,
            )
            return Destination(BackStackView)

        mnemonic = secret_mnemonic.split(" ")
        self.controller.storage.init_pending_mnemonic(num_words=len(mnemonic), is_electrum=(stype == 'Electrum mnemonic'))
        for i, word in enumerate(mnemonic):
            self.controller.storage.update_pending_mnemonic(word, i)

        from seedsigner.models.seed import InvalidSeedException
        try:
            self.controller.storage.convert_pending_mnemonic_to_pending_seed(
                wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE),
            )
        except InvalidSeedException:
            return Destination(SeedMnemonicInvalidView)

        if len(secret_passphrase) > 0:
            self.seed = self.controller.storage.get_pending_seed()
            self.seed.set_passphrase(secret_passphrase)
            return Destination(SeedReviewPassphraseView)

        return Destination(SeedFinalizeView)


class SeedBitbox02BackupSelectView(View):
    def __init__(self):
        super().__init__()
        self.microsd_dir: Path = MicroSD.get_microsd_dir()
        self.extensions = {".bin", ".dat", ".bb02", ".backup"}

    def _get_backup_files(self) -> list[Path]:
        backup_files: list[Path] = []
        if not self.microsd_dir.exists():
            raise Bitbox02BackupError(_("microSD card not detected."))
        for path in self.microsd_dir.rglob("*"):
            if not path.is_file():
                continue

            try:
                rel_parts = path.relative_to(self.microsd_dir).parts
            except ValueError:
                continue

            if any(part.startswith(".") for part in rel_parts):
                continue

            if path.suffix.lower() in self.extensions:
                backup_files.append(path)

        backup_files.sort(key=lambda p: p.relative_to(self.microsd_dir).as_posix().lower())
        return backup_files

    def run(self):
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

        try:
            backup_files = self._get_backup_files()
        except Exception as e:
            logger.exception("Failed to scan microSD for BitBox02 backups", exc_info=e)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        if not backup_files:
            self.run_screen(
                WarningScreen,
                title=_("No Backups Found"),
                status_headline=None,
                text=_("No BitBox02 backups (.bin, .bb02, .dat, .backup) were found on the microSD card."),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        button_data = [
            ButtonOption(path.relative_to(self.microsd_dir).as_posix(), SeedSignerIconConstants.MICROSD)
            for path in backup_files
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Select BitBox02 backup"),
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        selected_path = backup_files[selected_menu_num]

        try:
            details = decode_bitbox02_backup(selected_path.read_bytes())
        except (OSError, Bitbox02BackupError, ValueError) as e:
            logger.exception("Failed to load BitBox02 backup", exc_info=e)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(SeedBitbox02BackupSelectView)

        try:
            seed = Seed(details.mnemonic)
        except InvalidSeedException:
            return Destination(SeedMnemonicInvalidView)

        self.controller.storage.set_pending_seed(seed)

        return Destination(SeedBitbox02BackupSummaryView, view_args={"details": details})


class SeedBitbox02BackupSummaryView(View):
    CONTINUE = ButtonOption(_("Continue"))

    def __init__(self, details: Bitbox02BackupDetails):
        super().__init__()
        self.details = details

    def run(self):
        text_lines = []
        if self.details.name:
            text_lines.append(_("Backup name: {}").format(self.details.name))
        if self.details.timestamp:
            text_lines.append(_("Created: {}").format(format_timestamp(self.details.timestamp)))
        if self.details.generator:
            text_lines.append(_("Firmware: {}").format(self.details.generator))
        if self.details.birthdate:
            text_lines.append(_("Birthdate: {}").format(format_timestamp(self.details.birthdate)))
        text_lines.append(_("Seed length: {} words").format(len(self.details.mnemonic)))

        self.run_screen(
            LargeIconStatusScreen,
            title=_("BitBox02 backup"),
            status_headline=_("Seed loaded"),
            text="\n".join(text_lines),
            show_back_button=False,
            button_data=[self.CONTINUE],
        )

        return Destination(SeedFinalizeView)


class SeedPassportBackupSelectView(View):
    def __init__(self):
        super().__init__()
        self.microsd_dir: Path = MicroSD.get_microsd_dir()
        self.extensions = {".7z"}

    def _get_backup_files(self) -> list[Path]:
        backup_files: list[Path] = []
        if not self.microsd_dir.exists():
            raise PassportBackupError(_("microSD card not detected."))

        for path in self.microsd_dir.rglob("*"):
            if not path.is_file():
                continue

            try:
                rel_parts = path.relative_to(self.microsd_dir).parts
            except ValueError:
                continue

            if any(part.startswith(".") for part in rel_parts):
                continue

            if path.suffix.lower() in self.extensions:
                backup_files.append(path)

        backup_files.sort(key=lambda p: p.relative_to(self.microsd_dir).as_posix().lower())
        return backup_files

    def run(self):
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

        try:
            backup_files = self._get_backup_files()
        except Exception as e:
            logger.exception("Failed to scan microSD for Passport backups", exc_info=e)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        if not backup_files:
            self.run_screen(
                WarningScreen,
                title=_("No Backups Found"),
                status_headline=None,
                text=_("No Passport backups (.7z) were found on the microSD card."),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        button_data = [
            ButtonOption(path.relative_to(self.microsd_dir).as_posix(), SeedSignerIconConstants.MICROSD)
            for path in backup_files
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Select Passport backup"),
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        selected_path = backup_files[selected_menu_num]

        return Destination(
            SeedPassportBackupCodeEntryView,
            view_args={"backup_path": selected_path},
        )


class SeedPassportBackupCodeEntryView(View):
    def __init__(self, backup_path: Path):
        super().__init__()
        self.backup_path = Path(backup_path)

    def run(self):
        backup_code = self.run_screen(
            KeyboardScreen,
            title=_("Passport backup code"),
            rows=4,
            cols=5,
            keys_charset="0123456789",
            show_save_button=True,
        )

        if backup_code == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        backup_code = str(backup_code).strip()
        if not backup_code:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=_("Backup code cannot be empty."),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(SeedPassportBackupCodeEntryView, view_args={"backup_path": self.backup_path})

        try:
            details = decode_passport_backup(self.backup_path, backup_code)
        except (OSError, PassportBackupError, ValueError) as e:
            logger.exception("Failed to load Passport backup", exc_info=e)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(SeedPassportBackupCodeEntryView, view_args={"backup_path": self.backup_path})

        try:
            seed = Seed(details.mnemonic)
        except InvalidSeedException:
            return Destination(SeedMnemonicInvalidView)

        self.controller.storage.set_pending_seed(seed)

        return Destination(SeedPassportBackupSummaryView, view_args={"details": details})


class SeedPassportBackupSummaryView(View):
    CONTINUE = ButtonOption(_("Continue"))

    def __init__(self, details: PassportBackupDetails):
        super().__init__()
        self.details = details

    def run(self):
        text_lines = []
        if self.details.chain:
            text_lines.append(_("Chain: {}".format(self.details.chain)))
        if self.details.xfp:
            text_lines.append(_("XFP: {}".format(self.details.xfp)))
        if self.details.firmware:
            text_lines.append(_("Firmware: {}".format(self.details.firmware)))
        text_lines.append(_("Seed length: {} words").format(len(self.details.mnemonic)))

        self.run_screen(
            LargeIconStatusScreen,
            title=_("Passport backup"),
            status_headline=_("Seed loaded"),
            text="\n".join(text_lines),
            show_back_button=False,
            button_data=[self.CONTINUE],
        )

        return Destination(SeedFinalizeView)


class SeedTapsignerBackupSelectView(View):
    def __init__(self):
        super().__init__()
        self.microsd_dir: Path = MicroSD.get_microsd_dir()

    def _get_backup_files(self) -> list[Path]:
        backup_files: list[Path] = []
        if not self.microsd_dir.exists():
            raise TapsignerBackupError(_("microSD card not detected."))

        for path in self.microsd_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() == ".aes":
                backup_files.append(path)

        backup_files.sort(key=lambda p: p.relative_to(self.microsd_dir).as_posix().lower())
        return backup_files

    def run(self):
        try:
            backup_files = self._get_backup_files()
        except Exception as e:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        if not backup_files:
            self.run_screen(
                WarningScreen,
                title=_("No Backups Found"),
                status_headline=None,
                text=_("No TAPSIGNER backups (.aes) were found on the microSD card."),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        selected = self.run_screen(
            ButtonListScreen,
            title=_("Select TAPSIGNER backup"),
            is_button_text_centered=False,
            button_data=[ButtonOption(path.relative_to(self.microsd_dir).as_posix(), SeedSignerIconConstants.MICROSD) for path in backup_files],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(SeedTapsignerBackupKeyEntryView, view_args={"backup_path": backup_files[selected]})


class SeedTapsignerBackupKeyEntryView(View):
    def __init__(self, backup_path: Path):
        super().__init__()
        self.backup_path = backup_path

    def run(self):
        key_hex = self.run_screen(
            KeyboardScreen,
            title=_("Backup key (hex)"),
            rows=4,
            cols=8,
            keys_charset="0123456789abcdef",
            show_save_button=True,
        )
        if key_hex == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        try:
            xprv, derivation_path = decode_tapsigner_backup(self.backup_path, str(key_hex))
            self.controller.storage.set_pending_seed(XprvSeed(xprv))
        except (OSError, TapsignerBackupError, InvalidSeedException) as e:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(SeedTapsignerBackupKeyEntryView, view_args={"backup_path": self.backup_path})

        return Destination(SeedTapsignerBackupSummaryView, view_args={"derivation_path": derivation_path})


class SeedTapsignerBackupSummaryView(View):
    def __init__(self, derivation_path: str | None):
        super().__init__()
        self.derivation_path = derivation_path

    def run(self):
        text = _("xprv loaded from TAPSIGNER backup.")
        if self.derivation_path:
            text = text + "\n" + _("Path: {}".format(self.derivation_path))

        self.run_screen(
            LargeIconStatusScreen,
            title=_("TAPSIGNER backup"),
            status_headline=_("Seed loaded"),
            text=text,
            show_back_button=False,
            button_data=[ButtonOption(_("Continue"))],
        )
        return Destination(SeedFinalizeView)


class SeedMnemonicEntryView(View):
    def __init__(self, cur_word_index: int = 0, is_calc_final_word: bool=False):
        super().__init__()
        self.cur_word_index = cur_word_index
        self.cur_word = self.controller.storage.get_pending_mnemonic_word(cur_word_index)
        self.is_calc_final_word = is_calc_final_word


    def run(self):
        ret = self.run_screen(
            seed_screens.SeedMnemonicEntryScreen,
            # TRANSLATOR_NOTE: Inserts the word number (e.g. "Seed Word #6")
            title=_("Seed Word #{}").format(self.cur_word_index + 1),  # Human-readable 1-indexing!
            initial_letters=list(self.cur_word) if self.cur_word else ["a"],
            wordlist=Seed.get_wordlist(wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)),
        )

        if ret == RET_CODE__BACK_BUTTON:
            if self.cur_word_index > 0:
                return Destination(BackStackView)
            else:
                self.controller.storage.discard_pending_mnemonic()
                return Destination(MainMenuView)
        
        # ret will be our new mnemonic word
        self.controller.storage.update_pending_mnemonic(ret, self.cur_word_index)

        if self.is_calc_final_word and self.cur_word_index == self.controller.storage.pending_mnemonic_length - 2:
            # Time to calculate the last word. User must decide how they want to specify
            # the last bits of entropy for the final word.
            from seedsigner.views.tools_views import ToolsCalcFinalWordFinalizePromptView
            return Destination(ToolsCalcFinalWordFinalizePromptView)

        if self.is_calc_final_word and self.cur_word_index == self.controller.storage.pending_mnemonic_length - 1:
            # Time to calculate the last word. User must either select a final word to
            # contribute entropy to the checksum word OR we assume 0 ("abandon").
            from seedsigner.views.tools_views import ToolsCalcFinalWordShowFinalWordView
            return Destination(ToolsCalcFinalWordShowFinalWordView)

        if self.cur_word_index < self.controller.storage.pending_mnemonic_length - 1:
            return Destination(
                SeedMnemonicEntryView,
                view_args={
                    "cur_word_index": self.cur_word_index + 1,
                    "is_calc_final_word": self.is_calc_final_word
                }
            )
        else:
            # Attempt to finalize the mnemonic
            from seedsigner.models.seed import InvalidSeedException
            try:
                self.controller.storage.convert_pending_mnemonic_to_pending_seed(
                    wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE),
                )
            except InvalidSeedException:
                return Destination(SeedMnemonicInvalidView)

            return Destination(SeedFinalizeView)



class SeedMnemonicInvalidView(View):
    EDIT = ButtonOption("Review & Edit")
    DISCARD = ButtonOption("Discard", button_label_color="red")

    def __init__(self):
        super().__init__()
        self.mnemonic: list[str] = self.controller.storage.pending_mnemonic


    def run(self):
        button_data = [self.EDIT, self.DISCARD]
        selected_menu_num = self.run_screen(
            DireWarningScreen,
            title=_("Invalid Mnemonic!"),
            status_icon_name=SeedSignerIconConstants.ERROR,
            status_headline=None,
            text=_("Checksum failure; not a valid seed phrase."),
            show_back_button=False,
            button_data=button_data,
        )

        if button_data[selected_menu_num] == self.EDIT:
            return Destination(SeedMnemonicEntryView, view_args={"cur_word_index": 0})

        elif button_data[selected_menu_num] == self.DISCARD:
            self.controller.storage.discard_pending_mnemonic()
            return Destination(MainMenuView)



class SeedFinalizeView(View):
    FINALIZE = ButtonOption("Done")
    LOAD_SEEDKEEPER = ButtonOption("Load Passphrase")
    TYPE_PASSPHRASE = ButtonOption("Type Passphrase")
    SCAN_PASSPHRASE = ButtonOption("Scan Passphrase")

    def __init__(self):
        super().__init__()
        self.seed = self.controller.storage.get_pending_seed()

        if isinstance(self.seed, XprvSeed):
            self.fingerprint = self.seed.get_fingerprint(network=self.settings.get_value(SettingsConstants.SETTING__NETWORK))
            return

        if self.seed.get_fingerprint == "":
            # Expected normal user flow
            self.fingerprint = self.seed.get_fingerprint(network=self.settings.get_value(SettingsConstants.SETTING__NETWORK))

        else:
            # This view should display the "naked" seed's fingerprint. Normally the
            # just-loaded seed would be naked, but this is special handling for the
            # screenshot generator which creates a pending seed w/a passphrase already
            # set.
            passphrase = self.seed.passphrase
            if isinstance(self.seed, Slip39Seed):
                self.seed.set_slip39_passphrase("")
            else:
                self.seed.set_passphrase("")
            self.fingerprint = self.seed.get_fingerprint(network=self.settings.get_value(SettingsConstants.SETTING__NETWORK))
            if isinstance(self.seed, Slip39Seed):
                self.seed.set_slip39_passphrase(passphrase)
            else:
                self.seed.set_passphrase(passphrase)


    def run(self):
        button_data = [self.FINALIZE]
        #self.TYPE_PASSPHRASE.button_label = self.seed.passphrase_label
        if isinstance(self.seed, XprvSeed):
            pass
        elif self.settings.get_value(SettingsConstants.SETTING__PASSPHRASE) != SettingsConstants.OPTION__DISABLED:
            button_data.append(self.TYPE_PASSPHRASE)
            button_data.append(self.SCAN_PASSPHRASE)
            if self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_SUPPORT) == SettingsConstants.OPTION__ENABLED:
                button_data.append(self.LOAD_SEEDKEEPER)

        selected_menu_num = self.run_screen(
            seed_screens.SeedFinalizeScreen,
            fingerprint=self.fingerprint,
            button_data=button_data,
        )

        if button_data[selected_menu_num] == self.FINALIZE:
            seed_num = self.controller.storage.finalize_pending_seed()
            return Destination(SeedOptionsView, view_args={"seed_num": seed_num}, clear_history=True)

        elif button_data[selected_menu_num] == self.TYPE_PASSPHRASE:
            return Destination(SeedAddPassphraseView)

        elif button_data[selected_menu_num] == self.SCAN_PASSPHRASE:
            return Destination(SeedScanPassphraseView)

        elif button_data[selected_menu_num] == self.LOAD_SEEDKEEPER:
            return Destination(SeedLoadSeedKeeperPassphraseView)

        elif selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)



class SeedAddPassphraseView(View):
    """
    initial_keyboard: used by the screenshot generator to render each different keyboard layout.
    """
    def __init__(self, initial_keyboard: str = seed_screens.SeedAddPassphraseScreen.KEYBOARD__LOWERCASE_BUTTON_TEXT):
        super().__init__()
        self.initial_keyboard = initial_keyboard
        self.seed = self.controller.storage.get_pending_seed()


    def run(self):
        passphrase_title=self.seed.passphrase_label
        ret_dict = self.run_screen(
            seed_screens.SeedAddPassphraseScreen,
            passphrase=self.seed.passphrase_display,
            title=passphrase_title,
            initial_keyboard=self.initial_keyboard,
        )

        passphrase = ret_dict["passphrase"]
        if isinstance(self.seed, Slip39Seed):
            self.seed.set_slip39_passphrase(passphrase)
        else:
            # The new passphrase will be the return value; it might be empty.
            self.seed.set_passphrase(passphrase)

        if "is_back_button" in ret_dict:
            if len(self.seed.passphrase) > 0:
                return Destination(SeedAddPassphraseExitDialogView)
            else:
                return Destination(SeedFinalizeView)
            
        elif len(self.seed.passphrase) > 0:
            return Destination(SeedReviewPassphraseView)
        
        else:
            return Destination(SeedFinalizeView)



class SeedAddPassphraseExitDialogView(View):
    EDIT = ButtonOption("Edit passphrase")
    DISCARD = ButtonOption("Discard passphrase", button_label_color="red")

    def __init__(self):
        super().__init__()
        self.seed = self.controller.storage.get_pending_seed()


    def run(self):
        button_data = [self.EDIT, self.DISCARD]
        
        selected_menu_num = self.run_screen(
            WarningScreen,
            title=_("Discard passphrase?"),
            status_headline=None,
            text=_("Your current passphrase entry will be erased"),
            show_back_button=False,
            button_data=button_data,
        )

        if button_data[selected_menu_num] == self.EDIT:
            return Destination(SeedAddPassphraseView)

        elif button_data[selected_menu_num] == self.DISCARD:
            if isinstance(self.seed, Slip39Seed):
                self.seed.set_slip39_passphrase("")
            else:
                self.seed.set_passphrase("")
            return Destination(SeedFinalizeView)

class SeedScanPassphraseView(View):
    def __init__(self):
        super().__init__()
        self.seed = self.controller.storage.get_pending_seed()

    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.models.decode_qr import DecodeQR
        decoder = DecodeQR(is_passphrase=True)
        self.run_screen(
            ScanScreen,
            instructions_text=_("Scan Passphrase"),
            decoder=decoder
        )
        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)
        if decoder.is_complete:
            passphrase = self.seed.passphrase_display + decoder.get_passphrase()
            if isinstance(self.seed, Slip39Seed):
                self.controller.storage.get_pending_seed().set_slip39_passphrase(passphrase)
            else:
                self.controller.storage.get_pending_seed().set_passphrase(passphrase)
            return Destination(SeedReviewPassphraseView)
        elif decoder.is_nonUTF8:
            DireWarningScreen(
                title=_("Error!"),
                show_back_button=False,
                status_headline=_("Invalid Text QR Code"),
                text=_("Non UTF-8 data detected.")
            ).display()
            return Destination(BackStackView)
        else:
            return Destination(BackStackView)

class SeedLoadSeedKeeperPassphraseView(View):
    def __init__(self):
        super().__init__()
        self.seed = self.controller.storage.get_pending_seed()

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
                label = header['label']
                stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))  # hex(header['type'])
                origin = SEEDKEEPER_DIC_ORIGIN.get(header['origin'], hex(header['origin']))  # hex(header['origin'])
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header['export_rights'],
                                                                 hex(header[
                                                                         'export_rights']))  # str(header['export_rights'])
                export_nbplain = str(header['export_nbplain'])
                export_nbsecure = str(header['export_nbsecure'])
                export_nbcounter = str(header['export_counter']) if header['type'] == 0x70 else 'N/A'
                fingerprint = header['fingerprint']

                if stype == "Password" and export_rights == 'Plaintext export allowed':
                    headers_parsed.append((sid, label))
                    button_data.append(ButtonOption(label))

            print(headers_parsed)
            if len(headers_parsed) < 1:
                self.run_screen(
                WarningScreen,
                title="No Secrets to Load",
                status_headline=None,
                text=f"No Password Secrets to Load from Seedkeeper",
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

            # Parse the Password (Ignore the other elements like login and url)
            password_length = secret_dict['secret_list'][0]

            secret_passphrase = binascii.unhexlify(secret_dict['secret'])[1:password_length+1].decode()

        except Exception as e:
            print(e)
            self.loading_screen.stop()
            time.sleep(0.1) # Sleep for 100ms
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=True,
            )
            return Destination(BackStackView)
        
        # The new passphrase will be the return value; it might be empty.
        if isinstance(self.seed, Slip39Seed):
            self.seed.set_slip39_passphrase(secret_passphrase)
        else:
            self.seed.set_passphrase(secret_passphrase)
        if len(self.seed.passphrase) > 0:
            return Destination(SeedReviewPassphraseView)
        else:
            return Destination(SeedFinalizeView)

class SeedReviewPassphraseView(View):
    """
        Display the completed passphrase back to the user.
    """
    DONE = ButtonOption("Done")
    EDIT = ButtonOption("Edit passphrase")
    SCAN = ButtonOption("Scan & Append Another")

    def __init__(self):
        super().__init__()
        self.seed = self.controller.storage.get_pending_seed()


    def run(self):
        # Get the before/after fingerprints
        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        passphrase = self.seed.passphrase
        fingerprint_with = self.seed.get_fingerprint(network=network)
        if isinstance(self.seed, Slip39Seed):
            self.seed.set_slip39_passphrase("")
        else:
            self.seed.set_passphrase("")
        fingerprint_without = self.seed.get_fingerprint(network=network)
        if isinstance(self.seed, Slip39Seed):
            self.seed.set_slip39_passphrase(passphrase)
        else:
            self.seed.set_passphrase(passphrase)
        
        button_data = [self.DONE, self.EDIT, self.SCAN]

        # Because we have an explicit "Edit" button, we disable "BACK" to keep the
        # routing options sane.
        selected_menu_num = self.run_screen(
            seed_screens.SeedReviewPassphraseScreen,
            fingerprint_without=fingerprint_without,
            fingerprint_with=fingerprint_with,
            passphrase=self.seed.passphrase_display,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            if isinstance(self.seed, Slip39Seed):
                self.seed.set_slip39_passphrase("")
            else:
                self.seed.set_passphrase("")
            return Destination(SeedFinalizeView)

        elif button_data[selected_menu_num] == self.DONE:
            seed_num = self.controller.storage.finalize_pending_seed()
            return Destination(SeedOptionsView, view_args={"seed_num": seed_num}, clear_history=True)
            
        elif button_data[selected_menu_num] == self.EDIT:
            return Destination(SeedAddPassphraseView)

        elif button_data[selected_menu_num] == self.SCAN:
            return Destination(SeedScanPassphraseView)



class SeedDiscardView(View):
    KEEP = ButtonOption("Keep Seed")
    DISCARD = ButtonOption("Discard", button_label_color="red")

    def __init__(self, seed_num: int = None):
        super().__init__()
        self.seed_num = seed_num
        if self.seed_num is not None:
            self.seed = self.controller.get_seed(self.seed_num)
        else:
            self.seed = self.controller.storage.pending_seed


    def run(self):
        button_data = [self.KEEP, self.DISCARD]

        fingerprint = self.seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
        # TRANSLATOR_NOTE: Inserts the seed fingerprint
        text = _("Wipe seed {} from the device?").format(fingerprint)
        selected_menu_num = self.run_screen(
            WarningScreen,
            title=_("Discard Seed?"),
            status_headline=None,
            text=text,
            show_back_button=False,
            button_data=button_data,
        )

        if button_data[selected_menu_num] == self.KEEP:
            # Use skip_current_view=True to prevent BACK from landing on this warning screen
            if self.seed_num is not None:
                return Destination(SeedOptionsView, view_args={"seed_num": self.seed_num}, skip_current_view=True)
            else:
                return Destination(SeedFinalizeView, skip_current_view=True)

        elif button_data[selected_menu_num] == self.DISCARD:
            if self.seed_num is not None:
                self.controller.discard_seed(self.seed_num)
            else:
                self.controller.storage.clear_pending_seed()
            return Destination(MainMenuView, clear_history=True)



class SeedElectrumMnemonicStartView(View):
    """
    Currently just a warning display before entering an Electrum seed.
    
    Could be expanded with a follow-up View to specify Electrum seed type.
    """
    def run(self):
        self.run_screen(
                WarningScreen,
                title=_("Electrum warning"),
                status_headline=None,
                text=_("Some features are disabled for Electrum seeds."),
                show_back_button=False,
        )

        self.controller.storage.init_pending_mnemonic(num_words=12, is_electrum=True)

        return Destination(SeedMnemonicEntryView)


class SeedSlip39MnemonicStartView(View):
    """Prompt before entering SLIP-39 shares."""

    def run(self):
        self.controller.storage.discard_pending_slip39_shares()

        TWENTY = ButtonOption("Enter 20 words")
        THIRTYTHREE = ButtonOption("Enter 33 words")
        SCAN = ButtonOption("Scan QR", SeedSignerIconConstants.QRCODE)
        SEEDKEEPER = ButtonOption("From SeedKeeper", FontAwesomeIconConstants.LOCK)
        button_data = [TWENTY, THIRTYTHREE, SCAN]
        if self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_SUPPORT) == SettingsConstants.OPTION__ENABLED:
            button_data.append(SEEDKEEPER)

        selected = self.run_screen(
            ButtonListScreen,
            title=_("Load Share"),
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected] == SCAN:
            from seedsigner.views.scan_views import ScanSlip39ShareQRView
            return Destination(ScanSlip39ShareQRView)

        if button_data[selected] == SEEDKEEPER:
            from seedsigner.views.seed_views import SeedSlip39LoadFromSeedkeeperView
            return Destination(SeedSlip39LoadFromSeedkeeperView)

        length = 20 if button_data[selected] == TWENTY else 33
        self.controller.storage.init_pending_slip39_share(num_words=length)
        return Destination(SeedSlip39ShareEntryView)


class SeedSlip39ShareEntryView(View):
    def __init__(self, cur_word_index: int = 0):
        super().__init__()
        self.cur_word_index = cur_word_index
        self.cur_word = self.controller.storage.get_pending_slip39_word(cur_word_index)

    def run(self):
        from importlib import import_module
        slip39_wordlist = import_module("shamir_mnemonic.wordlist").WORDLIST
        ret = self.run_screen(
            seed_screens.SeedMnemonicEntryScreen,
            title=_("Share Word #{}").format(self.cur_word_index + 1),
            initial_letters=list(self.cur_word) if self.cur_word else ["a"],
            wordlist=slip39_wordlist,
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        self.controller.storage.update_pending_slip39_share(ret, self.cur_word_index)

        if self.cur_word_index < self.controller.storage.pending_slip39_share_length - 1:
            return Destination(
                SeedSlip39ShareEntryView,
                view_args={"cur_word_index": self.cur_word_index + 1}
            )
        else:
            from seedsigner.models.seed import InvalidSeedException
            try:
                self.controller.storage.finalize_current_slip39_share()
            except InvalidSeedException:
                length = self.controller.storage.pending_slip39_share_length
                self.controller.storage.init_pending_slip39_share(num_words=length)
                return Destination(
                    SeedSlip39ShareInvalidView,
                    view_args={"length": length, "retry_scan": False},
                    skip_current_view=True,
                )
            return Destination(SeedSlip39MoreSharesView)


class SeedSlip39MoreSharesView(View):
    ADD = ButtonOption("Enter share")
    SCAN = ButtonOption("Scan share", SeedSignerIconConstants.QRCODE)
    SEEDKEEPER = ButtonOption("From SeedKeeper", FontAwesomeIconConstants.LOCK)
    DONE = ButtonOption("Combine shares")

    def run(self):
        entered = self.controller.storage.slip39_shares_entered
        needed = self.controller.storage.slip39_total_needed
        if needed > entered:
            button_data = [self.ADD, self.SCAN]
            if self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_SUPPORT) == SettingsConstants.OPTION__ENABLED:
                button_data.append(self.SEEDKEEPER)
        else:
            button_data = [self.DONE]
        info_text = None
        if needed:
            info_text = _("{} of {} needed").format(entered, needed)
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=info_text,
            is_button_text_centered=False,
            button_data=button_data,
        )

        if button_data[selected_menu_num] == self.ADD:
            self.controller.storage.init_pending_slip39_share()
            return Destination(SeedSlip39ShareEntryView)

        elif button_data[selected_menu_num] == self.SCAN:
            from seedsigner.views.scan_views import ScanSlip39ShareQRView
            return Destination(ScanSlip39ShareQRView)

        elif button_data[selected_menu_num] == self.SEEDKEEPER:
            from seedsigner.views.seed_views import SeedSlip39LoadFromSeedkeeperView
            return Destination(SeedSlip39LoadFromSeedkeeperView)

        from seedsigner.gui.screens.screen import LoadingScreenThread
        self.loading_screen = LoadingScreenThread(text="Combining Shares\n\n\n\n\n\n")
        self.loading_screen.start()
        try:
            self.controller.storage.convert_pending_slip39_shares_to_pending_seed()
        finally:
            time.sleep(1)
            self.loading_screen.stop()

        return Destination(SeedFinalizeView)


class SeedSlip39ShareInvalidView(View):
    def __init__(self, length: int, retry_scan: bool):
        super().__init__()
        self.length = length
        self.retry_scan = retry_scan

    def run(self):
        from seedsigner.gui.screens.screen import DireWarningScreen
        button = ButtonOption("Try Again")
        self.run_screen(
            DireWarningScreen,
            title=_("Invalid SLIP-39 Share"),
            show_back_button=False,
            status_icon_name=SeedSignerIconConstants.ERROR,
            status_headline=None,
            text=_("Checksum failure; not a valid SLIP-39 share."),
            button_data=[button],
        )

        if self.retry_scan:
            from seedsigner.views.scan_views import ScanSlip39ShareQRView
            return Destination(ScanSlip39ShareQRView, skip_current_view=True)
        else:
            self.controller.storage.init_pending_slip39_share(num_words=self.length)
            return Destination(SeedSlip39ShareEntryView, skip_current_view=True)


class SeedSlip39SelectShareView(View):
    def __init__(self, seed_num: int, next_view, **next_args):
        super().__init__()
        self.seed_num = seed_num
        self.next_view = next_view
        self.next_args = next_args

    def run(self):
        seed = self.controller.get_seed(self.seed_num)
        button_data = [ButtonOption(f"Share {i+1}") for i in range(len(seed.mnemonic_list))]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Share",
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        self.next_args.update({"seed_num": self.seed_num, "share_index": selected})
        return Destination(self.next_view, view_args=self.next_args)


class SeedSlip39LoadFromSeedkeeperView(View):
    """Load a SLIP-39 share from a SeedKeeper card."""

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
                stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))
                rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header['export_rights'], hex(header['export_rights']))
                label = header['label']
                if stype == "Password" and rights == 'Plaintext export allowed' and label.startswith("SLIP39:"):
                    headers_parsed.append(header['id'])
                    button_data.append(ButtonOption(label[len("SLIP39:"):]))

            if not headers_parsed:
                self.run_screen(
                    WarningScreen,
                    title="No Secrets to Load",
                    text="No SLIP39 Shares on SeedKeeper",
                    show_back_button=False,
                )
                return Destination(BackStackView)

            selected = self.run_screen(
                ButtonListScreen,
                title="Select Share",
                is_button_text_centered=False,
                button_data=button_data,
                show_back_button=True,
            )
            if selected == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            self.loading_screen = LoadingScreenThread(text="Loading Secret\n\n\n\n\n\n")
            self.loading_screen.start()
            secret_dict = Satochip_Connector.seedkeeper_export_secret(headers_parsed[selected], None)
            self.loading_screen.stop()

            length = secret_dict['secret_list'][0]
            share = binascii.unhexlify(secret_dict['secret'])[1:length+1].decode()

            from seedsigner.models.seed import InvalidSeedException
            try:
                self.controller.storage.add_slip39_share_mnemonic(share)
            except InvalidSeedException:
                return Destination(
                    SeedSlip39ShareInvalidView,
                    view_args={"length": len(share.split()), "retry_scan": False},
                    skip_current_view=True,
                )
        except Exception as e:
            print(e)
            if hasattr(self, 'loading_screen'):
                self.loading_screen.stop()
            self.run_screen(
                WarningScreen,
                title="Error",
                text=str(e),
                show_back_button=True,
            )
            return Destination(BackStackView)

        return Destination(SeedSlip39MoreSharesView, skip_current_view=True)


class SeedSlip39CreateFromBytesView(View):
    """Create a SLIP-39 seed from entropy bytes and start backup."""
    def __init__(self, secret: bytes):
        super().__init__()
        self.secret = secret

    def run(self):
        
        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title="Num Shares").display()
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        num_shares = int(ret)

        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title="Threshold").display()
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        threshold = int(ret)

        if threshold > num_shares:
            raise InvalidSeedException(
                "The requested threshold must not exceed the number of shares."
            )
        
        if threshold == 1 and num_shares > 1:
            raise InvalidSeedException(
                "Multi-Share with threshold of 1 not allowed."
            )

        extendable = (
            self.settings.get_value(SettingsConstants.SETTING__SLIP39_EXTENDABLE)
            == SettingsConstants.OPTION__ENABLED
        )
        shares = shamir_mnemonic.generate_mnemonics(
            1, [(threshold, num_shares)], self.secret, extendable=extendable
        )[0]
        seed = Slip39Seed(mnemonics=shares)
        self.controller.storage.set_pending_seed(seed)

        return Destination(SeedWordsWarningView, view_args={"seed_num": None, "share_index": 0}, clear_history=True)


class SeedSlip39RegenerateSharesView(View):
    """Regenerate SLIP-39 shares for an existing seed."""
    def __init__(self, seed_num: int):
        super().__init__()
        self.seed_num = seed_num
        self.seed = self.controller.get_seed(seed_num)
        self.seed_num = seed_num

    def run(self):
        if not self.seed.extendable:
            from seedsigner.gui.screens.screen import WarningScreen
            self.run_screen(
                WarningScreen,
                title=_("Non-extendable Seed"),
                show_back_button=False,
                status_icon_name=SeedSignerIconConstants.ERROR,
                status_headline=None,
                text=_("This SLIP-39 seed cannot regenerate new shares."),
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title="Num Shares").display()
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        num_shares = int(ret)

        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title="Threshold").display()
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        threshold = int(ret)

        self.seed.regenerate_shares(threshold, num_shares)
        return Destination(SeedWordsWarningView, view_args={"seed_num": self.seed_num, "share_index": 0})



"""****************************************************************************
    Views for actions on individual seeds:
****************************************************************************"""
class SeedOptionsView(View):
    SCAN_PSBT = ButtonOption("Scan PSBT", SeedSignerIconConstants.QRCODE)
    VERIFY_ADDRESS = ButtonOption("Verify Addr")
    EXPORT_XPUB = ButtonOption("Export Xpub")
    EXPLORER = ButtonOption("Address Explorer")
    SIGN_MESSAGE = ButtonOption("Sign Message")
    BACKUP = ButtonOption("Backup Seed", right_icon_name=SeedSignerIconConstants.CHEVRON_RIGHT)
    BIP85_CHILD_SEED = ButtonOption("BIP-85 Child Seed")
    DISCARD = ButtonOption("Discard Seed", button_label_color="red")


    def __init__(self, seed_num: int):
        super().__init__()
        self.seed_num = seed_num
        self.seed = self.controller.get_seed(self.seed_num)


    def run(self):
        from seedsigner.controller import Controller
        from seedsigner.views.psbt_views import PSBTOverviewView

        if self.controller.unverified_address:
            if self.controller.resume_main_flow == Controller.FLOW__VERIFY_SINGLESIG_ADDR:
                # Jump straight back into the single sig addr verification flow
                self.controller.resume_main_flow = None
                return Destination(SeedAddressVerificationView, view_args=dict(seed_num=self.seed_num), skip_current_view=True)

        if self.controller.resume_main_flow == Controller.FLOW__ADDRESS_EXPLORER:
            # Jump straight back into the address explorer script type selection flow
            # But don't cancel the `resume_main_flow` as we'll still need that after
            # derivation path is specified.
            return Destination(SeedExportXpubScriptTypeView, view_args=dict(seed_num=self.seed_num, sig_type=SettingsConstants.SINGLE_SIG), skip_current_view=True)

        elif self.controller.resume_main_flow == Controller.FLOW__SIGN_MESSAGE:
            self.controller.sign_message_data["seed_num"] = self.seed_num
            return Destination(SeedSignMessageConfirmMessageView, skip_current_view=True)

        if self.controller.psbt:
            from seedsigner.models.psbt_parser import PSBTParser
            if PSBTParser.has_matching_input_fingerprint(self.controller.psbt, self.seed, network=self.settings.get_value(SettingsConstants.SETTING__NETWORK)):
                if self.controller.resume_main_flow and self.controller.resume_main_flow == Controller.FLOW__PSBT:
                    # Re-route us directly back to the start of the PSBT flow
                    self.controller.resume_main_flow = None
                    self.controller.psbt_seed = self.seed
                    return Destination(PSBTOverviewView, skip_current_view=True)

        button_data = []

        if self.controller.unverified_address:
            # TODO: Verify that an addr verification flow can actually reach this code
            addr = self.controller.unverified_address["address"][:7]
            self.VERIFY_ADDRESS.button_label += f" {addr}"
            button_data.append(self.VERIFY_ADDRESS)

        button_data.append(self.SCAN_PSBT)
        
        if self.settings.get_value(SettingsConstants.SETTING__XPUB_EXPORT) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.EXPORT_XPUB)

        button_data.append(self.EXPLORER)
        button_data.append(self.BACKUP)

        if self.settings.get_value(SettingsConstants.SETTING__MESSAGE_SIGNING) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.SIGN_MESSAGE)
        
        if self.settings.get_value(SettingsConstants.SETTING__BIP85_CHILD_SEEDS) == SettingsConstants.OPTION__ENABLED and self.seed.bip85_supported:
            button_data.append(self.BIP85_CHILD_SEED)

        button_data.append(self.DISCARD)
        
        selected_menu_num = self.run_screen(
            seed_screens.SeedOptionsScreen,
            button_data=button_data,
            fingerprint=self.seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK)),
            has_passphrase=self.seed.passphrase is not None,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            # Force BACK to always return to the Main Menu
            return Destination(MainMenuView)

        if button_data[selected_menu_num] == self.SCAN_PSBT:
            from seedsigner.views.scan_views import ScanPSBTView
            self.controller.psbt_seed = self.controller.get_seed(self.seed_num)
            return Destination(ScanPSBTView)

        elif button_data[selected_menu_num] == self.VERIFY_ADDRESS:
            return Destination(SeedAddressVerificationView, view_args=dict(seed_num=self.seed_num))

        elif button_data[selected_menu_num] == self.EXPORT_XPUB:
            return Destination(SeedExportXpubSigTypeView, view_args=dict(seed_num=self.seed_num))

        elif button_data[selected_menu_num] == self.EXPLORER:
            self.controller.resume_main_flow = Controller.FLOW__ADDRESS_EXPLORER
            return Destination(SeedExportXpubScriptTypeView, view_args=dict(seed_num=self.seed_num, sig_type=SettingsConstants.SINGLE_SIG))

        elif button_data[selected_menu_num] == self.SIGN_MESSAGE:
            from seedsigner.views.scan_views import ScanView
            self.controller.sign_message_data = dict(seed_num=self.seed_num)
            self.controller.resume_main_flow = Controller.FLOW__SIGN_MESSAGE
            return Destination(ScanView)

        elif button_data[selected_menu_num] == self.BACKUP:
            return Destination(SeedBackupView, view_args=dict(seed_num=self.seed_num))

        elif button_data[selected_menu_num] == self.BIP85_CHILD_SEED:
            return Destination(SeedBIP85ApplicationModeView, view_args={"seed_num": self.seed_num})

        elif button_data[selected_menu_num] == self.DISCARD:
            return Destination(SeedDiscardView, view_args=dict(seed_num=self.seed_num))



class SeedBackupView(View):
    VIEW_WORDS = ButtonOption("View Seed Words")
    EXPORT_SEEDQR = ButtonOption("Export as SeedQR")
    EXPORT_PLAINTEXTQR = ButtonOption("Export as Plaintext QR")
    TO_SEEDKEEPER = ButtonOption("To SeedKeeper")
    REGENERATE_SHARES = ButtonOption("Regenerate Shares")

    def __init__(self, seed_num):
        super().__init__()
        self.seed_num = seed_num
        self.seed = self.controller.get_seed(self.seed_num)
    

    def run(self):

        button_data = [self.VIEW_WORDS]
        if self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_SUPPORT) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TO_SEEDKEEPER)
        if isinstance(self.seed, Slip39Seed):
            button_data.append(self.REGENERATE_SHARES)

        if self.seed.seedqr_supported:
            button_data.append(self.EXPORT_SEEDQR)

        if self.settings.get_value(SettingsConstants.SETTING__PLAINTEXTQR) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.EXPORT_PLAINTEXTQR)

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Backup Seed"),
            button_data=button_data,
            is_bottom_list=True,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.VIEW_WORDS:
            if isinstance(self.seed, Slip39Seed):
                return Destination(SeedSlip39SelectShareView, view_args={"seed_num": self.seed_num, "next_view": SeedWordsWarningView})
            return Destination(SeedWordsWarningView, view_args={"seed_num": self.seed_num})

        elif button_data[selected_menu_num] == self.EXPORT_PLAINTEXTQR:
            if isinstance(self.seed, Slip39Seed):
                return Destination(SeedSlip39SelectShareView, view_args={"seed_num": self.seed_num, "next_view": SeedExportPlaintextQRView})
            return Destination(SeedExportPlaintextQRView, view_args={"seed_num": self.seed_num})

        elif button_data[selected_menu_num] == self.EXPORT_SEEDQR:
            return Destination(SeedTranscribeSeedQRFormatView, view_args={"seed_num": self.seed_num})

        elif button_data[selected_menu_num] == self.TO_SEEDKEEPER:
            if isinstance(self.seed, Slip39Seed):
                return Destination(SeedSlip39SelectShareView, view_args={"seed_num": self.seed_num, "next_view": SaveToSeedkeeperView})
            return Destination(SaveToSeedkeeperView, view_args={"seed_num": self.seed_num})

        elif button_data[selected_menu_num] == self.REGENERATE_SHARES:
            return Destination(SeedSlip39RegenerateSharesView, view_args={"seed_num": self.seed_num})


"""****************************************************************************
    Export Xpub flow
****************************************************************************"""
class SeedExportXpubSigTypeView(View):
    SINGLE_SIG = ButtonOption("Single Sig", return_data=SettingsConstants.SINGLE_SIG)
    MULTISIG = ButtonOption("Multisig", return_data=SettingsConstants.MULTISIG)

    def __init__(self, seed_num: int):
        super().__init__()
        self.seed_num = seed_num


    def run(self):
        if len(self.settings.get_value(SettingsConstants.SETTING__SIG_TYPES)) == 1:
            # Nothing to select; skip this screen
            return Destination(SeedExportXpubScriptTypeView, view_args={"seed_num": self.seed_num, "sig_type": self.settings.get_value(SettingsConstants.SETTING__SIG_TYPES)[0]}, skip_current_view=True)

        button_data = [self.SINGLE_SIG, self.MULTISIG]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Export Xpub"),
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(SeedExportXpubScriptTypeView, view_args={"seed_num": self.seed_num, "sig_type": button_data[selected_menu_num].return_data})



class SeedExportXpubScriptTypeView(View):
    def __init__(self, seed_num: int, sig_type: str):
        super().__init__()
        self.seed_num = seed_num
        self.sig_type = sig_type


    def run(self):
        from seedsigner.controller import Controller
        from .tools_views import ToolsAddressExplorerAddressTypeView
        args = {"seed_num": self.seed_num, "sig_type": self.sig_type}

        script_types = self.settings.get_value(SettingsConstants.SETTING__SCRIPT_TYPES)

        seed = self.controller.storage.seeds[self.seed_num]
        if seed.script_override:
            # This seed only allows one script type
            # TODO: Does it matter if the Settings don't have the override script type
            # enabled?
            script_types = [seed.script_override]

        if len(script_types) == 1:
            # Nothing to select; skip this screen
            args["script_type"] = script_types[0]

            if args["script_type"] == SettingsConstants.CUSTOM_DERIVATION:
                return Destination(SeedExportXpubCustomDerivationView, view_args=args, skip_current_view=True)

            if (
                self.settings.get_value(SettingsConstants.SETTING__ACCOUNT_PROMPT)
                == SettingsConstants.OPTION__ENABLED
            ):
                if self.controller.resume_main_flow == Controller.FLOW__ADDRESS_EXPLORER:
                    del args["sig_type"]
                    return Destination(AccountNumberView, view_args=dict(next_view_cls=ToolsAddressExplorerAddressTypeView, next_view_args=args), skip_current_view=True)
                else:
                    return Destination(AccountNumberView, view_args=dict(next_view_cls=SeedExportXpubCoordinatorView, next_view_args=args), skip_current_view=True)
            else:
                if self.controller.resume_main_flow == Controller.FLOW__ADDRESS_EXPLORER:
                    del args["sig_type"]
                    return Destination(ToolsAddressExplorerAddressTypeView, view_args=args, skip_current_view=True)
                else:
                    return Destination(SeedExportXpubCoordinatorView, view_args=args, skip_current_view=True)
        
        title = _("Export Xpub")
        if self.controller.resume_main_flow == Controller.FLOW__ADDRESS_EXPLORER:
            title = _("Address Explorer")

        button_data = []
        for script_type, display_name in SettingsConstants.ALL_SCRIPT_TYPES:
            if script_type in self.settings.get_value(SettingsConstants.SETTING__SCRIPT_TYPES):
                button_data.append(ButtonOption(display_name, return_data=script_type))

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=title,
            is_button_text_centered=False,
            button_data=button_data,
            is_bottom_list=True,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            # If previous view is SeedOptionsView then that should be where resume_main_flow started (otherwise it would have been skipped).
            if len(self.controller.back_stack) >= 2 and self.controller.back_stack[-2].View_cls == SeedOptionsView:
                self.controller.resume_main_flow = None
            return Destination(BackStackView)

        else:
            args["script_type"] = button_data[selected_menu_num].return_data

            if args["script_type"] == SettingsConstants.CUSTOM_DERIVATION:
                return Destination(SeedExportXpubCustomDerivationView, view_args=args)

            if (
                self.settings.get_value(SettingsConstants.SETTING__ACCOUNT_PROMPT)
                == SettingsConstants.OPTION__ENABLED
            ):
                if self.controller.resume_main_flow == Controller.FLOW__ADDRESS_EXPLORER:
                    del args["sig_type"]
                    return Destination(AccountNumberView, view_args=dict(next_view_cls=ToolsAddressExplorerAddressTypeView, next_view_args=args))
                else:
                    return Destination(AccountNumberView, view_args=dict(next_view_cls=SeedExportXpubCoordinatorView, next_view_args=args))
            else:
                if self.controller.resume_main_flow == Controller.FLOW__ADDRESS_EXPLORER:
                    del args["sig_type"]
                    return Destination(ToolsAddressExplorerAddressTypeView, view_args=args)
                else:
                    return Destination(SeedExportXpubCoordinatorView, view_args=args)



class SeedExportXpubCustomDerivationView(View):
    def __init__(self, seed_num: int, sig_type: str, script_type: str):
        super().__init__()
        self.seed_num = seed_num
        self.sig_type = sig_type
        self.script_type = script_type
        self.custom_derivation_path = "m/"


    def run(self):
        from seedsigner.controller import Controller
        ret = self.run_screen(
            seed_screens.SeedExportXpubCustomDerivationScreen,
            initial_value=self.custom_derivation_path,
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        # ret will be the custom derivation path
        custom_derivation = ret

        if self.controller.resume_main_flow == Controller.FLOW__ADDRESS_EXPLORER:
            from .tools_views import ToolsAddressExplorerAddressTypeView
            return Destination(ToolsAddressExplorerAddressTypeView, view_args=dict(seed_num=self.seed_num, script_type=self.script_type, custom_derivation=custom_derivation))

        return Destination(
            SeedExportXpubCoordinatorView,
            view_args={
                "seed_num": self.seed_num,
                "sig_type": self.sig_type,
                "script_type": self.script_type,
                "custom_derivation": custom_derivation,
            }
        )



class AccountNumberView(View):
    def __init__(self, next_view_cls, next_view_args: dict):
        super().__init__()
        self.next_view_cls = next_view_cls
        self.next_view_args = next_view_args

    def run(self):
        ret = self.run_screen(
            seed_screens.SeedExportXpubAccountNumberScreen,
            initial_value="0",
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        self.next_view_args["account"] = int(ret)
        return Destination(self.next_view_cls, view_args=self.next_view_args)



class SeedExportXpubCoordinatorView(View):
    def __init__(self, seed_num: int, sig_type: str, script_type: str, custom_derivation: str = None, account: int = 0):
        super().__init__()
        self.seed_num = seed_num
        self.sig_type = sig_type
        self.script_type = script_type
        self.custom_derivation = custom_derivation
        self.account = account


    def run(self):
        args = {
            "seed_num": self.seed_num,
            "sig_type": self.sig_type,
            "script_type": self.script_type,
            "custom_derivation": self.custom_derivation,
            "account": self.account,
        }
        if len(self.settings.get_value(SettingsConstants.SETTING__COORDINATORS)) == 1:
            # Nothing to select; skip this screen
            args["coordinator"] = self.settings.get_value(SettingsConstants.SETTING__COORDINATORS)[0]
            entry = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__COORDINATORS)
            args["coordinator_label"] = entry.get_selection_option_display_name_by_value(args["coordinator"])
            return Destination(SeedExportXpubWarningView, view_args=args, skip_current_view=True)

        button_data = []
        for display_name, setting_option in zip(self.settings.get_multiselect_value_display_names(SettingsConstants.SETTING__COORDINATORS), self.settings.get_value(SettingsConstants.SETTING__COORDINATORS)):
            button_data.append(ButtonOption(display_name, return_data=setting_option))

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Export Xpub"),
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # coordinators_settings_entry = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__COORDINATORS)
        # selected_display_name = button_data[selected_menu_num]
        # args["coordinator"] = coordinators_settings_entry.get_selection_option_value_by_display_name(selected_display_name)
        args["coordinator"] = button_data[selected_menu_num].return_data
        args["coordinator_label"] = button_data[selected_menu_num].button_label

        return Destination(SeedExportXpubWarningView, view_args=args)



class SeedExportXpubWarningView(View):
    def __init__(self, seed_num: int, sig_type: str, script_type: str, coordinator: str, custom_derivation: str, coordinator_label: str, account: int = 0):
        super().__init__()
        self.seed_num = seed_num
        self.sig_type = sig_type
        self.script_type = script_type
        self.coordinator = coordinator
        self.custom_derivation = custom_derivation
        self.coordinator_label = coordinator_label
        self.account = account


    def run(self):
        destination = Destination(
            SeedExportXpubDetailsView,
            view_args={
                "seed_num": self.seed_num,
                "sig_type": self.sig_type,
                "script_type": self.script_type,
                "coordinator": self.coordinator,
                "custom_derivation": self.custom_derivation,
                "coordinator_label": self.coordinator_label,
                "account": self.account,
            },
            skip_current_view=True,  # Prevent going BACK to WarningViews
        )

        if self.settings.get_value(SettingsConstants.SETTING__PRIVACY_WARNINGS) == SettingsConstants.OPTION__DISABLED:
            # Skip the WarningView entirely
            return destination

        selected_menu_num = self.run_screen(
            WarningScreen,
            status_headline=_("Privacy Leak!"),
            text=_("Xpub can be used to view all future transactions."),
        )

        if selected_menu_num == 0:
            # User clicked "I Understand"
            return destination

        elif selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)



class SeedExportXpubDetailsView(View):
    """
        Collects the user input from all the previous screens leading up to this and
        finally calculates the xpub and displays the summary view to the user.
    """
    def __init__(self, seed_num: int, sig_type: str, script_type: str, coordinator: str, custom_derivation: str, coordinator_label: str, account: int = 0):
        super().__init__()
        self.sig_type = sig_type
        self.script_type = script_type
        self.coordinator = coordinator
        self.custom_derivation = custom_derivation
        self.coordinator_label = coordinator_label
        self.account = account

        self.seed_num = seed_num
        self.seed = self.controller.get_seed(self.seed_num)


    def run(self):
        seed_derivation_override = self.seed.derivation_override(self.sig_type)
        if self.script_type == SettingsConstants.CUSTOM_DERIVATION:
            derivation_path = self.custom_derivation
        elif seed_derivation_override:
            derivation_path = seed_derivation_override
        else:
            from seedsigner.helpers import embit_utils
            derivation_path = embit_utils.get_standard_derivation_path(
                network=self.settings.get_value(SettingsConstants.SETTING__NETWORK),
                wallet_type=self.sig_type,
                script_type=self.script_type,
                account=self.account,
            )

        if self.settings.get_value(SettingsConstants.SETTING__XPUB_DETAILS) == SettingsConstants.OPTION__DISABLED:
            # We're just skipping right past this screen
            selected_menu_num = 0

        else:
            # The derivation calc takes a few moments. Run the loading screen while we wait.
            from seedsigner.gui.screens.screen import LoadingScreenThread
            self.loading_screen = LoadingScreenThread(text=_("Generating xpub..."))
            self.loading_screen.start()

            try:
                from embit.bip32 import HDKey
                from embit.networks import NETWORKS
                embit_network = NETWORKS[SettingsConstants.map_network_to_embit(self.settings.get_value(SettingsConstants.SETTING__NETWORK))]
                version = self.seed.detect_version(
                    derivation_path,
                    self.settings.get_value(SettingsConstants.SETTING__NETWORK),
                    self.sig_type
                )
                root = self.seed.get_root(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
                fingerprint = hexlify(root.child(0).fingerprint).decode('utf-8')
                xprv = root.derive(derivation_path)
                xpub = xprv.to_public()
                xpub_base58 = xpub.to_string(version=version)

            finally:
                self.loading_screen.stop()

            selected_menu_num = self.run_screen(
                seed_screens.SeedExportXpubDetailsScreen,
                fingerprint=fingerprint,
                has_passphrase=self.seed.passphrase is not None,
                derivation_path=derivation_path,
                xpub=xpub_base58,
            )

        if selected_menu_num == 0:
            return Destination(
                SeedExportXpubQRDisplayView,
                dict(seed_num=self.seed_num,
                     coordinator=self.coordinator,
                     derivation_path=derivation_path,
                     sig_type=self.sig_type,
                     script_type=self.script_type,
                     coordinator_label=self.coordinator_label
                )
            )

        elif selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)



class SeedExportXpubQRDisplayView(View):
    def __init__(self, seed_num: int, coordinator: str, derivation_path: str, sig_type: str = SettingsConstants.SINGLE_SIG, script_type: str = SettingsConstants.NATIVE_SEGWIT, coordinator_label: str = ""):
        super().__init__()
        self.seed = self.controller.get_seed(seed_num)
        self.seed_num = seed_num
        self.script_type = script_type
        self.sig_type = sig_type
        self.derivation_path = derivation_path
        self.coordinator_label = coordinator_label

        encoder_args = dict(
            seed=self.seed,
            derivation=derivation_path,
            network=self.settings.get_value(SettingsConstants.SETTING__NETWORK),
            qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
            sig_type=sig_type
        )

        if coordinator == SettingsConstants.COORDINATOR__SPECTER_DESKTOP:
            self.qr_encoder = SpecterXPubQrEncoder(**encoder_args)

        elif coordinator in [SettingsConstants.COORDINATOR__BLUE_WALLET,
                             SettingsConstants.COORDINATOR__KEEPER]:
            self.qr_encoder = StaticXpubQrEncoder(**encoder_args)

        else:
            self.qr_encoder = UrXpubQrEncoder(**encoder_args)


    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=self.qr_encoder
        )
        if self.sig_type == SettingsConstants.SINGLE_SIG:
            return Destination(
                SeedExportXpubVerifyAddressView,
                view_args=dict(
                    seed_num=self.seed_num,
                    derivation_path=self.derivation_path,
                    script_type=self.script_type,
                    sig_type=self.sig_type,
                    coordinator_label=self.coordinator_label,
                ),
                skip_current_view=True,
            )
        return Destination(MainMenuView)


class SeedExportXpubVerifyAddressView(View):
    def __init__(self, seed_num: int, derivation_path: str, script_type: str, sig_type: str, coordinator_label: str):
        super().__init__()
        self.seed_num = seed_num
        self.derivation_path = derivation_path
        self.script_type = script_type
        self.sig_type = sig_type
        self.coordinator_label = coordinator_label

    def run(self):
        from seedsigner.gui.screens.screen import WarningScreen, ButtonOption
        from seedsigner.views.scan_views import ScanXpubAddressView
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Verify Address"),
            status_icon_name=SeedSignerIconConstants.QRCODE,
            status_headline=None,
            text=_("Open {} and display a receive address from the wallet you just exported.").format(self.coordinator_label),
            button_data=[ButtonOption(_("Scan"))],
            show_back_button=False,
        )

        return Destination(
            ScanXpubAddressView,
            view_args=dict(
                seed_num=self.seed_num,
                derivation_path=self.derivation_path,
                script_type=self.script_type,
                sig_type=self.sig_type,
                coordinator_label=self.coordinator_label,
            ),
            skip_current_view=True
        )



"""****************************************************************************
    View Seed Words flow
****************************************************************************"""
class SeedWordsWarningView(View):
    def __init__(self, seed_num: int, bip85_data: dict = None, share_index: int | None = None):
        super().__init__()
        self.seed_num = seed_num
        self.bip85_data = bip85_data
        self.share_index = share_index


    def run(self):
        destination = Destination(
            SeedWordsView,
            view_args=dict(
                seed_num=self.seed_num,
                page_index=0,
                bip85_data=self.bip85_data,
                share_index=self.share_index
            ),
            skip_current_view=True,  # Prevent going BACK to WarningViews
        )
        if self.settings.get_value(SettingsConstants.SETTING__DIRE_WARNINGS) == SettingsConstants.OPTION__DISABLED:
            # Forward straight to showing the words
            return destination

        selected_menu_num = self.run_screen(
            DireWarningScreen,
            text=_("You must keep your seed words private & away from all online devices."),
        )

        if selected_menu_num == 0:
            # User clicked "I Understand"
            return destination

        elif selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)



class SeedWordsView(View):
    NEXT = ButtonOption("Next")
    DONE = ButtonOption("Done")

    def __init__(self, seed_num: int, bip85_data: dict = None, page_index: int = 0, share_index: int | None = None):
        super().__init__()
        self.seed_num = seed_num
        if self.seed_num is None:
            self.seed = self.controller.storage.get_pending_seed()
        else:
            self.seed = self.controller.get_seed(self.seed_num)
        self.bip85_data = bip85_data
        self.page_index = page_index
        self.share_index = share_index


    def run(self):
        # Slice the mnemonic to our current 4-word section
        words_per_page = 4  # TODO: eventually make this configurable for bigger screens?

        if self.bip85_data is not None:
            mnemonic = self.seed.get_bip85_child_mnemonic(self.bip85_data["child_index"], self.bip85_data["num_words"]).split()
            # TRANSLATOR_NOTE: Inserts the child index (e.g. "Child #0")
            title = _("Child #{}").format(self.bip85_data["child_index"])
        else:
            if isinstance(self.seed, Slip39Seed) and self.share_index is not None:
                mnemonic = self.seed.mnemonic_list[self.share_index].split()
            else:
                try:
                    mnemonic = self.seed.mnemonic_display_list
                except SeedWordsUnavailableException as e:
                    self.run_screen(
                        WarningScreen,
                        title=_("Seed Words"),
                        status_headline=None,
                        text=str(e),
                        show_back_button=False,
                        button_data=[ButtonOption(_("OK"))],
                    )
                    return Destination(BackStackView)
            title = _("Seed Words")
        words = mnemonic[self.page_index*words_per_page:(self.page_index + 1)*words_per_page]

        button_data = []
        num_pages = int(len(mnemonic)/words_per_page)
        if self.page_index < num_pages - 1 or self.seed_num is None:
            button_data.append(self.NEXT)
        else:
            button_data.append(self.DONE)

        selected_menu_num = seed_screens.SeedWordsScreen(
            title=f"{title}: {self.page_index+1}/{num_pages}",
            words=words,
            page_index=self.page_index,
            num_pages=num_pages,
            button_data=button_data,
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.NEXT:
            if self.seed_num is None and self.page_index == num_pages - 1:
                return Destination(
                    SeedWordsBackupTestPromptView,
                    view_args=dict(seed_num=self.seed_num, bip85_data=self.bip85_data, share_index=self.share_index),
                )
            else:
                return Destination(
                    SeedWordsView,
                    view_args=dict(seed_num=self.seed_num, page_index=self.page_index + 1, bip85_data=self.bip85_data, share_index=self.share_index)
                )

        elif button_data[selected_menu_num] == self.DONE:
            # Must clear history to avoid BACK button returning to private info
            return Destination(
                SeedWordsBackupTestPromptView,
                view_args=dict(seed_num=self.seed_num, bip85_data=self.bip85_data, share_index=self.share_index),
            )



"""****************************************************************************
    BIP85 - Derive child mnemonic (seed) flow
****************************************************************************"""
class SeedBIP85ApplicationModeView(View):
    """
        * Ask the user the application type as defined in the BIP0085 spec.
        * Currently only Word mode of 12, 24 words (Application number: 39')
        * Possible future additions are
        *  WIF (HDSEED)
        *  XPRV (BIP32)
    """
    # TODO: Future enhancement to display WIF (HD-SEED) and XPRV (Bip32)?
    WORDS_12 = ButtonOption("12 Words")
    WORDS_18 = ButtonOption("18 Words")
    WORDS_24 = ButtonOption("24 Words")

    def __init__(self, seed_num: int):
        super().__init__()
        self.seed_num = seed_num
        self.num_words = 0
        self.bip85_app_num = 39     # TODO: Support other Application numbers; TODO: Define this as a constant

    def run(self):
        button_data = [self.WORDS_12, self.WORDS_18, self.WORDS_24]

        selected_menu_num = ButtonListScreen(
            title=_("BIP-85 Num Words"),
            button_data=button_data
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.WORDS_12:
            self.num_words = 12

        elif button_data[selected_menu_num] == self.WORDS_18:
            self.num_words = 18

        elif button_data[selected_menu_num] == self.WORDS_24:
            self.num_words = 24

        return Destination(
            SeedBIP85SelectChildIndexView,
            view_args=dict(seed_num=self.seed_num, num_words=self.num_words)
        )



class SeedBIP85SelectChildIndexView(View):
    # View to retrieve the derived seed index
    def __init__(self, seed_num: int, num_words: int):
        super().__init__()
        self.seed_num = seed_num
        self.num_words = num_words


    def run(self):
        # TODO: Change this later to use the generic Screen input keyboard
        ret = seed_screens.SeedBIP85SelectChildIndexScreen().display()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if not 0 <= int(ret) < 2**31:
            return Destination(
                SeedBIP85InvalidChildIndexView,
                view_args=dict(
                    seed_num=self.seed_num, 
                    num_words=self.num_words
                ),
                skip_current_view=True
            )

        return Destination(
            SeedWordsBackupTestPromptView,
            view_args=dict(
                seed_num=self.seed_num,
                bip85_data=dict(child_index=int(ret), num_words=self.num_words),
            )
        )



class SeedBIP85InvalidChildIndexView(View):
    def __init__(self, seed_num: int, num_words: int):
        super().__init__()
        self.seed_num = seed_num
        self.num_words = num_words


    def run(self):
        DireWarningScreen(
            title=_("BIP-85 Index Error"),
            show_back_button=False,
            status_icon_name=SeedSignerIconConstants.ERROR,
            status_headline=_("Invalid Child Index"),
            text=_("BIP-85 Child Index must be between 0 and 2^31-1."),
            button_data=[ButtonOption("Try Again")]
        ).display()

        return Destination(
                SeedBIP85SelectChildIndexView,
                view_args=dict(
                    seed_num=self.seed_num, 
                    num_words=self.num_words
                ),
                skip_current_view=True
            )



"""****************************************************************************
    Seed Words Backup Test
****************************************************************************"""
class SeedWordsBackupTestPromptView(View):
    VERIFY = ButtonOption("Verify")
    REVIEW = ButtonOption("Review")
    SKIP = ButtonOption("Skip")
    FINALIZE = ButtonOption("Finalize child")

    def __init__(self, seed_num: int, bip85_data: dict = None, share_index: int | None = None):
        super().__init__()
        self.seed_num = seed_num
        self.bip85_data = bip85_data
        self.share_index = share_index


    def run(self):
        button_data = [self.VERIFY, self.REVIEW, self.SKIP]
        if self.seed_num is not None and self.bip85_data:
            button_data.append(self.FINALIZE)

        selected_menu_num = seed_screens.SeedWordsBackupTestPromptScreen(
            button_data=button_data,
        ).display()

        if button_data[selected_menu_num] == self.VERIFY:
            return Destination(
                SeedWordsBackupTestView,
                view_args=dict(seed_num=self.seed_num, bip85_data=self.bip85_data, share_index=self.share_index),
            )

        elif button_data[selected_menu_num] == self.REVIEW:
            return Destination(
                SeedWordsWarningView,
                view_args=dict(seed_num=self.seed_num, bip85_data=self.bip85_data, share_index=self.share_index),
            )

        elif button_data[selected_menu_num] == self.SKIP:
            seed = self.controller.storage.get_pending_seed() if self.seed_num is None else self.controller.get_seed(self.seed_num)
            if isinstance(seed, Slip39Seed) and self.share_index is not None and self.share_index < len(seed.mnemonic_list) - 1:
                return Destination(SeedWordsWarningView, view_args=dict(seed_num=self.seed_num, share_index=self.share_index + 1))
            if self.seed_num is not None:
                return Destination(SeedOptionsView, view_args=dict(seed_num=self.seed_num))
            else:
                return Destination(SeedFinalizeView)

        elif button_data[selected_menu_num] == self.FINALIZE:
            parent = self.controller.storage.seeds[self.seed_num]
            child = Seed(parent.get_bip85_child_mnemonic(
                self.bip85_data["child_index"], self.bip85_data["num_words"]
                ).split())
            self.controller.storage.set_pending_seed(child)
            return Destination(SeedFinalizeView)



class SeedWordsBackupTestView(View):
    def __init__(self, seed_num: int, bip85_data: dict = None, confirmed_list: list[bool] = None, cur_index: int = None, rand_seed: int = None, share_index: int | None = None):
        """
        Note: `rand_seed` is ONLY USED BY THE SCREENSHOT GENERATOR!!! (to ensure
        consistent screenshot results).
        """
        super().__init__()
        self.seed_num = seed_num
        if self.seed_num is None:
            self.seed = self.controller.storage.get_pending_seed()
        else:
            self.seed = self.controller.get_seed(self.seed_num)
        self.bip85_data = bip85_data
        self.share_index = share_index

        if self.bip85_data is not None:
            self.mnemonic_list = self.seed.get_bip85_child_mnemonic(self.bip85_data["child_index"], self.bip85_data["num_words"]).split()
        else:
            if isinstance(self.seed, Slip39Seed) and self.share_index is not None:
                self.mnemonic_list = self.seed.mnemonic_list[self.share_index].split()
            else:
                self.mnemonic_list = self.seed.mnemonic_display_list

        self.confirmed_list = confirmed_list
        if not self.confirmed_list:
            self.confirmed_list = []

        self.cur_index = cur_index
        self.rand_seed = rand_seed


    def run(self):
        from embit import bip39

        if self.rand_seed is not None:
            random.seed(self.rand_seed + self.cur_index if self.cur_index is not None else 0)

        if self.cur_index is None:
            self.cur_index = int(random.random() * len(self.mnemonic_list))
            while self.cur_index in self.confirmed_list:
                self.cur_index = int(random.random() * len(self.mnemonic_list))

        real_word = ButtonOption(self.mnemonic_list[self.cur_index])
        fake_word1 = ButtonOption(bip39.WORDLIST[int(random.random() * 2047)])
        fake_word2 = ButtonOption(bip39.WORDLIST[int(random.random() * 2047)])
        fake_word3 = ButtonOption(bip39.WORDLIST[int(random.random() * 2047)])

        button_data = [real_word, fake_word1, fake_word2, fake_word3]
        random.shuffle(button_data)

        # TRANSLATOR_NOTE: Inserts the word number (e.g. "Verify Word #1")
        title = _("Verify Word #{}").format(self.cur_index + 1)
        selected_menu_num = ButtonListScreen(
            title=title,
            show_back_button=False,
            button_data=button_data,
            is_bottom_list=True,
            is_button_text_centered=True,
        ).display()

        if button_data[selected_menu_num] == real_word:
            self.confirmed_list.append(self.cur_index)
            if len(self.confirmed_list) == len(self.mnemonic_list):
                # Successfully confirmed the full mnemonic!
                return Destination(
                    SeedWordsBackupTestSuccessView,
                    view_args=dict(seed_num=self.seed_num, bip85_data=self.bip85_data, share_index=self.share_index),
                )
            else:
                # Continue testing the remaining words
                return Destination(
                    SeedWordsBackupTestView,
                    view_args=dict(seed_num=self.seed_num, confirmed_list=self.confirmed_list, bip85_data=self.bip85_data, share_index=self.share_index),
                )

        else:
            # Picked the WRONG WORD!
                return Destination(
                    SeedWordsBackupTestMistakeView,
                    view_args=dict(
                        seed_num=self.seed_num,
                        bip85_data=self.bip85_data,
                        cur_index=self.cur_index,
                        wrong_word=button_data[selected_menu_num].button_label,
                        confirmed_list=self.confirmed_list,
                        share_index=self.share_index,
                    )
                )



class SeedWordsBackupTestMistakeView(View):
    REVIEW = ButtonOption("Review Seed Words")
    RETRY = ButtonOption("Try Again")

    def __init__(self, seed_num: int, bip85_data: dict = None, cur_index: int = None, wrong_word: str = None, confirmed_list: list[bool] = None, share_index: int | None = None):
        super().__init__()
        self.seed_num = seed_num
        self.bip85_data = bip85_data
        self.cur_index = cur_index
        self.wrong_word = wrong_word
        self.confirmed_list = confirmed_list
        self.share_index = share_index


    def run(self):
        button_data = [self.REVIEW, self.RETRY]

        # TRANSLATOR_NOTE: Inserts the word number and the word (e.g. "Word #1 is not "apple"!")
        text = _("Word #{} is not \"{}\"!").format(self.cur_index + 1, self.wrong_word)

        # TRANSLATOR_NOTE: User selected the wrong word during the mnemonic backup test (e.g. incorrectly said the 5th word was "zoo")
        status_headline = _("Wrong Word!")

        selected_menu_num = DireWarningScreen(
            title=_("Verification Error"),
            show_back_button=False,
            status_icon_name=SeedSignerIconConstants.ERROR,
            status_headline=status_headline,
            button_data=button_data,
            text=text,
        ).display()

        if button_data[selected_menu_num] == self.REVIEW:
            return Destination(
                SeedWordsView,
                view_args=dict(seed_num=self.seed_num, bip85_data=self.bip85_data, share_index=self.share_index),
            )

        elif button_data[selected_menu_num] == self.RETRY:
            return Destination(
                SeedWordsBackupTestView,
                view_args=dict(
                    seed_num=self.seed_num,
                    confirmed_list=self.confirmed_list,
                    cur_index=self.cur_index,
                    bip85_data=self.bip85_data,
                    share_index=self.share_index,
                )
            )



class SeedWordsBackupTestSuccessView(View):
    def __init__(self, seed_num: int, bip85_data: dict = None, share_index: int | None = None):
        super().__init__()
        self.seed_num = seed_num
        self.bip85_data = bip85_data
        self.share_index = share_index


    def run(self):
        from seedsigner.gui.screens.screen import LargeIconStatusScreen
        LargeIconStatusScreen(
            title=_("Backup Verified"),
            show_back_button=False,
            status_headline=_("Success!"),
            text=_("All mnemonic backup words were successfully verified!"),
            button_data=[ButtonOption("OK")]
        ).display()

        # if BIP-85 child is backed-up, setup to finalize it.
        if self.seed_num is not None and self.bip85_data:
            parent = self.controller.storage.seeds[self.seed_num]
            child = Seed(parent.get_bip85_child_mnemonic(
                self.bip85_data["child_index"], self.bip85_data["num_words"]
                ).split())
            self.controller.storage.set_pending_seed(child)
            self.seed_num = None

        if self.seed_num is not None:
            seed = self.controller.get_seed(self.seed_num)
            if isinstance(seed, Slip39Seed) and self.share_index is not None and self.share_index < len(seed.mnemonic_list) - 1:
                return Destination(SeedWordsWarningView, view_args={"seed_num": self.seed_num, "share_index": self.share_index + 1})
            return Destination(SeedOptionsView, view_args=dict(seed_num=self.seed_num), clear_history=True)
        else:
            seed = self.controller.storage.get_pending_seed()
            if isinstance(seed, Slip39Seed) and self.share_index is not None and self.share_index < len(seed.mnemonic_list) - 1:
                return Destination(SeedWordsWarningView, view_args={"seed_num": None, "share_index": self.share_index + 1})
            return Destination(SeedFinalizeView)


"""****************************************************************************
    Export as SeedQR
****************************************************************************"""
class SeedTranscribeSeedQRFormatView(View):
    def __init__(self, seed_num: int):
        super().__init__()
        self.seed_num = seed_num


    def run(self):
        from seedsigner.helpers.qr import QR

        seed = self.controller.get_seed(self.seed_num)

        encoder_args = dict(
            mnemonic=seed.mnemonic_list,
            wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE),
        )

        qr_helper = QR()
        button_data = []

        standard_encoder = SeedQrEncoder(**encoder_args)
        standard_modules = qr_helper.qrsize(standard_encoder.next_part())
        button_data.append(
            ButtonOption(
                f"Standard: {standard_modules}x{standard_modules}",
                return_data=(QRType.SEED__SEEDQR, standard_modules),
            )
        )

        if self.settings.get_value(SettingsConstants.SETTING__COMPACT_SEEDQR) == SettingsConstants.OPTION__ENABLED:
            compact_encoder = CompactSeedQrEncoder(**encoder_args)
            compact_modules = qr_helper.qrsize(compact_encoder.next_part())
            button_data.append(
                ButtonOption(
                    f"Compact: {compact_modules}x{compact_modules}",
                    return_data=(QRType.SEED__COMPACTSEEDQR, compact_modules),
                )
            )

        if self.settings.get_value(SettingsConstants.SETTING__ENCRYPTED_QR) == SettingsConstants.OPTION__ENABLED:
            button_data.append(
                ButtonOption(
                    "Encrypted",
                    return_data=(QRType.SEED__ENCRYPTEDQR, 0),
                )
            )

        if len(button_data) == 1:
            seedqr_format, num_modules = button_data[0].return_data
            return Destination(
                SeedTranscribeSeedQRWarningView,
                view_args={
                    "seed_num": self.seed_num,
                    "seedqr_format": seedqr_format,
                    "num_modules": num_modules,
                },
                skip_current_view=True,
            )

        selected_menu_num = self.run_screen(
            seed_screens.SeedTranscribeSeedQRFormatScreen,
            title=_("SeedQR Format"),
            is_compactqr=(
                self.settings.get_value(SettingsConstants.SETTING__COMPACT_SEEDQR)
                == SettingsConstants.OPTION__ENABLED
            ),
            is_encryptedqr=(
                self.settings.get_value(SettingsConstants.SETTING__ENCRYPTED_QR)
                == SettingsConstants.OPTION__ENABLED
            ),
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        seedqr_format, num_modules = button_data[selected_menu_num].return_data

        return Destination(
            SeedTranscribeSeedQRWarningView,
            view_args={
                "seed_num": self.seed_num,
                "seedqr_format": seedqr_format,
                "num_modules": num_modules,
            },
        )



class SeedTranscribeSeedQRWarningView(View):
    def __init__(self, seed_num: int, seedqr_format: str = QRType.SEED__SEEDQR, num_modules: int = 29):
        super().__init__()
        self.seed_num = seed_num
        self.seedqr_format = seedqr_format
        self.num_modules = num_modules
    

    def run(self):
        destination = Destination(
            SeedTranscribeSeedQRWholeQRView,
            view_args={
                "seed_num": self.seed_num,
                "seedqr_format": self.seedqr_format,
                "num_modules": self.num_modules,
            },
            skip_current_view=True,  # Prevent going BACK to WarningViews
        )

        if self.settings.get_value(SettingsConstants.SETTING__DIRE_WARNINGS) == SettingsConstants.OPTION__DISABLED:
            # Forward straight to transcribing the SeedQR
            return destination

        selected_menu_num = self.run_screen(
            DireWarningScreen,
            status_headline=_("SeedQR is your private key!"),
            text=_("Never photograph or scan it into a device that connects to the internet."),
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        else:
            # User clicked "I Understand"
            return destination



class SeedTranscribeSeedQRWholeQRView(View):
    def __init__(self, seed_num: int, seedqr_format: str, num_modules: int):
        super().__init__()
        self.seed_num = seed_num
        self.seedqr_format = seedqr_format
        self.num_modules = num_modules
        self.seed = self.controller.get_seed(seed_num)
    

    def run(self):
        if self.seedqr_format == QRType.SEED__ENCRYPTEDQR:
            TYPE = ButtonOption("Type encryption key")
            SCAN = ButtonOption("Scan encryption key")
            button_data = [TYPE, SCAN]

            selected_menu_num = self.run_screen(
                ButtonListScreen,
                title=_("Input Encryption Key"),
                button_data=button_data,
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            elif button_data[selected_menu_num] == TYPE:
                return Destination(
                    SeedEncryptedQRTypeEncryptionKeyView,
                    view_args=dict(seed_num=self.seed_num)
                )

            elif button_data[selected_menu_num] == SCAN:
                return Destination(
                    SeedEncryptedQRScanEncryptionKeyView,
                    view_args=dict(seed_num=self.seed_num)
                )

        else:
            encoder_args = dict(mnemonic=self.seed.mnemonic_list,
                                wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE))
            if self.seedqr_format == QRType.SEED__SEEDQR:
                e = SeedQrEncoder(**encoder_args)
            elif self.seedqr_format == QRType.SEED__COMPACTSEEDQR:
                e = CompactSeedQrEncoder(**encoder_args)

            data = e.next_part()

            ret = seed_screens.SeedTranscribeSeedQRWholeQRScreen(
                qr_data=data,
                num_modules=self.num_modules,
            ).display()

            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            else:
                return Destination(
                    SeedTranscribeSeedQRZoomedInView,
                    view_args={
                        "seed_num": self.seed_num,
                        "seedqr_format": self.seedqr_format
                    }
                )



class SeedEncryptedQRTypeEncryptionKeyView(View):
    def __init__(self, seed_num: int, encryption_key: str = ""):
        super().__init__()
        self.seed_num = seed_num
        self.encryption_key = encryption_key

    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanTypeEncryptionKeyScreen
        ret_dict = self.run_screen(ScanTypeEncryptionKeyScreen, encryptionkey=self.encryption_key)
        encryption_key=ret_dict["encryptionkey"]

        if "is_back_button" in ret_dict:
            if len(encryption_key) > 0:
                return Destination(
                    SeedEncryptedQRTypeEncryptionKeyExitDialogView,
                    view_args=dict(encryption_key=encryption_key, seed_num=self.seed_num),
                    skip_current_view=True
                )
            else:
                return Destination(BackStackView)

        else:
            return Destination(
                SeedEncryptedQRReviewEncryptionKeyView,
                view_args=dict(encryption_key=encryption_key, seed_num=self.seed_num),
                skip_current_view=True
            )



class SeedEncryptedQRTypeEncryptionKeyExitDialogView(View):
    EDIT = ButtonOption("Edit encryption key")
    DISCARD = ButtonOption("Discard encryption key", button_label_color="red")

    def __init__(self, encryption_key: str, seed_num: int):
        super().__init__()
        self.encryption_key = encryption_key
        self.seed_num = seed_num


    def run(self):
        button_data = [self.EDIT, self.DISCARD]
        
        selected_menu_num = self.run_screen(
            WarningScreen,
            title=_("Discard encryption key?"),
            status_headline=None,
            text=_("Your current key entry will be erased"),
            show_back_button=False,
            button_data=button_data
        )

        if button_data[selected_menu_num] == self.EDIT:
            return Destination(
                SeedEncryptedQRTypeEncryptionKeyView,
                view_args=dict(seed_num=self.seed_num, encryption_key=self.encryption_key),
                skip_current_view=True
            )

        elif button_data[selected_menu_num] == self.DISCARD:
            return Destination(BackStackView)



class SeedEncryptedQRScanEncryptionKeyView(View):
    def __init__(self, seed_num: int, encryption_key: str = ""):
        super().__init__()
        self.seed_num = seed_num
        self.encryption_key = encryption_key

    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.models.decode_qr import DecodeQR
        decoder = DecodeQR(is_encryptionkey=True)
        self.run_screen(
            ScanScreen,
            instructions_text=_("Scan encryption key"),
            decoder=decoder
        )
        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)
        if decoder.is_complete:
            self.encryption_key += decoder.get_encryption_key()
            return Destination(
                SeedEncryptedQRReviewEncryptionKeyView,
                view_args=dict(encryption_key=self.encryption_key, seed_num=self.seed_num),
                skip_current_view=True
            )
        elif decoder.is_nonUTF8:
            DireWarningScreen(
                title=_("Error!"),
                show_back_button=False,
                status_headline=_("Invalid Text QR Code"),
                text=_("Non UTF-8 data detected.")
            ).display()
            return Destination(BackStackView)
        else:
            return Destination(BackStackView)



class SeedEncryptedQRReviewEncryptionKeyView(View):
    def __init__(self, encryption_key: str, seed_num: int):
        super().__init__()
        self.encryption_key = encryption_key
        self.seed_num = seed_num
        self.mode_name = self.settings.get_value(SettingsConstants.SETTING__ENCRYPTION_MODE)

    def run(self):
        if len(self.encryption_key) > 200:
            WarningScreen(
                title=_("Error"),
                show_back_button=False,
                status_headline=_("Invalid Key"),
                text=_("Key length is too long."),
            ).display()
            return Destination(BackStackView)

        PROCEED = ButtonOption("Proceed")
        EDIT = ButtonOption("Edit encryption key")
        SCAN = ButtonOption("Scan & Append Another")
        button_data = [PROCEED, EDIT, SCAN]

        from seedsigner.gui.screens.scan_screens import ScanReviewEncryptionKeyScreen

        selected_menu_num = self.run_screen(
            ScanReviewEncryptionKeyScreen,
            encryptionkey=self.encryption_key,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == PROCEED:
            if self.mode_name in (SettingsConstants.ENCRYPTION_MODE_ECB, SettingsConstants.ENCRYPTION_MODE_ECBV1):
                return Destination(
                    SeedEncryptedQRMnemonicIDPromptView,
                    view_args=dict(encryption_key=self.encryption_key, i_vector=None, seed_num=self.seed_num)
                )
            else:
                return Destination(
                    SeedEncryptedQRnonECBModeView,
                    view_args=dict(encryption_key=self.encryption_key, seed_num=self.seed_num, mode_name=self.mode_name)
                )

        elif button_data[selected_menu_num] == EDIT:
                return Destination(
                    SeedEncryptedQRTypeEncryptionKeyView,
                    view_args=dict(seed_num=self.seed_num, encryption_key=self.encryption_key),
                    skip_current_view=True
                )

        elif button_data[selected_menu_num] == SCAN:
                return Destination(
                    SeedEncryptedQRScanEncryptionKeyView,
                    view_args=dict(seed_num=self.seed_num, encryption_key=self.encryption_key),
                    skip_current_view=True
                )



class SeedEncryptedQRnonECBModeView(View):
    def __init__(self, encryption_key: str, seed_num: int, mode_name: str):
        super().__init__()
        self.encryption_key = encryption_key
        self.seed_num = seed_num
        self.mode_name = mode_name


    def run(self):
        CANCEL = ButtonOption("Cancel")
        button_data=[ButtonOption("Input from Camera"), CANCEL]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=f"Additional Entropy for {self.mode_name} mode",
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == CANCEL:
            return Destination(BackStackView)

        from seedsigner.gui.screens.tools_screens import ToolsImageEntropyLivePreviewScreen, ToolsImageEntropyFinalImageScreen
        self.controller.image_entropy_preview_frames = None
        ret = ToolsImageEntropyLivePreviewScreen().display()
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Take the final full-res image
        from seedsigner.hardware.camera import Camera
        camera = Camera.get_instance()
        camera.start_single_frame_mode(resolution=(720, 480))
        time.sleep(0.25)
        entropy_image = camera.capture_frame()
        camera.stop_single_frame_mode()

        # A copy of the image for display. The actual image data is 720x480
        display_version = autocontrast(
            entropy_image,
            cutoff=2
        ).crop(
            (120, 0, 600, 480)
        ).resize(
            (self.canvas_width, self.canvas_height), Image.BICUBIC
        )
        ret = ToolsImageEntropyFinalImageScreen(
            final_image=display_version
        ).display()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        entropy_hash = hashlib.sha256(entropy_image.tobytes()).digest()
        from seedsigner.helpers import kef
        iv_len = kef.MODE_IVS.get(kef.MODE_NUMBERS[self.mode_name], 0)
        i_vector = entropy_hash[:iv_len]

        return Destination(
            SeedEncryptedQRMnemonicIDPromptView,
            view_args=dict(encryption_key=self.encryption_key, i_vector=i_vector, seed_num=self.seed_num)
        )



class SeedEncryptedQRMnemonicIDPromptView(View):
    def __init__(self, encryption_key: str, i_vector: bytes, seed_num: int):
        super().__init__()
        self.encryption_key = encryption_key
        self.i_vector = i_vector
        self.seed_num = seed_num

        self.seed = self.controller.get_seed(seed_num)


    def run(self):
        DEFAULT = ButtonOption("Use fingerprint")
        CUSTOM_ID = ButtonOption("Assign custom ID")
        button_data = [DEFAULT, CUSTOM_ID]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Input Mnemonic ID"),
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == CUSTOM_ID:
            return Destination(
                SeedEncryptedQRMnemonicIDEntryView,
                view_args=dict(encryption_key=self.encryption_key, i_vector=self.i_vector, seed_num=self.seed_num)
            )

        elif button_data[selected_menu_num] == DEFAULT:
            mnemonic_id = self.seed.get_fingerprint(network=self.settings.get_value(SettingsConstants.SETTING__NETWORK))
            return Destination(
                SeedEncryptedQRReviewMnemonicIDView,
                view_args=dict(encryption_key=self.encryption_key, i_vector=self.i_vector, mnemonic_id=mnemonic_id, seed_num=self.seed_num)
            )



class SeedEncryptedQRMnemonicIDEntryView(View):
    def __init__(self, encryption_key: str, i_vector: bytes, seed_num: int, custom_id: str = ""):
        super().__init__()
        self.encryption_key = encryption_key
        self.i_vector = i_vector
        self.seed_num = seed_num
        self.custom_id = custom_id


    def run(self):
        from seedsigner.gui.screens.seed_screens import SeedEncryptedQRMnemonicIDScreen
        ret_dict = self.run_screen(SeedEncryptedQRMnemonicIDScreen, mnemonic_id=self.custom_id)
        mnemonic_id = ret_dict["mnemonic_id"]

        if "is_back_button" in ret_dict:
            if len(mnemonic_id) > 0:
                return Destination(
                    SeedEncryptedQRMnemonicIDEntryExitDialogView,
                    view_args=dict(encryption_key=self.encryption_key, i_vector=self.i_vector, mnemonic_id=mnemonic_id, seed_num=self.seed_num),
                    skip_current_view=True
                )
            else:
                return Destination(BackStackView)

        else:
            return Destination(
                SeedEncryptedQRReviewMnemonicIDView,
                view_args=dict(encryption_key=self.encryption_key, i_vector=self.i_vector, mnemonic_id=mnemonic_id, seed_num=self.seed_num),
                skip_current_view=True
            )



class SeedEncryptedQRMnemonicIDEntryExitDialogView(View):
    EDIT = ButtonOption("Edit mnemonic ID")
    DISCARD = ButtonOption("Discard mnemonic ID", button_label_color="red")

    def __init__(self, encryption_key: str, i_vector: bytes, mnemonic_id: str, seed_num: int):
        super().__init__()
        self.encryption_key = encryption_key
        self.i_vector = i_vector
        self.mnemonic_id = mnemonic_id
        self.seed_num = seed_num


    def run(self):
        button_data = [self.EDIT, self.DISCARD]
        
        selected_menu_num = self.run_screen(
            WarningScreen,
            title=_("Discard mnemonic ID?"),
            status_headline=None,
            text=_("Your current mnemonic ID entry will be erased"),
            show_back_button=False,
            button_data=button_data
        )

        if button_data[selected_menu_num] == self.EDIT:
            return Destination(
                SeedEncryptedQRMnemonicIDEntryView,
                view_args=dict(encryption_key=self.encryption_key, i_vector=self.i_vector, seed_num=self.seed_num, custom_id=self.mnemonic_id),
                skip_current_view=True
            )

        elif button_data[selected_menu_num] == self.DISCARD:
            return Destination(BackStackView)



class SeedEncryptedQRReviewMnemonicIDView(View):
    def __init__(self, encryption_key: str, i_vector: bytes, mnemonic_id: str, seed_num: int):
        super().__init__()
        self.encryption_key = encryption_key
        self.i_vector = i_vector
        self.mnemonic_id = mnemonic_id
        self.seed_num = seed_num

        self.seed = self.controller.get_seed(seed_num)


    def run(self):
        from seedsigner.gui.screens.seed_screens import SeedEncryptedQRReviewMnemonicIDScreen

        PROCEED = ButtonOption("Proceed")
        EDIT = ButtonOption("Edit mnemonic ID")
        button_data = [PROCEED, EDIT]

        selected_menu_num = self.run_screen(
            SeedEncryptedQRReviewMnemonicIDScreen,
            mnemonic_id=self.mnemonic_id,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)


        elif button_data[selected_menu_num] == EDIT:
            return Destination(
                SeedEncryptedQRMnemonicIDEntryView,
                view_args=dict(encryption_key=self.encryption_key, i_vector=self.i_vector, seed_num=self.seed_num, custom_id=self.mnemonic_id),
                skip_current_view=True
            )

        elif button_data[selected_menu_num] == PROCEED:
            from seedsigner.gui.screens.screen import LoadingScreenThread
            loading_screen = LoadingScreenThread(text=_("Processing..."))
            loading_screen.start()

            try:
                from seedsigner.models.encryption import EncryptedQRCode
                from seedsigner.helpers.base43 import base43_encode
                encrypted_qr = EncryptedQRCode()
                encrypted_qr.add_delta()
                qr_data = encrypted_qr.create(
                               key=self.encryption_key,
                               mnemonic_id=self.mnemonic_id,
                               mnemonic=self.seed.mnemonic_str,
                               i_vector=self.i_vector
                           )
                version_number = encrypted_qr.version
                del encrypted_qr

                if version_number > 1:
                    qr_data = base43_encode(qr_data)

                if not qr_data:
                    WarningScreen(
                        title=_("Error"),
                        show_back_button=False,
                        status_headline=_("Encryption failure"),
                        text="",
                    ).display()
                    return Destination(BackStackView)

            finally:
                loading_screen.stop()

            return Destination(
                SeedEncryptedQRTranscribeModePromptView,
                view_args=dict(data=qr_data, seed_num=self.seed_num)
            )



class SeedEncryptedQRTranscribeModePromptView(View):
    def __init__(self, data: bytes, seed_num: int):
        super().__init__()
        self.data = data
        self.seed_num = seed_num


    def run(self):
        from seedsigner.helpers.qr import QR
        num_modules = QR().qrsize(data=self.data)
        if num_modules <= 33:
            TRANSCRIBE = ButtonOption("Transcribe mode")
            FULLSCREEN = ButtonOption("FullScreen mode")

            button_data = [TRANSCRIBE, FULLSCREEN]

            selected_menu_num = self.run_screen(
                seed_screens.SeedEncryptedQRTranscribeModePromptScreen,
                title=_("Transcribe Mode ?"),
                is_button_text_centered=False,
                button_data=button_data
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            elif button_data[selected_menu_num] == TRANSCRIBE:
                return Destination(
                    SeedEncryptedQRTranscribeModeView,
                    view_args=dict(data=self.data, num_modules=num_modules, seed_num=self.seed_num)
                )

        return Destination(
            SeedEncryptedQRFullScreenModeView,
            view_args=dict(data=self.data, seed_num=self.seed_num)
        )



class SeedEncryptedQRTranscribeModeView(View):
    def __init__(self, data: bytes, num_modules: int, seed_num: int):
        super().__init__()
        self.data = data
        self.num_modules = num_modules
        self.seed_num = seed_num


    def run(self):
        ret = seed_screens.SeedTranscribeEncryptedQRWholeQRScreen(
            qr_data=self.data,
            num_modules=self.num_modules
        ).display()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        else:
            return Destination(
                SeedTranscribeEncryptedQRZoomedInView,
                view_args=dict(data=self.data, num_modules=self.num_modules, seed_num=self.seed_num)
            )



class SeedTranscribeEncryptedQRZoomedInView(View):
    def __init__(self, data: bytes, num_modules: int, seed_num: int):
        super().__init__()
        self.data = data
        self.num_modules = num_modules
        self.seed_num = seed_num


    def run(self):
        seed_screens.SeedTranscribeEncryptedQRZoomedInScreen(
            qr_data=self.data,
            num_modules=self.num_modules
        ).display()
        return Destination(
            SeedOptionsView,
            view_args=dict(seed_num=self.seed_num),
            clear_history=True
        )



class SeedEncryptedQRFullScreenModeView(View):
    def __init__(self, data: bytes, seed_num: int):
        super().__init__()
        self.data = data
        self.seed_num = seed_num

    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        encoder_args = dict(data=self.data)
        e = GenericStaticQrEncoder(**encoder_args)
        QRDisplayScreen(qr_encoder=e).display()
        return Destination(
            SeedOptionsView,
            view_args=dict(seed_num=self.seed_num),
            clear_history=True
        )



class SeedTranscribeSeedQRZoomedInView(View):
    """
    intial_zone_x, initial_zone_y: Used by the screenshot generator to shift the view
    to a more interesting part of the QR code template.
    """
    def __init__(self, seed_num: int, seedqr_format: str, initial_zone_x: int = 0, initial_zone_y: int = 0):
        super().__init__()
        self.seed_num = seed_num
        self.seedqr_format = seedqr_format
        self.seed = self.controller.get_seed(seed_num)
        self.initial_zone_x = initial_zone_x
        self.initial_zone_y = initial_zone_y 


    def run(self):
        encoder_args = dict(mnemonic=self.seed.mnemonic_list,
                            wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE))
        if self.seedqr_format == QRType.SEED__SEEDQR:
            e = SeedQrEncoder(**encoder_args)
        elif self.seedqr_format == QRType.SEED__COMPACTSEEDQR:
            e = CompactSeedQrEncoder(**encoder_args)

        data = e.next_part()

        from seedsigner.helpers.qr import QR
        num_modules = QR().qrsize(data)

        seed_screens.SeedTranscribeSeedQRZoomedInScreen(
            qr_data=data,
            num_modules=num_modules,
            initial_zone_x=self.initial_zone_x,
            initial_zone_y=self.initial_zone_y,
        ).display()

        return Destination(SeedTranscribeSeedQRConfirmQRPromptView, view_args={"seed_num": self.seed_num})



class SeedTranscribeSeedQRConfirmQRPromptView(View):
    SCAN = ButtonOption("Confirm SeedQR", SeedSignerIconConstants.QRCODE)
    DONE = ButtonOption("Done")

    def __init__(self, seed_num: int):
        super().__init__()
        self.seed_num = seed_num
        self.seed = self.controller.get_seed(seed_num)
    

    def run(self):
        button_data = [self.SCAN, self.DONE]

        selected_menu_option = self.run_screen(
            seed_screens.SeedTranscribeSeedQRConfirmQRPromptScreen,
            title=_("Confirm SeedQR?"),
            button_data=button_data,
        )

        if selected_menu_option == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_option] == self.SCAN:
            return Destination(SeedTranscribeSeedQRConfirmScanView, view_args={"seed_num": self.seed_num})

        elif button_data[selected_menu_option] == self.DONE:
            return Destination(SeedOptionsView, view_args={"seed_num": self.seed_num}, clear_history=True)



class SeedTranscribeSeedQRConfirmScanView(View):
    def __init__(self, seed_num: int):
        from seedsigner.models.decode_qr import DecodeQR
        super().__init__()
        self.seed_num = seed_num
        self.seed = self.controller.get_seed(seed_num)
        wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
        self.decoder = DecodeQR(wordlist_language_code=wordlist_language_code)

    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen

        # Run the live preview and QR code capture process
        # TODO: Does this belong in its own BaseThread?
        self.run_screen(
            ScanScreen,
            decoder=self.decoder,
            instructions_text=_("Scan your SeedQR")
        )

        if self.decoder.is_complete:
            if self.decoder.is_seed:
                seed_mnemonic = self.decoder.get_seed_phrase()
                # Found a valid mnemonic seed! But does it match?
                if seed_mnemonic != self.seed.mnemonic_list:
                    return Destination(SeedTranscribeSeedQRConfirmWrongSeedView, skip_current_view=True)
                else:
                    return Destination(SeedTranscribeSeedQRConfirmSuccessView, view_args={"seed_num": self.seed_num})

        else:
            # Will this case ever happen? Will trigger if a different kind of QR code is scanned
            return Destination(SeedTranscribeSeedQRConfirmInvalidQRView, skip_current_view=True)


class SeedTranscribeSeedQRConfirmWrongSeedView(View):
    """
    A valid SeedQR was scanned but it did NOT match the one we just transcribed!
    """
    def run(self):
        self.run_screen(
            DireWarningScreen,
            title=_("Confirm SeedQR"),
            status_headline=_("Error!"),
            text=_("Your transcribed SeedQR does not match your original seed!"),
            show_back_button=False,
            button_data=[ButtonOption("Review SeedQR")],
        )

        # Skip BACK to the zoomed in transcription view
        return Destination(BackStackView, skip_current_view=True)



class SeedTranscribeSeedQRConfirmInvalidQRView(View):
    """
    A QR code was scanned but it was not a SeedQR and certainly not the SeedQR we just
    transcribed!
    """
    def run(self):
        # TODO: A better error message would be something like: "The QR code you scanned does not contain a valid SeedQR."
        self.run_screen(
            DireWarningScreen,
            title=_("Confirm SeedQR"),
            status_headline=_("Error!"),
            text=_("Your transcribed SeedQR could not be read!"),
            show_back_button=False,
            button_data=[ButtonOption("Review SeedQR")],
        )

        # Skip BACK to the zoomed in transcription view
        return Destination(BackStackView, skip_current_view=True)



class SeedTranscribeSeedQRConfirmSuccessView(View):
    """
    The SeedQR we just scanned matched the one we just transcribed.
    """
    def __init__(self, seed_num: int):
        super().__init__()
        self.seed_num = seed_num


    def run(self):
        from seedsigner.gui.screens.screen import LargeIconStatusScreen
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Confirm SeedQR"),
            status_headline=_("Success!"),
            text=_("Your transcribed SeedQR successfully scanned and yielded the same seed."),
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )

        return Destination(SeedOptionsView, view_args={"seed_num": self.seed_num})



"""****************************************************************************
    Address verification
****************************************************************************"""
class AddressVerificationStartView(View):
    def __init__(self, address: str, script_type: str, network: str):
        super().__init__()
        self.controller.unverified_address = dict(
            address=address,
            script_type=script_type,
            network=network
        )


    def run(self):
        from seedsigner.helpers import embit_utils
        from seedsigner.controller import Controller

        if self.controller.unverified_address["script_type"] == SettingsConstants.LEGACY_P2PKH:
            # Legacy P2PKH addresses are always singlesig
            sig_type = SettingsConstants.SINGLE_SIG
            destination = Destination(SeedSelectSeedView, view_args=dict(flow=Controller.FLOW__VERIFY_SINGLESIG_ADDR), skip_current_view=True)

        if self.controller.unverified_address["script_type"] == SettingsConstants.NESTED_SEGWIT:
            # No way to differentiate single sig from multisig
            return Destination(AddressVerificationSigTypeView, skip_current_view=True)

        if self.controller.unverified_address["script_type"] == SettingsConstants.NATIVE_SEGWIT:
            if len(self.controller.unverified_address["address"]) >= 62:
                # Mainnet/testnet are 62, regtest is 64
                sig_type = SettingsConstants.MULTISIG
                if self.controller.multisig_wallet_descriptor:
                    # Can jump straight to the brute-force verification View
                    destination = Destination(SeedAddressVerificationView, skip_current_view=True)
                else:
                    self.controller.resume_main_flow = Controller.FLOW__VERIFY_MULTISIG_ADDR
                    destination = Destination(LoadMultisigWalletDescriptorView, skip_current_view=True)

            else:
                sig_type = SettingsConstants.SINGLE_SIG
                destination = Destination(SeedSelectSeedView, view_args=dict(flow=Controller.FLOW__VERIFY_SINGLESIG_ADDR), skip_current_view=True)

        elif self.controller.unverified_address["script_type"] == SettingsConstants.TAPROOT:
            sig_type = SettingsConstants.SINGLE_SIG
            destination = Destination(SeedSelectSeedView, view_args=dict(flow=Controller.FLOW__VERIFY_SINGLESIG_ADDR), skip_current_view=True)

        derivation_path = embit_utils.get_standard_derivation_path(
            network=self.controller.unverified_address["network"],
            wallet_type=sig_type,
            script_type=self.controller.unverified_address["script_type"]
        )

        self.controller.unverified_address["sig_type"] = sig_type
        self.controller.unverified_address["derivation_path"] = derivation_path

        return destination



class AddressVerificationSigTypeView(View):
    SINGLE_SIG = ButtonOption("Single Sig")
    MULTISIG = ButtonOption("Multisig")

    def run(self):
        from seedsigner.helpers import embit_utils
        from seedsigner.controller import Controller
        button_data = [self.SINGLE_SIG, self.MULTISIG]
        selected_menu_num = self.run_screen(
            seed_screens.AddressVerificationSigTypeScreen,
            title=_("Verify Address"),
            text=_("Sig type can't be auto-detected from this address. Please specify:"),
            button_data=button_data,
            is_bottom_list=True,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            self.controller.unverified_address = None
            return Destination(BackStackView)
        
        elif button_data[selected_menu_num] == self.SINGLE_SIG:
            sig_type = SettingsConstants.SINGLE_SIG
            destination = Destination(SeedSelectSeedView, view_args=dict(flow=Controller.FLOW__VERIFY_SINGLESIG_ADDR))

        elif button_data[selected_menu_num] == self.MULTISIG:
            sig_type = SettingsConstants.MULTISIG
            if self.controller.multisig_wallet_descriptor:
                destination = Destination(SeedAddressVerificationView)
            else:
                self.controller.resume_main_flow = Controller.FLOW__VERIFY_MULTISIG_ADDR
                destination = Destination(LoadMultisigWalletDescriptorView)

        self.controller.unverified_address["sig_type"] = sig_type
        derivation_path = embit_utils.get_standard_derivation_path(
            network=self.controller.unverified_address["network"],
            wallet_type=sig_type,
            script_type=self.controller.unverified_address["script_type"]
        )
        self.controller.unverified_address["derivation_path"] = derivation_path

        return destination



class SeedAddressVerificationView(View):
    """
        Creates a worker thread to brute-force calculate addresses. Writes its
        iteration status to a shared `ThreadsafeCounter`.

        The `ThreadsafeCounter` is sent to the display Screen which is monitored in
        its own `ProgressThread` to show the current iteration onscreen.

        Performs single sig verification on `seed_num` if specified, otherwise assumes
        multisig.

        For singlesig with a seed, automatically searches all standard derivation
        paths (BIP44/49/84/86) across accounts 0-9 and non-standard paths (BRD,
        Coldcard), checking 100 addresses per path.
    """
    # TRANSLATOR_NOTE: Option when scanning for a matching address; skips ten addresses ahead
    SKIP_10 = ButtonOption("Skip 10")
    CANCEL = ButtonOption("Cancel")

    MAX_ITERATIONS_EXPORT_XPUB = 1000
    EXPANDED_ADDRS_PER_PATH = 100

    def __init__(self, seed_num: int = None, export_for_xpub: bool = False):
        super().__init__()
        self.seed_num = seed_num
        self.export_for_xpub = export_for_xpub
        self.is_multisig = self.controller.unverified_address["sig_type"] == SettingsConstants.MULTISIG
        self.seed_derivation_override = ""
        if not self.is_multisig:
            if seed_num is not None:
                self.seed = self.controller.get_seed(seed_num)
                self.seed_derivation_override = self.seed.derivation_override(sig_type=SettingsConstants.SINGLE_SIG)
            else:
                self.seed = None
        else:
            self.seed = None
        self.address = self.controller.unverified_address["address"]
        self.derivation_path = self.seed_derivation_override if self.seed_derivation_override else self.controller.unverified_address["derivation_path"]
        self.script_type = self.controller.unverified_address["script_type"]
        self.sig_type = self.controller.unverified_address["sig_type"]
        self.network = self.controller.unverified_address["network"]

        # TODO: This should be in `Seed` or `PSBT` utility class
        embit_network = SettingsConstants.map_network_to_embit(self.network)

        # The ThreadsafeCounter will be shared by the brute-force thread to keep track of
        # its current addr index number and the Screen to display its progress and
        # respond to UI requests to jump the index ahead.
        self.threadsafe_counter = ThreadsafeCounter()

        # Shared coordination var so the display thread can detect success
        self.verified_index = ThreadsafeCounter(initial_value=None)
        self.verified_index_is_change = ThreadsafeCounter(initial_value=None)

        # For singlesig with a seed (non-export), automatically search all standard
        # derivation paths and accounts. For multisig or export-for-xpub, use the
        # single-path brute force thread.
        self.is_expanded = self.seed is not None and not self.is_multisig and not self.export_for_xpub
        if self.is_expanded:
            from seedsigner.helpers import embit_utils
            derivation_paths = embit_utils.get_expanded_search_derivation_paths(
                network=self.network,
            )
            self.addr_verification_thread = self.ExpandedBruteForceAddressVerificationThread(
                address=self.address,
                seed=self.seed,
                script_type=self.script_type,
                embit_network=embit_network,
                network=self.network,
                derivation_paths=derivation_paths,
                addrs_per_path=self.EXPANDED_ADDRS_PER_PATH,
                threadsafe_counter=self.threadsafe_counter,
                verified_index=self.verified_index,
                verified_index_is_change=self.verified_index_is_change,
            )
        else:
            # Create the brute-force calculation thread that will run in the background
            self.addr_verification_thread = self.BruteForceAddressVerificationThread(
                address=self.address,
                seed=self.seed,
                descriptor=self.controller.multisig_wallet_descriptor,
                script_type=self.script_type,
                embit_network=embit_network,
                derivation_path=self.derivation_path,
                threadsafe_counter=self.threadsafe_counter,
                verified_index=self.verified_index,
                verified_index_is_change=self.verified_index_is_change,
            )


    def run(self):
        # Start brute-force calculations from the zero-th index
        try:
            self.addr_verification_thread.start()

            # Expanded search doesn't support Skip 10 (iterates paths, not just indices)
            if self.is_expanded:
                button_data = [self.CANCEL]
            else:
                button_data = [self.SKIP_10, self.CANCEL]

            script_type_settings_entry = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__SCRIPT_TYPES)
            script_type_display = script_type_settings_entry.get_selection_option_display_name_by_value(self.script_type)

            sig_type_settings_entry = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__SIG_TYPES)
            sig_type_display = sig_type_settings_entry.get_selection_option_display_name_by_value(self.sig_type)

            network_settings_entry = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__NETWORK)
            network_display = network_settings_entry.get_selection_option_display_name_by_value(self.network)
            mainnet = network_settings_entry.get_selection_option_display_name_by_value(SettingsConstants.MAINNET)

            if self.export_for_xpub:
                max_iterations = self.MAX_ITERATIONS_EXPORT_XPUB
            elif self.is_expanded:
                from seedsigner.helpers import embit_utils
                num_paths = len(embit_utils.get_expanded_search_derivation_paths(
                    network=self.network,
                ))
                max_iterations = num_paths * self.EXPANDED_ADDRS_PER_PATH
            else:
                max_iterations = None

            # Display the Screen to show the brute-forcing progress.
            # Using a loop here to handle the SKIP_10 button presses to increment the counter
            # and resume displaying the screen. User won't even notice that the Screen is
            # being re-constructed.
            while True:
                selected_menu_num = self.run_screen(
                    seed_screens.SeedAddressVerificationScreen,
                    address=self.address,
                    derivation_path=self.derivation_path,
                    script_type=script_type_display,
                    sig_type=sig_type_display,
                    network=network_display,
                    is_mainnet=network_display == mainnet,
                    threadsafe_counter=self.threadsafe_counter,
                    verified_index=self.verified_index,
                    button_data=button_data,
                    max_iterations=max_iterations,
                )

                if self.verified_index.cur_count is not None:
                    break

                if selected_menu_num == RET_CODE__BACK_BUTTON:
                    break

                if selected_menu_num is None:
                    # Only happens in the test suite; the screen isn't actually executed so
                    # it returns before the brute force thread has completed.
                    time.sleep(0.1)
                else:
                    if button_data[selected_menu_num] == self.SKIP_10:
                        self.threadsafe_counter.increment(10)

                    elif button_data[selected_menu_num] == self.CANCEL:
                        break

                if max_iterations is not None and self.threadsafe_counter.cur_count >= max_iterations:
                    break

            if self.verified_index.cur_count is not None:
                # Successfully verified the addr; update the data
                self.controller.unverified_address["verified_index"] = self.verified_index.cur_count
                self.controller.unverified_address["verified_index_is_change"] = self.verified_index_is_change.cur_count == 1
                if self.is_expanded and self.addr_verification_thread.matched_derivation_path:
                    self.controller.unverified_address["derivation_path"] = self.addr_verification_thread.matched_derivation_path
                if self.export_for_xpub:
                    return Destination(SeedExportXpubVerificationSuccessView)
                return Destination(SeedAddressVerificationSuccessView, view_args=dict(seed_num=self.seed_num))

            if self.export_for_xpub and max_iterations is not None and self.threadsafe_counter.cur_count >= max_iterations:
                return Destination(SeedExportXpubVerificationFailedView, view_args=dict(reason="no_match"))

        finally:
            # Halt the thread if the user gave up (will already be stopped if it verified the
            # target addr).
            self.addr_verification_thread.stop()

            # Block until the thread has stopped
            while self.addr_verification_thread.is_alive():
                time.sleep(0.01)

        return Destination(MainMenuView)



    class BruteForceAddressVerificationThread(BaseThread):
        def __init__(self, address: str, seed: Seed, descriptor: Descriptor, script_type: str, embit_network: str, derivation_path: str, threadsafe_counter: ThreadsafeCounter, verified_index: ThreadsafeCounter, verified_index_is_change: ThreadsafeCounter):
            """
                Either seed or descriptor will be None
            """
            super().__init__()
            self.address = address
            self.seed = seed
            self.descriptor = descriptor
            self.script_type = script_type
            self.embit_network = embit_network
            self.derivation_path = derivation_path
            self.threadsafe_counter = threadsafe_counter
            self.verified_index = verified_index
            self.verified_index_is_change = verified_index_is_change

            if self.seed:
                self.xpub = self.seed.get_xpub(wallet_path=self.derivation_path, network=Settings.get_instance().get_value(SettingsConstants.SETTING__NETWORK))


        def run(self):
            from seedsigner.helpers import embit_utils
            while self.keep_running:
                if self.threadsafe_counter.cur_count % 10 == 0:
                    logger.info(f"Incremented to {self.threadsafe_counter.cur_count}")
                
                i = self.threadsafe_counter.cur_count

                if self.descriptor:
                    receive_address = embit_utils.get_multisig_address(descriptor=self.descriptor, index=i, is_change=False, embit_network=self.embit_network)
                    change_address = embit_utils.get_multisig_address(descriptor=self.descriptor, index=i, is_change=True, embit_network=self.embit_network)

                else:
                    receive_address = embit_utils.get_single_sig_address(xpub=self.xpub, script_type=self.script_type, index=i, is_change=False, embit_network=self.embit_network)
                    change_address = embit_utils.get_single_sig_address(xpub=self.xpub, script_type=self.script_type, index=i, is_change=True, embit_network=self.embit_network)
                    
                if self.address == receive_address:
                    self.verified_index.set_value(i)
                    self.verified_index_is_change.set_value(0)
                    self.keep_running = False
                    break

                elif self.address == change_address:
                    self.verified_index.set_value(i)
                    self.verified_index_is_change.set_value(1)
                    self.keep_running = False
                    break

                # Increment our index counter
                self.threadsafe_counter.increment()



    class ExpandedBruteForceAddressVerificationThread(BaseThread):
        """
            Searches all standard derivation paths (BIP44/49/84/86) across accounts
            0-9 and non-standard paths, checking a fixed number of addresses per path.
            The script type used for address generation is inferred from the scanned
            address.
        """
        def __init__(self, address: str, seed: Seed, script_type: str, embit_network: str, network: str, derivation_paths: list, addrs_per_path: int, threadsafe_counter: ThreadsafeCounter, verified_index: ThreadsafeCounter, verified_index_is_change: ThreadsafeCounter):
            super().__init__()
            self.address = address
            self.seed = seed
            self.script_type = script_type
            self.embit_network = embit_network
            self.network = network
            self.derivation_paths = derivation_paths
            self.addrs_per_path = addrs_per_path
            self.threadsafe_counter = threadsafe_counter
            self.verified_index = verified_index
            self.verified_index_is_change = verified_index_is_change
            self.matched_derivation_path = None


        def run(self):
            from seedsigner.helpers import embit_utils
            for path in self.derivation_paths:
                if not self.keep_running:
                    return

                try:
                    xpub = self.seed.get_xpub(wallet_path=path, network=self.network)
                except Exception:
                    # Skip paths that can't be derived for this seed type
                    self.threadsafe_counter.increment(self.addrs_per_path)
                    continue

                for i in range(self.addrs_per_path):
                    if not self.keep_running:
                        return

                    receive_address = embit_utils.get_single_sig_address(
                        xpub=xpub, script_type=self.script_type,
                        index=i, is_change=False, embit_network=self.embit_network,
                    )
                    change_address = embit_utils.get_single_sig_address(
                        xpub=xpub, script_type=self.script_type,
                        index=i, is_change=True, embit_network=self.embit_network,
                    )

                    if self.address == receive_address:
                        self.matched_derivation_path = path
                        self.verified_index.set_value(i)
                        self.verified_index_is_change.set_value(0)
                        self.keep_running = False
                        return

                    elif self.address == change_address:
                        self.matched_derivation_path = path
                        self.verified_index.set_value(i)
                        self.verified_index_is_change.set_value(1)
                        self.keep_running = False
                        return

                    self.threadsafe_counter.increment()



class SeedAddressVerificationSuccessView(View):
    def __init__(self, seed_num: int):
        super().__init__()
        self.seed_num = seed_num
        if self.seed_num is not None:
            self.seed = self.controller.get_seed(seed_num)
    

    def run(self):
        self.run_screen(
            seed_screens.SeedAddressVerificationSuccessScreen,
            address = self.controller.unverified_address["address"],
            verified_index = self.controller.unverified_address["verified_index"],
            verified_index_is_change = self.controller.unverified_address["verified_index_is_change"],
        )

        return Destination(MainMenuView)



class SeedExportXpubVerificationSuccessView(View):
    def run(self):
        from seedsigner.gui.screens.screen import WarningScreen, ButtonOption
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Wallet Export"),
            status_icon_name=SeedSignerIconConstants.SUCCESS,
            text=_("Wallet export successful."),
            button_data=[ButtonOption(_("OK"))],
            show_back_button=False,
        )
        self.controller.multisig_wallet_descriptor = None
        return Destination(MainMenuView)


class SeedExportXpubVerificationFailedView(View):
    def __init__(self, reason: str = "no_match"):
        super().__init__()
        self.reason = reason

    def run(self):
        from seedsigner.gui.screens.screen import WarningScreen, ButtonOption
        if self.reason == "script_mismatch":
            text = _("Address format doesn't match exported script type. Wallet export unsuccessful.")
        else:
            text = _("Unable to match wallet to current seed. Wallet export unsuccessful.")
        self.run_screen(
            WarningScreen,
            title=_("Export Failed"),
            status_icon_name=SeedSignerIconConstants.ERROR,
            status_headline=None,
            text=text,
            button_data=[ButtonOption(_("OK"))],
            show_back_button=False,
        )
        self.controller.multisig_wallet_descriptor = None
        return Destination(MainMenuView)


class LoadMultisigWalletDescriptorView(View):
    SCAN = ButtonOption("Scan Descriptor", SeedSignerIconConstants.QRCODE)
    FROM_SEEDKEEPER = ButtonOption("Load SeedKeeper", FontAwesomeIconConstants.LOCK)
    CANCEL = ButtonOption("Cancel")

    def run(self):
        button_data = [self.SCAN]
        if self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_SUPPORT) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.FROM_SEEDKEEPER)
        button_data.append(self.CANCEL)
        selected_menu_num = self.run_screen(
            seed_screens.LoadMultisigWalletDescriptorScreen,
            button_data=button_data,
            show_back_button=False,
        )

        if button_data[selected_menu_num] == self.SCAN:
            from seedsigner.views.scan_views import ScanWalletDescriptorView
            return Destination(ScanWalletDescriptorView)

        elif button_data[selected_menu_num] == self.CANCEL:
            from seedsigner.controller import Controller
            if self.controller.resume_main_flow == Controller.FLOW__PSBT:
                return Destination(BackStackView)
            else:
                return Destination(MainMenuView)

        elif button_data[selected_menu_num] == self.FROM_SEEDKEEPER:
            from seedsigner.views.tools_views import ToolsSeedkeeperLoadDescriptorView
            return Destination(ToolsSeedkeeperLoadDescriptorView)



class MultisigWalletDescriptorView(View):
    RETURN = ButtonOption("Return to PSBT")
    VERIFY_ADDR = ButtonOption("Verify Addr")
    ADDRESS_EXPLORER = ButtonOption("Address Explorer")
    OK = ButtonOption("OK")

    def run(self):
        descriptor = self.controller.multisig_wallet_descriptor

        fingerprints = []
        for key in descriptor.keys:
            fingerprint = hexlify(key.fingerprint).decode()
            fingerprints.append(fingerprint)
        
        policy = descriptor.brief_policy.split("multisig")[0].strip()
        # policy = " / ".join(policy.split(" of ")) # i18n w/o l10n since coming from non-l10n embit

        button_data = [self.OK]
        if self.controller.resume_main_flow:
            from seedsigner.controller import Controller
            if self.controller.resume_main_flow == Controller.FLOW__PSBT:
                button_data = [self.RETURN]
            elif self.controller.resume_main_flow == Controller.FLOW__VERIFY_MULTISIG_ADDR and self.controller.unverified_address:
                verify_addr_display = f"""{_(self.VERIFY_ADDR.button_label)} {self.controller.unverified_address["address"][:7]}"""
                button_data = [ButtonOption(verify_addr_display)]
            elif self.controller.resume_main_flow == Controller.FLOW__ADDRESS_EXPLORER:
                button_data = [self.ADDRESS_EXPLORER]

        selected_menu_num = self.run_screen(
            seed_screens.MultisigWalletDescriptorScreen,
            policy=policy,
            fingerprints=fingerprints,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            self.controller.multisig_wallet_descriptor = None
            return Destination(BackStackView)
        
        elif button_data[selected_menu_num] == self.RETURN:
            # Jump straight back to PSBT change verification
            from seedsigner.views.psbt_views import PSBTChangeDetailsView
            self.controller.resume_main_flow = None
            return Destination(PSBTChangeDetailsView, view_args=dict(change_address_num=0))

        elif button_data[selected_menu_num].button_label.startswith(_(self.VERIFY_ADDR.button_label)):
            self.controller.resume_main_flow = None
            return Destination(SeedAddressVerificationView)

        elif button_data[selected_menu_num] == self.ADDRESS_EXPLORER:
            from seedsigner.views.tools_views import ToolsAddressExplorerAddressTypeView
            self.controller.resume_main_flow = None
            return Destination(ToolsAddressExplorerAddressTypeView)

        return Destination(MainMenuView)



"""****************************************************************************
    Sign Message Views
****************************************************************************"""
class SeedSignMessageStartView(View):
    """
    Routes users straight through to the "Sign" screen if a signing `seed_num` has
    already been selected. Otherwise routes to `SeedSelectSeedView` to select or
    load a seed first.
    """
    def __init__(self, derivation_path: str, message: str):
        from seedsigner.helpers import embit_utils
        super().__init__()
        self.derivation_path = derivation_path
        self.message = message

        if self.settings.get_value(SettingsConstants.SETTING__MESSAGE_SIGNING) == SettingsConstants.OPTION__DISABLED:
            self.set_redirect(Destination(OptionDisabledView, view_args=dict(settings_attr=SettingsConstants.SETTING__MESSAGE_SIGNING)))
            return

        # calculate the actual receive address
        addr_format = embit_utils.parse_derivation_path(derivation_path)
        if not addr_format["clean_match"]:
            self.set_redirect(Destination(NotYetImplementedView, view_args=dict(text=f"Signing messages for custom derivation paths not supported")))
            self.controller.resume_main_flow = None
            return

        # Note: addr_format["network"] can be MAINNET or [TESTNET, REGTEST]
        if self.settings.get_value(SettingsConstants.SETTING__NETWORK) not in addr_format["network"]:
            from seedsigner.views.view import NetworkMismatchErrorView
            self.set_redirect(Destination(NetworkMismatchErrorView, view_args=dict(derivation_path=self.derivation_path)))

            # cleanup. Note: We could leave this in place so the user can resume the
            # flow, but for now we avoid complications and keep things simple.
            self.controller.resume_main_flow = None
            return

        data = self.controller.sign_message_data
        if not data:
            data = {}
            self.controller.sign_message_data = data
        data["derivation_path"] = derivation_path
        data["message"] = message
        data["addr_format"] = addr_format

        # May be None
        self.seed_num = data.get("seed_num")
    
        if self.seed_num is not None:
            # We already know which seed we're signing with
            self.set_redirect(Destination(SeedSignMessageConfirmMessageView, skip_current_view=True))
        else:
            from seedsigner.controller import Controller
            self.set_redirect(Destination(SeedSelectSeedView, view_args=dict(flow=Controller.FLOW__SIGN_MESSAGE), skip_current_view=True))



class SeedSignMessageConfirmMessageView(View):
    def __init__(self, page_num: int = 0):
        super().__init__()
        self.page_num = page_num  # Note: zero-indexed numbering!


    def run(self):
        from seedsigner.gui.screens.seed_screens import SeedSignMessageConfirmMessageScreen

        selected_menu_num = self.run_screen(
            SeedSignMessageConfirmMessageScreen,
            page_num=self.page_num,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            if self.page_num == 0:
                # We're exiting this flow entirely
                self.controller.resume_main_flow = None
                self.controller.sign_message_data = None
            return Destination(BackStackView)

        # User clicked "Next"
        if self.page_num == len(self.controller.sign_message_data["paged_message"]) - 1:
            # We've reached the end of the paged message
            return Destination(SeedSignMessageConfirmAddressView)
        else:
            return Destination(SeedSignMessageConfirmMessageView, view_args=dict(page_num=self.page_num + 1))



class SeedSignMessageConfirmAddressView(View):
    def __init__(self):
        from embit import bip32
        from seedsigner.helpers import embit_utils

        super().__init__()
        data = self.controller.sign_message_data
        self.seed_num = data.get("seed_num")
        self.derivation_path = data.get("derivation_path")

        if not self.derivation_path:
            raise Exception("Routing error: sign_message_data hasn't been set")

        addr_format = embit_utils.parse_derivation_path(self.derivation_path)
        if not addr_format["clean_match"] or addr_format["script_type"] == SettingsConstants.CUSTOM_DERIVATION:
            raise Exception(_("Signing messages for custom derivation paths not supported"))

        if addr_format["network"] != SettingsConstants.MAINNET:
            if self.settings.get_value(SettingsConstants.SETTING__NETWORK) in [SettingsConstants.TESTNET, SettingsConstants.REGTEST]:
                addr_format["network"] = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
            else:
                from seedsigner.views.view import NetworkMismatchErrorView
                self.set_redirect(Destination(NetworkMismatchErrorView, view_args=dict(derivation_path=self.derivation_path)))

                # cleanup. Note: We could leave this in place so the user can resume the
                # flow, but for now we avoid complications and keep things simple.
                self.controller.resume_main_flow = None
                self.controller.sign_message_data = None
                return

        if self.controller.sign_message_with_satochip:
            connector = self.controller.Satochip_Connector
            script_type = addr_format["script_type"]
            if script_type == SettingsConstants.NATIVE_SEGWIT:
                xtype = "p2wpkh"
            elif script_type == SettingsConstants.NESTED_SEGWIT:
                xtype = "p2wpkh-p2sh"
            elif script_type == SettingsConstants.LEGACY_P2PKH:
                xtype = "standard"
            elif script_type == SettingsConstants.TAPROOT:
                xtype = "standard"
            else:
                xtype = "p2wpkh"
            is_mainnet = addr_format["network"] == SettingsConstants.MAINNET
            from seedsigner.helpers.satochip_signer import format_path_string
            from seedsigner.gui.screens.screen import LoadingScreenThread
            wallet_path = format_path_string(addr_format["wallet_derivation_path"])
            loading = LoadingScreenThread(text=_("Exporting xpub..."))
            loading.start()
            try:
                xpub_base58 = connector.card_bip32_get_xpub(wallet_path, xtype, is_mainnet)
                xpub = bip32.HDKey.from_base58(xpub_base58)
            finally:
                loading.stop()
        else:
            if self.seed_num is None:
                raise Exception("Routing error: sign_message_data hasn't been set")
            seed = self.controller.get_seed(self.seed_num)
            xpub = seed.get_xpub(wallet_path=addr_format["wallet_derivation_path"], network=addr_format["network"])

        data["addr_format"] = addr_format
        embit_network = embit_utils.get_embit_network_name(addr_format["network"])
        self.address = embit_utils.get_single_sig_address(
            xpub=xpub,
            script_type=addr_format["script_type"],
            index=addr_format["index"],
            is_change=addr_format["is_change"],
            embit_network=embit_network,
        )
        data["address"] = self.address


    def run(self):
        from seedsigner.gui.screens.seed_screens import SeedSignMessageConfirmAddressScreen
        selected_menu_num = self.run_screen(
            SeedSignMessageConfirmAddressScreen,
            derivation_path=self.derivation_path,
            address=self.address,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # User clicked "Sign Message"
        return Destination(SeedSignMessageSignedMessageQRView)



class SeedSignMessageSignedMessageQRView(View):
    """
    Displays the signed message as a QR code.
    """
    def __init__(self):
        from seedsigner.helpers import embit_utils
        super().__init__()
        data = self.controller.sign_message_data

        derivation_path = data["derivation_path"]
        message: str = data["message"]

        if self.controller.sign_message_with_satochip:
            from seedsigner.helpers.satochip_signer import (
                sign_message_with_satochip,
                verify_satochip_message_address,
            )
            from seedsigner.gui.screens.screen import LoadingScreenThread

            loading = LoadingScreenThread(text=_("Signing message..."))
            loading.start()
            error: str | None = None
            try:
                verify_satochip_message_address(
                    self.controller.Satochip_Connector,
                    data.get("addr_format", {}),
                    data.get("address"),
                )
                self.signed_message = sign_message_with_satochip(
                    derivation_path, message, self.controller.Satochip_Connector
                )
            except Exception as exc:
                error = str(exc)
            finally:
                loading.stop()
            if error:
                self.set_redirect(
                    Destination(
                        SeedSignMessageSatochipVerificationFailedView,
                        view_args=dict(error=error),
                        skip_current_view=True,
                    )
                )
                return
        else:
            self.seed_num = data["seed_num"]
            seed = self.controller.get_seed(self.seed_num)
            self.signed_message = embit_utils.sign_message(
                seed_bytes=seed.get_root().secret,
                derivation=derivation_path,
                msg=message.encode(),
            )


    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        qr_encoder = GenericStaticQrEncoder(data=self.signed_message)
        
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=qr_encoder,
        )

        # cleanup
        self.controller.resume_main_flow = None
        self.controller.sign_message_data = None
        self.controller.sign_message_with_satochip = False

        # Exiting/Canceling the QR display screen always returns Home
        return Destination(MainMenuView, skip_current_view=True)


class SeedSignMessageSatochipVerificationFailedView(View):
    def __init__(self, error: str):
        super().__init__()
        self.error = error

    def run(self):
        from seedsigner.gui.screens.screen import WarningScreen, ButtonOption

        self.run_screen(
            WarningScreen,
            title=_("Verification Failed"),
            status_headline=None,
            text=self.error,
            button_data=[ButtonOption(_("OK"))],
            show_back_button=False,
        )

        self.controller.resume_main_flow = None
        self.controller.sign_message_data = None
        self.controller.sign_message_with_satochip = False

        return Destination(MainMenuView, skip_current_view=True)


class SeedExportPlaintextQRView(View):
    def __init__(self, seed_num: int, share_index: int | None = None):
        super().__init__()
        self.seed_num = seed_num
        self.seed = self.controller.get_seed(seed_num)
        self.share_index = share_index


    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        data = self.seed.mnemonic_str
        if isinstance(self.seed, XprvSeed):
            data = self.seed.get_root().to_base58()
        if isinstance(self.seed, Slip39Seed) and self.share_index is not None:
            data = self.seed.mnemonic_list[self.share_index]
        encoder_args = dict(data=data)
        e = GenericStaticQrEncoder(**encoder_args)

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=e
        )

        return Destination(
            SeedOptionsView,
            view_args={"seed_num": self.seed_num}
        )

"""****************************************************************************
    Save to SeedKeeper Workflow
****************************************************************************"""
class SaveToSeedkeeperView(View):
    def mnemonic_to_entropy(self, bip39_mnemonic, wordlist):
        from mnemonic import Mnemonic
        print(f"Worldlist: {wordlist}")

        mnemonic_obj = Mnemonic(wordlist)
        entropy = mnemonic_obj.to_entropy(bip39_mnemonic)

        return entropy  # bytearray
    def __init__(self, seed_num: int, bip85_data: dict = None, share_index: int | None = None):
        super().__init__()
        self.seed_num = seed_num
        self.bip85_data = bip85_data
        self.share_index = share_index

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        try:
            Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])

            if not Satochip_Connector:
                return Destination(BackStackView)

            seed = self.controller.get_seed(self.seed_num)

            if isinstance(seed, Slip39Seed):
                if self.share_index is None:
                    button_data = [ButtonOption(f"Share {i+1}") for i in range(len(seed.mnemonic_list))]
                    share_sel = self.run_screen(
                        ButtonListScreen,
                        title="Select Share",
                        is_button_text_centered=False,
                        button_data=button_data,
                        show_back_button=True,
                    )
                    if share_sel == RET_CODE__BACK_BUTTON:
                        return Destination(BackStackView)
                else:
                    share_sel = self.share_index

                share = seed.mnemonic_list[share_sel]
                fingerprint = seed.get_fingerprint(network=self.settings.get_value(SettingsConstants.SETTING__NETWORK))
                ret = seed_screens.SeedAddPassphraseScreen(
                    title="Secret Label",
                    passphrase=fingerprint,
                ).display()
                if "is_back_button" in ret:
                    return Destination(BackStackView)

                label = "SLIP39:" + ret['passphrase']
                export_rights = "Plaintext export allowed"
                header = Satochip_Connector.make_header("Password", export_rights, label)
                share_list = list(bytes(share, 'utf-8'))
                secret_list = [len(share_list)] + share_list
                secret_dic = {'header': header, 'secret_list': secret_list}

            else:
                fingerprint = seed.get_fingerprint(network=self.settings.get_value(SettingsConstants.SETTING__NETWORK))
                ret = seed_screens.SeedAddPassphraseScreen(
                    title="Seed Label",
                    passphrase=fingerprint,
                ).display()
                if "is_back_button" in ret:
                    return Destination(BackStackView)
                status = Satochip_Connector.card_get_status()[3]
                print(status)
                if isinstance(seed, ElectrumSeed):
                    print("Saving Electrum seed")
                    label = ret['passphrase']
                    export_rights = "Plaintext export allowed"
                    type = "Electrum mnemonic"
                    subtype = 0
                    electrum_mnemonic_list = list(bytes(seed.mnemonic_str, 'utf-8'))
                    electrum_passphrase_list = list(bytes(seed.passphrase, 'utf-8'))
                    secret_list = [len(electrum_mnemonic_list)] + electrum_mnemonic_list + [len(electrum_passphrase_list)] + electrum_passphrase_list
                    header = Satochip_Connector.make_header(type, export_rights, label, subtype=subtype)
                    secret_dic = {'header': header, 'secret_list': secret_list}
                else:
                    if isinstance(seed, XprvSeed) and status['protocol_minor_version'] == 1:
                        self.run_screen(
                            WarningScreen,
                            title="Error",
                            status_headline=None,
                            text="SeedKeeper v1 cannot store xprv seeds.",
                            show_back_button=True,
                        )
                        return Destination(BackStackView)

                    if status['protocol_minor_version'] == 1:  # Seedkeeper v1
                        print("Saving to SeedKeeper V1")
                        label = ret['passphrase']
                        export_rights = "Plaintext export allowed"
                        type = "BIP39 mnemonic"
                        subtype = 0
                        bip39_mnemonic = seed.mnemonic_str
                        bip39_mnemonic_list = list(bytes(bip39_mnemonic, 'utf-8'))
                        bip39_passphrase = seed.passphrase
                        bip39_passphrase_list = list(bytes(bip39_passphrase, 'utf-8'))
                        secret_list = [len(bip39_mnemonic_list)] + bip39_mnemonic_list + [len(bip39_passphrase_list)] + bip39_passphrase_list
                    else:
                        print("Saving to SeedKeeper V2")
                        label = ret['passphrase']
                        export_rights = "Plaintext export allowed"
                        if isinstance(seed, XprvSeed):
                            type = "Data"
                            label = f"XPRV:{label}"
                            xprv_list = list(bytes(seed.get_root().to_base58(), 'utf-8'))
                            secret_list = list(len(xprv_list).to_bytes(2, "big")) + xprv_list
                        else:
                            type = "Masterseed"
                            subtype = 0x01
                            wordlist_byte = dict_swap_keys_values(BIP39_WORDLIST_DIC).get("english")
                            bip39_entropy_bytes = self.mnemonic_to_entropy(seed.mnemonic_str, "english")
                            bip39_entropy_list = list(bip39_entropy_bytes)
                            bip39_passphrase_list = list(bytes(seed.passphrase, 'utf-8'))
                            masterseed_bytes = seed.seed_bytes
                            masterseed_list = list(masterseed_bytes)
                            secret_list = ([len(masterseed_list)] +
                                           masterseed_list +
                                           [wordlist_byte] +
                                           [len(bip39_entropy_list)] +
                                           bip39_entropy_list +
                                           [len(bip39_passphrase_list)] +
                                           bip39_passphrase_list
                                           )
                    if type == "Data":
                        header = Satochip_Connector.make_header(type, export_rights, label)
                    else:
                        header = Satochip_Connector.make_header(type, export_rights, label, subtype=subtype)
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
                    show_back_button=True,
                )
                return Destination(BackStackView)

            if not fits:
                self.run_screen(
                    WarningScreen,
                    title="Not Enough Space",
                    status_headline=None,
                    text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
                    show_back_button=True,
                )
                return Destination(BackStackView)

            self.loading_screen = LoadingScreenThread(text="Saving Seed\n\n\n\n\n\n")
            self.loading_screen.start()
            (sid, fingerprint) = Satochip_Connector.seedkeeper_import_secret(secret_dic)
            print("Imported - SID:", sid, " Fingerprint:", fingerprint)

            self.loading_screen.stop()
            time.sleep(0.1) # Sleep for 100ms
            self.run_screen(
                LargeIconStatusScreen,
                title="Secret Saved",
                status_headline=None,
                text=f"Secret Successfully Saved to Seedkeeper",
                show_back_button=True,
            )
            return Destination(SeedOptionsView, view_args={"seed_num": self.seed_num}, clear_history=True)

        except Exception as e:
            print(e)
            self.loading_screen.stop()
            time.sleep(0.1) # Sleep for 100ms
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=True,
            )
            return Destination(BackStackView)
