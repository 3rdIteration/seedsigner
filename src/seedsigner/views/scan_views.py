import logging
import re
import time
import subprocess

#from embit.descriptor import Descriptor

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON, ButtonListScreen, WarningScreen, DireWarningScreen
from seedsigner.gui.screens.scan_screens import (
    ScanAmbiguousQRScreen,
    ScanEncryptedQRScreen,
    ScanTypeEncryptionKeyScreen,
    ScanReviewEncryptionKeyScreen,
)
from seedsigner.gui.screens import LargeIconStatusScreen
from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.seed import Seed, AezeedSeed, XprvSeed, InvalidSeedException

from gettext import gettext as _
from seedsigner.helpers.l10n import mark_for_translation as _mft

from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import BackStackView, ErrorView, MainMenuView, NotYetImplementedView, View, Destination
from seedsigner.views.seed_views import SeedSlip39MoreSharesView, SeedSlip39ShareInvalidView
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.hardware.microsd import MicroSD

logger = logging.getLogger(__name__)


def finalize_mnemonic_seed(
    controller,
    settings,
    seed_mnemonic: list[str],
    seed_type: str,
    wordlist_language_code: str,
    skip_current_view: bool = False,
) -> Destination:
    # Found a valid mnemonic seed! All new seeds should be considered
    #   pending (might set a passphrase, SeedXOR, etc) until finalized.
    if seed_type == "aezeed":
        seed = AezeedSeed(mnemonic=seed_mnemonic)
        controller.storage.set_pending_seed(seed)
        if seed.seed_bytes is None:
            from seedsigner.views.seed_views import SeedAezeedPassphraseModeView
            return Destination(SeedAezeedPassphraseModeView)
    else:
        from seedsigner.models.seed import Seed
        controller.storage.set_pending_seed(
            Seed(mnemonic=seed_mnemonic, wordlist_language_code=wordlist_language_code)
        )
        if settings.get_value(SettingsConstants.SETTING__PASSPHRASE) == SettingsConstants.OPTION__REQUIRED:
            from seedsigner.views.seed_views import SeedAddPassphraseView
            return Destination(SeedAddPassphraseView)

    from .seed_views import SeedFinalizeView
    return Destination(SeedFinalizeView, skip_current_view=skip_current_view)


def finalize_xprv_seed(controller, candidate: str, skip_current_view: bool = False) -> Destination:
    from embit import bip32

    try:
        hdkey = bip32.HDKey.from_string(candidate)
    except Exception:
        return Destination(ScanInvalidQRTypeView)

    if not hdkey.is_private:
        return Destination(ScanInvalidQRTypeView)

    try:
        controller.storage.set_pending_seed(XprvSeed(candidate))
    except InvalidSeedException:
        return Destination(ScanInvalidQRTypeView)

    from .seed_views import SeedFinalizeView
    return Destination(SeedFinalizeView, skip_current_view=skip_current_view)



class ScanView(View):
    """
        The catch-all generic scanning View that will accept any of our supported QR
        formats and will route to the most sensible next step.

        Can also be used as a base class for more specific scanning flows with
        dedicated errors when an unexpected QR type is scanned (e.g. Scan PSBT was
        selected but a SeedQR was scanned).
    """
    instructions_text = _mft("Scan a QR code")
    invalid_qr_type_message = _mft("QRCode not recognized or not yet supported.")


    def __init__(self):
        from seedsigner.models.decode_qr import DecodeQR

        super().__init__()
        # Define the decoder here to make it available to child classes' is_valid_qr_type
        # checks and so we can inject data into it in the test suite's `before_run()`.
        self.wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
        self.decoder: DecodeQR = DecodeQR(wordlist_language_code=self.wordlist_language_code)


    @property
    def is_valid_qr_type(self):
        return True

    def _finalize_mnemonic_seed(self, seed_mnemonic: list[str], seed_type: str) -> Destination:
        return finalize_mnemonic_seed(
            controller=self.controller,
            settings=self.settings,
            seed_mnemonic=seed_mnemonic,
            seed_type=seed_type,
            wordlist_language_code=self.wordlist_language_code,
        )

    def _finalize_xprv_seed(self, xprv: str) -> Destination:
        return finalize_xprv_seed(controller=self.controller, candidate=xprv)


    def _scanner_unavailable_destination(self) -> Destination:
        if DecodeQR.is_qr_scanner_available():
            return None

        return Destination(
            ErrorView,
            view_args=dict(
                title="Error",
                status_headline=_("QR Scanner Unavailable"),
                text=_("QR scanning backend missing. Install zbar (or OpenCV on desktop) and restart."),
                button_text=_("Back"),
                next_destination=Destination(BackStackView, skip_current_view=True),
            ),
            skip_current_view=True,
        )


    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen

        unavailable = self._scanner_unavailable_destination()
        if unavailable is not None:
            return unavailable

        # Start the live preview and background QR reading
        self.run_screen(
            ScanScreen,
            instructions_text=self.instructions_text,
            decoder=self.decoder
        )

        # A long scan might have exceeded the screensaver timeout; ensure screensaver
        # doesn't immediately engage when we leave here.
        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)

        # Handle the results
        if self.decoder.is_complete:
            if not self.is_valid_qr_type:
                # We recognized the QR type but it was not the type expected for the
                # current flow.
                # Report QR types in more human-readable text (e.g. QRType
                # `seed__compactseedqr` as "seed: compactseedqr").
                # TODO: cleanup l10n presentation
                return Destination(ErrorView, view_args=dict(
                    title="Error",
                    status_headline=_("Wrong QR Type"),
                    text=_(self.invalid_qr_type_message) + f""", received "{self.decoder.qr_type.replace("__", ": ").replace("_", " ")}\" format""",
                    button_text=_("Back"),
                    next_destination=Destination(BackStackView, skip_current_view=True),
                ))

            if self.decoder.is_seed:
                seed_mnemonic = self.decoder.get_seed_phrase()
                seed_type = self.decoder.get_seed_type()

                if not seed_mnemonic:
                    # seed is not valid, Exit if not valid with message
                    return Destination(NotYetImplementedView)

                if seed_type == "ambiguous":
                    TYPE_BIP39 = ButtonOption("BIP39")
                    TYPE_AEZEED = ButtonOption("Aezeed")
                    button_data = [TYPE_BIP39, TYPE_AEZEED]
                    selected = self.run_screen(
                        ButtonListScreen,
                        title=_("Select Seed Type"),
                        is_button_text_centered=True,
                        button_data=button_data,
                    )
                    if selected == RET_CODE__BACK_BUTTON:
                        return Destination(BackStackView)
                    seed_type = "aezeed" if button_data[selected] == TYPE_AEZEED else "bip39"

                return self._finalize_mnemonic_seed(seed_mnemonic, seed_type)

            elif self.decoder.is_slip39_share:
                share = self.decoder.get_slip39_share()
                words = share.split()
                self.controller.storage.init_pending_slip39_share(num_words=len(words))
                for i, w in enumerate(words):
                    self.controller.storage.update_pending_slip39_share(w, i)
                self.controller.storage.finalize_current_slip39_share()
                return Destination(SeedSlip39MoreSharesView)

            elif self.decoder.is_xprv:
                return self._finalize_xprv_seed(self.decoder.get_xprv())

            elif self.decoder.is_ambiguous_qr:
                return Destination(
                    ScanAmbiguousQRPromptView,
                    view_args=dict(
                        segment=self.decoder.get_ambiguous_segment(),
                        candidate_types=self.decoder.get_ambiguous_candidate_types(),
                        public_data=self.decoder.get_ambiguous_public_data(),
                    ),
                    skip_current_view=True,
                )
            
            elif self.decoder.is_psbt:
                from seedsigner.views.psbt_views import PSBTSelectSeedView
                psbt = self.decoder.get_psbt()
                if psbt is None:
                    # The QR announced itself as a psbt (a UR2 `crypto-psbt`
                    # says so in its type string) but the payload doesn't
                    # parse. Refuse here: routing on with `controller.psbt =
                    # None` only produces a bare "No transaction currently
                    # loaded" exception two Views later.
                    logger.warning("Scanned psbt could not be parsed")
                    self.run_screen(
                        WarningScreen,
                        title=_("Invalid PSBT"),
                        status_headline=None,
                        text=_("This transaction could not be read. It may be corrupted or malformed."),
                        button_data=[ButtonOption("Done")],
                        show_back_button=False,
                    )
                    return Destination(MainMenuView, clear_history=True)

                self.controller.psbt = psbt
                self.controller.psbt_parser = None
                # Delivered by QR: there is no file, so no mtime to date it by.
                # Clear rather than leave, or a previous microSD transaction's
                # timestamp would be applied to this one.
                self.controller.psbt_source_time = None
                return Destination(PSBTSelectSeedView, skip_current_view=True)

            elif self.decoder.is_settings:
                from seedsigner.views.settings_views import SettingsIngestSettingsQRView
                data = self.decoder.get_settings_data()
                return Destination(SettingsIngestSettingsQRView, view_args=dict(data=data))
            
            elif self.decoder.is_wallet_descriptor:
                from embit.descriptor import Descriptor
                from seedsigner.views.seed_views import MultisigWalletDescriptorView
                from seedsigner.helpers import embit_utils

                descriptor_str = self.decoder.get_wallet_descriptor()

                # Ensure keys include branch/index wildcards so the Address Explorer
                # and change verification work correctly for all descriptor formats.
                descriptor_str = embit_utils.normalize_descriptor_str(descriptor_str)

                descriptor = Descriptor.from_string(descriptor_str)

                self.controller.multisig_wallet_descriptor = descriptor
                return Destination(MultisigWalletDescriptorView, skip_current_view=True)
            
            elif self.decoder.is_address:
                from seedsigner.views.seed_views import AddressVerificationStartView
                address = self.decoder.get_address()
                (script_type, network) = self.decoder.get_address_type()

                return Destination(
                    AddressVerificationStartView,
                    skip_current_view=True,
                    view_args={
                        "address": address,
                        "script_type": script_type,
                        "network": network,
                    }
                )
            
            elif self.decoder.is_sign_message:
                from seedsigner.views.seed_views import SeedSignMessageStartView
                qr_data = self.decoder.get_qr_data()

                return Destination(
                    SeedSignMessageStartView,
                    view_args=dict(
                        derivation_path=qr_data["derivation_path"],
                        message=qr_data["message"],
                    )
                )

            elif self.decoder.is_time:
                dt = self.decoder.get_time()
                if dt:
                    if MicroSD.is_desktop_mode():
                        self.run_screen(
                            WarningScreen,
                            title="Unavailable",
                            status_headline=None,
                            text="Setting the system time is not supported on desktop.",
                            show_back_button=False,
                            button_data=[ButtonOption("OK")],
                        )
                        return Destination(MainMenuView)
                    try:
                        subprocess.run([
                            "date",
                            "-s",
                            dt.strftime("%Y-%m-%d %H:%M:%S"),
                        ], check=True)
                        # Reset activity-based timers since system time changed
                        self.controller.reset_screensaver_timeout()
                        self.run_screen(
                            LargeIconStatusScreen,
                            title="Success",
                            status_headline=None,
                            text=_("Time set to:") + f" {dt.strftime('%Y-%m-%d %H:%M:%S')}",
                            show_back_button=False,
                        )
                    except Exception as e:
                        return Destination(
                            ErrorView,
                            view_args=dict(
                                title="Error",
                                status_headline=_("Set Time Failed"),
                                text=str(e),
                                button_text=_("Back"),
                                next_destination=Destination(MainMenuView, skip_current_view=True),
                            ),
                        )
                    return Destination(MainMenuView)
                else:
                    return Destination(
                        ErrorView,
                        view_args=dict(
                            title="Error",
                            status_headline=_("Invalid Time"),
                            text=_("Could not parse time from QR"),
                            button_text=_("Back"),
                            next_destination=Destination(MainMenuView, skip_current_view=True),
                        ),
                    )

            elif self.decoder.is_bip38:
                if self.settings.get_value(SettingsConstants.SETTING__BIP38_KEYS) == SettingsConstants.OPTION__ENABLED:
                    from seedsigner.views.psbt_views import PSBTBIP38PassphraseView

                    bip38 = self.decoder.get_bip38()
                    return Destination(PSBTBIP38PassphraseView, view_args=dict(encrypted=bip38), skip_current_view=True)
                else:
                    return Destination(ScanInvalidQRTypeView)

            elif self.decoder.is_wif:
                if self.settings.get_value(SettingsConstants.SETTING__WIF_KEYS) == SettingsConstants.OPTION__ENABLED:
                    from seedsigner.models.wif import WIFKey
                    from seedsigner.views.psbt_views import PSBTOverviewView

                    wif = self.decoder.get_wif()
                    self.controller.psbt_seed = WIFKey(wif)
                    return Destination(PSBTOverviewView, skip_current_view=True)
                else:
                    return Destination(ScanInvalidQRTypeView)

            elif self.decoder.is_encrypted_seedqr:
                DECRYPT = ButtonOption("Decrypt")
                CANCEL = ButtonOption("Cancel")
                button_data = [DECRYPT, CANCEL]

                public_data = self.decoder.get_public_data()

                selected_menu_num = self.run_screen(
                    ScanEncryptedQRScreen,
                    public_data=public_data,
                    button_data=button_data,
                )

                if button_data[selected_menu_num] == DECRYPT:
                    return Destination(ScanEncryptedQREncryptionKeyView)

                elif button_data[selected_menu_num] == CANCEL:
                    self.controller.storage2.clear_encryptedqr()
                    return Destination(MainMenuView)

            else:
                return Destination(NotYetImplementedView)

        elif self.decoder.is_invalid:
            # For now, don't even try to re-do the attempted operation, just reset and
            # start everything over.
            self.controller.resume_main_flow = None
            return Destination(ScanInvalidQRTypeView)

        return Destination(MainMenuView)



class ScanPSBTView(ScanView):
    instructions_text = _mft("Scan Transaction")
    invalid_qr_type_message = _mft("Expected a transaction")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_psbt



class ScanSeedQRView(ScanView):
    instructions_text = _mft("Scan SeedQR")
    invalid_qr_type_message = _mft("Expected a SeedQR")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_seed or self.decoder.is_encrypted_seedqr or self.decoder.is_xprv or self.decoder.is_ambiguous_qr


class ScanSlip39ShareQRView(ScanView):
    instructions_text = _mft("Scan SLIP-39 Share")
    invalid_qr_type_message = _mft("Expected a SLIP-39 share QR")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_slip39_share

    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.models.qr_type import QRType

        unavailable = self._scanner_unavailable_destination()
        if unavailable is not None:
            return unavailable

        self.run_screen(
            ScanScreen,
            instructions_text=self.instructions_text,
            decoder=self.decoder
        )

        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)

        if self.decoder.is_complete:
            share = self.decoder.get_slip39_share()
            words = share.split()
            self.controller.storage.init_pending_slip39_share(num_words=len(words))
            for i, w in enumerate(words):
                self.controller.storage.update_pending_slip39_share(w, i)
            try:
                self.controller.storage.finalize_current_slip39_share()
            except InvalidSeedException:
                return Destination(
                    SeedSlip39ShareInvalidView,
                    view_args={"length": len(words), "retry_scan": True},
                    skip_current_view=True,
                )
            return Destination(SeedSlip39MoreSharesView)

        elif self.decoder.qr_type == QRType.SEED__SLIP39:
            return Destination(
                SeedSlip39ShareInvalidView,
                view_args={"length": 33, "retry_scan": True},
                skip_current_view=True,
            )

        elif self.decoder.is_invalid:
            self.controller.resume_main_flow = None
            return Destination(ScanInvalidQRTypeView)

        return Destination(BackStackView)


class ScanWIFQRView(ScanView):
    instructions_text = _mft("Scan WIF")
    invalid_qr_type_message = _mft("Expected a WIF private key")

    @property
    def is_valid_qr_type(self):
        return (
            self.settings.get_value(SettingsConstants.SETTING__WIF_KEYS) == SettingsConstants.OPTION__ENABLED
            and self.decoder.is_wif
        )


class ScanBIP38QRView(ScanView):
    instructions_text = _mft("Scan BIP38")
    invalid_qr_type_message = _mft("Expected a BIP38 private key")

    @property
    def is_valid_qr_type(self):
        return (
            self.settings.get_value(SettingsConstants.SETTING__BIP38_KEYS) == SettingsConstants.OPTION__ENABLED
            and self.decoder.is_bip38
        )



class ScanWalletDescriptorView(ScanView):
    instructions_text = _mft("Scan descriptor")
    invalid_qr_type_message = _mft("Expected a wallet descriptor QR")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_wallet_descriptor



class ScanAddressView(ScanView):
    instructions_text = _mft("Scan address QR")
    invalid_qr_type_message = _mft("Expected an address QR")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_address


class ScanXpubAddressView(ScanAddressView):
    def __init__(self, seed: Seed, derivation_path: str, script_type: str, sig_type: str, coordinator_label: str):
        super().__init__()
        self.seed = seed
        self.derivation_path = derivation_path
        self.script_type = script_type
        self.sig_type = sig_type
        self.instructions_text = _("Scan {} receive address from the wallet you just exported").format(coordinator_label)

    def run(self):
        destination = super().run()
        from .seed_views import AddressVerificationStartView, SeedAddressVerificationView, SeedExportXpubVerificationFailedView

        if destination.View_cls == AddressVerificationStartView:
            address = self.decoder.get_address()
            (scanned_script_type, network) = self.decoder.get_address_type()
            if scanned_script_type != self.script_type:
                return Destination(
                    SeedExportXpubVerificationFailedView,
                    view_args=dict(reason="script_mismatch"),
                    skip_current_view=True,
                )
            self.controller.unverified_address = dict(
                address=address,
                script_type=self.script_type,
                network=network,
                sig_type=self.sig_type,
                derivation_path=self.derivation_path,
            )
            return Destination(
                SeedAddressVerificationView,
                view_args=dict(seed=self.seed, export_for_xpub=True),
                skip_current_view=True,
            )

        return destination



class ScanAmbiguousQRPromptView(View):
    COMPACT = ButtonOption("CompactSeedQR")
    ENCRYPTED = ButtonOption("EncryptedQR")
    XPRV = ButtonOption("xprv")
    CANCEL = ButtonOption("Cancel")

    def __init__(self, segment: bytes | str, candidate_types: list[str], public_data: str = None):
        super().__init__()
        self.segment = segment
        self.candidate_types = candidate_types
        self.public_data = public_data
        self.wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)

    def run(self):
        from seedsigner.models.qr_type import QRType

        button_data = []
        if QRType.SEED__COMPACTSEEDQR in self.candidate_types:
            button_data.append(self.COMPACT)
        if QRType.SEED__ENCRYPTEDQR in self.candidate_types:
            button_data.append(self.ENCRYPTED)
        if QRType.SEED__XPRV in self.candidate_types:
            button_data.append(self.XPRV)
        button_data.append(self.CANCEL)

        selected_menu_num = self.run_screen(
            ScanAmbiguousQRScreen,
            message=_("Data matches multiple\nQR types."),
            button_data=button_data,
        )

        selected_option = button_data[selected_menu_num]

        if selected_option == self.ENCRYPTED:
            analysis = DecodeQR.analyze_bytedata_payload(self.segment)
            if analysis.encrypted_qr and analysis.public_data:
                DECRYPT = ButtonOption("Decrypt")
                CANCEL = ButtonOption("Cancel")
                button_data = [DECRYPT, CANCEL]

                selected_menu_num = self.run_screen(
                    ScanEncryptedQRScreen,
                    public_data=analysis.public_data,
                    button_data=button_data,
                )

                if button_data[selected_menu_num] == DECRYPT:
                    DecodeQR.store_encrypted_qr_candidate(analysis.encrypted_qr, analysis.public_data)
                    return Destination(ScanEncryptedQREncryptionKeyView, skip_current_view=True)

                elif button_data[selected_menu_num] == CANCEL:
                    return Destination(MainMenuView)

            return Destination(ScanInvalidQRTypeView)

        if selected_option == self.COMPACT:
            from embit import bip39
            return finalize_mnemonic_seed(
                controller=self.controller,
                settings=self.settings,
                # Create independent copies so wipe_list() won't corrupt
                # the shared global wordlist strings.
                seed_mnemonic=["".join(w) for w in bip39.mnemonic_from_bytes(self.segment).split()],
                seed_type="bip39",
                wordlist_language_code=self.wordlist_language_code,
            )

        if selected_option == self.XPRV:
            return finalize_xprv_seed(
                controller=self.controller,
                candidate=self.segment.decode("utf-8").strip(),
            )


        return Destination(MainMenuView)


class ScanEncryptedQREncryptionKeyView(View):
    def run(self):
        TYPE = ButtonOption("Type encryption key")
        SCAN = ButtonOption("Scan encryption key")
        CANCEL = ButtonOption("Cancel")
        button_data = [TYPE, SCAN, CANCEL]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Input Encryption Key",
            show_back_button=False,
            button_data=button_data,
        )

        if button_data[selected_menu_num] == TYPE:
            return Destination(ScanEncryptedQRTypeEncryptionKeyView)

        elif button_data[selected_menu_num] == SCAN:
            return Destination(ScanEncryptedQRScanEncryptionKeyView)

        elif button_data[selected_menu_num] == CANCEL:
            self.controller.storage2.clear_encryptedqr()
            return Destination(MainMenuView)



class ScanEncryptedQRTypeEncryptionKeyView(View):
    def __init__(self, encryption_key: str = ""):
        super().__init__()
        self.encryption_key = encryption_key


    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanTypeEncryptionKeyScreen
        ret_dict = self.run_screen(ScanTypeEncryptionKeyScreen, encryptionkey=self.encryption_key)
        encryption_key=ret_dict["encryptionkey"]

        if "is_back_button" in ret_dict:
            if len(encryption_key) > 0:
                return Destination(
                    ScanEncryptedQRTypeEncryptionKeyExitDialogView,
                    view_args=dict(encryption_key=encryption_key),
                    skip_current_view=True
                )
            else:
                return Destination(BackStackView)

        else:
            return Destination(
                ScanEncryptedQRReviewEncryptionKeyView,
                view_args=dict(encryption_key=encryption_key),
                skip_current_view=True
            )



class ScanEncryptedQRTypeEncryptionKeyExitDialogView(View):
    EDIT = ButtonOption("Edit encryption key")
    DISCARD = ButtonOption("Discard encryption key", button_label_color="red")

    def __init__(self, encryption_key: str):
        super().__init__()
        self.encryption_key = encryption_key


    def run(self):
        button_data = [self.EDIT, self.DISCARD]
        
        selected_menu_num = self.run_screen(
            WarningScreen,
            title="Discard encryption key?",
            status_headline=None,
            text=f"Your current key entry will be erased",
            show_back_button=False,
            button_data=button_data
        )

        if button_data[selected_menu_num] == self.EDIT:
            return Destination(
                ScanEncryptedQRTypeEncryptionKeyView,
                view_args=dict(encryption_key=self.encryption_key),
                skip_current_view=True
            )

        elif button_data[selected_menu_num] == self.DISCARD:
            return Destination(BackStackView)



class ScanEncryptedQRScanEncryptionKeyView(View):
    def __init__(self, encryption_key: str = ""):
        super().__init__()
        self.encryption_key = encryption_key


    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen
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
                ScanEncryptedQRReviewEncryptionKeyView,
                view_args=dict(encryption_key=self.encryption_key),
                skip_current_view=True
            )
        elif decoder.is_nonUTF8:
            DireWarningScreen(
                title="Error!",
                show_back_button=False,
                status_headline="Invalid Text QR Code",
                text=f"Non UTF-8 data detected."
            ).display()
            return Destination(BackStackView)
        else:
            return Destination(BackStackView)



class ScanEncryptedQRReviewEncryptionKeyView(View):
    def __init__(self, encryption_key: str):
        super().__init__()
        self.encryption_key = encryption_key

    def run(self):
        if len(self.encryption_key) > 200:
            WarningScreen(
                title="Error",
                show_back_button=False,
                status_headline="Invalid Key",
                text="Key length is too long.",
            ).display()
            return Destination(BackStackView)

        PROCEED = ButtonOption("Proceed")
        EDIT = ButtonOption("Edit")
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
            return Destination(
                ScanDecryptEncryptedQRView,
                view_args=dict(encryption_key=self.encryption_key),
            )

        elif button_data[selected_menu_num] == EDIT:
            return Destination(
                ScanEncryptedQRTypeEncryptionKeyView,
                view_args=dict(encryption_key=self.encryption_key),
                skip_current_view=True
            )

        elif button_data[selected_menu_num] == SCAN:
            return Destination(
                ScanEncryptedQRScanEncryptionKeyView,
                view_args=dict(encryption_key=self.encryption_key),
                skip_current_view=True
            )



class ScanDecryptEncryptedQRView(View):
    """
        Decrypt an encrypted QR
    """
    def __init__(self, encryption_key: str, encrypted_data: bytes = None):
        super().__init__()
        self.encryption_key: str = encryption_key
        self.encrypted_data: bytes = encrypted_data
        self.wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)

    def _route_decrypted_payload(self, word_bytes: bytes) -> Destination:
        from seedsigner.models.qr_type import QRType

        analysis = DecodeQR.analyze_bytedata_payload(word_bytes)
        resolved_qr_type = DecodeQR.resolve_payload_type(analysis)

        if resolved_qr_type == QRType.SEED__COMPACTSEEDQR:
            from embit import bip39
            return finalize_mnemonic_seed(
                controller=self.controller,
                settings=self.settings,
                # Create independent copies so wipe_list() won't corrupt
                # the shared global wordlist strings.
                seed_mnemonic=["".join(w) for w in bip39.mnemonic_from_bytes(word_bytes).split()],
                seed_type="bip39",
                wordlist_language_code=self.wordlist_language_code,
                skip_current_view=True,
            )

        if resolved_qr_type == QRType.SEED__XPRV:
            candidate = word_bytes.decode("utf-8").strip()
            return finalize_xprv_seed(
                controller=self.controller,
                candidate=candidate,
                skip_current_view=True,
            )

        if resolved_qr_type == QRType.SEED__ENCRYPTEDQR:
            if analysis.encrypted_qr and analysis.public_data:
                DECRYPT = ButtonOption("Decrypt")
                CANCEL = ButtonOption("Cancel")
                button_data = [DECRYPT, CANCEL]

                selected_menu_num = self.run_screen(
                    ScanEncryptedQRScreen,
                    public_data=analysis.public_data,
                    button_data=button_data,
                )

                if button_data[selected_menu_num] == DECRYPT:
                    DecodeQR.store_encrypted_qr_candidate(analysis.encrypted_qr, analysis.public_data)
                    return Destination(ScanEncryptedQREncryptionKeyView, skip_current_view=True)

                elif button_data[selected_menu_num] == CANCEL:
                    return Destination(MainMenuView)

            return Destination(ScanInvalidQRTypeView)


        if resolved_qr_type == QRType.SEED__AMBIGUOUS_QR:
            return Destination(
                ScanAmbiguousQRPromptView,
                view_args=dict(
                    segment=word_bytes,
                    candidate_types=analysis.candidate_types,
                    public_data=analysis.public_data,
                ),
                skip_current_view=True,
            )

        try:
            decoded_text = word_bytes.decode("utf-8")
        except UnicodeDecodeError:
            decoded_text = None

        if decoded_text:
            return Destination(
                ScanDecryptedTextView,
                view_args=dict(text=decoded_text),
                skip_current_view=True,
            )

        return Destination(ScanInvalidQRTypeView)


    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        self.loading_screen = LoadingScreenThread(text="Processing...")
        self.loading_screen.start()

        status = DecodeQRStatus.INVALID
        word_bytes = None
        encryptedqr = None
        try:
            from seedsigner.models.decode_qr import EncryptedQrDecoder
            from seedsigner.models.qr_type import QRType
            decoder = EncryptedQrDecoder()
            status = decoder.add(self.encrypted_data, qr_type=QRType.SEED__ENCRYPTEDQR)
            if status == DecodeQRStatus.COMPLETE:
                encryptedqr = self.controller.storage2.encryptedqr
                if encryptedqr:
                    word_bytes = encryptedqr.encrypted_qr.decrypt(self.encryption_key)
        finally:
            self.loading_screen.stop()

        if status == DecodeQRStatus.COMPLETE:
            if not encryptedqr:
                return Destination(ScanInvalidQRTypeView)
            if not word_bytes:
                WarningScreen(
                    title="Error",
                    show_back_button=False,
                    status_headline="decryption failure",
                    text="Review your encryption key.",
                ).display()
                return Destination(BackStackView)

            self.controller.storage2.clear_encryptedqr()
            return self._route_decrypted_payload(word_bytes)

        else:
            self.controller.storage2.clear_encryptedqr()
            WarningScreen(
                title="Error",
                show_back_button=False,
                status_headline="decryption failure",
                text="Unknown error",
            ).display()
            return Destination(BackStackView)


class ScanInvalidQRTypeView(View):
    def run(self):
        from seedsigner.gui.screens import WarningScreen

        # TODO: This screen says "Error" but is intentionally using the WarningScreen in
        # order to avoid the perception that something is broken on our end. This should
        # either change to use the red ErrorScreen or the "Error" title should be
        # changed to something softer.
        self.run_screen(
            WarningScreen,
            title=_("Error"),
            status_headline=_("Unknown QR Type"),
            text=_("QRCode is invalid or is a data format not yet supported."),
            button_data=[ButtonOption("Back to Main Menu")],
        )

        return Destination(MainMenuView, clear_history=True)


class ScanDecryptedTextView(View):
    def __init__(self, text: str):
        super().__init__()
        self.text = text

    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsTextQRReviewTextScreen

        DONE = ButtonOption("Done")

        self.run_screen(
            ToolsTextQRReviewTextScreen,
            title=_("Decrypted Text"),
            textToEncode=self.text,
            max_lines=8,
            visible_space=False,
            button_data=[DONE],
            show_back_button=False,
        )

        return Destination(MainMenuView, clear_history=True)
