import logging
import re
import time

#from embit.descriptor import Descriptor

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON, ButtonListScreen, WarningScreen, DireWarningScreen
from seedsigner.gui.screens.scan_screens import ScanEncryptedQRScreen, ScanTypeEncryptionKeyScreen, ScanReviewEncryptionKeyScreen
from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.seed import Seed

from gettext import gettext as _
from seedsigner.helpers.l10n import mark_for_translation as _mft

from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import BackStackView, ErrorView, MainMenuView, NotYetImplementedView, View, Destination
from seedsigner.gui.screens.screen import ButtonOption

logger = logging.getLogger(__name__)



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


    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen

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
                    button_text="Back",
                    next_destination=Destination(BackStackView, skip_current_view=True),
                ))

            if self.decoder.is_seed:
                seed_mnemonic = self.decoder.get_seed_phrase()

                if not seed_mnemonic:
                    # seed is not valid, Exit if not valid with message
                    return Destination(NotYetImplementedView)
                else:
                    # Found a valid mnemonic seed! All new seeds should be considered
                    #   pending (might set a passphrase, SeedXOR, etc) until finalized.
                    from seedsigner.models.seed import Seed
                    from .seed_views import SeedFinalizeView
                    self.controller.storage.set_pending_seed(
                        Seed(mnemonic=seed_mnemonic, wordlist_language_code=self.wordlist_language_code)
                    )
                    if self.settings.get_value(SettingsConstants.SETTING__PASSPHRASE) == SettingsConstants.OPTION__REQUIRED:
                        from seedsigner.views.seed_views import SeedAddPassphraseView
                        return Destination(SeedAddPassphraseView)
                    else:
                        return Destination(SeedFinalizeView)
            
            elif self.decoder.is_psbt:
                from seedsigner.views.psbt_views import PSBTSelectSeedView
                psbt = self.decoder.get_psbt()
                self.controller.psbt = psbt
                self.controller.psbt_parser = None
                return Destination(PSBTSelectSeedView, skip_current_view=True)

            elif self.decoder.is_settings:
                from seedsigner.views.settings_views import SettingsIngestSettingsQRView
                data = self.decoder.get_settings_data()
                return Destination(SettingsIngestSettingsQRView, view_args=dict(data=data))
            
            elif self.decoder.is_wallet_descriptor:
                from embit.descriptor import Descriptor
                from seedsigner.views.seed_views import MultisigWalletDescriptorView

                descriptor_str = self.decoder.get_wallet_descriptor()

                try:
                    # We need to replace `/0/*` wildcards with `/{0,1}/*` in order to use
                    # the Descriptor to verify change, too.
                    orig_descriptor_str = descriptor_str
                    if len(re.findall (r'\[([0-9,a-f,A-F]+?)(\/[0-9,\/,h\']+?)\].*?(\/0\/\*)', descriptor_str)) > 0:
                        p = re.compile(r'(\[[0-9,a-f,A-F]+?\/[0-9,\/,h\']+?\].*?)(\/0\/\*)')
                        descriptor_str = p.sub(r'\1/{0,1}/*', descriptor_str)
                    elif len(re.findall (r'(\[[0-9,a-f,A-F]+?\/[0-9,\/,h,\']+?\][a-z,A-Z,0-9]*?)([\,,\)])', descriptor_str)) > 0:
                        p = re.compile(r'(\[[0-9,a-f,A-F]+?\/[0-9,\/,h,\']+?\][a-z,A-Z,0-9]*?)([\,,\)])')
                        descriptor_str = p.sub(r'\1/{0,1}/*\2', descriptor_str)
                except Exception as e:
                    logger.info(repr(e), exc_info=True)
                    descriptor_str = orig_descriptor_str

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
    instructions_text = _mft("Scan PSBT")
    invalid_qr_type_message = _mft("Expected a PSBT")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_psbt



class ScanSeedQRView(ScanView):
    instructions_text = _mft("Scan SeedQR")
    invalid_qr_type_message = _mft("Expected a SeedQR")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_seed or self.decoder.is_encrypted_seedqr



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
    DISCARD = ButtonOption("Discard encryption key", None, None, "red")

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
    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen
        decoder = DecodeQR(is_encryptionkey=True)
        self.run_screen(
            ScanScreen,
            instructions_text="Scan encryption key",
            decoder=decoder
        )
        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)
        if decoder.is_complete:
            encryption_key = decoder.get_encryption_key()
            return Destination(
                ScanEncryptedQRReviewEncryptionKeyView,
                view_args=dict(encryption_key=encryption_key),
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
        button_data = [PROCEED, EDIT]

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



class ScanDecryptEncryptedQRView(View):
    """
        Decrypt an encrypted QR
    """
    def __init__(self, encryption_key: str, encrypted_data: bytes = None):
        super().__init__()
        self.encryption_key: str = encryption_key
        self.encrypted_data: bytes = encrypted_data
        self.wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)


    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        self.loading_screen = LoadingScreenThread(text="Processing...")
        self.loading_screen.start()

        try:
            from seedsigner.models.decode_qr import EncryptedQrDecoder
            from seedsigner.models.qr_type import QRType
            decoder = EncryptedQrDecoder()
            status = decoder.add(self.encrypted_data, qr_type=QRType.SEED__ENCRYPTEDQR, encryption_key=self.encryption_key)
        finally:
            self.loading_screen.stop()

        if status == DecodeQRStatus.COMPLETE:
            self.controller.storage2.clear_encryptedqr()
            self.controller.storage.set_pending_seed(
                Seed(mnemonic=decoder.get_seed_phrase(), wordlist_language_code=self.wordlist_language_code)
            )
            if self.settings.get_value(SettingsConstants.SETTING__PASSPHRASE) == SettingsConstants.OPTION__REQUIRED:
                from seedsigner.views.seed_views import SeedAddPassphraseView
                return Destination(SeedAddPassphraseView, skip_current_view=True)
            else:
                from .seed_views import SeedFinalizeView
                return Destination(SeedFinalizeView, skip_current_view=True)

        elif status == DecodeQRStatus.WRONG_KEY:
            WarningScreen(
                title="Error",
                show_back_button=False,
                status_headline="decryption failure",
                text="Review your encryption key.",
            ).display()
            return Destination(BackStackView)

        else:
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
            button_data=[ButtonOption("Done")],
        )

        return Destination(MainMenuView, clear_history=True)

