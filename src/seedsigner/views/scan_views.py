"""Generic QR scan view.

The legacy SeedSigner scan flow (SeedQR / SLIP-39 / WIF / BIP38 /
Encrypted QR / wallet descriptor / address / sign-message / time / aezeed
ambiguity) was bound to the on-device seed manager. With the keycard-only
firmware the only QR payloads we still consume here are settings QRs and
PSBTs. Bitcoin signing is wired in once the new Tools > Keycard > Bitcoin
flow lands (commit C10); for now PSBT scanning surfaces a stub error.

The ``ScanView`` base class is also reused by ``ScanEthSignRequestView`` in
``keycard_views.py`` (UR ``eth-sign-request``).
"""

import logging
import time

from gettext import gettext as _

from seedsigner.gui.screens.screen import (
    RET_CODE__BACK_BUTTON, ButtonListScreen, ButtonOption,
    LargeIconStatusScreen, WarningScreen,
)
from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import (
    BackStackView, ErrorView, MainMenuView, NotYetImplementedView, View,
    Destination,
)

logger = logging.getLogger(__name__)


class ScanView(View):
    """Generic scan view. Accepts settings QRs and emits a clear error for
    any other payload — concrete payload handlers (PSBT, ETH sign-request)
    live in their own subclasses or callers.
    """
    instructions_text = _mft("Scan a QR code")
    invalid_qr_type_message = _mft("QRCode not recognized or not yet supported.")

    def __init__(self):
        from seedsigner.models.decode_qr import DecodeQR

        super().__init__()
        self.wordlist_language_code = self.settings.get_value(
            SettingsConstants.SETTING__WORDLIST_LANGUAGE,
        )
        self.decoder: DecodeQR = DecodeQR(
            wordlist_language_code=self.wordlist_language_code,
        )

    @property
    def is_valid_qr_type(self):
        return True

    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen

        self.run_screen(
            ScanScreen,
            instructions_text=self.instructions_text,
            decoder=self.decoder,
        )

        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)

        if self.decoder.is_complete:
            if not self.is_valid_qr_type:
                return Destination(ErrorView, view_args=dict(
                    title="Error",
                    status_headline=_("Wrong QR Type"),
                    text=_(self.invalid_qr_type_message) + f""", received "{self.decoder.qr_type.replace("__", ": ").replace("_", " ")}\" format""",
                    button_text=_("Back"),
                    next_destination=Destination(BackStackView, skip_current_view=True),
                ))

            if self.decoder.is_settings:
                from seedsigner.views.settings_views import SettingsIngestSettingsQRView
                data = self.decoder.get_settings_data()
                return Destination(SettingsIngestSettingsQRView, view_args=dict(data=data))

            if self.decoder.is_psbt:
                # Bitcoin PSBT signing via Keycard is added in a later
                # commit (C10). For now surface a clear "not yet" so the
                # scan doesn't silently swallow the payload.
                return Destination(NotYetImplementedView)

            return Destination(NotYetImplementedView)

        if self.decoder.is_invalid:
            self.controller.resume_main_flow = None
            return Destination(ScanInvalidQRTypeView)

        return Destination(MainMenuView)


class ScanInvalidQRTypeView(View):
    """Catch-all error view for an unrecognised QR payload."""

    def run(self):
        self.run_screen(
            WarningScreen,
            title="Error",
            status_headline=_("Unrecognised QR"),
            text=_("Scanned QR code was not in a supported format."),
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(MainMenuView, clear_history=True)
