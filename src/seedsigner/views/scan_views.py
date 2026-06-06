"""Generic QR scan view.

The legacy SeedSigner scan flow (SeedQR / SLIP-39 / WIF / BIP38 /
Encrypted QR / wallet descriptor / address / sign-message / time / aezeed
ambiguity) was bound to the on-device seed manager. With the keycard-only
firmware the payloads we still consume here are settings QRs, PSBTs (BTC
Keycard sign flow) and UR ``eth-sign-request`` (ETH Keycard sign flow).

The ``ScanView`` base class is also reused by ``ScanEthSignRequestView`` and
``ToolsKeycardBtcSignPsbtScanView`` in ``keycard_views.py``.
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
    BackStackView, ErrorView, MainMenuView, View,
    Destination,
)

logger = logging.getLogger(__name__)


class HomeScanView(View):
    """Home > Scan entry point for the keycard-only firmware.

    There is no "scan with" chooser any more: every payload we can act on
    needs a card (PSBT -> Keycard BTC sign, ``eth-sign-request`` -> Keycard
    ETH sign; a settings QR is the only card-less payload and still imports).
    So the reader is checked up front — no card means an "Insert card" error
    *before* the camera opens, instead of letting the user scan + review and
    only discover the missing card at sign time.

    When a card is present it is paired silently (best-effort, default
    credentials) so the later sign step doesn't interrupt the flow for a
    pairing password, then control passes to the generic :class:`ScanView`
    which decodes the QR and routes it to the matching keycard flow.
    """

    def run(self):
        from seedsigner.helpers.card_probe import probe_card

        # A reader/driver hiccup or a missing PCSC stack surfaces as "no card"
        # rather than a crash; the user can reseat and retry. The probe opens
        # and releases its own connection, so it never holds the reader past
        # this view.
        try:
            present = probe_card("keycard", self.controller).present
        except Exception:
            logger.exception("home-scan card probe failed")
            present = False

        if not present:
            # Subtle toast (matches CardsMenuView) instead of a heavy
            # full-screen error: every Home>Scan payload needs a card, so
            # bounce home with a gentle "Insert a card first" hint.
            try:
                from seedsigner.gui.toast import InfoToast
                self.controller.activate_toast(
                    InfoToast(label_text=_("Insert a card first"))
                )
            except Exception:
                logger.exception("InfoToast dispatch failed in HomeScanView")
            return Destination(MainMenuView, clear_history=True)

        # Best-effort: pair the inserted card now (default credentials) so a
        # later sign step doesn't interrupt mid-review for a pairing password.
        # Fully non-fatal — the sign flows re-try and fall back to the Pair
        # view for cards that use a custom pairing password.
        try:
            if not self.controller.has_any_keycard_auth():
                from seedsigner.helpers.keycard.ui_helpers import (
                    try_silent_ephemeral_pair,
                )
                try_silent_ephemeral_pair(self)
        except Exception:
            logger.exception("home-scan silent pairing failed")

        return Destination(ScanView, skip_current_view=True)


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
                self.controller.psbt = self.decoder.get_psbt()
                from seedsigner.views.keycard_views import ToolsKeycardBtcSignPsbtReviewView
                return Destination(ToolsKeycardBtcSignPsbtReviewView, skip_current_view=True)

            if self.decoder.is_eth_sign_request:
                try:
                    request = self.decoder.get_eth_sign_request()
                except Exception as exc:
                    logger.exception("eth-sign-request parsing failed")
                    return Destination(ErrorView, view_args=dict(
                        title=_("Invalid request"),
                        status_headline=_("Could not decode"),
                        text=str(exc)[:120],
                        button_text=_("Back"),
                        next_destination=Destination(BackStackView, skip_current_view=True),
                    ))
                if request is None:
                    return Destination(ErrorView, view_args=dict(
                        title=_("Invalid request"),
                        status_headline=_("No data decoded"),
                        text=_("The scanned QR was empty or malformed."),
                        button_text=_("Back"),
                        next_destination=Destination(BackStackView, skip_current_view=True),
                    ))
                self.controller.eth_sign_request = request
                from seedsigner.views.keycard_views import ToolsKeycardSignEthOverviewView
                return Destination(ToolsKeycardSignEthOverviewView, skip_current_view=True)

            return Destination(ErrorView, view_args=dict(
                title=_("Unsupported"),
                status_headline=_("QR not supported"),
                text=_("received {}").format(self.decoder.qr_type),
                button_text=_("Back"),
                next_destination=Destination(BackStackView, skip_current_view=True),
            ))

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
