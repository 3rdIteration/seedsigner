"""Tools > Keycard views.

Threat model & UX model
-----------------------
Each operation that touches the card opens its own session
(connect → SELECT → OPEN_SECURE_CHANNEL → VERIFY_PIN), runs its work,
and lets the connection drop. The PIN is never cached on the
controller — it lives in a local ``bytearray`` that is wiped before
return. The pairing key, by contrast, is cached on the controller for
the duration of the boot so the user only re-enters the pairing
password once.

Wipe is best-effort: Python's GC and CPython's string interning prevent
ironclad zeroing. Assume any value still resident in memory at the
moment of physical seizure is recoverable. Mitigation is operational
(short sessions, PIN re-entry per operation, no debug logging of
secrets), not cryptographic.

Shared helpers (path formatting, pubkey extraction, PIN/text prompts,
session opening, byte wiping) live in ``helpers/keycard/ui_helpers``.
This module re-exports them under their old underscore-prefixed names
so existing callers and tests keep working.
"""

from __future__ import annotations

import logging
import time
import unicodedata
from typing import Optional

from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    DireWarningScreen,
    ErrorScreen,
    LargeIconStatusScreen,
    WarningScreen,
)
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.gui.screens.scan_screens import ScanScreen
from seedsigner.helpers.ethereum import DEFAULT_ETH_PATH
from seedsigner.helpers.ethereum.address import (
    pubkey_to_address, to_checksum_address,
)
from seedsigner.helpers.ethereum.ur_codec import (
    DATA_TYPE_LEGACY_TX, DATA_TYPE_PERSONAL_MESSAGE,
    DATA_TYPE_TYPED_DATA, DATA_TYPE_TYPED_TX,
    EthSignRequest,
)
from seedsigner.helpers.keycard.ui_helpers import (
    extract_pubkey,
    format_path,
    open_unlocked_session,
    prompt_for_pin,
    prompt_for_text,
    wipe_bytearray,
)
from seedsigner.helpers.secure_delete import wipe_string
from seedsigner.models.encode_qr import EthSignatureQrEncoder
from seedsigner.views.view import (
    BackStackView, Destination, MainMenuView, NotYetImplementedView, View,
)
from seedsigner.views.scan_views import ScanView

# Backwards-compatible aliases for older imports / tests.
_format_path = format_path
_extract_pubkey = extract_pubkey
_wipe_bytearray = wipe_bytearray
_prompt_for_pin = prompt_for_pin
_prompt_for_text = prompt_for_text
_open_unlocked_session = open_unlocked_session

logger = logging.getLogger(__name__)

DATA_TYPE_LABELS = {
    DATA_TYPE_LEGACY_TX: "Legacy / EIP-155",
    DATA_TYPE_TYPED_DATA: "EIP-712 typed data",
    DATA_TYPE_PERSONAL_MESSAGE: "Personal sign",
    DATA_TYPE_TYPED_TX: "EIP-1559",
}

PIN_LENGTH = 6
PUK_LENGTH = 12


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------


class ToolsKeycardMenuView(View):
    SIGN_ETH = ButtonOption("Sign ETH transaction")
    EXPORT_PUBKEY = ButtonOption("Export ETH address")
    PAIR = ButtonOption("Pair card")
    FORGET = ButtonOption("Forget saved pairing")
    UNPAIR = ButtonOption("Unpair (this device)")
    GENERATE_KEY = ButtonOption("Generate key on card")
    INIT = ButtonOption("Initialise blank card")
    STATUS = ButtonOption("Card status")

    def run(self):
        button_data = [
            self.SIGN_ETH,
            self.EXPORT_PUBKEY,
            self.PAIR,
            self.FORGET,
            self.UNPAIR,
            self.GENERATE_KEY,
            self.INIT,
            self.STATUS,
        ]
        selected = self.run_screen(
            ButtonListScreen,
            title="Keycard",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        chosen = button_data[selected]
        if chosen == self.SIGN_ETH:
            return Destination(ToolsKeycardSignEthStartView)
        if chosen == self.EXPORT_PUBKEY:
            return Destination(ToolsKeycardExportPubkeyView)
        if chosen == self.PAIR:
            return Destination(ToolsKeycardPairView)
        if chosen == self.FORGET:
            return Destination(ToolsKeycardForgetSavedPairingView)
        if chosen == self.UNPAIR:
            return Destination(ToolsKeycardUnpairView)
        if chosen == self.GENERATE_KEY:
            return Destination(ToolsKeycardGenerateKeyView)
        if chosen == self.INIT:
            return Destination(ToolsKeycardInitView)
        if chosen == self.STATUS:
            return Destination(ToolsKeycardStatusView)
        return Destination(NotYetImplementedView)


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


class ToolsKeycardStatusView(View):
    def run(self):
        try:
            from seedsigner.helpers.keycard.client import KeycardClient
            from seedsigner.helpers.keycard.reader import wait_for_card
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        try:
            connection = wait_for_card(timeout_s=5.0)
            client = KeycardClient(connection)
            info = client.select()
        except Exception as exc:
            return _error_destination("Card not reachable", str(exc))

        version = f"{(info.app_version >> 8) & 0xFF}.{info.app_version & 0xFF}"
        text = (
            f"Applet v{version}\n"
            f"Pairing slots: {info.free_pairing_slots}\n"
            f"Key on card: {'yes' if info.key_uid else 'no'}"
        )
        self.run_screen(
            LargeIconStatusScreen,
            title="Keycard",
            status_headline=None,
            text=text,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(BackStackView)


# ---------------------------------------------------------------------------
# Initialise
# ---------------------------------------------------------------------------


class ToolsKeycardInitView(View):
    """One-shot Init wizard: random PIN/PUK/password, INIT APDU, display."""

    CONTINUE = ButtonOption("Continue")
    INITIALISE = ButtonOption("Initialise card")

    def run(self):
        try:
            from seedsigner.helpers.keycard import secrets as kc_secrets
            from seedsigner.helpers.keycard.client import KeycardClient
            from seedsigner.helpers.keycard.commands import init as init_apdu
            from seedsigner.helpers.keycard.crypto import derive_pairing_secret
            from seedsigner.helpers.keycard.reader import wait_for_card
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        ret = self.run_screen(
            DireWarningScreen,
            title="Initialise?",
            status_headline=None,
            text="This wipes any existing PIN/PUK/pairing on the card.",
            show_back_button=True,
            button_data=[self.CONTINUE],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        pin = kc_secrets.generate_pin()
        puk = kc_secrets.generate_puk()
        pairing_password = kc_secrets.generate_pairing_password()

        backup_text = (
            f"PIN     {pin}\n"
            f"PUK     {puk}\n"
            f"Pairing {pairing_password}"
        )
        ret = self.run_screen(
            WarningScreen,
            title="Write these down",
            status_headline=None,
            text=backup_text,
            show_back_button=True,
            button_data=[self.INITIALISE],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        try:
            connection = wait_for_card(timeout_s=5.0)
            client = KeycardClient(connection)
            client.select()
            secret = derive_pairing_secret(pairing_password)
            client.init(pin.encode("ascii"), puk.encode("ascii"), secret)
        except Exception as exc:
            logger.exception("Keycard INIT failed")
            return _error_destination("INIT failed", str(exc))

        self.run_screen(
            LargeIconStatusScreen,
            title="Initialised",
            status_headline=None,
            text="Card ready.\nNext: Pair card.",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView)


# ---------------------------------------------------------------------------
# Pair
# ---------------------------------------------------------------------------


class ToolsKeycardPairView(View):
    """Unified load-or-pair flow: tries the encrypted microSD blob first.

    On success either:
      - decrypts a previously-saved pairing for this card (no new slot used),
      - or runs PAIR APDU and persists the result for next boot.
    """

    def run(self):
        try:
            from seedsigner.helpers.keycard import pairing_storage
            from seedsigner.helpers.keycard.client import KeycardClient
            from seedsigner.helpers.keycard.crypto import derive_pairing_secret
            from seedsigner.helpers.keycard.reader import wait_for_card
            from seedsigner.helpers.keycard.secure_channel import (
                PairingInfo, SecureChannelError,
            )
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        password = _prompt_for_text(self, "Pairing password")
        if password is None:
            return Destination(BackStackView)

        # Local mutable wrapper so we can wipe deterministically.
        password_buf = bytearray(password.encode("utf-8"))
        try:
            wipe_string(password)
        except Exception:
            pass

        try:
            normalised = unicodedata.normalize("NFKD", password_buf.decode("utf-8"))
        except Exception as exc:
            _wipe_bytearray(password_buf)
            return _error_destination("Bad password", str(exc))

        try:
            connection = wait_for_card(timeout_s=5.0)
            client = KeycardClient(connection)
            select_info = client.select()
        except Exception as exc:
            try:
                wipe_string(normalised)
            except Exception:
                pass
            _wipe_bytearray(password_buf)
            logger.exception("Keycard SELECT failed")
            return _error_destination("Card not reachable", str(exc))

        pairing: Optional[PairingInfo] = None
        loaded_from_disk = False
        try:
            stored = pairing_storage.load(normalised)
        except pairing_storage.PairingStorageError as exc:
            logger.info("saved pairing rejected: %s", exc)
            stored = None

        if stored is not None and stored.instance_uid == select_info.instance_uid:
            pairing = stored.pairing
            loaded_from_disk = True

        if pairing is None:
            try:
                secret = derive_pairing_secret(normalised)
                pairing = client.pair(secret)
            except Exception as exc:
                try:
                    wipe_string(normalised)
                except Exception:
                    pass
                _wipe_bytearray(password_buf)
                logger.exception("Keycard PAIR failed")
                return _error_destination("PAIR failed", str(exc))
            try:
                pairing_storage.save(normalised, pairing, select_info.instance_uid)
            except Exception:
                logger.exception("could not persist pairing")
                # Non-fatal: keep the in-memory pairing.

        try:
            wipe_string(normalised)
        except Exception:
            pass
        _wipe_bytearray(password_buf)

        self.controller.keycard_pairing = pairing
        text = (
            f"Slot {pairing.pairing_index}\n"
            f"loaded from disk" if loaded_from_disk else f"Slot {pairing.pairing_index}\n"
            f"saved for next boot"
        )
        self.run_screen(
            LargeIconStatusScreen,
            title="Paired",
            status_headline=None,
            text=text,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView)


class ToolsKeycardForgetSavedPairingView(View):
    CONFIRM = ButtonOption("Forget")

    def run(self):
        try:
            from seedsigner.helpers.keycard import pairing_storage
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        ret = self.run_screen(
            WarningScreen,
            title="Forget pairing?",
            status_headline=None,
            text="Removes the saved blob from microSD.",
            show_back_button=True,
            button_data=[self.CONFIRM],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        removed = pairing_storage.remove()
        self.controller.keycard_pairing = None
        msg = "Saved pairing removed." if removed else "No saved pairing found."
        self.run_screen(
            LargeIconStatusScreen,
            title="Done",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView)


class ToolsKeycardUnpairView(View):
    CONFIRM = ButtonOption("Unpair")

    def run(self):
        pairing = getattr(self.controller, "keycard_pairing", None)
        if pairing is None:
            return _error_destination("Not paired", "Nothing to unpair.")

        ret = self.run_screen(
            WarningScreen,
            title="Unpair?",
            status_headline=None,
            text=f"Free slot {pairing.pairing_index} on the card.",
            show_back_button=True,
            button_data=[self.CONFIRM],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        pin = _prompt_for_pin(self, "Card PIN")
        if pin is None:
            return Destination(BackStackView)

        try:
            client, _ = _open_unlocked_session(self, pin)
            client.unpair(pairing.pairing_index)
        except Exception as exc:
            logger.exception("Keycard UNPAIR failed")
            return _error_destination("UNPAIR failed", str(exc))
        finally:
            _wipe_bytearray(pin)

        self.controller.keycard_pairing = None
        return Destination(ToolsKeycardMenuView)


# ---------------------------------------------------------------------------
# Generate key
# ---------------------------------------------------------------------------


class ToolsKeycardGenerateKeyView(View):
    CONFIRM = ButtonOption("Generate key")

    def run(self):
        if getattr(self.controller, "keycard_pairing", None) is None:
            return Destination(ToolsKeycardPairView)

        ret = self.run_screen(
            DireWarningScreen,
            title="Generate key?",
            status_headline=None,
            text="Replaces any existing key on this card.",
            show_back_button=True,
            button_data=[self.CONFIRM],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        pin = _prompt_for_pin(self, "Card PIN")
        if pin is None:
            return Destination(BackStackView)

        try:
            client, _ = _open_unlocked_session(self, pin)
            client.generate_key()
        except Exception as exc:
            logger.exception("Keycard GENERATE_KEY failed")
            return _error_destination("Generate failed", str(exc))
        finally:
            _wipe_bytearray(pin)

        self.run_screen(
            LargeIconStatusScreen,
            title="Key created",
            status_headline=None,
            text="Card holds a fresh master key.",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView)


# ---------------------------------------------------------------------------
# Export pubkey / address
# ---------------------------------------------------------------------------


class ToolsKeycardExportPubkeyView(View):
    def run(self):
        if getattr(self.controller, "keycard_pairing", None) is None:
            return Destination(ToolsKeycardPairView)

        pin = _prompt_for_pin(self, "Card PIN")
        if pin is None:
            return Destination(BackStackView)

        try:
            client, _ = _open_unlocked_session(self, pin)
            client.derive_key(DEFAULT_ETH_PATH)
            response = client.export_pubkey()
        except Exception as exc:
            logger.exception("Keycard EXPORT failed")
            return _error_destination("Export failed", str(exc))
        finally:
            _wipe_bytearray(pin)

        pubkey = _extract_pubkey(response)
        if pubkey is None:
            return _error_destination("Bad response", "Could not parse key.")

        try:
            address = to_checksum_address(pubkey_to_address(pubkey))
        except Exception as exc:
            return _error_destination("Bad pubkey", str(exc))

        # 42-char address won't fit one display line; show in chunks of 21.
        text = f"m/44'/60'/0'/0/0\n{address[:21]}\n{address[21:]}"
        self.run_screen(
            LargeIconStatusScreen,
            title="ETH address",
            status_headline=None,
            text=text,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView)


# ---------------------------------------------------------------------------
# Sign ETH (scan → review → sign → display)
# ---------------------------------------------------------------------------


class ToolsKeycardSignEthStartView(View):
    def run(self):
        if getattr(self.controller, "keycard_pairing", None) is None:
            return Destination(ToolsKeycardPairView)
        return Destination(ScanEthSignRequestView)


class ScanEthSignRequestView(ScanView):
    @property
    def is_valid_qr_type(self):
        return self.decoder.is_eth_sign_request

    def run(self):
        self.run_screen(
            ScanScreen,
            instructions_text="Scan ETH sign request",
            decoder=self.decoder,
        )
        time.sleep(0.1)

        if not self.decoder.is_complete:
            return Destination(BackStackView)

        try:
            request = self.decoder.get_eth_sign_request()
        except Exception as exc:
            logger.exception("eth-sign-request parsing failed")
            return _error_destination("Invalid request", str(exc))
        if request is None:
            return _error_destination("Invalid request", "No data decoded")

        self.controller.eth_sign_request = request
        return Destination(ToolsKeycardSignEthOverviewView)


class ToolsKeycardSignEthOverviewView(View):
    CONFIRM = ButtonOption("Confirm & sign")
    CANCEL = ButtonOption("Cancel")

    def run(self):
        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination("No request", "Scan one first")

        kind = DATA_TYPE_LABELS.get(request.data_type, f"type {request.data_type}")
        path = _format_path(request.derivation_path.components)
        addr_line = ""
        if request.address:
            addr_line = f"\n{to_checksum_address(request.address)}"
        text = (
            f"{kind}\n"
            f"chain {request.chain_id}\n"
            f"path {path}{addr_line}"
        )
        button_data = [self.CONFIRM, self.CANCEL]
        ret = self.run_screen(
            ButtonListScreen,
            title="Sign ETH?",
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=False,
            status_headline=None,
        )
        if ret == RET_CODE__BACK_BUTTON or button_data[ret] == self.CANCEL:
            self.controller.eth_sign_request = None
            return Destination(BackStackView)
        return Destination(ToolsKeycardSignEthFinalizeView)


class ToolsKeycardSignEthFinalizeView(View):
    def run(self):
        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination("No request", "Lost request mid-flow")
        if getattr(self.controller, "keycard_pairing", None) is None:
            return Destination(ToolsKeycardPairView)

        try:
            from seedsigner.helpers.keycard_signer import sign_with_keycard
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        pin = _prompt_for_pin(self, "Card PIN")
        if pin is None:
            return Destination(BackStackView)

        try:
            client, _ = _open_unlocked_session(self, pin)
            signature = sign_with_keycard(client, request)
        except Exception as exc:
            logger.exception("Keycard signing failed")
            return _error_destination("Signing failed", str(exc))
        finally:
            _wipe_bytearray(pin)

        self.controller.eth_signature = signature
        return Destination(ToolsKeycardSignEthQrDisplayView)


class ToolsKeycardSignEthQrDisplayView(View):
    def run(self):
        signature = getattr(self.controller, "eth_signature", None)
        if signature is None:
            return _error_destination("No signature", "Nothing to display")

        from seedsigner.gui.screens.psbt_screens import PSBTSignedQRDisplayScreen

        encoder = EthSignatureQrEncoder(eth_signature=signature)
        self.run_screen(
            PSBTSignedQRDisplayScreen,
            qr_encoder=encoder,
        )
        self.controller.eth_sign_request = None
        self.controller.eth_signature = None
        return Destination(MainMenuView)


# ---------------------------------------------------------------------------
# Helpers (the rest live in helpers/keycard/ui_helpers.py)
# ---------------------------------------------------------------------------


def _error_destination(title: str, message: str) -> Destination:
    return Destination(KeycardErrorView, view_args={"title": title, "message": message})


class KeycardErrorView(View):
    def __init__(self, title: str, message: str):
        super().__init__()
        self.title = title
        self.message = message

    def run(self):
        msg = self.message[:120]
        self.run_screen(
            ErrorScreen,
            title=self.title,
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(BackStackView)
