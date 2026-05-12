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
from typing import List, Optional, Tuple

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
    classify_card_error,
    extract_extended_pubkey,
    extract_pubkey,
    format_path,
    open_unlocked_session,
    open_unlocked_session_cached_or_prompt,
    prompt_for_pin,
    prompt_for_text,
    select_with_autodetect,
    wipe_bytearray,
)
from seedsigner.helpers.secure_delete import wipe_string
from seedsigner.models.encode_qr import EthSignatureQrEncoder
from seedsigner.models.settings_definition import SettingsConstants
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
_open_unlocked_session_cached_or_prompt = open_unlocked_session_cached_or_prompt

logger = logging.getLogger(__name__)

DATA_TYPE_LABELS = {
    DATA_TYPE_LEGACY_TX: "Legacy / EIP-155",
    DATA_TYPE_TYPED_DATA: "EIP-712 typed data",
    DATA_TYPE_PERSONAL_MESSAGE: "Personal sign",
    DATA_TYPE_TYPED_TX: "EIP-1559",
}

PIN_LENGTH = 6
PUK_LENGTH = 12

# Pairing password baked into cards initialised by keycard-shell /
# keycard-cli (the typical "stock" state). Tried silently before the
# user is prompted, so unmodified cards Just Work without ceremony.
DEFAULT_PAIRING_PASSWORD = "KeycardDefaultPairing"


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------


class ToolsKeycardMenuView(View):
    """Top-level Keycard menu. Daily-use ops at the top, setup and
    maintenance hidden behind submenus to keep the list scannable.

    On entry the card is probed (see ``card_probe.run_card_gate``):
    a missing card snaps back to ``MainMenuView`` with a "No card"
    toast; an uninstantiated applet routes straight to
    ``ToolsKeycardInitView``.
    """

    SIGN_ETH = ButtonOption("Sign ETH")
    VIEW_WALLETS = ButtonOption("View wallets")
    EXPORT_PUBKEY = ButtonOption("Export xpub")
    SETUP = ButtonOption("Setup")
    MANAGE = ButtonOption("Manage")

    def run(self):
        from seedsigner.helpers.card_probe import run_card_gate
        gate = run_card_gate(
            self, "keycard", title="Keycard", setup_view=ToolsKeycardInitView,
        )
        if gate is not None:
            return gate

        button_data = [
            self.SIGN_ETH,
            self.VIEW_WALLETS,
            self.EXPORT_PUBKEY,
            self.SETUP,
            self.MANAGE,
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
        if chosen == self.VIEW_WALLETS:
            return Destination(ToolsKeycardWalletsListView)
        if chosen == self.EXPORT_PUBKEY:
            return Destination(ToolsKeycardPairWalletView)
        if chosen == self.SETUP:
            return Destination(ToolsKeycardSetupMenuView)
        if chosen == self.MANAGE:
            return Destination(ToolsKeycardManageMenuView)
        return Destination(NotYetImplementedView)


class ToolsKeycardSetupMenuView(View):
    """Provisioning flows for a fresh/blank card."""

    INIT = ButtonOption("Initialise card")
    GENERATE_KEY = ButtonOption("Generate key")
    IMPORT_SEED = ButtonOption("Import seed")

    def run(self):
        button_data = [self.INIT, self.GENERATE_KEY, self.IMPORT_SEED]
        selected = self.run_screen(
            ButtonListScreen,
            title="Setup",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        chosen = button_data[selected]
        if chosen == self.INIT:
            return Destination(ToolsKeycardInitView)
        if chosen == self.GENERATE_KEY:
            return Destination(ToolsKeycardGenerateKeyView)
        if chosen == self.IMPORT_SEED:
            return Destination(ToolsKeycardImportSeedView)
        return Destination(NotYetImplementedView)


class ToolsKeycardManageMenuView(View):
    """Maintenance flows: introspection, credential rotation,
    multi-instance management, plus the destructive ops behind
    ``Advanced``."""

    STATUS = ButtonOption("Status")
    CHANGE_PIN = ButtonOption("Change PIN")
    INSTANCES = ButtonOption("Instances")
    ADVANCED = ButtonOption("Advanced")

    def run(self):
        button_data = [
            self.STATUS,
            self.CHANGE_PIN,
            self.INSTANCES,
            self.ADVANCED,
        ]
        selected = self.run_screen(
            ButtonListScreen,
            title="Manage",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        chosen = button_data[selected]
        if chosen == self.STATUS:
            return Destination(ToolsKeycardStatusView)
        if chosen == self.CHANGE_PIN:
            return Destination(ToolsKeycardChangePinView)
        if chosen == self.INSTANCES:
            return Destination(ToolsKeycardInstancesMenuView)
        if chosen == self.ADVANCED:
            return Destination(ToolsKeycardAdvancedMenuView)
        return Destination(NotYetImplementedView)


class ToolsKeycardAdvancedMenuView(View):
    """Houses operations the casual user shouldn't see in the main menu:
    manual pair refresh, pairing removal, factory reset.
    """

    PAIR = ButtonOption("Pair card")
    REMOVE_PAIRING = ButtonOption("Remove pairing")
    FACTORY_RESET = ButtonOption("Factory reset")
    UNINSTALL = ButtonOption("Uninstall applet")

    def run(self):
        button_data = [
            self.PAIR,
            self.REMOVE_PAIRING,
            self.FACTORY_RESET,
            self.UNINSTALL,
        ]
        selected = self.run_screen(
            ButtonListScreen,
            title="Advanced",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        chosen = button_data[selected]
        if chosen == self.PAIR:
            return Destination(ToolsKeycardPairView)
        if chosen == self.REMOVE_PAIRING:
            return Destination(ToolsKeycardRemovePairingView)
        if chosen == self.FACTORY_RESET:
            return Destination(ToolsKeycardFactoryResetView)
        if chosen == self.UNINSTALL:
            return Destination(ToolsKeycardUninstallAppletView)
        return Destination(NotYetImplementedView)


class ToolsKeycardUninstallAppletView(View):
    """Delete the Keycard package via GlobalPlatform (default ISD keys).

    The Status Keycard package is a single CAP with three applet
    instances (signing applet, NDEF, Cash). DELETE with ``with_related``
    on the package AID nukes all three.
    """

    def run(self):
        from seedsigner.gui.screens.screen import (
            DireWarningScreen, LargeIconStatusScreen,
        )

        ret = self.run_screen(
            DireWarningScreen,
            title="Uninstall",
            status_headline=None,
            text="Delete the Keycard package?\nMaster key will be lost.",
            show_back_button=True,
            button_data=[ButtonOption("Delete")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        try:
            from seedsigner.helpers.keycard import global_platform as gp
            from seedsigner.helpers.keycard.reader import (
                release_other_smartcard_holders, wait_for_card,
            )
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        try:
            release_other_smartcard_holders(self.controller)
            connection = wait_for_card(timeout_s=5.0)
        except Exception as exc:
            return _error_destination("Card not reachable", str(exc))

        try:
            channel = gp.GpSecureChannel(connection)
            channel.select_isd()
            try:
                channel.open()
            except Exception as exc:
                return _error_destination(
                    "ISD keys required",
                    "Default ISD keys missing.\nWipe via PC or full Factory Reset.",
                )
            # Package AID for Status Keycard.
            package_aid = bytes.fromhex("A0000008040001")
            try:
                gp.delete_aid(channel, package_aid, with_related=True)
            except Exception as exc:
                return _error_destination("Uninstall failed", str(exc))
        finally:
            try:
                connection.disconnect()
            except Exception:
                pass

        # Cached pairings for this card are now stale; drop them.
        self.controller.forget_all_pairings()

        self.run_screen(
            LargeIconStatusScreen,
            title="Uninstall",
            status_headline=None,
            text="Keycard package removed.",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        from seedsigner.views.view import CardsMenuView
        return Destination(CardsMenuView, skip_current_view=True)


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


class ToolsKeycardStatusView(View):
    def run(self):
        try:
            from seedsigner.helpers.keycard.client import KeycardClient
            from seedsigner.helpers.keycard.reader import (
                release_other_smartcard_holders, wait_for_card,
            )
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        try:
            release_other_smartcard_holders(self.controller)
            connection = wait_for_card(timeout_s=5.0)
            client = KeycardClient(connection)
            info = select_with_autodetect(client, self.controller)
        except Exception as exc:
            title, body = classify_card_error(exc)
            return _error_destination(title, body)

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
# Factory reset (wipe card)
# ---------------------------------------------------------------------------


class ToolsKeycardFactoryResetView(View):
    """Wipe everything on the card: PIN, PUK, pairings, master key.

    The applet supports this on Status firmware revisions that include
    INS_FACTORY_RESET (0xFD). On older applets the call returns
    `0x6D00` "instruction not supported"; we surface that with a
    pointer to keycard-shell as a fallback.

    On success we also drop the device's persisted pairing storage and
    in-memory cache: nothing on this device should reference the now-
    blank card any more.
    """

    CONFIRM = ButtonOption("Wipe card")

    def run(self):
        try:
            from seedsigner.helpers.keycard import pairing_storage
            from seedsigner.helpers.keycard.client import KeycardClient
            from seedsigner.helpers.keycard.commands import APDUError
            from seedsigner.helpers.keycard.reader import (
                release_other_smartcard_holders, wait_for_card,
            )
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        ret = self.run_screen(
            DireWarningScreen,
            title="Factory reset?",
            status_headline=None,
            text="Wipes EVERYTHING on the\ncard. Cannot be undone.",
            show_back_button=True,
            button_data=[self.CONFIRM],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        try:
            release_other_smartcard_holders(self.controller)
            connection = wait_for_card(timeout_s=5.0)
            client = KeycardClient(connection)
            select_with_autodetect(client, self.controller)
            client.factory_reset()
        except APDUError as exc:
            logger.warning("FACTORY_RESET unsupported: %s", exc)
            if (exc.sw & 0xFF00) == 0x6D00:
                return _error_destination(
                    "Not supported",
                    "Update applet, or use\nkeycard-shell on PC.",
                )
            title, body = classify_card_error(exc, default_title="Reset failed")
            return _error_destination(title, body)
        except Exception as exc:
            logger.exception("FACTORY_RESET failed")
            title, body = classify_card_error(exc, default_title="Reset failed")
            return _error_destination(title, body)

        # Drop the device's local state for the now-blank card.
        try:
            pairing_storage.remove_all()
        except Exception:
            logger.exception("could not clear local pairings after factory reset")
        self.controller.forget_all_pairings()

        self.run_screen(
            LargeIconStatusScreen,
            title="Card wiped",
            status_headline=None,
            text="Run Init to reuse it.",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView, skip_current_view=True)


# ---------------------------------------------------------------------------
# Initialise
# ---------------------------------------------------------------------------


class ToolsKeycardInitView(View):
    """One-shot Init wizard: random PIN/PUK + default pairing secret, INIT APDU, display.

    Uses the well-known ``DEFAULT_PAIRING_PASSWORD`` (matches keycard-cli /
    keycard-shell convention) as the on-card pairing secret. The PAIR view
    already tries this password silently before prompting, so the user
    never has to write down or type a pairing password — only PIN and
    PUK. Threat model: the pairing slot still requires the PIN to do
    anything useful with the card; the pairing-secret alone gives an
    attacker a slot but not the seed.
    """

    CONTINUE = ButtonOption("Continue")
    INITIALISE = ButtonOption("Initialise card")

    def run(self):
        import hmac

        try:
            from seedsigner.helpers.keycard import secrets as kc_secrets
            from seedsigner.helpers.keycard.client import KeycardClient
            from seedsigner.helpers.keycard.crypto import derive_pairing_secret
            from seedsigner.helpers.keycard.reader import (
                release_other_smartcard_holders, wait_for_card,
            )
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

        pin_buf: Optional[bytearray] = None
        confirm_buf: Optional[bytearray] = None
        try:
            # Loop until two identical PIN entries succeed or the user backs out.
            while True:
                pin_buf = prompt_for_pin(self, "Set PIN (6 digits)")
                if pin_buf is None:
                    return Destination(BackStackView)
                confirm_buf = prompt_for_pin(self, "Confirm PIN")
                if confirm_buf is None:
                    wipe_bytearray(pin_buf)
                    pin_buf = None
                    return Destination(BackStackView)
                if hmac.compare_digest(bytes(pin_buf), bytes(confirm_buf)):
                    wipe_bytearray(confirm_buf)
                    confirm_buf = None
                    break
                wipe_bytearray(pin_buf)
                wipe_bytearray(confirm_buf)
                pin_buf = None
                confirm_buf = None
                self.run_screen(
                    WarningScreen,
                    title="PINs differ",
                    status_headline=None,
                    text="Try again.",
                    show_back_button=True,
                    button_data=[ButtonOption("Retry")],
                )

            # Optional wallet name — captured here, persisted by the
            # next successful pair in ToolsKeycardPairView via the
            # controller's pending_keycard_label slot. Empty/cancelled
            # => no label (anonymous wallet).
            label_raw = prompt_for_text(self, "Wallet name (optional)", max_len=16)
            if label_raw is None:
                label_clean = None
            else:
                stripped = label_raw.strip()
                label_clean = stripped if stripped else None
            self.controller.pending_keycard_label = label_clean

            puk = kc_secrets.generate_puk()

            ret = self.run_screen(
                WarningScreen,
                title="Write this down",
                status_headline=None,
                text=f"PUK  {puk}",
                show_back_button=True,
                button_data=[self.INITIALISE],
            )
            if ret == RET_CODE__BACK_BUTTON:
                self.controller.pending_keycard_label = None
                return Destination(BackStackView)

            try:
                release_other_smartcard_holders(self.controller)
                connection = wait_for_card(timeout_s=5.0)
                client = KeycardClient(connection)
                select_with_autodetect(client, self.controller)
                secret = derive_pairing_secret(DEFAULT_PAIRING_PASSWORD)
                client.init(bytes(pin_buf), puk.encode("ascii"), secret)
            except Exception as exc:
                logger.exception("Keycard INIT failed")
                title, body = classify_card_error(exc, default_title="INIT failed")
                return _error_destination(title, body)

            self.run_screen(
                LargeIconStatusScreen,
                title="Initialised",
                status_headline=None,
                text="PIN/PUK set.\nPair, then Generate key.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(ToolsKeycardMenuView, skip_current_view=True)
        finally:
            if pin_buf is not None:
                wipe_bytearray(pin_buf)
            if confirm_buf is not None:
                wipe_bytearray(confirm_buf)


# ---------------------------------------------------------------------------
# Change PIN
# ---------------------------------------------------------------------------


class ToolsKeycardChangePinView(View):
    """Replace the user PIN on the active Keycard instance.

    Opens a PIN-verified session with the current PIN (prompts on cache
    miss), captures the new PIN twice (entry + confirm), sends
    CHANGE PIN, and drops the cached PIN so the next operation
    re-prompts with the new value.
    """

    def run(self):
        from seedsigner.helpers.keycard import (
            KeycardCardChangedError, KeycardNotInitialisedError,
            KeycardPinPromptCancelled,
        )

        new_pin: Optional[bytearray] = None
        confirm_pin: Optional[bytearray] = None
        try:
            try:
                client, _ = _open_unlocked_session_cached_or_prompt(
                    self, pin_title="Current PIN", require_key=False,
                )
            except KeycardPinPromptCancelled:
                return Destination(BackStackView)
            except KeycardCardChangedError:
                return Destination(ToolsKeycardPairView)
            except KeycardNotInitialisedError as exc:
                title, body = classify_card_error(exc)
                return _error_destination(title, body)
            except Exception as exc:
                logger.exception("Keycard CHANGE PIN: session open failed")
                title, body = classify_card_error(
                    exc, default_title="Change PIN failed",
                )
                return _error_destination(title, body)

            select_resp = client.select_response
            instance_uid = (
                bytes(select_resp.instance_uid) if select_resp else b""
            )

            new_pin = prompt_for_pin(self, "New PIN")
            if new_pin is None:
                return Destination(BackStackView)
            confirm_pin = prompt_for_pin(self, "Confirm new PIN")
            if confirm_pin is None:
                return Destination(BackStackView)
            if bytes(new_pin) != bytes(confirm_pin):
                return _error_destination(
                    "Mismatch", "New PINs do not\nmatch. Retry.",
                )

            try:
                client.change_pin(bytes(new_pin))
            except Exception as exc:
                logger.exception("Keycard CHANGE PIN failed")
                title, body = classify_card_error(
                    exc, default_title="Change PIN failed",
                )
                return _error_destination(title, body)

            if instance_uid:
                self.controller.forget_pin_for(instance_uid)

            self.run_screen(
                LargeIconStatusScreen,
                title="PIN changed",
                status_headline=None,
                text="New PIN active.\nUse it on next op.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(ToolsKeycardMenuView, skip_current_view=True)
        finally:
            wipe_bytearray(new_pin)
            wipe_bytearray(confirm_pin)


# ---------------------------------------------------------------------------
# Pair
# ---------------------------------------------------------------------------


def _try_ephemeral_pair_with_secret(
    client, SecureChannelError, secret: bytes,
) -> Optional[object]:
    """Attempt PAIR(P2=EPHEMERAL) with a pre-derived 32-byte secret.

    Returns the resulting ``PairingInfo`` on success, ``None`` on
    cryptogram mismatch (wrong secret). Other PAIR errors propagate.
    Caller must have verified ``app_version >= 0x0302`` first.
    """
    from seedsigner.helpers.keycard.commands import PAIR_P2_EPHEMERAL
    try:
        return client.pair(secret, p2=PAIR_P2_EPHEMERAL)
    except SecureChannelError as exc:
        if "cryptogram" in str(exc).lower():
            return None
        raise


def _try_pair_with_raw_psk(
    client,
    pairing_storage,
    SecureChannelError,
    psk: bytes,
    instance_uid: bytes,
    label: Optional[str] = None,
) -> Tuple[Optional[object], Optional[str], Optional[str]]:
    """Attempt to pair using a raw 32-byte pairing secret (no PBKDF2).

    Returns ``(pairing, source, effective_label)`` where
    ``effective_label`` is the label stored on disk (``"disk"`` path)
    or the one we just wrote (``"pair"`` path); ``None`` on mismatch.
    """
    if len(psk) != 32:
        raise ValueError("PSK must be 32 bytes")
    storage_pwd = "raw-psk:" + psk.hex()
    try:
        try:
            stored = pairing_storage.load(storage_pwd, instance_uid=instance_uid)
        except pairing_storage.PairingStorageError as exc:
            logger.info("saved pairing rejected: %s", exc)
            stored = None
        if stored is not None and stored.instance_uid == instance_uid:
            return stored.pairing, "disk", stored.label

        try:
            pairing = client.pair(psk)
        except SecureChannelError as exc:
            if "cryptogram" in str(exc).lower():
                return None, None, None  # PSK does not match — fall through
            raise
        try:
            pairing_storage.save(storage_pwd, pairing, instance_uid, label=label)
        except Exception:
            logger.exception("could not persist pairing")
        return pairing, "pair", label
    finally:
        try:
            wipe_string(storage_pwd)
        except Exception:
            pass


def _try_pair_with_password(
    client,
    pairing_storage,
    derive_pairing_secret,
    SecureChannelError,
    pwd: str,
    instance_uid: bytes,
    label: Optional[str] = None,
) -> Tuple[Optional[object], Optional[str], Optional[str]]:
    """Attempt to obtain a PairingInfo for ``instance_uid`` using ``pwd``.

    Returns ``(pairing, source, effective_label)`` where ``source`` is
    ``"disk"`` or ``"pair"`` on success, and ``effective_label`` is the
    label that ended up on disk (if any). ``(None, None, None)`` on
    cryptogram mismatch.
    """
    # Force a fresh str object — prevents wipe_string from zeroing the
    # caller's buffer or any interned constant (e.g. DEFAULT_PAIRING_PASSWORD).
    fresh = "".join(pwd)
    normalised = unicodedata.normalize("NFKD", fresh)
    try:
        try:
            stored = pairing_storage.load(normalised, instance_uid=instance_uid)
        except pairing_storage.PairingStorageError as exc:
            logger.info("saved pairing rejected: %s", exc)
            stored = None
        if stored is not None and stored.instance_uid == instance_uid:
            return stored.pairing, "disk", stored.label

        try:
            secret = derive_pairing_secret(normalised)
            pairing = client.pair(secret)
        except SecureChannelError as exc:
            if "cryptogram" in str(exc).lower():
                return None, None, None  # wrong password — caller falls through
            raise
        try:
            pairing_storage.save(normalised, pairing, instance_uid, label=label)
        except Exception:
            logger.exception("could not persist pairing")
            # Non-fatal: keep the in-memory pairing.
        return pairing, "pair", label
    finally:
        for s in (fresh, normalised):
            try:
                wipe_string(s)
            except Exception:
                pass


class ToolsKeycardPairView(View):
    """Pair the card currently in the reader for this boot.

    Behaviour:
      1. SELECT the inserted card to discover its ``instance_uid``.
      2. If a pairing for that UID is already cached this boot, return
         immediately without prompting (multi-card auto-switch friendly).
      3. Try the keycard-shell / keycard-cli default pairing password
         (``"KeycardDefaultPairing"``) silently — both the on-disk cache
         and a fresh PAIR APDU. PAIR failures with that password do not
         consume a slot, so this is free for cards with a custom secret.
      4. Only on default-password mismatch, prompt for a custom one and
         try again.
      5. Persist the resulting pairing under the per-UID filename and
         cache it on the controller's keycard_pairings dict.
    """

    def run(self):
        try:
            from seedsigner.helpers.keycard import pairing_storage
            from seedsigner.helpers.keycard.client import KeycardClient
            from seedsigner.helpers.keycard.commands import (
                supports_ephemeral_pairing,
            )
            from seedsigner.helpers.keycard.crypto import (
                KEYCARD_SHELL_DEFAULT_PSK, derive_pairing_secret,
            )
            from seedsigner.helpers.keycard.reader import (
                release_other_smartcard_holders, wait_for_card,
            )
            from seedsigner.helpers.keycard.secure_channel import (
                PairingInfo, SecureChannelError,
            )
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        try:
            release_other_smartcard_holders(self.controller)
            connection = wait_for_card(timeout_s=5.0)
            client = KeycardClient(connection)
            select_info = select_with_autodetect(client, self.controller)
        except Exception as exc:
            logger.exception("Keycard SELECT failed")
            title, body = classify_card_error(exc)
            return _error_destination(title, body)

        if select_info.app_version == 0:
            return _error_destination(
                "Not initialised",
                "Run Setup ›\nInitialise card first.",
            )

        instance_uid = bytes(select_info.instance_uid)
        self.controller.last_keycard_uid = instance_uid
        self.controller.remember_aid_for_uid(
            self.controller.active_keycard_aid, instance_uid,
        )

        free_slots = select_info.free_pairing_slots
        ephemeral_supported = supports_ephemeral_pairing(select_info.app_version)

        # v3.2+ cards: prefer ephemeral pairing. The persistent slot is
        # never touched, nothing reaches disk, and the on-card key is
        # cleared on every applet deselect — we only cache the 32-byte
        # pairing *secret* (derived from the password) for the boot.
        if ephemeral_supported:
            return self._run_ephemeral(
                client, select_info, instance_uid,
                derive_pairing_secret, KEYCARD_SHELL_DEFAULT_PSK,
                SecureChannelError,
            )

        # Pre-3.2 path: keep the existing persistent flow with on-disk
        # encrypted blob and slot consumption.
        if self.controller.get_pairing_for(instance_uid) is not None:
            self.run_screen(
                LargeIconStatusScreen,
                title="Already paired",
                status_headline=None,
                text=f"Paired this session.\n{free_slots} slot(s) free on card.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(ToolsKeycardMenuView, skip_current_view=True)

        # If the card has no free slots and we have no cached pairing
        # to reuse, PAIR will fail with SW=0x6A84. Stop early with a
        # helpful message instead of bouncing through the password
        # prompt.
        if free_slots == 0:
            return _error_destination(
                "No free slots",
                "Card is full. Unpair on a\npaired device, or reset.",
            )

        # --- Silent fast paths -------------------------------------
        # Try, in order:
        #   1. Our legacy "KeycardDefaultPairing" string-as-password
        #      (kept for back-compat with cards a user manually init'd
        #      with that password).
        #   2. The keycard-shell raw 32-byte PSK — keycard-shell stores
        #      this verbatim as the pairing secret, with no PBKDF2.
        #
        # PAIR step-1 cryptogram mismatches do NOT consume a card slot,
        # so trying both silently is free for cards using neither default.
        pending_label = getattr(self.controller, "pending_keycard_label", None)
        used_default = False
        pairing = None
        source = None
        effective_label = None
        try:
            pairing, source, effective_label = _try_pair_with_password(
                client, pairing_storage, derive_pairing_secret,
                SecureChannelError,
                DEFAULT_PAIRING_PASSWORD, instance_uid,
                label=pending_label,
            )
            if pairing is None:
                pairing, source, effective_label = _try_pair_with_raw_psk(
                    client, pairing_storage, SecureChannelError,
                    KEYCARD_SHELL_DEFAULT_PSK, instance_uid,
                    label=pending_label,
                )
        except Exception as exc:
            logger.exception("Keycard PAIR (default secrets) failed")
            title, body = classify_card_error(exc, default_title="PAIR failed")
            return _error_destination(title, body)

        used_default = pairing is not None

        # --- Custom-password fallback -------------------------------
        if pairing is None:
            password = _prompt_for_text(self, "Pairing password")
            if password is None:
                return Destination(BackStackView)
            password_buf = bytearray(password.encode("utf-8"))
            try:
                wipe_string(password)
            except Exception:
                pass
            try:
                custom = password_buf.decode("utf-8")
            except Exception as exc:
                _wipe_bytearray(password_buf)
                return _error_destination("Bad password", str(exc))
            try:
                pairing, source, effective_label = _try_pair_with_password(
                    client, pairing_storage, derive_pairing_secret,
                    SecureChannelError,
                    custom, instance_uid,
                    label=pending_label,
                )
            except Exception as exc:
                _wipe_bytearray(password_buf)
                logger.exception("Keycard PAIR (custom pwd) failed")
                title, body = classify_card_error(exc, default_title="PAIR failed")
                return _error_destination(title, body)
            finally:
                try:
                    wipe_string(custom)
                except Exception:
                    pass
            _wipe_bytearray(password_buf)
            if pairing is None:
                return _error_destination(
                    "Wrong password",
                    "Pairing password did\nnot match this card.",
                )

        self.controller.set_pairing_for(instance_uid, pairing)
        # Cache the human-readable wallet name so List/Switch/Delete
        # views can show it instead of just the AID hex.
        self.controller.set_label_for(instance_uid, effective_label)
        # Consume the pending label once it has been written to disk.
        # We clear it on the "disk" path too: a label captured at Init
        # is only meaningful for a brand-new card whose first PAIR
        # writes a fresh blob; if we ended up reading an existing blob
        # the label was already set there and the pending value is
        # stale (likely from a previous Init that never paired).
        self.controller.pending_keycard_label = None

        if source == "disk":
            detail = "loaded from disk"
        else:
            # PAIR consumed a slot, so the cached count is 1 stale.
            free_slots = max(0, free_slots - 1)
            detail = "saved for next boot"
        pwd_label = "default password" if used_default else "custom password"
        text = (
            f"Slot {pairing.pairing_index} ({free_slots} free)\n"
            f"{pwd_label}\n{detail}"
        )
        self.run_screen(
            LargeIconStatusScreen,
            title="Paired",
            status_headline=None,
            text=text,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView, skip_current_view=True)

    # ---- ephemeral (v3.2+) path -------------------------------------

    def _run_ephemeral(
        self, client, select_info, instance_uid,
        derive_pairing_secret, raw_psk, SecureChannelError,
    ) -> Destination:
        """Pair using v3.2 ephemeral mode (no disk persistence).

        Tries silently in order:
          1. Default-password-derived secret (most stock cards).
          2. keycard-shell raw 32-byte PSK (cards from keycard-shell).
          3. Custom user password (only if both above failed).

        On success caches the 32-byte secret in
        ``controller.keycard_ephemeral_secrets``; ``open_unlocked_session``
        will re-PAIR(P2=EPHEMERAL) each time it needs an authenticated
        session, since the on-card ephemeral key is cleared on every
        applet deselect.
        """
        # Reuse the cached secret if any — equivalent of "Already paired".
        if self.controller.get_ephemeral_secret_for(instance_uid) is not None:
            self.run_screen(
                LargeIconStatusScreen,
                title="Already paired",
                status_headline=None,
                text="Ephemeral pairing\nactive this boot.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(ToolsKeycardMenuView, skip_current_view=True)

        secret_used: Optional[bytes] = None
        used_default = False
        try:
            # 1. PBKDF2 from the well-known default password.
            default_secret = derive_pairing_secret(DEFAULT_PAIRING_PASSWORD)
            try:
                if _try_ephemeral_pair_with_secret(
                    client, SecureChannelError, default_secret,
                ) is not None:
                    secret_used = default_secret
                    used_default = True
            except Exception as exc:
                logger.exception("ephemeral PAIR (default pwd) failed")
                title, body = classify_card_error(
                    exc, default_title="PAIR failed",
                )
                return _error_destination(title, body)

            # 2. keycard-shell raw PSK (no PBKDF2).
            if secret_used is None:
                try:
                    if _try_ephemeral_pair_with_secret(
                        client, SecureChannelError, raw_psk,
                    ) is not None:
                        secret_used = raw_psk
                        used_default = True
                except Exception as exc:
                    logger.exception("ephemeral PAIR (shell PSK) failed")
                    title, body = classify_card_error(
                        exc, default_title="PAIR failed",
                    )
                    return _error_destination(title, body)
        finally:
            # Wipe the failing default secrets if we didn't end up using
            # them. ``default_secret`` is freshly allocated each call so
            # the wipe is meaningful; the raw PSK is a module-level
            # constant we MUST NOT touch.
            try:
                if secret_used is not default_secret:
                    buf = bytearray(default_secret)
                    for i in range(len(buf)):
                        buf[i] = 0
            except Exception:
                pass

        # 3. Fall back to a user-typed password.
        if secret_used is None:
            password = _prompt_for_text(self, "Pairing password")
            if password is None:
                return Destination(BackStackView)
            password_buf = bytearray(password.encode("utf-8"))
            try:
                wipe_string(password)
            except Exception:
                pass
            try:
                custom = password_buf.decode("utf-8")
            except Exception as exc:
                _wipe_bytearray(password_buf)
                return _error_destination("Bad password", str(exc))
            normalised = unicodedata.normalize("NFKD", custom)
            try:
                custom_secret = derive_pairing_secret(normalised)
                try:
                    paired = _try_ephemeral_pair_with_secret(
                        client, SecureChannelError, custom_secret,
                    )
                except Exception as exc:
                    logger.exception("ephemeral PAIR (custom pwd) failed")
                    title, body = classify_card_error(
                        exc, default_title="PAIR failed",
                    )
                    return _error_destination(title, body)
                if paired is None:
                    # Wipe the unused secret before bailing out.
                    try:
                        buf = bytearray(custom_secret)
                        for i in range(len(buf)):
                            buf[i] = 0
                    except Exception:
                        pass
                    return _error_destination(
                        "Wrong password",
                        "Pairing password did\nnot match this card.",
                    )
                secret_used = custom_secret
            finally:
                _wipe_bytearray(password_buf)
                for s in (custom, normalised):
                    try:
                        wipe_string(s)
                    except Exception:
                        pass

        assert secret_used is not None
        self.controller.set_ephemeral_secret_for(instance_uid, secret_used)
        # set_ephemeral_secret_for() copies the bytes into its cache, so
        # we still hold a reference here. Wipe ours best-effort.
        try:
            buf = bytearray(secret_used)
            for i in range(len(buf)):
                buf[i] = 0
        except Exception:
            pass

        pwd_label = "default password" if used_default else "custom password"
        text = (
            "Ephemeral pairing\n"
            f"{pwd_label}\nNo disk persistence."
        )
        self.run_screen(
            LargeIconStatusScreen,
            title="Paired",
            status_headline=None,
            text=text,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView, skip_current_view=True)


class ToolsKeycardRemovePairingView(View):
    """Unified pairing removal.

    Always tries UNPAIR (which frees the card slot) before deleting
    the on-disk blob and cache, falling back to local-only removal
    when no card is reachable. The previous "Forget" flow only
    deleted local state, leaving the card slot reserved — five
    forget→re-pair cycles would exhaust the card's pairing slots.
    """

    UNPAIR_CARD = ButtonOption("Unpair this card")
    LOCAL_ALL = ButtonOption("Remove all (local)")

    def run(self):
        from seedsigner.helpers.keycard import pairing_storage
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.reader import (
            NoCardError, NoReaderError,
        )
        from seedsigner.helpers.keycard.ui_helpers import (
            identify_inserted_card,
        )

        instance_uid: Optional[bytes] = None
        try:
            _, instance_uid = identify_inserted_card(self)
        except (NoCardError, NoReaderError):
            instance_uid = None
        except APDUError as exc:
            if exc.sw == 0x6A82:
                # No matching applet on this card; treat as "no card"
                # so the user can still manage local entries.
                instance_uid = None
            else:
                logger.exception("Remove-pairing SELECT failed")
                title, body = classify_card_error(exc)
                return _error_destination(title, body)
        except Exception as exc:
            logger.exception("Remove-pairing SELECT failed")
            title, body = classify_card_error(exc)
            return _error_destination(title, body)

        entries = pairing_storage.list_pairings()

        button_data: List[ButtonOption] = []
        if instance_uid is not None:
            button_data.append(self.UNPAIR_CARD)
        button_data.append(self.LOCAL_ALL)
        for entry in entries:
            label = ("Card legacy" if entry.is_legacy
                     else f"Card {entry.fingerprint[:4]}…{entry.fingerprint[-4:]}")
            button_data.append(ButtonOption(label))

        title = "Remove pairing" if instance_uid is not None else f"Remove ({len(entries)} saved)"
        ret = self.run_screen(
            ButtonListScreen,
            title=title,
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        chosen = button_data[ret]
        if chosen == self.UNPAIR_CARD:
            return self._unpair_current_card(instance_uid)
        if chosen == self.LOCAL_ALL:
            return self._remove_all_local()

        # Saved-entry path. The picker offset is 1 (no-card) or 2
        # (card-present, UNPAIR_CARD precedes LOCAL_ALL).
        offset = 2 if instance_uid is not None else 1
        idx = ret - offset
        if not (0 <= idx < len(entries)):
            return Destination(BackStackView)
        return self._remove_local_entry(entries[idx])

    # --- sub-flows ----------------------------------------------------

    def _unpair_current_card(self, instance_uid: bytes) -> Destination:
        from seedsigner.helpers.keycard import KeycardCardChangedError

        is_ephemeral = (
            self.controller.get_ephemeral_secret_for(instance_uid) is not None
        )
        if is_ephemeral:
            confirm_text = "Forgets ephemeral\npairing for this boot."
        else:
            confirm_text = "Frees the card slot\nand deletes local copy."
        ret = self.run_screen(
            WarningScreen,
            title="Unpair card?",
            status_headline=None,
            text=confirm_text,
            show_back_button=True,
            button_data=[ButtonOption("Unpair")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        from seedsigner.helpers.keycard import KeycardPinPromptCancelled

        unpair_failed_exc: Optional[BaseException] = None
        try:
            client, pairing = _open_unlocked_session_cached_or_prompt(
                self, require_key=False,
            )
            client.unpair(pairing.pairing_index)
        except KeycardPinPromptCancelled:
            return Destination(BackStackView)
        except KeycardCardChangedError:
            return Destination(ToolsKeycardPairView)
        except Exception as exc:
            logger.exception("Keycard UNPAIR failed")
            unpair_failed_exc = exc

        if unpair_failed_exc is not None:
            confirm = self.run_screen(
                WarningScreen,
                title="UNPAIR failed",
                status_headline=None,
                text="Card slot stays in use.\nRemove local only?",
                show_back_button=True,
                button_data=[ButtonOption("Remove local")],
            )
            if confirm == RET_CODE__BACK_BUTTON:
                title, body = classify_card_error(
                    unpair_failed_exc, default_title="UNPAIR failed",
                )
                return _error_destination(title, body)
            self._drop_local_for_uid(instance_uid)
            self._show_done("Removed local",
                            "Slot still in use\non the card.")
            return Destination(ToolsKeycardMenuView, skip_current_view=True)

        self._drop_local_for_uid(instance_uid)
        self._show_done("Unpaired", "Slot freed; local removed.")
        return Destination(ToolsKeycardMenuView, skip_current_view=True)

    def _drop_local_for_uid(self, instance_uid: bytes) -> None:
        from seedsigner.helpers.keycard import pairing_storage
        self.controller.forget_pairing_for(instance_uid)
        try:
            pairing_storage.remove(instance_uid=instance_uid)
        except Exception:
            logger.exception("could not remove unpaired storage")

    def _remove_all_local(self) -> Destination:
        from seedsigner.helpers.keycard import pairing_storage

        ret = self.run_screen(
            DireWarningScreen,
            title="Remove all?",
            status_headline=None,
            text="Local only. Slots stay\nused on the cards.",
            show_back_button=True,
            button_data=[ButtonOption("Remove all")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        count = pairing_storage.remove_all()
        self.controller.forget_all_pairings()
        self._show_done("Removed", f"Removed {count} pairing(s).")
        return Destination(ToolsKeycardMenuView, skip_current_view=True)

    def _remove_local_entry(self, entry) -> Destination:
        from seedsigner.helpers.keycard import pairing_storage

        ret = self.run_screen(
            WarningScreen,
            title="Remove?",
            status_headline=None,
            text=f"Local only.\n{entry.path.name[:24]}",
            show_back_button=True,
            button_data=[ButtonOption("Remove")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        removed = pairing_storage.remove(path=entry.path)
        if not entry.is_legacy:
            for uid in list(self.controller.keycard_pairings.keys()):
                if pairing_storage.fingerprint_for_uid(uid) == entry.fingerprint:
                    self.controller.forget_pairing_for(uid)

        self._show_done(
            "Removed" if removed else "Not found",
            "Saved pairing removed." if removed else "Already gone.",
        )
        return Destination(ToolsKeycardRemovePairingView, skip_current_view=True)

    def _show_done(self, title: str, text: str) -> None:
        self.run_screen(
            LargeIconStatusScreen,
            title=title,
            status_headline=None,
            text=text,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )


# ---------------------------------------------------------------------------
# Generate key
# ---------------------------------------------------------------------------


class ToolsKeycardGenerateKeyView(View):
    CONFIRM = ButtonOption("Generate key")

    def run(self):
        from seedsigner.helpers.keycard import KeycardCardChangedError

        if not self.controller.has_any_keycard_auth():
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

        from seedsigner.helpers.keycard import KeycardPinPromptCancelled

        try:
            client, _ = _open_unlocked_session_cached_or_prompt(
                self, require_key=False,
            )
            client.generate_key()
        except KeycardPinPromptCancelled:
            return Destination(BackStackView)
        except KeycardCardChangedError:
            return Destination(ToolsKeycardPairView)
        except Exception as exc:
            logger.exception("Keycard GENERATE_KEY failed")
            title, body = classify_card_error(exc, default_title="Generate failed")
            return _error_destination(title, body)

        # The on-card master key just changed — any cached View-wallets
        # addresses for this AID were derived from the old key.
        _invalidate_wallets_cache_for_active_aid(self.controller)

        self.run_screen(
            LargeIconStatusScreen,
            title="Key created",
            status_headline=None,
            text="Card holds a fresh master key.",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView, skip_current_view=True)


# ---------------------------------------------------------------------------
# Import seedphrase to card (LOAD_KEY P1=BIP39_SEED)
# ---------------------------------------------------------------------------


class ToolsKeycardImportSeedView(View):
    """Push a BIP-39 seedphrase onto the card via LOAD_KEY P1=0x02.

    Threat model
    ------------
    Unlike the standard SeedSigner Tools flows, this view sends the
    seed bytes off-device — encrypted under the secure channel — to the
    card. After the card ACKs, the only persistent copy is in the card.
    A compromised reader or a clone of the card observed at this exact
    moment could harvest the seed; the model is the same as
    ``keycard-shell load`` on a PC.

    The seed and mnemonic are NEVER stored in
    ``controller.in_memory_seeds`` and never reach disk. The flow lives
    in this single view so a try/finally guarantees the wipe of every
    intermediate buffer (mnemonic, passphrase, 64-byte seed, PIN) on
    every exit path.

    Wipes are best-effort given Python's GC; users should treat seizure
    in the middle of an import as a likely seed compromise.
    """

    SCAN = ButtonOption("Scan SeedQR")
    TYPE_12 = ButtonOption("Type 12 words")
    TYPE_24 = ButtonOption("Type 24 words")
    CONFIRM = ButtonOption("Push to card")
    SKIP_PASSPHRASE = ButtonOption("No passphrase")
    SET_PASSPHRASE = ButtonOption("Set passphrase")

    def run(self):
        from seedsigner.helpers.keycard import (
            KeycardCardChangedError, KeycardPinPromptCancelled,
        )

        # 1. Strong warning + confirm to enter the flow.
        warn_ret = self.run_screen(
            DireWarningScreen,
            title="Import to card?",
            status_headline=None,
            text="Seed leaves device once,\nencrypted to card. Replaces\nany existing key on card.",
            show_back_button=True,
            button_data=[ButtonOption("Continue")],
        )
        if warn_ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # 2. Pick the input method.
        button_data = [self.SCAN, self.TYPE_12, self.TYPE_24]
        choice_ret = self.run_screen(
            ButtonListScreen,
            title="Source",
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if choice_ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        choice = button_data[choice_ret]

        # Buffers we must wipe on every exit path.
        words: list = []
        passphrase_buf = bytearray()
        seed64 = bytearray(64)

        try:
            # 3. Capture the mnemonic.
            if choice == self.SCAN:
                phrase = self._capture_via_scan()
            else:
                num_words = 12 if choice == self.TYPE_12 else 24
                phrase = self._capture_via_keyboard(num_words)
            if phrase is None:
                return Destination(BackStackView)
            # Copy each word into a freshly-allocated string so wipes
            # never touch the BIP-39 wordlist (see CLAUDE.md guidance).
            words = ["".join(w) for w in phrase]

            # 4. Validate checksum via embit.
            from embit import bip39, bip32
            mnemonic = " ".join(words)
            try:
                bip39.mnemonic_to_seed(mnemonic, password="")
            except Exception:
                return _error_destination("Invalid seed",
                                          "Checksum failed.")

            # 5. Optional passphrase.
            pp_choice_data = [self.SKIP_PASSPHRASE, self.SET_PASSPHRASE]
            pp_choice = self.run_screen(
                ButtonListScreen,
                title="Passphrase?",
                is_button_text_centered=False,
                button_data=pp_choice_data,
                show_back_button=True,
            )
            if pp_choice == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            passphrase = ""
            if pp_choice_data[pp_choice] == self.SET_PASSPHRASE:
                got = _prompt_for_text(self, "Passphrase", max_len=80)
                if got is None:
                    return Destination(BackStackView)
                passphrase_buf.extend(got.encode("utf-8"))
                try:
                    wipe_string(got)
                except Exception:
                    pass
                try:
                    passphrase = passphrase_buf.decode("utf-8")
                except Exception as exc:
                    return _error_destination("Bad passphrase", str(exc))

            # 6. Compute seed + master fingerprint for confirmation.
            try:
                derived = bip39.mnemonic_to_seed(mnemonic, password=passphrase)
                seed64[:] = derived
                root = bip32.HDKey.from_seed(bytes(seed64))
                fingerprint = root.my_fingerprint.hex()
            except Exception as exc:
                logger.exception("seed derivation failed")
                return _error_destination("Derive failed", str(exc))

            # 7. Confirmation screen showing master fingerprint.
            confirm_ret = self.run_screen(
                WarningScreen,
                title="Push?",
                status_headline=None,
                text=f"Master fp:\n{fingerprint}\nVerify before push.",
                show_back_button=True,
                button_data=[self.CONFIRM],
            )
            if confirm_ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            # 8. Push (PIN handled by the wrapper — cached or prompted).
            try:
                client, _ = _open_unlocked_session_cached_or_prompt(
                    self, require_key=False,
                )
                client.load_bip39_seed(bytes(seed64))
            except KeycardPinPromptCancelled:
                return Destination(BackStackView)
            except KeycardCardChangedError:
                return Destination(ToolsKeycardPairView)
            except Exception as exc:
                logger.exception("LOAD_KEY failed")
                title, body = classify_card_error(exc, default_title="Push failed")
                return _error_destination(title, body)

            # The on-card master key just changed — any cached View-wallets
            # addresses for this AID were derived from the old key.
            _invalidate_wallets_cache_for_active_aid(self.controller)

            self.run_screen(
                LargeIconStatusScreen,
                title="Wallet imported",
                status_headline=None,
                text=f"Master fp:\n{fingerprint}",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(ToolsKeycardMenuView, skip_current_view=True)
        finally:
            # Best-effort wipe of every intermediate secret.
            for i in range(len(words)):
                try:
                    wipe_string(words[i])
                except Exception:
                    pass
            _wipe_bytearray(passphrase_buf)
            _wipe_bytearray(seed64)

    # ---- input capture helpers ----

    def _capture_via_scan(self) -> Optional[list]:
        """Scan a SeedQR / Compact SeedQR / mnemonic QR.

        Returns the list of BIP-39 words on success, ``None`` on
        back-out, or raises a Destination via _error_destination on
        invalid payloads (caller handles via try/except).
        """
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.models.decode_qr import DecodeQR

        decoder = DecodeQR()
        self.run_screen(
            ScanScreen,
            instructions_text="Scan SeedQR",
            decoder=decoder,
        )
        time.sleep(0.1)
        if not decoder.is_complete:
            return None
        if not decoder.is_seed:
            raise RuntimeError("Not a seed QR")
        phrase = decoder.get_seed_phrase()
        if not phrase or len(phrase) not in (12, 18, 21, 24):
            raise RuntimeError(f"Unexpected seed length: {len(phrase) if phrase else 0}")
        return list(phrase)

    def _capture_via_keyboard(self, num_words: int) -> Optional[list]:
        """Capture ``num_words`` words via the on-screen keyboard."""
        from seedsigner.gui.screens import seed_screens
        from seedsigner.models.seed import Seed

        wordlist = Seed.get_wordlist(
            wordlist_language_code=self.settings.get_value(
                SettingsConstants.SETTING__WORDLIST_LANGUAGE,
            ),
        )
        words: list = []
        for i in range(num_words):
            ret = self.run_screen(
                seed_screens.SeedMnemonicEntryScreen,
                title=f"Word #{i + 1}",
                initial_letters=["a"],
                wordlist=wordlist,
            )
            if ret == RET_CODE__BACK_BUTTON:
                return None
            if not isinstance(ret, str) or not ret:
                return None
            words.append(ret)
        return words


# ---------------------------------------------------------------------------
# Export pubkey / address
# ---------------------------------------------------------------------------


def _hash160(data: bytes) -> bytes:
    """RIPEMD-160(SHA-256(data)) — BIP-32 fingerprint primitive."""
    import hashlib
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _compress_pubkey(uncompressed: bytes) -> bytes:
    """Compress a 65-byte (0x04 ‖ X ‖ Y) secp256k1 pubkey to 33 bytes."""
    if len(uncompressed) != 65 or uncompressed[0] != 0x04:
        raise ValueError("expected 65-byte uncompressed pubkey")
    prefix = b"\x02" if uncompressed[64] % 2 == 0 else b"\x03"
    return prefix + uncompressed[1:33]


# Hardened-bit OR helper for BIP-32 path components.
_H = 0x80000000

# Path components for derive_key (high bit = hardened).
_PATH_44H = [44 | _H]
_PATH_44H_60H = [44 | _H, 60 | _H]
_PATH_44H_60H_0H = [44 | _H, 60 | _H, 0 | _H]


class ToolsKeycardPairWalletView(View):
    """Export the BIP-44 ETH HD account as a ``crypto-hdkey`` UR.

    Rabby and MetaMask Mobile import this UR and from then on derive
    receive addresses (``0/i``) themselves. Subsequent eth-sign-request
    QRs from those wallets target paths under ``m/44'/60'/0'`` and the
    Keycard signs them in :class:`ToolsKeycardSignEthFinalizeView`.

    Flow inside one PIN-verified session:

    1. ``m`` → master pubkey → master fingerprint.
    2. ``m/44'/60'`` → parent pubkey → parent fingerprint.
    3. ``m/44'/60'/0'`` → account pubkey + chain code.
    4. ``m/44'/60'/0'/0/0`` → first-receive pubkey for the address screen.

    The ``crypto-hdkey`` QR is the primary screen; the checksum address
    screen is shown after the user dismisses the QR, so they can
    physically read off ``m/0/0`` and compare to what their wallet
    displays after import.
    """

    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.helpers.keycard import (
            KeycardCardChangedError, KeycardPinPromptCancelled,
        )
        from seedsigner.models.encode_qr import EthHDKeyQrEncoder

        if not self.controller.has_any_keycard_auth():
            return Destination(ToolsKeycardPairView)

        master_pub = parent_pub = None
        account_pub = chain_code = None
        first_addr_pub = None
        failed_step: Optional[str] = None
        failed_head: bytes = b""

        steps = [
            ("master", [], False),
            ("m/44'/60'", _PATH_44H_60H, False),
            ("m/44'/60'/0'", _PATH_44H_60H_0H, True),
            ("m/44'/60'/0'/0/0", list(DEFAULT_ETH_PATH), False),
        ]
        results: dict = {}

        try:
            client, _ = _open_unlocked_session_cached_or_prompt(self)
            for label, path, ext in steps:
                client.derive_key(path)
                raw = client.export_pubkey(extended=ext)
                logger.info(
                    "Keycard EXPORT %s -> %d bytes head=%s",
                    label, len(raw), raw[:8].hex() if raw else "",
                )
                parsed = (
                    extract_extended_pubkey(raw) if ext
                    else _extract_pubkey(raw)
                )
                if parsed is None:
                    failed_step = label
                    failed_head = raw[:16] if raw else b""
                    break
                results[label] = parsed
        except KeycardPinPromptCancelled:
            return Destination(BackStackView)
        except KeycardCardChangedError:
            return Destination(ToolsKeycardPairView)
        except Exception as exc:
            logger.exception("Keycard EXPORT (pair-wallet) failed")
            title, body = classify_card_error(exc, default_title="Export failed")
            return _error_destination(title, body)

        if failed_step is not None:
            head_hex = failed_head.hex() if failed_head else "(empty)"
            return _error_destination(
                "Parse fail",
                f"Step {failed_step}\nresp={head_hex}",
            )

        master_pub = results["master"]
        parent_pub = results["m/44'/60'"]
        account_pub, chain_code = results["m/44'/60'/0'"]
        first_addr_pub = results["m/44'/60'/0'/0/0"]

        try:
            master_fp = _hash160(_compress_pubkey(master_pub))[:4]
            parent_fp = _hash160(_compress_pubkey(parent_pub))[:4]
            address = to_checksum_address(pubkey_to_address(first_addr_pub))
        except Exception as exc:
            return _error_destination("Bad pubkey", str(exc))

        encoder = EthHDKeyQrEncoder(
            pubkey=account_pub,
            chain_code=chain_code,
            parent_fingerprint=parent_fp,
            source_fingerprint=master_fp,
        )
        self.run_screen(QRDisplayScreen, qr_encoder=encoder)

        # Secondary screen: textual address for visual verification.
        text = f"m/44'/60'/0'/0/0\n{address[:21]}\n{address[21:]}"
        self.run_screen(
            LargeIconStatusScreen,
            title="ETH address",
            status_headline=None,
            text=text,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView, skip_current_view=True)


# Backwards-compatible alias for any external importer (tests, scripts).
ToolsKeycardExportPubkeyView = ToolsKeycardPairWalletView


# ---------------------------------------------------------------------------
# View wallets — paginated list of m/44'/60'/0'/0/i addresses for the
# active Keycard instance. Mirrors the Bitcoin Address Explorer pattern
# (see ``ToolsAddressExplorerAddressListView``): one PIN-verified session
# per page-load, results cached on the controller per-AID so paging back
# and forth doesn't re-derive.
# ---------------------------------------------------------------------------


WALLETS_PER_PAGE = 10


def _wallets_cache_for_active_aid(controller) -> list:
    """Return the per-AID address list, creating it on first access."""
    if controller.keycard_wallets_data is None:
        controller.keycard_wallets_data = {}
    aid_hex = bytes(controller.active_keycard_aid).hex()
    return controller.keycard_wallets_data.setdefault(aid_hex, [])


def _invalidate_wallets_cache_for_active_aid(controller) -> None:
    """Drop the cached View-wallets list for the active AID.

    Call after any operation that changes the on-card master key
    (GENERATE_KEY, LOAD_KEY) so the next View-wallets entry re-derives
    against the new key instead of showing addresses from the old one.
    """
    if controller.keycard_wallets_data is None:
        return
    aid_hex = bytes(controller.active_keycard_aid).hex()
    controller.keycard_wallets_data.pop(aid_hex, None)


class ToolsKeycardWalletsListView(View):
    """Paginated list of EIP-55 addresses for the active Keycard instance."""

    def __init__(self, start_index: int = 0, selected_button_index: int = 0,
                 initial_scroll: int = 0):
        super().__init__()
        self.start_index = start_index
        self.selected_button_index = selected_button_index
        self.initial_scroll = initial_scroll

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.gui.screens.tools_screens import (
            ToolsAddressExplorerAddressListScreen,
        )
        from seedsigner.helpers.keycard import (
            KeycardCardChangedError, KeycardPinPromptCancelled,
        )

        if not self.controller.has_any_keycard_auth():
            return Destination(ToolsKeycardPairView)

        cache = _wallets_cache_for_active_aid(self.controller)
        end_index = self.start_index + WALLETS_PER_PAGE

        if len(cache) < end_index:
            loading_screen = None
            try:
                client, _ = _open_unlocked_session_cached_or_prompt(self)
                loading_screen = LoadingScreenThread(text="Deriving addrs...")
                loading_screen.start()
                for i in range(len(cache), end_index):
                    client.derive_key([44 | _H, 60 | _H, 0 | _H, 0, i])
                    raw = client.export_pubkey()
                    pub = _extract_pubkey(raw)
                    if pub is None:
                        return _error_destination(
                            "Parse fail",
                            f"Index {i}\nresp={raw[:16].hex() if raw else '(empty)'}",
                        )
                    addr = to_checksum_address(pubkey_to_address(pub))
                    cache.append(addr)
            except KeycardPinPromptCancelled:
                return Destination(BackStackView)
            except KeycardCardChangedError:
                return Destination(ToolsKeycardPairView)
            except Exception as exc:
                logger.exception("Keycard View wallets failed")
                title, body = classify_card_error(
                    exc, default_title="Derive failed",
                )
                return _error_destination(title, body)
            finally:
                if loading_screen is not None:
                    loading_screen.stop()

        addresses = cache[self.start_index:end_index]
        active_aid_short = _format_aid_short(self.controller.active_keycard_aid)

        selected = self.run_screen(
            ToolsAddressExplorerAddressListScreen,
            title=f"Wallets ({active_aid_short})",
            start_index=self.start_index,
            addresses=addresses,
            selected_button=self.selected_button_index,
            scroll_y_initial_offset=self.initial_scroll,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if selected == len(addresses):
            # "Next N" button.
            return Destination(
                ToolsKeycardWalletsListView,
                view_args=dict(start_index=end_index),
            )

        # Preserve scroll position so returning lands on the same row.
        try:
            initial_scroll = self.screen.buttons[0].scroll_y
        except Exception:
            initial_scroll = 0

        index = selected + self.start_index
        return Destination(
            ToolsKeycardWalletAddressView,
            view_args=dict(
                index=index,
                address=addresses[selected],
                start_index=self.start_index,
                parent_initial_scroll=initial_scroll,
            ),
            skip_current_view=True,
        )


class ToolsKeycardWalletAddressView(View):
    """Detail screen for a single Keycard wallet address: QR + back."""

    def __init__(self, index: int, address: str, start_index: int,
                 parent_initial_scroll: int = 0):
        super().__init__()
        self.index = index
        self.address = address
        self.start_index = start_index
        self.parent_initial_scroll = parent_initial_scroll

    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import GenericStaticQrEncoder

        qr_encoder = GenericStaticQrEncoder(data=self.address)
        self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)

        return Destination(
            ToolsKeycardWalletsListView,
            view_args=dict(
                start_index=self.start_index,
                selected_button_index=self.index - self.start_index,
                initial_scroll=self.parent_initial_scroll,
            ),
            skip_current_view=True,
        )


# ---------------------------------------------------------------------------
# Manage instances (GlobalPlatform: list / switch active / install / delete)
# ---------------------------------------------------------------------------


# Status Keycard package AID (containing the applet binary). Issued
# instances live under AIDs that share this prefix and add an instance
# byte (e.g. 01, 02, 03 for the last byte).
KEYCARD_PACKAGE_AID = bytes.fromhex("A0000008040001")
KEYCARD_APPLET_AID = bytes.fromhex("A000000804000101")


def _format_aid_short(aid: bytes) -> str:
    if len(aid) == 0:
        return "(empty)"
    hexstr = aid.hex()
    if len(hexstr) <= 16:
        return hexstr
    return hexstr[:6] + "…" + hexstr[-4:]


def _instance_uid_for_aid(controller, aid: bytes) -> Optional[bytes]:
    """Best-effort: return the cached ``instance_uid`` that maps to ``aid``.

    Uses the controller's AID→UID map populated at SELECT time. Falls
    back to ``None`` for AIDs we have never paired this boot, in which
    case the caller renders the AID hex.
    """
    if not hasattr(controller, "get_uid_for_aid"):
        return None
    return controller.get_uid_for_aid(aid)


def _format_instance_label(aid: bytes, controller) -> str:
    """Render an instance row as ``"<label>  (<aid>)"`` when known.

    Falls back to the short AID alone when no label is cached this
    session — e.g. card inserted for the first time without a Pair.
    """
    short_aid = _format_aid_short(aid)
    uid = _instance_uid_for_aid(controller, aid)
    label = controller.get_label_for(uid) if uid else None
    if not label:
        return short_aid
    text = f"{label}  ({short_aid})"
    if len(text) > 26:
        text = text[:25] + "…"
    return text


def _next_free_instance_aid(existing: list) -> bytes:
    """Suggest the next instance AID by bumping the last byte.

    Status default instance AID ends in ``...0101``. We look at every
    existing instance whose AID begins with ``KEYCARD_APPLET_AID`` +
    one byte and pick the smallest unused last byte.
    """
    from seedsigner.helpers.keycard.global_platform import MAX_KEYCARD_INSTANCES
    used = set()
    for aid in existing:
        if (
            len(aid) == len(KEYCARD_APPLET_AID) + 2
            and aid.startswith(KEYCARD_APPLET_AID)
            and aid[-2] == 0x01
        ):
            used.add(aid[-1])
    for candidate in range(0x01, 0x01 + MAX_KEYCARD_INSTANCES):
        if candidate not in used:
            return KEYCARD_APPLET_AID + bytes([0x01, candidate])
    raise RuntimeError(
        f"no free instance slot (max {MAX_KEYCARD_INSTANCES})"
    )


class ToolsKeycardInstancesMenuView(View):
    """Top-level Manage Instances menu.

    All four operations talk to the Card Manager (ISD), not the Keycard
    applet itself. The user must be aware their card uses the GP
    default ISD keys (`404142...4F`); we don't try to brute-force or
    prompt for alternates here.
    """

    LIST = ButtonOption("List instances")
    SWITCH = ButtonOption("Switch active")
    CREATE = ButtonOption("Create instance")
    RENAME = ButtonOption("Rename instance")
    DELETE = ButtonOption("Delete instance")

    def run(self):
        active = _format_instance_label(
            self.controller.active_keycard_aid, self.controller,
        )
        button_data = [self.LIST, self.SWITCH, self.CREATE, self.RENAME, self.DELETE]
        ret = self.run_screen(
            ButtonListScreen,
            title=f"Active: {active}",
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        chosen = button_data[ret]
        if chosen == self.LIST:
            return Destination(ToolsKeycardInstancesListView)
        if chosen == self.SWITCH:
            return Destination(ToolsKeycardInstancesSwitchView)
        if chosen == self.CREATE:
            return Destination(ToolsKeycardInstancesCreateView)
        if chosen == self.RENAME:
            return Destination(ToolsKeycardInstancesRenameView)
        if chosen == self.DELETE:
            return Destination(ToolsKeycardInstancesDeleteView)
        return Destination(BackStackView)


def _open_isd_channel(controller):
    """Helper: open the GP secure channel against the inserted card.

    Returns ``(channel, instances, connection)``. ``instances`` is the
    list reported by the ISD's GET STATUS; if the ISD reports zero,
    callers can fall back to :func:`probe_keycard_instance_aids` using
    ``connection`` (which terminates the GP channel as a side-effect).
    Caller surfaces errors via ``_error_destination`` — we deliberately
    let exceptions bubble.
    """
    from seedsigner.helpers.keycard.global_platform import (
        GpSecureChannel, list_instances,
    )
    from seedsigner.helpers.keycard.reader import (
        release_other_smartcard_holders, wait_for_card,
    )

    release_other_smartcard_holders(controller)
    connection = wait_for_card(timeout_s=5.0)
    channel = GpSecureChannel(connection)
    channel.select_isd()
    channel.open()
    instances = list_instances(channel)
    return channel, instances, connection


def _instances_or_probe_fallback(controller, instances, connection):
    """If GET STATUS came back empty, probe likely AIDs via cleartext SELECT.

    Returns a list of ``AppletInstance`` (with stub life_cycle/privileges
    when discovered via probing). Probing terminates the GP channel as
    a side-effect, so the caller MUST stop using ``channel`` afterwards.
    """
    if instances:
        return instances
    from seedsigner.helpers.keycard.global_platform import (
        AppletInstance, probe_keycard_instance_aids,
    )
    aids = probe_keycard_instance_aids(connection)
    return [AppletInstance(aid=aid, life_cycle=0, privileges=0) for aid in aids]


class ToolsKeycardInstancesListView(View):
    def run(self):
        try:
            channel, instances, isd_connection = _open_isd_channel(self.controller)
        except Exception as exc:
            logger.exception("GP list_instances failed")
            title, body = classify_card_error(exc, default_title="GP failed")
            return _error_destination(title, body)

        # Some cards / Card Manager configurations don't expose installed
        # applets via GET STATUS. Fall back to probing known Keycard AIDs
        # via cleartext SELECT — this terminates the GP channel as a side
        # effect, which is fine because we don't issue more GP commands.
        instances = _instances_or_probe_fallback(
            self.controller, instances, isd_connection,
        )

        from seedsigner.helpers.keycard.global_platform import MAX_KEYCARD_INSTANCES
        keycard_instances = [
            i for i in instances if i.aid.startswith(KEYCARD_APPLET_AID)
        ]
        if not instances:
            text = "No applet instances\nfound."
        else:
            lines = [
                _format_instance_label(i.aid, self.controller) for i in instances
            ]
            text = "\n".join(lines[:6])
        self.run_screen(
            LargeIconStatusScreen,
            title=f"Instances ({len(keycard_instances)}/{MAX_KEYCARD_INSTANCES})",
            status_headline=None,
            text=text,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(BackStackView)


class ToolsKeycardInstancesSwitchView(View):
    def run(self):
        try:
            channel, instances, isd_connection = _open_isd_channel(self.controller)
        except Exception as exc:
            logger.exception("GP list_instances failed")
            title, body = classify_card_error(exc, default_title="GP failed")
            return _error_destination(title, body)

        instances = _instances_or_probe_fallback(
            self.controller, instances, isd_connection,
        )

        # Filter to AIDs that look like Keycard instances.
        candidates = [
            i for i in instances if i.aid.startswith(KEYCARD_APPLET_AID)
        ]
        if not candidates:
            return _error_destination(
                "No instances",
                "No Keycard applet found on this card.",
            )

        from seedsigner.helpers.keycard.global_platform import MAX_KEYCARD_INSTANCES
        button_data = [
            ButtonOption(_format_instance_label(i.aid, self.controller))
            for i in candidates
        ]
        ret = self.run_screen(
            ButtonListScreen,
            title=f"Pick active ({len(candidates)}/{MAX_KEYCARD_INSTANCES})",
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        chosen = candidates[ret].aid
        self.controller.active_keycard_aid = chosen
        # Drop any cached wallets list whose AID no longer matches the
        # current active. Cheap to recompute and avoids showing stale
        # addresses derived against a different instance's master key.
        if self.controller.keycard_wallets_data is not None:
            self.controller.keycard_wallets_data.clear()

        self.run_screen(
            LargeIconStatusScreen,
            title="Active set",
            status_headline=None,
            text=_format_aid_short(chosen),
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardInstancesMenuView, skip_current_view=True)


class ToolsKeycardInstancesCreateView(View):
    """Install a fresh Keycard applet instance from the on-card package."""

    CONFIRM = ButtonOption("Create")

    def run(self):
        from seedsigner.helpers.keycard.global_platform import (
            GpProtocolError, MAX_KEYCARD_INSTANCES,
            install_for_install_with_fallback,
        )

        try:
            channel, instances, isd_connection = _open_isd_channel(self.controller)
        except Exception as exc:
            logger.exception("GP open failed")
            title, body = classify_card_error(exc, default_title="GP open failed")
            return _error_destination(title, body)

        existing_aids = [i.aid for i in instances]
        keycard_count = sum(
            1 for aid in existing_aids if aid.startswith(KEYCARD_APPLET_AID)
        )
        if keycard_count >= MAX_KEYCARD_INSTANCES:
            return _error_destination(
                "Maximum reached",
                f"Delete one of the {MAX_KEYCARD_INSTANCES} instances first.",
            )
        try:
            new_aid = _next_free_instance_aid(existing_aids)
        except Exception as exc:
            return _error_destination("No slot", str(exc))

        ret = self.run_screen(
            DireWarningScreen,
            title="Create instance?",
            status_headline=None,
            text=f"New AID:\n{_format_aid_short(new_aid)}\nCard must have package.",
            show_back_button=True,
            button_data=[self.CONFIRM],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        try:
            install_for_install_with_fallback(
                channel,
                package_aid=KEYCARD_PACKAGE_AID,
                applet_aid=KEYCARD_APPLET_AID,
                instance_aid=new_aid,
            )
        except GpProtocolError as exc:
            logger.exception("INSTALL [for install] failed")
            # GpProtocolError messages are like "Security status not
            # satisfied (0x6982)" — surface that directly so the user
            # has the SW to share if reporting. Keep within 2 lines.
            detail = str(exc)[:80]
            return _error_destination("Install failed", detail)
        except Exception as exc:
            logger.exception("INSTALL [for install] failed")
            title, body = classify_card_error(exc, default_title="Install failed")
            return _error_destination(title, body)

        self.run_screen(
            LargeIconStatusScreen,
            title="Created",
            status_headline=None,
            text=f"AID:\n{_format_aid_short(new_aid)}\nRun Init next.",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardInstancesMenuView, skip_current_view=True)


class ToolsKeycardInstancesRenameView(View):
    """Rename the wallet label associated with a Keycard instance.

    Lists the keycard-prefixed instances on the inserted card, lets the
    user pick one, captures the new name, and re-encrypts the on-disk
    pairing blob with the updated label. Tries the well-known pairing
    passwords (KeycardDefaultPairing, keycard-shell raw PSK) silently
    first; only prompts the user for a pairing password when both
    silent paths fail to decrypt — same UX pattern as the Pair flow.
    """

    def run(self):
        try:
            from seedsigner.helpers.keycard import pairing_storage
            from seedsigner.helpers.keycard.client import KeycardClient
            from seedsigner.helpers.keycard.crypto import KEYCARD_SHELL_DEFAULT_PSK
            from seedsigner.helpers.keycard.reader import (
                release_other_smartcard_holders, wait_for_card,
            )
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        try:
            channel, instances, isd_connection = _open_isd_channel(self.controller)
        except Exception as exc:
            logger.exception("GP open failed")
            title, body = classify_card_error(exc, default_title="GP failed")
            return _error_destination(title, body)

        instances = _instances_or_probe_fallback(
            self.controller, instances, isd_connection,
        )
        candidates = [
            i for i in instances if i.aid.startswith(KEYCARD_APPLET_AID)
        ]
        if not candidates:
            return _error_destination(
                "No instances", "No Keycard applet found.",
            )

        button_data = [
            ButtonOption(_format_instance_label(i.aid, self.controller))
            for i in candidates
        ]
        ret = self.run_screen(
            ButtonListScreen,
            title="Rename?",
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        target_aid = candidates[ret].aid

        # Resolve instance_uid via SELECT against the chosen AID.
        try:
            release_other_smartcard_holders(self.controller)
            connection = wait_for_card(timeout_s=5.0)
            client = KeycardClient(connection)
            select_info = client.select(aid=target_aid)
        except Exception as exc:
            logger.exception("Keycard SELECT failed")
            title, body = classify_card_error(exc, default_title="SELECT failed")
            return _error_destination(title, body)
        instance_uid = bytes(select_info.instance_uid)
        self.controller.remember_aid_for_uid(target_aid, instance_uid)

        raw = prompt_for_text(self, "New wallet name", max_len=16)
        if raw is None:
            return Destination(BackStackView)
        stripped = raw.strip()
        new_label = stripped if stripped else None

        silent_pwds = [
            DEFAULT_PAIRING_PASSWORD,
            "raw-psk:" + KEYCARD_SHELL_DEFAULT_PSK.hex(),
        ]
        updated = False
        for storage_pwd in silent_pwds:
            try:
                pairing_storage.update_label(storage_pwd, instance_uid, new_label)
                updated = True
                break
            except pairing_storage.PairingStorageError:
                continue
            except OSError:
                return _error_destination(
                    "Storage error", "Insert microSD and retry.",
                )

        if not updated:
            password = prompt_for_text(self, "Pairing password")
            if password is None:
                return Destination(BackStackView)
            try:
                try:
                    pairing_storage.update_label(password, instance_uid, new_label)
                except pairing_storage.PairingStorageError:
                    return _error_destination(
                        "Wrong password", "Could not decrypt blob.",
                    )
                except OSError:
                    return _error_destination(
                        "Storage error", "Insert microSD and retry.",
                    )
            finally:
                try:
                    wipe_string(password)
                except Exception:
                    pass

        # Reflect the change in the controller cache so the next
        # screen render shows the new name.
        self.controller.set_label_for(instance_uid, new_label)

        self.run_screen(
            LargeIconStatusScreen,
            title="Renamed",
            status_headline=None,
            text=new_label or "(no name)",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardInstancesMenuView, skip_current_view=True)


class ToolsKeycardInstancesDeleteView(View):
    """Delete an applet instance and drop its local pairing."""

    def run(self):
        from seedsigner.helpers.keycard.global_platform import delete_aid

        try:
            channel, instances, isd_connection = _open_isd_channel(self.controller)
        except Exception as exc:
            logger.exception("GP open failed")
            title, body = classify_card_error(exc, default_title="GP failed")
            return _error_destination(title, body)

        candidates = [
            i for i in instances if i.aid.startswith(KEYCARD_APPLET_AID)
        ]
        if not candidates:
            return _error_destination(
                "No instances", "Nothing to delete.",
            )

        button_data = [
            ButtonOption(_format_instance_label(i.aid, self.controller))
            for i in candidates
        ]
        ret = self.run_screen(
            ButtonListScreen,
            title="Delete?",
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        target = candidates[ret].aid

        confirm_ret = self.run_screen(
            DireWarningScreen,
            title="Confirm delete?",
            status_headline=None,
            text=f"Delete instance\n{_format_aid_short(target)}?",
            show_back_button=True,
            button_data=[ButtonOption("Delete")],
        )
        if confirm_ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        try:
            delete_aid(channel, target, with_related=True)
        except Exception as exc:
            logger.exception("DELETE failed")
            title, body = classify_card_error(exc, default_title="Delete failed")
            return _error_destination(title, body)

        # Drop any cached pairing whose previously-observed UID we
        # can't tie to this AID. Best-effort: we don't know the
        # mapping AID → instance_uid here without re-SELECTing the
        # applet (which we just deleted). Leave the cache for now;
        # next operation will get KeycardCardChangedError if needed.

        # If the deleted AID was the active one, fall back to default.
        if self.controller.active_keycard_aid == target:
            self.controller.active_keycard_aid = KEYCARD_APPLET_AID + b"\x01\x01"
        # Invalidate the cached wallet list for the deleted AID (and
        # the fallback default, in case both pointed at the same blob).
        if self.controller.keycard_wallets_data is not None:
            self.controller.keycard_wallets_data.pop(bytes(target).hex(), None)

        self.run_screen(
            LargeIconStatusScreen,
            title="Deleted",
            status_headline=None,
            text=_format_aid_short(target),
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardInstancesMenuView, skip_current_view=True)


# ---------------------------------------------------------------------------
# Sign ETH (scan → review → sign → display)
# ---------------------------------------------------------------------------


def _format_wei(wei: int) -> str:
    if wei == 0:
        return "0 ETH"
    eth = wei / 10 ** 18
    if eth >= 0.0001:
        return f"{eth:.6f} ETH"
    if wei >= 10 ** 9:
        gwei = wei / 10 ** 9
        return f"{gwei:.3f} gwei"
    return f"{wei} wei"


def _decode_legacy_tx(sign_data: bytes):
    try:
        from seedsigner.helpers.ethereum import rlp
        items = rlp.decode(sign_data)
    except Exception:
        return None
    if not isinstance(items, list) or len(items) < 6:
        return None
    try:
        return {
            "nonce": rlp.decode_int(items[0]),
            "gas_price": rlp.decode_int(items[1]),
            "gas_limit": rlp.decode_int(items[2]),
            "to": bytes(items[3]) if isinstance(items[3], (bytes, bytearray)) else b"",
            "value": rlp.decode_int(items[4]),
            "data": bytes(items[5]) if isinstance(items[5], (bytes, bytearray)) else b"",
        }
    except Exception:
        return None


def _decode_eip1559_tx(sign_data: bytes):
    try:
        from seedsigner.helpers.ethereum import rlp
        if not sign_data or sign_data[0] != 0x02:
            return None
        items = rlp.decode(sign_data[1:])
    except Exception:
        return None
    if not isinstance(items, list) or len(items) < 8:
        return None
    try:
        return {
            "chain_id": rlp.decode_int(items[0]),
            "nonce": rlp.decode_int(items[1]),
            "max_priority": rlp.decode_int(items[2]),
            "max_fee": rlp.decode_int(items[3]),
            "gas_limit": rlp.decode_int(items[4]),
            "to": bytes(items[5]) if isinstance(items[5], (bytes, bytearray)) else b"",
            "value": rlp.decode_int(items[6]),
            "data": bytes(items[7]) if isinstance(items[7], (bytes, bytearray)) else b"",
        }
    except Exception:
        return None


def _eth_tx_summary(request: "EthSignRequest"):
    """Return parsed (to, value, gas_limit, data) for tx-typed requests, else None."""
    if request.data_type == DATA_TYPE_LEGACY_TX:
        return _decode_legacy_tx(request.sign_data)
    if request.data_type == DATA_TYPE_TYPED_TX:
        return _decode_eip1559_tx(request.sign_data)
    return None


class ToolsKeycardSignEthStartView(View):
    def run(self):
        # skip_current_view=True so a BACK from the scan returns to the
        # Keycard menu instead of bouncing back here and re-launching
        # the camera.
        if not self.controller.has_any_keycard_auth():
            return Destination(ToolsKeycardPairView, skip_current_view=True)
        return Destination(ScanEthSignRequestView, skip_current_view=True)


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
    """Page 1/N — kind, chain, path, address. Continues to TX details."""
    CONTINUE = ButtonOption("Continue")
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
        button_data = [self.CONTINUE, self.CANCEL]
        ret = self.run_screen(
            LargeIconStatusScreen,
            title="Sign ETH? 1/N",
            status_icon_size=0,
            status_headline=None,
            text=text,
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=False,
        )
        if ret == RET_CODE__BACK_BUTTON or button_data[ret] == self.CANCEL:
            self.controller.eth_sign_request = None
            return Destination(BackStackView)
        return Destination(ToolsKeycardSignEthDetailsView)


class ToolsKeycardSignEthDetailsView(View):
    """Page 2/N — to/value/gas for legacy/EIP1559; raw hash for typed-data;
    decoded text for personal-sign. Confirms directly if no calldata follows.
    """
    SHOW_DATA = ButtonOption("Show data")
    CONFIRM = ButtonOption("Confirm & sign")
    CANCEL = ButtonOption("Cancel")

    def run(self):
        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination("No request", "Lost mid-flow")

        tx = _eth_tx_summary(request)
        has_data = False
        if tx is not None:
            to_bytes = tx.get("to") or b""
            to_str = "(create)" if not to_bytes else to_checksum_address(to_bytes)
            # Truncate the address middle so the line still fits on a 240px screen.
            if len(to_str) > 14:
                to_str = f"{to_str[:8]}…{to_str[-4:]}"
            text = (
                f"to {to_str}\n"
                f"value {_format_wei(tx['value'])}\n"
                f"gas {tx.get('gas_limit', 0)}"
            )
            has_data = bool(tx.get("data"))
        elif request.data_type == DATA_TYPE_PERSONAL_MESSAGE:
            try:
                msg = bytes(request.sign_data).decode("utf-8")
            except Exception:
                msg = bytes(request.sign_data).hex()
            preview = msg if len(msg) <= 80 else msg[:78] + "…"
            text = f"message:\n{preview}"
        elif request.data_type == DATA_TYPE_TYPED_DATA:
            digest = bytes(request.sign_data).hex()
            text = f"EIP-712 hash:\n{digest[:32]}\n{digest[32:64] if len(digest) >= 64 else ''}"
            has_data = len(bytes(request.sign_data)) > 0
        else:
            text = f"raw\n{bytes(request.sign_data)[:32].hex()}…"
            has_data = True

        if has_data:
            button_data = [self.SHOW_DATA, self.CONFIRM, self.CANCEL]
        else:
            button_data = [self.CONFIRM, self.CANCEL]

        ret = self.run_screen(
            LargeIconStatusScreen,
            title="TX details 2/N",
            status_icon_size=0,
            status_headline=None,
            text=text,
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        if button_data[ret] == self.CANCEL:
            self.controller.eth_sign_request = None
            return Destination(BackStackView)
        if button_data[ret] == self.SHOW_DATA:
            return Destination(ToolsKeycardSignEthDataView, view_args={"page": 0})
        return Destination(ToolsKeycardSignEthFinalizeView)


class ToolsKeycardSignEthDataView(View):
    """Page 3/N — paginated calldata hex (or raw payload for typed-data).

    96 hex chars per page (= 48 bytes), wrapped 24 chars per line so the
    240px screen displays four lines without overflow.
    """
    NEXT = ButtonOption("Next page")
    PREV = ButtonOption("Previous")
    CONFIRM = ButtonOption("Confirm & sign")
    CANCEL = ButtonOption("Cancel")

    PAGE_HEX_CHARS = 96
    LINE_HEX_CHARS = 24

    def __init__(self, page: int = 0):
        super().__init__()
        self.page = max(0, page)

    def run(self):
        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination("No request", "Lost mid-flow")

        tx = _eth_tx_summary(request)
        if tx is not None:
            data = tx.get("data") or b""
        else:
            # Typed-data hash / personal-message / unknown — show raw bytes.
            data = bytes(request.sign_data)

        if not data:
            return Destination(
                ToolsKeycardSignEthFinalizeView, skip_current_view=True,
            )

        hex_data = data.hex()
        total_pages = (len(hex_data) + self.PAGE_HEX_CHARS - 1) // self.PAGE_HEX_CHARS
        page = min(self.page, total_pages - 1)
        start = page * self.PAGE_HEX_CHARS
        chunk = hex_data[start:start + self.PAGE_HEX_CHARS]
        wrapped = "\n".join(
            chunk[i:i + self.LINE_HEX_CHARS]
            for i in range(0, len(chunk), self.LINE_HEX_CHARS)
        )

        button_data = []
        if page < total_pages - 1:
            button_data.append(self.NEXT)
        if page > 0:
            button_data.append(self.PREV)
        button_data.append(self.CONFIRM)
        button_data.append(self.CANCEL)

        ret = self.run_screen(
            LargeIconStatusScreen,
            title=f"Data {page + 1}/{total_pages}",
            status_icon_size=0,
            status_headline=None,
            text=wrapped,
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        choice = button_data[ret]
        if choice == self.CANCEL:
            self.controller.eth_sign_request = None
            return Destination(BackStackView)
        if choice == self.NEXT:
            return Destination(
                ToolsKeycardSignEthDataView,
                view_args={"page": page + 1},
                skip_current_view=True,
            )
        if choice == self.PREV:
            return Destination(
                ToolsKeycardSignEthDataView,
                view_args={"page": page - 1},
                skip_current_view=True,
            )
        return Destination(ToolsKeycardSignEthFinalizeView)


class ToolsKeycardSignEthFinalizeView(View):
    def run(self):
        from seedsigner.helpers.keycard import (
            KeycardCardChangedError, KeycardPinPromptCancelled,
        )

        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination("No request", "Lost request mid-flow")
        if not self.controller.has_any_keycard_auth():
            return Destination(ToolsKeycardPairView)

        try:
            from seedsigner.helpers.keycard_signer import sign_with_keycard
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        try:
            client, _ = _open_unlocked_session_cached_or_prompt(self)
            signature = sign_with_keycard(client, request)
        except KeycardPinPromptCancelled:
            return Destination(BackStackView)
        except KeycardCardChangedError:
            self.controller.eth_sign_request = None
            self.controller.eth_signature = None
            return Destination(ToolsKeycardPairView)
        except Exception as exc:
            logger.exception("Keycard signing failed")
            self.controller.eth_sign_request = None
            self.controller.eth_signature = None
            title, body = classify_card_error(exc, default_title="Signing failed")
            return _error_destination(title, body, return_to_main=True)

        self.controller.eth_signature = signature
        return Destination(ToolsKeycardSignEthQrDisplayView)


class ToolsKeycardSignEthQrDisplayView(View):
    def run(self):
        signature = getattr(self.controller, "eth_signature", None)
        if signature is None:
            return _error_destination("No signature", "Nothing to display")

        from seedsigner.gui.screens.screen import QRDisplayScreen

        encoder = EthSignatureQrEncoder(eth_signature=signature)
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=encoder,
        )
        self.controller.eth_sign_request = None
        self.controller.eth_signature = None
        return Destination(MainMenuView)


# ---------------------------------------------------------------------------
# Helpers (the rest live in helpers/keycard/ui_helpers.py)
# ---------------------------------------------------------------------------


def _error_destination(
    title: str,
    message: str,
    *,
    return_to_main: bool = False,
) -> Destination:
    return Destination(
        KeycardErrorView,
        view_args={
            "title": title,
            "message": message,
            "return_to_main": return_to_main,
        },
        skip_current_view=True,
    )


class KeycardErrorView(View):
    def __init__(self, title: str, message: str, return_to_main: bool = False):
        super().__init__()
        self.title = title
        self.message = message
        self.return_to_main = return_to_main

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
        if self.return_to_main:
            return Destination(MainMenuView, clear_history=True)
        # Route explicitly to the Keycard menu (not BackStackView): every
        # Keycard error is dispatched with skip_current_view=True, so the
        # back stack state at this point depends on whatever sub-flow
        # raised. Sending the user straight to the menu — and clearing the
        # breadcrumbs — is deterministic and matches what successful flows
        # already do (e.g. ToolsKeycardInitView, ToolsKeycardFactoryResetView).
        return Destination(ToolsKeycardMenuView, clear_history=True)
