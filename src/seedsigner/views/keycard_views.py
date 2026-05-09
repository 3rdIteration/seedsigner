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
    IMPORT_SEED = ButtonOption("Import seedphrase to card")
    INIT = ButtonOption("Initialise blank card")
    FACTORY_RESET = ButtonOption("Factory reset card")
    INSTANCES = ButtonOption("Manage instances")
    STATUS = ButtonOption("Card status")

    def run(self):
        button_data = [
            self.SIGN_ETH,
            self.EXPORT_PUBKEY,
            self.PAIR,
            self.FORGET,
            self.UNPAIR,
            self.GENERATE_KEY,
            self.IMPORT_SEED,
            self.INIT,
            self.FACTORY_RESET,
            self.INSTANCES,
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
        if chosen == self.IMPORT_SEED:
            return Destination(ToolsKeycardImportSeedView)
        if chosen == self.INIT:
            return Destination(ToolsKeycardInitView)
        if chosen == self.FACTORY_RESET:
            return Destination(ToolsKeycardFactoryResetView)
        if chosen == self.INSTANCES:
            return Destination(ToolsKeycardInstancesMenuView)
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
            from seedsigner.helpers.keycard.reader import (
                release_other_smartcard_holders, wait_for_card,
            )
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        try:
            release_other_smartcard_holders(self.controller)
            connection = wait_for_card(timeout_s=5.0)
            client = KeycardClient(connection)
            info = client.select(aid=self.controller.active_keycard_aid)
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
            client.select(aid=self.controller.active_keycard_aid)
            client.factory_reset()
        except APDUError as exc:
            logger.warning("FACTORY_RESET unsupported: %s", exc)
            if (exc.sw & 0xFF00) == 0x6D00:
                return _error_destination(
                    "Not supported",
                    "Update applet, or use\nkeycard-shell on PC.",
                )
            return _error_destination("Reset failed", str(exc))
        except Exception as exc:
            logger.exception("FACTORY_RESET failed")
            return _error_destination("Reset failed", str(exc))

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
        return Destination(ToolsKeycardMenuView)


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
            release_other_smartcard_holders(self.controller)
            connection = wait_for_card(timeout_s=5.0)
            client = KeycardClient(connection)
            client.select(aid=self.controller.active_keycard_aid)
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
    """Pair the card currently in the reader for this boot.

    Behaviour:
      1. SELECT the inserted card to discover its ``instance_uid``.
      2. If a pairing for that UID is already cached this boot, return
         immediately without prompting (multi-card auto-switch friendly).
      3. Otherwise prompt for the pairing password, try to load a
         previously-saved encrypted blob (per-UID file, with legacy
         single-file fallback), and only fall back to a fresh PAIR APDU
         when no blob is available.
      4. Persist the resulting pairing under the per-UID filename and
         cache it on the controller's keycard_pairings dict.
    """

    def run(self):
        try:
            from seedsigner.helpers.keycard import pairing_storage
            from seedsigner.helpers.keycard.client import KeycardClient
            from seedsigner.helpers.keycard.crypto import derive_pairing_secret
            from seedsigner.helpers.keycard.reader import (
                release_other_smartcard_holders, wait_for_card,
            )
            from seedsigner.helpers.keycard.secure_channel import PairingInfo
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        try:
            release_other_smartcard_holders(self.controller)
            connection = wait_for_card(timeout_s=5.0)
            client = KeycardClient(connection)
            select_info = client.select(aid=self.controller.active_keycard_aid)
        except Exception as exc:
            logger.exception("Keycard SELECT failed")
            return _error_destination("Card not reachable", str(exc))

        instance_uid = bytes(select_info.instance_uid)
        self.controller.last_keycard_uid = instance_uid

        if self.controller.get_pairing_for(instance_uid) is not None:
            self.run_screen(
                LargeIconStatusScreen,
                title="Already paired",
                status_headline=None,
                text="This card is paired in the\ncurrent session.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(ToolsKeycardMenuView)

        password = _prompt_for_text(self, "Pairing password")
        if password is None:
            return Destination(BackStackView)

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

        pairing: Optional[PairingInfo] = None
        loaded_from_disk = False
        try:
            stored = pairing_storage.load(normalised, instance_uid=instance_uid)
        except pairing_storage.PairingStorageError as exc:
            logger.info("saved pairing rejected: %s", exc)
            stored = None

        if stored is not None and stored.instance_uid == instance_uid:
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
                pairing_storage.save(normalised, pairing, instance_uid)
            except Exception:
                logger.exception("could not persist pairing")
                # Non-fatal: keep the in-memory pairing.

        try:
            wipe_string(normalised)
        except Exception:
            pass
        _wipe_bytearray(password_buf)

        self.controller.set_pairing_for(instance_uid, pairing)
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
    """Forget pairings: current card, all cards, or a single saved entry."""

    FORGET_CURRENT = ButtonOption("Forget current card")
    FORGET_ALL = ButtonOption("Forget all")

    def run(self):
        try:
            from seedsigner.helpers.keycard import pairing_storage
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        entries = pairing_storage.list_pairings()

        button_data = [self.FORGET_CURRENT, self.FORGET_ALL]
        # One entry per saved blob, labelled by short fingerprint.
        for entry in entries:
            label = "Card legacy" if entry.is_legacy else f"Card {entry.fingerprint[:4]}…{entry.fingerprint[-4:]}"
            button_data.append(ButtonOption(label))

        title = f"Forget ({len(entries)} saved)"
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
        if chosen == self.FORGET_CURRENT:
            return Destination(ToolsKeycardForgetCurrentCardView)
        if chosen == self.FORGET_ALL:
            return Destination(ToolsKeycardForgetAllPairingsView)

        # Saved-entry path. Find the matching pairing_storage entry by
        # the same index (offset by 2 leading control buttons).
        idx = ret - 2
        if not (0 <= idx < len(entries)):
            return Destination(BackStackView)
        target_entry = entries[idx]

        warn_ret = self.run_screen(
            WarningScreen,
            title="Forget?",
            status_headline=None,
            text=f"Remove saved pairing\n{target_entry.path.name[:24]}",
            show_back_button=True,
            button_data=[ButtonOption("Forget")],
        )
        if warn_ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        removed = pairing_storage.remove(path=target_entry.path)
        # Best-effort: also drop matching in-memory cache entries by
        # comparing fingerprints.
        if not target_entry.is_legacy:
            for uid in list(self.controller.keycard_pairings.keys()):
                if pairing_storage.fingerprint_for_uid(uid) == target_entry.fingerprint:
                    self.controller.forget_pairing_for(uid)

        self.run_screen(
            LargeIconStatusScreen,
            title="Removed" if removed else "Not found",
            status_headline=None,
            text="Saved pairing removed." if removed else "Already gone.",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardForgetSavedPairingView, skip_current_view=True)


class ToolsKeycardForgetCurrentCardView(View):
    """Forget the pairing for the card currently in the reader."""

    CONFIRM = ButtonOption("Forget current")

    def run(self):
        try:
            from seedsigner.helpers.keycard import pairing_storage
            from seedsigner.helpers.keycard.ui_helpers import identify_inserted_card
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        try:
            _, instance_uid = identify_inserted_card(self)
        except Exception as exc:
            logger.exception("Forget-current SELECT failed")
            return _error_destination("Card not reachable", str(exc))

        ret = self.run_screen(
            WarningScreen,
            title="Forget current?",
            status_headline=None,
            text="Remove this card's pairing\nfrom storage and cache.",
            show_back_button=True,
            button_data=[self.CONFIRM],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        removed = pairing_storage.remove(instance_uid=instance_uid)
        self.controller.forget_pairing_for(instance_uid)

        self.run_screen(
            LargeIconStatusScreen,
            title="Done",
            status_headline=None,
            text="Pairing removed." if removed else "No saved pairing found.",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView)


class ToolsKeycardForgetAllPairingsView(View):
    """Forget every pairing this device knows about."""

    CONFIRM = ButtonOption("Forget all")

    def run(self):
        try:
            from seedsigner.helpers.keycard import pairing_storage
        except ImportError as exc:
            return _error_destination("Keycard support unavailable", str(exc))

        ret = self.run_screen(
            DireWarningScreen,
            title="Forget ALL?",
            status_headline=None,
            text="Removes every saved\npairing on this device.",
            show_back_button=True,
            button_data=[self.CONFIRM],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        count = pairing_storage.remove_all()
        self.controller.forget_all_pairings()

        self.run_screen(
            LargeIconStatusScreen,
            title="Done",
            status_headline=None,
            text=f"Removed {count} pairing(s).",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView)


class ToolsKeycardUnpairView(View):
    CONFIRM = ButtonOption("Unpair")

    def run(self):
        from seedsigner.helpers.keycard import KeycardCardChangedError

        if not self.controller.keycard_pairings:
            return _error_destination("Not paired", "Nothing to unpair.")

        ret = self.run_screen(
            WarningScreen,
            title="Unpair?",
            status_headline=None,
            text="Free this card's slot\non the card.",
            show_back_button=True,
            button_data=[self.CONFIRM],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        pin = _prompt_for_pin(self, "Card PIN")
        if pin is None:
            return Destination(BackStackView)

        try:
            client, pairing = _open_unlocked_session(self, pin)
            client.unpair(pairing.pairing_index)
        except KeycardCardChangedError:
            return Destination(ToolsKeycardPairView)
        except Exception as exc:
            logger.exception("Keycard UNPAIR failed")
            return _error_destination("UNPAIR failed", str(exc))
        finally:
            _wipe_bytearray(pin)

        # Drop the unpaired card from cache + storage.
        from seedsigner.helpers.keycard import pairing_storage
        uid = self.controller.last_keycard_uid
        if uid is not None:
            self.controller.forget_pairing_for(uid)
            try:
                pairing_storage.remove(instance_uid=uid)
            except Exception:
                logger.exception("could not remove unpaired storage")
        return Destination(ToolsKeycardMenuView)


# ---------------------------------------------------------------------------
# Generate key
# ---------------------------------------------------------------------------


class ToolsKeycardGenerateKeyView(View):
    CONFIRM = ButtonOption("Generate key")

    def run(self):
        from seedsigner.helpers.keycard import KeycardCardChangedError

        if not self.controller.keycard_pairings:
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
        except KeycardCardChangedError:
            return Destination(ToolsKeycardPairView)
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
        from seedsigner.helpers.keycard import KeycardCardChangedError

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
        pin: Optional[bytearray] = None

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

            # 8. PIN + push.
            pin = _prompt_for_pin(self, "Card PIN")
            if pin is None:
                return Destination(BackStackView)

            try:
                client, _ = _open_unlocked_session(self, pin)
                client.load_bip39_seed(bytes(seed64))
            except KeycardCardChangedError:
                return Destination(ToolsKeycardPairView)
            except Exception as exc:
                logger.exception("LOAD_KEY failed")
                return _error_destination("Push failed", str(exc))

            self.run_screen(
                LargeIconStatusScreen,
                title="Wallet imported",
                status_headline=None,
                text=f"Master fp:\n{fingerprint}",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(ToolsKeycardMenuView)
        finally:
            # Best-effort wipe of every intermediate secret.
            for i in range(len(words)):
                try:
                    wipe_string(words[i])
                except Exception:
                    pass
            _wipe_bytearray(passphrase_buf)
            _wipe_bytearray(seed64)
            _wipe_bytearray(pin)

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


class ToolsKeycardExportPubkeyView(View):
    def run(self):
        from seedsigner.helpers.keycard import KeycardCardChangedError

        if not self.controller.keycard_pairings:
            return Destination(ToolsKeycardPairView)

        pin = _prompt_for_pin(self, "Card PIN")
        if pin is None:
            return Destination(BackStackView)

        try:
            client, _ = _open_unlocked_session(self, pin)
            client.derive_key(DEFAULT_ETH_PATH)
            response = client.export_pubkey()
        except KeycardCardChangedError:
            return Destination(ToolsKeycardPairView)
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


def _next_free_instance_aid(existing: list) -> bytes:
    """Suggest the next instance AID by bumping the last byte.

    Status default instance AID ends in ``...0101``. We look at every
    existing instance whose AID begins with ``KEYCARD_APPLET_AID`` +
    one byte and pick the smallest unused last byte.
    """
    used = set()
    for aid in existing:
        if (
            len(aid) == len(KEYCARD_APPLET_AID) + 2
            and aid.startswith(KEYCARD_APPLET_AID)
            and aid[-2] == 0x01
        ):
            used.add(aid[-1])
    for candidate in range(0x01, 0x10):
        if candidate not in used:
            return KEYCARD_APPLET_AID + bytes([0x01, candidate])
    raise RuntimeError("no free instance slot in 0x0101..0x010F")


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
    DELETE = ButtonOption("Delete instance")

    def run(self):
        active = _format_aid_short(self.controller.active_keycard_aid)
        button_data = [self.LIST, self.SWITCH, self.CREATE, self.DELETE]
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
        if chosen == self.DELETE:
            return Destination(ToolsKeycardInstancesDeleteView)
        return Destination(BackStackView)


def _open_isd_channel(controller):
    """Helper: open the GP secure channel against the inserted card.

    Returns (gp_channel, list_of_instances). Caller surfaces errors via
    ``_error_destination`` — we deliberately let exceptions bubble.
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
    return channel, instances


class ToolsKeycardInstancesListView(View):
    def run(self):
        try:
            channel, instances = _open_isd_channel(self.controller)
        except Exception as exc:
            logger.exception("GP list_instances failed")
            return _error_destination("GP failed", str(exc))

        if not instances:
            text = "No applet instances\nfound."
        else:
            lines = [_format_aid_short(i.aid) for i in instances]
            text = "\n".join(lines[:6])
        self.run_screen(
            LargeIconStatusScreen,
            title=f"Instances ({len(instances)})",
            status_headline=None,
            text=text,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(BackStackView)


class ToolsKeycardInstancesSwitchView(View):
    def run(self):
        try:
            channel, instances = _open_isd_channel(self.controller)
        except Exception as exc:
            logger.exception("GP list_instances failed")
            return _error_destination("GP failed", str(exc))

        # Filter to AIDs that look like Keycard instances.
        candidates = [
            i for i in instances if i.aid.startswith(KEYCARD_APPLET_AID)
        ]
        if not candidates:
            return _error_destination(
                "No instances",
                "No Keycard applet found on this card.",
            )

        button_data = [
            ButtonOption(_format_aid_short(i.aid)) for i in candidates
        ]
        ret = self.run_screen(
            ButtonListScreen,
            title="Pick active",
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        chosen = candidates[ret].aid
        self.controller.active_keycard_aid = chosen

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
            install_for_install,
        )

        try:
            channel, instances = _open_isd_channel(self.controller)
        except Exception as exc:
            logger.exception("GP open failed")
            return _error_destination("GP failed", str(exc))

        existing_aids = [i.aid for i in instances]
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
            install_for_install(
                channel,
                package_aid=KEYCARD_PACKAGE_AID,
                applet_aid=KEYCARD_APPLET_AID,
                instance_aid=new_aid,
            )
        except Exception as exc:
            logger.exception("INSTALL [for install] failed")
            return _error_destination("Install failed", str(exc))

        self.run_screen(
            LargeIconStatusScreen,
            title="Created",
            status_headline=None,
            text=f"AID:\n{_format_aid_short(new_aid)}\nRun Init next.",
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardInstancesMenuView, skip_current_view=True)


class ToolsKeycardInstancesDeleteView(View):
    """Delete an applet instance and drop its local pairing."""

    def run(self):
        from seedsigner.helpers.keycard.global_platform import delete_aid

        try:
            channel, instances = _open_isd_channel(self.controller)
        except Exception as exc:
            logger.exception("GP open failed")
            return _error_destination("GP failed", str(exc))

        candidates = [
            i for i in instances if i.aid.startswith(KEYCARD_APPLET_AID)
        ]
        if not candidates:
            return _error_destination(
                "No instances", "Nothing to delete.",
            )

        button_data = [
            ButtonOption(_format_aid_short(i.aid)) for i in candidates
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
            return _error_destination("Delete failed", str(exc))

        # Drop any cached pairing whose previously-observed UID we
        # can't tie to this AID. Best-effort: we don't know the
        # mapping AID → instance_uid here without re-SELECTing the
        # applet (which we just deleted). Leave the cache for now;
        # next operation will get KeycardCardChangedError if needed.

        # If the deleted AID was the active one, fall back to default.
        if self.controller.active_keycard_aid == target:
            self.controller.active_keycard_aid = KEYCARD_APPLET_AID + b"\x01\x01"

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


class ToolsKeycardSignEthStartView(View):
    def run(self):
        if not self.controller.keycard_pairings:
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
            LargeIconStatusScreen,
            title="Confirm",
            status_icon_size=0,
            status_headline="Sign ETH?",
            text=text,
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=False,
        )
        if ret == RET_CODE__BACK_BUTTON or button_data[ret] == self.CANCEL:
            self.controller.eth_sign_request = None
            return Destination(BackStackView)
        return Destination(ToolsKeycardSignEthFinalizeView)


class ToolsKeycardSignEthFinalizeView(View):
    def run(self):
        from seedsigner.helpers.keycard import KeycardCardChangedError

        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination("No request", "Lost request mid-flow")
        if not self.controller.keycard_pairings:
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
        except KeycardCardChangedError:
            self.controller.eth_sign_request = None
            self.controller.eth_signature = None
            return Destination(ToolsKeycardPairView)
        except Exception as exc:
            logger.exception("Keycard signing failed")
            self.controller.eth_sign_request = None
            self.controller.eth_signature = None
            return _error_destination(
                "Signing failed", str(exc), return_to_main=True,
            )
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
        return Destination(BackStackView)
