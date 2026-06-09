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

import json
import logging
import time
import unicodedata
from gettext import gettext as _
from gettext import ngettext
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
    try_silent_ephemeral_pair,
    wipe_bytearray,
)
from seedsigner.helpers.l10n import mark_for_translation as _mft
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

# User-facing transaction-type labels (shown on the ETH sign overview).
# Marked with _mft so they're extracted; the display site wraps with _().
DATA_TYPE_LABELS = {
    DATA_TYPE_LEGACY_TX: _mft("Legacy / EIP-155"),
    DATA_TYPE_TYPED_DATA: _mft("EIP-712 typed data"),
    DATA_TYPE_PERSONAL_MESSAGE: _mft("Personal sign"),
    DATA_TYPE_TYPED_TX: _mft("EIP-1559"),
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
    """Top-level Keycard menu, trimmed to the daily-use ops so the common
    path is short:

    * **Ethereum / Bitcoin** — sign / export with the active instance's key.
    * **Switch instance** — change the active applet instance (the rest of
      the instance-set ops live under Settings ▸ Instances).
    * **Lock card** — drop cached PINs so the next op re-prompts.
    * **Settings** — everything less frequent: this-instance key/PIN/pairing
      ops, the instance set (list/create/delete), and whole-card ops.

    Branches that act on one instance carry the active instance label
    (``Inst N``) in their title; card-wide branches do not.

    On entry the card is probed (see ``card_probe.run_card_gate``):
    a missing card snaps back to ``MainMenuView`` with a "No card"
    toast; an uninstantiated applet routes straight to
    ``ToolsKeycardInitView``.
    """

    ETHEREUM = ButtonOption("Ethereum")
    BITCOIN = ButtonOption("Bitcoin")
    SWITCH_INSTANCE = ButtonOption("Switch instance")
    LOCK = ButtonOption("Lock card")
    SETTINGS = ButtonOption("Settings")

    def run(self):
        from seedsigner.helpers.card_probe import run_card_gate
        gate = run_card_gate(
            self, "keycard", title=_("Keycard"), setup_view=ToolsKeycardInitView,
        )
        if gate is not None:
            return gate

        # "Switch instance" is only meaningful when the card holds more
        # than one instance. Resolve the count from the session cache,
        # enumerating the card's instances once (authoritative GET STATUS,
        # no PIN) when unknown. ``None`` means "couldn't determine" — keep
        # the entry visible; only hide it when we're confident there's
        # exactly one.
        count = self.controller.keycard_instance_count
        if count is None:
            count = _count_keycard_instances(self.controller)
            if count is not None:
                self.controller.keycard_instance_count = count

        button_data = [self.ETHEREUM, self.BITCOIN]
        if count != 1:
            button_data.append(self.SWITCH_INSTANCE)
        button_data += [self.LOCK, self.SETTINGS]
        # Surface the active instance in the title so the user always
        # knows which instance signing / export will use this session.
        active = _instance_display_name(self.controller, self.controller.active_keycard_aid)
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Keycard · {}").format(active),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        chosen = button_data[selected]
        if chosen == self.ETHEREUM:
            return Destination(ToolsKeycardEthereumMenuView)
        if chosen == self.BITCOIN:
            return Destination(ToolsKeycardBitcoinMenuView)
        if chosen == self.SWITCH_INSTANCE:
            return Destination(ToolsKeycardInstancesSwitchView)
        if chosen == self.LOCK:
            return Destination(ToolsKeycardLockView)
        if chosen == self.SETTINGS:
            return Destination(ToolsKeycardSettingsMenuView)
        return Destination(NotYetImplementedView)


class ToolsKeycardSettingsMenuView(View):
    """Less-frequent Keycard management, grouped out of the daily-use menu:

    * **Manage Instances** — everything about the applet instances: the
      active one's key/PIN/pairing/init ops (``This instance``) plus
      create / delete of the instance *set*.
    * **Manage Card** — whole-card / package ops (status, storage, uninstall
      the applet package).
    """

    MANAGE_INSTANCES = ButtonOption("Manage Instances")
    CARD = ButtonOption("Manage Card")

    def run(self):
        button_data = [self.MANAGE_INSTANCES, self.CARD]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Settings"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        chosen = button_data[selected]
        if chosen == self.MANAGE_INSTANCES:
            return Destination(ToolsKeycardInstancesMenuView)
        if chosen == self.CARD:
            return Destination(ToolsKeycardCardMenuView)
        return Destination(NotYetImplementedView)


class ToolsKeycardThisInstanceMenuView(View):
    """Operations that act on the **active** instance's key/identity:
    load a key (generate / import), change PIN, rename, factory reset.

    The title carries the active instance label so the scope of every
    child action is explicit.
    """

    GENERATE_KEY = ButtonOption("Generate key")
    IMPORT_SEED = ButtonOption("Import seed")
    CHANGE_PIN = ButtonOption("Change PIN")
    RENAME = ButtonOption("Rename instance")
    INIT = ButtonOption("Initialise instance")
    FACTORY_RESET = ButtonOption("Factory reset")
    LOCK = ButtonOption("Lock card")

    def run(self):
        active = _instance_display_name(self.controller, self.controller.active_keycard_aid)
        # Daily-use key ops up top; the rarer lifecycle ops (Initialise /
        # Factory reset) group at the bottom. "Initialise instance" runs
        # INIT against this instance's applet — it lives here, not under
        # Card, because INIT provisions one instance, not the whole card.
        button_data = [
            self.GENERATE_KEY,
            self.IMPORT_SEED,
            self.CHANGE_PIN,
        ]
        # Naming is stored in a plaintext microSD file, so the entry only
        # appears when we can actually persist (Persistent Settings + microSD).
        # Otherwise the instance stays labelled by its applet index ("Inst N").
        if _instance_rename_available(self.controller):
            button_data.append(self.RENAME)
        button_data += [
            self.INIT,
            self.FACTORY_RESET,
            self.LOCK,
        ]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("This instance · {}").format(active),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        chosen = button_data[selected]
        if chosen == self.GENERATE_KEY:
            return Destination(ToolsKeycardGenerateKeyView)
        if chosen == self.IMPORT_SEED:
            return Destination(ToolsKeycardImportSeedView)
        if chosen == self.CHANGE_PIN:
            return Destination(ToolsKeycardChangePinView)
        if chosen == self.RENAME:
            return Destination(ToolsKeycardThisInstanceRenameView)
        if chosen == self.INIT:
            return Destination(ToolsKeycardInitView)
        if chosen == self.FACTORY_RESET:
            return Destination(ToolsKeycardFactoryResetView)
        if chosen == self.LOCK:
            return Destination(ToolsKeycardLockView)
        return Destination(NotYetImplementedView)


def _instance_rename_available(controller=None) -> bool:
    """Whether the Rename-instance flow can run.

    Naming is stored in a plaintext microSD file (``instance_names``), so it
    needs Persistent Settings on **and** a microSD present. It works for every
    card — including v3.2+ ephemeral-paired ones — because the name does not
    live in the pairing blob.
    """
    from seedsigner.helpers.keycard import instance_names
    return instance_names.is_enabled()


class ToolsKeycardThisInstanceRenameView(View):
    """Set / change the active instance's name.

    The name is stored in a plaintext microSD file keyed by ``instance_uid``
    (see ``instance_names``), independent of the pairing blob — so it works
    for ephemeral-paired cards too and needs no pairing password. When set, it
    replaces the ``Inst N`` label everywhere the active instance is shown.
    """

    def run(self):
        from seedsigner.helpers.keycard import instance_names
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.reader import NoCardError, NoReaderError
        from seedsigner.helpers.keycard.ui_helpers import identify_inserted_card

        # Defensive gate (the menu already hides the entry when unavailable).
        if not _instance_rename_available(self.controller):
            return _error_destination(
                _("Not available"),
                _("Enable Persistent Settings\nand insert a microSD."),
            )

        active_aid = self.controller.active_keycard_aid

        # Resolve the active instance UID (prefer the session map; SELECT only
        # if we must).
        uid = self.controller.get_uid_for_aid(active_aid)
        if uid is None:
            try:
                _client, uid = identify_inserted_card(self)
            except (NoCardError, NoReaderError) as exc:
                return _no_card_toast_or_error(self, exc, default_title=_("Rename failed"))
            except APDUError as exc:
                if exc.sw == 0x6A82:
                    return _error_destination(
                        _("No instance"),
                        _("No Keycard applet\non this card."),
                    )
                logger.exception("Rename SELECT failed")
                title, body = classify_card_error(exc)
                return _error_destination(title, body)
            except Exception as exc:
                logger.exception("Rename SELECT failed")
                title, body = classify_card_error(exc)
                return _error_destination(title, body)
            self.controller.remember_aid_for_uid(active_aid, uid)

        name = _prompt_for_text(self, _("Instance name"), max_len=instance_names.NAME_MAX_LEN)
        if name is None:
            return Destination(BackStackView)

        try:
            instance_names.set_name(uid, name)
        except Exception:
            logger.exception("instance_names.set_name failed")
            return _error_destination(
                _("Save failed"),
                _("Could not write the\nname to the microSD."),
            )

        # Cache exactly what landed on disk (set_name normalises/clamps).
        stored = instance_names.get_name(uid)
        self.controller.set_instance_name_for(uid, stored)

        if not stored:
            # Whitespace-only input clears the name; just return quietly.
            return Destination(ToolsKeycardThisInstanceMenuView, skip_current_view=True)

        self.run_screen(
            LargeIconStatusScreen,
            title=_("Renamed"),
            status_headline=None,
            text=_("Now shown as {}.").format(stored),
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardThisInstanceMenuView, skip_current_view=True)


class ToolsKeycardLockView(View):
    """Drop all cached card PINs (and any Satochip session) so the next
    operation re-prompts for the PIN.

    The name is deliberately neutral ("Lock card"): it must NOT hint that
    re-authenticating with a *different* PIN can reach an on-card decoy
    (duress) wallet. To anyone watching, this just relocks the card.

    Reuses ``Controller.wipe_card_session_secrets()`` so locking is
    semantically identical to a card-removal wipe. NOT gated on
    ``SETTING__CACHE_SCARD_PIN`` — it must work even when PIN caching is
    enabled, otherwise the duress wallet stays unreachable for power
    users who keep caching on.
    """

    def run(self):
        self.controller.wipe_card_session_secrets()
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Card locked"),
            status_headline=None,
            text=_("PIN cleared.\nYou'll be asked for it next time."),
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView, clear_history=True)


class ToolsKeycardPairingMenuView(View):
    """Pairing ops for the active instance: pair a new slot, or remove
    a pairing. Both act on the active instance, so the title carries its
    label."""

    PAIR = ButtonOption("Pair card")
    REMOVE_PAIRING = ButtonOption("Remove pairing")

    def run(self):
        active = _instance_display_name(self.controller, self.controller.active_keycard_aid)
        button_data = [self.PAIR, self.REMOVE_PAIRING]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Pairing · {}").format(active),
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
        return Destination(NotYetImplementedView)


class ToolsKeycardCardMenuView(View):
    """Whole-card / package ops that are *not* tied to a single
    instance: read card status / storage, uninstall the Keycard package
    (removes every instance). No instance label in the title — these act
    on the card, not one instance.

    Initialising an instance moved to ``This instance ▸ Initialise
    instance`` (INIT provisions one instance, not the whole card).
    """

    STATUS = ButtonOption("Status")
    STORAGE = ButtonOption("Storage")
    UNINSTALL = ButtonOption("Uninstall applet")

    def run(self):
        button_data = [self.STATUS, self.STORAGE, self.UNINSTALL]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Manage Card"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        chosen = button_data[selected]
        if chosen == self.STATUS:
            return Destination(ToolsKeycardStatusView)
        if chosen == self.STORAGE:
            return Destination(ToolsKeycardStorageView)
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
            title=_("Uninstall"),
            status_headline=None,
            text=_("Delete the Keycard package?\nMaster key will be lost."),
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
            return _error_destination(_("Keycard support unavailable"), str(exc))

        try:
            release_other_smartcard_holders(self.controller)
            connection = wait_for_card(timeout_s=5.0)
        except Exception as exc:
            return _error_destination(_("Card not reachable"), str(exc))

        try:
            channel = gp.GpSecureChannel(connection)
            channel.select_isd()
            try:
                channel.open()
            except Exception as exc:
                return _error_destination(
                    _("ISD keys required"),
                    _("Default ISD keys missing.\nWipe via PC or full Factory Reset."),
                )
            # Package AID for Status Keycard.
            package_aid = bytes.fromhex("A0000008040001")
            try:
                gp.delete_aid(channel, package_aid, with_related=True)
            except Exception as exc:
                return _error_destination(_("Uninstall failed"), str(exc))
        finally:
            try:
                connection.disconnect()
            except Exception:
                pass

        # Cached pairings for this card are now stale; drop them.
        self.controller.forget_all_pairings()

        self.run_screen(
            LargeIconStatusScreen,
            title=_("Uninstall"),
            status_headline=None,
            text=_("Keycard package removed."),
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
            return _error_destination(_("Keycard support unavailable"), str(exc))

        try:
            release_other_smartcard_holders(self.controller)
            connection = wait_for_card(timeout_s=5.0)
            client = KeycardClient(connection)
            info = select_with_autodetect(client, self.controller)
        except Exception as exc:
            title, body = classify_card_error(exc)
            return _error_destination(title, body)

        version = f"{(info.app_version >> 8) & 0xFF}.{info.app_version & 0xFF}"
        text = _("Applet v{}\nPairing slots: {}\nKey on card: {}").format(
            version,
            info.free_pairing_slots,
            _("yes") if info.key_uid else _("no"),
        )
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Keycard"),
            status_headline=None,
            text=text,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(BackStackView)


class ToolsKeycardStorageView(View):
    """Card-memory overview with an occupation bar.

    Reads free NV memory via GlobalPlatform GET DATA 0xFF21 and estimates
    the used portion from the on-card footprint of the apps installed on the
    card. The card never reports its true capacity, so the bar's total is
    ``free + used``. Degrades to an "unavailable" message when the card
    doesn't expose the memory tag.
    """

    def run(self):
        from seedsigner.gui.screens.screen import KeycardStorageScreen
        from seedsigner.helpers.card_probe import probe_installed_applets
        from seedsigner.helpers.keycard.ui_helpers import query_card_memory
        from seedsigner.views.view import estimated_used_nv

        mem = query_card_memory(self)
        if mem is None:
            self.run_screen(
                LargeIconStatusScreen,
                title=_("Storage"),
                status_headline=None,
                text=_("Storage info not available\non this card."),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        try:
            probe = probe_installed_applets(self.controller)
        except Exception:
            probe = None
        used = estimated_used_nv(probe) if probe is not None else 0
        total = mem.free_nv + used

        self.run_screen(
            KeycardStorageScreen,
            title=_("Storage"),
            used_bytes=used,
            total_bytes=total,
            free_bytes=mem.free_nv,
        )
        return Destination(BackStackView)


# ---------------------------------------------------------------------------
# Factory reset (wipe card)
# ---------------------------------------------------------------------------


class ToolsKeycardFactoryResetView(View):
    """Factory-reset the **active instance**: PIN, PUK, pairings, key.

    ``INS_FACTORY_RESET`` (0xFD) resets the applet *instance* we SELECT
    (the active one) back to its post-install state — other instances on
    the card are not touched. On older applets the call returns
    `0x6D00` "instruction not supported"; we surface that with a
    pointer to keycard-shell as a fallback.

    On success we also drop the device's persisted pairing blob and
    in-memory cache **for just this instance** (looked up by the
    instance UID observed at SELECT), so other instances' saved
    pairings survive. If the UID can't be determined we fall back to a
    full clear, so a card we just blanked never keeps a stale pairing.
    """

    CONFIRM = ButtonOption("Wipe")

    def run(self):
        try:
            from seedsigner.helpers.keycard import pairing_storage
            from seedsigner.helpers.keycard.client import KeycardClient
            from seedsigner.helpers.keycard.commands import APDUError
            from seedsigner.helpers.keycard.reader import (
                release_other_smartcard_holders, wait_for_card,
            )
        except ImportError as exc:
            return _error_destination(_("Keycard support unavailable"), str(exc))

        label = _instance_display_name(self.controller, self.controller.active_keycard_aid)
        ret = self.run_screen(
            DireWarningScreen,
            title=_("Wipe {}?").format(label),
            status_headline=None,
            text=_("Erases the key & PIN on\nthis instance. Cannot undo."),
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
            # Capture the instance UID *before* the reset blanks it, so we
            # can drop only this instance's saved pairing afterwards.
            select_resp = client.select_response
            reset_uid = (
                bytes(select_resp.instance_uid)
                if select_resp and select_resp.instance_uid
                else None
            )
            client.factory_reset()
        except APDUError as exc:
            logger.warning("FACTORY_RESET unsupported: %s", exc)
            if (exc.sw & 0xFF00) == 0x6D00:
                return _error_destination(
                    _("Not supported"),
                    _("Update applet, or use\nkeycard-shell on PC."),
                )
            title, body = classify_card_error(exc, default_title=_("Reset failed"))
            return _error_destination(title, body)
        except Exception as exc:
            logger.exception("FACTORY_RESET failed")
            title, body = classify_card_error(exc, default_title=_("Reset failed"))
            return _error_destination(title, body)

        # Drop the device's local state for the now-blank instance. The
        # reset only wipes the active instance on-card, so we forget just
        # that instance's pairing — other instances are untouched. If the
        # UID is unknown, fall back to a full clear so a card we just
        # blanked never keeps a stale pairing.
        try:
            if reset_uid:
                pairing_storage.remove(instance_uid=reset_uid)
            else:
                pairing_storage.remove_all()
        except Exception:
            logger.exception("could not clear local pairing(s) after factory reset")
        # The instance is now blank; drop its persisted name too (the reset
        # regenerates the UID, so the new instance starts as "Inst N").
        if reset_uid:
            try:
                from seedsigner.helpers.keycard import instance_names
                instance_names.remove_name(reset_uid)
            except Exception:
                logger.exception("could not clear instance name after factory reset")
        if reset_uid:
            self.controller.forget_pairing_for(reset_uid)
        else:
            self.controller.forget_all_pairings()

        self.run_screen(
            LargeIconStatusScreen,
            title=_("{} wiped").format(label),
            status_headline=None,
            text=_("Run Init to reuse it."),
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

    INITIALISE = ButtonOption("Initialise card")
    SKIP_DURESS = ButtonOption("Skip")
    SET_DURESS = ButtonOption("Set duress PIN")

    def run(self):
        import hmac

        try:
            from seedsigner.helpers.card_probe import probe_card
            from seedsigner.helpers.keycard import secrets as kc_secrets
            from seedsigner.helpers.keycard.client import KeycardClient
            from seedsigner.helpers.keycard.crypto import derive_pairing_secret
            from seedsigner.helpers.keycard.reader import (
                release_other_smartcard_holders, wait_for_card,
            )
        except ImportError as exc:
            return _error_destination(_("Keycard support unavailable"), str(exc))

        # Bail out *before* asking for PIN/PUK if the inserted card is already
        # initialised — otherwise client.init() below would reject it with the
        # cryptic SW=0x6D00 only after the user has set and confirmed a PIN. The
        # probe is read-only and never prompts. Only block on a definitely
        # initialised Keycard; no card / non-Keycard / pre-init all fall through
        # to the normal flow (and the post-SELECT guard below is the backstop).
        probe = probe_card("keycard", self.controller)
        if probe.present and probe.kind_match and probe.initialised:
            return _error_destination(
                _("Already initialised"),
                _("Use Factory reset to\nwipe and re-init."),
            )

        pin_buf: Optional[bytearray] = None
        confirm_buf: Optional[bytearray] = None
        duress_buf: Optional[bytearray] = None
        duress_confirm_buf: Optional[bytearray] = None
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
                    title=_("PINs differ"),
                    status_headline=None,
                    text=_("Try again."),
                    show_back_button=True,
                    button_data=[ButtonOption("Retry")],
                )

            puk = kc_secrets.generate_puk()

            # Optional duress (alt) PIN — provisioned here at INIT (there is
            # no add-it-from-a-main-PIN-session route). Entering it later
            # unlocks a decoy wallet derived from the SAME seed via an
            # alternate chain code, routed transparently on-card. It MUST
            # differ from the main PIN: an equal alt PIN makes verifyPIN match
            # both and route to the decoy, shadowing the real wallet until the
            # two PINs are made distinct again (recoverable, but a footgun).
            duress_button_data = [self.SKIP_DURESS, self.SET_DURESS]
            duress_choice = self.run_screen(
                LargeIconStatusScreen,
                title=_("Duress PIN"),
                status_icon_size=0,
                status_headline=None,
                text=(
                    "A 2nd PIN that unlocks a decoy wallet instead of your "
                    "real one. Settable only now, never later."
                ),
                button_data=duress_button_data,
            )
            if duress_choice == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            if duress_button_data[duress_choice] == self.SET_DURESS:
                # Entry+confirm loop mirroring the main PIN loop above. The
                # only exits are: a valid duress PIN that differs from the
                # main PIN, or the user backing out of a PIN screen (which
                # skips duress and proceeds with a normal init — the main PIN
                # is already committed).
                while True:
                    duress_buf = prompt_for_pin(self, "Set duress PIN")
                    if duress_buf is None:
                        break
                    duress_confirm_buf = prompt_for_pin(self, "Confirm duress PIN")
                    if duress_confirm_buf is None:
                        wipe_bytearray(duress_buf)
                        duress_buf = None
                        break
                    if not hmac.compare_digest(
                        bytes(duress_buf), bytes(duress_confirm_buf)
                    ):
                        wipe_bytearray(duress_buf)
                        wipe_bytearray(duress_confirm_buf)
                        duress_buf = None
                        duress_confirm_buf = None
                        self.run_screen(
                            WarningScreen,
                            title=_("Duress PINs differ"),
                            status_headline=None,
                            text=_("Try again."),
                            show_back_button=True,
                            button_data=[ButtonOption("Retry")],
                        )
                        continue
                    wipe_bytearray(duress_confirm_buf)
                    duress_confirm_buf = None
                    if hmac.compare_digest(bytes(pin_buf), bytes(duress_buf)):
                        wipe_bytearray(duress_buf)
                        duress_buf = None
                        self.run_screen(
                            WarningScreen,
                            title=_("Must differ"),
                            status_headline=None,
                            text=_("Duress PIN can't equal\nyour main PIN."),
                            show_back_button=True,
                            button_data=[ButtonOption("Retry")],
                        )
                        continue
                    break

            # keycard-shell parity: if no duress PIN was chosen, still set an
            # explicit *random* one (CSPRNG, guaranteed != main) instead of
            # letting the applet fall back to its predictable PUK[:6] default
            # decoy. The value is never shown — the card simply has no usable
            # decoy unless the owner deliberately picked one above.
            if duress_buf is None:
                while True:
                    random_duress = kc_secrets.generate_pin()
                    duress_buf = bytearray(random_duress.encode("ascii"))
                    try:
                        wipe_string(random_duress)
                    except Exception:
                        pass
                    if not hmac.compare_digest(bytes(pin_buf), bytes(duress_buf)):
                        break
                    wipe_bytearray(duress_buf)
                    duress_buf = None

            ret = self.run_screen(
                WarningScreen,
                title=_("Write this down"),
                status_headline=None,
                # TRANSLATOR_NOTE: {} is the card's PUK code (12 digits)
                text=_("PUK  {}").format(puk),
                show_back_button=True,
                button_data=[self.INITIALISE],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            try:
                release_other_smartcard_holders(self.controller)
                connection = wait_for_card(timeout_s=5.0)
                client = KeycardClient(connection)
                info = select_with_autodetect(client, self.controller)
                # Authoritative backstop: catches the race where no card was
                # present at the early probe but an already-initialised card is
                # inserted before INIT. app_version != 0 means initialised.
                if info.app_version != 0:
                    return _error_destination(
                        _("Already initialised"),
                        _("Use Factory reset to\nwipe and re-init."),
                    )
                secret = derive_pairing_secret(DEFAULT_PAIRING_PASSWORD)
                # Honour the user-configurable PIN-attempt limit (Settings >
                # Smartcard PIN Attempts, 2..10). The wizard always sets a
                # duress PIN above, so INIT uses the 58-byte form that carries
                # maxPINAttempts on-card — the setting reliably takes effect.
                from seedsigner.models.settings import Settings
                max_pin_attempts = Settings.get_instance().get_value(
                    SettingsConstants.SETTING__SCARD_PIN_ATTEMPTS
                )
                client.init(
                    bytes(pin_buf), puk.encode("ascii"), secret,
                    duress_pin=(bytes(duress_buf) if duress_buf is not None else None),
                    max_pin_attempts=max_pin_attempts,
                )
            except Exception as exc:
                logger.exception("Keycard INIT failed")
                title, body = classify_card_error(exc, default_title=_("INIT failed"))
                return _error_destination(title, body)

            self.run_screen(
                LargeIconStatusScreen,
                title=_("Initialised"),
                status_headline=None,
                text=_("PIN/PUK set.\nNow load a seed."),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            # Chain into the setup chooser (Generate vs Import). The
            # individual Setup-menu entries still work as standalone, so
            # users who back out can re-run either step from the menu.
            return Destination(
                ToolsKeycardSetupChooseSeedView, skip_current_view=True,
            )
        finally:
            if pin_buf is not None:
                wipe_bytearray(pin_buf)
            if confirm_buf is not None:
                wipe_bytearray(confirm_buf)
            if duress_buf is not None:
                wipe_bytearray(duress_buf)
            if duress_confirm_buf is not None:
                wipe_bytearray(duress_confirm_buf)


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
                client, _unused = _open_unlocked_session_cached_or_prompt(
                    self, pin_title=_("Current PIN"), require_key=False,
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
                    exc, default_title=_("Change PIN failed"),
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
                    _("Mismatch"), _("New PINs do not\nmatch. Retry."),
                )

            try:
                client.change_pin(bytes(new_pin))
            except Exception as exc:
                logger.exception("Keycard CHANGE PIN failed")
                title, body = classify_card_error(
                    exc, default_title=_("Change PIN failed"),
                )
                return _error_destination(title, body)

            if instance_uid:
                self.controller.forget_pin_for(instance_uid)

            self.run_screen(
                LargeIconStatusScreen,
                title=_("PIN changed"),
                status_headline=None,
                text=_("New PIN active.\nUse it on next op."),
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
) -> Tuple[Optional[object], Optional[str]]:
    """Attempt to pair using a raw 32-byte pairing secret (no PBKDF2).

    Returns ``(pairing, source)`` where ``source`` is ``"disk"`` or
    ``"pair"`` on success; ``(None, None)`` on cryptogram mismatch.
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
            return stored.pairing, "disk"

        try:
            pairing = client.pair(psk)
        except SecureChannelError as exc:
            if "cryptogram" in str(exc).lower():
                return None, None  # PSK does not match — fall through
            raise
        try:
            pairing_storage.save(storage_pwd, pairing, instance_uid)
        except Exception:
            logger.exception("could not persist pairing")
        return pairing, "pair"
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
) -> Tuple[Optional[object], Optional[str]]:
    """Attempt to obtain a PairingInfo for ``instance_uid`` using ``pwd``.

    Returns ``(pairing, source)`` where ``source`` is ``"disk"`` or
    ``"pair"`` on success; ``(None, None)`` on cryptogram mismatch.
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
            return stored.pairing, "disk"

        try:
            secret = derive_pairing_secret(normalised)
            pairing = client.pair(secret)
        except SecureChannelError as exc:
            if "cryptogram" in str(exc).lower():
                return None, None  # wrong password — caller falls through
            raise
        try:
            pairing_storage.save(normalised, pairing, instance_uid)
        except Exception:
            logger.exception("could not persist pairing")
            # Non-fatal: keep the in-memory pairing.
        return pairing, "pair"
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
            return _error_destination(_("Keycard support unavailable"), str(exc))

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
                _("Not initialised"),
                _("Initialise this\ninstance first."),
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
                title=_("Already paired"),
                status_headline=None,
                # TRANSLATOR_NOTE: {} is the number of free pairing slots on the card
                text=ngettext(
                    "Paired this session.\n{} slot free on card.",
                    "Paired this session.\n{} slots free on card.",
                    free_slots,
                ).format(free_slots),
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
                _("No free slots"),
                _("Card is full. Unpair on a\npaired device, or reset."),
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
        used_default = False
        pairing = None
        source = None
        try:
            pairing, source = _try_pair_with_password(
                client, pairing_storage, derive_pairing_secret,
                SecureChannelError,
                DEFAULT_PAIRING_PASSWORD, instance_uid,
            )
            if pairing is None:
                pairing, source = _try_pair_with_raw_psk(
                    client, pairing_storage, SecureChannelError,
                    KEYCARD_SHELL_DEFAULT_PSK, instance_uid,
                )
        except Exception as exc:
            logger.exception("Keycard PAIR (default secrets) failed")
            title, body = classify_card_error(exc, default_title=_("PAIR failed"))
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
                return _error_destination(_("Bad password"), str(exc))
            try:
                pairing, source = _try_pair_with_password(
                    client, pairing_storage, derive_pairing_secret,
                    SecureChannelError,
                    custom, instance_uid,
                )
            except Exception as exc:
                _wipe_bytearray(password_buf)
                logger.exception("Keycard PAIR (custom pwd) failed")
                title, body = classify_card_error(exc, default_title=_("PAIR failed"))
                return _error_destination(title, body)
            finally:
                try:
                    wipe_string(custom)
                except Exception:
                    pass
            _wipe_bytearray(password_buf)
            if pairing is None:
                return _error_destination(
                    _("Wrong password"),
                    _("Pairing password did\nnot match this card."),
                )

        self.controller.set_pairing_for(instance_uid, pairing)

        if source == "disk":
            detail = _("loaded from disk")
        else:
            # PAIR consumed a slot, so the cached count is 1 stale.
            free_slots = max(0, free_slots - 1)
            detail = _("saved for next boot")
        pwd_label = _("default password") if used_default else _("custom password")
        # TRANSLATOR_NOTE: {} are slot index, free-slot count, password kind, detail line
        text = _("Slot {} ({} free)\n{}\n{}").format(
            pairing.pairing_index, free_slots, pwd_label, detail
        )
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Paired"),
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
        # No status screen: silent return so the user is dropped back where
        # they came from instead of bouncing through an "OK" confirmation.
        if self.controller.get_ephemeral_secret_for(instance_uid) is not None:
            return Destination(BackStackView)

        secret_used: Optional[bytes] = None
        try:
            # 1. PBKDF2 from the well-known default password.
            default_secret = derive_pairing_secret(DEFAULT_PAIRING_PASSWORD)
            try:
                if _try_ephemeral_pair_with_secret(
                    client, SecureChannelError, default_secret,
                ) is not None:
                    secret_used = default_secret
            except Exception as exc:
                logger.exception("ephemeral PAIR (default pwd) failed")
                title, body = classify_card_error(
                    exc, default_title=_("PAIR failed"),
                )
                return _error_destination(title, body)

            # 2. keycard-shell raw PSK (no PBKDF2).
            if secret_used is None:
                try:
                    if _try_ephemeral_pair_with_secret(
                        client, SecureChannelError, raw_psk,
                    ) is not None:
                        secret_used = raw_psk
                except Exception as exc:
                    logger.exception("ephemeral PAIR (shell PSK) failed")
                    title, body = classify_card_error(
                        exc, default_title=_("PAIR failed"),
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
                return _error_destination(_("Bad password"), str(exc))
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
                        exc, default_title=_("PAIR failed"),
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
                        _("Wrong password"),
                        _("Pairing password did\nnot match this card."),
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

        # No "Paired" status screen: v3.2 ephemeral pairing is a transparent
        # session-bootstrap step, not a user-facing action. Silently return
        # so the user lands back in whichever flow triggered the pairing.
        return Destination(BackStackView)


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
            label = (_("Card legacy") if entry.is_legacy
                     else _("Card {}…{}").format(entry.fingerprint[:4], entry.fingerprint[-4:]))
            button_data.append(ButtonOption(label))

        title = (_("Remove pairing") if instance_uid is not None
                 else _("Remove ({} saved)").format(len(entries)))
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
            confirm_text = _("Forgets ephemeral\npairing for this boot.")
        else:
            confirm_text = _("Frees the card slot\nand deletes local copy.")
        ret = self.run_screen(
            WarningScreen,
            title=_("Unpair card?"),
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
                title=_("UNPAIR failed"),
                status_headline=None,
                text=_("Card slot stays in use.\nRemove local only?"),
                show_back_button=True,
                button_data=[ButtonOption("Remove local")],
            )
            if confirm == RET_CODE__BACK_BUTTON:
                title, body = classify_card_error(
                    unpair_failed_exc, default_title=_("UNPAIR failed"),
                )
                return _error_destination(title, body)
            self._drop_local_for_uid(instance_uid)
            self._show_done(_("Removed local"),
                            "Slot still in use\non the card.")
            return Destination(ToolsKeycardMenuView, skip_current_view=True)

        self._drop_local_for_uid(instance_uid)
        self._show_done(_("Unpaired"), _("Slot freed; local removed."))
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
            title=_("Remove all?"),
            status_headline=None,
            text=_("Local only. Slots stay\nused on the cards."),
            show_back_button=True,
            button_data=[ButtonOption("Remove all")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        count = pairing_storage.remove_all()
        self.controller.forget_all_pairings()
        # TRANSLATOR_NOTE: {} is the number of removed saved pairings
        self._show_done(
            _("Removed"),
            ngettext("Removed {} pairing.", "Removed {} pairings.", count).format(count),
        )
        return Destination(ToolsKeycardMenuView, skip_current_view=True)

    def _remove_local_entry(self, entry) -> Destination:
        from seedsigner.helpers.keycard import pairing_storage

        ret = self.run_screen(
            WarningScreen,
            title=_("Remove?"),
            status_headline=None,
            text=_("Local only.\n{}").format(entry.path.name[:24]),
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
            _("Removed") if removed else _("Not found"),
            _("Saved pairing removed.") if removed else _("Already gone."),
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
    """Entry-point for the on-card key generation flow.

    Card supplies the entropy via ``GENERATE_MNEMONIC`` (INS=0xD2); the
    host shows the mnemonic to the user ONCE for backup, optionally runs
    a word-by-word quiz, derives the 64-byte BIP-39 seed and pushes it
    back to the card via ``LOAD_KEY``. After the load the seed cannot be
    extracted from the card — same trust model as keycard-shell.
    """

    CONFIRM = ButtonOption("Continue")

    def run(self):
        ret = self.run_screen(
            DireWarningScreen,
            title=_("Generate seed?"),
            status_headline=None,
            text=_("Card generates a new\nseed and loads it on-card."),
            show_back_button=True,
            button_data=[self.CONFIRM],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(
            ToolsKeycardGenerateMnemonicLengthView, skip_current_view=True,
        )


# ---------------------------------------------------------------------------
# Import seedphrase to card (LOAD_KEY P1=BIP39_SEED)
# ---------------------------------------------------------------------------


class ToolsKeycardImportSeedView(View):
    """Push a BIP-39 seedphrase onto the card via LOAD_KEY P1=0x03.

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
    HEX = ButtonOption("Import hex (NGRAVE)")
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
            title=_("Import to card?"),
            status_headline=None,
            text=_("Seed leaves device once,\nencrypted to card."),
            show_back_button=True,
            button_data=[ButtonOption("Continue")],
        )
        if warn_ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # 2. Pick the input method.
        button_data = [self.SCAN, self.TYPE_12, self.TYPE_24, self.HEX]
        choice_ret = self.run_screen(
            ButtonListScreen,
            title=_("Source"),
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
            elif choice == self.HEX:
                phrase = self._capture_via_hex()
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
                return _error_destination(_("Invalid seed"),
                                          "Checksum failed.")

            # 5. Optional passphrase.
            pp_choice_data = [self.SKIP_PASSPHRASE, self.SET_PASSPHRASE]
            pp_choice = self.run_screen(
                ButtonListScreen,
                title=_("Passphrase?"),
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
                    return _error_destination(_("Bad passphrase"), str(exc))

            # 6. Compute seed + master fingerprint for confirmation.
            try:
                derived = bip39.mnemonic_to_seed(mnemonic, password=passphrase)
                seed64[:] = derived
                root = bip32.HDKey.from_seed(bytes(seed64))
                fingerprint = root.my_fingerprint.hex()
            except Exception as exc:
                logger.exception("seed derivation failed")
                return _error_destination(_("Derive failed"), str(exc))

            # 7. Confirmation screen showing master fingerprint.
            confirm_ret = self.run_screen(
                WarningScreen,
                title=_("Push?"),
                status_headline=None,
                text=_("Master fp:\n{}\nVerify before push.").format(fingerprint),
                show_back_button=True,
                button_data=[self.CONFIRM],
            )
            if confirm_ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            # 8. Push (PIN handled by the wrapper — cached or prompted).
            try:
                client, _unused = _open_unlocked_session_cached_or_prompt(
                    self, require_key=False,
                )
                client.load_bip39_seed(bytes(seed64))
            except KeycardPinPromptCancelled:
                return Destination(BackStackView)
            except KeycardCardChangedError:
                return Destination(ToolsKeycardPairView)
            except Exception as exc:
                logger.exception("LOAD_KEY failed")
                title, body = classify_card_error(exc, default_title=_("Push failed"))
                return _error_destination(title, body)

            # The on-card master key just changed — any cached View-wallets
            # addresses for this AID were derived from the old key.
            _invalidate_wallets_cache_for_active_aid(self.controller)

            self.run_screen(
                LargeIconStatusScreen,
                title=_("Wallet imported"),
                status_headline=None,
                text=_("Master fp:\n{}").format(fingerprint),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            # Hand the mnemonic + passphrase to the Seedkeeper-offer
            # chain via the controller. Use fresh string allocations so
            # the local-buffer wipe in the ``finally`` below cannot reach
            # the controller's copy.
            self.controller.pending_keycard_mnemonic = [
                "".join(w) for w in words
            ]
            self.controller.pending_keycard_passphrase = bytearray(
                bytes(passphrase_buf),
            )
            return Destination(
                ToolsKeycardSeedkeeperOfferView, skip_current_view=True,
            )
        finally:
            # Best-effort wipe of every intermediate secret. The
            # controller's copies (if we got that far) are untouched by
            # these wipes since they're independent allocations.
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
            instructions_text=_("Scan SeedQR"),
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
        from embit import bip39

        wordlist = bip39.WORDLIST
        words: list = []
        for i in range(num_words):
            ret = self.run_screen(
                seed_screens.SeedMnemonicEntryScreen,
                title=_("Word #{}").format(i + 1),
                initial_letters=["a"],
                wordlist=wordlist,
            )
            if ret == RET_CODE__BACK_BUTTON:
                return None
            if not isinstance(ret, str) or not ret:
                return None
            words.append(ret)
        return words

    def _capture_via_hex(self) -> Optional[list]:
        """Capture an NGRAVE "Perfect Key" (or raw BIP-39 entropy) in hex.

        The NGRAVE hex *is* the BIP-39 entropy: 64 hex chars (256-bit) maps
        to the 24-word mnemonic, exactly the ``Entropy`` field in the Ian
        Coleman tool. 32 hex chars (128-bit → 12 words) is also accepted.

        Returns the BIP-39 word list (fresh string copies, never references
        into the shared WORDLIST), or ``None`` on back-out / invalid input.
        The intermediate entropy buffer is wiped before returning.
        """
        from seedsigner.gui.screens.screen import KeycardHexEntryScreen
        from embit import bip39

        SCAN_HEX = ButtonOption("Scan QR")
        TYPE_HEX = ButtonOption("Type hex")
        method_data = [SCAN_HEX, TYPE_HEX]
        method = self.run_screen(
            ButtonListScreen,
            title=_("Hex source"),
            is_button_text_centered=False,
            button_data=method_data,
            show_back_button=True,
        )
        if method == RET_CODE__BACK_BUTTON:
            return None

        if method_data[method] == SCAN_HEX:
            raw = self._scan_hex_text()
        else:
            ret = KeycardHexEntryScreen(title=_("Enter hex")).display()
            raw = ret if isinstance(ret, str) else None
        if not raw:
            return None

        # Normalise: strip whitespace / optional 0x, lower-case.
        cleaned = "".join(raw.split()).lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        if len(cleaned) not in (32, 64) or any(
            c not in "0123456789abcdef" for c in cleaned
        ):
            self.run_screen(
                WarningScreen,
                title=_("Invalid hex"),
                status_headline=None,
                text=_("Need 32 or 64 hex\nchars (12 or 24 words)."),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return None

        entropy = bytearray.fromhex(cleaned)
        try:
            mnemonic = bip39.mnemonic_from_bytes(bytes(entropy))
        finally:
            _wipe_bytearray(entropy)
        # Fresh copies so the caller's wipe never touches the WORDLIST.
        return ["".join(w) for w in mnemonic.split()]

    def _scan_hex_text(self) -> Optional[str]:
        """Scan a plain-text QR and return its raw payload (the hex string)."""
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.models.decode_qr import DecodeQR

        decoder = DecodeQR(is_text=True)
        self.run_screen(
            ScanScreen,
            instructions_text=_("Scan hex QR"),
            decoder=decoder,
        )
        time.sleep(0.1)
        if not decoder.is_complete:
            return None
        return decoder.get_text()


# ---------------------------------------------------------------------------
# Setup chain: Init → (Generate | Import) → Backup → LOAD_KEY → Seedkeeper?
# ---------------------------------------------------------------------------


def _wipe_pending_setup_state(controller) -> None:
    """Wipe transient mnemonic / passphrase held during the Setup chain.

    Safe to call repeatedly; idempotent. Each terminal step in the chain
    (success, error, skip, back-out) calls this so a yanked card or a
    crash during the next user input cannot leak the mnemonic.
    """
    from seedsigner.helpers.secure_delete import wipe_list

    if controller.pending_keycard_mnemonic is not None:
        try:
            wipe_list(controller.pending_keycard_mnemonic)
        except Exception:
            pass
        controller.pending_keycard_mnemonic = None
    if controller.pending_keycard_passphrase is not None:
        try:
            wipe_bytearray(controller.pending_keycard_passphrase)
        except Exception:
            pass
        controller.pending_keycard_passphrase = None


def _backup_error_retry(view, title: str, body: str) -> Destination:
    """Backup wizard error → Retry / Cancel, WITHOUT losing the seed.

    Card creation is the only window in which the host holds the seed, so
    a transient backup failure (save error, capacity, probe failure, card
    removed) must NOT drop ``pending_keycard_mnemonic`` — otherwise the
    user can never back it up. Retry returns to the destination chooser
    (re-pick This / Another / Both); only an explicit Cancel (back button)
    wipes and exits to the Keycard menu. The ``MainMenuView`` re-entry
    backstop still wipes if the user navigates Home.

    Security tradeoff: the seed (already sealed in the Keycard via
    LOAD_KEY) persists in host memory across retries within this wizard.
    Bounded to the wizard session; wiped on success, Cancel, and Home.
    """
    ret = view.run_screen(
        WarningScreen,
        title=title,
        status_headline=None,
        text=body[:120],
        show_back_button=True,  # back == Cancel
        button_data=[ButtonOption("Retry")],
    )
    if ret == RET_CODE__BACK_BUTTON:
        _wipe_pending_setup_state(view.controller)
        return Destination(ToolsKeycardMenuView, clear_history=True)
    return Destination(ToolsKeycardSeedkeeperDestChooserView)


class ToolsKeycardSetupChooseSeedView(View):
    """Post-Init chooser: Generate a new seed on card, or Import one.

    Reached from ``ToolsKeycardInitView`` on a freshly-initialised card.
    Backing out lands on the Card menu (via BackStack) — the user can
    still re-run either path later from ``This instance`` (Generate key
    / Import seed).
    """

    GENERATE = ButtonOption("Generate new seed")
    IMPORT = ButtonOption("Import existing seed")

    def run(self):
        button_data = [self.GENERATE, self.IMPORT]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Load seed"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        chosen = button_data[selected]
        if chosen == self.GENERATE:
            return Destination(ToolsKeycardGenerateKeyView)
        if chosen == self.IMPORT:
            return Destination(ToolsKeycardImportSeedView)
        return Destination(NotYetImplementedView)


class ToolsKeycardGenerateMnemonicLengthView(View):
    """Pick mnemonic length for ``GENERATE MNEMONIC``."""

    WORDS_12 = ButtonOption("12 words")
    WORDS_24 = ButtonOption("24 words")

    def run(self):
        button_data = [self.WORDS_12, self.WORDS_24]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Mnemonic length"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        word_count = 12 if button_data[selected] == self.WORDS_12 else 24
        return Destination(
            ToolsKeycardGenerateMnemonicRunView,
            view_args={"word_count": word_count},
        )


class ToolsKeycardGenerateMnemonicRunView(View):
    """Call GENERATE MNEMONIC on the card and stash the result.

    On success, ``controller.pending_keycard_mnemonic`` holds the
    fresh mnemonic (each word is ``"".join(WORDLIST[i])`` so wiping the
    list does NOT corrupt the global BIP-39 wordlist).
    """

    def __init__(self, word_count: int):
        super().__init__()
        self.word_count = word_count

    def run(self):
        from seedsigner.helpers.keycard import (
            KeycardCardChangedError, KeycardPinPromptCancelled,
        )

        # Make sure no leftovers from a previous attempt linger.
        _wipe_pending_setup_state(self.controller)

        try:
            client, _unused = _open_unlocked_session_cached_or_prompt(
                self, require_key=False,
            )
            indices = client.generate_mnemonic(self.word_count)
        except KeycardPinPromptCancelled:
            return Destination(BackStackView)
        except KeycardCardChangedError:
            return Destination(ToolsKeycardPairView)
        except Exception as exc:
            logger.exception("GENERATE_MNEMONIC failed")
            title, body = classify_card_error(
                exc, default_title=_("Generate failed"),
            )
            return _error_destination(title, body)

        from embit import bip39
        wordlist = bip39.WORDLIST
        # Fresh per-word allocations so a later wipe never targets the
        # shared wordlist (CLAUDE.md "Secure wipe and shared wordlist
        # safety").
        words: list = []
        for idx in indices:
            if idx < 0 or idx >= len(wordlist):
                return _error_destination(
                    _("Bad mnemonic"), _("Index {} out of range").format(idx),
                )
            words.append("".join(wordlist[idx]))

        self.controller.pending_keycard_mnemonic = words
        return Destination(
            ToolsKeycardGenerateSeedWordsView,
            view_args={"page_index": 0},
            skip_current_view=True,
        )


class ToolsKeycardGenerateSeedWordsView(View):
    """Paginated display of the just-generated mnemonic (4 words/page).

    Reuses the ``SeedWordsScreen`` layout but reads from
    ``controller.pending_keycard_mnemonic`` so the words never travel
    through ``SeedStorage`` (which is Bitcoin-side and not appropriate
    for a card-bound seed).
    """

    NEXT = ButtonOption("Next")
    DONE = ButtonOption("Done")

    def __init__(self, page_index: int = 0):
        super().__init__()
        self.page_index = page_index

    def run(self):
        from seedsigner.gui.screens import seed_screens

        mnemonic = self.controller.pending_keycard_mnemonic or []
        if not mnemonic:
            # State got cleared (e.g. via MainMenuView re-entry); bail.
            return Destination(BackStackView)
        words_per_page = 4
        num_pages = max(1, len(mnemonic) // words_per_page)
        words = mnemonic[
            self.page_index * words_per_page :
            (self.page_index + 1) * words_per_page
        ]
        is_last_page = self.page_index >= num_pages - 1
        button_data = [self.DONE if is_last_page else self.NEXT]

        selected = seed_screens.SeedWordsScreen(
            title=_("Seed Words: {}/{}").format(self.page_index + 1, num_pages),
            words=words,
            page_index=self.page_index,
            num_pages=num_pages,
            button_data=button_data,
        ).display()

        if selected == RET_CODE__BACK_BUTTON:
            if self.page_index == 0:
                # First page back = abort; wipe and unwind.
                _wipe_pending_setup_state(self.controller)
                return Destination(BackStackView)
            return Destination(
                ToolsKeycardGenerateSeedWordsView,
                view_args={"page_index": self.page_index - 1},
                skip_current_view=True,
            )

        if button_data[selected] == self.NEXT:
            return Destination(
                ToolsKeycardGenerateSeedWordsView,
                view_args={"page_index": self.page_index + 1},
                skip_current_view=True,
            )
        # DONE → backup-test prompt
        return Destination(ToolsKeycardGenerateSeedBackupPromptView)


class ToolsKeycardGenerateSeedBackupPromptView(View):
    """Ask whether to verify the backup word-by-word, or skip.

    Skip does NOT re-show the mnemonic — the user has had their one
    look at the previous step. Backing out of this screen returns to
    the last page of the mnemonic display.
    """

    VERIFY = ButtonOption("Verify words")
    SKIP = ButtonOption("Skip")

    def run(self):
        from seedsigner.gui.screens import seed_screens

        # Use the existing prompt screen so the look matches Bitcoin
        # flows. It accepts a custom button_data list.
        selected = seed_screens.SeedWordsBackupTestPromptScreen(
            button_data=[self.VERIFY, self.SKIP],
        ).display()

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        button = (self.VERIFY, self.SKIP)[selected]
        if button == self.VERIFY:
            return Destination(ToolsKeycardGenerateSeedBackupQuizView)
        # SKIP → straight to passphrase prompt
        return Destination(
            ToolsKeycardGenerateSeedPassphrasePromptView,
        )


class ToolsKeycardGenerateSeedBackupQuizView(View):
    """Word-by-word verification quiz for the freshly-generated mnemonic.

    Pulls the mnemonic from ``controller.pending_keycard_mnemonic`` —
    NOT from ``SeedStorage`` — so the quiz never round-trips through a
    Bitcoin-side ``Seed`` object.
    """

    def __init__(self,
                 confirmed_list: Optional[List[int]] = None,
                 cur_index: Optional[int] = None,
                 rand_seed: Optional[int] = None):
        super().__init__()
        self.confirmed_list = confirmed_list or []
        self.cur_index = cur_index
        self.rand_seed = rand_seed

    def run(self):
        import random
        from embit import bip39

        mnemonic = self.controller.pending_keycard_mnemonic or []
        if not mnemonic:
            return Destination(BackStackView)

        if self.rand_seed is not None:
            random.seed(
                self.rand_seed + (self.cur_index or 0),
            )
        if self.cur_index is None:
            self.cur_index = int(random.random() * len(mnemonic))
            while self.cur_index in self.confirmed_list:
                self.cur_index = int(random.random() * len(mnemonic))

        real = ButtonOption(mnemonic[self.cur_index])
        # `"".join(...)` keeps wipes off the shared global wordlist. The word
        # is built in a local first so the string extractor never sees a
        # literal first arg to ButtonOption (a random BIP-39 word is not UI
        # copy, and `ButtonOption("".join(...))` would mark an empty msgid).
        fake_options = []
        for _attempt in range(3):
            fake_word = "".join(bip39.WORDLIST[int(random.random() * 2047)])
            fake_options.append(ButtonOption(fake_word))
        button_data = [real] + fake_options
        random.shuffle(button_data)

        selected = self.run_screen(
            ButtonListScreen,
            title=_("Verify Word #{}").format(self.cur_index + 1),
            show_back_button=False,
            button_data=button_data,
            is_bottom_list=True,
            is_button_text_centered=True,
        )

        if button_data[selected] == real:
            self.confirmed_list.append(self.cur_index)
            if len(self.confirmed_list) == len(mnemonic):
                return Destination(
                    ToolsKeycardGenerateSeedPassphrasePromptView,
                )
            return Destination(
                ToolsKeycardGenerateSeedBackupQuizView,
                view_args={"confirmed_list": self.confirmed_list},
            )
        # Wrong word
        return Destination(
            ToolsKeycardGenerateSeedBackupMistakeView,
            view_args={
                "cur_index": self.cur_index,
                "wrong_word": button_data[selected].button_label,
                "confirmed_list": self.confirmed_list,
            },
        )


class ToolsKeycardGenerateSeedBackupMistakeView(View):
    """Shown when the user picks the wrong word in the quiz."""

    REVIEW = ButtonOption("Review words")
    RETRY = ButtonOption("Try Again")

    def __init__(self, cur_index: int, wrong_word: str,
                 confirmed_list: Optional[List[int]] = None):
        super().__init__()
        self.cur_index = cur_index
        self.wrong_word = wrong_word
        self.confirmed_list = confirmed_list or []

    def run(self):
        text = f'Word #{self.cur_index + 1} is not "{self.wrong_word}".'
        selected = self.run_screen(
            DireWarningScreen,
            title=_("Verification error"),
            show_back_button=False,
            status_headline=_("Wrong word!"),
            button_data=[self.REVIEW, self.RETRY],
            text=text,
        )
        if (self.REVIEW, self.RETRY)[selected] == self.REVIEW:
            return Destination(
                ToolsKeycardGenerateSeedWordsView,
                view_args={"page_index": 0},
                skip_current_view=True,
            )
        return Destination(
            ToolsKeycardGenerateSeedBackupQuizView,
            view_args={
                "confirmed_list": self.confirmed_list,
                "cur_index": self.cur_index,
            },
        )


class ToolsKeycardGenerateSeedPassphrasePromptView(View):
    """Ask whether to add a BIP-39 passphrase to the generated mnemonic.

    Mirrors the Import flow's optional-passphrase step. The passphrase
    (if any) is stashed on ``controller.pending_keycard_passphrase`` as
    a bytearray so wipes are reliable.
    """

    SKIP = ButtonOption("No passphrase")
    SET = ButtonOption("Set passphrase")

    def run(self):
        button_data = [self.SKIP, self.SET]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Passphrase?"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        chosen = button_data[selected]
        if chosen == self.SKIP:
            # explicit empty -> store empty bytearray so later steps
            # don't have to special-case None.
            self.controller.pending_keycard_passphrase = bytearray()
            return Destination(
                ToolsKeycardGenerateSeedLoadView, skip_current_view=True,
            )
        # SET → on-screen keyboard
        got = _prompt_for_text(self, "Passphrase", max_len=80)
        if got is None:
            return Destination(BackStackView)
        buf = bytearray()
        try:
            buf.extend(got.encode("utf-8"))
        finally:
            try:
                wipe_string(got)
            except Exception:
                pass
        self.controller.pending_keycard_passphrase = buf
        return Destination(
            ToolsKeycardGenerateSeedLoadView, skip_current_view=True,
        )


class ToolsKeycardGenerateSeedLoadView(View):
    """Derive 64-byte BIP-39 seed and push it to the card via LOAD_KEY.

    On success, hands the mnemonic over to
    ``ToolsKeycardSeedkeeperOfferView`` which decides whether to prompt
    for a backup save (only if a Seedkeeper applet is detected on the
    same card). Wipes the local 64-byte seed and any intermediate
    buffers on every exit path; the mnemonic/passphrase live on the
    controller until the Seedkeeper-offer chain wipes them.
    """

    def run(self):
        from seedsigner.helpers.keycard import (
            KeycardCardChangedError, KeycardPinPromptCancelled,
        )

        mnemonic = self.controller.pending_keycard_mnemonic
        passphrase_buf = self.controller.pending_keycard_passphrase
        if not mnemonic or passphrase_buf is None:
            return Destination(BackStackView)

        seed64 = bytearray(64)
        try:
            from embit import bip39, bip32
            mnemonic_str = " ".join(mnemonic)
            try:
                passphrase_str = passphrase_buf.decode("utf-8")
            except Exception as exc:
                _wipe_pending_setup_state(self.controller)
                return _error_destination(_("Bad passphrase"), str(exc))

            try:
                derived = bip39.mnemonic_to_seed(
                    mnemonic_str, password=passphrase_str,
                )
                seed64[:] = derived
                root = bip32.HDKey.from_seed(bytes(seed64))
                fingerprint = root.my_fingerprint.hex()
            except Exception as exc:
                logger.exception("seed derivation failed")
                _wipe_pending_setup_state(self.controller)
                return _error_destination(_("Derive failed"), str(exc))

            try:
                client, _unused = _open_unlocked_session_cached_or_prompt(
                    self, require_key=False,
                )
                client.load_bip39_seed(bytes(seed64))
            except KeycardPinPromptCancelled:
                _wipe_pending_setup_state(self.controller)
                return Destination(BackStackView)
            except KeycardCardChangedError:
                _wipe_pending_setup_state(self.controller)
                return Destination(ToolsKeycardPairView)
            except Exception as exc:
                logger.exception("LOAD_KEY failed")
                _wipe_pending_setup_state(self.controller)
                title, body = classify_card_error(
                    exc, default_title=_("Push failed"),
                )
                return _error_destination(title, body)

            _invalidate_wallets_cache_for_active_aid(self.controller)

            self.run_screen(
                LargeIconStatusScreen,
                title=_("Seed loaded"),
                status_headline=None,
                text=_("Master fp:\n{}").format(fingerprint),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(
                ToolsKeycardSeedkeeperOfferView, skip_current_view=True,
            )
        finally:
            wipe_bytearray(seed64)


class ToolsKeycardSeedkeeperOfferView(View):
    """Offer to back up the just-loaded seed onto a Seedkeeper applet.

    The card-creation moment is the *only* window in which the host holds
    the seed: once it is sealed in the Keycard it can never be read back,
    only signed with. So this is where we offer a Seedkeeper backup.

    Three destinations are offered on the next screen (``This card`` /
    ``Another card`` / ``Both``). If the Keycard's card has no Seedkeeper
    applet, the ``This card`` path offers to install one first.

    Skipping wipes the pending mnemonic and returns to the Keycard menu;
    that is a user-driven exit, so dropping the seed is correct here.
    """

    YES = ButtonOption("Save backup")
    NO = ButtonOption("Skip")

    def run(self):
        # Ask first — we don't need a card present to pose the question,
        # and the destination chooser decides what to probe / install.
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Save to Seedkeeper?"),
            is_button_text_centered=False,
            button_data=[self.YES, self.NO],
        )
        if selected == RET_CODE__BACK_BUTTON or (
            (self.YES, self.NO)[selected] == self.NO
        ):
            _wipe_pending_setup_state(self.controller)
            return Destination(
                ToolsKeycardMenuView, clear_history=True,
            )
        return Destination(ToolsKeycardSeedkeeperDestChooserView)


class ToolsKeycardSeedkeeperDestChooserView(View):
    """Pick where to back up: this card, a separate card, or both.

    * **This card** — back up to a Seedkeeper applet on the same physical
      card (installing the applet first if it isn't present).
    * **Another card** — swap in a *separate* Seedkeeper card.
    * **Both** — this card AND a separate card.

    Backing out is a user-driven exit, so it wipes the pending seed.
    """

    THIS_CARD = ButtonOption("This card")
    OTHER_CARD = ButtonOption("Another card")
    BOTH = ButtonOption("Both")

    def run(self):
        button_data = [self.THIS_CARD, self.OTHER_CARD, self.BOTH]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Save backup to"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            _wipe_pending_setup_state(self.controller)
            return Destination(ToolsKeycardMenuView, clear_history=True)
        chosen = button_data[selected]
        if chosen == self.THIS_CARD:
            return Destination(
                ToolsKeycardSeedkeeperThisCardView, view_args={"remaining": []},
            )
        if chosen == self.OTHER_CARD:
            return Destination(ToolsKeycardSeedkeeperSwapInsertView)
        # Both: save to this card first, then swap to a separate card.
        return Destination(
            ToolsKeycardSeedkeeperThisCardView,
            view_args={"remaining": ["other"]},
        )


class ToolsKeycardSeedkeeperThisCardView(View):
    """Back up to a Seedkeeper applet on the Keycard's own card.

    Probes the inserted card; if no Seedkeeper applet is present, offers
    to install one (reusing the GlobalPlatform install + iOS-coexistence
    warning shared with the Cards menu). A freshly-installed applet has
    no PIN yet — the save step's ``init_satochip`` runs ``card_setup``
    (PIN prompt) inline. ``remaining`` carries any *further* destinations
    (e.g. ``["other"]`` for the Both flow) through to the save step.

    Threat model: the pending seed now survives a same-card applet
    install (``gp.jar`` shells out, taking seconds) before the first
    save. Wipe is best-effort on every terminal branch + MainMenu.
    """

    INSTALL = ButtonOption("Install")
    CANCEL = ButtonOption("Cancel")

    def __init__(self, remaining=None):
        super().__init__()
        self.remaining = remaining or []

    def run(self):
        from seedsigner.helpers.card_probe import probe_installed_applets
        from seedsigner.helpers.keycard.reader import (
            release_other_smartcard_holders,
        )

        try:
            release_other_smartcard_holders(self.controller)
        except Exception:
            pass
        try:
            state = probe_installed_applets(self.controller)
        except Exception:
            state = None

        has_seedkeeper = bool(
            state and getattr(state, "seedkeeper_installed", False)
        )
        if not has_seedkeeper:
            sel = self.run_screen(
                ButtonListScreen,
                title=_("No Seedkeeper applet"),
                is_button_text_centered=False,
                button_data=[self.INSTALL, self.CANCEL],
            )
            if sel == RET_CODE__BACK_BUTTON or (
                [self.INSTALL, self.CANCEL][sel] == self.CANCEL
            ):
                # User-driven exit → wipe.
                _wipe_pending_setup_state(self.controller)
                return Destination(ToolsKeycardMenuView, clear_history=True)
            from seedsigner.views.view import install_seedkeeper_applet
            result = install_seedkeeper_applet(self)
            if result is not None:
                # "back" (user cancelled a prompt) or "error" (warning
                # already shown). Keep the seed; let the user retry.
                return _backup_error_retry(
                    self, "Install failed",
                    "Could not install\nSeedkeeper applet.",
                )

        return Destination(
            ToolsKeycardSeedkeeperFormatChooserView,
            view_args={"remaining": self.remaining},
        )


class ToolsKeycardSeedkeeperSwapInsertView(View):
    """Prompt the user to swap in a separate Seedkeeper card, then verify it.

    Threat model: the pending mnemonic lives in
    ``controller.pending_keycard_mnemonic`` across the physical card swap —
    a longer host-memory exposure than a same-card backup. Every exit path
    here (cancel, no-card, error) wipes it; ``MainMenuView`` re-entry wipes
    it again as a backstop. Seizure mid-swap should be treated as a likely
    seed compromise (the wipe is best-effort given CPython's GC).
    """

    CONTINUE = ButtonOption("Continue")
    RETRY = ButtonOption("Retry")

    def run(self):
        from seedsigner.helpers.card_probe import probe_installed_applets
        from seedsigner.helpers.keycard.reader import (
            release_other_smartcard_holders,
        )

        ret = self.run_screen(
            WarningScreen,
            title=_("Insert Seedkeeper"),
            status_headline=None,
            text=_("Remove Keycard, insert\nyour Seedkeeper card."),
            show_back_button=True,
            button_data=[self.CONTINUE],
        )
        if ret == RET_CODE__BACK_BUTTON:
            _wipe_pending_setup_state(self.controller)
            return Destination(ToolsKeycardMenuView, clear_history=True)

        try:
            release_other_smartcard_holders(self.controller)
        except Exception:
            pass
        try:
            state = probe_installed_applets(self.controller)
        except Exception:
            state = None

        if not (state and getattr(state, "seedkeeper_installed", False)):
            retry = self.run_screen(
                WarningScreen,
                title=_("No Seedkeeper"),
                status_headline=None,
                text=_("No Seedkeeper card\ndetected."),
                show_back_button=True,
                button_data=[self.RETRY],
            )
            if retry == RET_CODE__BACK_BUTTON:
                _wipe_pending_setup_state(self.controller)
                return Destination(ToolsKeycardMenuView, clear_history=True)
            return Destination(ToolsKeycardSeedkeeperSwapInsertView)

        return Destination(ToolsKeycardSeedkeeperFormatChooserView)


class ToolsKeycardSeedkeeperFormatChooserView(View):
    """Pick how to encode the mnemonic on the Seedkeeper applet."""

    MNEMONIC = ButtonOption("BIP39 mnemonic")
    PASSWORD = ButtonOption("UTF-8 password")

    def __init__(self, remaining=None):
        super().__init__()
        self.remaining = remaining or []

    def run(self):
        button_data = [self.MNEMONIC, self.PASSWORD]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Backup format"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        chosen = button_data[selected]
        secret_type = "bip39" if chosen == self.MNEMONIC else "password"
        return Destination(
            ToolsKeycardSeedkeeperSaveRunView,
            view_args={"secret_type": secret_type, "remaining": self.remaining},
            skip_current_view=True,
        )


class ToolsKeycardSeedkeeperSaveRunView(View):
    """Write the pending mnemonic to the Seedkeeper applet.

    Uses pysatochip's typed "BIP39 mnemonic" header for the mnemonic
    format (matches the iOS-compatible layout used by
    ``ToolsSeedkeeperImportXprvView``), or the standard Password layout
    for the UTF-8 format. The mnemonic / passphrase are wiped after the
    save (success or failure) so a stuck user never leaves them on the
    controller.
    """

    def __init__(self, secret_type: str = "bip39", remaining=None):
        super().__init__()
        self.secret_type = secret_type
        # Further destinations still to write after this one (e.g.
        # ``["other"]`` for the Both flow). Tracked purely as a view-arg.
        self.remaining = remaining or []

    def run(self):
        from seedsigner.gui.screens import seed_screens
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.helpers import seedkeeper_utils

        try:
            from pysatochip.CardConnector import UnexpectedSW12Error
        except Exception as exc:
            # Irrecoverable (pysatochip missing) — retrying won't help, so
            # this is the one error path that still wipes the seed.
            _wipe_pending_setup_state(self.controller)
            return _error_destination(
                _("Seedkeeper unavailable"), str(exc),
            )

        mnemonic = self.controller.pending_keycard_mnemonic
        passphrase_buf = self.controller.pending_keycard_passphrase
        if not mnemonic or passphrase_buf is None:
            return Destination(BackStackView)

        mnemonic_str = " ".join(mnemonic)
        try:
            passphrase_str = passphrase_buf.decode("utf-8")
        except Exception:
            passphrase_str = ""

        label_ret = seed_screens.SeedAddPassphraseScreen(
            title=_("Secret label"),
        ).display()
        if isinstance(label_ret, dict) and "is_back_button" in label_ret:
            return Destination(BackStackView)
        if not isinstance(label_ret, dict):
            # Transient: keep the seed, let the user retry the backup.
            return _backup_error_retry(self, "Bad label", "Could not read label")
        label = label_ret.get("passphrase", "").strip() or "Keycard backup"

        Satochip_Connector = seedkeeper_utils.init_satochip(
            self, init_card_filter=["seedkeeper"],
        )
        if not Satochip_Connector:
            # PIN cancelled or card not reachable — init_satochip already
            # surfaced the reason. Keep the seed and return to the
            # destination chooser so the user can retry or pick another
            # target (a back-out there wipes).
            return Destination(ToolsKeycardSeedkeeperDestChooserView)

        export_rights = "Plaintext export allowed"
        if self.secret_type == "bip39":
            # iOS-compatible "BIP39 mnemonic" layout, subtype=0.
            # Body: [size|mnemonic|size|passphrase].
            mnem_bytes = list(mnemonic_str.encode("utf-8"))
            pp_bytes = list(passphrase_str.encode("utf-8"))
            secret_list = (
                [len(mnem_bytes)] + mnem_bytes
                + [len(pp_bytes)] + pp_bytes
            )
            header = Satochip_Connector.make_header(
                "BIP39 mnemonic", export_rights, label, subtype=0,
            )
        else:
            # Password layout: [pw|login=0|url=0]. iOS app crashes
            # without the trailing length=0 fields, per the SLIP-39
            # save path in seed_views.py.
            words_blob = mnemonic_str
            if passphrase_str:
                # Carry the passphrase as a separate line so an
                # operator restoring the secret in another tool can
                # see it. The Keycard cannot be rehydrated from a
                # mnemonic alone if a passphrase was used.
                words_blob = f"{mnemonic_str}\npassphrase:{passphrase_str}"
            pw_bytes = list(words_blob.encode("utf-8"))
            secret_list = [len(pw_bytes)] + pw_bytes + [0x00] + [0x00]
            header = Satochip_Connector.make_header(
                "Password", export_rights, label,
            )

        secret_dic = {"header": header, "secret_list": secret_list}

        loading = None
        try:
            fits, required, free = seedkeeper_utils.ensure_seedkeeper_capacity(
                Satochip_Connector, secret_dic,
            )
        except Exception as exc:
            return _backup_error_retry(self, "Seedkeeper error", str(exc))

        if not fits:
            return _backup_error_retry(
                self, "Not enough space",
                seedkeeper_utils.format_seedkeeper_space_error(required, free),
            )

        try:
            loading = LoadingScreenThread(text=_("Saving secret\n\n\n\n\n\n"))
            loading.start()
            Satochip_Connector.seedkeeper_import_secret(secret_dic)
            loading.stop()
        except UnexpectedSW12Error as exc:
            if loading is not None:
                loading.stop()
            from seedsigner.helpers.iso7816 import format_sw_error
            if exc.sw1 == 0x6A and exc.sw2 == 0x84:
                err = "Not enough space on Seedkeeper"
            else:
                err = format_sw_error(exc.sw1, exc.sw2)
            return _backup_error_retry(self, "Save failed", err)
        except Exception as exc:
            if loading is not None:
                loading.stop()
            logger.exception("Seedkeeper import failed")
            return _backup_error_retry(self, "Save failed", str(exc))

        # Saved successfully. If a further destination remains (the Both
        # flow), DON'T wipe yet — swap to a separate card and save again.
        if "other" in self.remaining:
            self.run_screen(
                LargeIconStatusScreen,
                title=_("Saved (1 of 2)"),
                status_headline=None,
                text=_("Now back up to a\nseparate card."),
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(ToolsKeycardSeedkeeperSwapInsertView)

        _wipe_pending_setup_state(self.controller)
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Backup saved"),
            status_headline=None,
            text=_("Mnemonic stored on Seedkeeper."),
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(
            ToolsKeycardMenuView, clear_history=True,
        )


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
            if not try_silent_ephemeral_pair(self):
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
            client, _unused = _open_unlocked_session_cached_or_prompt(self)
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
            title, body = classify_card_error(exc, default_title=_("Export failed"))
            return _error_destination(title, body)

        if failed_step is not None:
            head_hex = failed_head.hex() if failed_head else "(empty)"
            return _error_destination(
                _("Parse fail"),
                # TRANSLATOR_NOTE: {} are a step number and a hex response dump
                _("Step {}\nresp={}").format(failed_step, head_hex),
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
            return _error_destination(_("Bad pubkey"), str(exc))

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
            title=_("ETH address"),
            status_headline=None,
            text=text,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsKeycardMenuView, skip_current_view=True)


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
            if not try_silent_ephemeral_pair(self):
                return Destination(ToolsKeycardPairView)

        cache = _wallets_cache_for_active_aid(self.controller)
        end_index = self.start_index + WALLETS_PER_PAGE

        if len(cache) < end_index:
            loading_screen = None
            try:
                client, _unused = _open_unlocked_session_cached_or_prompt(self)
                loading_screen = LoadingScreenThread(text=_("Deriving addrs..."))
                loading_screen.start()
                for i in range(len(cache), end_index):
                    client.derive_key([44 | _H, 60 | _H, 0 | _H, 0, i])
                    raw = client.export_pubkey()
                    pub = _extract_pubkey(raw)
                    if pub is None:
                        return _error_destination(
                            _("Parse fail"),
                            # TRANSLATOR_NOTE: {} are an index and a hex response dump
                            _("Index {}\nresp={}").format(
                                i, raw[:16].hex() if raw else '(empty)'),
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
                    exc, default_title=_("Derive failed"),
                )
                return _error_destination(title, body)
            finally:
                if loading_screen is not None:
                    loading_screen.stop()

        addresses = cache[self.start_index:end_index]
        active_aid_short = _instance_display_name(self.controller, self.controller.active_keycard_aid)

        selected = self.run_screen(
            ToolsAddressExplorerAddressListScreen,
            title=_("Wallets ({})").format(active_aid_short),
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
    # Keycard instance AIDs are ≤10 bytes (≤20 hex) and all share the same
    # 8-byte prefix, so the old first-6+last-4 truncation rendered two
    # distinct instances (e.g. 9-byte ``…0101`` vs 10-byte ``…0101``)
    # identically. Show short AIDs in FULL so they can be told apart — only
    # truncate genuinely long (>12-byte) AIDs.
    if len(hexstr) <= 24:
        return hexstr
    return hexstr[:6] + "…" + hexstr[-4:]


def _format_instance_label(aid: bytes) -> str:
    """Human-readable name for a Keycard instance: ``Inst N``.

    Keycard instance AIDs are ``KEYCARD_APPLET_AID`` + a one-byte instance
    index — either the 9-byte canonical form (``prefix + slot``, real cards)
    or the 10-byte legacy form (``prefix + 0x01 + slot``, older SeedSigner
    builds). In **both** the index is the last byte, which we surface as
    ``Inst N`` so the user has a stable handle on which instance every
    signing / export / wipe acts on, instead of cryptic AID hex. AIDs that
    don't match the instance pattern fall back to the short hex form.

    Note a 9-byte ``…0101`` and a 10-byte ``…0101`` both render ``Inst 1``;
    that residual ambiguity is why destructive screens (Delete) also show the
    full AID — the label alone is not a safe delete key.
    """
    if (
        aid.startswith(KEYCARD_APPLET_AID)
        and len(aid) in (len(KEYCARD_APPLET_AID) + 1, len(KEYCARD_APPLET_AID) + 2)
    ):
        return _("Inst {}").format(aid[-1])
    return _format_aid_short(aid)


def _instance_display_name(controller, aid: bytes) -> str:
    """User-assigned instance name if one is cached, else the ``Inst N`` label.

    The ``isinstance(name, str)`` guard is load-bearing: routing tests pass a
    bare ``MagicMock`` controller whose ``get_instance_name_for_aid`` returns a
    truthy Mock — without the guard that Mock would leak into a title's
    ``.format`` call. A real, non-empty name wins; everything else falls back.
    """
    name = controller.get_instance_name_for_aid(aid) if controller is not None else None
    return name if isinstance(name, str) and name else _format_instance_label(aid)


def _next_free_instance_aid(existing: list) -> bytes:
    """Suggest the next free instance AID, in the 9-byte canonical form.

    The slot index is the **last byte** of an instance AID in *both* the
    9-byte canonical form (``KEYCARD_APPLET_AID + slot``, used by
    keycard-cli/keycard-shell and real cards) and the 10-byte legacy form
    (``KEYCARD_APPLET_AID + 0x01 + slot``, minted by older SeedSigner builds).
    We therefore mark a slot used from the last byte of **every** AID under
    the applet prefix, regardless of length — so a 9-byte ``…0103`` correctly
    occupies slot 3. (The old code only recognised the 10-byte form, so it
    treated real 9-byte instances as absent and minted a colliding ``…0101``
    that equalled ``APPLET_AID`` and stole the boot-default slot.)

    New instances are minted in the **9-byte canonical form** to match real
    cards, and we never return an AID that already exists.
    """
    from seedsigner.helpers.keycard.global_platform import MAX_KEYCARD_INSTANCES
    existing_set = {bytes(a) for a in existing}
    used = set()
    for aid in existing_set:
        if aid.startswith(KEYCARD_APPLET_AID) and len(aid) > len(KEYCARD_APPLET_AID):
            used.add(aid[-1])
    for candidate in range(0x01, 0x01 + MAX_KEYCARD_INSTANCES):
        if candidate in used:
            continue
        new_aid = KEYCARD_APPLET_AID + bytes([candidate])
        if new_aid in existing_set:
            # Defensive: a same-slot AID of a different length already exists.
            continue
        return new_aid
    raise RuntimeError(
        f"no free instance slot (max {MAX_KEYCARD_INSTANCES})"
    )


class ToolsKeycardInstancesMenuView(View):
    """Manage Instances menu.

    Groups everything about the applet instances: the **active** one's
    key / PIN / pairing / init ops (``This instance``) and create / delete
    of the instance *set*. The create/delete ops talk to the Card Manager
    (ISD); the card must use the GP default ISD keys (`404142...4F`) — we
    don't brute-force or prompt for alternates here.

    On first entry per boot a one-screen explainer describes what
    instances are (several keys on one card); later entries skip it
    (``Controller.keycard_instances_intro_shown``).
    """

    THIS_INSTANCE = ButtonOption("This instance")
    CREATE = ButtonOption("Create instance")
    DELETE = ButtonOption("Delete instance")

    def run(self):
        # Show the explainer once per boot, then fall through to the menu.
        if not self.controller.keycard_instances_intro_shown:
            self.controller.keycard_instances_intro_shown = True
            ret = self.run_screen(
                LargeIconStatusScreen,
                title=_("Instances"),
                status_icon_size=0,
                status_headline=None,
                text=_(
                    "One card can hold several keys (\"instances\"), "
                    "each with its own PIN & seed."
                ),
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        active = _instance_display_name(self.controller, self.controller.active_keycard_aid)
        button_data = [self.THIS_INSTANCE, self.CREATE, self.DELETE]
        ret = self.run_screen(
            ButtonListScreen,
            title=_("Manage Inst · {}").format(active),
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        chosen = button_data[ret]
        if chosen == self.THIS_INSTANCE:
            return Destination(ToolsKeycardThisInstanceMenuView)
        if chosen == self.CREATE:
            return Destination(ToolsKeycardInstancesCreateView)
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


def _resolve_instance_uids(controller, connection, aids):
    """SELECT each AID to learn its ``instance_uid`` and cache the AID→UID map.

    Enumeration (``GET STATUS``) returns only AIDs, so without this the only
    instance we can name is one that happened to be SELECTed this session.
    SELECT is unauthenticated (no PIN) and there are at most
    ``MAX_KEYCARD_INSTANCES`` (4) candidates, so resolving every UID is cheap.
    Best-effort: a per-AID failure just leaves that row on the ``Inst N``
    label. Must run **after** any GP/``GET STATUS`` work on ``connection`` —
    SELECTing an applet deselects the ISD and breaks the GP channel.
    """
    if connection is None:
        return
    try:
        from seedsigner.helpers.keycard.client import KeycardClient
        client = KeycardClient(connection)
    except Exception:
        logger.debug("instance UID resolve: client init failed", exc_info=True)
        return
    for aid in aids:
        try:
            info = client.select(aid=aid)
            controller.remember_aid_for_uid(aid, info.instance_uid)
        except Exception:
            logger.debug("instance UID resolve failed for %s", aid.hex(), exc_info=True)


def _count_keycard_instances(controller):
    """Best-effort count of Keycard applet instances on the inserted card.

    Authoritative: opens the ISD GP channel and reads GET STATUS — the same
    enumeration the Manage Instances / Switch flows use — then filters to
    ``KEYCARD_APPLET_AID``. GET STATUS returns the instances' *real* AIDs,
    so it counts every instance regardless of suffix and is **not** capped
    at ``MAX_KEYCARD_INSTANCES``.

    Returns ``None`` whenever the count can't be trusted — no card,
    non-default ISD keys, GET STATUS unsupported (empty), or any error — so
    the caller keeps "Switch instance" visible rather than hide the only way
    to switch on a guess. We deliberately do **not** fall back to the
    cleartext-SELECT AID probe here: it only knows the standard
    ``…0101``–``…0104`` suffixes and would under-count instances installed
    at other AIDs (the cause of the "Switch instance vanished on a
    multi-instance card" bug).
    """
    connection = None
    try:
        _channel, instances, connection = _open_isd_channel(controller)
        keycard_instances = [
            i for i in instances if i.aid.startswith(KEYCARD_APPLET_AID)
        ]
        # Resolve each instance's UID now (cheap, no PIN) so the top-menu
        # title shows the active instance's real name on first entry, not just
        # after the first signing op. Runs after GET STATUS; breaks the GP
        # channel, which we no longer use.
        _resolve_instance_uids(
            controller, connection, [i.aid for i in keycard_instances]
        )
        # Empty -> GET STATUS unsupported / nothing reported: treat as
        # "unknown" (None) so we don't hide on a false zero/one.
        return len(keycard_instances) if keycard_instances else None
    except Exception:
        logger.debug("keycard instance count failed", exc_info=True)
        return None
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                pass


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


class ToolsKeycardInstancesSwitchView(View):
    def run(self):
        try:
            channel, instances, isd_connection = _open_isd_channel(self.controller)
        except Exception as exc:
            logger.exception("GP list_instances failed")
            title, body = classify_card_error(exc, default_title=_("GP failed"))
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
                _("No instances"),
                _("No Keycard applet found on this card."),
            )

        # Free, accurate refresh of the count the top menu uses to decide
        # whether to show "Switch instance".
        self.controller.keycard_instance_count = len(candidates)

        # Resolve every instance's UID (cheap SELECT, no PIN) so each row
        # renders its real name, not just the active one. Best-effort: an
        # unresolved row falls back to "Inst N".
        _resolve_instance_uids(
            self.controller, isd_connection, [i.aid for i in candidates]
        )

        from seedsigner.helpers.keycard.global_platform import MAX_KEYCARD_INSTANCES
        active = self.controller.active_keycard_aid
        button_data = [
            ButtonOption(
                ("» " if i.aid == active else "")
                + _instance_display_name(self.controller, i.aid)
            )
            for i in candidates
        ]
        ret = self.run_screen(
            ButtonListScreen,
            title=_("Pick active ({}/{})").format(len(candidates), MAX_KEYCARD_INSTANCES),
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        chosen = candidates[ret].aid
        self.controller.active_keycard_aid = chosen
        # Switching the active instance must not carry the previous
        # instance's unlocked PIN across — the next op should re-prompt so
        # the user can, if needed, type a different (e.g. duress) PIN.
        # Drop all cached PINs: reader-independent, and the active AID→UID
        # map is too often empty to scope this safely. One extra prompt is
        # the documented acceptable cost (see wipe_card_session_secrets).
        self.controller.forget_all_pins()
        # Drop any cached wallets list whose AID no longer matches the
        # current active. Cheap to recompute and avoids showing stale
        # addresses derived against a different instance's master key.
        if self.controller.keycard_wallets_data is not None:
            self.controller.keycard_wallets_data.clear()

        self.run_screen(
            LargeIconStatusScreen,
            title=_("Active set"),
            status_headline=None,
            text=_instance_display_name(self.controller, chosen),
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        # "Switch instance" is launched from the top Keycard menu, so return
        # there (re-rendering its title with the new active instance) rather
        # than to the Instances submenu.
        return Destination(ToolsKeycardMenuView, clear_history=True)


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
            title, body = classify_card_error(exc, default_title=_("GP open failed"))
            return _error_destination(title, body)

        existing_aids = [i.aid for i in instances]
        keycard_count = sum(
            1 for aid in existing_aids if aid.startswith(KEYCARD_APPLET_AID)
        )
        if keycard_count >= MAX_KEYCARD_INSTANCES:
            return _error_destination(
                _("Maximum reached"),
                _("Delete one of the {} instances first.").format(MAX_KEYCARD_INSTANCES),
            )
        try:
            new_aid = _next_free_instance_aid(existing_aids)
        except Exception as exc:
            return _error_destination(_("No slot"), str(exc))

        ret = self.run_screen(
            DireWarningScreen,
            title=_("Create instance?"),
            status_headline=None,
            text=_("New AID:\n{}\nCard must have package.").format(_format_aid_short(new_aid)),
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
            return _error_destination(_("Install failed"), detail)
        except Exception as exc:
            logger.exception("INSTALL [for install] failed")
            title, body = classify_card_error(exc, default_title=_("Install failed"))
            return _error_destination(title, body)

        # Instance set changed — force the top menu to re-probe the count
        # (so "Switch instance" reappears now that there are >1).
        self.controller.keycard_instance_count = None

        self.run_screen(
            LargeIconStatusScreen,
            title=_("Created"),
            status_headline=None,
            text=_("AID:\n{}\nRun Init next.").format(_format_aid_short(new_aid)),
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
            title, body = classify_card_error(exc, default_title=_("GP failed"))
            return _error_destination(title, body)

        candidates = [
            i for i in instances if i.aid.startswith(KEYCARD_APPLET_AID)
        ]
        if not candidates:
            return _error_destination(
                _("No instances"), _("Nothing to delete."),
            )

        # Label each row with the resolved name (if cached this session) AND
        # the FULL AID. The full AID is the load-bearing disambiguator: two
        # instances can share an ``Inst N`` label (a 9-byte and a 10-byte AID
        # at the same slot), and deleting the wrong one is destructive. We do
        # NOT call ``_resolve_instance_uids`` here — it SELECTs each AID, which
        # deselects the ISD and would break the GP channel we still need for
        # ``delete_aid``; we rely on the session AID→UID cache + the full AID.
        button_data = [
            ButtonOption(
                _instance_display_name(self.controller, i.aid)
                + " " + i.aid.hex()
            )
            for i in candidates
        ]
        ret = self.run_screen(
            ButtonListScreen,
            title=_("Delete?"),
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        target = candidates[ret].aid

        confirm_ret = self.run_screen(
            DireWarningScreen,
            title=_("Confirm delete?"),
            status_headline=None,
            text=_("Delete {}\n{}?").format(
                _instance_display_name(self.controller, target), target.hex()
            ),
            show_back_button=True,
            button_data=[ButtonOption("Delete")],
        )
        if confirm_ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Look up the UID we cached at SELECT time, before we DELETE
        # the applet — afterwards the AID no longer responds to SELECT
        # so the mapping must come from the in-memory cache.
        deleted_uid = self.controller.get_uid_for_aid(target)

        try:
            delete_aid(channel, target, with_related=True)
        except Exception as exc:
            logger.exception("DELETE failed")
            title, body = classify_card_error(exc, default_title=_("Delete failed"))
            return _error_destination(title, body)

        # Drop any cached pairing whose UID we previously observed via
        # SELECT. If we never paired with this AID this boot the cache
        # lookup misses; that's fine — there's no local state to clear
        # in that case anyway.
        if deleted_uid is not None:
            from seedsigner.helpers.keycard import pairing_storage
            self.controller.forget_pairing_for(deleted_uid)
            try:
                pairing_storage.remove(instance_uid=deleted_uid)
            except Exception:
                logger.exception("could not remove deleted pairing blob")

        # If the deleted AID was the active one, fall back to the 9-byte
        # canonical default slot. The default SELECT (10-byte APPLET_AID)
        # still first-tries then probes both forms, so a 9- or 10-byte
        # remaining instance is resolved regardless.
        if self.controller.active_keycard_aid == target:
            self.controller.active_keycard_aid = KEYCARD_APPLET_AID + b"\x01"
        # Invalidate the cached wallet list for the deleted AID (and
        # the fallback default, in case both pointed at the same blob).
        if self.controller.keycard_wallets_data is not None:
            self.controller.keycard_wallets_data.pop(bytes(target).hex(), None)
        # Instance set changed — re-probe the count on the next top menu
        # render (so "Switch instance" hides again once only one is left).
        self.controller.keycard_instance_count = None

        self.run_screen(
            LargeIconStatusScreen,
            title=_("Deleted"),
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
            if not try_silent_ephemeral_pair(self):
                return Destination(ToolsKeycardPairView, skip_current_view=True)
        return Destination(ScanEthSignRequestView, skip_current_view=True)


class ScanEthSignRequestView(ScanView):
    @property
    def is_valid_qr_type(self):
        return self.decoder.is_eth_sign_request

    def run(self):
        self.run_screen(
            ScanScreen,
            instructions_text=_("Scan ETH sign request"),
            decoder=self.decoder,
        )
        time.sleep(0.1)

        if not self.decoder.is_complete:
            return Destination(BackStackView)

        try:
            request = self.decoder.get_eth_sign_request()
        except Exception as exc:
            logger.exception("eth-sign-request parsing failed")
            return _error_destination(_("Invalid request"), str(exc))
        if request is None:
            return _error_destination(_("Invalid request"), _("No data decoded"))

        self.controller.eth_sign_request = request
        return Destination(ToolsKeycardSignEthVerifyCardView)


class ToolsKeycardSignEthVerifyCardView(View):
    """Between scan and review: confirm the scanned request actually belongs
    to the wallet on the active card/instance *before* any review or signing.

    Replicates keycard-shell's early "wrong keycard" reject so we never sign —
    and never display a signature QR — for another wallet (which today only
    fails much later, on the online app). The card is unlocked here using the
    cached PIN when available and is only prompted for when it isn't; the PIN
    then stays cached, so the later Finalize step doesn't re-prompt."""

    def run(self):
        from seedsigner.helpers.keycard import (
            KeycardCardChangedError, KeycardPinPromptCancelled,
        )

        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination(_("No request"), _("Scan one first"))
        if not self.controller.has_any_keycard_auth():
            if not try_silent_ephemeral_pair(self):
                return Destination(ToolsKeycardPairView)

        try:
            client, _unused = _open_unlocked_session_cached_or_prompt(self)
            mismatch = _eth_request_card_mismatch(client, request)
        except KeycardPinPromptCancelled:
            return Destination(BackStackView)
        except KeycardCardChangedError:
            self.controller.eth_sign_request = None
            return Destination(ToolsKeycardPairView)
        except Exception as exc:
            logger.exception("Keycard identity check failed")
            from seedsigner.helpers.keycard.reader import (
                NoCardError, NoReaderError,
            )
            if isinstance(exc, (NoCardError, NoReaderError)):
                # No card → subtle toast + stay on this verify view, which
                # re-reads controller.eth_sign_request. Don't drop the request
                # so the user can insert a card and retry without re-scanning.
                return _no_card_toast_or_error(
                    self, exc, default_title=_("Check failed"),
                    stay=Destination(ToolsKeycardSignEthVerifyCardView),
                )
            self.controller.eth_sign_request = None
            title, body = classify_card_error(exc, default_title=_("Check failed"))
            return _error_destination(title, body, return_to_main=True)

        if mismatch:
            self.controller.eth_sign_request = None
            return _error_destination(
                _("Wrong card"),
                _("This request is for a different wallet. Try another keycard."),
                return_to_main=True,
            )
        return Destination(ToolsKeycardSignEthOverviewView)


class ToolsKeycardSignEthOverviewView(View):
    """First step of the linear sign wizard — kind, chain, path, address.
    A single primary action; the top-nav back arrow cancels the flow."""
    CONTINUE = ButtonOption("Continue")

    def run(self):
        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination(_("No request"), _("Scan one first"))

        from seedsigner.helpers.ethereum.chains import chain_label
        kind = DATA_TYPE_LABELS.get(request.data_type)
        kind = _(kind) if kind else _("type {}").format(request.data_type)
        path = _format_path(request.derivation_path.components)
        addr_line = ""
        if request.address:
            addr_line = f"\n{to_checksum_address(request.address)}"
        # TRANSLATOR_NOTE: {} are tx-type label, chain name, derivation path, optional address
        text = _("{}\n{}\npath {}{}").format(
            kind, chain_label(request.chain_id), path, addr_line
        )
        ret = self.run_screen(
            LargeIconStatusScreen,
            title=_("Sign ETH?"),
            status_icon_size=0,
            status_headline=None,
            text=text,
            is_button_text_centered=False,
            button_data=[self.CONTINUE],
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            self.controller.eth_sign_request = None
            return Destination(BackStackView)
        return Destination(ToolsKeycardSignEthDetailsView)


class ToolsKeycardSignEthDetailsView(View):
    """Second step — to/value/gas for legacy/EIP1559; typed-data summary;
    decoded text for personal-sign.  A single Continue advances the wizard:
    to the ERC-8213 digest screen when one applies (tx with calldata, EIP-712
    typed data), to the raw-data viewer for personal-sign, otherwise straight
    to the final Confirm gate.  The top-nav back arrow returns to Overview.
    """
    CONTINUE = ButtonOption("Continue")

    def run(self):
        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination(_("No request"), _("Lost mid-flow"))

        tx = _eth_tx_summary(request)
        has_digest = False  # tx with calldata, or EIP-712 typed-data
        has_data_only = False  # personal-sign / unknown — drill straight into data
        if tx is not None:
            to_bytes = tx.get("to") or b""
            to_str = _("(create)") if not to_bytes else to_checksum_address(to_bytes)
            # Truncate the address middle so the line still fits on a 240px screen.
            if len(to_str) > 14:
                to_str = f"{to_str[:8]}…{to_str[-4:]}"
            text = _("to {}\nvalue {}\ngas {}").format(
                to_str, _format_wei(tx['value']), tx.get('gas_limit', 0)
            )
            has_digest = bool(tx.get("data"))
        elif request.data_type == DATA_TYPE_PERSONAL_MESSAGE:
            try:
                msg = bytes(request.sign_data).decode("utf-8")
            except Exception:
                msg = bytes(request.sign_data).hex()
            preview = msg if len(msg) <= 80 else msg[:78] + "…"
            text = _("message:\n{}").format(preview)
            has_data_only = bool(request.sign_data)
        elif request.data_type == DATA_TYPE_TYPED_DATA:
            try:
                typed = json.loads(bytes(request.sign_data).decode("utf-8"))
                primary = typed.get("primaryType", "?")
            except (UnicodeDecodeError, json.JSONDecodeError):
                primary = "?"
            text = _("EIP-712 typed data\nprimary: {}").format(primary)
            has_digest = True
        else:
            text = _("raw\n{}…").format(bytes(request.sign_data)[:32].hex())
            has_data_only = True

        ret = self.run_screen(
            LargeIconStatusScreen,
            title=_("TX details"),
            status_icon_size=0,
            status_headline=None,
            text=text,
            is_button_text_centered=False,
            button_data=[self.CONTINUE],
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        if has_digest:
            # Human-readable decode (what the tx does) before the digest hashes.
            return Destination(ToolsKeycardSignEthDecodedView, view_args={"page": 0})
        if has_data_only:
            return Destination(ToolsKeycardSignEthDataView, view_args={"page": 0})
        return Destination(ToolsKeycardSignEthConfirmView)


class ToolsKeycardSignEthDecodedView(View):
    """Human-readable decode of *what the transaction does* — a transfer, an
    approve, a swap, … — shown between Details and the digest screens.

    Display-only: nothing here changes the bytes that get signed; the ERC-8213
    calldata digest / EIP-712 hashes on the following screens remain the source
    of truth.  An unknown function selector renders an explicit blind-signing
    warning instead of hiding it.  Long values are truncated (the raw-hex
    "Show data" drill-down stays available for byte-exact review).

    Paginated like the digest/data views: one primary button (Next page, or
    Continue on the last page) plus a "Show data" drill-down; the top-nav back
    arrow walks back one page at a time.
    """
    NEXT = ButtonOption("Next page")
    CONTINUE = ButtonOption("Continue")
    SHOW_DATA = ButtonOption("Show data")

    def __init__(self, page: int = 0):
        super().__init__()
        self.page = max(0, page)

    def _pages(self, request: "EthSignRequest"):
        from seedsigner.helpers.ethereum import calldata_decoder

        tx = _eth_tx_summary(request)
        if tx is not None:
            data = tx.get("data") or b""
            if not data:
                return []
            return calldata_decoder.pages_for_calldata(
                data, chain_id=request.chain_id, to_address=tx.get("to") or None,
            )
        if request.data_type == DATA_TYPE_TYPED_DATA:
            try:
                typed = json.loads(bytes(request.sign_data).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return []
            return calldata_decoder.render_typed_data_pages(typed)
        return []

    def run(self):
        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination(_("No request"), _("Lost mid-flow"))

        pages = self._pages(request)
        if not pages:
            # Nothing to decode → straight to the digest screens.
            return Destination(
                ToolsKeycardSignEthDigestView, view_args={"page": 0},
                skip_current_view=True,
            )

        total = len(pages)
        page = min(self.page, total - 1)
        header, body = pages[page]
        counter = f" {page + 1}/{total}" if total > 1 else ""
        text = f"{header}\n{body}"

        is_last = page >= total - 1
        button_data = [self.CONTINUE if is_last else self.NEXT, self.SHOW_DATA]

        ret = self.run_screen(
            LargeIconStatusScreen,
            title=_("Decoded{}").format(counter),
            status_icon_size=0,
            status_headline=None,
            text=text,
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            # Pages are pushed normally, so back walks back one page at a time.
            return Destination(BackStackView)
        choice = button_data[ret]
        if choice == self.NEXT:
            return Destination(
                ToolsKeycardSignEthDecodedView, view_args={"page": page + 1},
            )
        if choice == self.SHOW_DATA:
            return Destination(
                ToolsKeycardSignEthDataView, view_args={"page": 0},
            )
        return Destination(ToolsKeycardSignEthDigestView, view_args={"page": 0})


class ToolsKeycardSignEthDigestView(View):
    """ERC-8213 digest screens, inserted between Details and the raw-data
    viewer so the user can verify a single 32-byte hash against a second
    device instead of paging through hex.

    - legacy/EIP-1559 tx with non-empty data: 1 page (Calldata digest).
    - EIP-712 typed-data: 3 pages (EIP-712 digest, Domain hash, Message hash).
    - empty calldata / personal-sign / unknown: no pages → skip to Confirm.

    Linear-wizard navigation: a single primary button (Next page, or Continue
    on the last page) plus an optional "Show data" drill-down — never more than
    two buttons, so the hash is never crowded.  The top-nav back arrow walks
    back one page at a time (pages are pushed normally, not skipped).
    """
    NEXT = ButtonOption("Next page")
    CONTINUE = ButtonOption("Continue")
    SHOW_DATA = ButtonOption("Show data")

    def __init__(self, page: int = 0):
        super().__init__()
        self.page = max(0, page)

    def _pages(self, request: "EthSignRequest"):
        from seedsigner.helpers.ethereum import eip712
        from seedsigner.helpers.ethereum.erc8213 import compute_calldata_digest

        tx = _eth_tx_summary(request)
        if tx is not None:
            data = tx.get("data") or b""
            if not data:
                return []
            return [(_("Calldata digest"), compute_calldata_digest(data))]
        if request.data_type == DATA_TYPE_TYPED_DATA:
            try:
                typed = json.loads(bytes(request.sign_data).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return []
            return [
                (_("EIP-712 digest"), eip712.signing_hash(typed)),
                (_("Domain hash"),    eip712.domain_separator(typed)),
                (_("Message hash"),   eip712.message_hash(typed)),
            ]
        return []

    def run(self):
        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination(_("No request"), _("Lost mid-flow"))

        pages = self._pages(request)
        if not pages:
            return Destination(
                ToolsKeycardSignEthConfirmView, skip_current_view=True,
            )

        total = len(pages)
        page = min(self.page, total - 1)
        label, digest = pages[page]
        digest_hex = digest.hex()
        text = f"{label}\n{digest_hex[:32]}\n{digest_hex[32:]}"

        is_last = page >= total - 1
        button_data = [self.CONTINUE if is_last else self.NEXT, self.SHOW_DATA]

        ret = self.run_screen(
            LargeIconStatusScreen,
            title=_("Digest {}/{}").format(page + 1, total),
            status_icon_size=0,
            status_headline=None,
            text=text,
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            # Pages are pushed normally, so back pops one digest page at a
            # time and finally returns to the Details step.
            return Destination(BackStackView)
        choice = button_data[ret]
        if choice == self.NEXT:
            return Destination(
                ToolsKeycardSignEthDigestView, view_args={"page": page + 1},
            )
        if choice == self.SHOW_DATA:
            return Destination(
                ToolsKeycardSignEthDataView, view_args={"page": 0},
            )
        return Destination(ToolsKeycardSignEthConfirmView)


class ToolsKeycardSignEthDataView(View):
    """Optional raw-data drill-down — paginated calldata hex (or raw payload
    for typed-data).

    96 hex chars per page (= 48 bytes), wrapped 24 chars per line so the
    240px screen displays four lines without overflow.  Linear-wizard
    navigation: one primary button (Next page, or Continue on the last page);
    the top-nav back arrow walks back one page at a time.
    """
    NEXT = ButtonOption("Next page")
    CONTINUE = ButtonOption("Continue")

    PAGE_HEX_CHARS = 96
    LINE_HEX_CHARS = 24

    def __init__(self, page: int = 0):
        super().__init__()
        self.page = max(0, page)

    def run(self):
        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination(_("No request"), _("Lost mid-flow"))

        tx = _eth_tx_summary(request)
        if tx is not None:
            data = tx.get("data") or b""
        else:
            # Typed-data hash / personal-message / unknown — show raw bytes.
            data = bytes(request.sign_data)

        if not data:
            return Destination(
                ToolsKeycardSignEthConfirmView, skip_current_view=True,
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

        is_last = page >= total_pages - 1
        button_data = [self.CONTINUE if is_last else self.NEXT]

        ret = self.run_screen(
            LargeIconStatusScreen,
            title=_("Data {}/{}").format(page + 1, total_pages),
            status_icon_size=0,
            status_headline=None,
            text=wrapped,
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            # Pages are pushed normally, so back walks back one page at a time.
            return Destination(BackStackView)
        choice = button_data[ret]
        if choice == self.NEXT:
            return Destination(
                ToolsKeycardSignEthDataView, view_args={"page": page + 1},
            )
        return Destination(ToolsKeycardSignEthConfirmView)


class ToolsKeycardSignEthConfirmView(View):
    """Final confirmation gate before the card signs.  Deliberately a single
    action so the summary is never crowded by buttons; the top-nav back arrow
    returns to the previous review step."""
    CONFIRM = ButtonOption("Confirm & sign")

    def run(self):
        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination(_("No request"), _("Lost mid-flow"))

        path = _format_path(request.derivation_path.components)
        text = _("Sign with Keycard?\nchain {}  {}").format(request.chain_id, path)
        ret = self.run_screen(
            LargeIconStatusScreen,
            title=_("Confirm"),
            status_icon_size=0,
            status_headline=None,
            text=text,
            is_button_text_centered=False,
            button_data=[self.CONFIRM],
            show_back_button=True,
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(ToolsKeycardSignEthFinalizeView)


class ToolsKeycardSignEthFinalizeView(View):
    def run(self):
        from seedsigner.helpers.keycard import (
            KeycardCardChangedError, KeycardPinPromptCancelled,
        )

        request: Optional[EthSignRequest] = getattr(self.controller, "eth_sign_request", None)
        if request is None:
            return _error_destination(_("No request"), _("Lost request mid-flow"))
        if not self.controller.has_any_keycard_auth():
            if not try_silent_ephemeral_pair(self):
                return Destination(ToolsKeycardPairView)

        try:
            from seedsigner.helpers.keycard_signer import sign_with_keycard
        except ImportError as exc:
            return _error_destination(_("Keycard support unavailable"), str(exc))

        try:
            client, _unused = _open_unlocked_session_cached_or_prompt(self)
            # Defense in depth: even though ToolsKeycardSignEthVerifyCardView
            # already gated this after the scan, re-confirm right before the
            # irreversible sign so a routing change / alternate entry can never
            # produce a signature for another wallet. (No-identity requests
            # still pass — by design.)
            if _eth_request_card_mismatch(client, request):
                self.controller.eth_sign_request = None
                self.controller.eth_signature = None
                return _error_destination(
                    _("Wrong card"),
                    _("This request is for a different wallet. Try another keycard."),
                    return_to_main=True,
                )
            signature = sign_with_keycard(client, request)
        except KeycardPinPromptCancelled:
            return Destination(BackStackView)
        except KeycardCardChangedError:
            self.controller.eth_sign_request = None
            self.controller.eth_signature = None
            return Destination(ToolsKeycardPairView)
        except Exception as exc:
            logger.exception("Keycard signing failed")
            from seedsigner.helpers.keycard.reader import (
                NoCardError, NoReaderError,
            )
            if isinstance(exc, (NoCardError, NoReaderError)):
                # No card → subtle toast + stay on the Confirm screen, which
                # re-reads controller.eth_sign_request. Don't drop the request.
                return _no_card_toast_or_error(
                    self, exc, default_title=_("Signing failed"),
                )
            self.controller.eth_sign_request = None
            self.controller.eth_signature = None
            title, body = classify_card_error(exc, default_title=_("Signing failed"))
            return _error_destination(title, body, return_to_main=True)

        self.controller.eth_signature = signature
        return Destination(ToolsKeycardSignEthQrDisplayView)


class ToolsKeycardSignEthQrDisplayView(View):
    def run(self):
        signature = getattr(self.controller, "eth_signature", None)
        if signature is None:
            return _error_destination(_("No signature"), _("Nothing to display"))

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


def _card_master_fingerprint(client) -> bytes:
    """Derive the card's BIP-32 master fingerprint (HASH160 of the master
    pubkey, first 4 bytes).

    Identifies the *wallet/seed*, NOT the physical card: two cards holding
    the same mnemonic share it, and a card's real vs. decoy (duress) wallet
    share it too (same master key, only the chain code differs). So comparing
    it never rejects an equivalent card and never leaks the decoy — it differs
    only when the underlying seed differs. Requires an unlocked session."""
    from seedsigner.helpers.bitcoin import xpub as btc_xpub
    from seedsigner.helpers.keycard import commands as kc_cmds
    from seedsigner.helpers.keycard_btc_signer import (
        _parse_pubkey_only, compress_pubkey,
    )

    client.derive_key([], source=kc_cmds.DERIVE_P1_FROM_MASTER)
    master_resp = client.export_pubkey(path_components=None, extended=False)
    master_pub = _parse_pubkey_only(master_resp)
    return btc_xpub.pubkey_fingerprint(compress_pubkey(master_pub))


def _card_eth_address_at(client, components) -> str:
    """Derive the EIP-55 checksummed ETH address at ``components`` (a full
    path from the master, hardened bits set) from the card. Mirrors the
    "View wallets" derivation. Requires an unlocked session."""
    client.derive_key(list(components))
    raw = client.export_pubkey()
    pub = _extract_pubkey(raw)
    if pub is None:
        raise ValueError("EXPORT KEY returned no public key")
    return to_checksum_address(pubkey_to_address(pub))


def _eth_request_card_mismatch(client, request) -> bool:
    """True iff the scanned ETH request demonstrably belongs to a *different*
    wallet than the one on the unlocked card.

    Prefers the explicit signing address when the request carries one (also
    catches a wrong derivation path); otherwise falls back to the master
    fingerprint. Returns ``False`` when the request carries neither — there is
    then nothing to verify against, so we don't block a possibly-valid sign."""
    address = getattr(request, "address", None)
    if address:
        derived = _card_eth_address_at(client, request.derivation_path.components)
        return derived.lower() != to_checksum_address(address).lower()
    source_fp = getattr(request.derivation_path, "source_fingerprint", None)
    if source_fp is not None:
        # Real-world requests (Keystone/Frame/keycard-shell) encode the
        # fingerprint as a uint32 → it decodes to an int. Normalize to 4 bytes
        # so we compare correctly and never hit bytes(<int>) (which would
        # allocate a giant buffer, not the fingerprint).
        from seedsigner.helpers.ethereum.ur_codec import _as_fingerprint_bytes
        fp = _as_fingerprint_bytes(source_fp)
        if fp is not None:
            return fp != _card_master_fingerprint(client)
    return False


def _no_card_toast_or_error(view, exc, *, default_title: str, stay=None):
    """Card-absent → subtle toast + stay; otherwise the standard error.

    When the caught exception is simply "no card / no reader in the
    slot", a full ``ErrorScreen`` is heavy-handed: the user just needs
    to insert a card and retry. Mirror the Cards-menu UX
    (``CardsMenuView``) — flash an ``InfoToast`` reading "Insert a card
    first" and return ``stay`` (default: one step back via
    ``BackStackView``) so any already-scanned PSBT / message survives.

    Any other exception falls through to ``classify_card_error`` +
    ``_error_destination`` exactly as before.
    """
    from seedsigner.helpers.keycard.reader import NoCardError, NoReaderError
    if isinstance(exc, (NoCardError, NoReaderError)):
        # Card confirmed absent during an op — drop cached PINs so a
        # re-inserted card (possibly a different one) is re-authenticated.
        # Reader-independent backstop for the PC/SC 'removed' event, which
        # is unreliable on contactless readers. This touches ONLY the PIN
        # cache, not scanned state (eth_sign_request / psbt / message), so
        # retry-without-rescan still holds — it just re-prompts for the PIN.
        try:
            view.controller.wipe_card_session_secrets()
        except Exception:
            logger.exception("wipe on no-card observation failed")
        from seedsigner.gui.toast import InfoToast
        try:
            view.controller.activate_toast(
                InfoToast(label_text=_("Insert a card first"))
            )
        except Exception:
            logger.exception("InfoToast dispatch failed")
        return stay if stay is not None else Destination(BackStackView)
    title, body = classify_card_error(exc, default_title=default_title)
    return _error_destination(title, body, return_to_main=True)


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


# ---------------------------------------------------------------------------
# Bitcoin (BIP-84 P2WPKH single-sig, mainnet)
# ---------------------------------------------------------------------------
#
# Mirrors the ETH sign chain: a small menu, an Export-xpub flow that
# DERIVE + EXPORT_KEY against the account path, a PSBT sign flow that
# scans + reviews + signs, and a BIP-137 message-sign flow.
#
# Session handling reuses the same helpers as the ETH path
# (``_open_unlocked_session_cached_or_prompt``, ``classify_card_error``).
# Each flow drops its own scratch state on the Controller; cleanup
# happens on the success path and in every error branch.


class ToolsKeycardEthereumMenuView(View):
    """Ethereum submenu, mirrors the Bitcoin one.

    ``Sign request`` is chain-agnostic across the ETH request kinds
    (legacy tx, EIP-1559, EIP-712 typed data, personal_sign) — the
    start view auto-detects from the scanned ``eth-sign-request`` UR.
    """

    EXPORT_XPUB = ButtonOption("Connect software wallet")
    SIGN_REQUEST = ButtonOption("Sign request")
    VIEW_WALLETS = ButtonOption("View wallets")

    def run(self):
        from seedsigner.helpers.card_probe import run_card_gate
        gate = run_card_gate(
            self, "keycard", title=_("Ethereum"), setup_view=ToolsKeycardInitView,
        )
        if gate is not None:
            return gate

        button_data = [self.SIGN_REQUEST, self.VIEW_WALLETS, self.EXPORT_XPUB]
        active = _instance_display_name(self.controller, self.controller.active_keycard_aid)
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Ethereum · {}").format(active),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        chosen = button_data[selected]
        if chosen == self.EXPORT_XPUB:
            return Destination(ToolsKeycardPairWalletView)
        if chosen == self.SIGN_REQUEST:
            return Destination(ToolsKeycardSignEthStartView)
        if chosen == self.VIEW_WALLETS:
            return Destination(ToolsKeycardWalletsListView)
        return Destination(NotYetImplementedView)


class ToolsKeycardBitcoinMenuView(View):
    EXPORT_XPUB = ButtonOption("Connect software wallet")
    SIGN_PSBT = ButtonOption("Sign PSBT")
    SIGN_MESSAGE = ButtonOption("Sign message")

    def run(self):
        from seedsigner.helpers.card_probe import run_card_gate
        gate = run_card_gate(
            self, "keycard", title=_("Bitcoin"), setup_view=ToolsKeycardInitView,
        )
        if gate is not None:
            return gate

        button_data = [self.SIGN_PSBT, self.SIGN_MESSAGE, self.EXPORT_XPUB]
        active = _instance_display_name(self.controller, self.controller.active_keycard_aid)
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Bitcoin · {}").format(active),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        chosen = button_data[selected]
        if chosen == self.EXPORT_XPUB:
            return Destination(ToolsKeycardBtcExportXpubView)
        if chosen == self.SIGN_PSBT:
            return Destination(ToolsKeycardBtcSignPsbtScanView)
        if chosen == self.SIGN_MESSAGE:
            return Destination(ToolsKeycardBtcSignMessageStartView)
        return Destination(NotYetImplementedView)


class ToolsKeycardBtcExportXpubView(View):
    """Derive the BIP-84 account xpub on the Keycard and display the
    canonical ``wpkh(...)`` descriptor as a static QR.

    UR ``crypto-account`` animated export is a follow-up: the
    descriptor is sufficient for Sparrow / Specter / BlueWallet to
    ingest as text and avoids the extra encoder dependency at MVP.
    """

    def run(self):
        from seedsigner.helpers.keycard import (
            KeycardCardChangedError, KeycardPinPromptCancelled,
        )

        if not self.controller.has_any_keycard_auth():
            if not try_silent_ephemeral_pair(self):
                return Destination(ToolsKeycardPairView)

        try:
            from seedsigner.helpers.bitcoin import DEFAULT_BTC_ACCOUNT_PATH
            from seedsigner.helpers.keycard_btc_signer import export_xpub
        except ImportError as exc:
            return _error_destination(_("BTC support unavailable"), str(exc))

        try:
            client, _unused = _open_unlocked_session_cached_or_prompt(self)
            xpub_export = export_xpub(client, DEFAULT_BTC_ACCOUNT_PATH)
        except KeycardPinPromptCancelled:
            return Destination(BackStackView)
        except KeycardCardChangedError:
            return Destination(ToolsKeycardPairView)
        except Exception as exc:
            logger.exception("Keycard export_xpub failed")
            # No card → subtle toast + back one step (no scanned data here).
            return _no_card_toast_or_error(self, exc, default_title=_("Export failed"))

        # Brief headline + path before showing the QR.
        self.run_screen(
            LargeIconStatusScreen,
            title=_("BIP-84 xpub"),
            status_headline=None,
            text=_("fp {}\n{}").format(xpub_export.master_fingerprint.hex(), DEFAULT_BTC_ACCOUNT_PATH),
            show_back_button=False,
            button_data=[ButtonOption("Show QR")],
        )

        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import GenericStaticQrEncoder

        encoder = GenericStaticQrEncoder(data=xpub_export.descriptor)
        self.run_screen(QRDisplayScreen, qr_encoder=encoder)
        return Destination(ToolsKeycardBitcoinMenuView, clear_history=True)


class ToolsKeycardBtcSignPsbtScanView(ScanView):
    """Scan PSBT (animated UR or single-frame base64) and route to the
    review screen. Any other QR type triggers the standard wrong-type
    error.
    """
    instructions_text = _("Scan PSBT")
    invalid_qr_type_message = _mft("Expected a PSBT QR")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_psbt

    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen
        import time as _time

        self.run_screen(
            ScanScreen,
            instructions_text=self.instructions_text,
            decoder=self.decoder,
        )
        self.controller.reset_screensaver_timeout()
        _time.sleep(0.1)

        if not self.decoder.is_complete:
            return Destination(ToolsKeycardBitcoinMenuView, clear_history=True)
        if not self.decoder.is_psbt:
            return _error_destination(
                _("Wrong QR type"),
                _("Expected a PSBT but got: ") + (self.decoder.qr_type or "?"),
                return_to_main=False,
            )

        self.controller.psbt = self.decoder.get_psbt()
        return Destination(ToolsKeycardBtcSignPsbtReviewView)


class ToolsKeycardBtcSignPsbtReviewView(View):
    """Parse the PSBT against the card's master fingerprint and present
    a summary (input count, total in, total out, fee) before signing.
    Non-P2WPKH inputs are rejected here with a clear error — the MVP
    bound matches keycard-shell."""

    def run(self):
        from seedsigner.helpers.keycard import (
            KeycardCardChangedError, KeycardPinPromptCancelled,
        )

        psbt = getattr(self.controller, "psbt", None)
        if psbt is None:
            return _error_destination(_("No PSBT"), _("Lost PSBT mid-flow"))

        if not self.controller.has_any_keycard_auth():
            if not try_silent_ephemeral_pair(self):
                return Destination(ToolsKeycardPairView)

        try:
            from seedsigner.helpers.bitcoin import psbt_helpers
            from seedsigner.helpers import keycard_btc_signer  # noqa: F401  (availability probe)
        except ImportError as exc:
            return _error_destination(_("BTC support unavailable"), str(exc))

        try:
            client, _unused = _open_unlocked_session_cached_or_prompt(self)
            master_fingerprint = _card_master_fingerprint(client)
        except KeycardPinPromptCancelled:
            return Destination(BackStackView)
        except KeycardCardChangedError:
            self.controller.psbt = None
            return Destination(ToolsKeycardPairView)
        except Exception as exc:
            logger.exception("Keycard fingerprint probe failed")
            from seedsigner.helpers.keycard.reader import (
                NoCardError, NoReaderError,
            )
            if isinstance(exc, (NoCardError, NoReaderError)):
                # No card → subtle toast + re-enter this review view (which
                # re-reads the already-scanned controller.psbt) so the user
                # can insert a card and retry without re-scanning.
                return _no_card_toast_or_error(
                    self, exc, default_title=_("Probe failed"),
                    stay=Destination(ToolsKeycardBtcSignPsbtReviewView),
                )
            self.controller.psbt = None
            title, body = classify_card_error(exc, default_title=_("Probe failed"))
            return _error_destination(title, body, return_to_main=True)

        # Reject a PSBT that belongs to a *different* wallet up front: at least
        # one input's BIP-32 origin fingerprint must match this card's master
        # fingerprint. Without this, _first_bip32_derivation falls back to the
        # first derivation and we'd produce a valid-looking signature for
        # someone else's key — caught only later by the online wallet. Mirrors
        # keycard-shell's early "wrong keycard". (A PSBT with no derivation
        # hints at all is left to extract(), which raises its own error.)
        has_any_derivation = any(inp.bip32_derivations for inp in psbt.inputs)
        belongs = any(
            der.fingerprint == master_fingerprint
            for inp in psbt.inputs
            for der in inp.bip32_derivations.values()
        )
        if has_any_derivation and not belongs:
            self.controller.psbt = None
            return _error_destination(
                _("Wrong card"),
                _("This PSBT is for a different wallet. Try another keycard."),
                return_to_main=True,
            )

        try:
            parsed = psbt_helpers.extract(psbt, master_fingerprint)
        except ValueError as exc:
            self.controller.psbt = None
            return _error_destination(_("PSBT rejected"), str(exc), return_to_main=True)

        self.controller.btc_parsed_psbt = parsed

        total_in = sum(v.amount_sats for v in parsed.inputs)
        total_out = sum(v.amount_sats for v in parsed.outputs if not v.is_change)
        ret = self.run_screen(
            LargeIconStatusScreen,
            title=_("Review PSBT"),
            status_headline=None,
            # TRANSLATOR_NOTE: PSBT summary — input count, output count (with sat total), fee in sats
            text=_("in: {}\nout: {} ({} sat)\nfee: {} sat").format(
                len(parsed.inputs),
                sum(1 for v in parsed.outputs if not v.is_change),
                total_out,
                parsed.fee_sats,
            ),
            show_back_button=True,
            button_data=[ButtonOption("Sign")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            self.controller.psbt = None
            self.controller.btc_parsed_psbt = None
            return Destination(ToolsKeycardBitcoinMenuView, clear_history=True)

        return Destination(ToolsKeycardBtcSignPsbtFinalizeView)


class ToolsKeycardBtcSignPsbtFinalizeView(View):
    def run(self):
        from seedsigner.helpers.keycard import (
            KeycardCardChangedError, KeycardPinPromptCancelled,
        )

        parsed = getattr(self.controller, "btc_parsed_psbt", None)
        if parsed is None:
            return _error_destination(_("No PSBT"), _("Lost PSBT mid-flow"))

        try:
            from seedsigner.helpers.keycard_btc_signer import sign_psbt as kc_sign_psbt
        except ImportError as exc:
            return _error_destination(_("BTC support unavailable"), str(exc))

        try:
            client, _unused = _open_unlocked_session_cached_or_prompt(self)
            kc_sign_psbt(client, parsed)
        except KeycardPinPromptCancelled:
            return Destination(BackStackView)
        except KeycardCardChangedError:
            self.controller.psbt = None
            self.controller.btc_parsed_psbt = None
            return Destination(ToolsKeycardPairView)
        except Exception as exc:
            logger.exception("Keycard sign_psbt failed")
            from seedsigner.helpers.keycard.reader import (
                NoCardError, NoReaderError,
            )
            if isinstance(exc, (NoCardError, NoReaderError)):
                # No card → subtle toast + re-enter this finalize view (the
                # parsed PSBT stays on controller.btc_parsed_psbt) so the
                # user can insert a card and retry without re-scanning.
                return _no_card_toast_or_error(
                    self, exc, default_title=_("Signing failed"),
                    stay=Destination(ToolsKeycardBtcSignPsbtFinalizeView),
                )
            self.controller.psbt = None
            self.controller.btc_parsed_psbt = None
            title, body = classify_card_error(exc, default_title=_("Signing failed"))
            return _error_destination(title, body, return_to_main=True)

        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import UrPsbtQrEncoder

        encoder = UrPsbtQrEncoder(psbt=parsed.psbt)
        self.run_screen(QRDisplayScreen, qr_encoder=encoder)
        self.controller.psbt = None
        self.controller.btc_parsed_psbt = None
        return Destination(MainMenuView, clear_history=True)


class ToolsKeycardBtcSignMessageStartView(View):
    """BIP-137 message signing entry: scan a UR ``bytes`` / generic text
    QR with the message body, then sign at the default BIP-84 path.

    MVP keeps the path fixed at ``DEFAULT_BTC_PATH`` (``m/84'/0'/0'/0/0``);
    a future revision can let the user pick a derivation. The signed
    output is the base64 string ``bitcoin-cli verifymessage`` accepts.
    """

    def run(self):
        return Destination(ToolsKeycardBtcSignMessageScanView, skip_current_view=True)


class ToolsKeycardBtcSignMessageScanView(ScanView):
    instructions_text = _("Scan message QR")
    invalid_qr_type_message = _mft("Expected a text / signmessage QR")

    @property
    def is_valid_qr_type(self):
        # Accept Sparrow's ``signmessage <path> ascii:<msg>`` QR, a UR
        # ``bytes`` payload, or any single-frame text QR.
        return (
            getattr(self.decoder, "is_sign_message", False)
            or getattr(self.decoder, "is_text", False)
            or getattr(self.decoder, "is_bytes", False)
        )

    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen
        import time as _time

        self.run_screen(
            ScanScreen,
            instructions_text=self.instructions_text,
            decoder=self.decoder,
        )
        self.controller.reset_screensaver_timeout()
        _time.sleep(0.1)

        if not self.decoder.is_complete:
            return Destination(ToolsKeycardBitcoinMenuView, clear_history=True)

        # Sparrow / Specter "signmessage" QR carries both the message and the
        # derivation path the host expects us to sign with.
        if getattr(self.decoder, "is_sign_message", False):
            data = self.decoder.get_qr_data() or {}
            message = data.get("message")
            derivation_path = data.get("derivation_path")
            if not isinstance(message, str) or not message:
                return _error_destination(
                    _("Wrong QR type"), _("Could not extract a message from the QR."),
                )
            return Destination(
                ToolsKeycardBtcSignMessageFinalizeView,
                view_args=dict(message=message, derivation_path=derivation_path),
            )

        # Otherwise fall back to a plain text / UR-bytes payload, signed at
        # the default BIP-84 path.
        try:
            message = self.decoder.get_text()
        except Exception:
            message = None
        if message is None:
            try:
                raw = self.decoder.get_qr_data()
            except Exception:
                return _error_destination(
                    _("Wrong QR type"), _("Could not extract a message from the QR."),
                )
            if isinstance(raw, (bytes, bytearray)):
                try:
                    message = bytes(raw).decode("utf-8")
                except UnicodeDecodeError:
                    return _error_destination(
                        _("Unsupported encoding"), _("Message must be UTF-8 text."),
                    )
            elif isinstance(raw, str):
                message = raw
            else:
                return _error_destination(
                    _("Wrong QR type"), _("Could not extract a message from the QR."),
                )

        return Destination(
            ToolsKeycardBtcSignMessageFinalizeView,
            view_args=dict(message=message),
        )


class ToolsKeycardBtcSignMessageFinalizeView(View):
    def __init__(self, message: str, derivation_path: str | None = None):
        super().__init__()
        self.message = message
        self.derivation_path = derivation_path

    def run(self):
        from seedsigner.helpers.keycard import (
            KeycardCardChangedError, KeycardPinPromptCancelled,
        )

        if not self.controller.has_any_keycard_auth():
            if not try_silent_ephemeral_pair(self):
                return Destination(ToolsKeycardPairView)

        try:
            from seedsigner.helpers.bitcoin import DEFAULT_BTC_PATH
            from seedsigner.helpers.keycard_btc_signer import sign_message as kc_sign_message
        except ImportError as exc:
            return _error_destination(_("BTC support unavailable"), str(exc))

        path = self.derivation_path or DEFAULT_BTC_PATH
        try:
            client, _unused = _open_unlocked_session_cached_or_prompt(self)
            sig_b64 = kc_sign_message(client, self.message, path)
        except KeycardPinPromptCancelled:
            return Destination(BackStackView)
        except KeycardCardChangedError:
            return Destination(ToolsKeycardPairView)
        except Exception as exc:
            logger.exception("Keycard sign_message failed")
            from seedsigner.helpers.keycard.reader import (
                NoCardError, NoReaderError,
            )
            if isinstance(exc, (NoCardError, NoReaderError)):
                # No card → subtle toast + re-enter this finalize view with
                # the same message/path so the user can insert a card and
                # retry without re-scanning.
                return _no_card_toast_or_error(
                    self, exc, default_title=_("Signing failed"),
                    stay=Destination(
                        ToolsKeycardBtcSignMessageFinalizeView,
                        view_args=dict(
                            message=self.message,
                            derivation_path=self.derivation_path,
                        ),
                    ),
                )
            title, body = classify_card_error(exc, default_title=_("Signing failed"))
            return _error_destination(title, body, return_to_main=True)

        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import GenericStaticQrEncoder

        # The 65-byte signature fits a single-frame text QR comfortably.
        encoder = GenericStaticQrEncoder(data=sig_b64)
        self.run_screen(QRDisplayScreen, qr_encoder=encoder)
        return Destination(ToolsKeycardBitcoinMenuView, clear_history=True)
