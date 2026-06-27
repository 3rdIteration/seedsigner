"""Card-applet probe used by the Cards top-level menu.

Each app View (Keycard / SeedKeeper) calls :func:`probe_card` on entry
to decide whether to show its menu, route to the setup wizard, or snap
back to MainMenu with a "No card" toast. The probe is intentionally
cheap (single SELECT + at most one GET STATUS) and never prompts for
a PIN — the view layer is responsible for the next step.

Threat model: no seed material flows here. ``probe_card`` touches no
controller state; ``run_card_gate`` records only the **non-secret** active
AID→instance-UID mapping (so display can resolve instance names) and no
secret/auth state. The probe opens its own connection and releases it before
returning so the active session for each app remains the source of truth for
ongoing ops.

The :func:`run_card_gate` helper wraps the probe + branching logic so
each app View can call a single function on entry.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from gettext import gettext as _
from typing import Literal, Optional

logger = logging.getLogger(__name__)


CardKind = Literal["keycard", "seedkeeper"]


# Cleartext AIDs we SELECT-probe to enumerate installed applets. Keycard
# uses a stable package prefix + 1-byte instance suffix; cards initialised
# by keycard-shell may live at any suffix in 0x01..0x0F (matches the range
# autodetected by `select_with_autodetect`).
APPLET_AID_SEEDKEEPER = bytes([0x53, 0x65, 0x65, 0x64, 0x4b, 0x65, 0x65, 0x70, 0x65, 0x72])  # "SeedKeeper"


@dataclass
class ProbeResult:
    """Outcome of probing the reader for a specific applet kind."""

    present: bool                       # any card in any reader
    kind_match: bool                    # requested applet selected OK
    initialised: bool                   # PIN / master key already configured
    instance_uid: Optional[bytes] = None
    app_version: Optional[int] = None   # Keycard only
    detail: Optional[str] = None        # diagnostic, may be shown in UI


@dataclass
class CardInstalledState:
    """Which of the supported applets are installed on the inserted card."""

    present: bool                       # any card detected at all
    keycard_installed: bool
    seedkeeper_installed: bool


def probe_card(kind: CardKind, controller, timeout_s: float = 1.5) -> ProbeResult:
    """Probe the inserted card for the requested applet kind.

    Returns a :class:`ProbeResult`; never raises. Reader-level failures
    map to ``present=False`` with ``detail`` populated.
    """
    if kind == "keycard":
        return _probe_keycard(controller, timeout_s=timeout_s)
    if kind == "seedkeeper":
        return _probe_seedkeeper(controller, timeout_s=timeout_s)
    raise ValueError(f"unknown card kind: {kind!r}")


# ---------------------------------------------------------------------------
# Keycard
# ---------------------------------------------------------------------------


def _probe_keycard(controller, timeout_s: float) -> ProbeResult:
    try:
        from seedsigner.helpers.keycard.client import KeycardClient
        from seedsigner.helpers.keycard.reader import (
            NoCardError, NoReaderError, list_readers,
            release_other_smartcard_holders, wait_for_card,
        )
        from seedsigner.helpers.keycard.ui_helpers import select_with_autodetect
    except ImportError as exc:
        return ProbeResult(False, False, False, detail=str(exc))

    if not list_readers():
        return ProbeResult(False, False, False, detail="No reader attached")

    connection = None
    try:
        release_other_smartcard_holders(controller)
        try:
            connection = wait_for_card(timeout_s=timeout_s)
        except NoReaderError as exc:
            return ProbeResult(False, False, False, detail=str(exc))
        except NoCardError:
            return ProbeResult(False, False, False, detail="No card detected")

        client = KeycardClient(connection)
        try:
            info = select_with_autodetect(client, controller)
        except Exception as exc:
            # SELECT failed — likely not a Keycard at all (e.g. SW=0x6A82
            # exhausted). The card is present, but the applet isn't.
            logger.debug("Keycard SELECT failed: %s", exc)
            return ProbeResult(True, False, False, detail="Not a Keycard")

        return ProbeResult(
            present=True,
            kind_match=True,
            initialised=(info.app_version != 0),
            instance_uid=bytes(info.instance_uid) if info.instance_uid else None,
            app_version=info.app_version,
            detail=None if info.app_version != 0 else "Applet not initialised",
        )
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# SeedKeeper (pysatochip)
# ---------------------------------------------------------------------------


def _probe_seedkeeper(controller, timeout_s: float) -> ProbeResult:
    try:
        from pysatochip.CardConnector import CardConnector
    except Exception as exc:  # pragma: no cover — only fires when lib missing
        return ProbeResult(False, False, False, detail=str(exc))

    try:
        from seedsigner.helpers.keycard.reader import (
            list_readers, release_other_smartcard_holders,
        )
        if not list_readers():
            return ProbeResult(False, False, False, detail="No reader attached")
        release_other_smartcard_holders(controller)
    except Exception:
        # Reader-list utilities are best-effort; carry on and let
        # CardConnector decide.
        pass

    connector = None
    try:
        try:
            connector = CardConnector(card_filter=["seedkeeper"])
        except Exception as exc:
            # Most common cause: no card / wrong applet. Treat as "wrong
            # kind" only if we can confirm a card is present at all.
            from seedsigner.helpers.keycard.reader import list_readers
            if list_readers():
                return ProbeResult(True, False, False, detail=str(exc))
            return ProbeResult(False, False, False, detail=str(exc))

        # Short polling loop: pysatochip occasionally returns empty
        # status on the first call after connect. One retry is enough.
        status = None
        for _ in range(2):
            try:
                status = connector.card_get_status()
                if status and len(status) > 3 and status[3]:
                    break
            except Exception as exc:
                logger.debug("card_get_status failed: %s", exc)
                status = None

        if not status or len(status) <= 3 or not status[3]:
            return ProbeResult(True, False, False, detail="No applet response")

        status_dict = status[3]
        initialised = bool(status_dict.get("setup_done", False))
        uid_hex = getattr(connector, "UID_SHA1", None)
        instance_uid = bytes.fromhex(uid_hex) if isinstance(uid_hex, str) else None
        return ProbeResult(
            present=True,
            kind_match=True,
            initialised=initialised,
            instance_uid=instance_uid,
            detail=None if initialised else "Applet not initialised",
        )
    finally:
        if connector is not None:
            try:
                connector.card_disconnect()
            except Exception:
                pass
            # pysatochip's card_disconnect() leaves the connector's
            # RemovalObserver on pyscard's singleton CardMonitor; remove it
            # too, else it lingers and re-grabs the next inserted card,
            # starving a freshly-built connector across a swap. Best-effort
            # (deleteObserver raises ValueError if already removed).
            try:
                connector.cardmonitor.deleteObserver(connector.cardobserver)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Gate helper (used by app views)
# ---------------------------------------------------------------------------


def run_card_gate(view, kind: CardKind, *, title: str, setup_view):
    """Probe → branch → return a Destination, or ``None`` to mean
    "card is present, applet matches and is initialised; carry on with
    the normal menu".

    Branches:

    - **Absent**: surfaces an ``InfoToast`` ("No card — returned home")
      and redirects to ``MainMenuView`` with ``clear_history=True``. No
      intermediate "Insert card" screen; if the user wants to retry,
      they reopen the Cards menu after inserting.
    - **Wrong applet**: warning, then back to ``CardsMenuView``.
    - **Uninitialised**: routes to ``setup_view``. When the setup flow
      returns, the caller's back-stack lands back on the gated View,
      which re-probes.
    - **OK**: returns ``None`` so the caller proceeds to its menu.

    ``view`` is the calling View (used for ``run_screen`` and
    ``controller``). ``title`` is the screen header (e.g. "SeedKeeper").
    """
    from seedsigner.views.view import BackStackView, Destination, MainMenuView

    probe = probe_card(kind, view.controller)

    # Record the active instance's AID→UID mapping (public identity, not
    # secret state) so display helpers can resolve a user-assigned instance
    # name at menu-render time — the probe already SELECTed the card and holds
    # its UID, which would otherwise be unknown until the first signing op
    # (e.g. an instance name would vanish until then after a reboot). Cleared
    # on card-change like the rest of the per-card session state.
    if kind == "keycard" and probe.instance_uid:
        try:
            # Reader-independent card-swap check, reusing the SELECT the probe
            # just did (no extra card I/O): if the inserted instance differs
            # from the one we last authenticated, scrub the previous card's
            # session secrets (PINs, derived-address cache, instance names,
            # instance count) BEFORE the menu renders. Covers readers whose
            # PC/SC 'removed' event is unreliable (NFC/PN532). Runs before
            # remember_aid_for_uid because the wipe clears the AID→UID map.
            from seedsigner.helpers.keycard.ui_helpers import detect_card_swap
            detect_card_swap(view.controller, probe.instance_uid)
            view.controller.remember_aid_for_uid(
                view.controller.active_keycard_aid, probe.instance_uid,
            )
        except Exception:
            logger.debug(
                "could not record / swap-check probed keycard UID",
                exc_info=True,
            )

    if not probe.present:
        # Card was pulled (or never present) between CardsMenuView and
        # this app menu. Snap straight back to MainMenu with a toast so
        # the user is not stuck on a "please insert card" prompt.
        try:
            from seedsigner.gui.toast import InfoToast
            view.controller.activate_toast(
                InfoToast(label_text=_("No card — returned home"))
            )
        except Exception:
            logger.exception("InfoToast dispatch failed in run_card_gate")
        return Destination(MainMenuView, clear_history=True)

    if not probe.kind_match:
        # Card is present but the requested applet isn't installed.
        # Offer the install path before the user is stuck with a
        # warning-and-back dead end.
        from seedsigner.gui.screens.screen import ButtonListScreen
        from seedsigner.gui.screens.screen import ButtonOption
        install_btn = ButtonOption("Install applet")
        cancel_btn = ButtonOption("Cancel")
        selected = view.run_screen(
            ButtonListScreen,
            title=title,
            is_button_text_centered=False,
            is_bottom_list=True,
            button_data=[install_btn, cancel_btn],
        )
        from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON as _BACK
        if selected == _BACK or selected == 1:
            return Destination(BackStackView)
        # User picked Install. The dedicated install view does the
        # gp.jar handshake; on success it re-enters the gated view
        # which will then probe again and see the new applet.
        from seedsigner.views.view import CardsInstallAppletView
        return Destination(
            CardsInstallAppletView,
            view_args={"kind": kind},
            skip_current_view=True,
        )

    if not probe.initialised:
        # The setup wizard handles PIN / master-key creation. Coming
        # back from it lands on the gated View, which re-probes.
        return Destination(setup_view, skip_current_view=True)

    return None


# ---------------------------------------------------------------------------
# Installed-applet enumeration (used for Cards menu checkmarks)
# ---------------------------------------------------------------------------


def probe_installed_applets(controller, timeout_s: float = 1.5) -> CardInstalledState:
    """Enumerate which of the supported applets are installed.

    Uses cleartext ``SELECT AID`` probes so it works on any card, with
    or without default ISD keys. ``SW=0x9000`` means installed,
    ``SW=0x6A82`` (or any other error) means missing. The function
    never raises — readers without a card or without smartcard support
    return ``present=False`` and all flags ``False``.
    """
    state = CardInstalledState(False, False, False)
    try:
        from seedsigner.helpers.keycard.client import KeycardClient
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.reader import (
            NoCardError, NoReaderError, list_readers,
            release_other_smartcard_holders, wait_for_card,
        )
    except ImportError as exc:
        logger.debug("smartcard stack unavailable: %s", exc)
        return state

    if not list_readers():
        return state

    connection = None
    try:
        release_other_smartcard_holders(controller)
        try:
            connection = wait_for_card(timeout_s=timeout_s)
        except (NoReaderError, NoCardError):
            return state

        state.present = True
        client = KeycardClient(connection)

        # Keycard: probe the instance-suffix range in BOTH the 9-byte and
        # 10-byte conventions, preferring the currently-active AID first.
        # Mirrors `select_with_autodetect` (shared candidate builder) so a
        # keycard-shell-initialised card on a non-default suffix — or a
        # legacy 10-byte instance — is still flagged as installed.
        from seedsigner.helpers.keycard.global_platform import (
            keycard_instance_aid_candidates,
        )
        candidates: list[bytes] = []
        active = getattr(controller, "active_keycard_aid", None)
        if active:
            candidates.append(bytes(active))
        for candidate in keycard_instance_aid_candidates():
            if candidate not in candidates:
                candidates.append(candidate)
        for aid in candidates:
            apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid)
            try:
                client.transmit(apdu)
                state.keycard_installed = True
                break
            except APDUError:
                continue
            except Exception as exc:
                logger.debug("SELECT %s failed: %s", aid.hex(), exc)

        # SeedKeeper: single fixed AID.
        aid = APPLET_AID_SEEDKEEPER
        apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid)
        try:
            client.transmit(apdu)
            state.seedkeeper_installed = True
        except APDUError:
            pass
        except Exception as exc:
            logger.debug("SELECT %s failed: %s", aid.hex(), exc)
        return state
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                pass
