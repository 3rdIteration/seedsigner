"""Card-applet probe used by the Cards top-level menu.

Each app View (Keycard / Satochip / SeedKeeper) calls :func:`probe_card`
on entry to decide whether to show its menu, route to the setup wizard,
or fall back to the "Insert card" screen. The probe is intentionally
cheap (single SELECT + at most one GET STATUS) and never prompts for a
PIN — the view layer is responsible for the next step.

Threat model: no seed material flows here. Caches/secret state in the
controller are not touched. The probe opens its own connection and
releases it before returning so the active session for each app remains
the source of truth for ongoing ops.

The :func:`run_card_gate` helper wraps the probe + branching logic so
each app View can call a single function on entry.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal, Optional

logger = logging.getLogger(__name__)


CardKind = Literal["keycard", "satochip", "seedkeeper"]


@dataclass
class ProbeResult:
    """Outcome of probing the reader for a specific applet kind."""

    present: bool                       # any card in any reader
    kind_match: bool                    # requested applet selected OK
    initialised: bool                   # PIN / master key already configured
    instance_uid: Optional[bytes] = None
    app_version: Optional[int] = None   # Keycard only
    detail: Optional[str] = None        # diagnostic, may be shown in UI


def probe_card(kind: CardKind, controller, timeout_s: float = 1.5) -> ProbeResult:
    """Probe the inserted card for the requested applet kind.

    Returns a :class:`ProbeResult`; never raises. Reader-level failures
    map to ``present=False`` with ``detail`` populated.
    """
    if kind == "keycard":
        return _probe_keycard(controller, timeout_s=timeout_s)
    if kind in ("satochip", "seedkeeper"):
        return _probe_satochip_family(kind, controller, timeout_s=timeout_s)
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
# Satochip / SeedKeeper (pysatochip)
# ---------------------------------------------------------------------------


def _probe_satochip_family(kind: CardKind, controller, timeout_s: float) -> ProbeResult:
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
            connector = CardConnector(card_filter=[kind])
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


# ---------------------------------------------------------------------------
# Gate helper (used by app views)
# ---------------------------------------------------------------------------


def run_card_gate(view, kind: CardKind, *, title: str, setup_view):
    """Probe → branch → return a Destination, or ``None`` to mean
    "card is present, applet matches and is initialised; carry on with
    the normal menu".

    Branches:

    - **Absent**: shows :class:`CardWaitScreen`. On insert, returns a
      Destination that re-enters the caller View (so the probe runs
      again with the new card). On Cancel, returns to ``CardsMenuView``.
    - **Wrong applet**: warning, then back to ``CardsMenuView``.
    - **Uninitialised**: routes to ``setup_view``. When the setup flow
      returns, the caller's back-stack lands back on the gated View,
      which re-probes.
    - **OK**: returns ``None`` so the caller proceeds to its menu.

    ``view`` is the calling View (used for ``run_screen`` and
    ``controller``). ``title`` is the screen header (e.g. "Satochip").
    """
    from seedsigner.gui.screens.screen import (
        RET_CODE__BACK_BUTTON, RET_CODE__CARD_INSERTED, CardWaitScreen,
        WarningScreen,
    )
    from seedsigner.views.view import BackStackView, Destination

    probe = probe_card(kind, view.controller)

    if not probe.present:
        ret = view.run_screen(CardWaitScreen, title=title)
        if ret == RET_CODE__CARD_INSERTED:
            # Re-enter the calling view so the next loop probes the
            # newly inserted card.
            return Destination(view.__class__, skip_current_view=True)
        # Cancel: pop back up the stack (parent is CardsMenuView).
        return Destination(BackStackView)

    if not probe.kind_match:
        view.run_screen(
            WarningScreen,
            title=title,
            status_headline=None,
            text=f"Not a {title} card.\nInsert the right card.",
            show_back_button=True,
        )
        return Destination(BackStackView)

    if not probe.initialised:
        # The setup wizard handles PIN / master-key creation. Coming
        # back from it lands on the gated View, which re-probes.
        return Destination(setup_view, skip_current_view=True)

    return None
