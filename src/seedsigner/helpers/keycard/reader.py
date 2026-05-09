"""PC/SC reader discovery and connection helpers for Keycard.

Uses ``CardRequest.waitforcard()`` (event-based, ``SCardGetStatusChange``
under the hood) to wait for any reader to report a card -- the same
primitive ``keycard-cli`` and ``keycard-shell`` use. This handles
multi-slot readers (ID-1 + ID-000/SIM) without polling.

Multi-source notes
------------------
The device shares its smartcard reader between several consumers:
``Satochip_Connector`` (pysatochip), the GPG ``scdaemon`` (which polls
any inserted card), and this Keycard module. pyscard's PC/SC layer
issues exclusive ``SCardConnect`` handles, so a Keycard ``connect()``
fails with ``CardConnectionException("card not connected")`` whenever
another consumer is currently holding the slot. ``release_other_smartcard_holders``
mirrors the existing pattern in ``helpers.seedkeeper_utils.disconnect_smartcard_connections``
and is called once at the start of every Keycard flow.
"""

from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)


class NoReaderError(Exception):
    pass


class NoCardError(Exception):
    pass


def list_readers():
    from smartcard.System import readers as _readers
    return list(_readers())


def release_other_smartcard_holders(controller=None) -> None:
    """Release the PC/SC reader from other in-process / system holders.

    Mirrors ``helpers.seedkeeper_utils.disconnect_smartcard_connections``.
    Without this, the GPG ``scdaemon`` (which polls any present card on a
    short interval) and a stale ``Satochip_Connector`` keep the reader
    locked and our ``connect()`` fails with
    ``CardConnectionException("card not connected")`` even though a card
    is physically inserted.

    Best-effort: every step is wrapped in ``except Exception`` because
    the call lives on the hot path of every Keycard operation; a missing
    ``gpgconf`` or an already-disconnected Satochip must not break us.
    """
    if controller is not None:
        try:
            conn = getattr(controller, "Satochip_Connector", None)
            if conn is not None:
                try:
                    conn.card_disconnect()
                except Exception:
                    pass
                try:
                    controller.Satochip_Connector = None
                except Exception:
                    pass
        except Exception:
            pass

    try:
        from subprocess import run
        # Kill the GPG scdaemon. We deliberately do NOT relaunch it: scdaemon
        # polls any inserted card on a short interval and grabs the exclusive
        # PC/SC handle, which makes our subsequent connect() fail with
        # CardConnectionException("card not connected") even when the card is
        # physically present. gpg-agent will respawn scdaemon on demand the
        # next time GPG actually needs it.
        run(["gpgconf", "--kill", "scdaemon"], check=False)
    except Exception:
        pass

    if controller is not None:
        try:
            from seedsigner.models.settings import Settings
            from seedsigner.models.settings_definition import SettingsConstants
            scinterface = Settings.get_instance().get_value(
                SettingsConstants.SETTING__SMARTCARD_INTERFACES
            )
            if scinterface and "pn532" in scinterface:
                try:
                    from subprocess import run
                    run(["ifdnfc-activate", "yes"], check=False)
                except Exception:
                    pass
        except Exception:
            pass


def wait_for_card(timeout_s: float = 15.0):
    """Block until any attached reader detects a card, or time out.

    Event-driven via PC/SC ``SCardGetStatusChange`` -- watches all
    readers simultaneously, so multi-slot hardware works out of the
    box. Raises :class:`NoReaderError` when no reader is attached and
    :class:`NoCardError` when the timeout elapses or every retry of
    ``connect()`` fails.

    Retries ``connect()`` over the full ``timeout_s`` budget with a
    300 ms backoff. Each retry re-arms ``waitforcard()`` so a card that
    is repeatedly in/out of the slot is also handled.
    """
    from smartcard.CardRequest import CardRequest
    from smartcard.CardType import AnyCardType
    from smartcard.Exceptions import (
        CardConnectionException,
        CardRequestTimeoutException,
        NoCardException,
    )

    if not list_readers():
        raise NoReaderError("no smart card readers found")

    deadline = time.time() + timeout_s
    last_exc = None

    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        sub_timeout = max(0.5, remaining)
        service = None
        try:
            request = CardRequest(timeout=sub_timeout, cardType=AnyCardType())
            service = request.waitforcard()
            service.connection.connect()
            return service.connection
        except CardRequestTimeoutException:
            break
        except (CardConnectionException, NoCardException) as exc:
            last_exc = exc
            # Release the half-open PC/SC handle before retrying; otherwise
            # we accumulate zombie connections that keep the reader busy and
            # poison subsequent attempts in the same session.
            if service is not None:
                try:
                    service.connection.disconnect()
                except Exception:
                    pass
            time.sleep(0.3)

    if last_exc is not None:
        raise NoCardError("card not reachable; reseat and retry") from last_exc
    raise NoCardError(f"no card detected within {timeout_s}s")
