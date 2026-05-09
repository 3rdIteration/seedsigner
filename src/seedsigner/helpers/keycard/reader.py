"""PC/SC reader discovery and connection helpers for Keycard.

Uses ``CardRequest.waitforcard()`` (event-based, ``SCardGetStatusChange``
under the hood) to wait for any reader to report a card -- the same
primitive ``keycard-cli`` and ``keycard-shell`` use. This handles
multi-slot readers (ID-1 + ID-000/SIM) without polling.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class NoReaderError(Exception):
    pass


class NoCardError(Exception):
    pass


def list_readers():
    from smartcard.System import readers as _readers
    return list(_readers())


def wait_for_card(timeout_s: float = 15.0):
    """Block until any attached reader detects a card, or time out.

    Event-driven via PC/SC ``SCardGetStatusChange`` -- watches all
    readers simultaneously, so multi-slot hardware works out of the
    box. Raises :class:`NoReaderError` when no reader is attached and
    :class:`NoCardError` when the timeout elapses.
    """
    from smartcard.CardRequest import CardRequest
    from smartcard.CardType import AnyCardType
    from smartcard.Exceptions import CardRequestTimeoutException

    if not list_readers():
        raise NoReaderError("no smart card readers found")

    try:
        request = CardRequest(timeout=timeout_s, cardType=AnyCardType())
        service = request.waitforcard()
    except CardRequestTimeoutException as exc:
        raise NoCardError(f"no card detected within {timeout_s}s") from exc

    service.connection.connect()
    return service.connection
