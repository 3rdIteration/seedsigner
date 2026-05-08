"""PC/SC reader discovery and connection helpers for Keycard."""

from __future__ import annotations

import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


class NoReaderError(Exception):
    pass


class NoCardError(Exception):
    pass


def list_readers():
    from smartcard.System import readers as _readers
    return list(_readers())


def wait_for_card(timeout_s: float = 5.0, poll_interval: float = 0.2):
    """Connect to the first reader that has a card present, or time out."""
    deadline = time.time() + timeout_s
    last_error: Optional[Exception] = None

    while time.time() < deadline:
        readers = list_readers()
        if not readers:
            last_error = NoReaderError("no smart card readers found")
            time.sleep(poll_interval)
            continue
        for reader in readers:
            try:
                conn = reader.createConnection()
                conn.connect()
                return conn
            except Exception as exc:
                last_error = exc
                continue
        time.sleep(poll_interval)
    if last_error is not None:
        raise NoCardError(f"no card detected within {timeout_s}s: {last_error}")
    raise NoCardError(f"no card detected within {timeout_s}s")
