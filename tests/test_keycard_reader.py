"""Unit tests for ``helpers/keycard/reader.py``.

Verifies that ``wait_for_card`` uses ``CardRequest.waitforcard()`` --
the same event-driven primitive (PC/SC ``SCardGetStatusChange``) that
``keycard-cli`` and ``keycard-shell`` use for multi-reader card
detection. This avoids the prior polling loop, which was prone to
missing inserts on the 200 ms gap and caused user-visible "Card not
reachable" errors on devices with multiple slots.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def _install_hw_mocks():
    for mod in [
        "RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
        "smartcard", "smartcard.System", "smartcard.CardRequest",
        "smartcard.CardType", "smartcard.Exceptions",
        "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
    ]:
        sys.modules.setdefault(mod, MagicMock())

_install_hw_mocks()


class _FakeTimeoutException(Exception):
    pass


class TestWaitForCard(unittest.TestCase):
    def test_uses_card_request_and_returns_connection(self):
        """``CardRequest.waitforcard()`` is the canonical multi-reader wait.

        The connection returned must be the one inside the ``CardService``,
        and ``connect()`` must be called on it before returning so the
        caller gets a ready-to-transmit handle.
        """
        from seedsigner.helpers.keycard import reader

        connection = MagicMock(name="connection")
        service = MagicMock(name="service")
        service.connection = connection
        request = MagicMock(name="request")
        request.waitforcard.return_value = service

        # CardRequest is constructed inside the function -- patch the class.
        fake_card_request_module = MagicMock()
        fake_card_request_module.CardRequest = MagicMock(return_value=request)
        fake_card_type_module = MagicMock()
        fake_exceptions_module = MagicMock()
        fake_exceptions_module.CardRequestTimeoutException = _FakeTimeoutException

        with patch.dict(sys.modules, {
            "smartcard.CardRequest": fake_card_request_module,
            "smartcard.CardType": fake_card_type_module,
            "smartcard.Exceptions": fake_exceptions_module,
        }), patch.object(reader, "list_readers", return_value=[MagicMock()]):
            returned = reader.wait_for_card(timeout_s=7.5)

        self.assertIs(returned, connection)
        connection.connect.assert_called_once_with()
        request.waitforcard.assert_called_once_with()
        # Timeout must be propagated to CardRequest.
        kwargs = fake_card_request_module.CardRequest.call_args.kwargs
        self.assertEqual(kwargs.get("timeout"), 7.5)

    def test_raises_no_reader_when_none_attached(self):
        from seedsigner.helpers.keycard import reader

        with patch.object(reader, "list_readers", return_value=[]):
            with self.assertRaises(reader.NoReaderError):
                reader.wait_for_card(timeout_s=1.0)

    def test_translates_timeout_exception_to_no_card_error(self):
        from seedsigner.helpers.keycard import reader

        request = MagicMock(name="request")
        request.waitforcard.side_effect = _FakeTimeoutException("timed out")

        fake_card_request_module = MagicMock()
        fake_card_request_module.CardRequest = MagicMock(return_value=request)
        fake_card_type_module = MagicMock()
        fake_exceptions_module = MagicMock()
        fake_exceptions_module.CardRequestTimeoutException = _FakeTimeoutException

        with patch.dict(sys.modules, {
            "smartcard.CardRequest": fake_card_request_module,
            "smartcard.CardType": fake_card_type_module,
            "smartcard.Exceptions": fake_exceptions_module,
        }), patch.object(reader, "list_readers", return_value=[MagicMock()]):
            with self.assertRaises(reader.NoCardError):
                reader.wait_for_card(timeout_s=0.1)


if __name__ == "__main__":
    unittest.main()
