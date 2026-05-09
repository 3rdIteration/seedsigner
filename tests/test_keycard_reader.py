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


class _FakeCardConnectionException(Exception):
    pass


class _FakeNoCardException(Exception):
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
        # Timeout must be propagated to CardRequest. The reader budget-tracks
        # the deadline, so allow a small drift from the wall clock.
        kwargs = fake_card_request_module.CardRequest.call_args.kwargs
        self.assertAlmostEqual(kwargs.get("timeout"), 7.5, places=1)

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


    def test_retries_on_card_connection_exception(self):
        """First ``connect()`` raises ``CardConnectionException`` (reader
        contention or settling); reader retries and succeeds on the second
        attempt within the timeout budget."""
        from seedsigner.helpers.keycard import reader

        good_connection = MagicMock(name="good_connection")
        bad_connection = MagicMock(name="bad_connection")
        bad_connection.connect.side_effect = _FakeCardConnectionException("contention")

        bad_service = MagicMock(name="bad_service")
        bad_service.connection = bad_connection
        good_service = MagicMock(name="good_service")
        good_service.connection = good_connection

        request = MagicMock(name="request")
        request.waitforcard.side_effect = [bad_service, good_service]

        fake_card_request_module = MagicMock()
        fake_card_request_module.CardRequest = MagicMock(return_value=request)
        fake_card_type_module = MagicMock()
        fake_exceptions_module = MagicMock()
        fake_exceptions_module.CardRequestTimeoutException = _FakeTimeoutException
        fake_exceptions_module.CardConnectionException = _FakeCardConnectionException
        fake_exceptions_module.NoCardException = _FakeNoCardException

        with patch.dict(sys.modules, {
            "smartcard.CardRequest": fake_card_request_module,
            "smartcard.CardType": fake_card_type_module,
            "smartcard.Exceptions": fake_exceptions_module,
        }), patch.object(reader, "list_readers", return_value=[MagicMock()]), \
                patch.object(reader.time, "sleep"):
            returned = reader.wait_for_card(timeout_s=5.0)

        self.assertIs(returned, good_connection)
        self.assertEqual(request.waitforcard.call_count, 2)

    def test_raises_no_card_when_connect_keeps_failing(self):
        """If ``connect()`` keeps raising until the deadline elapses, the
        reader translates the underlying pyscard error into our friendly
        ``NoCardError`` instead of leaking the raw text."""
        from seedsigner.helpers.keycard import reader

        bad_connection = MagicMock(name="bad_connection")
        bad_connection.connect.side_effect = _FakeCardConnectionException("nope")
        bad_service = MagicMock(name="bad_service")
        bad_service.connection = bad_connection

        request = MagicMock(name="request")
        request.waitforcard.return_value = bad_service

        fake_card_request_module = MagicMock()
        fake_card_request_module.CardRequest = MagicMock(return_value=request)
        fake_card_type_module = MagicMock()
        fake_exceptions_module = MagicMock()
        fake_exceptions_module.CardRequestTimeoutException = _FakeTimeoutException
        fake_exceptions_module.CardConnectionException = _FakeCardConnectionException
        fake_exceptions_module.NoCardException = _FakeNoCardException

        # Drive the loop by advancing fake time past the deadline after a
        # couple of iterations, so the test is deterministic and quick.
        time_seq = iter([0.0, 0.0, 0.1, 0.2, 99.9, 99.9])
        with patch.dict(sys.modules, {
            "smartcard.CardRequest": fake_card_request_module,
            "smartcard.CardType": fake_card_type_module,
            "smartcard.Exceptions": fake_exceptions_module,
        }), patch.object(reader, "list_readers", return_value=[MagicMock()]), \
                patch.object(reader.time, "sleep"), \
                patch.object(reader.time, "time", side_effect=lambda: next(time_seq)):
            with self.assertRaises(reader.NoCardError):
                reader.wait_for_card(timeout_s=5.0)


class TestReleaseOtherSmartcardHolders(unittest.TestCase):
    def test_disconnects_satochip_and_kicks_scdaemon(self):
        from seedsigner.helpers.keycard import reader

        controller = MagicMock(name="controller")
        connector = MagicMock(name="Satochip_Connector")
        controller.Satochip_Connector = connector

        with patch("subprocess.run") as mock_run:
            reader.release_other_smartcard_holders(controller)

        connector.card_disconnect.assert_called_once_with()
        self.assertIsNone(controller.Satochip_Connector)
        kill_calls = [
            c for c in mock_run.call_args_list
            if c.args and c.args[0][:2] == ["gpgconf", "--kill"]
        ]
        launch_calls = [
            c for c in mock_run.call_args_list
            if c.args and c.args[0][:2] == ["gpgconf", "--launch"]
        ]
        self.assertEqual(len(kill_calls), 1)
        self.assertEqual(len(launch_calls), 1)

    def test_no_op_when_no_satochip_present(self):
        from seedsigner.helpers.keycard import reader

        controller = MagicMock(name="controller")
        controller.Satochip_Connector = None

        with patch("subprocess.run"):
            reader.release_other_smartcard_holders(controller)


if __name__ == "__main__":
    unittest.main()
