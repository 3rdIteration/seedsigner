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


def _make_reader_mock(name):
    """Build a fake pyscard Reader with a unique createConnection result."""
    fake_reader = MagicMock(name=f"reader[{name}]")
    fake_reader.name = name
    fake_reader.createConnection.return_value = MagicMock(
        name=f"connection[{name}]"
    )
    return fake_reader


class TestWaitForCard(unittest.TestCase):
    def test_returns_a_fresh_connection_built_on_the_detected_reader(self):
        """``CardRequest.waitforcard()`` is the canonical multi-reader wait.

        We then build our OWN connection on the detected reader (instead of
        returning ``service.connection``) so the lifetime of its PC/SC
        hcontext is owned by the caller, not by the about-to-be-GC'd
        ``CardRequest``. Without this, the caller's first ``transmit()``
        raises ``CardConnectionException("Card not connected")``.
        """
        from seedsigner.helpers.keycard import reader

        # service.connection only tells us which reader to use; we don't
        # use the connection itself.
        service_connection = MagicMock(name="service_connection")
        service_connection.getReader.return_value = "MyReader 00 00"
        service = MagicMock(name="service")
        service.connection = service_connection
        request = MagicMock(name="request")
        request.waitforcard.return_value = service

        target_reader = _make_reader_mock("MyReader 00 00")
        other_reader = _make_reader_mock("OtherReader 00 00")

        fake_card_request_module = MagicMock()
        fake_card_request_module.CardRequest = MagicMock(return_value=request)
        fake_card_type_module = MagicMock()
        fake_exceptions_module = MagicMock()
        fake_exceptions_module.CardRequestTimeoutException = _FakeTimeoutException

        with patch.dict(sys.modules, {
            "smartcard.CardRequest": fake_card_request_module,
            "smartcard.CardType": fake_card_type_module,
            "smartcard.Exceptions": fake_exceptions_module,
        }), patch.object(
            reader, "list_readers",
            return_value=[other_reader, target_reader],
        ):
            returned = reader.wait_for_card(timeout_s=7.5)

        # The returned object must be the connection from the detected
        # reader, NOT the one inside the CardService.
        self.assertIs(returned, target_reader.createConnection.return_value)
        self.assertIsNot(returned, service_connection)
        target_reader.createConnection.assert_called_once_with()
        returned.connect.assert_called_once_with()
        # We do not connect or use service.connection.
        service_connection.connect.assert_not_called()
        # Other readers are left alone.
        other_reader.createConnection.assert_not_called()
        # Timeout must be propagated to CardRequest.
        kwargs = fake_card_request_module.CardRequest.call_args.kwargs
        self.assertAlmostEqual(kwargs.get("timeout"), 7.5, places=1)

    def test_raises_no_card_when_detected_reader_vanishes(self):
        """If the reader name from waitforcard isn't in list_readers() any
        more (hot-unplug between detect and connect), surface NoCardError
        instead of crashing on next(StopIteration)."""
        from seedsigner.helpers.keycard import reader

        service_connection = MagicMock(name="service_connection")
        service_connection.getReader.return_value = "GhostReader 00 00"
        service = MagicMock(name="service")
        service.connection = service_connection
        request = MagicMock(name="request")
        request.waitforcard.return_value = service

        fake_card_request_module = MagicMock()
        fake_card_request_module.CardRequest = MagicMock(return_value=request)
        fake_card_type_module = MagicMock()
        fake_exceptions_module = MagicMock()
        fake_exceptions_module.CardRequestTimeoutException = _FakeTimeoutException
        fake_exceptions_module.CardConnectionException = _FakeCardConnectionException
        fake_exceptions_module.NoCardException = _FakeNoCardException

        # First list_readers call (gate at top of wait_for_card) sees a
        # reader; subsequent call inside the loop returns an empty list,
        # simulating hot-unplug.
        time_seq = iter([0.0, 0.0, 0.1, 0.2, 99.9, 99.9])
        with patch.dict(sys.modules, {
            "smartcard.CardRequest": fake_card_request_module,
            "smartcard.CardType": fake_card_type_module,
            "smartcard.Exceptions": fake_exceptions_module,
        }), patch.object(
            reader, "list_readers",
            side_effect=[[MagicMock()], [], [], [], []],
        ), patch.object(reader.time, "sleep"), \
                patch.object(reader.time, "time", side_effect=lambda: next(time_seq)):
            with self.assertRaises(reader.NoCardError):
                reader.wait_for_card(timeout_s=5.0)

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

        # Two attempts -> two distinct connection objects from the same Reader.
        bad_connection = MagicMock(name="bad_connection")
        bad_connection.connect.side_effect = _FakeCardConnectionException("contention")
        good_connection = MagicMock(name="good_connection")

        target_reader = MagicMock(name="target_reader")
        target_reader.name = "Reader 00 00"
        target_reader.createConnection.side_effect = [
            bad_connection, good_connection,
        ]

        # service.connection only used for getReader() — we drop the rest.
        service_connection = MagicMock(name="service_connection")
        service_connection.getReader.return_value = "Reader 00 00"
        service = MagicMock(name="service")
        service.connection = service_connection
        request = MagicMock(name="request")
        request.waitforcard.return_value = service

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
        }), patch.object(reader, "list_readers", return_value=[target_reader]), \
                patch.object(reader.time, "sleep"):
            returned = reader.wait_for_card(timeout_s=5.0)

        self.assertIs(returned, good_connection)
        self.assertEqual(target_reader.createConnection.call_count, 2)
        # First (failed) connection must have been disconnected before retry.
        bad_connection.disconnect.assert_called()

    def test_raises_no_card_when_connect_keeps_failing(self):
        """If ``connect()`` keeps raising until the deadline elapses, the
        reader translates the underlying pyscard error into our friendly
        ``NoCardError`` instead of leaking the raw text."""
        from seedsigner.helpers.keycard import reader

        bad_connection = MagicMock(name="bad_connection")
        bad_connection.connect.side_effect = _FakeCardConnectionException("nope")

        target_reader = MagicMock(name="target_reader")
        target_reader.name = "Reader 00 00"
        target_reader.createConnection.return_value = bad_connection

        service_connection = MagicMock(name="service_connection")
        service_connection.getReader.return_value = "Reader 00 00"
        service = MagicMock(name="service")
        service.connection = service_connection
        request = MagicMock(name="request")
        request.waitforcard.return_value = service

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
        }), patch.object(reader, "list_readers", return_value=[target_reader]), \
                patch.object(reader.time, "sleep"), \
                patch.object(reader.time, "time", side_effect=lambda: next(time_seq)):
            with self.assertRaises(reader.NoCardError):
                reader.wait_for_card(timeout_s=5.0)


class TestReleaseOtherSmartcardHolders(unittest.TestCase):
    def test_disconnects_satochip_and_kills_scdaemon(self):
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
        # We deliberately do NOT relaunch scdaemon: it would race for the
        # PC/SC exclusive lock and break our subsequent connect().
        self.assertEqual(len(launch_calls), 0)

    def test_no_op_when_no_satochip_present(self):
        from seedsigner.helpers.keycard import reader

        controller = MagicMock(name="controller")
        controller.Satochip_Connector = None

        with patch("subprocess.run"):
            reader.release_other_smartcard_holders(controller)


if __name__ == "__main__":
    unittest.main()
