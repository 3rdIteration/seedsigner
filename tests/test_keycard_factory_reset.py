"""Tests for the FACTORY_RESET APDU and the wrapping client method."""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def _install_hw_mocks():
    for mod in [
        "RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
        "smartcard", "smartcard.System", "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
        "periphery",
    ]:
        sys.modules.setdefault(mod, MagicMock())


_install_hw_mocks()


class TestFactoryResetApdu(unittest.TestCase):
    def test_apdu_byte_layout(self):
        from seedsigner.helpers.keycard.commands import (
            CLA_PROPRIETARY, INS_FACTORY_RESET,
            FACTORY_RESET_P1_MAGIC, FACTORY_RESET_P2_MAGIC,
            factory_reset,
        )
        apdu = factory_reset()
        self.assertEqual(apdu[0], CLA_PROPRIETARY)
        self.assertEqual(apdu[1], INS_FACTORY_RESET)
        self.assertEqual(apdu[2], FACTORY_RESET_P1_MAGIC)
        self.assertEqual(apdu[3], FACTORY_RESET_P2_MAGIC)
        # No data, no Le.
        self.assertEqual(len(apdu), 4)

    def test_constants_match_status_keycard_spec(self):
        """The magic constants and INS code are part of the on-card
        protocol — changing them silently would brick existing cards."""
        from seedsigner.helpers.keycard import commands
        self.assertEqual(commands.INS_FACTORY_RESET, 0xFD)
        self.assertEqual(commands.FACTORY_RESET_P1_MAGIC, 0xAA)
        self.assertEqual(commands.FACTORY_RESET_P2_MAGIC, 0x55)


class TestFactoryResetClientMethod(unittest.TestCase):
    def test_happy_path_transmits_apdu_and_returns(self):
        from seedsigner.helpers.keycard.client import KeycardClient
        from seedsigner.helpers.keycard.commands import factory_reset

        connection = MagicMock()
        connection.transmit.return_value = ([], 0x90, 0x00)

        client = KeycardClient(connection)
        client.factory_reset()  # should not raise

        connection.transmit.assert_called_once_with(factory_reset())

    def test_unsupported_applet_raises_apdu_error(self):
        from seedsigner.helpers.keycard.client import KeycardClient
        from seedsigner.helpers.keycard.commands import APDUError

        connection = MagicMock()
        connection.transmit.return_value = ([], 0x6D, 0x00)  # INS not supported

        client = KeycardClient(connection)
        with self.assertRaises(APDUError) as ctx:
            client.factory_reset()
        self.assertEqual(ctx.exception.sw, 0x6D00)


if __name__ == "__main__":
    unittest.main()
