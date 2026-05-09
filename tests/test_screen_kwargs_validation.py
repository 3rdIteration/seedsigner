"""Static guard against the ``ButtonListScreen(status_headline=...)`` regression.

``ButtonListScreen`` is a ``@dataclass`` with no ``status_headline`` field;
only ``LargeIconStatusScreen`` (and its ``WarningScreen`` / ``ErrorScreen``
subclasses) own that kwarg. Passing it to ``ButtonListScreen`` raises
``TypeError: __init__() got an unexpected keyword argument`` at runtime,
which is exactly the user-visible crash the stealth menu and the sign-eth
overview hit in production.

This test asserts the field topology so a copy-paste of the wrong screen
class is caught by CI rather than by a hardware run.
"""

from __future__ import annotations

import dataclasses
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
        "smartcard", "smartcard.System", "smartcard.CardRequest",
        "smartcard.CardType", "smartcard.Exceptions",
        "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
    ]:
        sys.modules.setdefault(mod, MagicMock())

_install_hw_mocks()


class TestScreenFieldTopology(unittest.TestCase):
    def test_button_list_screen_does_not_have_status_headline(self):
        from seedsigner.gui.screens.screen import ButtonListScreen

        field_names = {f.name for f in dataclasses.fields(ButtonListScreen)}
        self.assertNotIn(
            "status_headline", field_names,
            "ButtonListScreen must not gain a status_headline field — that "
            "kwarg belongs to LargeIconStatusScreen and its subclasses.",
        )

    def test_large_icon_status_screen_has_status_headline(self):
        from seedsigner.gui.screens.screen import LargeIconStatusScreen

        field_names = {f.name for f in dataclasses.fields(LargeIconStatusScreen)}
        self.assertIn("status_headline", field_names)
        self.assertIn("text", field_names)

    def test_passing_status_headline_to_button_list_screen_raises_type_error(self):
        from seedsigner.gui.screens.screen import ButtonListScreen, ButtonOption

        with self.assertRaises(TypeError) as ctx:
            ButtonListScreen(
                title="x",
                button_data=[ButtonOption("OK")],
                status_headline=None,
            )
        self.assertIn("status_headline", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
