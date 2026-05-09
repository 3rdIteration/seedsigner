"""Regression test for ``SeedAddPassphraseScreen`` back-arrow behavior.

Previously, when the on-screen back arrow (top_nav) was selected,
KEY_LEFT was silently ignored. The only way to exit the keyboard was
to navigate UP to the top nav and then KEY_PRESS (joystick centre) --
not discoverable, and a Keycard user reported getting stuck on the
keyboard. KEY_LEFT on the back arrow now triggers the same "back"
return as KEY_PRESS does.
"""

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
    ]:
        sys.modules.setdefault(mod, MagicMock())

_install_hw_mocks()


class _CtxLock:
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        return False


def _build_screen_without_post_init(passphrase="hello"):
    """Construct a SeedAddPassphraseScreen without running __init__/__post_init__.

    The full init pipeline builds keyboards, fonts, and renderer state
    that would require a real PIL canvas. For this unit test we only
    need the attributes the ``_run`` loop touches before the early
    KEY_LEFT return: passphrase, hw_inputs, renderer.lock, top_nav,
    keyboard_abc.
    """
    from seedsigner.gui.screens.seed_screens import SeedAddPassphraseScreen
    screen = object.__new__(SeedAddPassphraseScreen)
    screen.passphrase = passphrase
    screen.keyboard_abc = MagicMock()
    screen.renderer = MagicMock()
    screen.renderer.lock = _CtxLock()
    screen.hw_inputs = MagicMock()
    screen.top_nav = MagicMock()
    return screen


class TestPassphraseScreenBackArrow(unittest.TestCase):
    def test_key_left_on_top_nav_returns_back(self):
        from seedsigner.hardware.buttons import HardwareButtonsConstants

        screen = _build_screen_without_post_init(passphrase="hello")
        screen.hw_inputs.wait_for.return_value = HardwareButtonsConstants.KEY_LEFT
        screen.top_nav.is_selected = True

        result = screen._run()

        self.assertIsInstance(result, dict)
        self.assertTrue(result.get("is_back_button"))
        self.assertEqual(result.get("passphrase"), "hello")

    def test_key_press_on_top_nav_still_returns_back(self):
        """The original KEY_PRESS exit path must keep working."""
        from seedsigner.hardware.buttons import HardwareButtonsConstants

        screen = _build_screen_without_post_init(passphrase="abc")
        screen.hw_inputs.wait_for.return_value = HardwareButtonsConstants.KEY_PRESS
        screen.top_nav.is_selected = True

        result = screen._run()

        self.assertIsInstance(result, dict)
        self.assertTrue(result.get("is_back_button"))
        self.assertEqual(result.get("passphrase"), "abc")


if __name__ == "__main__":
    unittest.main()
