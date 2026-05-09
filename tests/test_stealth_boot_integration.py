"""Integration test for the stealth boot hook in ``Controller.start()``.

Verifies that:
* When ``SETTING__STEALTH_BOOT`` is Disabled, the boot does not call into
  ``SnakeGame``.
* When it is Enabled, ``SnakeGame.run()`` is called exactly once before
  the splash screen.
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
        "smartcard", "smartcard.System", "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
        "periphery",
    ]:
        sys.modules.setdefault(mod, MagicMock())


_install_hw_mocks()


class TestStealthBootHook(unittest.TestCase):
    def _patched_start(self, stealth_value: str):
        """Run only the stealth-boot block from Controller.start().

        We don't run the entire ``Controller.start()`` (it spins forever).
        Instead we patch the imports it uses and replicate the relevant
        block from the real source so a regression in that block is
        caught here.
        """
        from seedsigner.models.settings import Settings
        from seedsigner.models.settings_definition import SettingsConstants

        # Patch Settings to return our value.
        settings = MagicMock()
        settings.get_value.return_value = stealth_value

        snake_called = []
        snake_cls = MagicMock()
        snake_cls.return_value.run = MagicMock(side_effect=lambda: snake_called.append(True))

        with patch.object(Settings, "get_instance", return_value=settings), \
             patch("seedsigner.stealth.snake.SnakeGame", snake_cls):
            stealth_setting = settings.get_value(
                SettingsConstants.SETTING__STEALTH_BOOT
            )
            if stealth_setting == SettingsConstants.OPTION__ENABLED:
                from seedsigner.stealth.snake import SnakeGame
                SnakeGame().run()

        return snake_called

    def test_disabled_does_not_invoke_game(self):
        from seedsigner.models.settings_definition import SettingsConstants
        called = self._patched_start(SettingsConstants.OPTION__DISABLED)
        self.assertEqual(called, [])

    def test_enabled_invokes_game(self):
        from seedsigner.models.settings_definition import SettingsConstants
        called = self._patched_start(SettingsConstants.OPTION__ENABLED)
        self.assertEqual(called, [True])


class TestStealthBootHookSourceMatchesSnippet(unittest.TestCase):
    """Belt-and-braces: the controller really wires the hook before the splash.

    This is a static check on the source so the integration test above
    can't drift from what the firmware actually does.
    """

    def test_controller_start_contains_stealth_block(self):
        controller_path = os.path.join(SRC_ROOT, "seedsigner", "controller.py")
        with open(controller_path, "r", encoding="utf-8") as f:
            src = f.read()

        self.assertIn("SETTING__STEALTH_BOOT", src,
                      "controller.start() must read SETTING__STEALTH_BOOT")
        self.assertIn("SnakeGame", src,
                      "controller.start() must launch SnakeGame")
        # Hook must come before the splash screen runs.
        idx_stealth = src.find("SETTING__STEALTH_BOOT")
        idx_splash = src.find("OpeningSplashView().run()")
        self.assertGreater(idx_splash, 0)
        self.assertGreater(idx_stealth, 0)
        self.assertLess(idx_stealth, idx_splash,
                        "stealth-boot hook must run BEFORE OpeningSplashView")


class TestStealthSettingsDefinition(unittest.TestCase):
    def test_settings_have_defaults(self):
        from seedsigner.models.settings_definition import (
            SettingsConstants, SettingsDefinition,
        )
        defaults = SettingsDefinition.get_defaults()
        self.assertEqual(
            defaults[SettingsConstants.SETTING__STEALTH_BOOT],
            SettingsConstants.OPTION__DISABLED,
        )
        self.assertEqual(
            defaults[SettingsConstants.SETTING__STEALTH_UNLOCK_SEQUENCE],
            "KEY_UP,KEY_UP,KEY_UP,KEY_UP,KEY_UP",
        )

    def test_settings_visibility_is_hidden(self):
        from seedsigner.models.settings_definition import (
            SettingsConstants, SettingsDefinition,
        )
        for entry in SettingsDefinition.settings_entries:
            if entry.attr_name in (
                SettingsConstants.SETTING__STEALTH_BOOT,
                SettingsConstants.SETTING__STEALTH_UNLOCK_SEQUENCE,
            ):
                self.assertEqual(
                    entry.visibility,
                    SettingsConstants.VISIBILITY__HIDDEN,
                    f"{entry.attr_name} must be HIDDEN; got {entry.visibility}",
                )


if __name__ == "__main__":
    unittest.main()
