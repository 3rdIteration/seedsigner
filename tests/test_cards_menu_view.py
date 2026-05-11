"""Tests for the top-level Cards menu.

Pins the 3-entry shape (SeedKeeper / Satochip / Keycard) and confirms
each entry routes to the matching app View. The legacy
``Tools > Smartcard Tools`` indirection and the ``CardManagementView``
"Initialise blank card" picker were removed once the per-app probe
took over uninstantiated-card routing.
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
        "smartcard", "smartcard.System", "smartcard.CardMonitoring",
        "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
        "periphery",
    ]:
        sys.modules.setdefault(mod, MagicMock())


_install_hw_mocks()


class TestCardsMenuShape(unittest.TestCase):
    def test_has_three_entries(self):
        from seedsigner.views.view import CardsMenuView
        labels = [
            CardsMenuView.SEEDKEEPER.button_label,
            CardsMenuView.SATOCHIP.button_label,
            CardsMenuView.KEYCARD.button_label,
        ]
        self.assertEqual(labels, ["SeedKeeper", "Satochip", "Keycard"])

    def test_legacy_classes_removed(self):
        """The Initialise blank card flow and the Tools-side mirror are
        gone — keep them gone so we don't accidentally resurrect dead
        entry points."""
        from seedsigner.views import view as view_mod
        from seedsigner.views import tools_views
        self.assertFalse(hasattr(view_mod, "CardManagementView"))
        self.assertFalse(hasattr(tools_views, "ToolsSmartcardMenuView"))


class TestCardsMenuRouting(unittest.TestCase):
    """Confirm each entry routes to the correct app View."""

    def _route(self, button_index):
        from seedsigner.views.view import CardsMenuView
        v = CardsMenuView.__new__(CardsMenuView)
        v.run_screen = MagicMock(return_value=button_index)
        return v.run()

    def test_seedkeeper_routes(self):
        from seedsigner.views.tools_views import ToolsSeedkeeperView
        dest = self._route(0)
        self.assertIs(dest.View_cls, ToolsSeedkeeperView)

    def test_satochip_routes(self):
        from seedsigner.views.tools_views import ToolsSatochipView
        dest = self._route(1)
        self.assertIs(dest.View_cls, ToolsSatochipView)

    def test_keycard_routes(self):
        from seedsigner.views.keycard_views import ToolsKeycardMenuView
        dest = self._route(2)
        self.assertIs(dest.View_cls, ToolsKeycardMenuView)


if __name__ == "__main__":
    unittest.main()
