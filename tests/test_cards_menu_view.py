"""Tests for the top-level Cards menu.

Pins the 4-entry shape (SeedKeeper / Satochip / Keycard / Factory
Reset), confirms install-state checkmarks render, and that each entry
routes to the correct destination. The legacy
``Tools > Smartcard Tools`` indirection and the ``CardManagementView``
"Initialise blank card" picker were removed once the per-app probe
took over uninstantiated-card routing.
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
        "smartcard", "smartcard.System", "smartcard.CardMonitoring",
        "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
        "periphery",
    ]:
        sys.modules.setdefault(mod, MagicMock())


_install_hw_mocks()


def _make_view():
    """Build a CardsMenuView without going through ``View.__init__``."""
    from seedsigner.views.view import CardsMenuView
    v = CardsMenuView.__new__(CardsMenuView)
    v.controller = MagicMock()
    return v


def _absent_state():
    from seedsigner.helpers.card_probe import CardInstalledState
    return CardInstalledState(False, False, False, False)


def _present_state(**flags):
    from seedsigner.helpers.card_probe import CardInstalledState
    return CardInstalledState(
        True,
        flags.get("keycard", False),
        flags.get("satochip", False),
        flags.get("seedkeeper", False),
    )


class TestCardsMenuShape(unittest.TestCase):
    def test_labels(self):
        from seedsigner.views.view import CardsMenuView
        self.assertEqual(CardsMenuView.SEEDKEEPER_LABEL, "SeedKeeper")
        self.assertEqual(CardsMenuView.SATOCHIP_LABEL, "Satochip")
        self.assertEqual(CardsMenuView.KEYCARD_LABEL, "Keycard")
        self.assertEqual(CardsMenuView.FACTORY_RESET_LABEL, "Factory reset card")

    def test_legacy_classes_removed(self):
        from seedsigner.views import view as view_mod
        from seedsigner.views import tools_views
        self.assertFalse(hasattr(view_mod, "CardManagementView"))
        self.assertFalse(hasattr(tools_views, "ToolsSmartcardMenuView"))


class TestCardsMenuRendering(unittest.TestCase):
    """The menu must show 4 entries and only render checkmarks when a
    card is actually present."""

    def _run_and_capture(self, state, selected_index):
        v = _make_view()
        captured = {}

        def fake_run_screen(_screen_cls, **kwargs):
            captured["button_data"] = kwargs["button_data"]
            return selected_index

        v.run_screen = fake_run_screen
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=state,
        ):
            dest = v.run()
        return dest, captured["button_data"]

    def test_no_card_no_checkmarks(self):
        _, buttons = self._run_and_capture(_absent_state(), selected_index=0)
        self.assertEqual(len(buttons), 4)
        # First three should have no right icon when card is absent.
        for b in buttons[:3]:
            self.assertIsNone(b.right_icon_name)

    def test_present_card_renders_checkmarks(self):
        from seedsigner.gui.components import SeedSignerIconConstants
        _, buttons = self._run_and_capture(
            _present_state(keycard=True, satochip=False, seedkeeper=True),
            selected_index=0,
        )
        labels = [b.button_label for b in buttons]
        self.assertEqual(
            labels, ["SeedKeeper", "Satochip", "Keycard", "Factory reset card"],
        )
        # Order is SeedKeeper, Satochip, Keycard.
        self.assertEqual(buttons[0].right_icon_name, SeedSignerIconConstants.CHECK)
        self.assertEqual(buttons[1].right_icon_name, SeedSignerIconConstants.CHECKBOX)
        self.assertEqual(buttons[2].right_icon_name, SeedSignerIconConstants.CHECK)


class TestCardsMenuRouting(unittest.TestCase):
    """Confirm each entry routes to the correct destination."""

    def _route(self, button_index):
        v = _make_view()
        v.run_screen = MagicMock(return_value=button_index)
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=_absent_state(),
        ):
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

    def test_factory_reset_routes(self):
        from seedsigner.views.view import CardsFactoryResetView
        dest = self._route(3)
        self.assertIs(dest.View_cls, CardsFactoryResetView)


class TestCardsMenuRefresh(unittest.TestCase):
    """When a card-event listener fires while the menu is on screen,
    ``run()`` re-probes and re-renders rather than holding stale state."""

    def test_refreshes_on_card_event_then_routes(self):
        from seedsigner.hardware.buttons import HardwareButtonsConstants
        from seedsigner.views.tools_views import ToolsSeedkeeperView

        v = _make_view()

        # Capture the listener so we can simulate the CardMonitor firing it.
        registered = {}

        def reg_ins(fn):
            registered["ins"] = fn

        def unreg_ins(fn):
            registered.pop("ins", None)

        def reg_rem(fn):
            registered["rem"] = fn

        def unreg_rem(fn):
            registered.pop("rem", None)

        v.controller.register_card_inserted_listener.side_effect = reg_ins
        v.controller.unregister_card_inserted_listener.side_effect = unreg_ins
        v.controller.register_card_removed_listener.side_effect = reg_rem
        v.controller.unregister_card_removed_listener.side_effect = unreg_rem

        # First render: simulate a card-inserted event while the screen
        # waits for input, then return OVERRIDE so the view loops.
        # Second render: user picks SeedKeeper.
        run_calls = [0]

        def fake_run_screen(_screen_cls, **_kwargs):
            i = run_calls[0]
            run_calls[0] += 1
            if i == 0:
                self.assertIn("ins", registered)
                registered["ins"]()  # CardMonitor woke us up.
                return HardwareButtonsConstants.OVERRIDE
            return 0

        v.run_screen = fake_run_screen

        probe_count = [0]
        states = [_absent_state(), _present_state(keycard=True)]

        def fake_probe(_):
            i = probe_count[0]
            probe_count[0] += 1
            return states[min(i, len(states) - 1)]

        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            side_effect=fake_probe,
        ):
            dest = v.run()

        # Probe ran twice (once before each render).
        self.assertEqual(probe_count[0], 2)
        # Routing on the second iteration matches the user's choice.
        self.assertIs(dest.View_cls, ToolsSeedkeeperView)
        # Listeners were unregistered in the finally block.
        self.assertNotIn("ins", registered)
        self.assertNotIn("rem", registered)


class TestBackButtonNotSwallowedByOverride(unittest.TestCase):
    """Regression: ``RET_CODE__BACK_BUTTON`` and
    ``HardwareButtonsConstants.OVERRIDE`` share the value ``1000``. The
    refresh loop must distinguish them via the listener flag so a back
    press is never mistaken for a card-event override (which previously
    sent the user to SeedKeeper — the first item — on the next iteration)."""

    def test_back_press_without_card_event_returns_to_backstack(self):
        from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
        from seedsigner.views.view import BackStackView

        v = _make_view()
        v.run_screen = MagicMock(return_value=RET_CODE__BACK_BUTTON)
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=_absent_state(),
        ):
            dest = v.run()
        self.assertIs(dest.View_cls, BackStackView)


if __name__ == "__main__":
    unittest.main()
