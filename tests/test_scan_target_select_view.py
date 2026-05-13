"""Tests for the home-page Scan target chooser.

Covers the 2-option menu inserted between ``MainMenuView.SCAN`` and the
camera: SeedSigner (default decoder) vs. Keycard (Ethereum sign-request
flow). The Keycard button always renders, but its right-icon flips
between CHECK (ready) and INFO (needs setup).
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
    from seedsigner.views.view import ScanTargetSelectView
    v = ScanTargetSelectView.__new__(ScanTargetSelectView)
    v.controller = MagicMock()
    v.controller.has_any_keycard_auth.return_value = False
    return v


def _absent_state():
    from seedsigner.helpers.card_probe import CardInstalledState
    return CardInstalledState(False, False, False)


def _present_state(keycard=False, seedkeeper=False):
    from seedsigner.helpers.card_probe import CardInstalledState
    return CardInstalledState(True, keycard, seedkeeper)


class TestScanTargetSelectShape(unittest.TestCase):
    def test_labels(self):
        from seedsigner.views.view import ScanTargetSelectView
        self.assertEqual(ScanTargetSelectView.SEEDSIGNER.button_label, "SeedSigner")
        self.assertEqual(ScanTargetSelectView.KEYCARD_LABEL, "Keycard (Ethereum)")


class TestScanTargetSelectRendering(unittest.TestCase):
    """The menu always shows 2 entries. The Keycard right-icon reflects
    readiness: CHECK when card present + applet installed + pairing
    saved, INFO otherwise."""

    def _run_and_capture(self, state, has_auth, selected_index):
        v = _make_view()
        v.controller.has_any_keycard_auth.return_value = has_auth
        captured = {}

        def fake_run_screen(_screen_cls, **kwargs):
            captured["button_data"] = kwargs["button_data"]
            captured["title"] = kwargs.get("title")
            return selected_index

        v.run_screen = fake_run_screen
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=state,
        ):
            dest = v.run()
        return dest, captured

    def test_renders_two_entries_with_seedsigner_first(self):
        _, cap = self._run_and_capture(_absent_state(), False, selected_index=0)
        labels = [b.button_label for b in cap["button_data"]]
        self.assertEqual(labels, ["SeedSigner", "Keycard (Ethereum)"])

    def test_keycard_ready_shows_check_icon(self):
        from seedsigner.gui.components import SeedSignerIconConstants
        _, cap = self._run_and_capture(
            _present_state(keycard=True), has_auth=True, selected_index=0,
        )
        keycard_btn = cap["button_data"][1]
        self.assertEqual(keycard_btn.right_icon_name, SeedSignerIconConstants.CHECK)

    def test_keycard_no_card_shows_info_icon(self):
        from seedsigner.gui.components import SeedSignerIconConstants
        _, cap = self._run_and_capture(_absent_state(), False, selected_index=0)
        keycard_btn = cap["button_data"][1]
        self.assertEqual(keycard_btn.right_icon_name, SeedSignerIconConstants.INFO)

    def test_keycard_no_pairing_shows_info_icon(self):
        from seedsigner.gui.components import SeedSignerIconConstants
        _, cap = self._run_and_capture(
            _present_state(keycard=True), has_auth=False, selected_index=0,
        )
        keycard_btn = cap["button_data"][1]
        self.assertEqual(keycard_btn.right_icon_name, SeedSignerIconConstants.INFO)

    def test_keycard_card_without_applet_shows_info_icon(self):
        from seedsigner.gui.components import SeedSignerIconConstants
        _, cap = self._run_and_capture(
            _present_state(keycard=False), has_auth=True, selected_index=0,
        )
        keycard_btn = cap["button_data"][1]
        self.assertEqual(keycard_btn.right_icon_name, SeedSignerIconConstants.INFO)


class TestScanTargetSelectRouting(unittest.TestCase):
    def _route(self, button_index, state=None, has_auth=False):
        if state is None:
            state = _absent_state()
        v = _make_view()
        v.controller.has_any_keycard_auth.return_value = has_auth
        v.run_screen = MagicMock(return_value=button_index)
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=state,
        ):
            return v.run()

    def test_seedsigner_routes_to_scan_view(self):
        from seedsigner.views.scan_views import ScanView
        dest = self._route(0)
        self.assertIs(dest.View_cls, ScanView)
        self.assertFalse(dest.skip_current_view)

    def test_keycard_routes_to_sign_eth_start(self):
        from seedsigner.views.keycard_views import ToolsKeycardSignEthStartView
        dest = self._route(
            1,
            state=_present_state(keycard=True),
            has_auth=True,
        )
        self.assertIs(dest.View_cls, ToolsKeycardSignEthStartView)
        self.assertTrue(dest.skip_current_view)

    def test_keycard_routes_to_sign_eth_start_even_without_pairing(self):
        """``ToolsKeycardSignEthStartView`` itself handles the no-pairing
        case (it redirects to ``ToolsKeycardPairView``). The chooser does
        not duplicate that logic — it always routes to the start view."""
        from seedsigner.views.keycard_views import ToolsKeycardSignEthStartView
        dest = self._route(1, state=_absent_state(), has_auth=False)
        self.assertIs(dest.View_cls, ToolsKeycardSignEthStartView)


class TestScanTargetSelectBackNav(unittest.TestCase):
    def test_back_button_returns_to_backstack(self):
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

    def test_power_button_returns_to_power_options(self):
        from seedsigner.gui.screens.screen import RET_CODE__POWER_BUTTON
        from seedsigner.views.view import PowerOptionsView

        v = _make_view()
        v.run_screen = MagicMock(return_value=RET_CODE__POWER_BUTTON)
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=_absent_state(),
        ):
            dest = v.run()
        self.assertIs(dest.View_cls, PowerOptionsView)


class TestScanTargetSelectProbeFailure(unittest.TestCase):
    """A reader error or missing PCSC library must not crash the menu;
    it should fall through to the "not ready" rendering."""

    def test_probe_exception_falls_back_to_info_icon(self):
        from seedsigner.gui.components import SeedSignerIconConstants

        v = _make_view()
        captured = {}

        def fake_run_screen(_screen_cls, **kwargs):
            captured["button_data"] = kwargs["button_data"]
            return 0

        v.run_screen = fake_run_screen
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            side_effect=RuntimeError("no reader"),
        ):
            v.run()
        keycard_btn = captured["button_data"][1]
        self.assertEqual(keycard_btn.right_icon_name, SeedSignerIconConstants.INFO)

    def test_has_auth_exception_falls_back_to_info_icon(self):
        from seedsigner.gui.components import SeedSignerIconConstants

        v = _make_view()
        v.controller.has_any_keycard_auth.side_effect = AttributeError("no attr")
        captured = {}

        def fake_run_screen(_screen_cls, **kwargs):
            captured["button_data"] = kwargs["button_data"]
            return 0

        v.run_screen = fake_run_screen
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=_present_state(keycard=True),
        ):
            v.run()
        keycard_btn = captured["button_data"][1]
        self.assertEqual(keycard_btn.right_icon_name, SeedSignerIconConstants.INFO)


class TestScanTargetSelectRefreshOnInsert(unittest.TestCase):
    """When a card-inserted listener fires while the menu is on screen,
    the view re-probes and re-renders rather than returning a stale
    routing decision."""

    def test_refreshes_on_insert_then_routes(self):
        from seedsigner.hardware.buttons import HardwareButtonsConstants
        from seedsigner.views.scan_views import ScanView

        v = _make_view()
        registered = {}

        def reg_ins(fn):
            registered["ins"] = fn

        def unreg_ins(fn):
            registered.pop("ins", None)

        v.controller.register_card_inserted_listener.side_effect = reg_ins
        v.controller.unregister_card_inserted_listener.side_effect = unreg_ins

        run_calls = [0]

        def fake_run_screen(_screen_cls, **_kwargs):
            i = run_calls[0]
            run_calls[0] += 1
            if i == 0:
                self.assertIn("ins", registered)
                registered["ins"]()
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

        self.assertEqual(probe_count[0], 2)
        self.assertIs(dest.View_cls, ScanView)
        self.assertNotIn("ins", registered)


if __name__ == "__main__":
    unittest.main()
