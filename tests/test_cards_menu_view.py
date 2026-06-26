"""Tests for the top-level Cards menu.

Pins the 3-entry shape (Keycard / SeedKeeper / Factory
reset), confirms install-state checkmarks render, and that each entry
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
    return CardInstalledState(False, False, False)


def _present_state(**flags):
    from seedsigner.helpers.card_probe import CardInstalledState
    return CardInstalledState(
        True,
        flags.get("keycard", False),
        flags.get("seedkeeper", False),
    )


class TestCardsMenuShape(unittest.TestCase):
    def test_labels(self):
        from seedsigner.views.view import CardsMenuView
        self.assertEqual(CardsMenuView.SEEDKEEPER_LABEL, "SeedKeeper")
        self.assertEqual(CardsMenuView.KEYCARD_LABEL, "Keycard")
        self.assertEqual(CardsMenuView.FACTORY_RESET_LABEL, "Factory reset card")

    def test_legacy_classes_removed(self):
        from seedsigner.views import view as view_mod
        from seedsigner.views import tools_views
        self.assertFalse(hasattr(view_mod, "CardManagementView"))
        self.assertFalse(hasattr(tools_views, "ToolsSmartcardMenuView"))


class TestCardsMenuRendering(unittest.TestCase):
    """The menu must show 3 entries with install-state checkmarks when
    a card is present. The absent-card path is covered by
    :class:`TestCardsMenuGate` below."""

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

    def test_present_card_renders_checkmarks(self):
        from seedsigner.gui.components import SeedSignerIconConstants
        _, buttons = self._run_and_capture(
            _present_state(keycard=True, seedkeeper=True),
            selected_index=0,
        )
        labels = [b.button_label for b in buttons]
        self.assertEqual(
            labels, ["Keycard", "SeedKeeper", "Factory reset card"],
        )
        # Order is Keycard, SeedKeeper, Factory reset.
        self.assertEqual(buttons[0].right_icon_name, SeedSignerIconConstants.CHECK)
        self.assertEqual(buttons[1].right_icon_name, SeedSignerIconConstants.CHECK)


class TestCardsMenuGate(unittest.TestCase):
    """No card → bounce to MainMenu with an InfoToast. Every menu entry
    requires a card to do anything useful, so we don't even render the
    menu in the no-card case."""

    def test_no_card_redirects_to_main_menu(self):
        from seedsigner.views.view import MainMenuView
        v = _make_view()
        # run_screen must not be called on this path.
        v.run_screen = MagicMock(side_effect=AssertionError("run_screen called on gate path"))
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=_absent_state(),
        ):
            dest = v.run()
        self.assertIs(dest.View_cls, MainMenuView)
        self.assertTrue(dest.clear_history)

    def test_no_card_activates_info_toast(self):
        v = _make_view()
        v.run_screen = MagicMock(side_effect=AssertionError("run_screen called on gate path"))
        fake_toast_instance = MagicMock(name="InfoToast_instance")
        fake_toast_cls = MagicMock(return_value=fake_toast_instance, name="InfoToast")
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=_absent_state(),
        ), patch(
            "seedsigner.gui.toast.InfoToast", fake_toast_cls,
        ):
            v.run()
        # Toast was constructed with the localized "insert a card" label.
        fake_toast_cls.assert_called_once()
        kwargs = fake_toast_cls.call_args.kwargs
        self.assertIn("label_text", kwargs)
        self.assertIn("Insert a card", kwargs["label_text"])
        # And handed off to the controller's toast manager.
        v.controller.activate_toast.assert_called_once_with(fake_toast_instance)


class TestCardsMenuRouting(unittest.TestCase):
    """Confirm each entry routes to the correct destination."""

    def _route(self, button_index):
        v = _make_view()
        v.run_screen = MagicMock(return_value=button_index)
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=_present_state(),
        ):
            return v.run()

    def test_keycard_routes(self):
        from seedsigner.views.keycard_views import ToolsKeycardMenuView
        dest = self._route(0)
        self.assertIs(dest.View_cls, ToolsKeycardMenuView)

    def test_seedkeeper_routes(self):
        from seedsigner.views.tools_views import ToolsSeedkeeperView
        dest = self._route(1)
        self.assertIs(dest.View_cls, ToolsSeedkeeperView)

    def test_factory_reset_routes(self):
        from seedsigner.views.view import CardsFactoryResetView
        dest = self._route(2)
        self.assertIs(dest.View_cls, CardsFactoryResetView)


class TestCardsMenuRefreshOnInsert(unittest.TestCase):
    """When a card-inserted listener fires while the menu is on screen,
    ``run()`` re-probes and re-renders rather than holding stale state.
    Removals are handled centrally in Controller and don't go through
    this path anymore."""

    def test_refreshes_on_insert_then_routes(self):
        from seedsigner.hardware.buttons import HardwareButtonsConstants
        from seedsigner.views.keycard_views import ToolsKeycardMenuView

        v = _make_view()

        # Capture the insert listener so we can simulate the CardMonitor firing it.
        registered = {}

        def reg_ins(fn):
            registered["ins"] = fn

        def unreg_ins(fn):
            registered.pop("ins", None)

        v.controller.register_card_inserted_listener.side_effect = reg_ins
        v.controller.unregister_card_inserted_listener.side_effect = unreg_ins

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
        states = [_present_state(), _present_state(keycard=True)]

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
        # Routing on the second iteration matches the user's choice
        # (index 0 is Keycard, the first Cards-menu entry).
        self.assertIs(dest.View_cls, ToolsKeycardMenuView)
        # Listener was unregistered in the finally block.
        self.assertNotIn("ins", registered)
        # CardsMenuView no longer subscribes to removals; the central
        # Controller redirect owns that path.
        v.controller.register_card_removed_listener.assert_not_called()

    def test_cardsmenuview_does_not_subscribe_to_removals(self):
        """Regression: CardsMenuView previously registered itself for
        removed events, which competed with the central redirect and
        caused the menu to refresh in place instead of bailing to
        MainMenu on card removal."""
        v = _make_view()
        v.run_screen = MagicMock(return_value=0)
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=_present_state(),
        ):
            v.run()
        v.controller.register_card_removed_listener.assert_not_called()
        v.controller.unregister_card_removed_listener.assert_not_called()


class TestBackButtonNotSwallowedByInsertOverride(unittest.TestCase):
    """Regression: ``RET_CODE__BACK_BUTTON`` and
    ``HardwareButtonsConstants.OVERRIDE`` share the value ``1000``. The
    refresh loop must distinguish them via the listener flag so a back
    press is never mistaken for a card-insert override (which previously
    sent the user to SeedKeeper — the first item — on the next iteration)."""

    def test_back_press_without_card_event_returns_to_backstack(self):
        from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
        from seedsigner.views.view import BackStackView

        v = _make_view()
        v.run_screen = MagicMock(return_value=RET_CODE__BACK_BUTTON)
        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=_present_state(),
        ):
            dest = v.run()
        self.assertIs(dest.View_cls, BackStackView)


class TestCardRemovedRedirect(unittest.TestCase):
    """Centralised redirect in ``Controller``: when a card is removed
    while the active view belongs to the cards subtree, the next
    destination is force-replaced with ``MainMenuView``."""

    def _stub_controller(self, back_stack_top_view_cls):
        """Build a partially-initialised Controller for unit tests."""
        from seedsigner.controller import Controller, BackStack
        from seedsigner.views.view import Destination
        c = Controller.__new__(Controller)
        c.back_stack = BackStack()
        if back_stack_top_view_cls is not None:
            c.back_stack.append(Destination(back_stack_top_view_cls))
        c._pending_card_removed_redirect = False
        return c

    def test_is_card_view_true_for_cards_menu(self):
        from seedsigner.views.view import CardsMenuView
        c = self._stub_controller(None)
        self.assertTrue(c._is_card_view(CardsMenuView))

    def test_is_card_view_true_for_cards_factory_reset(self):
        from seedsigner.views.view import CardsFactoryResetView
        c = self._stub_controller(None)
        self.assertTrue(c._is_card_view(CardsFactoryResetView))

    def test_is_card_view_true_for_keycard_views_module(self):
        from seedsigner.views.keycard_views import ToolsKeycardMenuView
        c = self._stub_controller(None)
        self.assertTrue(c._is_card_view(ToolsKeycardMenuView))

    def test_is_card_view_true_for_seedkeeper_prefix(self):
        from seedsigner.views.tools_views import ToolsSeedkeeperView
        c = self._stub_controller(None)
        self.assertTrue(c._is_card_view(ToolsSeedkeeperView))

    def test_is_card_view_false_for_main_menu(self):
        from seedsigner.views.view import MainMenuView
        c = self._stub_controller(None)
        self.assertFalse(c._is_card_view(MainMenuView))

    def test_is_card_view_false_for_none(self):
        c = self._stub_controller(None)
        self.assertFalse(c._is_card_view(None))

    def test_listener_sets_flag_when_in_cards_menu(self):
        from seedsigner.views.view import CardsMenuView
        c = self._stub_controller(CardsMenuView)
        c._on_card_removed_redirect()
        self.assertTrue(c._pending_card_removed_redirect)

    def test_listener_sets_flag_when_in_keycard_view(self):
        from seedsigner.views.keycard_views import ToolsKeycardMenuView
        c = self._stub_controller(ToolsKeycardMenuView)
        c._on_card_removed_redirect()
        self.assertTrue(c._pending_card_removed_redirect)

    def test_listener_noop_outside_card_view(self):
        from seedsigner.views.view import MainMenuView
        c = self._stub_controller(MainMenuView)
        c._on_card_removed_redirect()
        self.assertFalse(c._pending_card_removed_redirect)

    def test_listener_noop_when_back_stack_empty(self):
        c = self._stub_controller(None)
        c._on_card_removed_redirect()
        self.assertFalse(c._pending_card_removed_redirect)

    def test_listener_noop_on_seedkeeper_swap_view(self):
        """The 3 deliberate card-swap prompts must NOT trigger the
        redirect-to-Home: the user is mid-swap with the card pulled, so
        snapping to Home (and wiping the pending seed there) would make the
        2nd backup/import impossible."""
        from seedsigner.views import keycard_views
        for name in (
            "ToolsKeycardSeedkeeperSwapInsertView",
            "ToolsKeycardImportSeedkeeperInsertView",
            "ToolsKeycardImportSeedkeeperReinsertView",
        ):
            view_cls = getattr(keycard_views, name)
            c = self._stub_controller(view_cls)
            c._on_card_removed_redirect()
            self.assertFalse(
                c._pending_card_removed_redirect,
                f"{name} should be exempt from the card-removed redirect",
            )

    def test_listener_still_redirects_on_non_swap_keycard_view(self):
        """A keycard view that operates on a *present* card (not a swap
        prompt) still redirects on removal — the exemption is scoped to the
        swap-prompt screens only."""
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperSaveRunView,
        )
        c = self._stub_controller(ToolsKeycardSeedkeeperSaveRunView)
        c._on_card_removed_redirect()
        self.assertTrue(c._pending_card_removed_redirect)

    def test_card_removed_toast_suppressed_on_swap_view(self):
        """``dispatch_card_removed_event`` suppresses the 'Card removed'
        toast on a swap-prompt view, but still shows it on other card
        views."""
        from seedsigner.views.keycard_views import (
            ToolsKeycardSeedkeeperSwapInsertView,
            ToolsKeycardMenuView,
        )
        fake_toast_cls = MagicMock(name="CardRemovedToast")
        with patch("seedsigner.gui.toast.CardRemovedToast", fake_toast_cls):
            # Exempt swap view → no toast.
            c = self._stub_controller(ToolsKeycardSeedkeeperSwapInsertView)
            c._card_removed_listeners = []
            c.activate_toast = MagicMock()
            c.dispatch_card_removed_event()
            c.activate_toast.assert_not_called()
            fake_toast_cls.assert_not_called()

            # Non-exempt card view → toast shows.
            c2 = self._stub_controller(ToolsKeycardMenuView)
            c2._card_removed_listeners = []
            c2.activate_toast = MagicMock()
            c2.dispatch_card_removed_event()
            c2.activate_toast.assert_called_once()
            fake_toast_cls.assert_called_once()


class TestOverrideInterruptPropagation(unittest.TestCase):
    """``trigger_override()`` previously *returned* ``OVERRIDE`` (1000)
    from ``wait_for``, which the screen ``_run`` loops silently dropped
    (the value matches no key in their ``elif`` chains), leaving the
    user stuck on the current screen. Now ``wait_for`` raises
    ``OverrideInterrupt`` and ``BaseScreen.display`` translates it to
    ``RET_CODE__BACK_BUTTON`` so the calling View returns to the main
    loop, which then applies any pending redirect."""

    def setUp(self):
        # Other test modules (via base.py) replace seedsigner.hardware.buttons
        # in sys.modules with a MagicMock. Force-load the real module here so
        # OverrideInterrupt is the real exception class and HardwareButtons is
        # the real class. Restore the mock on tearDown so the rest of the suite
        # is unaffected. Crucially, do NOT reload the screen module — that
        # would re-create its classes (ButtonOption, BaseScreen, ...) and
        # break isinstance checks elsewhere (e.g. FlowTest in base.py).
        import importlib
        self._saved_buttons_entry = sys.modules.pop("seedsigner.hardware.buttons", None)
        self._saved_hw_buttons_attr = None
        if isinstance(self._saved_buttons_entry, MagicMock):
            import seedsigner.hardware
            self._saved_hw_buttons_attr = getattr(seedsigner.hardware, "buttons", None)
            if isinstance(self._saved_hw_buttons_attr, MagicMock):
                delattr(seedsigner.hardware, "buttons")
        self.buttons_module = importlib.import_module("seedsigner.hardware.buttons")

    def tearDown(self):
        # Restore the mock (if any) so other tests in the suite see the
        # state base.py expects.
        if isinstance(self._saved_buttons_entry, MagicMock):
            sys.modules["seedsigner.hardware.buttons"] = self._saved_buttons_entry
            import seedsigner.hardware
            if self._saved_hw_buttons_attr is not None:
                seedsigner.hardware.buttons = self._saved_hw_buttons_attr

    def test_wait_for_raises_when_override_set_during_loop(self):
        """``wait_for`` resets ``override_ind`` at entry (so stale flags
        from a previous call don't fire) and then polls it inside the
        loop. The on-device pattern is: another thread (CardMonitor,
        WipeTimer) calls ``trigger_override`` *while* ``wait_for`` is
        already looping. We simulate that with a Timer that flips the
        flag a tick after wait_for starts."""
        import threading
        import time as time_mod
        HardwareButtons = self.buttons_module.HardwareButtons
        OverrideInterrupt = self.buttons_module.OverrideInterrupt
        from seedsigner.controller import Controller

        stub_ctrl = MagicMock()
        stub_ctrl.screensaver_activation_ms = float("inf")
        stub_ctrl.is_screensaver_running = False

        hw = HardwareButtons.__new__(HardwareButtons)
        hw.override_ind = False
        hw.last_input_time = int(time_mod.time() * 1000)
        hw._gpio_pins = {}
        hw._low_since_ms = {}
        hw.cur_input = None
        hw.cur_input_started = None
        hw.debounce_threshold_ms = 10
        hw.first_repeat_threshold = 225
        hw.next_repeat_threshold = 250

        threading.Timer(0.05, hw.trigger_override).start()

        with patch.object(Controller, "get_instance", return_value=stub_ctrl):
            with self.assertRaises(OverrideInterrupt):
                hw.wait_for(keys=[])
        self.assertFalse(hw.override_ind)

    def test_base_screen_display_translates_override_to_back_button(self):
        # The screen module may have been imported with a MagicMock-flavoured
        # buttons module (via base.py), in which case its module-level
        # ``OverrideInterrupt`` reference is a MagicMock attribute rather
        # than the real exception class. Patch the reference for the
        # duration of this test so its ``except OverrideInterrupt:`` clause
        # matches the real exception we raise.
        from seedsigner.gui.screens import screen as screen_module
        OverrideInterrupt = self.buttons_module.OverrideInterrupt
        with patch.object(screen_module, "OverrideInterrupt", OverrideInterrupt):
            BaseScreen = screen_module.BaseScreen
            RET_CODE__BACK_BUTTON = screen_module.RET_CODE__BACK_BUTTON

            s = BaseScreen.__new__(BaseScreen)
            s.renderer = MagicMock()
            s.threads = []
            s.components = []
            s.paste_images = []
            s.scroll_y = 0
            s._render = MagicMock()
            s.get_threads = MagicMock(return_value=[])
            s._run = MagicMock(side_effect=OverrideInterrupt())

            result = s.display()
            self.assertEqual(result, RET_CODE__BACK_BUTTON)


if __name__ == "__main__":
    unittest.main()
