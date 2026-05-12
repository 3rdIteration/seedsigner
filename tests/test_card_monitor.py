"""Tests for the background PC/SC card-event observer.

Covers:
* ``Controller.on_card_removed`` wipes Keycard PINs and the Satochip
  session, even when called from a background thread context.
* ``Controller.on_card_inserted`` is a no-op stub for Phase 4 (Phase 5
  will fill it in).
* ``_PinWipingObserver.update`` correctly routes pyscard's
  ``(addedcards, removedcards)`` tuple to the right controller
  callbacks and tolerates malformed payloads.
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


class _FakeController:
    """Minimal controller stand-in exercising the observer contract."""

    def __init__(self):
        self.forget_all_pins_called = 0
        self.forget_satochip_session_called = 0
        self.inserted_events = []
        self.raise_on_pin_wipe = False
        # Real Controller exposes these listener registries; the
        # observer dispatch path now uses them. Tests don't care about
        # their content but the attribute must exist.
        self._card_inserted_listeners = []
        self._card_removed_listeners = []
        self.toasts_activated = []

    def forget_all_pins(self):
        self.forget_all_pins_called += 1
        if self.raise_on_pin_wipe:
            raise RuntimeError("simulated failure")

    def forget_satochip_session(self):
        self.forget_satochip_session_called += 1

    def activate_toast(self, toast):
        # Real ``activate_toast`` spins up a thread; in tests we just
        # record the call so the observer pathway doesn't crash on
        # missing infrastructure.
        self.toasts_activated.append(toast)

    def _notify_card_listeners(self, listeners, *args):
        from seedsigner.controller import Controller
        Controller._notify_card_listeners(self, listeners, *args)

    # Real Controller wires these into the same callbacks; mirror that here.
    def wipe_card_session_secrets(self):
        from seedsigner.controller import Controller
        Controller.wipe_card_session_secrets(self)

    def dispatch_card_removed_event(self, reader_name=None):
        from seedsigner.controller import Controller
        Controller.dispatch_card_removed_event(self, reader_name)

    def on_card_removed(self, reader_name=None):
        # Borrow the real implementation logic to keep the test
        # honest — the observer contract is what we're testing, but
        # the controller method is what runs in production.
        from seedsigner.controller import Controller
        Controller.on_card_removed(self, reader_name)

    def on_card_inserted(self, atr, reader_name=None):
        self.inserted_events.append((bytes(atr), reader_name))


class TestPinWipingObserver(unittest.TestCase):
    def _make_observer(self, controller):
        from seedsigner.helpers.card_monitor import _PinWipingObserver
        return _PinWipingObserver(controller)

    def test_removed_card_triggers_pin_wipe(self):
        ctrl = _FakeController()
        obs = self._make_observer(ctrl)
        card = MagicMock(reader="reader1")
        obs.update(observable=None, handlers=([], [card]))
        self.assertEqual(ctrl.forget_all_pins_called, 1)
        self.assertEqual(ctrl.forget_satochip_session_called, 1)

    def test_inserted_card_routes_atr_and_reader(self):
        ctrl = _FakeController()
        obs = self._make_observer(ctrl)
        card = MagicMock(reader="reader1")
        card.atr = [0x3B, 0x80, 0x80, 0x01, 0x01]
        obs.update(observable=None, handlers=([card], []))
        self.assertEqual(len(ctrl.inserted_events), 1)
        atr, reader = ctrl.inserted_events[0]
        self.assertEqual(atr, bytes([0x3B, 0x80, 0x80, 0x01, 0x01]))
        self.assertEqual(reader, "reader1")

    def test_simultaneous_add_and_remove_dispatches_both(self):
        ctrl = _FakeController()
        obs = self._make_observer(ctrl)
        old = MagicMock(reader="r1")
        new = MagicMock(reader="r1")
        new.atr = [0x3B, 0x00]
        obs.update(observable=None, handlers=([new], [old]))
        self.assertEqual(ctrl.forget_all_pins_called, 1)
        self.assertEqual(len(ctrl.inserted_events), 1)

    def test_malformed_handlers_tuple_is_ignored(self):
        ctrl = _FakeController()
        obs = self._make_observer(ctrl)
        # Should not raise, should not invoke any callbacks.
        obs.update(observable=None, handlers=None)
        obs.update(observable=None, handlers=("just one",))
        self.assertEqual(ctrl.forget_all_pins_called, 0)
        self.assertEqual(ctrl.inserted_events, [])

    def test_wipe_failure_does_not_block_satochip_wipe(self):
        """Even if Keycard wipe raises, the Satochip session must still
        be forgotten — the two cleanup paths are independent."""
        ctrl = _FakeController()
        ctrl.raise_on_pin_wipe = True
        obs = self._make_observer(ctrl)
        card = MagicMock(reader="r1")
        obs.update(observable=None, handlers=([], [card]))
        self.assertEqual(ctrl.forget_all_pins_called, 1)
        self.assertEqual(ctrl.forget_satochip_session_called, 1)


class TestRemovalDebounce(unittest.TestCase):
    """The observer must absorb spurious removed/inserted bounces from
    PC/SC drivers without surfacing a "Card removed" toast or notifying
    removal listeners. The defensive wipe still runs unconditionally."""

    def _make_observer_with_dispatch_capture(self):
        from seedsigner.helpers.card_monitor import _PinWipingObserver
        ctrl = _FakeController()
        # Replace the bound delegating method with a capture so we can
        # tell whether the debounced dispatch ever fired.
        dispatch_calls = []
        ctrl.dispatch_card_removed_event = lambda r=None: dispatch_calls.append(r)
        return _PinWipingObserver(ctrl), ctrl, dispatch_calls

    def test_inserted_within_window_cancels_dispatch(self):
        import time
        obs, ctrl, dispatch_calls = self._make_observer_with_dispatch_capture()
        old = MagicMock(reader="r1")
        new = MagicMock(reader="r1")
        new.atr = [0x3B, 0x00]

        obs.update(observable=None, handlers=([], [old]))
        # Insert lands well before the 250 ms window expires.
        obs.update(observable=None, handlers=([new], []))
        # Wait past the original deadline to confirm the timer was cancelled.
        time.sleep(0.4)

        # Defensive wipe still ran on the removed event…
        self.assertEqual(ctrl.forget_all_pins_called, 1)
        # …but the user-visible removal event is suppressed.
        self.assertEqual(dispatch_calls, [])
        # And the insertion was dispatched normally.
        self.assertEqual(len(ctrl.inserted_events), 1)

    def test_removal_alone_dispatches_after_window(self):
        import time
        obs, ctrl, dispatch_calls = self._make_observer_with_dispatch_capture()
        card = MagicMock(reader="r1")

        obs.update(observable=None, handlers=([], [card]))

        # Before the window the dispatch hasn't fired yet.
        time.sleep(0.05)
        self.assertEqual(dispatch_calls, [])
        # Past the window it has.
        time.sleep(0.35)
        self.assertEqual(dispatch_calls, ["r1"])
        # Wipe ran immediately, not deferred.
        self.assertEqual(ctrl.forget_all_pins_called, 1)

    def test_distinct_readers_are_independent(self):
        """A spurious bounce on reader A must not cancel a real
        removal pending on reader B."""
        import time
        obs, ctrl, dispatch_calls = self._make_observer_with_dispatch_capture()
        card_a = MagicMock(reader="a")
        card_b = MagicMock(reader="b")
        card_a_in = MagicMock(reader="a")
        card_a_in.atr = [0x3B, 0x00]

        obs.update(observable=None, handlers=([], [card_a]))
        obs.update(observable=None, handlers=([], [card_b]))
        # Cancel only reader "a" via re-insertion.
        obs.update(observable=None, handlers=([card_a_in], []))
        time.sleep(0.4)

        # Reader b's removal still fires; reader a's was cancelled.
        self.assertEqual(dispatch_calls, ["b"])


class TestStartStopCardMonitor(unittest.TestCase):
    def test_start_returns_none_when_smartcard_unavailable(self):
        """If pyscard cannot be imported, start_card_monitor must
        return None and not crash — desktop CI environments and unit
        tests with no PCSC stack rely on this fallback."""
        from seedsigner.helpers import card_monitor

        # The mocked smartcard module lacks ``CardMonitoring`` as a
        # real Python class; importing it succeeds but using it would
        # do something non-deterministic. We patch the import to fail
        # explicitly to exercise the graceful-degradation branch.
        original = sys.modules.get("smartcard.CardMonitoring")
        sys.modules["smartcard.CardMonitoring"] = None  # forces ImportError
        try:
            ret = card_monitor.start_card_monitor(_FakeController())
            self.assertIsNone(ret)
        finally:
            if original is not None:
                sys.modules["smartcard.CardMonitoring"] = original
            else:
                sys.modules.pop("smartcard.CardMonitoring", None)

    def test_stop_with_none_observer_is_noop(self):
        from seedsigner.helpers import card_monitor
        # Should not raise.
        card_monitor.stop_card_monitor(None)


class TestOnCardInsertedToast(unittest.TestCase):
    """``Controller.on_card_inserted`` only emits a toast when
    ``SETTING__AUTO_PIN_ON_INSERT`` is enabled. Default is OFF so a
    bare boot doesn't surface card activity to the casual observer."""

    def _patched_controller(self, setting_value):
        from seedsigner.controller import Controller
        from seedsigner.models.settings_definition import SettingsConstants

        ctrl = MagicMock(spec=Controller)
        ctrl.activate_toast = MagicMock()
        ctrl.identify_inserted_card_kind = MagicMock(return_value="Card")
        # Listener registries used by the card-event fan-out (added in
        # Phase 5b alongside CardWaitScreen).
        ctrl._card_inserted_listeners = []
        ctrl._card_removed_listeners = []

        # Patch Settings.get_instance() so on_card_inserted reads our value.
        from unittest.mock import patch
        settings_patch = patch(
            "seedsigner.controller.Settings.get_instance"
        )
        return ctrl, settings_patch, setting_value, SettingsConstants

    def test_disabled_setting_does_not_dispatch_toast(self):
        from seedsigner.controller import Controller

        ctrl, sp, value, sc = self._patched_controller(sc_disabled := "D")
        with sp as get_instance:
            get_instance.return_value.get_value.return_value = sc_disabled
            Controller.on_card_inserted(ctrl, atr=b"\x3B\x80", reader_name="r1")
        ctrl.activate_toast.assert_not_called()

    def test_enabled_setting_dispatches_toast(self):
        from unittest.mock import patch
        from seedsigner.controller import Controller

        ctrl, sp, _, _ = self._patched_controller("E")
        # ``CardInsertedToast`` extends ``BaseToastOverlayManagerThread``
        # which calls ``Renderer.get_instance()`` in its ``__init__`` —
        # that singleton isn't configured in this lightweight unit
        # test, so we replace the toast class with a sentinel that
        # records the call without exercising the Renderer.
        sentinel = object()
        toast_factory = MagicMock(return_value=sentinel)
        with sp as get_instance, patch(
            "seedsigner.gui.toast.CardInsertedToast", toast_factory
        ):
            get_instance.return_value.get_value.return_value = "E"
            Controller.on_card_inserted(ctrl, atr=b"\x3B\x80", reader_name="r1")
        toast_factory.assert_called_once_with(kind="Card")
        ctrl.activate_toast.assert_called_once_with(sentinel)


if __name__ == "__main__":
    unittest.main()
