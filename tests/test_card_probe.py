"""Tests for ``helpers/card_probe.py``.

The probe is meant to be a fast, side-effect-free read of the inserted
applet's state. These tests stub out the reader / pysatochip layer and
assert that the probe maps each underlying state to the right
:class:`ProbeResult`.
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


class _FakeSelectInfo:
    def __init__(self, app_version=0x0302, instance_uid=b"\xAA" * 16):
        self.app_version = app_version
        self.instance_uid = instance_uid


def _patch_reader_present():
    """Make ``list_readers`` return a non-empty list and the helper
    ``release_other_smartcard_holders`` a no-op."""
    return patch.multiple(
        "seedsigner.helpers.keycard.reader",
        list_readers=MagicMock(return_value=[MagicMock()]),
        release_other_smartcard_holders=MagicMock(return_value=None),
    )


def _patch_reader_absent():
    return patch(
        "seedsigner.helpers.keycard.reader.list_readers",
        MagicMock(return_value=[]),
    )


class TestProbeKeycard(unittest.TestCase):
    def test_no_reader(self):
        from seedsigner.helpers.card_probe import probe_card
        with _patch_reader_absent():
            res = probe_card("keycard", controller=MagicMock())
        self.assertFalse(res.present)
        self.assertFalse(res.kind_match)
        self.assertFalse(res.initialised)

    def test_card_absent(self):
        from seedsigner.helpers.card_probe import probe_card
        from seedsigner.helpers.keycard.reader import NoCardError
        with _patch_reader_present(), \
             patch("seedsigner.helpers.keycard.reader.wait_for_card",
                   side_effect=NoCardError("no card")):
            res = probe_card("keycard", controller=MagicMock())
        self.assertFalse(res.present)

    def test_card_present_initialised(self):
        from seedsigner.helpers.card_probe import probe_card
        info = _FakeSelectInfo(app_version=0x0302)
        with _patch_reader_present(), \
             patch("seedsigner.helpers.keycard.reader.wait_for_card",
                   return_value=MagicMock()), \
             patch("seedsigner.helpers.keycard.client.KeycardClient",
                   return_value=MagicMock()), \
             patch("seedsigner.helpers.keycard.ui_helpers.select_with_autodetect",
                   return_value=info):
            res = probe_card("keycard", controller=MagicMock())
        self.assertTrue(res.present)
        self.assertTrue(res.kind_match)
        self.assertTrue(res.initialised)
        self.assertEqual(res.app_version, 0x0302)
        self.assertEqual(res.instance_uid, b"\xAA" * 16)

    def test_card_present_uninitialised(self):
        from seedsigner.helpers.card_probe import probe_card
        info = _FakeSelectInfo(app_version=0)
        with _patch_reader_present(), \
             patch("seedsigner.helpers.keycard.reader.wait_for_card",
                   return_value=MagicMock()), \
             patch("seedsigner.helpers.keycard.client.KeycardClient",
                   return_value=MagicMock()), \
             patch("seedsigner.helpers.keycard.ui_helpers.select_with_autodetect",
                   return_value=info):
            res = probe_card("keycard", controller=MagicMock())
        self.assertTrue(res.present)
        self.assertTrue(res.kind_match)
        self.assertFalse(res.initialised)
        self.assertEqual(res.app_version, 0)

    def test_card_present_wrong_applet(self):
        """SELECT raised — card present but not a Keycard."""
        from seedsigner.helpers.card_probe import probe_card
        with _patch_reader_present(), \
             patch("seedsigner.helpers.keycard.reader.wait_for_card",
                   return_value=MagicMock()), \
             patch("seedsigner.helpers.keycard.client.KeycardClient",
                   return_value=MagicMock()), \
             patch("seedsigner.helpers.keycard.ui_helpers.select_with_autodetect",
                   side_effect=Exception("SW=6A82")):
            res = probe_card("keycard", controller=MagicMock())
        self.assertTrue(res.present)
        self.assertFalse(res.kind_match)


def _patched_card_connector(setup_done: bool, status_payload_ok=True):
    """Construct a CardConnector mock that returns a sane status tuple."""
    connector = MagicMock()
    if status_payload_ok:
        connector.card_get_status.return_value = (
            None, 0x90, 0x00, {"setup_done": setup_done, "is_seeded": True},
        )
    else:
        connector.card_get_status.return_value = (None, 0x6F, 0x00, {})
    connector.UID_SHA1 = "aa" * 20
    return connector


class TestProbeSeedKeeper(unittest.TestCase):
    def test_seedkeeper_initialised(self):
        from seedsigner.helpers.card_probe import probe_card
        connector = _patched_card_connector(setup_done=True)
        with _patch_reader_present(), \
             patch("pysatochip.CardConnector.CardConnector",
                   return_value=connector):
            res = probe_card("seedkeeper", controller=MagicMock())
        self.assertTrue(res.present)
        self.assertTrue(res.initialised)

    def test_seedkeeper_uninitialised(self):
        from seedsigner.helpers.card_probe import probe_card
        connector = _patched_card_connector(setup_done=False)
        with _patch_reader_present(), \
             patch("pysatochip.CardConnector.CardConnector",
                   return_value=connector):
            res = probe_card("seedkeeper", controller=MagicMock())
        self.assertTrue(res.present)
        self.assertTrue(res.kind_match)
        self.assertFalse(res.initialised)

    def test_connector_raises_card_absent(self):
        from seedsigner.helpers.card_probe import probe_card
        with _patch_reader_absent(), \
             patch("pysatochip.CardConnector.CardConnector",
                   side_effect=Exception("no card")):
            res = probe_card("seedkeeper", controller=MagicMock())
        self.assertFalse(res.present)

    def test_connector_raises_card_present(self):
        """Reader has *something* but pysatochip rejects it — likely a
        Keycard or a card we can't talk to with the SeedKeeper applet."""
        from seedsigner.helpers.card_probe import probe_card
        with _patch_reader_present(), \
             patch("pysatochip.CardConnector.CardConnector",
                   side_effect=Exception("applet not found")):
            res = probe_card("seedkeeper", controller=MagicMock())
        self.assertTrue(res.present)
        self.assertFalse(res.kind_match)

    def test_unknown_kind_raises(self):
        from seedsigner.helpers.card_probe import probe_card
        with self.assertRaises(ValueError):
            probe_card("smartpgp", controller=MagicMock())  # type: ignore[arg-type]


class TestProbeInstalledApplets(unittest.TestCase):
    """SELECT-probe should set the per-applet flags from each transmit
    outcome (SW=0x9000 → installed, APDUError → missing).

    The Keycard probe iterates a small range of instance suffixes
    (0x01..0x0F), so the mock dispatches outcomes by AID rather than by
    call order.
    """

    _KEYCARD_PREFIX = bytes.fromhex("A000000804000101")
    _SEEDKEEPER_AID = bytes([0x53, 0x65, 0x65, 0x64, 0x4b, 0x65, 0x65, 0x70, 0x65, 0x72])

    def _patched_stack(self, *, keycard_installed_suffix=None,
                       seedkeeper_installed=False):
        """Return a context manager whose mocked ``transmit`` matches the
        APDU's AID against the expected outcomes.

        ``keycard_installed_suffix`` is an int suffix (0x01..0x0F) that
        returns success; any other suffix raises ``APDUError(0x6A82)``.
        """
        from contextlib import ExitStack
        from unittest.mock import patch
        from seedsigner.helpers.keycard.commands import APDUError

        keycard_prefix = self._KEYCARD_PREFIX
        seedkeeper_aid = self._SEEDKEEPER_AID

        class _MockClient:
            def __init__(self, _conn):
                pass

            def transmit(self, apdu):
                # APDU layout: [CLA, INS, P1, P2, Lc, ...aid...]
                aid = bytes(apdu[5:])
                if aid.startswith(keycard_prefix) and len(aid) == 9:
                    suffix = aid[-1]
                    if keycard_installed_suffix is not None and suffix == keycard_installed_suffix:
                        return b""
                    raise APDUError(0x6A82, "applet not found")
                if aid == seedkeeper_aid:
                    if seedkeeper_installed:
                        return b""
                    raise APDUError(0x6A82, "applet not found")
                raise APDUError(0x6A82, "unknown AID")

        stack = ExitStack()
        stack.enter_context(_patch_reader_present())
        stack.enter_context(patch(
            "seedsigner.helpers.keycard.reader.wait_for_card",
            return_value=MagicMock(),
        ))
        stack.enter_context(patch(
            "seedsigner.helpers.keycard.client.KeycardClient",
            _MockClient,
        ))
        return stack

    def test_all_installed(self):
        from seedsigner.helpers.card_probe import probe_installed_applets
        with self._patched_stack(keycard_installed_suffix=0x01,
                                  seedkeeper_installed=True):
            state = probe_installed_applets(MagicMock())
        self.assertTrue(state.present)
        self.assertTrue(state.keycard_installed)
        self.assertTrue(state.seedkeeper_installed)

    def test_none_installed(self):
        from seedsigner.helpers.card_probe import probe_installed_applets
        with self._patched_stack():
            state = probe_installed_applets(MagicMock())
        self.assertTrue(state.present)
        self.assertFalse(state.keycard_installed)
        self.assertFalse(state.seedkeeper_installed)

    def test_only_keycard(self):
        from seedsigner.helpers.card_probe import probe_installed_applets
        with self._patched_stack(keycard_installed_suffix=0x01):
            state = probe_installed_applets(MagicMock())
        self.assertTrue(state.keycard_installed)
        self.assertFalse(state.seedkeeper_installed)

    def test_keycard_non_default_suffix(self):
        """keycard-shell cards often live on a non-default suffix; the
        probe must still flag them as installed."""
        from seedsigner.helpers.card_probe import probe_installed_applets
        with self._patched_stack(keycard_installed_suffix=0x03):
            state = probe_installed_applets(MagicMock())
        self.assertTrue(state.keycard_installed)

    def test_keycard_prefers_active_aid(self):
        """If ``controller.active_keycard_aid`` is set, the probe should
        try it first (mirroring select_with_autodetect)."""
        from seedsigner.helpers.card_probe import probe_installed_applets
        controller = MagicMock()
        controller.active_keycard_aid = self._KEYCARD_PREFIX + b"\x07"
        with self._patched_stack(keycard_installed_suffix=0x07):
            state = probe_installed_applets(controller)
        self.assertTrue(state.keycard_installed)

    def test_only_seedkeeper(self):
        from seedsigner.helpers.card_probe import probe_installed_applets
        with self._patched_stack(seedkeeper_installed=True):
            state = probe_installed_applets(MagicMock())
        self.assertFalse(state.keycard_installed)
        self.assertTrue(state.seedkeeper_installed)

    def test_no_reader_returns_absent(self):
        from seedsigner.helpers.card_probe import probe_installed_applets
        with _patch_reader_absent():
            state = probe_installed_applets(MagicMock())
        self.assertFalse(state.present)
        self.assertFalse(state.keycard_installed)


class TestRunCardGate(unittest.TestCase):
    """Branch coverage for the gate helper that wraps probe + routing."""

    def _make_view(self, run_screen_return=None):
        view = MagicMock()
        view.controller = MagicMock()
        view.run_screen = MagicMock(return_value=run_screen_return)
        view.__class__ = MagicMock()
        return view

    def test_returns_none_when_card_ok(self):
        from seedsigner.helpers.card_probe import ProbeResult, run_card_gate
        view = self._make_view()
        ok = ProbeResult(present=True, kind_match=True, initialised=True)
        with patch("seedsigner.helpers.card_probe.probe_card", return_value=ok):
            result = run_card_gate(view, "keycard", title="Keycard",
                                   setup_view=MagicMock())
        self.assertIsNone(result)

    def test_routes_to_setup_when_uninitialised(self):
        from seedsigner.helpers.card_probe import ProbeResult, run_card_gate
        view = self._make_view()
        uninit = ProbeResult(present=True, kind_match=True, initialised=False)
        setup_view = MagicMock(name="SetupView")
        with patch("seedsigner.helpers.card_probe.probe_card", return_value=uninit):
            result = run_card_gate(view, "keycard", title="Keycard",
                                   setup_view=setup_view)
        self.assertIs(result.View_cls, setup_view)
        self.assertTrue(result.skip_current_view)

    def test_wrong_applet_offers_install(self):
        """Card present but wrong applet → menu with Install / Cancel.
        The "Install" path (index 0) routes to ``CardsInstallAppletView``
        with the requested ``kind``."""
        from seedsigner.helpers.card_probe import ProbeResult, run_card_gate
        view = self._make_view(run_screen_return=0)
        wrong = ProbeResult(present=True, kind_match=False, initialised=False)
        with patch("seedsigner.helpers.card_probe.probe_card", return_value=wrong):
            result = run_card_gate(view, "seedkeeper", title="SeedKeeper",
                                   setup_view=MagicMock())
        from seedsigner.views.view import CardsInstallAppletView
        self.assertIs(result.View_cls, CardsInstallAppletView)
        self.assertEqual(result.view_args.get("kind"), "seedkeeper")
        self.assertTrue(result.skip_current_view)

    def test_wrong_applet_cancel_pops_back(self):
        from seedsigner.helpers.card_probe import ProbeResult, run_card_gate
        view = self._make_view(run_screen_return=1)  # Cancel
        wrong = ProbeResult(present=True, kind_match=False, initialised=False)
        with patch("seedsigner.helpers.card_probe.probe_card", return_value=wrong):
            result = run_card_gate(view, "seedkeeper", title="SeedKeeper",
                                   setup_view=MagicMock())
        from seedsigner.views.view import BackStackView
        self.assertIs(result.View_cls, BackStackView)

    def test_absent_redirects_home_with_toast(self):
        """Card absent → snap back to MainMenuView with an InfoToast.

        Replaces the old CardWaitScreen flow: no intermediate "Insert
        card" screen, just a direct redirect plus a "No card — returned
        home" notification surfaced via ``Controller.activate_toast``.
        ``InfoToast`` itself requires a configured ``Renderer``, so we
        patch the class with a sentinel and assert it was constructed
        with the expected label text.
        """
        from seedsigner.helpers.card_probe import ProbeResult, run_card_gate
        view = self._make_view()
        absent = ProbeResult(present=False, kind_match=False, initialised=False)
        toast_factory = MagicMock(name="InfoToast")
        with patch("seedsigner.helpers.card_probe.probe_card", return_value=absent), \
             patch("seedsigner.gui.toast.InfoToast", toast_factory):
            result = run_card_gate(view, "keycard", title="Keycard",
                                   setup_view=MagicMock())
        from seedsigner.views.view import MainMenuView
        self.assertIs(result.View_cls, MainMenuView)
        self.assertTrue(result.clear_history)
        toast_factory.assert_called_once()
        kwargs = toast_factory.call_args.kwargs
        self.assertIn("No card", kwargs.get("label_text", ""))
        view.controller.activate_toast.assert_called_once_with(
            toast_factory.return_value
        )


if __name__ == "__main__":
    unittest.main()
