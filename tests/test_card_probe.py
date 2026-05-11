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


class TestProbeSatochipFamily(unittest.TestCase):
    def test_satochip_initialised(self):
        from seedsigner.helpers.card_probe import probe_card
        connector = _patched_card_connector(setup_done=True)
        with _patch_reader_present(), \
             patch("pysatochip.CardConnector.CardConnector",
                   return_value=connector):
            res = probe_card("satochip", controller=MagicMock())
        self.assertTrue(res.present)
        self.assertTrue(res.kind_match)
        self.assertTrue(res.initialised)

    def test_satochip_uninitialised(self):
        from seedsigner.helpers.card_probe import probe_card
        connector = _patched_card_connector(setup_done=False)
        with _patch_reader_present(), \
             patch("pysatochip.CardConnector.CardConnector",
                   return_value=connector):
            res = probe_card("satochip", controller=MagicMock())
        self.assertTrue(res.present)
        self.assertTrue(res.kind_match)
        self.assertFalse(res.initialised)

    def test_seedkeeper_initialised(self):
        from seedsigner.helpers.card_probe import probe_card
        connector = _patched_card_connector(setup_done=True)
        with _patch_reader_present(), \
             patch("pysatochip.CardConnector.CardConnector",
                   return_value=connector):
            res = probe_card("seedkeeper", controller=MagicMock())
        self.assertTrue(res.present)
        self.assertTrue(res.initialised)

    def test_connector_raises_card_absent(self):
        from seedsigner.helpers.card_probe import probe_card
        with _patch_reader_absent(), \
             patch("pysatochip.CardConnector.CardConnector",
                   side_effect=Exception("no card")):
            res = probe_card("satochip", controller=MagicMock())
        self.assertFalse(res.present)

    def test_connector_raises_card_present(self):
        """Reader has *something* but pysatochip rejects it — likely a
        Keycard or a card we can't talk to with the Satochip applet."""
        from seedsigner.helpers.card_probe import probe_card
        with _patch_reader_present(), \
             patch("pysatochip.CardConnector.CardConnector",
                   side_effect=Exception("applet not found")):
            res = probe_card("satochip", controller=MagicMock())
        self.assertTrue(res.present)
        self.assertFalse(res.kind_match)

    def test_unknown_kind_raises(self):
        from seedsigner.helpers.card_probe import probe_card
        with self.assertRaises(ValueError):
            probe_card("smartpgp", controller=MagicMock())  # type: ignore[arg-type]


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

    def test_warns_on_wrong_applet(self):
        from seedsigner.helpers.card_probe import ProbeResult, run_card_gate
        view = self._make_view()
        wrong = ProbeResult(present=True, kind_match=False, initialised=False)
        with patch("seedsigner.helpers.card_probe.probe_card", return_value=wrong):
            result = run_card_gate(view, "keycard", title="Keycard",
                                   setup_view=MagicMock())
        # WarningScreen was rendered; result is a back-stack pop.
        self.assertTrue(view.run_screen.called)
        from seedsigner.views.view import BackStackView
        self.assertIs(result.View_cls, BackStackView)

    def test_cancel_from_wait_pops_back(self):
        from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
        from seedsigner.helpers.card_probe import ProbeResult, run_card_gate
        view = self._make_view(run_screen_return=RET_CODE__BACK_BUTTON)
        absent = ProbeResult(present=False, kind_match=False, initialised=False)
        with patch("seedsigner.helpers.card_probe.probe_card", return_value=absent):
            result = run_card_gate(view, "keycard", title="Keycard",
                                   setup_view=MagicMock())
        from seedsigner.views.view import BackStackView
        self.assertIs(result.View_cls, BackStackView)

    def test_insert_from_wait_reenters_view(self):
        from seedsigner.gui.screens.screen import RET_CODE__CARD_INSERTED
        from seedsigner.helpers.card_probe import ProbeResult, run_card_gate
        view = self._make_view(run_screen_return=RET_CODE__CARD_INSERTED)
        view_cls = view.__class__
        absent = ProbeResult(present=False, kind_match=False, initialised=False)
        with patch("seedsigner.helpers.card_probe.probe_card", return_value=absent):
            result = run_card_gate(view, "keycard", title="Keycard",
                                   setup_view=MagicMock())
        self.assertIs(result.View_cls, view_cls)
        self.assertTrue(result.skip_current_view)


if __name__ == "__main__":
    unittest.main()
