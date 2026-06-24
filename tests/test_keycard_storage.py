"""Tests for the Keycard "Storage" feature.

Covers:
- ``parse_extended_card_resources`` (GET DATA 0xFF21 TLV parser) across the
  wrapped / bare / multi-byte / missing-tag / truncated encodings.
- ``GpSecureChannel.get_extended_card_resources`` end-to-end against a fake
  PC/SC connection (success + unsupported-tag → raises).
- The per-app size helpers in ``views/view.py`` used for both the occupation
  bar and the pre-install free-space check.
- ``_warn_if_low_space`` soft-warning behaviour (warn / override / skip).
- ``ToolsKeycardStorageView`` routing: renders the bar screen when memory is
  available and an "unavailable" message otherwise.
"""

from __future__ import annotations

import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def _install_hw_mocks():
    for mod in [
        "RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
        "smartcard", "smartcard.System", "smartcard.CardMonitoring", "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
        "periphery",
    ]:
        sys.modules.setdefault(mod, MagicMock())


_install_hw_mocks()


# ---------------------------------------------------------------------------
# parse_extended_card_resources
# ---------------------------------------------------------------------------
class TestParseExtendedCardResources(unittest.TestCase):
    def _parse(self, hexstr):
        from seedsigner.helpers.keycard.global_platform import (
            parse_extended_card_resources,
        )
        return parse_extended_card_resources(bytes.fromhex(hexstr))

    def test_wrapped_template(self):
        # FF21 len=09 { 81 01 02 | 82 02 7FFF | 83 02 0F00 }
        m = self._parse("FF2109 810102 82027FFF 83020F00".replace(" ", ""))
        self.assertEqual(m.num_apps, 2)
        self.assertEqual(m.free_nv, 0x7FFF)
        self.assertEqual(m.free_volatile, 0x0F00)

    def test_bare_inner_tlvs(self):
        m = self._parse("810103 8203010000 830200FF".replace(" ", ""))
        self.assertEqual(m.num_apps, 3)
        self.assertEqual(m.free_nv, 0x010000)  # 3-byte value
        self.assertEqual(m.free_volatile, 0x00FF)

    def test_missing_volatile_defaults_zero(self):
        m = self._parse("810101 82021000".replace(" ", ""))
        self.assertEqual(m.num_apps, 1)
        self.assertEqual(m.free_nv, 0x1000)
        self.assertEqual(m.free_volatile, 0)

    def test_long_form_outer_length(self):
        # FF21 81 09 { ... } — long-form length on the outer template.
        m = self._parse("FF2181 09 810102 82027FFF 83020F00".replace(" ", ""))
        self.assertEqual(m.free_nv, 0x7FFF)
        self.assertEqual(m.num_apps, 2)

    def test_truncated_entry_bails(self):
        # 82 claims 4 bytes but only 1 is present → stop, don't crash.
        m = self._parse("810101 8204AB".replace(" ", ""))
        self.assertEqual(m.num_apps, 1)
        self.assertEqual(m.free_nv, 0)

    def test_empty_input(self):
        m = self._parse("")
        self.assertEqual((m.num_apps, m.free_nv, m.free_volatile), (0, 0, 0))


# ---------------------------------------------------------------------------
# GpSecureChannel.get_extended_card_resources
# ---------------------------------------------------------------------------
class _FakeConn:
    """Minimal PC/SC connection: SELECT always 9000, GET DATA configurable."""

    def __init__(self, get_data_resp, get_data_sw=(0x90, 0x00)):
        self.get_data_resp = list(get_data_resp)
        self.get_data_sw = get_data_sw

    def transmit(self, apdu):
        ins = apdu[1]
        if ins == 0xA4:          # SELECT ISD
            return ([], 0x90, 0x00)
        if ins == 0xCA:          # GET DATA
            return (self.get_data_resp, self.get_data_sw[0], self.get_data_sw[1])
        return ([], 0x90, 0x00)


class TestGetExtendedCardResources(unittest.TestCase):
    def test_reads_free_memory(self):
        from seedsigner.helpers.keycard.global_platform import GpSecureChannel
        resp = bytes.fromhex("FF2109 810102 82027FFF 83020F00".replace(" ", ""))
        ch = GpSecureChannel(_FakeConn(resp))
        ch.select_isd()
        mem = ch.get_extended_card_resources()
        self.assertEqual(mem.free_nv, 0x7FFF)
        self.assertEqual(mem.num_apps, 2)

    def test_unsupported_tag_raises(self):
        from seedsigner.helpers.keycard.global_platform import (
            GpSecureChannel, GpProtocolError,
        )
        # GET DATA returns 6A88 "referenced data not found".
        ch = GpSecureChannel(_FakeConn(b"", get_data_sw=(0x6A, 0x88)))
        ch.select_isd()
        with self.assertRaises(GpProtocolError):
            ch.get_extended_card_resources()


# ---------------------------------------------------------------------------
# query_card_memory degrade-to-None
# ---------------------------------------------------------------------------
class TestQueryCardMemory(unittest.TestCase):
    def test_returns_none_on_failure(self):
        from seedsigner.helpers.keycard import ui_helpers
        from seedsigner.helpers.keycard import reader as reader_mod
        from seedsigner.helpers import seedkeeper_utils

        view = MagicMock()
        with patch.object(reader_mod, "release_other_smartcard_holders"), \
             patch.object(reader_mod, "wait_for_card",
                          side_effect=Exception("no card")), \
             patch.object(seedkeeper_utils, "disconnect_smartcard_connections"):
            self.assertIsNone(ui_helpers.query_card_memory(view))


# ---------------------------------------------------------------------------
# view.py size helpers
# ---------------------------------------------------------------------------
class TestSizeHelpers(unittest.TestCase):
    def test_store_bytes_from_param(self):
        from seedsigner.views.view import store_bytes_from_param
        self.assertEqual(store_bytes_from_param("0FFF"), 4 * 1024)
        self.assertEqual(store_bytes_from_param("1FFF"), 8 * 1024)
        self.assertEqual(store_bytes_from_param("FFFF"), 64 * 1024)

    def test_required_nv_keycard(self):
        # Required = the recalibrated real footprint (cap size scaled down to
        # exclude the .cap's non-loaded Debug/Descriptor/Export components).
        from seedsigner.views import view as view_mod
        with patch.object(view_mod, "cap_size_for_kind", return_value=30000):
            self.assertEqual(
                view_mod.required_nv_for_install("keycard"),
                int(30000 * view_mod.CAP_NV_FOOTPRINT_RATIO),
            )

    def test_required_nv_seedkeeper_adds_store(self):
        from seedsigner.views import view as view_mod
        with patch.object(view_mod, "cap_size_for_kind", return_value=10000):
            req = view_mod.required_nv_for_install("seedkeeper", "0FFF")
            self.assertEqual(
                req, int(10000 * view_mod.CAP_NV_FOOTPRINT_RATIO) + 4 * 1024)

    def test_required_nv_seedkeeper_default_store(self):
        from seedsigner.views import view as view_mod
        with patch.object(view_mod, "cap_size_for_kind", return_value=10000):
            req = view_mod.required_nv_for_install("seedkeeper")
            self.assertEqual(
                req,
                int(10000 * view_mod.CAP_NV_FOOTPRINT_RATIO)
                + view_mod.SEEDKEEPER_DEFAULT_STORE_BYTES,
            )

    def test_required_nv_none_when_cap_unknown(self):
        from seedsigner.views import view as view_mod
        with patch.object(view_mod, "cap_size_for_kind", return_value=None):
            self.assertIsNone(view_mod.required_nv_for_install("keycard"))

    def test_estimated_used_nv(self):
        from seedsigner.views import view as view_mod

        sizes = {"keycard": 30000, "seedkeeper": 10000}

        def both(installed_keycard, installed_seedkeeper):
            probe = types.SimpleNamespace(
                keycard_installed=installed_keycard,
                seedkeeper_installed=installed_seedkeeper,
            )
            with patch.object(view_mod, "cap_size_for_kind",
                              side_effect=lambda k: sizes[k]):
                return view_mod.estimated_used_nv(probe)

        r = view_mod.CAP_NV_FOOTPRINT_RATIO
        self.assertEqual(both(False, False), 0)
        self.assertEqual(both(True, False), int(30000 * r))
        self.assertEqual(
            both(True, True),
            int(30000 * r) + int(10000 * r) + view_mod.SEEDKEEPER_DEFAULT_STORE_BYTES,
        )


# ---------------------------------------------------------------------------
# Per-instance NV estimate (memory-aware instance limit)
# ---------------------------------------------------------------------------
class TestInstanceNvEstimate(unittest.TestCase):
    def test_falls_back_to_constant(self):
        from seedsigner.views import view as view_mod
        # None / unset measurement -> conservative constant.
        c = types.SimpleNamespace(keycard_measured_instance_nv=None)
        self.assertEqual(
            view_mod.keycard_instance_nv_estimate(c),
            view_mod.KEYCARD_INSTANCE_NV_ESTIMATE_BYTES,
        )

    def test_uses_measured_when_present(self):
        from seedsigner.views import view as view_mod
        c = types.SimpleNamespace(keycard_measured_instance_nv=1500)
        self.assertEqual(view_mod.keycard_instance_nv_estimate(c), 1500)

    def test_non_int_measurement_ignored(self):
        from seedsigner.views import view as view_mod
        from unittest.mock import MagicMock
        # A MagicMock attr (or any non-int) must not poison the arithmetic.
        c = MagicMock()
        self.assertEqual(
            view_mod.keycard_instance_nv_estimate(c),
            view_mod.KEYCARD_INSTANCE_NV_ESTIMATE_BYTES,
        )


class TestInstanceVolatileEstimate(unittest.TestCase):
    def test_falls_back_to_constant(self):
        from seedsigner.views import view as view_mod
        c = types.SimpleNamespace(keycard_measured_instance_volatile=None)
        self.assertEqual(
            view_mod.keycard_instance_volatile_estimate(c),
            view_mod.KEYCARD_INSTANCE_VOLATILE_ESTIMATE_BYTES,
        )

    def test_uses_measured_when_present(self):
        from seedsigner.views import view as view_mod
        c = types.SimpleNamespace(keycard_measured_instance_volatile=300)
        self.assertEqual(view_mod.keycard_instance_volatile_estimate(c), 300)

    def test_non_int_measurement_ignored(self):
        from seedsigner.views import view as view_mod
        from unittest.mock import MagicMock
        c = MagicMock()
        self.assertEqual(
            view_mod.keycard_instance_volatile_estimate(c),
            view_mod.KEYCARD_INSTANCE_VOLATILE_ESTIMATE_BYTES,
        )


class TestEstimateRemainingInstances(unittest.TestCase):
    def test_memory_is_binding(self):
        from seedsigner.views.view import (
            estimate_remaining_instances, LOW_SPACE_MARGIN_BYTES,
        )
        # free 20 KB, 3 KB each: (20480-2048)//3072 = 5; slot headroom 14.
        self.assertEqual(
            estimate_remaining_instances(20480, 2, 3072, 16),
            (20480 - LOW_SPACE_MARGIN_BYTES) // 3072,
        )

    def test_slot_ceiling_is_binding(self):
        from seedsigner.views.view import estimate_remaining_instances
        # Plenty of memory, but only 1 slot left below the ceiling.
        self.assertEqual(estimate_remaining_instances(10**9, 15, 3072, 16), 1)

    def test_zero_when_memory_exhausted(self):
        from seedsigner.views.view import estimate_remaining_instances
        # free below the margin -> no room.
        self.assertEqual(estimate_remaining_instances(1000, 2, 3072, 16), 0)

    def test_zero_when_slots_exhausted(self):
        from seedsigner.views.view import estimate_remaining_instances
        self.assertEqual(estimate_remaining_instances(10**9, 16, 3072, 16), 0)

    def test_none_free_nv_uses_slot_headroom(self):
        from seedsigner.views.view import estimate_remaining_instances
        # Card didn't expose the memory tag: fall back to slot headroom alone.
        self.assertEqual(estimate_remaining_instances(None, 4, 3072, 16), 12)

    def test_ram_is_binding(self):
        from seedsigner.views.view import (
            estimate_remaining_instances, LOW_SPACE_VOLATILE_MARGIN_BYTES,
        )
        # Plenty of EEPROM + slots, but RAM is the scarce resource: free RAM
        # 1024, 512 each -> (1024-256)//512 = 1. RAM gate wins over NV (huge) and
        # slot headroom (14).
        self.assertEqual(
            estimate_remaining_instances(
                10**9, 2, 3072, 16,
                free_volatile=1024, per_instance_volatile=512,
            ),
            (1024 - LOW_SPACE_VOLATILE_MARGIN_BYTES) // 512,
        )

    def test_free_volatile_zero_falls_back_to_nv(self):
        from seedsigner.views.view import estimate_remaining_instances
        # free_volatile == 0 means tag 0x83 absent/unsupported, NOT "no RAM":
        # the RAM gate must be skipped and the result equal the NV+slot estimate.
        with_zero = estimate_remaining_instances(
            20480, 2, 3072, 16, free_volatile=0, per_instance_volatile=512,
        )
        without = estimate_remaining_instances(20480, 2, 3072, 16)
        self.assertEqual(with_zero, without)
        self.assertGreater(with_zero, 0)

    def test_free_volatile_none_falls_back_to_nv(self):
        from seedsigner.views.view import estimate_remaining_instances
        with_none = estimate_remaining_instances(
            20480, 2, 3072, 16, free_volatile=None, per_instance_volatile=512,
        )
        without = estimate_remaining_instances(20480, 2, 3072, 16)
        self.assertEqual(with_none, without)

    def test_ram_gate_ignored_when_per_instance_volatile_none(self):
        from seedsigner.views.view import estimate_remaining_instances
        # Card reports RAM but we have no per-instance RAM estimate -> skip gate.
        with_no_per = estimate_remaining_instances(
            20480, 2, 3072, 16, free_volatile=1024, per_instance_volatile=None,
        )
        without = estimate_remaining_instances(20480, 2, 3072, 16)
        self.assertEqual(with_no_per, without)

    def test_real_full_card_returns_zero(self):
        """Regression with the field card's measured GET DATA 0xFF21 values:
        NV=46596 (plenty), but free RAM=303 (exhausted) after 4 instances. The
        RAM gate must drive the estimate to 0 even though EEPROM/slots are free."""
        from seedsigner.views.view import (
            estimate_remaining_instances,
            KEYCARD_INSTANCE_VOLATILE_ESTIMATE_BYTES,
        )
        self.assertEqual(
            estimate_remaining_instances(
                46596, 4, 3072, 16,
                free_volatile=303,
                per_instance_volatile=KEYCARD_INSTANCE_VOLATILE_ESTIMATE_BYTES,
            ),
            0,
        )


# ---------------------------------------------------------------------------
# _warn_if_low_space
# ---------------------------------------------------------------------------
class TestWarnIfLowSpace(unittest.TestCase):
    def _mem(self, free_nv):
        from seedsigner.helpers.keycard.global_platform import CardMemory
        return CardMemory(free_nv=free_nv, free_volatile=0, num_apps=1)

    def test_warns_and_back_cancels(self):
        from seedsigner.views import view as view_mod
        from seedsigner.helpers.keycard import ui_helpers
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        from seedsigner.gui.screens.screen import DireWarningScreen

        view = MagicMock()
        view.run_screen = MagicMock(return_value=RET_CODE__BACK_BUTTON)
        with patch.object(view_mod, "cap_size_for_kind", return_value=30000), \
             patch.object(ui_helpers, "query_card_memory",
                          return_value=self._mem(1000)):
            result = view_mod._warn_if_low_space(view, "keycard")
        self.assertEqual(result, "back")
        self.assertIs(view.run_screen.call_args.args[0], DireWarningScreen)

    def test_override_proceeds(self):
        from seedsigner.views import view as view_mod
        from seedsigner.helpers.keycard import ui_helpers

        view = MagicMock()
        view.run_screen = MagicMock(return_value=0)  # "Install anyway"
        with patch.object(view_mod, "cap_size_for_kind", return_value=30000), \
             patch.object(ui_helpers, "query_card_memory",
                          return_value=self._mem(1000)):
            self.assertIsNone(view_mod._warn_if_low_space(view, "keycard"))
        self.assertTrue(view.run_screen.called)

    def test_enough_space_no_warning(self):
        from seedsigner.views import view as view_mod
        from seedsigner.helpers.keycard import ui_helpers

        view = MagicMock()
        view.run_screen = MagicMock()
        with patch.object(view_mod, "cap_size_for_kind", return_value=30000), \
             patch.object(ui_helpers, "query_card_memory",
                          return_value=self._mem(100000)):
            self.assertIsNone(view_mod._warn_if_low_space(view, "keycard"))
        view.run_screen.assert_not_called()

    def test_unreadable_memory_skips(self):
        from seedsigner.views import view as view_mod
        from seedsigner.helpers.keycard import ui_helpers

        view = MagicMock()
        view.run_screen = MagicMock()
        with patch.object(view_mod, "cap_size_for_kind", return_value=30000), \
             patch.object(ui_helpers, "query_card_memory", return_value=None):
            self.assertIsNone(view_mod._warn_if_low_space(view, "keycard"))
        view.run_screen.assert_not_called()

    def test_unknown_cap_size_skips(self):
        from seedsigner.views import view as view_mod
        from seedsigner.helpers.keycard import ui_helpers

        view = MagicMock()
        view.run_screen = MagicMock()
        with patch.object(view_mod, "cap_size_for_kind", return_value=None), \
             patch.object(ui_helpers, "query_card_memory") as q:
            self.assertIsNone(view_mod._warn_if_low_space(view, "keycard"))
        view.run_screen.assert_not_called()
        q.assert_not_called()  # short-circuits before touching the card

    def test_cap_oversize_no_longer_false_positives(self):
        # Regression: the .cap file over-estimates the real on-card footprint,
        # so a card that fits the *real* applet (but not the raw cap size) must
        # NOT warn. With a free amount below the raw cap but comfortably above
        # the recalibrated footprint, the old code warned and the new code
        # doesn't.
        from seedsigner.views import view as view_mod
        from seedsigner.helpers.keycard import ui_helpers

        cap = 30000
        real = int(cap * view_mod.CAP_NV_FOOTPRINT_RATIO)
        free = real + view_mod.LOW_SPACE_MARGIN_BYTES + 1000
        self.assertLess(free, cap)  # the raw-cap check would have warned here

        view = MagicMock()
        view.run_screen = MagicMock()
        with patch.object(view_mod, "cap_size_for_kind", return_value=cap), \
             patch.object(ui_helpers, "query_card_memory",
                          return_value=self._mem(free)):
            self.assertIsNone(view_mod._warn_if_low_space(view, "keycard"))
        view.run_screen.assert_not_called()

    def test_clear_shortfall_still_warns(self):
        # A card that can't even fit the recalibrated footprint still warns.
        from seedsigner.views import view as view_mod
        from seedsigner.helpers.keycard import ui_helpers
        from seedsigner.gui.screens.screen import DireWarningScreen

        cap = 30000
        real = int(cap * view_mod.CAP_NV_FOOTPRINT_RATIO)
        free = real - view_mod.LOW_SPACE_MARGIN_BYTES - 1000

        view = MagicMock()
        view.run_screen = MagicMock(return_value=0)  # "Install anyway"
        with patch.object(view_mod, "cap_size_for_kind", return_value=cap), \
             patch.object(ui_helpers, "query_card_memory",
                          return_value=self._mem(free)):
            self.assertIsNone(view_mod._warn_if_low_space(view, "keycard"))
        self.assertIs(view.run_screen.call_args.args[0], DireWarningScreen)

    def test_prefetched_mem_skips_second_query(self):
        # When a CardMemory is passed in (already read to show free space on
        # the chooser), the check must not re-query the card.
        from seedsigner.views import view as view_mod
        from seedsigner.helpers.keycard import ui_helpers

        view = MagicMock()
        view.run_screen = MagicMock()
        with patch.object(view_mod, "cap_size_for_kind", return_value=30000), \
             patch.object(ui_helpers, "query_card_memory") as q:
            self.assertIsNone(
                view_mod._warn_if_low_space(
                    view, "keycard", mem=self._mem(100000)))
        q.assert_not_called()
        view.run_screen.assert_not_called()


# ---------------------------------------------------------------------------
# ToolsKeycardStorageView
# ---------------------------------------------------------------------------
class TestStorageView(unittest.TestCase):
    def _make_view(self):
        from seedsigner.views.keycard_views import ToolsKeycardStorageView
        view = ToolsKeycardStorageView.__new__(ToolsKeycardStorageView)
        view.controller = MagicMock()
        # Real Controller defaults these; on a MagicMock the attributes would
        # otherwise be truthy/non-int Mocks and skew the estimate.
        view.controller.keycard_install_full = False
        view.controller.keycard_measured_instance_nv = None
        view.controller.keycard_measured_instance_volatile = None
        view.run_screen = MagicMock(return_value=0)
        return view

    def test_unavailable_when_no_memory(self):
        from seedsigner.helpers.keycard import ui_helpers
        from seedsigner.gui.screens.screen import (
            KeycardStorageScreen, LargeIconStatusScreen,
        )
        from seedsigner.views.view import BackStackView

        view = self._make_view()
        with patch.object(ui_helpers, "query_card_memory", return_value=None):
            dest = view.run()

        self.assertIs(view.run_screen.call_args.args[0], LargeIconStatusScreen)
        self.assertIs(dest.View_cls, BackStackView)
        # The bar screen must NOT have been used.
        self.assertNotEqual(view.run_screen.call_args.args[0], KeycardStorageScreen)

    def test_renders_bar_with_computed_totals(self):
        from seedsigner.views import view as view_mod
        from seedsigner.views import keycard_views
        from seedsigner.helpers.keycard import ui_helpers
        from seedsigner.helpers import card_probe as card_probe_mod
        from seedsigner.helpers.keycard.global_platform import CardMemory
        from seedsigner.gui.screens.screen import KeycardStorageScreen

        view = self._make_view()
        # No measured per-instance footprint -> the estimate uses the constant.
        view.controller.keycard_measured_instance_nv = None
        mem = CardMemory(free_nv=50000, free_volatile=0, num_apps=2)
        probe = types.SimpleNamespace(
            keycard_installed=True, seedkeeper_installed=False,
        )
        with patch.object(ui_helpers, "query_card_memory", return_value=mem), \
             patch.object(card_probe_mod, "probe_installed_applets",
                          return_value=probe), \
             patch.object(keycard_views, "_probe_keycard_instance_count_exact",
                          return_value=2), \
             patch.object(view_mod, "estimated_used_nv", return_value=20000):
            view.run()

        kwargs = view.run_screen.call_args.kwargs
        self.assertIs(view.run_screen.call_args.args[0], KeycardStorageScreen)
        self.assertEqual(kwargs["free_bytes"], 50000)
        self.assertEqual(kwargs["free_volatile_bytes"], 0)
        self.assertEqual(kwargs["used_bytes"], 20000)
        self.assertEqual(kwargs["total_bytes"], 70000)
        # 2 instances exist; ceiling 16 -> slot headroom 14. Memory headroom
        # (50000-2048)//3072 = 15. min(14, 15) = 14.
        self.assertEqual(kwargs["remaining_instances"], 14)


if __name__ == "__main__":
    unittest.main()
