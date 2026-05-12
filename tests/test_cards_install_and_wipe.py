"""Tests for the Keycard install / factory-reset hardening that handles
orphan 7-byte package load files.

``probe_installed_applets`` only ``SELECT``s against instance AIDs, so a
card that has just the Keycard *package* loaded (no instances) appears
"not installed" to both the menu and the factory-reset target picker.
The install path covers that gap by unconditionally cascade-deleting the
package before ``--load``; the factory-reset path covers it by always
including the Keycard package in its delete list. Both rely on a new
``suppress_failure_dialog`` kwarg on ``run_globalplatform`` so a clean
card doesn't surface a spurious "Failed" screen.
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


def _make_install_view(kind="keycard"):
    from seedsigner.views.view import CardsInstallAppletView
    v = CardsInstallAppletView.__new__(CardsInstallAppletView)
    v.kind = kind
    v.controller = MagicMock()
    v.run_screen = MagicMock(return_value=0)
    return v


def _make_factory_reset_view():
    from seedsigner.views.view import CardsFactoryResetView
    v = CardsFactoryResetView.__new__(CardsFactoryResetView)
    v.controller = MagicMock()
    return v


def _present_state(**flags):
    from seedsigner.helpers.card_probe import CardInstalledState
    return CardInstalledState(
        True,
        flags.get("keycard", False),
        flags.get("satochip", False),
        flags.get("seedkeeper", False),
    )


def _absent_state():
    """Reader has no card at all (probe returns ``present=False``)."""
    from seedsigner.helpers.card_probe import CardInstalledState
    return CardInstalledState(False, False, False, False)


def _present_but_empty_state():
    """Card in reader, but no Keycard / Satochip / SeedKeeper applets
    detected. This is the "clean card, default ISD keys" scenario the
    factory-reset path must still target Keycard against (orphan-load-
    file recovery)."""
    from seedsigner.helpers.card_probe import CardInstalledState
    return CardInstalledState(True, False, False, False)


class TestKeycardInstallPreDelete(unittest.TestCase):
    """``CardsInstallAppletView`` must run ``--delete A0000008040001
    -force`` with the failure dialog suppressed *before* anything else
    when installing the Keycard applet."""

    def _stub_microsd_and_runner(self, run_results):
        """Patch ``MicroSD.get_microsd_dir`` so the CAP path "exists" and
        ``run_globalplatform`` so we capture every invocation. ``run_results``
        is a list of return values applied positionally — pre-delete is
        index 0, then --load, then 3 × --create."""
        from pathlib import Path

        cap_path = Path("/tmp/seedsigner-test-microsd")
        cap_dir = cap_path / "javacard-cap"
        cap_dir.mkdir(parents=True, exist_ok=True)
        (cap_dir / "Keycard-3.2.cap").touch()

        calls = []

        def fake_run(*args, **kwargs):
            calls.append((args, kwargs))
            idx = len(calls) - 1
            return run_results[idx] if idx < len(run_results) else run_results[-1]

        microsd_patch = patch(
            "seedsigner.hardware.microsd.MicroSD.get_microsd_dir",
            return_value=cap_path,
        )
        runner_patch = patch(
            "seedsigner.helpers.seedkeeper_utils.run_globalplatform",
            side_effect=fake_run,
        )
        disconnect_patch = patch(
            "seedsigner.helpers.seedkeeper_utils.disconnect_smartcard_connections",
            MagicMock(),
        )
        return microsd_patch, runner_patch, disconnect_patch, calls

    def test_pre_delete_is_first_and_suppressed(self):
        v = _make_install_view("keycard")
        # All steps succeed (truthy).
        m, r, d, calls = self._stub_microsd_and_runner([True, True, True, True, True])
        with m, r, d:
            v.run()

        # 1 pre-delete + 1 --load + 3 × --create = 5.
        self.assertEqual(len(calls), 5)
        first_args, first_kwargs = calls[0]
        # Positional command argument: (view, command, label, success).
        self.assertEqual(first_args[1], "--delete A0000008040001 -force")
        self.assertEqual(first_args[2], "Preparing Keycard install")
        self.assertIs(first_kwargs.get("suppress_failure_dialog"), True)

        # The --load step must run with `-force` and *no* suppression.
        load_args, load_kwargs = calls[1]
        self.assertIn("--load", load_args[1])
        self.assertIn("-force", load_args[1])
        self.assertNotIn("suppress_failure_dialog", load_kwargs)

        # The 3 create steps come from _KEYCARD_CREATE_COMMANDS — order
        # is signing instance, NDEF, third instance.
        for i in range(2, 5):
            cmd = calls[i][0][1]
            self.assertIn("--create", cmd)
            self.assertIn("A0000008040001", cmd)

    def test_step_failure_reports_which_step(self):
        v = _make_install_view("keycard")
        captured_text = {}

        def fake_run_screen(_screen, **kwargs):
            captured_text["text"] = kwargs.get("text", "")
            return 0

        v.run_screen = fake_run_screen
        # Pre-delete succeeds (True), --load succeeds (True),
        # first --create FAILS (None) — should bail at the second step
        # of the audible recipe ("steps" = --load + 3 × --create = 4).
        # The pre-delete is intentionally NOT counted in the step
        # numbering shown to the user.
        m, r, d, _ = self._stub_microsd_and_runner([True, True, None, True, True])
        with m, r, d:
            v.run()

        self.assertIn("2/4", captured_text["text"])
        self.assertIn("Creating Keycard instance 1/3", captured_text["text"])

    def test_clean_card_install_still_succeeds(self):
        """Pre-delete returning None on a clean card (gp.jar's "not
        present on card" → suppressed) must not abort the install."""
        v = _make_install_view("keycard")
        # Pre-delete fails (None, but suppressed); load + 3 creates succeed.
        m, r, d, _ = self._stub_microsd_and_runner([None, True, True, True, True])
        with m, r, d:
            dest = v.run()

        # Reached the post-install routing.
        self.assertIsNotNone(dest)


class TestFactoryResetAlwaysTargetsKeycard(unittest.TestCase):
    """``_attempt_globalplatform_wipe`` must always include the Keycard
    package in its delete list — even when the probe reports keycard
    absent — so an orphan load file is reachable. The failure dialog is
    suppressed in that case so a genuinely clean card doesn't show
    a spurious "Failed" screen."""

    def _capture_calls(self, state, run_side_effect):
        view = _make_factory_reset_view()
        calls = []

        def fake_run(*args, **kwargs):
            calls.append((args, kwargs))
            return run_side_effect(len(calls) - 1)

        with patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=state,
        ), patch(
            "seedsigner.helpers.seedkeeper_utils.run_globalplatform",
            side_effect=fake_run,
        ):
            from seedsigner.views.view import _attempt_globalplatform_wipe
            result = _attempt_globalplatform_wipe(view)
        return result, calls

    def test_clean_card_still_attempts_keycard_silently(self):
        # Card present, probe sees nothing. All deletes return None.
        result, calls = self._capture_calls(
            _present_but_empty_state(), lambda _: None,
        )

        # Exactly one call: the Keycard package delete.
        self.assertEqual(len(calls), 1)
        args, kwargs = calls[0]
        self.assertEqual(args[1], "--delete A0000008040001 -force")
        self.assertIs(kwargs.get("suppress_failure_dialog"), True)

        # User-facing report stays clean — no spurious "Skipped: Keycard.".
        self.assertEqual(result, ["No applets to delete."])

    def test_no_card_in_reader_returns_early(self):
        # Pre-existing behaviour: if no card at all, don't even try.
        result, calls = self._capture_calls(_absent_state(), lambda _: True)
        self.assertEqual(calls, [])
        self.assertEqual(result, ["No card detected."])

    def test_keycard_present_runs_audible_delete(self):
        # Keycard present → suppress=False so a real failure does surface.
        state = _present_state(keycard=True)
        result, calls = self._capture_calls(state, lambda _: True)

        # One call, Keycard, NOT suppressed.
        self.assertEqual(len(calls), 1)
        args, kwargs = calls[0]
        self.assertEqual(args[1], "--delete A0000008040001 -force")
        self.assertIs(kwargs.get("suppress_failure_dialog"), False)
        self.assertEqual(result, ["Deleted: Keycard."])

    def test_all_present_deletes_in_order(self):
        state = _present_state(keycard=True, satochip=True, seedkeeper=True)
        result, calls = self._capture_calls(state, lambda _: True)
        names_in_call_order = [args[2] for (args, _) in calls]
        self.assertEqual(
            names_in_call_order,
            ["Deleting SeedKeeper", "Deleting Satochip", "Deleting Keycard"],
        )
        self.assertEqual(result, ["Deleted: SeedKeeper, Satochip, Keycard."])

    def test_isd_keys_rotated_falls_back(self):
        # Probe sees Keycard installed but every delete fails →
        # caller should fall back to soft-reset (return None).
        state = _present_state(keycard=True, satochip=True)

        result, _ = self._capture_calls(state, lambda _: None)
        self.assertIsNone(result)

    def test_clean_card_does_not_pollute_skipped(self):
        # Silenced failure must not show up as "Skipped: Keycard." —
        # already covered above, but pin it explicitly.
        result, _ = self._capture_calls(
            _present_but_empty_state(), lambda _: None,
        )
        self.assertNotIn("Skipped", " ".join(result))


class TestRunGlobalplatformSignature(unittest.TestCase):
    """Sanity check: the new kwarg has a safe default."""

    def test_suppress_failure_dialog_defaults_false(self):
        import inspect
        from seedsigner.helpers import seedkeeper_utils
        sig = inspect.signature(seedkeeper_utils.run_globalplatform)
        param = sig.parameters.get("suppress_failure_dialog")
        self.assertIsNotNone(param)
        self.assertEqual(param.default, False)


if __name__ == "__main__":
    unittest.main()
