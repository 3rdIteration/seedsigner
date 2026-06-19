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
        flags.get("seedkeeper", False),
    )


def _absent_state():
    """Reader has no card at all (probe returns ``present=False``)."""
    from seedsigner.helpers.card_probe import CardInstalledState
    return CardInstalledState(False, False, False)


def _present_but_empty_state():
    """Card in reader, but no Keycard / SeedKeeper applets detected. This
    is the "clean card, default ISD keys" scenario the factory-reset path
    must still target Keycard against (orphan-load-file recovery)."""
    from seedsigner.helpers.card_probe import CardInstalledState
    return CardInstalledState(True, False, False)


class TestKeycardInstallPreDelete(unittest.TestCase):
    """``CardsInstallAppletView`` must run ``--delete A0000008040001
    -force`` with the failure dialog suppressed *before* anything else
    when installing the Keycard applet."""

    def _stub_microsd_and_runner(self, run_results, probe_state=None):
        """Patch ``MicroSD.get_microsd_dir`` so the CAP path "exists" and
        ``run_globalplatform`` so we capture every invocation. ``run_results``
        is a list of return values applied positionally — pre-delete is
        index 0, then --load, then 3 × --create. ``probe_state`` overrides
        the ``probe_installed_applets`` return value; defaults to a blank
        absent state so the cross-applet compatibility warning is skipped."""
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

        if probe_state is None:
            probe_state = _absent_state()
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
        probe_patch = patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            return_value=probe_state,
        )
        return microsd_patch, runner_patch, disconnect_patch, probe_patch, calls

    def test_pre_delete_is_first_and_suppressed(self):
        v = _make_install_view("keycard")
        # All steps succeed (truthy).
        m, r, d, p, calls = self._stub_microsd_and_runner([True, True, True])
        with m, r, d, p:
            v.run()

        # 1 pre-delete + 1 --load + 1 --create (signing only) = 3.
        # NDEF and Cash are skipped to avoid breaking SeedKeeper iOS
        # interop (NDEF AID is the ISO/IEC 14443 Type-4 standard).
        self.assertEqual(len(calls), 3)
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

        # The single create step is the signing instance.
        create_cmd = calls[2][0][1]
        self.assertIn("--create A00000080400010101", create_cmd)
        self.assertIn("--applet A000000804000101", create_cmd)

    def test_step_failure_reports_which_step(self):
        v = _make_install_view("keycard")
        captured_text = {}

        def fake_run_screen(_screen, **kwargs):
            captured_text["text"] = kwargs.get("text", "")
            return 0

        v.run_screen = fake_run_screen
        # Pre-delete succeeds (True), --load succeeds (True),
        # --create FAILS (None) — should bail at the second step of the
        # audible recipe ("steps" = --load + 1 × --create = 2). The
        # pre-delete is intentionally NOT counted in the step numbering
        # shown to the user.
        m, r, d, p, _ = self._stub_microsd_and_runner([True, True, None])
        with m, r, d, p:
            v.run()

        self.assertIn("2/2", captured_text["text"])
        self.assertIn("Creating Keycard signing instance", captured_text["text"])

    def test_clean_card_install_still_succeeds(self):
        """Pre-delete returning None on a clean card (gp.jar's "not
        present on card" → suppressed) must not abort the install."""
        v = _make_install_view("keycard")
        # Pre-delete fails (None, but suppressed); load + create succeed.
        m, r, d, p, _ = self._stub_microsd_and_runner([None, True, True])
        with m, r, d, p:
            dest = v.run()

        # Reached the post-install routing.
        self.assertIsNotNone(dest)


class TestCrossAppletCompatibilityWarning(unittest.TestCase):
    """``CardsInstallAppletView`` must warn before installing one applet
    on a card that already has the other. Mere coexistence of SeedKeeper
    and the Keycard package crashes the Seedkeeper iOS app's reveal flow
    (verified hands-on by deleting only the Keycard package and seeing
    iOS reveal recover). The warning is a DireWarningScreen with a single
    ``Install anyway`` button + back-to-cancel."""

    def _stub(self, run_results, probe_state):
        from pathlib import Path
        cap_path = Path("/tmp/seedsigner-test-microsd")
        cap_dir = cap_path / "javacard-cap"
        cap_dir.mkdir(parents=True, exist_ok=True)
        (cap_dir / "Keycard-3.2.cap").touch()
        (cap_dir / "SeedKeeper-0.2-official.cap").touch()
        calls = []

        def fake_run(*args, **kwargs):
            calls.append((args, kwargs))
            idx = len(calls) - 1
            return run_results[idx] if idx < len(run_results) else run_results[-1]

        return (
            patch("seedsigner.hardware.microsd.MicroSD.get_microsd_dir", return_value=cap_path),
            patch("seedsigner.helpers.seedkeeper_utils.run_globalplatform", side_effect=fake_run),
            patch("seedsigner.helpers.seedkeeper_utils.disconnect_smartcard_connections", MagicMock()),
            patch("seedsigner.helpers.card_probe.probe_installed_applets", return_value=probe_state),
            calls,
        )

    def test_keycard_install_warns_when_seedkeeper_present(self):
        from seedsigner.gui.screens.screen import DireWarningScreen
        v = _make_install_view("keycard")
        # First run_screen call → DireWarning, accept ("Install anyway" = index 0).
        screen_calls = []

        def fake_run_screen(screen_cls, **kwargs):
            screen_calls.append((screen_cls, kwargs))
            return 0
        v.run_screen = fake_run_screen
        m, r, d, p, calls = self._stub([True, True, True], _present_state(seedkeeper=True))
        with m, r, d, p:
            v.run()
        # First screen MUST be the DireWarning.
        self.assertEqual(screen_calls[0][0], DireWarningScreen)
        self.assertEqual(screen_calls[0][1].get("title"), "Compatibility")
        self.assertIn("iOS", screen_calls[0][1].get("text", ""))
        # Install still proceeds: 1 pre-delete + 1 --load + 1 --create = 3.
        self.assertEqual(len(calls), 3)

    def test_keycard_install_aborts_when_back_pressed_on_warning(self):
        from seedsigner.gui.screens.screen import (
            DireWarningScreen, RET_CODE__BACK_BUTTON,
        )
        v = _make_install_view("keycard")
        screen_calls = []

        def fake_run_screen(screen_cls, **kwargs):
            screen_calls.append((screen_cls, kwargs))
            return RET_CODE__BACK_BUTTON
        v.run_screen = fake_run_screen
        m, r, d, p, calls = self._stub([True, True, True], _present_state(seedkeeper=True))
        with m, r, d, p:
            v.run()
        # DireWarning shown once and then the back button aborted everything.
        self.assertEqual(len(screen_calls), 1)
        self.assertEqual(screen_calls[0][0], DireWarningScreen)
        # No gp.jar calls — install never started.
        self.assertEqual(calls, [])

    def test_seedkeeper_install_warns_when_keycard_present(self):
        from seedsigner.gui.screens.screen import DireWarningScreen
        v = _make_install_view("seedkeeper")
        # SeedKeeper install also runs a storage chooser screen. First run_screen
        # is the DireWarning (accept), second is the storage chooser (pick 0).
        screen_calls = []

        def fake_run_screen(screen_cls, **kwargs):
            screen_calls.append((screen_cls, kwargs))
            return 0
        v.run_screen = fake_run_screen
        m, r, d, p, calls = self._stub([True], _present_state(keycard=True))
        with m, r, d, p:
            v.run()
        self.assertEqual(screen_calls[0][0], DireWarningScreen)
        self.assertEqual(screen_calls[0][1].get("title"), "Compatibility")
        # SeedKeeper install = single gp.jar call.
        self.assertEqual(len(calls), 1)
        self.assertIn("--install", calls[0][0][1])

    def test_no_warning_when_only_target_kind_present(self):
        # Installing Keycard on a card that already has Keycard (reinstall):
        # no SeedKeeper present → no warning, jump straight into the recipe.
        from seedsigner.gui.screens.screen import DireWarningScreen
        v = _make_install_view("keycard")
        screen_calls = []

        def fake_run_screen(screen_cls, **kwargs):
            screen_calls.append((screen_cls, kwargs))
            return 0
        v.run_screen = fake_run_screen
        m, r, d, p, calls = self._stub([True, True, True], _present_state(keycard=True))
        with m, r, d, p:
            v.run()
        for s, _ in screen_calls:
            self.assertNotEqual(s, DireWarningScreen)

    def test_no_warning_when_probe_fails(self):
        # If probe raises (no reader / driver issue) we skip the warning
        # rather than blocking the install path.
        from seedsigner.gui.screens.screen import DireWarningScreen
        v = _make_install_view("keycard")
        screen_calls = []

        def fake_run_screen(screen_cls, **kwargs):
            screen_calls.append((screen_cls, kwargs))
            return 0
        v.run_screen = fake_run_screen
        from pathlib import Path
        cap_path = Path("/tmp/seedsigner-test-microsd")
        (cap_path / "javacard-cap").mkdir(parents=True, exist_ok=True)
        (cap_path / "javacard-cap" / "Keycard-3.2.cap").touch()
        with patch(
            "seedsigner.hardware.microsd.MicroSD.get_microsd_dir", return_value=cap_path,
        ), patch(
            "seedsigner.helpers.seedkeeper_utils.run_globalplatform", return_value=True,
        ), patch(
            "seedsigner.helpers.seedkeeper_utils.disconnect_smartcard_connections", MagicMock(),
        ), patch(
            "seedsigner.helpers.card_probe.probe_installed_applets",
            side_effect=RuntimeError("no reader"),
        ):
            v.run()
        for s, _ in screen_calls:
            self.assertNotEqual(s, DireWarningScreen)


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
        state = _present_state(keycard=True, seedkeeper=True)
        result, calls = self._capture_calls(state, lambda _: True)
        names_in_call_order = [args[2] for (args, _) in calls]
        self.assertEqual(
            names_in_call_order,
            ["Deleting SeedKeeper", "Deleting Keycard"],
        )
        self.assertEqual(result, ["Deleted: SeedKeeper, Keycard."])

    def test_isd_keys_rotated_falls_back(self):
        # Probe sees Keycard installed but every delete fails →
        # caller should fall back to soft-reset (return None).
        state = _present_state(keycard=True, seedkeeper=True)

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
