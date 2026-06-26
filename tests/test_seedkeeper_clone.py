"""Tests for the Seedkeeper Copy/Clone secrets flow.

Covers the parts that are unit-testable without two physical cards:
  * scope/mode routing in ``ToolsSeedkeeperCloneSecretsView.run()``
    (All vs Single; Add-New vs Replace),
  * the destination write logic in ``_clone_to_destination`` — append
    (skip-by-fingerprint, never delete) vs replace (wipe-then-copy),
  * the v1 guard and the cancel-without-deleting safety property,
  * best-effort scrub of the collected plaintext payloads.

The full two-card swap round trip needs hardware — see CLAUDE.md
"Hardware verification".
"""
import unittest
from unittest.mock import MagicMock, patch

from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.views import tools_views
from seedsigner.views.tools_views import ToolsSeedkeeperCloneSecretsView
from seedsigner.views.view import BackStackView, MainMenuView


# pysatochip.JCconstants is mocked by conftest, so the module-level dicts
# imported into tools_views are MagicMocks. Inject real maps for the tests.
REAL_TYPES = {0x90: "Password"}
REAL_RIGHTS = {0x01: "Plaintext export allowed"}


def _make_view(run_screen_side_effect=None):
    view = ToolsSeedkeeperCloneSecretsView.__new__(ToolsSeedkeeperCloneSecretsView)
    view.controller = MagicMock()
    if run_screen_side_effect is not None:
        view.run_screen = MagicMock(side_effect=run_screen_side_effect)
    else:
        view.run_screen = MagicMock()
    return view


def _src_secret(fingerprint, label="p", stype=0x90, rights=0x01, subtype=0):
    return {
        "header": {
            "type": stype,
            "export_rights": rights,
            "label": label,
            "subtype": subtype,
            "fingerprint": fingerprint,
        },
        "secret": {"secret_list": [1, 2, 3], "secret": "aabb"},
    }


class TestCloneRouting(unittest.TestCase):
    """run() drives the scope chooser (All/Single) and, for All, the mode
    chooser (Add-New/Replace), then hands off to ``_clone_to_destination``."""

    def test_all_append_routes(self):
        src = [_src_secret("f1")]
        view = _make_view(run_screen_side_effect=[0, 0, 1])  # All, Add-New, No
        view._collect_exportable_secrets = MagicMock(return_value=src)
        view._clone_to_destination = MagicMock(return_value=(True, None))

        dest = view.run()

        view._clone_to_destination.assert_called_once_with(src, replace=False)
        self.assertIs(dest.View_cls, BackStackView)

    def test_all_replace_routes(self):
        src = [_src_secret("f1")]
        view = _make_view(run_screen_side_effect=[0, 1, 1])  # All, Replace, No
        view._collect_exportable_secrets = MagicMock(return_value=src)
        view._clone_to_destination = MagicMock(return_value=(True, None))

        view.run()

        view._clone_to_destination.assert_called_once_with(src, replace=True)

    def test_single_routes_one_secret(self):
        src = [_src_secret("f1"), _src_secret("f2")]
        view = _make_view(run_screen_side_effect=[1, 1])  # Single, then No
        view._collect_exportable_secrets = MagicMock(return_value=src)
        view._select_one_secret = MagicMock(return_value=src[1])
        view._clone_to_destination = MagicMock(return_value=(True, None))

        view.run()

        view._clone_to_destination.assert_called_once_with([src[1]], replace=False)

    def test_scope_back_exits(self):
        view = _make_view(run_screen_side_effect=[RET_CODE__BACK_BUTTON])
        view._collect_exportable_secrets = MagicMock()
        dest = view.run()
        self.assertIs(dest.View_cls, BackStackView)
        view._collect_exportable_secrets.assert_not_called()

    def test_mode_back_returns_to_scope(self):
        # All -> mode BACK -> scope BACK (never reads the source)
        view = _make_view(
            run_screen_side_effect=[0, RET_CODE__BACK_BUTTON, RET_CODE__BACK_BUTTON]
        )
        view._collect_exportable_secrets = MagicMock()
        dest = view.run()
        self.assertIs(dest.View_cls, BackStackView)
        view._collect_exportable_secrets.assert_not_called()

    def test_single_selection_back_rereads(self):
        # Single -> selection BACK wipes + returns to scope -> scope BACK exits.
        src = [_src_secret("f1")]
        view = _make_view(run_screen_side_effect=[1, RET_CODE__BACK_BUTTON])
        view._collect_exportable_secrets = MagicMock(return_value=src)
        view._select_one_secret = MagicMock(return_value=None)
        view._wipe_collected_secrets = MagicMock(wraps=view._wipe_collected_secrets)
        view._clone_to_destination = MagicMock()

        dest = view.run()

        view._clone_to_destination.assert_not_called()
        # collected scrubbed after the user backed out of the selection list
        self.assertTrue(view._wipe_collected_secrets.called)
        self.assertIs(dest.View_cls, BackStackView)


class TestCloneToDestination(unittest.TestCase):
    """The destination-write core: append skips by fingerprint and never
    deletes; replace wipes every existing secret first, then copies."""

    def setUp(self):
        self.patchers = [
            patch.object(tools_views, "SEEDKEEPER_DIC_TYPE", REAL_TYPES),
            patch.object(tools_views, "SEEDKEEPER_DIC_EXPORT_RIGHTS", REAL_RIGHTS),
            patch(
                "seedsigner.gui.screens.screen.LoadingScreenThread",
                MagicMock(),
            ),
            patch.object(
                tools_views.seedkeeper_utils,
                "ensure_seedkeeper_capacity",
                MagicMock(return_value=(True, 10, 99999)),
            ),
            patch.object(
                tools_views.seedkeeper_utils,
                "disconnect_smartcard_connections",
                MagicMock(),
            ),
        ]
        for p in self.patchers:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self.patchers])

    def _connector(self, dest_headers, protocol_minor_version=2):
        connector = MagicMock()
        connector.seedkeeper_list_secret_headers.return_value = dest_headers
        connector.card_get_status.return_value = (
            None,
            None,
            None,
            {"protocol_minor_version": protocol_minor_version},
        )
        connector.make_header.return_value = "newheader"
        return connector

    def test_append_skips_existing_fingerprint(self):
        connector = self._connector(dest_headers=[{"id": 1, "fingerprint": "f1"}])
        view = _make_view(run_screen_side_effect=[0, 0])  # insert Continue, completion
        src = [_src_secret("f1"), _src_secret("f2")]  # f1 already on dest

        with patch.object(
            tools_views.seedkeeper_utils, "init_satochip",
            MagicMock(return_value=connector),
        ):
            ok, err = view._clone_to_destination(src, replace=False)

        self.assertTrue(ok)
        self.assertIsNone(err)
        # only the non-duplicate (f2) imported; nothing deleted
        self.assertEqual(connector.seedkeeper_import_secret.call_count, 1)
        connector.seedkeeper_reset_secret.assert_not_called()

    def test_replace_wipes_then_imports_all(self):
        connector = self._connector(
            dest_headers=[
                {"id": 1, "fingerprint": "fa"},
                {"id": 2, "fingerprint": "f1"},  # collides with a source fp
            ]
        )
        # insert Continue, DireWarning proceed (0), completion
        view = _make_view(run_screen_side_effect=[0, 0, 0])
        src = [_src_secret("f1"), _src_secret("f2")]

        with patch.object(
            tools_views.seedkeeper_utils, "init_satochip",
            MagicMock(return_value=connector),
        ):
            ok, err = view._clone_to_destination(src, replace=True)

        self.assertTrue(ok)
        # every existing dest secret deleted...
        self.assertEqual(connector.seedkeeper_reset_secret.call_count, 2)
        # ...and ALL source secrets imported (no skip, fingerprints reset)
        self.assertEqual(connector.seedkeeper_import_secret.call_count, 2)

    def test_replace_v1_aborts_without_deleting(self):
        connector = self._connector(
            dest_headers=[{"id": 1, "fingerprint": "fa"}],
            protocol_minor_version=1,
        )
        view = _make_view(run_screen_side_effect=[0])  # insert Continue only
        src = [_src_secret("f1")]

        with patch.object(
            tools_views.seedkeeper_utils, "init_satochip",
            MagicMock(return_value=connector),
        ):
            ok, err = view._clone_to_destination(src, replace=True)

        self.assertFalse(ok)
        self.assertIn("v2", err)
        connector.seedkeeper_reset_secret.assert_not_called()
        connector.seedkeeper_import_secret.assert_not_called()

    def test_replace_cancel_does_not_delete(self):
        connector = self._connector(dest_headers=[{"id": 1, "fingerprint": "fa"}])
        # insert Continue, then BACK on the DireWarning
        view = _make_view(run_screen_side_effect=[0, RET_CODE__BACK_BUTTON])
        src = [_src_secret("f1")]

        with patch.object(
            tools_views.seedkeeper_utils, "init_satochip",
            MagicMock(return_value=connector),
        ):
            result, err = view._clone_to_destination(src, replace=True)

        # aborted: nothing deleted, nothing imported
        self.assertIsNone(result)
        connector.seedkeeper_reset_secret.assert_not_called()
        connector.seedkeeper_import_secret.assert_not_called()


class TestWipeCollectedSecrets(unittest.TestCase):
    """Best-effort scrub of the in-RAM source payloads on every exit."""

    def test_int_list_cleared(self):
        view = ToolsSeedkeeperCloneSecretsView.__new__(ToolsSeedkeeperCloneSecretsView)
        collected = [{"secret": {"secret_list": [1, 2, 3], "secret": "deadbeef"}}]
        view._wipe_collected_secrets(collected)
        self.assertEqual(collected[0]["secret"]["secret_list"], [])

    def test_none_and_malformed_entries_no_raise(self):
        view = ToolsSeedkeeperCloneSecretsView.__new__(ToolsSeedkeeperCloneSecretsView)
        view._wipe_collected_secrets(None)
        view._wipe_collected_secrets([])
        # entry without a "secret" dict must be skipped silently
        view._wipe_collected_secrets([{"header": {}}, {"secret": None}])


if __name__ == "__main__":
    unittest.main()
