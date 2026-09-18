"""
    Real-screen flow tests for Tools > Luckfox Build Tools.

    Why real screens: the ordinary FlowTest harness patches `View.run_screen`, so a
    mocked flow never constructs the Screen at all. That is exactly how a
    `ButtonListScreen(text=...)` call - a kwarg that screen does not accept - reached
    a device: every mocked flow passed, and the view crashed the first time it ran.
    Running the real Screens here builds each one with the arguments the View
    actually passes.

    The tools themselves are provided by SeedSigner OS rather than this app, so the
    app's CI may not have them. The navigation tests therefore mock
    `secure_boot_tools.is_available()` - they exercise every Screen up to the step
    that needs the tools - and the end-to-end tests skip when the tools cannot be
    resolved.
"""

import os

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import FlowStep, FlowTest
from real_screen_fixtures import use_microsd
from ui_driver import Back, TypeKeys, UISession, select

from seedsigner.helpers import secure_boot_tools
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
# tools_views first: it is a facade that star-imports the others, and reaching
# some of them directly first hits a circular import.
from seedsigner.views import tools_views
from seedsigner.views import resign_views as rv
from seedsigner.views.view import MainMenuView


MNEMONIC_12 = "blush twice taste dawn feed second opinion lazy thumb play neglect impact".split()

# What find_release_dirs() recognises a release folder by.
RELEASE_FILES = ("idblock.img", "download.bin", "uboot.img", "boot.img")

needs_tools = pytest.mark.skipif(
    not secure_boot_tools.is_available(),
    reason="SeedSigner OS tools not resolvable (set %s)" % secure_boot_tools.ENV_VAR)


class LuckfoxFlowTest(FlowTest):

    def setup_method(self):
        super().setup_method()
        self.enable_setting(True)

    def enable_setting(self, on: bool):
        self.settings.set_value(
            SettingsConstants.SETTING__LUCKFOX_BUILD_TOOLS,
            SettingsConstants.OPTION__ENABLED if on else SettingsConstants.OPTION__DISABLED,
        )

    def store_seed(self) -> Seed:
        seed = Seed(mnemonic=MNEMONIC_12)
        self.controller.storage.set_pending_seed(seed)
        return self.controller.storage.finalize_pending_seed()

    @staticmethod
    def placeholder_release(card, name="release"):
        """A folder the picker accepts. Navigation needs no real images."""
        folder = card / name
        folder.mkdir()
        for f in RELEASE_FILES:
            (folder / f).write_bytes(b"")
        return folder

    @staticmethod
    def tools_available(monkeypatch, available=True):
        monkeypatch.setattr(secure_boot_tools, "is_available", lambda: available)

    def to_submenu(self) -> list:
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxBuildToolsMenuView, real_screens=True),
        ]

    def bip85_keys(self, seed, rsa_index, ed_index=None):
        from seedsigner.views.tools_views import (bip85_ed25519_seed_from_root,
                                                  bip85_rsa_from_root)
        root = seed.get_root(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
        return (bip85_rsa_from_root(root, 2048, rsa_index),
                None if ed_index is None else bip85_ed25519_seed_from_root(root, ed_index))


def captured_flow(store):
    def capture(view):
        store.update(view.flow)
    return capture


class TestMenuEntry(LuckfoxFlowTest):
    """The entry is behind a setting (default off) AND the OS-provided tools."""

    def test_setting_defaults_off(self):
        from seedsigner.models.settings_definition import SettingsDefinition
        entry = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__LUCKFOX_BUILD_TOOLS)
        assert entry.default_value == SettingsConstants.OPTION__DISABLED

    @staticmethod
    def tools_menu_labels() -> list:
        """The labels ToolsMenuView offers, read straight from the list it builds.

        Asserting on the list is more direct than driving the UI into a selection
        error: the harness routes view exceptions to UnhandledExceptionView rather
        than raising them, so "could not select it" is not a clean signal.
        """
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        captured = {}
        view = tools_views.ToolsMenuView()

        def run_screen(Screen_cls, **kwargs):
            captured.update(kwargs)
            return RET_CODE__BACK_BUTTON

        view.run_screen = run_screen
        view.run()
        return [getattr(b, "button_label", b) for b in captured["button_data"]]

    @pytest.mark.parametrize("setting_on, tools_present, shown", [
        (False, True,  False),   # default: hidden even with the tools installed
        (True,  False, False),   # defconfig opted out: hidden even when enabled
        (False, False, False),
        (True,  True,  True),    # both gates open
    ])
    def test_gated_on_setting_and_tools(self, monkeypatch, setting_on, tools_present, shown):
        self.enable_setting(setting_on)
        self.tools_available(monkeypatch, tools_present)
        assert ("Luckfox Build Tools" in self.tools_menu_labels()) is shown

    def test_submenu_lists_every_tool(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        use_microsd(monkeypatch, tmp_path)
        session = UISession(script=select("Luckfox Build Tools") + select("Danger Zone"))
        self.run_sequence(self.to_submenu() + [FlowStep(rv.ToolsLuckfoxDangerZoneView)],
                          ui_session=session)
        labels = [b.button_label for b in (
            rv.ToolsLuckfoxBuildToolsMenuView.CHECK, rv.ToolsLuckfoxBuildToolsMenuView.EXPORT,
            rv.ToolsLuckfoxBuildToolsMenuView.RESIGN, rv.ToolsLuckfoxBuildToolsMenuView.PROVISION,
            rv.ToolsLuckfoxBuildToolsMenuView.FORCE, rv.ToolsLuckfoxBuildToolsMenuView.DANGER)]
        assert labels == ["Check Release", "Export Pubkeys", "Resign All",
                          "Provision MicroSD", "Force Rootfs Check", "Danger Zone"]

    def test_no_microsd_warns_and_backs_out(self, monkeypatch):
        self.tools_available(monkeypatch)
        self.mock_microsd.is_inserted = False
        session = UISession(script=select("OK"))
        self.run_sequence([FlowStep(rv.ToolsLuckfoxBuildToolsMenuView, real_screens=True)],
                          ui_session=session)
        assert session.renderer.frames


class TestNavigation(LuckfoxFlowTest):
    """Every Screen in each flow, built with the arguments the Views really pass,
    up to the step that needs the OS tools."""

    def test_resign_all(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        release = self.placeholder_release(use_microsd(monkeypatch, tmp_path))
        self.store_seed()
        flow = {}
        session = UISession(script=(
            select("Luckfox Build Tools", "Resign All", "Continue")
            + select(0)                  # seed picker - the screen that used to crash
            + [TypeKeys("3"), TypeKeys("5")]
            + select("release")
        ))
        self.run_sequence(self.to_submenu() + [
            FlowStep(rv.ToolsResignReleaseStartView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectSeedView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxRsaIndexView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxEd25519IndexView, real_screens=True),
            # The harness does not run the final step's View, so the flow is
            # captured from the step before it.
            FlowStep(rv.ToolsLuckfoxSelectFolderView, real_screens=True,
                     before_run=captured_flow(flow)),
            FlowStep(rv.ToolsResignConfirmView),
        ], ui_session=session)
        assert flow == dict(action="resign", seed_num=0, rsa_index=3, ed_index=5)
        assert session.renderer.frames

    def test_resign_confirm_screen(self, monkeypatch, tmp_path):
        """The confirmation lists what will be rewritten; needs inspect_release."""
        self.tools_available(monkeypatch)
        release = self.placeholder_release(use_microsd(monkeypatch, tmp_path))
        from seedsigner.helpers import resign_release
        monkeypatch.setattr(resign_release, "inspect_release", lambda folder: dict(
            files=list(RELEASE_FILES), rootfs=str(release / "rootfs.img"), update_img=True))
        session = UISession(script=select("Sign"))
        flow = dict(action="resign", seed_num=0, rsa_index=3, ed_index=5, folder=str(release))
        self.run_sequence([
            FlowStep(rv.ToolsResignConfirmView, real_screens=True),
            FlowStep(rv.ToolsResignRunView),
        ], initial_destination_view_args=dict(flow=flow), ui_session=session)

    def test_check_release(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        release = self.placeholder_release(use_microsd(monkeypatch, tmp_path))
        flow = {}
        session = UISession(script=select("Luckfox Build Tools", "Check Release", "release"))
        self.run_sequence(self.to_submenu() + [
            FlowStep(rv.ToolsLuckfoxSelectFolderView, real_screens=True,
                     before_run=captured_flow(flow)),
            FlowStep(rv.ToolsLuckfoxCheckReleaseView),
        ], ui_session=session)
        assert flow == dict(action="check")

    def test_export_pubkeys(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        use_microsd(monkeypatch, tmp_path)
        self.store_seed()
        session = UISession(script=(select("Luckfox Build Tools", "Export Pubkeys") + select(0)
                                    + [TypeKeys("3"), TypeKeys("5")]))
        self.run_sequence(self.to_submenu() + [
            FlowStep(rv.ToolsLuckfoxSelectSeedView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxRsaIndexView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxEd25519IndexView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxExportRunView),
        ], ui_session=session)

    def test_provision(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        self.placeholder_release(use_microsd(monkeypatch, tmp_path))
        session = UISession(script=select("Luckfox Build Tools", "Provision MicroSD", "release"))
        self.run_sequence(self.to_submenu() + [
            FlowStep(rv.ToolsLuckfoxSelectFolderView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxProvisionView),
        ], ui_session=session)

    def test_force_rootfs_check_shows_both_info_screens_first(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        self.placeholder_release(use_microsd(monkeypatch, tmp_path))
        session = UISession(script=select("Luckfox Build Tools", "Force Rootfs Check",
                                          "Next", "Continue", "release"))
        self.run_sequence(self.to_submenu() + [
            FlowStep(rv.ToolsLuckfoxForceInfoView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxForceInfoView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectFolderView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxForceStateView),
        ], ui_session=session)

    def test_force_state_refuses_an_unreadable_release(self, monkeypatch, tmp_path):
        """Placeholder images cannot be read: refused, and Back returns to the picker."""
        self.tools_available(monkeypatch)
        release = self.placeholder_release(use_microsd(monkeypatch, tmp_path))
        from seedsigner.helpers import resign_release
        monkeypatch.setattr(resign_release, "force_rootfs_state", lambda folder: None)
        # From the main menu, so the folder picker really is in history (the
        # harness does not push its starting view). The refusal may run to two
        # pages, so leave it by the back arrow.
        session = UISession(script=select("Luckfox Build Tools", "Force Rootfs Check",
                                          "Next", "Continue", "release") + [Back()])
        self.run_sequence(self.to_submenu() + [
            FlowStep(rv.ToolsLuckfoxForceInfoView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxForceInfoView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectFolderView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxForceStateView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxResultView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectFolderView),
        ], ui_session=session)

    def test_force_state_offers_the_opposite(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        release = self.placeholder_release(use_microsd(monkeypatch, tmp_path))
        from seedsigner.helpers import resign_release
        monkeypatch.setattr(resign_release, "force_rootfs_state", lambda folder: False)
        flow = {}
        session = UISession(script=select("Turn on"))
        start = dict(action="force", folder=str(release))
        self.run_sequence([
            FlowStep(rv.ToolsLuckfoxForceStateView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectSeedView, before_run=captured_flow(flow)),
        ], initial_destination_view_args=dict(flow=start), ui_session=session)

    def test_danger_zone_warns_before_the_folder(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        self.placeholder_release(use_microsd(monkeypatch, tmp_path))
        session = UISession(script=select("Luckfox Build Tools", "Danger Zone",
                                          "Arm eFuse Burn", "I understand", "release"))
        self.run_sequence(self.to_submenu() + [
            FlowStep(rv.ToolsLuckfoxDangerZoneView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxArmWarningView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectFolderView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxArmCheckView),
        ], ui_session=session)

    def test_no_seed_loaded_offers_to_load_one(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        use_microsd(monkeypatch, tmp_path)
        from seedsigner.views.seed_views import LoadSeedView
        session = UISession(script=select("Load a seed"))
        self.run_sequence([
            FlowStep(rv.ToolsLuckfoxSelectSeedView, real_screens=True),
            FlowStep(LoadSeedView),
        ], initial_destination_view_args=dict(flow=dict(action="export")), ui_session=session)

    def test_card_without_a_release_folder_warns(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        card = use_microsd(monkeypatch, tmp_path)
        (card / "photos").mkdir()
        session = UISession(script=select("OK"))
        self.run_sequence([
            FlowStep(rv.ToolsLuckfoxSelectFolderView, real_screens=True),
        ], initial_destination_view_args=dict(flow=dict(action="check")), ui_session=session)
        assert session.renderer.frames

    def test_result_view_finishes_at_the_main_menu(self):
        session = UISession(script=select("Done"))
        self.run_sequence([
            FlowStep(rv.ToolsLuckfoxResultView, real_screens=True),
            FlowStep(MainMenuView),
        ], initial_destination_view_args=dict(title="Resign All", text="Done:\n- boot.img"),
            ui_session=session)

    def test_update_img_deleted_screen(self):
        session = UISession(script=select("OK"))
        self.run_sequence([
            FlowStep(rv.ToolsLuckfoxUpdateImgDeletedView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxResultView),
        ], initial_destination_view_args=dict(title="Resign All", text="x"),
            ui_session=session)


@needs_tools
class TestEndToEnd(LuckfoxFlowTest):
    """Whole flows on a synthetic release, including the signing, checked after."""

    def release(self, card, **kw):
        from test_resign_release import _full_release
        return _full_release(card, **kw)

    def test_resign_all(self, monkeypatch, tmp_path):
        from seedsigner.helpers import resign_release as rr
        card = use_microsd(monkeypatch, tmp_path)
        folder = self.release(card)
        seed = self.store_seed()
        session = UISession(script=(
            select("Continue", 0) + [TypeKeys("3"), TypeKeys("5")]
            + select("release", "Sign", "OK")))
        self.run_sequence([
            FlowStep(rv.ToolsResignReleaseStartView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectSeedView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxRsaIndexView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxEd25519IndexView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectFolderView, real_screens=True),
            FlowStep(rv.ToolsResignConfirmView, real_screens=True),
            FlowStep(rv.ToolsResignRunView, real_screens=True),
            # the dedicated "stale update.img deleted" screen, then the report
            FlowStep(rv.ToolsLuckfoxUpdateImgDeletedView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxResultView),
        ], ui_session=session)

        rsa_key, ed_seed = self.bip85_keys(seed, 3, 5)
        results = rr.verify_release(folder, int(rsa_key.n), ed_seed)
        assert {n for n, _ok, _d in results} == {
            "idblock.img", "download.bin", "uboot.img", "boot.img", "rootfs.img"}
        for name, ok, detail in results:
            assert ok, "%s (%s) did not verify under the BIP85 keys" % (name, detail)
        assert not os.path.exists(os.path.join(folder, "update.img"))

    def test_check_release_reports_the_dev_keys(self, monkeypatch, tmp_path):
        card = use_microsd(monkeypatch, tmp_path)
        folder = self.release(card)
        seen = {}
        original_init = rv.ToolsLuckfoxResultView.__init__

        def capture(view, *args, **kwargs):
            seen.update(kwargs)
            original_init(view, *args, **kwargs)

        monkeypatch.setattr(rv.ToolsLuckfoxResultView, "__init__", capture)

        session = UISession(script=select("release"))
        self.run_sequence([
            FlowStep(rv.ToolsLuckfoxSelectFolderView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxCheckReleaseView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxResultView),
        ], initial_destination_view_args=dict(flow=dict(action="check")), ui_session=session)
        # what the result screen was given to show
        assert seen["text"].startswith("VALID")
        assert "PUBLISHED DEV KEY" in seen["text"]
        assert "Luckfox Pico Pro Max" in seen["text"]

    def test_force_rootfs_check_needs_the_release_key(self, monkeypatch, tmp_path):
        """A release signed with the dev key cannot be changed with a seed's key."""
        from seedsigner.helpers import resign_release as rr
        card = use_microsd(monkeypatch, tmp_path)
        folder = self.release(card)
        self.store_seed()
        session = UISession(script=select("Turn on", 0) + [TypeKeys("3")])
        self.run_sequence([
            FlowStep(rv.ToolsLuckfoxForceStateView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectSeedView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxRsaIndexView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxForceRunView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxResultView),
        ], initial_destination_view_args=dict(flow=dict(action="force", folder=folder)),
            ui_session=session)
        assert rr.force_rootfs_state(folder) is False

    def test_force_rootfs_check_with_the_release_key(self, monkeypatch, tmp_path):
        from seedsigner.helpers import resign_release as rr
        card = use_microsd(monkeypatch, tmp_path)
        folder = self.release(card)
        seed = self.store_seed()
        rsa_key, ed_seed = self.bip85_keys(seed, 3, 5)
        rr.resign_release(folder, rsa_key, ed_seed)       # now signed with the seed's key
        session = UISession(script=select("Turn on", 0) + [TypeKeys("3")])
        self.run_sequence([
            FlowStep(rv.ToolsLuckfoxForceStateView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectSeedView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxRsaIndexView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxForceRunView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxResultView),
        ], initial_destination_view_args=dict(flow=dict(action="force", folder=folder)),
            ui_session=session)
        assert rr.force_rootfs_state(folder) is True

    def test_arm_refuses_a_dev_key_release_before_the_seed(self, monkeypatch, tmp_path):
        card = use_microsd(monkeypatch, tmp_path)
        folder = self.release(card)
        self.enable_setting(True)
        monkeypatch.setattr(secure_boot_tools, "is_available", lambda: True)
        session = UISession(script=select("Luckfox Build Tools", "Danger Zone", "Arm eFuse Burn",
                                          "I understand", "release") + [Back()])
        self.run_sequence(self.to_submenu() + [
            FlowStep(rv.ToolsLuckfoxDangerZoneView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxArmWarningView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectFolderView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxArmCheckView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxResultView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectFolderView),
        ], ui_session=session)

    def test_provision_copies_to_the_card_root(self, monkeypatch, tmp_path):
        card = use_microsd(monkeypatch, tmp_path)
        folder = self.release(card)
        # one screen per warning: dev keys, the Max staging estimate, the short
        # boot.img write length
        session = UISession(script=select("Continue", "Continue", "Continue",
                                          "Copy to card", "OK"))
        self.run_sequence([
            FlowStep(rv.ToolsLuckfoxProvisionView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxProvisionDoneView, real_screens=True),
            FlowStep(MainMenuView),
        ], initial_destination_view_args=dict(flow=dict(action="provision", folder=folder)),
            ui_session=session)
        for name in ("sd_update.txt", "boot.img", "rootfs.img"):
            assert (card / name).is_file()
