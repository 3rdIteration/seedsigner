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
            rv.ToolsLuckfoxBuildToolsMenuView.RESIGN, rv.ToolsLuckfoxBuildToolsMenuView.REKEY,
            rv.ToolsLuckfoxBuildToolsMenuView.SIGN_DIGEST,
            rv.ToolsLuckfoxBuildToolsMenuView.PROVISION, rv.ToolsLuckfoxBuildToolsMenuView.FORCE,
            rv.ToolsLuckfoxBuildToolsMenuView.DANGER)]
        assert labels == ["Check Release", "Export Pubkeys", "Resign Release", "Air-Gap Re-Key",
                          "Sign Digest", "Provision MicroSD", "Force Rootfs Check", "Danger Zone"]

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
            select("Luckfox Build Tools", "Resign Release", "Continue", "BIP85 Derive")
            + select(0)                  # seed picker - the screen that used to crash
            + [TypeKeys("3"), TypeKeys("5")]
            + select("release")
        ))
        self.run_sequence(self.to_submenu() + [
            FlowStep(rv.ToolsResignReleaseStartView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxKeySourceView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectSeedView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxRsaIndexView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxEd25519IndexView, real_screens=True),
            # The harness does not run the final step's View, so the flow is
            # captured from the step before it.
            FlowStep(rv.ToolsLuckfoxSelectFolderView, real_screens=True,
                     before_run=captured_flow(flow)),
            FlowStep(rv.ToolsResignConfirmView),
        ], ui_session=session)
        assert flow == dict(action="resign", source="bip85", seed_num=0, rsa_index=3,
                            ed_index=5)
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

    def test_rekey_navigation(self, monkeypatch, tmp_path):
        """Start -> key source -> seed/index; export is the first run view."""
        self.tools_available(monkeypatch)
        use_microsd(monkeypatch, tmp_path)
        self.store_seed()
        flow = {}
        session = UISession(script=(select("Luckfox Build Tools", "Air-Gap Re-Key", "Continue",
                                           "BIP85 Derive") + select(0)
                                    + [TypeKeys("3"), TypeKeys("5")]))
        self.run_sequence(self.to_submenu() + [
            FlowStep(rv.ToolsRekeyStartView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxKeySourceView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectSeedView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxRsaIndexView, real_screens=True),
            # ed_index is set by this view's own run(), so capture one step earlier.
            FlowStep(rv.ToolsLuckfoxEd25519IndexView, real_screens=True,
                     before_run=captured_flow(flow)),
            FlowStep(rv.ToolsRekeyExportView),
        ], ui_session=session)
        assert flow == dict(action="rekey", source="bip85", seed_num=0, rsa_index=3)

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
        ], initial_destination_view_args=dict(title="Resign Release", text="Done:\n- boot.img"),
            ui_session=session)

    def test_update_img_deleted_screen(self):
        session = UISession(script=select("OK"))
        self.run_sequence([
            FlowStep(rv.ToolsLuckfoxUpdateImgDeletedView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxResultView),
        ], initial_destination_view_args=dict(title="Resign Release", text="x"),
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
            select("Continue", "BIP85 Derive", 0) + [TypeKeys("3"), TypeKeys("5")]
            + select("release", "Sign", "OK")))
        self.run_sequence([
            FlowStep(rv.ToolsResignReleaseStartView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxKeySourceView, real_screens=True),
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

    def test_rekey_ceremony(self, monkeypatch, tmp_path):
        """Export pubkeys -> sign rootfs -> sign the rest; keys leave RAM at the end."""
        from seedsigner.helpers import resign_release as rr
        rk, fs, ms, lr = secure_boot_tools.load()

        card = use_microsd(monkeypatch, tmp_path)
        folder = self.release(card)
        seed = self.store_seed()

        # One page per paged screen: the ceremony logic is what is under test here.
        monkeypatch.setattr(rv, "reflow_text_into_pages", lambda **kw: [kw["text"]])

        d = card / rr.DIGEST_DIR
        d.mkdir()
        size = lr.signed_size(lr.initramfs_members(rk.read(os.path.join(folder, "boot.img"))))
        (d / "rootfs.digest").write_bytes(lr.rootfs_prehash(folder, size))

        def add_round2_digests(view):      # the PC's work between the round-trips
            for name in ("download", "idblock"):
                path = os.path.join(folder, name + (".bin" if name == "download" else ".img"))
                buf = rk.read(path)
                (d / (name + ".digest")).write_bytes(rk.signing_digest(buf, rk.layout(buf)))
            for name in ("uboot", "boot"):
                path = os.path.join(folder, name + ".img")
                (d / (name + ".digest")).write_bytes(fs.signed_digest(rk.read(path)))

        # One Select per paged screen (instruction x2, final report): a list-mul of
        # one token would share its _clicked state across the three slots.
        session = UISession(script=(select("Luckfox Build Tools", "Air-Gap Re-Key", "Continue",
                                           "BIP85 Derive", 0)
                                    + [TypeKeys("3"), TypeKeys("5")]
                                    + select("Done", "Done", "Done")))
        self.run_sequence(self.to_submenu() + [
            FlowStep(rv.ToolsRekeyStartView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxKeySourceView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectSeedView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxRsaIndexView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxEd25519IndexView, real_screens=True),
            FlowStep(rv.ToolsRekeyExportView, real_screens=True),
            FlowStep(rv.ToolsRekeyInstructionView, real_screens=True),   # after export
            FlowStep(rv.ToolsRekeySignView, real_screens=True),          # round 1: rootfs only
            FlowStep(rv.ToolsRekeyInstructionView, real_screens=True),   # after round 1
            FlowStep(rv.ToolsRekeySignView, real_screens=True,
                     before_run=add_round2_digests),                     # round 2: the rest
            FlowStep(rv.ToolsLuckfoxResultView, real_screens=True),      # final report
        ], ui_session=session)

        rsa_key, ed_seed = self.bip85_keys(seed, 3, 5)
        assert rr.pubkeys_on_card(str(card), rsa_key, ed_seed)

        # every signature on the card verifies against this release's images
        n = int(rsa_key.n)
        for name in ("download", "idblock"):
            path = os.path.join(folder, name + (".bin" if name == "download" else ".img"))
            buf = rk.read(path)
            sig = (d / (name + ".sig")).read_bytes()
            assert rk.rsa_verify_digest(rk.signing_digest(buf, rk.layout(buf)),
                                        int.from_bytes(sig, "little"), n)
        for name in ("uboot", "boot"):
            path = os.path.join(folder, name + ".img")
            buf = bytearray(rk.read(path))
            fs._write_value(buf, fs.signature_node(buf), (d / (name + ".sig")).read_bytes())
            assert fs.verify_buf(buf, n)
        pk = ms.ed25519_public(ed_seed)
        msig = ms.load_sig(str(d / "rootfs.minisig"))
        assert msig["key_id"] == rr.ed25519_key_id(ed_seed)
        assert ms.ed25519_verify(pk, (d / "rootfs.digest").read_bytes(), msig["sig"])

    def test_rekey_sign_refuses_without_a_card(self, monkeypatch):
        """Round 1 with no card inserted is refused; the ceremony's keys stay put."""
        self.mock_microsd.is_inserted = False
        rsa_key, ed_seed = self.bip85_keys(self.store_seed(), 3, 5)
        rv.stash_seedkeeper_keys(self.controller, rsa_key, ed_seed)
        session = UISession(script=select("Done") + [Back()])   # instructions, then leave the refusal
        self.run_sequence([
            FlowStep(rv.ToolsRekeyInstructionView, real_screens=True),  # initial: not pushed to history
            FlowStep(rv.ToolsRekeySignView, real_screens=True),         # refuses: no card
            FlowStep(rv.ToolsLuckfoxResultView, real_screens=True),     # the refusal; Back() leaves it
            FlowStep(MainMenuView),                                     # where Back lands; not run
        ], initial_destination_view_args=dict(
            title="Air-Gap Re-Key", text="x", next_view=rv.ToolsRekeySignView,
            next_args=dict(flow=dict(action="rekey", rekey_round=1))), ui_session=session)
        assert rv.peek_rekey_keys(self.controller) is not None

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


# --- Resign Release with keys brought from MicroSD or a SeedKeeper -----------------

class FakeSeedKeeper:
    """Just the SeedKeeper calls the key picker makes, holding Data secrets."""

    def __init__(self, secrets, protocol_minor_version=2):
        self.secrets = secrets                   # [(label, bytes)]
        self.minor = protocol_minor_version
        self.exported = []

    def seedkeeper_list_secret_headers(self):
        return [dict(id=i + 1, type=0xC0, label=label)
                for i, (label, _data) in enumerate(self.secrets)]

    def card_get_status(self):
        return (b"", 0x90, 0x00, dict(protocol_minor_version=self.minor))

    def seedkeeper_export_secret(self, sid, pubkey_id):
        self.exported.append(sid)
        data = self.secrets[sid - 1][1]
        prefix = bytes([len(data)]) if self.minor == 1 else len(data).to_bytes(2, "big")
        return dict(secret_list=list(prefix + data))


def _own_keys():
    """A fresh RSA-2048 key and Ed25519 seed, as a user would bring them."""
    from Cryptodome.PublicKey import RSA
    return RSA.generate(2048, e=65537), bytes(range(32, 64))


def _minisign_seckey_bytes(seed):
    ms = secure_boot_tools.load()[2]
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        pub, sec = os.path.join(d, "k.pub"), os.path.join(d, "k.key")
        ms.main(["keygen", "--entropy", seed.hex(), "-p", pub, "-s", sec])
        with open(sec, "rb") as f:
            return f.read()


class TestKeySourceNavigation(LuckfoxFlowTest):
    def test_key_source_offers_all_three(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        use_microsd(monkeypatch, tmp_path)
        flow = {}
        session = UISession(script=select("Continue", "Load from MicroSD"))
        self.run_sequence([
            FlowStep(rv.ToolsResignReleaseStartView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxKeySourceView, real_screens=True,
                     before_run=captured_flow(flow)),
            FlowStep(rv.ToolsLuckfoxKeyFileView),
        ], ui_session=session)
        labels = [b.button_label for b in (rv.ToolsLuckfoxKeySourceView.BIP85,
                                           rv.ToolsLuckfoxKeySourceView.MICROSD,
                                           rv.ToolsLuckfoxKeySourceView.SEEDKEEPER)]
        assert labels == ["BIP85 Derive", "Load from MicroSD", "Load from SeedKeeper"]

    def test_seedkeeper_source_goes_to_the_secret_picker(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        use_microsd(monkeypatch, tmp_path)
        session = UISession(script=select("Continue", "Load from SeedKeeper"))
        self.run_sequence([
            FlowStep(rv.ToolsResignReleaseStartView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxKeySourceView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSeedKeeperKeysView),
        ], ui_session=session)

    def test_opening_the_submenu_drops_held_seedkeeper_keys(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        use_microsd(monkeypatch, tmp_path)
        rv.stash_seedkeeper_keys(self.controller, "rsa", b"ed")
        session = UISession(script=select("Check Release"))
        self.run_sequence([
            FlowStep(rv.ToolsLuckfoxBuildToolsMenuView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectFolderView),
        ], ui_session=session)
        assert rv.take_seedkeeper_keys(self.controller) is None


@needs_tools
class TestKeySourceEndToEnd(LuckfoxFlowTest):
    def release(self, card):
        from test_resign_release import _full_release
        return _full_release(card)

    def check_signed_with(self, folder, rsa_key, ed_seed):
        from seedsigner.helpers import resign_release as rr
        results = rr.verify_release(folder, int(rsa_key.n), ed_seed)
        assert {n for n, _ok, _d in results} == {
            "idblock.img", "download.bin", "uboot.img", "boot.img", "rootfs.img"}
        for name, ok, detail in results:
            assert ok, "%s (%s) did not verify under the loaded keys" % (name, detail)

    def test_keys_from_microsd_files(self, monkeypatch, tmp_path):
        card = use_microsd(monkeypatch, tmp_path)
        folder = self.release(card)
        rsa_key, ed_seed = _own_keys()
        keys = card / "keys"
        keys.mkdir()
        (keys / "release-rsa.pem").write_bytes(rsa_key.export_key(format="PEM"))
        (keys / "rootfs.key").write_bytes(_minisign_seckey_bytes(ed_seed))
        rsa_label = os.path.join("keys", "release-rsa.pem")
        ed_label = os.path.join("keys", "rootfs.key")

        session = UISession(script=(
            select("Continue", "Load from MicroSD")
            + select(ed_label, "Pick another")   # the Ed25519 key is refused as RSA
            + select(rsa_label, ed_label, "release", "Sign", "OK")))
        self.run_sequence([
            FlowStep(rv.ToolsResignReleaseStartView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxKeySourceView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxKeyFileView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxKeyFileView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectFolderView, real_screens=True),
            FlowStep(rv.ToolsResignConfirmView, real_screens=True),
            FlowStep(rv.ToolsResignRunView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxUpdateImgDeletedView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxResultView),
        ], ui_session=session)
        self.check_signed_with(folder, rsa_key, ed_seed)

    def test_keys_from_seedkeeper_secrets(self, monkeypatch, tmp_path):
        from seedsigner.helpers import seedkeeper_utils
        card = use_microsd(monkeypatch, tmp_path)
        folder = self.release(card)
        rsa_key, ed_seed = _own_keys()
        card_ = FakeSeedKeeper([
            ("notes", b"not a key"),
            ("release-rsa", rsa_key.export_key(format="DER")),
            ("rootfs-seed", ed_seed.hex().encode()),
        ])
        monkeypatch.setattr(seedkeeper_utils, "init_satochip", lambda *a, **kw: card_)

        session = UISession(script=(
            select("Continue", "Load from SeedKeeper")
            + select(0, "Pick another")          # "notes" is not an RSA key
            + select(1, 2, "release", "Sign", "OK")))
        self.run_sequence([
            FlowStep(rv.ToolsResignReleaseStartView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxKeySourceView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSeedKeeperKeysView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxSelectFolderView, real_screens=True),
            FlowStep(rv.ToolsResignConfirmView, real_screens=True),
            FlowStep(rv.ToolsResignRunView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxUpdateImgDeletedView, real_screens=True),
            FlowStep(rv.ToolsLuckfoxResultView),
        ], ui_session=session)
        self.check_signed_with(folder, rsa_key, ed_seed)
        # the keys were consumed by the signing step, not left in RAM
        assert rv.take_seedkeeper_keys(self.controller) is None


@needs_tools
class TestLowMemoryWarning(LuckfoxFlowTest):
    """The heavy actions warn when free RAM looks tight, and stay quiet otherwise."""

    @staticmethod
    def stats(available_kb, total_kb=64 * 1024):
        from seedsigner.helpers.system_memory import MemoryStats
        return MemoryStats(total_kb=total_kb, available_kb=available_kb)

    def test_line_is_empty_when_memory_is_comfortable(self, monkeypatch):
        from seedsigner.helpers import system_memory
        monkeypatch.setattr(system_memory, "get_memory_stats", lambda: self.stats(48 * 1024))
        assert rv._low_memory_line("hint") == ""

    def test_line_is_empty_without_meminfo(self, monkeypatch):
        """Desktop/CI hosts have no /proc: the check degrades to a skip."""
        from seedsigner.helpers import system_memory
        monkeypatch.setattr(system_memory, "get_memory_stats", lambda: self.stats(None))
        assert rv._low_memory_line("hint") == ""

    def test_line_reports_free_and_total_below_the_threshold(self, monkeypatch):
        from seedsigner.helpers import system_memory
        monkeypatch.setattr(system_memory, "get_memory_stats", lambda: self.stats(20 * 1024))
        line = rv._low_memory_line("The hint.")
        assert line.startswith("Low memory") and "20.0 MB" in line and "64.0 MB" in line
        assert line.endswith("The hint.")

    def test_confirm_screen_carries_the_warning(self, monkeypatch, tmp_path):
        from seedsigner.helpers import system_memory
        from test_resign_release import _full_release
        folder = _full_release(tmp_path)
        monkeypatch.setattr(system_memory, "get_memory_stats", lambda: self.stats(20 * 1024))

        view = rv.ToolsResignConfirmView(flow=dict(action=rv.ACTION__RESIGN,
                                                   rsa_index=3, ed_index=5, folder=str(folder)))
        captured = {}

        def run_screen(Screen_cls, **kwargs):
            captured.update(kwargs)
            return 0
        view.run_screen = run_screen
        view.run()
        assert "Low memory" in captured["text"]


# --- board support ---------------------------------------------------------------

class TestBoardSupport(LuckfoxFlowTest):
    """Every board can run the tools: they are ~55 KB of stdlib and every heavy
    path streams (a full mini-bundle re-sign peaks at ~14 MB measured), so even
    the Pico Mini's 64 MB DRAM fits them. There is no per-board refusal; an image
    whose build opted out simply does not carry the signers, and the menu hides
    itself via is_available() like Network Info does."""

    def setup_method(self):
        super().setup_method()
        self.enable_setting(False)

    @staticmethod
    def on_board(monkeypatch, runtime_profile):
        from seedsigner.models.settings import Settings
        monkeypatch.setattr(Settings, "RUNTIME_PROFILE", runtime_profile)

    def test_enabling_works_on_every_board(self, monkeypatch):
        from seedsigner.views import settings_views as sv
        attr = SettingsConstants.SETTING__LUCKFOX_BUILD_TOOLS
        for profile in ("luckfox_22", "luckfox_40", "luckfox_pi", "lc_lafrite", "desktop"):
            self.on_board(monkeypatch, profile)
            self.enable_setting(False)                        # start from Disabled each time
            # Run the view directly: it redisplays itself with skip_current_view, which
            # the flow harness cannot follow from a first step.
            view = sv.SettingsEntryUpdateSelectionView(attr_name=attr)
            view.run_screen = lambda *a, **kw: 0              # "Enabled"
            destination = view.run()
            assert destination.View_cls is sv.SettingsEntryUpdateSelectionView, profile
            assert self.settings.get_value(attr) == SettingsConstants.OPTION__ENABLED, profile

    def test_menu_shown_on_a_mini_when_the_tools_are_present(self, monkeypatch):
        """The old per-board block is gone: with the signers installed and the
        setting on, a Pico Mini gets the menu like any other board."""
        self.on_board(monkeypatch, "luckfox_22")
        self.enable_setting(True)
        self.tools_available(monkeypatch, True)
        assert "Luckfox Build Tools" in TestMenuEntry.tools_menu_labels()

    def test_menu_still_hidden_when_the_image_lacks_the_tools(self, monkeypatch):
        """An image built with no-secure-boot-tools has nothing to run, on any board."""
        self.on_board(monkeypatch, "luckfox_22")
        self.enable_setting(True)
        self.tools_available(monkeypatch, False)
        assert "Luckfox Build Tools" not in TestMenuEntry.tools_menu_labels()
