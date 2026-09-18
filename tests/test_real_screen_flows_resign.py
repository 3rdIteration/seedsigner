"""
    Real-screen flow tests for Tools > Luckfox Build Tools (re-sign a release).

    Why real screens: the ordinary FlowTest harness patches `View.run_screen`, so a
    mocked flow never constructs the Screen at all. That is exactly how a
    `ButtonListScreen(text=...)` call - a kwarg that screen does not accept - reached
    a device: every mocked flow passed, and the view crashed the first time it ran.
    Running the real Screens here builds each one with the arguments the View
    actually passes.

    The signing tools themselves are provided by SeedSigner OS rather than this app,
    so the app's CI does not have them. The navigation tests below therefore mock
    `secure_boot_tools.is_available()` - they exercise every Screen in the flow
    without needing the signers - and only the end-to-end signing test needs the
    real tools, skipping when they cannot be resolved.
"""

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import FlowStep, FlowTest
from real_screen_fixtures import use_microsd
from ui_driver import TypeKeys, UISession, select

from seedsigner.helpers import secure_boot_tools
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
# tools_views first: it is a facade that star-imports the others, and reaching
# some of them directly first hits a circular import.
from seedsigner.views import tools_views
from seedsigner.views import resign_views
from seedsigner.views.view import MainMenuView


MNEMONIC_12 = "blush twice taste dawn feed second opinion lazy thumb play neglect impact".split()

# What find_release_dirs() recognises a release folder by.
RELEASE_FILES = ("idblock.img", "download.bin", "uboot.img", "boot.img")


class ResignFlowTest(FlowTest):

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

    def to_luckfox_tools(self) -> list:
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, real_screens=True),
        ]


class TestMenuEntry(ResignFlowTest):
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

    def test_shown_when_enabled_and_available(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        use_microsd(monkeypatch, tmp_path)
        session = UISession(script=select("Luckfox Build Tools") + select("Continue"))
        self.run_sequence(
            self.to_luckfox_tools() + [
                FlowStep(resign_views.ToolsResignReleaseStartView, real_screens=True),
                FlowStep(resign_views.ToolsResignSelectSeedView),
            ],
            ui_session=session,
        )


class TestResignNavigation(ResignFlowTest):
    """Every Screen in the flow, built with the arguments the Views really pass."""

    def test_walks_every_screen_to_the_signing_step(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        card = use_microsd(monkeypatch, tmp_path)
        release = self.placeholder_release(card)
        self.store_seed()

        reached = {}

        def capture(view):
            reached.update(seed_num=view.seed_num, rsa_index=view.rsa_index,
                           ed_index=view.ed_index, folder=view.folder)

        session = UISession(script=(
            select("Luckfox Build Tools")
            + select("Continue")         # start: explanation
            + select(0)                  # seed picker - the screen that used to crash
            + [TypeKeys("3")]            # RSA BIP85 index
            + [TypeKeys("5")]            # Ed25519 BIP85 index
            + select("release")          # folder on the card
            + select("Sign")             # confirmation
        ))

        self.run_sequence(
            self.to_luckfox_tools() + [
                FlowStep(resign_views.ToolsResignReleaseStartView, real_screens=True),
                FlowStep(resign_views.ToolsResignSelectSeedView, real_screens=True),
                FlowStep(resign_views.ToolsResignRsaIndexView, real_screens=True),
                FlowStep(resign_views.ToolsResignEd25519IndexView, real_screens=True),
                FlowStep(resign_views.ToolsResignSelectFolderView, real_screens=True),
                # Captured on the confirmation step: it holds the exact arguments it
                # hands on, and the harness does not run the final step's View (it
                # only checks that the flow reached it).
                FlowStep(resign_views.ToolsResignConfirmView, real_screens=True,
                         before_run=capture),
                FlowStep(resign_views.ToolsResignRunView),
            ],
            ui_session=session,
        )

        assert session.renderer.frames, "the real screens never rendered"
        assert reached == dict(seed_num=0, rsa_index=3, ed_index=5, folder=str(release))

    def test_no_seed_loaded_offers_to_load_one(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        use_microsd(monkeypatch, tmp_path)
        from seedsigner.views.seed_views import LoadSeedView

        session = UISession(script=select("Continue") + select("Load a seed"))
        self.run_sequence([
            FlowStep(resign_views.ToolsResignReleaseStartView, real_screens=True),
            FlowStep(resign_views.ToolsResignSelectSeedView, real_screens=True),
            FlowStep(LoadSeedView),
        ], ui_session=session)

    def test_no_microsd_warns_and_backs_out(self, monkeypatch):
        self.tools_available(monkeypatch)
        self.mock_microsd.is_inserted = False
        session = UISession(script=select("OK"))
        self.run_sequence([
            FlowStep(resign_views.ToolsResignReleaseStartView, real_screens=True),
        ], ui_session=session)
        assert session.renderer.frames

    def test_card_without_a_release_folder_warns(self, monkeypatch, tmp_path):
        self.tools_available(monkeypatch)
        card = use_microsd(monkeypatch, tmp_path)
        (card / "photos").mkdir()
        session = UISession(script=select("OK"))
        self.run_sequence([
            FlowStep(resign_views.ToolsResignSelectFolderView, real_screens=True),
        ], initial_destination_view_args=dict(seed_num=0, rsa_index=0, ed_index=0),
            ui_session=session)
        assert session.renderer.frames


@pytest.mark.skipif(not secure_boot_tools.is_available(),
                    reason="SeedSigner OS signing tools not resolvable (set %s)"
                           % secure_boot_tools.ENV_VAR)
class TestResignEndToEnd(ResignFlowTest):
    """Drive the whole flow, including the signing, and check the result."""

    def test_signs_a_release_with_the_bip85_keys(self, monkeypatch, tmp_path):
        from Cryptodome.PublicKey import RSA
        # the synthetic image builders live with the helper's own tests
        from test_resign_release import _fit, _rk_container
        from seedsigner.helpers import resign_release as rr
        from seedsigner.views.tools_views import (bip85_ed25519_seed_from_root,
                                                  bip85_rsa_from_root)

        card = use_microsd(monkeypatch, tmp_path)
        folder = card / "release"
        folder.mkdir()
        old_n = int(RSA.generate(2048, e=65537).n)   # stands in for the dev key
        (folder / "idblock.img").write_bytes(bytes(_rk_container(old_n, 0x0)))
        (folder / "download.bin").write_bytes(bytes(_rk_container(old_n, 0x1bc)))
        (folder / "uboot.img").write_bytes(bytes(_fit(b"UBOOT" * 64, embed_modulus=old_n)))
        (folder / "boot.img").write_bytes(bytes(_fit(b"KERNEL" * 64)))
        rootfs = b"ROOTFS" * 1000
        (folder / "rootfs.img").write_bytes(rootfs + b"\xff" * 4096)
        (folder / "rootfs.img.size").write_text(str(len(rootfs)))

        seed = self.store_seed()

        session = UISession(script=(
            select("Continue") + select(0)
            + [TypeKeys("3")] + [TypeKeys("5")]
            + select("release") + select("Sign")
            + select("OK")               # result screen
        ))
        self.run_sequence([
            FlowStep(resign_views.ToolsResignReleaseStartView, real_screens=True),
            FlowStep(resign_views.ToolsResignSelectSeedView, real_screens=True),
            FlowStep(resign_views.ToolsResignRsaIndexView, real_screens=True),
            FlowStep(resign_views.ToolsResignEd25519IndexView, real_screens=True),
            FlowStep(resign_views.ToolsResignSelectFolderView, real_screens=True),
            FlowStep(resign_views.ToolsResignConfirmView, real_screens=True),
            FlowStep(resign_views.ToolsResignRunView, real_screens=True),
            FlowStep(MainMenuView),
        ], ui_session=session)

        # Re-derive what the device should have used and check every artifact.
        root = seed.get_root(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
        rsa_n = int(bip85_rsa_from_root(root, 2048, 3).n)
        ed_seed = bip85_ed25519_seed_from_root(root, 5)
        results = rr.verify_release(str(folder), rsa_n, ed_seed)
        assert {name for name, _ok, _d in results} == {
            "idblock.img", "download.bin", "uboot.img", "boot.img", "rootfs.img"}
        for name, ok, detail in results:
            assert ok, "%s (%s) did not verify under the BIP85 keys" % (name, detail)
