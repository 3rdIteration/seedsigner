"""****************************************************************************
    Re-sign Release Views

    The device-side half of the Luckfox air-gapped signing ceremony. A release
    built by CI is signed with a *published* dev key, so it verifies but gives no
    protection. This flow re-signs a release folder on the MicroSD with keys
    derived from the user's own seed via BIP85, so only that seed can produce an
    image the device will accept.

    Flow: seed -> RSA index -> Ed25519 index -> folder -> confirm -> run.

    Neither private key is written to storage at any point.
****************************************************************************"""
import logging
import os
from gettext import gettext as _

from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    DireWarningScreen,
    LargeIconStatusScreen,
    WarningScreen,
)
from seedsigner.gui.screens import seed_screens
from seedsigner.gui.screens.screen import ButtonOption, LoadingScreenThread
from seedsigner.gui.components import FontAwesomeIconConstants, SeedSignerIconConstants
from seedsigner.hardware.microsd import MicroSD
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views.view import View, Destination, BackStackView, MainMenuView

logger = logging.getLogger(__name__)

# RSA-2048 is not a preference: the Rockchip SPL verifier rejects any other key
# length with -EINVAL before the BootROM is reached.
RSA_KEY_BITS = 2048


class ToolsResignReleaseStartView(View):
    """Explain what this does, and refuse early if there is no card."""

    CONTINUE = ButtonOption("Continue")

    def run(self):
        if not MicroSD.get_instance().is_inserted:
            self.run_screen(
                WarningScreen,
                title=_("No MicroSD"),
                status_headline=None,
                text=_("Insert a MicroSD card holding the release folder to re-sign."),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        selected = self.run_screen(
            WarningScreen,
            title=_("Re-sign Release"),
            status_headline=_("Signing keys from your seed"),
            text=_("Re-signs a SeedSigner OS release on the MicroSD with RSA and "
                   "Ed25519 keys derived from a seed via BIP85. Keep a backup of "
                   "the seed and the indexes: without them you cannot sign updates "
                   "for a fused device."),
            button_data=[self.CONTINUE],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(ToolsResignSelectSeedView)


class ToolsResignSelectSeedView(View):
    """Pick one of the loaded seeds, or send the user off to load one."""

    LOAD_SEED = ButtonOption("Load a seed", SeedSignerIconConstants.QRCODE)

    def run(self):
        seeds = self.controller.storage.seeds
        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)

        button_data = [
            ButtonOption(seed.get_fingerprint(network),
                         SeedSignerIconConstants.FINGERPRINT, icon_color="blue")
            for seed in seeds
        ]
        button_data.append(self.LOAD_SEED)

        selected = self.run_screen(
            ButtonListScreen,
            title=_("Re-sign Release"),
            text=_("Select seed to sign with") if seeds else _("Load the seed to sign with"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected] == self.LOAD_SEED:
            from seedsigner.views.seed_views import LoadSeedView
            return Destination(LoadSeedView)

        return Destination(ToolsResignRsaIndexView, view_args=dict(seed_num=selected))


class ToolsResignRsaIndexView(View):
    """BIP85 child index for the RSA-2048 boot-chain key."""

    def __init__(self, seed_num: int):
        super().__init__()
        self.seed_num = seed_num

    def run(self):
        ret = seed_screens.SeedBIP85SelectChildIndexScreen(
            title=_("RSA Key Index")
        ).display()
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(
            ToolsResignEd25519IndexView,
            view_args=dict(seed_num=self.seed_num, rsa_index=int(ret)),
        )


class ToolsResignEd25519IndexView(View):
    """BIP85 child index for the Ed25519 rootfs key."""

    def __init__(self, seed_num: int, rsa_index: int):
        super().__init__()
        self.seed_num = seed_num
        self.rsa_index = rsa_index

    def run(self):
        ret = seed_screens.SeedBIP85SelectChildIndexScreen(
            title=_("Ed25519 Key Index")
        ).display()
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(
            ToolsResignSelectFolderView,
            view_args=dict(seed_num=self.seed_num, rsa_index=self.rsa_index,
                           ed_index=int(ret)),
        )


class ToolsResignSelectFolderView(View):
    """List the folders on the card that look like a release."""

    def __init__(self, seed_num: int, rsa_index: int, ed_index: int):
        super().__init__()
        self.seed_num = seed_num
        self.rsa_index = rsa_index
        self.ed_index = ed_index

    def run(self):
        from seedsigner.helpers import resign_release

        root = str(MicroSD.get_microsd_dir())
        folders = resign_release.find_release_dirs(root)
        if not folders:
            self.run_screen(
                WarningScreen,
                title=_("Nothing to sign"),
                status_headline=None,
                text=_("No release folder found on the MicroSD. A release folder "
                       "holds idblock.img, download.bin, uboot.img and boot.img."),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        labels = [os.path.basename(f) or "/" for f in folders]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Select Folder"),
            is_button_text_centered=False,
            button_data=[ButtonOption(label) for label in labels],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            ToolsResignConfirmView,
            view_args=dict(seed_num=self.seed_num, rsa_index=self.rsa_index,
                           ed_index=self.ed_index, folder=folders[selected]),
        )


class ToolsResignConfirmView(View):
    """Show exactly what will be rewritten, before touching anything."""

    SIGN = ButtonOption("Sign")

    def __init__(self, seed_num: int, rsa_index: int, ed_index: int, folder: str):
        super().__init__()
        self.seed_num = seed_num
        self.rsa_index = rsa_index
        self.ed_index = ed_index
        self.folder = folder

    def run(self):
        from seedsigner.helpers import resign_release

        info = resign_release.inspect_release(self.folder)
        names = list(info["files"])
        if info["rootfs"]:
            names.append(os.path.basename(info["rootfs"]))

        text = _("Will re-sign in {folder}:\n{files}\n\nRSA index {rsa}, "
                 "Ed25519 index {ed}. The files are overwritten in place.").format(
            folder=os.path.basename(self.folder) or "/",
            files=", ".join(names),
            rsa=self.rsa_index,
            ed=self.ed_index,
        )

        selected = self.run_screen(
            DireWarningScreen,
            title=_("Confirm Re-sign"),
            status_headline=None,
            text=text,
            button_data=[self.SIGN],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            ToolsResignRunView,
            view_args=dict(seed_num=self.seed_num, rsa_index=self.rsa_index,
                           ed_index=self.ed_index, folder=self.folder),
        )


class ToolsResignRunView(View):
    """Derive the keys, re-sign, verify, and report."""

    def __init__(self, seed_num: int, rsa_index: int, ed_index: int, folder: str):
        super().__init__()
        self.seed_num = seed_num
        self.rsa_index = rsa_index
        self.ed_index = ed_index
        self.folder = folder

    def run(self):
        from seedsigner.helpers import resign_release
        from seedsigner.views.gpg_views import bip85_rsa_from_root, bip85_ed25519_seed_from_root

        seed = self.controller.storage.seeds[self.seed_num]
        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        root = seed.get_root(network)

        # RSA-2048 key generation from a DRNG is slow on this hardware (tens of
        # seconds is normal), so the loading screen goes up before it starts.
        loading_screen = LoadingScreenThread(text=_("Deriving keys..."))
        loading_screen.start()
        try:
            rsa_key = bip85_rsa_from_root(root, RSA_KEY_BITS, self.rsa_index)
            ed_seed = bip85_ed25519_seed_from_root(root, self.ed_index)
        except Exception as e:
            loading_screen.stop()
            logger.exception("BIP85 key derivation failed")
            return self._error(_("Key derivation failed: {}").format(e))
        finally:
            loading_screen.stop()

        loading_screen = LoadingScreenThread(text=_("Signing..."))
        loading_screen.start()
        try:
            report = resign_release.resign_release(self.folder, rsa_key, ed_seed)
            checks = resign_release.verify_release(
                self.folder, int(rsa_key.n), ed_seed)
        except Exception as e:
            logger.exception("re-signing failed")
            return self._error(_("Signing failed: {}").format(e))
        finally:
            loading_screen.stop()

        failed = [name for name, ok, _detail in checks if not ok]
        if failed:
            return self._error(
                _("Signed, but these did not verify afterwards: {}").format(
                    ", ".join(failed)))

        lines = [_("Signed and verified: {}").format(
            ", ".join(name for name, _d in report.signed))]
        lines.extend(report.warnings)

        self.run_screen(
            LargeIconStatusScreen,
            title=_("Re-sign Release"),
            status_headline=_("Done") if not report.warnings else _("Done, with warnings"),
            text="\n\n".join(lines),
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(MainMenuView, clear_history=True)

    def _error(self, message):
        self.run_screen(
            WarningScreen,
            title=_("Re-sign Release"),
            status_headline=_("Failed"),
            text=message,
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(MainMenuView, clear_history=True)
