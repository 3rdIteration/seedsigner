"""****************************************************************************
    Luckfox Build Tools Views

    The device-side half of the Luckfox air-gapped signing ceremony. A release
    built by CI is signed with *published* dev keys, so it verifies but gives no
    protection. These tools check a release on the MicroSD, re-sign it with keys
    derived from the user's own seed via BIP85, prepare the card for U-Boot's
    MicroSD auto-flash, and (in the Danger Zone) arm the one-time secure-boot fuse.

    Every action is a `flow` dict passed from view to view. `next_step()` asks for
    whatever the action still needs (seed, key indexes, folder, ...) and then
    hands over to the action's final view, so each picker is written once.

    Neither private key is written to storage at any point.
****************************************************************************"""
import logging
import os
from gettext import gettext as _

from seedsigner.gui.components import GUIConstants, reflow_text_into_pages
from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    DireWarningScreen,
    LargeIconStatusScreen,
    WarningScreen,
)
from seedsigner.gui.screens import seed_screens
from seedsigner.gui.screens.screen import ButtonOption, LoadingScreenThread, PagedTextScreen
from seedsigner.gui.components import SeedSignerIconConstants
from seedsigner.hardware.microsd import MicroSD
from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views.view import View, Destination, BackStackView, MainMenuView

logger = logging.getLogger(__name__)

# RSA-2048 is not a preference: the Rockchip SPL verifier rejects any other key
# length with -EINVAL before the BootROM is reached.
RSA_KEY_BITS = 2048

ACTION__CHECK = "check"
ACTION__EXPORT = "export"
ACTION__RESIGN = "resign"
ACTION__PROVISION = "provision"
ACTION__FORCE = "force"
ACTION__ARM = "arm"

# What each action collects, in order. Force and Arm pick the folder first so a
# release they cannot work on is refused before anyone types in a seed.
STEPS = {
    ACTION__CHECK: ("folder",),
    ACTION__EXPORT: ("seed_num", "rsa_index", "ed_index"),
    ACTION__RESIGN: ("seed_num", "rsa_index", "ed_index", "folder"),
    ACTION__PROVISION: ("folder",),
    ACTION__FORCE: ("folder", "force_on", "seed_num", "rsa_index"),
    ACTION__ARM: ("folder", "arm_ok", "seed_num", "rsa_index"),
}

TITLES = {
    ACTION__CHECK: _mft("Check Release"),
    ACTION__EXPORT: _mft("Export Pubkeys"),
    ACTION__RESIGN: _mft("Resign All"),
    ACTION__PROVISION: _mft("Provision MicroSD"),
    ACTION__FORCE: _mft("Force Rootfs Check"),
    ACTION__ARM: _mft("Arm eFuse Burn"),
}


def next_step(flow: dict, skip_current_view: bool = False) -> Destination:
    """Route to the first thing `flow` still lacks, or to the action itself."""
    collectors = {
        "seed_num": ToolsLuckfoxSelectSeedView,
        "rsa_index": ToolsLuckfoxRsaIndexView,
        "ed_index": ToolsLuckfoxEd25519IndexView,
        "folder": ToolsLuckfoxSelectFolderView,
        "force_on": ToolsLuckfoxForceStateView,
        "arm_ok": ToolsLuckfoxArmCheckView,
    }
    finals = {
        ACTION__CHECK: ToolsLuckfoxCheckReleaseView,
        ACTION__EXPORT: ToolsLuckfoxExportRunView,
        ACTION__RESIGN: ToolsResignConfirmView,
        ACTION__PROVISION: ToolsLuckfoxProvisionView,
        ACTION__FORCE: ToolsLuckfoxForceRunView,
        ACTION__ARM: ToolsLuckfoxArmRunView,
    }
    for key in STEPS[flow["action"]]:
        if key not in flow:
            return Destination(collectors[key], view_args=dict(flow=flow),
                               skip_current_view=skip_current_view)
    return Destination(finals[flow["action"]], view_args=dict(flow=flow),
                       skip_current_view=skip_current_view)


def _bullets(items) -> str:
    return "\n".join("- %s" % i for i in items)


def _report_text(report, verified=None) -> str:
    parts = []
    if report.signed:
        parts.append(_("Done:") + "\n" + _bullets("%s: %s" % s for s in report.signed))
    if report.skipped:
        parts.append(_("Skipped:") + "\n" + _bullets("%s: %s" % s for s in report.skipped))
    if report.warnings:
        parts.append(_("Warnings:") + "\n" + _bullets(report.warnings))
    if verified is not None:
        parts.append(_("Verified afterwards: {}").format(", ".join(verified)))
    return "\n\n".join(parts) or _("Nothing needed changing.")


class _FlowView(View):
    """A view carrying a flow dict."""

    def __init__(self, flow: dict):
        super().__init__()
        self.flow = flow

    @property
    def title(self):
        return _(TITLES[self.flow["action"]])

    def result(self, text, title=None, finish="main", skip_current_view=False):
        return Destination(
            ToolsLuckfoxResultView,
            view_args=dict(title=title or self.title, text=text, finish=finish),
            skip_current_view=skip_current_view,
        )

    def refuse(self, text):
        """A dead end with no side effects: Back returns to where the user chose."""
        return self.result(text, title=_("Cannot continue"), finish="back",
                           skip_current_view=True)

    def derive_keys(self, want_ed: bool):
        """(rsa_key, ed_seed or None). RSA-2048 from a DRNG is slow on this
        hardware (tens of seconds is normal), so a loading screen goes up first."""
        from seedsigner.views.gpg_views import bip85_rsa_from_root, bip85_ed25519_seed_from_root
        seed = self.controller.storage.seeds[self.flow["seed_num"]]
        root = seed.get_root(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
        loading = LoadingScreenThread(text=_("Deriving keys..."))
        loading.start()
        try:
            rsa_key = bip85_rsa_from_root(root, RSA_KEY_BITS, self.flow["rsa_index"])
            ed_seed = bip85_ed25519_seed_from_root(root, self.flow["ed_index"]) if want_ed else None
        finally:
            loading.stop()
        return rsa_key, ed_seed


"""****************************************************************************
    The submenu
****************************************************************************"""
class ToolsLuckfoxBuildToolsMenuView(View):
    CHECK = ButtonOption("Check Release")
    EXPORT = ButtonOption("Export Pubkeys")
    RESIGN = ButtonOption("Resign All")
    PROVISION = ButtonOption("Provision MicroSD")
    FORCE = ButtonOption("Force Rootfs Check")
    DANGER = ButtonOption("Danger Zone", button_label_color="red")

    def run(self):
        if not MicroSD.get_instance().is_inserted:
            self.run_screen(
                WarningScreen,
                title=_("No MicroSD"),
                status_headline=None,
                text=_("Insert a MicroSD card holding a release folder."),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        button_data = [self.CHECK, self.EXPORT, self.RESIGN, self.PROVISION,
                       self.FORCE, self.DANGER]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Luckfox Build Tools"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        choice = button_data[selected]
        if choice == self.CHECK:
            return next_step(dict(action=ACTION__CHECK))
        if choice == self.EXPORT:
            return next_step(dict(action=ACTION__EXPORT))
        if choice == self.RESIGN:
            return Destination(ToolsResignReleaseStartView)
        if choice == self.PROVISION:
            return next_step(dict(action=ACTION__PROVISION))
        if choice == self.FORCE:
            return Destination(ToolsLuckfoxForceInfoView, view_args=dict(page=1))
        return Destination(ToolsLuckfoxDangerZoneView)


class ToolsLuckfoxResultView(View):
    """Read-only text, paged. `finish`: "main" (after changes) or "back"."""

    def __init__(self, title: str, text: str, finish: str = "main",
                 page_num: int = 0, paged_info: list = None):
        super().__init__()
        self.title, self.text, self.finish = title, text, finish
        self.page_num, self.paged_info = page_num, paged_info

    def run(self):
        if self.paged_info is None:
            width, height = PagedTextScreen.get_paging_dimensions()
            self.paged_info = reflow_text_into_pages(
                text=self.text, width=width, height=height,
                font_size=GUIConstants.get_body_font_size())
        selected = self.run_screen(
            PagedTextScreen,
            title=self.title,
            page_num=self.page_num,
            paged_info=self.paged_info,
            show_back_button=self.finish == "back" or self.page_num > 0,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        if self.page_num < len(self.paged_info) - 1:
            return Destination(ToolsLuckfoxResultView, view_args=dict(
                title=self.title, text=self.text, finish=self.finish,
                page_num=self.page_num + 1, paged_info=self.paged_info))
        if self.finish == "main":
            return Destination(MainMenuView, clear_history=True)
        # Pop every page of this text, back to the view before the first one.
        for _i in range(self.page_num):
            self.controller.back_stack.pop()
        return Destination(BackStackView)


"""****************************************************************************
    Shared pickers
****************************************************************************"""
class ToolsLuckfoxSelectSeedView(_FlowView):
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

        # SeedSelectSeedScreen, not ButtonListScreen: it is the one that takes the
        # `text` prompt (it is what SeedSelectSeedView uses). ButtonListScreen has no
        # such field and raised TypeError the moment this view ran on a device.
        selected = self.run_screen(
            seed_screens.SeedSelectSeedScreen,
            title=self.title,
            text=_("Select the signing seed") if seeds else _("Load the signing seed"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        if button_data[selected] == self.LOAD_SEED:
            from seedsigner.views.seed_views import LoadSeedView
            return Destination(LoadSeedView)
        return next_step(dict(self.flow, seed_num=selected))


class ToolsLuckfoxRsaIndexView(_FlowView):
    """BIP85 child index for the RSA-2048 boot-chain key."""

    def run(self):
        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title=_("RSA Key Index")).display()
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return next_step(dict(self.flow, rsa_index=int(ret)))


class ToolsLuckfoxEd25519IndexView(_FlowView):
    """BIP85 child index for the Ed25519 rootfs key."""

    def run(self):
        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title=_("Ed25519 Key Index")).display()
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return next_step(dict(self.flow, ed_index=int(ret)))


class ToolsLuckfoxSelectFolderView(_FlowView):
    """List the folders on the card that look like a release."""

    def run(self):
        from seedsigner.helpers import resign_release

        root = str(MicroSD.get_microsd_dir())
        folders = resign_release.find_release_dirs(root)
        if not folders:
            self.run_screen(
                WarningScreen,
                title=_("No release"),
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
        return next_step(dict(self.flow, folder=folders[selected]))


"""****************************************************************************
    1. Check Release
****************************************************************************"""
class ToolsLuckfoxCheckReleaseView(_FlowView):
    def run(self):
        from seedsigner.helpers import resign_release

        loading = LoadingScreenThread(text=_("Checking..."))
        loading.start()
        try:
            rep = resign_release.check_release(self.flow["folder"])
            pages = resign_release.report_pages(rep)
        except Exception as e:
            logger.exception("release check failed")
            return self.refuse(_("The check could not run: {}").format(e))
        finally:
            loading.stop()

        verdict = _("VALID: every signature checks out.") if rep.ok else \
            _("INVALID: see Signatures.")
        text = "\n\n".join([verdict] + ["%s\n%s" % (t, body) for t, body in pages])
        return self.result(text, finish="back", skip_current_view=True)


"""****************************************************************************
    2. Export Pubkeys
****************************************************************************"""
class ToolsLuckfoxExportRunView(_FlowView):
    def run(self):
        from seedsigner.helpers import resign_release

        try:
            rsa_key, ed_seed = self.derive_keys(want_ed=True)
            out = resign_release.export_pubkeys(
                str(MicroSD.get_microsd_dir()), rsa_key, ed_seed,
                self.flow["rsa_index"], self.flow["ed_index"])
        except Exception as e:
            logger.exception("exporting the public keys failed")
            return self.result(_("Export failed: {}").format(e))

        text = _("Written to {dir} on the MicroSD:\n- release-rsa.pub\n- release-rootfs.pub\n"
                 "- README.txt\n\nRSA fingerprint:\n{fp}\n\nRootfs key id:\n{kid}").format(
            dir=os.path.basename(out),
            fp=resign_release.rsa_modulus_fingerprint(int(rsa_key.n))[:32],
            kid=resign_release.ed25519_key_id_text(ed_seed))
        return self.result(text)


"""****************************************************************************
    3. Resign All
****************************************************************************"""
class ToolsResignReleaseStartView(View):
    """Explain what this does before asking for anything."""

    CONTINUE = ButtonOption("Continue")

    def run(self):
        selected = self.run_screen(
            WarningScreen,
            title=_("Resign All"),
            status_headline=_("Signing keys from your seed"),
            text=_("Re-signs everything with BIP85 keys. Back up the seed and both "
                   "indexes."),
            button_data=[self.CONTINUE],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return next_step(dict(action=ACTION__RESIGN))


class ToolsResignConfirmView(_FlowView):
    """Show exactly what will be rewritten, before touching anything."""

    SIGN = ButtonOption("Sign")

    def run(self):
        from seedsigner.helpers import resign_release

        info = resign_release.inspect_release(self.flow["folder"])
        names = list(info["files"])
        if info["rootfs"]:
            names.append(os.path.basename(info["rootfs"]))
        # The folder was picked on the previous screen; this one must fit 240px.
        text = _("{n} files, RSA index {rsa}, Ed25519 index {ed}. Overwritten "
                 "in place.").format(n=len(names), rsa=self.flow["rsa_index"],
                                     ed=self.flow["ed_index"])
        if info["update_img"]:
            text += " " + _("update.img is deleted.")

        selected = self.run_screen(
            DireWarningScreen,
            title=_("Confirm Resign"),
            status_headline=None,
            text=text,
            button_data=[self.SIGN],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(ToolsResignRunView, view_args=dict(flow=self.flow))


class ToolsResignRunView(_FlowView):
    """Derive the keys, re-sign, verify, and report."""

    def run(self):
        from seedsigner.helpers import resign_release

        try:
            rsa_key, ed_seed = self.derive_keys(want_ed=True)
        except Exception as e:
            logger.exception("BIP85 key derivation failed")
            return self.result(_("Key derivation failed: {}").format(e))

        folder = self.flow["folder"]
        loading = LoadingScreenThread(text=_("Signing..."))
        loading.start()
        try:
            report = resign_release.resign_release(folder, rsa_key, ed_seed)
            checks = resign_release.verify_release(folder, int(rsa_key.n), ed_seed)
        except Exception as e:
            logger.exception("re-signing failed")
            return self.result(_("Signing failed, nothing was written: {}").format(e))
        finally:
            loading.stop()

        failed = [name for name, ok, _d in checks if not ok]
        if failed:
            report.warn(_("These did NOT verify afterwards: {}").format(", ".join(failed)))
        text = _report_text(report, [n for n, ok, _d in checks if ok])
        if report.deleted_update_img:
            return Destination(ToolsLuckfoxUpdateImgDeletedView,
                               view_args=dict(title=self.title, text=text))
        return self.result(text)


class ToolsLuckfoxUpdateImgDeletedView(View):
    """update.img packs a copy of the old chain, so a re-sign deletes it; say so."""

    def __init__(self, title: str, text: str):
        super().__init__()
        self.title, self.text = title, text

    def run(self):
        self.run_screen(
            WarningScreen,
            title=_("update.img"),
            status_headline=_("Stale file deleted"),
            text=_("It held the old signatures. Flash the separate images "
                   "instead."),
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(ToolsLuckfoxResultView,
                           view_args=dict(title=self.title, text=self.text))


"""****************************************************************************
    4. Provision MicroSD for Update
****************************************************************************"""
class ToolsLuckfoxProvisionView(_FlowView):
    """Check the release and the card; confirm every risk; then copy."""

    COPY = ButtonOption("Copy to card")
    CONTINUE = ButtonOption("Continue")

    def run(self):
        from seedsigner.helpers import resign_release

        card = str(MicroSD.get_microsd_dir())
        loading = LoadingScreenThread(text=_("Checking..."))
        loading.start()
        try:
            chk = resign_release.provision_check(self.flow["folder"], card)
        except Exception as e:
            logger.exception("provisioning check failed")
            return self.refuse(_("The check could not run: {}").format(e))
        finally:
            loading.stop()

        if chk["problems"]:
            return self.refuse(_("This release cannot be auto-flashed from MicroSD:") +
                               "\n\n" + _bullets(chk["problems"]))

        warnings = list(chk["warnings"])
        if chk["fixable"]:
            warnings.append(_("sd_update.txt would truncate {}. It is corrected before "
                              "copying.").format(", ".join(f.split(":")[0] for f in chk["fixable"])))
        if chk["overwrite"]:
            warnings.append(_("Replaces the sd_update.txt and images already at the "
                              "card root."))
        # One warning per screen: each is a separate risk, and the panel is small.
        for i, warning in enumerate(warnings):
            selected = self.run_screen(
                WarningScreen,
                title=self.title,
                status_headline=_("Check {i}/{n}").format(i=i + 1, n=len(warnings)),
                text=warning,
                button_data=[self.CONTINUE],
            )
            if selected == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        model = chk["identity"].get("model") or _("unknown board")
        selected = self.run_screen(
            LargeIconStatusScreen,
            title=self.title,
            status_headline=model,
            text=_("Copy {n} files ({mib} MiB) to the card root and check each "
                   "copy.").format(n=len(chk["files"]), mib=max(1, chk["bytes"] >> 20))
            if not chk["in_place"] else _("Already at the card root; only the script "
                                          "is corrected."),
            button_data=[self.COPY],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        loading = LoadingScreenThread(text=_("Copying..."))
        loading.start()
        try:
            resign_release.provision_microsd(self.flow["folder"], card)
        except Exception as e:
            logger.exception("provisioning failed")
            return self.result(_("Copy failed: {}").format(e))
        finally:
            loading.stop()
        return Destination(ToolsLuckfoxProvisionDoneView)


class ToolsLuckfoxProvisionDoneView(View):
    def run(self):
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Provision MicroSD"),
            status_headline=_("Card ready"),
            text=_("Boot the Luckfox with it inserted. Then REMOVE the card, or it "
                   "reflashes on every boot."),
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(MainMenuView, clear_history=True)


"""****************************************************************************
    5. Force Rootfs Check
****************************************************************************"""
class ToolsLuckfoxForceInfoView(View):
    """Two screens of explanation before anything else."""

    def __init__(self, page: int = 1):
        super().__init__()
        self.page = page

    def run(self):
        if self.page == 1:
            text = _("The rootfs signature is checked at boot only once secure boot "
                     "is enabled (fuse burned).")
        else:
            text = _("Without secure boot the checker itself can be replaced. It "
                     "proves integrity only.")
        selected = self.run_screen(
            WarningScreen,
            title=_("Force Rootfs Check"),
            status_headline=_("Off unless secure boot") if self.page == 1 else
            _("Harmless, not protection"),
            text=text,
            button_data=[ButtonOption("Next") if self.page == 1 else ButtonOption("Continue")],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        if self.page == 1:
            return Destination(ToolsLuckfoxForceInfoView, view_args=dict(page=2))
        return next_step(dict(action=ACTION__FORCE))


class ToolsLuckfoxForceStateView(_FlowView):
    TURN_ON = ButtonOption("Turn on")
    TURN_OFF = ButtonOption("Turn off")

    def run(self):
        from seedsigner.helpers import resign_release

        try:
            state = resign_release.force_rootfs_state(self.flow["folder"])
        except Exception as e:
            logger.exception("reading the forced-check state failed")
            return self.refuse(_("Could not read this release: {}").format(e))
        if state is None:
            return self.refuse(_("This release's rootfs verifier predates the forced "
                                 "check, so it cannot be turned on. Use a newer build."))

        button_data = [self.TURN_OFF] if state else [self.TURN_ON]
        selected = self.run_screen(
            LargeIconStatusScreen,
            title=self.title,
            status_headline=_("Currently on") if state else _("Currently off"),
            text=_("Re-signs boot.img: needs the seed and RSA index this release "
                   "is signed with."),
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return next_step(dict(self.flow, force_on=not state))


class ToolsLuckfoxForceRunView(_FlowView):
    def run(self):
        from seedsigner.helpers import resign_release

        try:
            rsa_key, _unused = self.derive_keys(want_ed=False)
        except Exception as e:
            logger.exception("BIP85 key derivation failed")
            return self.result(_("Key derivation failed: {}").format(e))
        loading = LoadingScreenThread(text=_("Signing..."))
        loading.start()
        try:
            report = resign_release.set_force_rootfs(
                self.flow["folder"], rsa_key, self.flow["force_on"])
        except Exception as e:
            logger.exception("changing the forced check failed")
            return self.result(_("Nothing was changed: {}").format(e))
        finally:
            loading.stop()
        text = _report_text(report)
        if report.deleted_update_img:
            return Destination(ToolsLuckfoxUpdateImgDeletedView,
                               view_args=dict(title=self.title, text=text))
        return self.result(text)


"""****************************************************************************
    6. Danger Zone
****************************************************************************"""
class ToolsLuckfoxDangerZoneView(View):
    ARM = ButtonOption("Arm eFuse Burn", button_label_color="red")

    def run(self):
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Danger Zone"),
            is_button_text_centered=False,
            button_data=[self.ARM],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(ToolsLuckfoxArmWarningView)


class ToolsLuckfoxArmWarningView(View):
    """First of two irreversible-action warnings."""

    def run(self):
        selected = self.run_screen(
            DireWarningScreen,
            title=_("Arm eFuse Burn"),
            status_headline=_("IRREVERSIBLE"),
            text=_("Its next boot burns this key into OTP. The board then runs ONLY "
                   "images it signs, forever."),
            button_data=[ButtonOption("I understand")],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return next_step(dict(action=ACTION__ARM))


class ToolsLuckfoxArmCheckView(_FlowView):
    """Refuse before the seed is entered if the release is not fit to be burned."""

    def run(self):
        from seedsigner.helpers import resign_release

        loading = LoadingScreenThread(text=_("Checking..."))
        loading.start()
        try:
            reasons = resign_release.arm_burn_check(self.flow["folder"])
        except Exception as e:
            logger.exception("arm check failed")
            reasons = [str(e)]
        finally:
            loading.stop()
        if reasons:
            return self.refuse(_("Not armed:") + "\n\n" + _bullets(reasons))
        return next_step(dict(self.flow, arm_ok=True), skip_current_view=True)


class ToolsLuckfoxArmRunView(_FlowView):
    """Derive the key, prove it is the release's, warn once more, then arm."""

    ARM = ButtonOption("Arm the burn", button_label_color="red")

    def run(self):
        from seedsigner.helpers import resign_release

        try:
            rsa_key, _unused = self.derive_keys(want_ed=False)
            resign_release.require_release_key(self.flow["folder"], rsa_key)
        except Exception as e:
            logger.exception("arm key check failed")
            return self.result(_("Not armed: {}").format(e))

        selected = self.run_screen(
            DireWarningScreen,
            title=_("Final Warning"),
            status_headline=_("Burns a fuse. Forever."),
            text=_("Key {fp}, RSA index {i}. Flash this only to the board you mean "
                   "to lock.").format(
                fp=resign_release.rsa_modulus_fingerprint(int(rsa_key.n))[:16],
                i=self.flow["rsa_index"]),
            button_data=[self.ARM],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        loading = LoadingScreenThread(text=_("Arming..."))
        loading.start()
        try:
            report = resign_release.arm_burn(self.flow["folder"], rsa_key)
        except Exception as e:
            logger.exception("arming failed")
            return self.result(_("Not armed: {}").format(e))
        finally:
            loading.stop()
        text = _report_text(report)
        if report.deleted_update_img:
            return Destination(ToolsLuckfoxUpdateImgDeletedView,
                               view_args=dict(title=self.title, text=text))
        return self.result(text)
