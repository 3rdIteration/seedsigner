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
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views.view import View, Destination, BackStackView, MainMenuView

logger = logging.getLogger(__name__)

# RSA-2048 is not a preference: the Rockchip SPL verifier rejects any other key
# length with -EINVAL before the BootROM is reached.
RSA_KEY_BITS = 2048

ACTION__CHECK = "check"
ACTION__EXPORT = "export"
ACTION__RESIGN = "resign"
ACTION__REKEY = "rekey"
ACTION__SIGN_DIGEST = "sign_digest"
ACTION__PROVISION = "provision"
ACTION__FORCE = "force"
ACTION__ARM = "arm"

# What each action collects, in order. Force and Arm pick the folder first so a
# release they cannot work on is refused before anyone types in a seed. Sign
# Digest needs no folder: it signs whatever digests the card carries. Air-Gap
# Re-Key also needs no folder - the bundle lives on the PC; only the key source
# is collected here, and the ceremony itself paces the card round-trips.
STEPS = {
    ACTION__CHECK: ("folder",),
    ACTION__EXPORT: ("seed_num", "rsa_index", "ed_index"),
    # Resign Release asks where its keys come from first; see _steps().
    ACTION__RESIGN: ("source", "folder"),
    ACTION__REKEY: ("source",),
    ACTION__SIGN_DIGEST: ("source",),
    ACTION__PROVISION: ("folder",),
    ACTION__FORCE: ("folder", "force_on", "seed_num", "rsa_index"),
    ACTION__ARM: ("folder", "arm_ok", "seed_num", "rsa_index"),
}

TITLES = {
    ACTION__CHECK: _mft("Check Release"),
    ACTION__EXPORT: _mft("Export Pubkeys"),
    ACTION__RESIGN: _mft("Resign Release"),
    ACTION__REKEY: _mft("Air-Gap Re-Key"),
    ACTION__SIGN_DIGEST: _mft("Sign Digest"),
    ACTION__PROVISION: _mft("Provision MicroSD"),
    ACTION__FORCE: _mft("Force Rootfs Check"),
    ACTION__ARM: _mft("Arm eFuse Burn"),
}

# Free RAM below this, in kB, earns a warning before the heavy actions run. A
# full mini-bundle re-sign peaks at ~14 MB of Python heap measured; 32 MB leaves
# headroom for the app itself and is expected to trip on the Pico Mini (64 MB)
# but not on the Max/Pi or the Pi/La Frite boards. Re-tune after a hardware run.
RESIGN_MIN_AVAILABLE_KB = 32 * 1024


def _low_memory_line(hint=""):
    """A warning line when free RAM looks tight for the heavy actions, else "".

    Reads the kernel's own /proc/meminfo via helpers.system_memory, which never
    raises and degrades to None on a desktop/CI host without /proc - there the
    check is simply skipped. `hint` is one action-specific sentence. The app's
    own RSS (current + high-water mark) goes in too: on a 64 MB board that says
    how much of "free" the app itself will keep, and it is what to compare
    against after a hardware run when tuning RESIGN_MIN_AVAILABLE_KB."""
    from seedsigner.helpers import system_memory

    stats = system_memory.get_memory_stats()
    if stats.available_kb is None or stats.available_kb >= RESIGN_MIN_AVAILABLE_KB:
        return ""
    line = _("Low memory: {free} free of {total}, app using {rss}.").format(
                 free=system_memory.format_kb(stats.available_kb),
                 total=system_memory.format_kb(stats.total_kb),
                 rss=system_memory.format_kb(stats.app_rss_kb))
    if stats.app_peak_rss_kb is not None and stats.app_peak_rss_kb > (stats.app_rss_kb or 0):
        line += " " + _("Peak so far: {peak}.").format(
            peak=system_memory.format_kb(stats.app_peak_rss_kb))
    if hint:
        line += " " + hint
    return line


# Where Resign Release's keys come from.
KEY_SOURCE__BIP85 = "bip85"
KEY_SOURCE__MICROSD = "microsd"
KEY_SOURCE__SEEDKEEPER = "seedkeeper"


def _key_steps(flow: dict, want_ed: bool) -> tuple:
    """What the chosen key source needs collecting."""
    source = flow.get("source", KEY_SOURCE__BIP85)
    if source == KEY_SOURCE__MICROSD:
        return ("rsa_file",) + (("ed_file",) if want_ed else ())
    if source == KEY_SOURCE__SEEDKEEPER:
        return ("seedkeeper_keys",)
    return ("seed_num", "rsa_index") + (("ed_index",) if want_ed else ())


def _steps(flow: dict) -> tuple:
    steps = STEPS[flow["action"]]
    if "source" in steps and "source" in flow:
        at = steps.index("source") + 1
        steps = steps[:at] + _key_steps(flow, want_ed=True) + steps[at:]
    return steps


def next_step(flow: dict, skip_current_view: bool = False) -> Destination:
    """Route to the first thing `flow` still lacks, or to the action itself."""
    collectors = {
        "source": ToolsLuckfoxKeySourceView,
        "rsa_file": ToolsLuckfoxKeyFileView,
        "ed_file": ToolsLuckfoxKeyFileView,
        "seedkeeper_keys": ToolsLuckfoxSeedKeeperKeysView,
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
        ACTION__REKEY: ToolsRekeyExportView,
        ACTION__SIGN_DIGEST: ToolsSignDigestRunView,
        ACTION__PROVISION: ToolsLuckfoxProvisionView,
        ACTION__FORCE: ToolsLuckfoxForceRunView,
        ACTION__ARM: ToolsLuckfoxArmRunView,
    }
    for key in _steps(flow):
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

    def load_keys(self, want_ed: bool):
        """(rsa_key, (ed_seed, stored key id or None)) or a None pair.

        The key id is only non-None for keys loaded from a minisign secret-key
        file that carries its own; derived and bare-seed keys use the id their
        seed deterministically produces."""
        from seedsigner.helpers import resign_release
        source = self.flow.get("source", KEY_SOURCE__BIP85)
        if source == KEY_SOURCE__MICROSD:
            return (resign_release.load_key_file(self.flow["rsa_file"], "rsa"),
                    resign_release.load_key_file(self.flow["ed_file"], "ed25519")
                    if want_ed else None)
        if source == KEY_SOURCE__SEEDKEEPER:
            keys = take_seedkeeper_keys(self.controller)
            if keys is None:
                raise resign_release.ResignError(
                    "the SeedKeeper keys are no longer in memory; load them again")
            return keys[0], keys[1] if want_ed else None
        return self.derive_keys(want_ed)

    def derive_keys(self, want_ed: bool):
        """(rsa_key, (ed_seed, None) or None). RSA-2048 from a DRNG is slow on
        this hardware (tens of seconds is normal), so a loading screen goes up
        first. Derived keys have no stored id: it comes from the seed."""
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
        return rsa_key, (ed_seed, None) if want_ed else None


# Release signing keys are held here, in RAM only, between collection and use (a
# flow dict is logged, so it carries labels, never keys). Resign Release takes
# them at its run step; Air-Gap Re-Key keeps them across the card round-trips
# and clears them when the ceremony ends. Opening the submenu discards any left
# behind either way.
_SEEDKEEPER_KEYS_ATTR = "luckfox_release_keys"


def stash_seedkeeper_keys(controller, rsa_key, ed_seed):
    setattr(controller, _SEEDKEEPER_KEYS_ATTR, (rsa_key, ed_seed))


def take_seedkeeper_keys(controller):
    keys = getattr(controller, _SEEDKEEPER_KEYS_ATTR, None)
    setattr(controller, _SEEDKEEPER_KEYS_ATTR, None)
    return keys


def peek_rekey_keys(controller):
    """The (rsa_key, ed_seed) held for the in-progress re-key ceremony, or None.

    Non-destructive: the ceremony signs twice and needs them both times."""
    return getattr(controller, _SEEDKEEPER_KEYS_ATTR, None)


def clear_rekey_keys(controller):
    setattr(controller, _SEEDKEEPER_KEYS_ATTR, None)


# The Pico Mini (RV1103) cannot run the two heaviest actions: Resign Release runs
# out of memory re-signing the rootfs, and Force Rootfs Check has crashed on it.
# Both are refused with a warning instead; Sign Digest is unaffected and remains
# the air-gapped signing path (Force Rootfs Check's PC-side counterpart,
# `airgap-sign.py force`, only needs a digest signed here).
LUCKFOX_MINI_PROFILE = "luckfox_22"


"""****************************************************************************
    The submenu
****************************************************************************"""
class ToolsLuckfoxBuildToolsMenuView(View):
    CHECK = ButtonOption("Check Release")
    EXPORT = ButtonOption("Export Pubkeys")
    RESIGN = ButtonOption("Resign Release")
    REKEY = ButtonOption("Air-Gap Re-Key")
    SIGN_DIGEST = ButtonOption("Sign Digest")
    PROVISION = ButtonOption("Provision MicroSD")
    FORCE = ButtonOption("Force Rootfs Check")
    DANGER = ButtonOption("Danger Zone", button_label_color="red")

    def run(self):
        take_seedkeeper_keys(self.controller)       # drop any abandoned ones
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

        button_data = [self.CHECK, self.EXPORT, self.RESIGN, self.REKEY, self.SIGN_DIGEST,
                       self.PROVISION, self.FORCE, self.DANGER]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Luckfox Build Tools"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        choice = button_data[selected]
        if Settings.RUNTIME_PROFILE == LUCKFOX_MINI_PROFILE:
            # The Mini's DRAM cannot stage these; refuse before any picker runs.
            if choice == self.RESIGN:
                return Destination(ToolsLuckfoxResultView, view_args=dict(
                    title=_("Not supported here"), finish="back",
                    text=_(
                        "Resign Release needs more memory than this board has and crashes it. Use the "
                        "Sign Digest workflow instead: your PC lays digests on the card (airgap-sign.py), "
                        "you sign them here, and the PC splices the signatures back into the release.")))
            if choice == self.FORCE:
                return Destination(ToolsLuckfoxResultView, view_args=dict(
                    title=_("Not supported here"), finish="back",
                    text=_(
                        "Force Rootfs Check is too heavy for this board and crashes it. Do it from your "
                        "PC instead: airgap-sign.py force <bundle> --card <mount> reworks boot.img there "
                        "and leaves its digest on the card - sign it with Sign Digest, then splice.")))
        if choice == self.CHECK:
            return next_step(dict(action=ACTION__CHECK))
        if choice == self.EXPORT:
            return next_step(dict(action=ACTION__EXPORT))
        if choice == self.RESIGN:
            return Destination(ToolsResignReleaseStartView)
        if choice == self.REKEY:
            return Destination(ToolsRekeyStartView)
        if choice == self.SIGN_DIGEST:
            return Destination(ToolsSignDigestStartView)
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
class ToolsLuckfoxKeySourceView(_FlowView):
    """Derive the keys from a seed, or bring them: a file each, or a secret each."""

    BIP85 = ButtonOption("BIP85 Derive")
    MICROSD = ButtonOption("Load from MicroSD")
    SEEDKEEPER = ButtonOption("Load from SeedKeeper")

    def run(self):
        button_data = [self.BIP85, self.MICROSD, self.SEEDKEEPER]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Key Source"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        source = {0: KEY_SOURCE__BIP85, 1: KEY_SOURCE__MICROSD,
                  2: KEY_SOURCE__SEEDKEEPER}[selected]
        return next_step(dict(self.flow, source=source))


class ToolsLuckfoxKeyFileView(_FlowView):
    """Pick the file holding one key; the RSA key first, then the Ed25519 key."""

    @property
    def kind(self):
        return "rsa" if "rsa_file" not in self.flow else "ed25519"

    def run(self):
        from seedsigner.helpers import resign_release

        root = str(MicroSD.get_microsd_dir())
        files = resign_release.find_key_files(root)
        if not files:
            self.run_screen(
                WarningScreen,
                title=_("No key files"),
                status_headline=None,
                text=_("No small files on the MicroSD that could hold a key."),
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        title = _("RSA Key File") if self.kind == "rsa" else _("Ed25519 Key File")
        labels = [os.path.relpath(f, root) for f in files]
        while True:
            selected = self.run_screen(
                ButtonListScreen,
                title=title,
                is_button_text_centered=False,
                button_data=[ButtonOption(label) for label in labels],
            )
            if selected == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            try:
                resign_release.load_key_file(files[selected], self.kind)
            except Exception as e:
                self.run_screen(
                    WarningScreen,
                    title=title,
                    status_headline=_("Not usable"),
                    text=str(e),
                    button_data=[ButtonOption("Pick another")],
                )
                continue
            field = "rsa_file" if self.kind == "rsa" else "ed_file"
            return next_step(dict(self.flow, **{field: files[selected]}))


class ToolsLuckfoxSeedKeeperKeysView(_FlowView):
    """Pick one SeedKeeper secret per key, read both, and hold them in RAM."""

    def run(self):
        from seedsigner.helpers import resign_release, seedkeeper_utils

        connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
        if not connector:
            return Destination(BackStackView)

        loading = LoadingScreenThread(text=_("Listing secrets..."))
        loading.start()
        try:
            headers = connector.seedkeeper_list_secret_headers()
            minor = connector.card_get_status()[3].get("protocol_minor_version")
        except Exception as e:
            logger.exception("listing SeedKeeper secrets failed")
            return self.refuse(seedkeeper_utils.describe_seedkeeper_error(e, connector))
        finally:
            loading.stop()

        if not headers:
            return self.refuse(_("This SeedKeeper holds no secrets."))
        types = _seedkeeper_type_names()
        labels = []
        for h in headers:
            label = h.get("label") or "#%d" % h["id"]
            labels.append("%s (%s)" % (label, types[h["type"]]) if h["type"] in types else label)

        picked = []                                   # [(key, label)], RSA then Ed25519
        while len(picked) < 2:
            kind = "rsa" if not picked else "ed25519"
            selected = self.run_screen(
                ButtonListScreen,
                title=_("RSA Key Secret") if kind == "rsa" else _("Ed25519 Key Secret"),
                is_button_text_centered=False,
                button_data=[ButtonOption(label) for label in labels],
            )
            if selected == RET_CODE__BACK_BUTTON:
                if not picked:
                    return Destination(BackStackView)
                picked.pop()
                continue
            loading = LoadingScreenThread(text=_("Reading secret..."))
            loading.start()
            try:
                secret = connector.seedkeeper_export_secret(headers[selected]["id"], None)
                data = resign_release.seedkeeper_secret_bytes(secret["secret_list"], minor)
                key = (resign_release.parse_rsa_key(data) if kind == "rsa"
                       else resign_release.parse_ed25519_key(data))
            except Exception as e:
                logger.exception("reading a SeedKeeper key failed")
                error = e
            else:
                error = None
            finally:
                loading.stop()
            if error is not None:
                self.run_screen(
                    WarningScreen,
                    title=_("SeedKeeper"),
                    status_headline=_("Not usable"),
                    text=str(error),
                    button_data=[ButtonOption("Pick another")],
                )
                continue
            picked.append((key, labels[selected]))

        stash_seedkeeper_keys(self.controller, picked[0][0], picked[1][0])
        return next_step(dict(self.flow, seedkeeper_keys=True,
                              rsa_label=picked[0][1], ed_label=picked[1][1]))


def _seedkeeper_type_names() -> dict:
    """pysatochip's secret-type names, when the real library is present."""
    try:
        from pysatochip.JCconstants import SEEDKEEPER_DIC_TYPE
    except Exception:
        return {}
    return SEEDKEEPER_DIC_TYPE if isinstance(SEEDKEEPER_DIC_TYPE, dict) else {}


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
    CONTINUE = ButtonOption("Continue")

    def run(self):
        from seedsigner.helpers import resign_release

        # The check streams the rootfs and peaks at ~14 MB measured; on a tight
        # board say so before it runs, the same way Resign Release does.
        low_memory = _low_memory_line(
            _("The check streams the rootfs and usually fits."))
        if low_memory:
            selected = self.run_screen(
                WarningScreen,
                title=self.title,
                status_headline=_("Low memory"),
                text=low_memory,
                button_data=[self.CONTINUE],
            )
            if selected == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

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
            rsa_key, (ed_seed, _kid) = self.derive_keys(want_ed=True)
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
    3. Resign Release
****************************************************************************"""
class ToolsResignReleaseStartView(View):
    """Explain what this does before asking for anything."""

    CONTINUE = ButtonOption("Continue")

    def run(self):
        selected = self.run_screen(
            WarningScreen,
            title=_("Resign Release"),
            status_headline=_("Your keys, your releases"),
            text=_("Re-signs everything with your own keys. Keep a backup: a fused "
                   "board needs them."),
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
        text = _("{n} files, {keys}. Overwritten in place.").format(
            n=len(names), keys=self.key_summary())
        if info["update_img"]:
            text += " " + _("update.img is deleted.")
        low_memory = _low_memory_line(_("This may run out; Sign Digest needs far less."))
        if low_memory:
            text += "\n\n" + low_memory

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

    def key_summary(self):
        source = self.flow.get("source", KEY_SOURCE__BIP85)
        if source == KEY_SOURCE__MICROSD:
            return _("keys from MicroSD files")
        if source == KEY_SOURCE__SEEDKEEPER:
            return _("keys from SeedKeeper")
        return _("RSA index {rsa}, Ed25519 index {ed}").format(
            rsa=self.flow["rsa_index"], ed=self.flow["ed_index"])


class ToolsResignRunView(_FlowView):
    """Derive the keys, re-sign, verify, and report."""

    def run(self):
        from seedsigner.helpers import resign_release

        try:
            rsa_key, (ed_seed, stored_key_id) = self.load_keys(want_ed=True)
        except Exception as e:
            logger.exception("loading the signing keys failed")
            return self.result(_("Could not load the keys: {}").format(e))

        folder = self.flow["folder"]
        loading = LoadingScreenThread(text=_("Signing..."))
        loading.start()
        try:
            report = resign_release.resign_release(folder, rsa_key, ed_seed,
                                                   stored_key_id=stored_key_id)
            checks = resign_release.verify_release(folder, int(rsa_key.n), ed_seed,
                                                   stored_key_id=stored_key_id)
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
    3b. Sign Digest (air-gap: no bundle on the device)
****************************************************************************"""
class ToolsSignDigestStartView(View):
    """Explain the digest-signer role before asking for anything."""

    CONTINUE = ButtonOption("Continue")

    def run(self):
        selected = self.run_screen(
            WarningScreen,
            title=_("Sign Digest"),
            status_headline=_("No bundle needed"),
            text=_("Signs bare digests from the card's seedsigner-release-sign/ "
                   "folder: a few dozen bytes in, one signature out. The PC lays "
                   "the digests there and splices the signatures back."),
            button_data=[self.CONTINUE],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return next_step(dict(action=ACTION__SIGN_DIGEST))


class ToolsSignDigestRunView(_FlowView):
    """Load the keys, sign every digest on the card, and report."""

    def run(self):
        from seedsigner.helpers import resign_release

        try:
            rsa_key, (ed_seed, stored_key_id) = self.load_keys(want_ed=True)
        except Exception as e:
            logger.exception("loading the signing keys failed")
            return self.result(_("Could not load the keys: {}").format(e))

        loading = LoadingScreenThread(text=_("Signing..."))
        loading.start()
        try:
            report = resign_release.sign_digests(str(MicroSD.get_microsd_dir()),
                                                  rsa_key, ed_seed,
                                                  stored_key_id=stored_key_id)
        except Exception as e:
            logger.exception("signing the digests failed")
            return self.result(_("Signing failed, nothing was written: {}").format(e))
        finally:
            loading.stop()

        text = _report_text(report) + "\n\n" + \
            _("Take the card back to the PC and run `airgap-sign.py splice`.")
        if not report.ok:
            return self.refuse(text)
        # finish="main", NOT "back": popping back would land on this view again,
        # re-derive the keys and sign the same digests in a loop. The card goes
        # to the PC next anyway, so the main menu is where the user belongs.
        return self.result(text)


"""****************************************************************************
    3c. Air-Gap Re-Key (guided two-round-trip ceremony)

    Moves a release from its current boot key to the user's own keys with the
    private halves never leaving this device. The PC does round 0 (`rekey`,
    public halves only) and both splices; the device exports the pubkeys and
    signs twice - rootfs first, then everything else, because boot.img's
    signature covers the ramdisk the tier-C injection rewrites. Each step ends
    in an instruction screen; the next step validates the card before acting,
    so pressing on too early is refused rather than harmful.
****************************************************************************"""
class ToolsRekeyStartView(View):
    """Explain the ceremony before asking for anything."""

    CONTINUE = ButtonOption("Continue")

    def run(self):
        selected = self.run_screen(
            WarningScreen,
            title=_("Air-Gap Re-Key"),
            status_headline=_("Your keys never touch the PC"),
            text=_("Moves a release from its current boot key to your own. The "
                   "private keys stay on this device; the PC only ever sees "
                   "public halves and digests.\n\n"
                   "Two card round-trips, in an order that matters: rootfs "
                   "first, then everything else."),
            button_data=[self.CONTINUE],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return next_step(dict(action=ACTION__REKEY))


class ToolsRekeyInstructionView(View):
    """Paged ceremony instructions; the last page advances to `next_view`.

    Backing out returns to the previous step, which is safe to re-run: export
    is idempotent and signing is deterministic."""

    def __init__(self, title: str, text: str, next_view, next_args: dict = None,
                 page_num: int = 0, paged_info: list = None):
        super().__init__()
        self.title, self.text = title, text
        self.next_view = next_view
        self.next_args = next_args or {}
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
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        if self.page_num < len(self.paged_info) - 1:
            return Destination(ToolsRekeyInstructionView, view_args=dict(
                title=self.title, text=self.text, next_view=self.next_view,
                next_args=self.next_args, page_num=self.page_num + 1,
                paged_info=self.paged_info))
        return Destination(self.next_view, view_args=self.next_args)


class ToolsRekeyExportView(_FlowView):
    """Derive the keys, hold them in RAM for both signing rounds, and put the
    public halves on the card (skipping that when they are already there)."""

    def run(self):
        from seedsigner.helpers import resign_release

        try:
            rsa_key, (ed_seed, _kid) = self.load_keys(want_ed=True)
        except Exception as e:
            logger.exception("loading the re-key keys failed")
            return self.refuse(_("Could not load the keys: {}").format(e))
        # Hold them for the two signing rounds; opening the submenu again drops
        # any left behind if the ceremony is abandoned.
        stash_seedkeeper_keys(self.controller, rsa_key, ed_seed)

        card_root = str(MicroSD.get_microsd_dir())
        already = resign_release.pubkeys_on_card(card_root, rsa_key, ed_seed)
        if not already:
            try:
                out = resign_release.export_pubkeys(
                    card_root, rsa_key, ed_seed,
                    self.flow["rsa_index"], self.flow["ed_index"])
            except Exception as e:
                logger.exception("exporting the public keys failed")
                clear_rekey_keys(self.controller)
                return self.refuse(_("Export failed: {}").format(e))
        else:
            out = os.path.join(card_root, resign_release.KEYS_DIR)

        text = _("Public halves on the card ({dir}):\n- release-rsa.pub\n"
                 "- release-rootfs.pub\n\nRSA fingerprint:\n{fp}\n\nRootfs key "
                 "id:\n{kid}\n").format(
            dir=os.path.basename(out),
            fp=resign_release.rsa_modulus_fingerprint(int(rsa_key.n))[:32],
            kid=resign_release.ed25519_key_id_text(ed_seed))
        if already:
            text += _("They were already there and match, so nothing was "
                      "rewritten.\n")

        pc = _("\nOn the PC, with the card mounted:\n"
               "  airgap-sign.py rekey <bundle> --card <mount>\n"
               "  airgap-sign.py digests <bundle> --card <mount> --only rootfs\n\n"
               "Then take the card back here.")
        return Destination(ToolsRekeyInstructionView, view_args=dict(
            title=self.title, text=text + pc,
            next_view=ToolsRekeySignView, next_args=dict(flow=self.flow)))


class ToolsRekeySignView(_FlowView):
    """One signing round-trip. `rekey_round` in the flow: 1 (rootfs) or 2 (rest)."""

    def run(self):
        from seedsigner.helpers import resign_release

        if not MicroSD.get_instance().is_inserted:
            return self.refuse(_("Insert the card first - it must carry the "
                                 "digests the PC wrote."))
        keys = peek_rekey_keys(self.controller)
        if keys is None:
            clear_rekey_keys(self.controller)
            return self.refuse(_("The ceremony's keys are no longer in memory. "
                                 "Start Air-Gap Re-Key again."))
        rsa_key, ed_seed = keys

        loading = LoadingScreenThread(text=_("Signing..."))
        loading.start()
        try:
            report = resign_release.sign_digests(
                str(MicroSD.get_microsd_dir()), rsa_key, ed_seed)
        except Exception as e:
            logger.exception("signing the digests failed")
            return self.refuse(_("Signing failed, nothing was written: {}").format(e))
        finally:
            loading.stop()

        if not report.ok:
            return self.refuse(_report_text(report) + "\n\n" +
                               _("Fix this on the PC and bring the card back."))

        round_num = self.flow.get("rekey_round", 1)
        if round_num == 1:
            pc = _("\nOn the PC, with the card mounted:\n"
                   "  airgap-sign.py splice <bundle> --card <mount> \\\n"
                   "      --only rootfs --no-check\n"
                   "  airgap-sign.py digests <bundle> --card <mount> \\\n"
                   "      --only download,idblock,uboot,boot\n\n"
                   "Then take the card back here.")
            return Destination(ToolsRekeyInstructionView, view_args=dict(
                title=self.title, text=_report_text(report) + pc,
                next_view=ToolsRekeySignView,
                next_args=dict(flow=dict(self.flow, rekey_round=2))))

        # Round 2 done: the ceremony is over and the keys go away.
        clear_rekey_keys(self.controller)
        text = _report_text(report) + "\n\n" + \
            _("On the PC, with the card mounted:\n"
              "  airgap-sign.py splice <bundle> --card <mount>\n\n"
              "It must print RESULT: VALID. Then flash to a sacrificial, "
              "unfused board before trusting it.")
        # finish="main", NOT "back": popping back would land on this view again
        # and re-sign the same digests (harmless but pointless).
        return self.result(text)


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
