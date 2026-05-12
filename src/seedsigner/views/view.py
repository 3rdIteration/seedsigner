from dataclasses import dataclass, field
from gettext import gettext as _
from typing import Type

from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.gui.components import FontAwesomeIconConstants, SeedSignerIconConstants
from seedsigner.gui.screens import RET_CODE__POWER_BUTTON, RET_CODE__BACK_BUTTON, RET_CODE__DISPLAY_TOGGLE
from seedsigner.gui.screens.screen import BaseScreen, ButtonOption, LargeButtonScreen, WarningScreen, ErrorScreen
from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.models.settings_definition import SettingsDefinition
from seedsigner.models.threads import BaseThread


class BackStackView:
    """
        Empty class that just signals to the Controller to pop the most recent View off
        the back_stack.
    """
    pass



"""
    Views contain the biz logic to handle discrete tasks, exactly analogous to a Flask
    request/response function or a Django View. Each page/screen displayed to the user
    should be implemented in its own View.

    In a web context, the View would prepare data for the html/css/js presentation
    templates. We have to implement our own presentation layer (implemented as `Screen`
    objects). For the sake of code cleanliness and separation of concerns, the View code
    should not know anything about pixel-level rendering.

    Sequences that require multiple pages/screens should be implemented as a series of
    separate Views. Exceptions can be made for complex interactive sequences, but in
    general, if your View is instantiating multiple Screens, you're probably putting too
    much functionality in that View.

    As with http requests, Views can receive input vars to inform their behavior. Views
    can also prepare the next set of vars to set up the next View that should be
    displayed (akin to Flask's `return redirect(url, param1=x, param2=y))`).

    Navigation guidance:
    "Next" - Continue to next step
    "Done" - End of flow, return to entry point (non-destructive)
    "OK/Close" - Exit current screen (non-destructive)
    "Cancel" - End task and return to entry point (destructive)
"""
class View:
    def _initialize(self):
        """
        Whether the View is a regular class initialized by __init__() or a dataclass
        initialized by __post_init__(), this method will be called to set up the View's
        instance variables.
        """
        # Import here to avoid circular imports
        from seedsigner.controller import Controller
        from seedsigner.gui import Renderer

        self.controller: Controller = Controller.get_instance()
        self.settings = Settings.get_instance()

        # TODO: Pull all rendering-related code out of Views and into gui.screens implementations
        self.renderer = Renderer.get_instance()
        self.canvas_width = self.renderer.canvas_width
        self.canvas_height = self.renderer.canvas_height

        self.screen = None

        self._redirect: 'Destination' = None


    def __init__(self):
        self._initialize()


    def __post_init__(self):
        self._initialize()


    @property
    def has_redirect(self) -> bool:
        if not hasattr(self, '_redirect'):
            # Easy for a View to forget to call super().__init__()
            raise Exception(f"{self.__class__.__name__} did not call super().__init__()")
        return self._redirect is not None


    def set_redirect(self, destination: 'Destination'):
        """
        Enables early `__init__()` / `__post_init__()` logic to redirect away from the
        current View.

        Set a redirect Destination and then immediately `return` to exit `__init__()` or
        `__post_init__()`. When the `Destination.run()` is called, it will see the redirect
        and immediately return that new Destination to the Controller without running
        the View's `run()`.
        """
        # Always insure skip_current_view is set for a redirect
        destination.skip_current_view = True
        self._redirect = destination


    def get_redirect(self) -> 'Destination':
        return self._redirect


    def run_screen(self, Screen_cls: Type[BaseScreen], **kwargs) -> int | str:
        """
            Instantiates the provided Screen_cls and runs its interactive display.
            Returns the user's input upon completion.
        """
        self.screen = Screen_cls(**kwargs)
        return self.screen.display()


    def run(self, **kwargs) -> 'Destination':
        raise Exception("Must implement in the child class")



@dataclass
class Destination:
    """
        Basic struct to pass back to the Controller to tell it which View the user should
        be presented with next.
    """
    View_cls: Type[View]                # The target View to route to
    view_args: dict = None              # The input args required to instantiate the target View
    skip_current_view: bool = False     # The current View is just forwarding; omit current View from history
    clear_history: bool = False         # Optionally clears the back_stack to prevent "back"


    _SENSITIVE_ARG_NAMES = {
        "password",
        "passphrase",
        "mnemonic",
        "seed",
        "seed_bytes",
        "secret",
        "secret_list",
        "private_key",
        "pin",
    }

    @classmethod
    def _redact_for_repr(cls, value, key: str | None = None):
        if isinstance(value, dict):
            redacted = {}
            for k, v in value.items():
                key_name = str(k).lower()
                redacted[k] = cls._redact_for_repr(v, key=key_name)
            return redacted

        if isinstance(value, list):
            return [cls._redact_for_repr(item, key=key) for item in value]

        if isinstance(value, tuple):
            return tuple(cls._redact_for_repr(item, key=key) for item in value)

        if key and key in cls._SENSITIVE_ARG_NAMES:
            return "***redacted***"

        return value

    def __repr__(self):
        if self.View_cls is None:
            out = "None"
        else:
            out = self.View_cls.__name__
        if self.view_args:
            safe_view_args = self._redact_for_repr(self.view_args)
            out += f"({safe_view_args})"
        else:
            out += "()"
        if self.clear_history:
            out += f" | clear_history: {self.clear_history}"
        return out


    def _instantiate_view(self):
        # Use a local for the unpack so a Destination created with
        # view_args=None keeps view_args=None after run(). Mutating
        # self.view_args broke __eq__ when comparing a back_stack entry
        # (already run, view_args mutated to {}) with a fresh
        # Destination(..., view_args=None) returned via skip_current_view
        # — equal-by-intent destinations were treated as different and
        # appended again, leaving a stale duplicate on the back stack.
        view_args = self.view_args or {}
        self.view = self.View_cls(**view_args)
    

    def _run_view(self):
        if self.view.has_redirect:
            return self.view.get_redirect()
        return self.view.run()


    def run(self):
        self._instantiate_view()
        return self._run_view()


    def __eq__(self, obj):
        """
            Equality test IGNORES the skip_current_view and clear_history options.
            Treats view_args=None and view_args={} as equivalent so that an
            unmutated fresh Destination still matches one that was run.
        """
        return (isinstance(obj, Destination) and
            obj.View_cls == self.View_cls and
            (obj.view_args or {}) == (self.view_args or {}))
    

    def __ne__(self, obj):
        return not obj == self



#########################################################################################
#
# Root level Views don't have a sub-module home so they live at the top level here.
#
#########################################################################################
class MainMenuView(View):
    SCAN = ButtonOption("Scan", SeedSignerIconConstants.SCAN)
    CARDS = ButtonOption("Cards", FontAwesomeIconConstants.ID_CARD)
    TOOLS = ButtonOption("Tools", SeedSignerIconConstants.TOOLS)
    SETTINGS = ButtonOption("Settings", SeedSignerIconConstants.SETTINGS)

    def run(self):
        from seedsigner.gui.screens.screen import MainMenuScreen
        from seedsigner.controller import Controller
        from seedsigner.gui.toast import InfoToast

        controller = Controller.get_instance()
        controller.storage.discard_pending_slip39_shares()
        controller.tools_common_card_filter = None
        controller.psbt_from_microsd = False
        controller.psbt_microsd_save_path = None
        controller.psbt_microsd_seed_warning_shown = False
        if controller.auto_wiped:
            controller.auto_wiped = False
            controller.activate_toast(InfoToast(label_text=_("Data wiped after inactivity")))
        button_data = [self.SCAN, self.CARDS, self.TOOLS, self.SETTINGS]
        selected_menu_num = self.run_screen(
            MainMenuScreen,
            title=_("Home"),
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__POWER_BUTTON:
            return Destination(PowerOptionsView)

        if selected_menu_num == RET_CODE__DISPLAY_TOGGLE:
            # Display driver was switched via very-long-press; re-render the
            # home screen with the new display dimensions.
            return Destination(MainMenuView)

        if button_data[selected_menu_num] == self.SCAN:
            from seedsigner.views.scan_views import ScanView
            return Destination(ScanView)

        elif button_data[selected_menu_num] == self.CARDS:
            return Destination(CardsMenuView)

        elif button_data[selected_menu_num] == self.TOOLS:
            from seedsigner.views.tools_views import ToolsMenuView
            return Destination(ToolsMenuView)

        elif button_data[selected_menu_num] == self.SETTINGS:
            from seedsigner.views.settings_views import SettingsMenuView
            return Destination(SettingsMenuView)



class CardsMenuView(View):
    """
    Top-level entry point for smartcard apps. Each entry probes the card on
    selection: if uninstantiated the user is routed to the matching setup
    wizard before the app's own menu is shown.

    A SELECT-probe on entry annotates each entry with a trailing icon
    showing whether the applet is installed on the currently-inserted
    card. Factory Reset wipes every installed applet at the bottom.
    """

    SEEDKEEPER_LABEL = "SeedKeeper"
    SATOCHIP_LABEL = "Satochip"
    KEYCARD_LABEL = "Keycard"
    FACTORY_RESET_LABEL = "Factory reset card"

    def run(self):
        from seedsigner.gui.screens.screen import ButtonListScreen
        from seedsigner.hardware.buttons import (
            HardwareButtons, HardwareButtonsConstants,
        )
        from seedsigner.helpers.card_probe import probe_installed_applets

        controller = self.controller
        try:
            hw_inputs = HardwareButtons.get_instance()
        except Exception:
            hw_inputs = None

        # ``refresh_requested`` is mutated from the CardMonitor thread
        # via the listener callbacks below; the box pattern keeps the
        # closure cheap and avoids needing a Lock for a single bool.
        refresh_requested = [False]

        def _on_card_event(*_args, **_kwargs):
            refresh_requested[0] = True
            if hw_inputs is not None:
                try:
                    hw_inputs.trigger_override()
                except Exception:
                    # ``trigger_override`` is best-effort: the screen
                    # will still pick up the new state on next entry.
                    pass

        controller.register_card_inserted_listener(_on_card_event)
        controller.register_card_removed_listener(_on_card_event)
        try:
            while True:
                refresh_requested[0] = False
                state = probe_installed_applets(controller)

                def _entry(label: str, installed: bool) -> ButtonOption:
                    if not state.present:
                        return ButtonOption(label)
                    icon = (
                        SeedSignerIconConstants.CHECK if installed
                        else SeedSignerIconConstants.CHECKBOX
                    )
                    return ButtonOption(label, right_icon_name=icon)

                seedkeeper_btn = _entry(self.SEEDKEEPER_LABEL, state.seedkeeper_installed)
                satochip_btn = _entry(self.SATOCHIP_LABEL, state.satochip_installed)
                keycard_btn = _entry(self.KEYCARD_LABEL, state.keycard_installed)
                factory_reset_btn = ButtonOption(
                    self.FACTORY_RESET_LABEL,
                    icon_name=FontAwesomeIconConstants.LOCK,
                )

                button_data = [seedkeeper_btn, satochip_btn, keycard_btn, factory_reset_btn]

                selected_menu_num = self.run_screen(
                    ButtonListScreen,
                    title=_("Cards"),
                    is_button_text_centered=False,
                    button_data=button_data,
                )

                if selected_menu_num == HardwareButtonsConstants.OVERRIDE:
                    # CardMonitor woke us up — re-probe and redraw.
                    continue

                if selected_menu_num == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)

                chosen = button_data[selected_menu_num]
                if chosen is seedkeeper_btn:
                    from seedsigner.views.tools_views import ToolsSeedkeeperView
                    return Destination(ToolsSeedkeeperView)
                if chosen is satochip_btn:
                    from seedsigner.views.tools_views import ToolsSatochipView
                    return Destination(ToolsSatochipView)
                if chosen is keycard_btn:
                    from seedsigner.views.keycard_views import ToolsKeycardMenuView
                    return Destination(ToolsKeycardMenuView)
                if chosen is factory_reset_btn:
                    return Destination(CardsFactoryResetView)
        finally:
            controller.unregister_card_inserted_listener(_on_card_event)
            controller.unregister_card_removed_listener(_on_card_event)


_DEFAULT_CAP_BY_KIND = {
    # ``-force`` makes the install tolerant of a pre-existing load file
    # — necessary because earlier factory-reset builds left orphan
    # Keycard load files on user cards, and a fresh install fails with
    # "Applet loading not allowed" without this flag. Per-applet
    # uninstall views already use ``-force`` for the same reason.
    "satochip": ("SatoChip-0.12-official.cap", "--install {cap} -force"),
    # `{params}` is filled at install time from the storage chooser
    # (Change 3 below); 1FFF = 8 KB is the default.
    "seedkeeper": ("SeedKeeper-0.2-official.cap", "--install {cap} --params {params} -force"),
    # Keycard is a multi-instance package: --load then 3 × --create.
    # The recipe matches the proven keycard-cli install path; the
    # signing instance AID (A0000008040001010101) must stay exact —
    # `select_with_autodetect` and the rest of the Keycard views select
    # against it.
    "keycard": ("Keycard-3.2.cap", None),
}

# Seedkeeper --params values per the applet's INSTALL parameter format:
# the first byte sets the data-object-store size, with 0xFF meaning the
# applet's max. (4/8/16/32/64 KB → 0FFF/1FFF/3FFF/7FFF/FFFF.) Matches
# the chooser previously offered by the DIY-tools view (PR #189).
_SEEDKEEPER_STORAGE_OPTIONS = [
    ("4 KB", "0FFF"),
    ("8 KB (default)", "1FFF"),
    ("16 KB", "3FFF"),
    ("32 KB", "7FFF"),
    ("64 KB", "FFFF"),
]
_SEEDKEEPER_STORAGE_DEFAULT_INDEX = 1  # 8 KB

_KEYCARD_CREATE_COMMANDS = [
    "--package A0000008040001 --applet A000000804000101 --create A0000008040001010101",
    "--package A0000008040001 --applet A000000804000102 --create D2760000850101",
    "--package A0000008040001 --applet A000000804000103 --create A0000008040001030101",
]


class CardsInstallAppletView(View):
    """Install the .cap for a requested applet kind.

    Reuses ``seedkeeper_utils.run_globalplatform`` which shells out to
    ``gp.jar`` in the diy-tools squashfs. The .cap files are baked into
    the firmware image under ``<microsd>/javacard-cap/``.
    """

    def __init__(self, kind: str):
        super().__init__()
        self.kind = kind

    def run(self):
        from seedsigner.gui.screens.screen import (
            ButtonListScreen, LargeIconStatusScreen, WarningScreen,
        )
        from seedsigner.hardware.microsd import MicroSD
        from seedsigner.helpers import seedkeeper_utils

        info = _DEFAULT_CAP_BY_KIND.get(self.kind)
        if info is None:
            return _show_warning(self, "Install", f"Unknown applet kind: {self.kind}")

        cap_name, single_cmd_template = info
        cap_path = MicroSD.get_microsd_dir() / "javacard-cap" / cap_name
        if not cap_path.exists():
            return _show_warning(
                self, "Install",
                f"Applet bundle missing:\n{cap_name}\nRebuild seedsigner-os.",
            )

        # SeedKeeper: ask the user how much object storage to allocate
        # (4/8/16/32/64 KB). Restores the chooser that PR #189 added to
        # the pre-refactor DIY-tools install view.
        storage_param = None
        if self.kind == "seedkeeper":
            options = [
                ButtonOption(label, return_data=value)
                for (label, value) in _SEEDKEEPER_STORAGE_OPTIONS
            ]
            selected = self.run_screen(
                ButtonListScreen,
                title="Select Storage",
                is_button_text_centered=False,
                button_data=options,
                selected_button=_SEEDKEEPER_STORAGE_DEFAULT_INDEX,
            )
            if selected == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            storage_param = options[selected].return_data or "1FFF"

        if self.kind == "keycard":
            # Multi-step recipe: --load then 3 × --create instances.
            # ``-force`` on --load deletes any pre-existing Keycard load
            # file (orphan from older factory-reset builds).
            steps = [(f"--load {cap_path} -force", "Loading Keycard package")]
            steps.extend(
                (cmd, f"Creating Keycard instance {i + 1}/3")
                for i, cmd in enumerate(_KEYCARD_CREATE_COMMANDS)
            )
            for command, label in steps:
                result = seedkeeper_utils.run_globalplatform(self, command, label, None)
                if result is None:
                    return _show_warning(self, "Install", "Keycard install failed.")
        else:
            command = single_cmd_template.format(cap=str(cap_path), params=storage_param)
            result = seedkeeper_utils.run_globalplatform(
                self, command, f"Installing {self.kind}", None,
            )
            if result is None:
                return _show_warning(self, "Install", f"{self.kind} install failed.")

        # gp.jar leaves scdaemon holding the reader and may invalidate any
        # CardConnector the controller still references from before the
        # install. The pre-refactor flow bounced back to a generic menu
        # that re-probed via `run_card_gate`, which implicitly cleaned
        # this up; the direct-to-setup routing below skips that, so reset
        # the PC/SC state explicitly here.
        seedkeeper_utils.disconnect_smartcard_connections(self.controller)

        self.run_screen(
            LargeIconStatusScreen,
            title="Install",
            status_headline=None,
            text=f"{self.kind.capitalize()} applet installed.\nSet a device PIN to continue.",
            show_back_button=False,
            button_data=[ButtonOption("Set up")],
        )
        # Jump straight into the per-applet setup wizard — once the user
        # has just installed the applet, the obvious next step is PIN
        # setup. Skipping the menu hop also avoids the extra probe.
        if self.kind == "keycard":
            from seedsigner.views.keycard_views import ToolsKeycardInitView
            return Destination(ToolsKeycardInitView, skip_current_view=True)
        if self.kind == "satochip":
            from seedsigner.views.tools_views import ToolsSatochipSetupView
            return Destination(ToolsSatochipSetupView, skip_current_view=True)
        if self.kind == "seedkeeper":
            from seedsigner.views.tools_views import ToolsSeedkeeperSetupView
            return Destination(ToolsSeedkeeperSetupView, skip_current_view=True)
        return Destination(CardsMenuView, skip_current_view=True)


def _show_warning(view, title, text):
    from seedsigner.gui.screens.screen import WarningScreen
    view.run_screen(
        WarningScreen,
        title=title,
        status_headline=None,
        text=text,
        show_back_button=True,
    )
    return Destination(BackStackView)


class CardsFactoryResetView(View):
    """Wipe every applet on the inserted card.

    Tries GlobalPlatform first with the default ISD keys: opens an SCP02
    session, enumerates every applet AID via ``list_instances``, and
    issues ``delete_aid`` for each. If the SCP02 handshake fails because
    the ISD keys have been rotated, falls back to per-applet soft
    resets:

    - Keycard: cleartext ``FACTORY_RESET`` APDU wipes PIN / PUK / master
      key (applet stays loaded; data is gone).
    - Satochip / SeedKeeper: cannot be removed without ISD keys; surface
      a clear notice so the user knows the limit.
    """

    def run(self):
        from seedsigner.gui.screens.screen import (
            ButtonListScreen, DireWarningScreen, LargeIconStatusScreen,
        )
        from seedsigner.helpers.card_probe import probe_installed_applets

        ret = self.run_screen(
            DireWarningScreen,
            title=_("Factory reset"),
            status_headline=None,
            text=_("Wipe every applet on this card?"),
            show_back_button=True,
            button_data=[ButtonOption("Wipe")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        report_lines = _attempt_globalplatform_wipe(self)
        if report_lines is None:
            # GP path failed (likely rotated ISD keys); fall back to
            # per-applet soft reset.
            report_lines = _attempt_soft_reset(self, probe_installed_applets(self.controller))

        self.run_screen(
            LargeIconStatusScreen,
            title=_("Factory reset"),
            status_headline=None,
            text="\n".join(report_lines),
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        return Destination(CardsMenuView, skip_current_view=True)


def _attempt_globalplatform_wipe(view):
    """Returns a list of result lines, or None if the GP delete path
    failed entirely (caller should fall back to soft reset).

    Probes which of our three supported applets are present via
    cleartext SELECT (``probe_installed_applets``), then shells out to
    ``gp.jar --delete <AID> -force`` per kind — exactly the same command
    the per-applet Uninstall views use (see e.g.
    ``ToolsSeedkeeperUninstallAppletView``), which the user has verified
    works for SeedKeeper. We deliberately do NOT open a Python SCP02
    channel before gp.jar: every previous attempt to do so left the
    card in a state where gp.jar's DELETE returned SW=0x6985
    ("Could not delete X. Some app still active?"), even though the
    same gp.jar invocation succeeds from a cold start.

    For Keycard we pass the 7-byte package AID so a single
    ``--delete -force`` wipes the whole multi-instance package.
    """
    try:
        from seedsigner.helpers import seedkeeper_utils
        from seedsigner.helpers.card_probe import probe_installed_applets
    except ImportError as exc:
        return ["GlobalPlatform stack missing:", str(exc)]

    state = probe_installed_applets(view.controller)
    if not state.present:
        return ["No card detected."]

    # Each entry: (display name, AID hex passed to ``gp.jar --delete``).
    targets: list[tuple[str, str]] = []
    if state.seedkeeper_installed:
        targets.append(("SeedKeeper", "536565644b6565706572"))
    if state.satochip_installed:
        targets.append(("Satochip", "5361746f43686970"))
    if state.keycard_installed:
        # Package AID — deletes the load file + all 3 instances in one shot.
        targets.append(("Keycard", "A0000008040001"))

    if not targets:
        return ["No applets to delete."]

    deleted: list[str] = []
    skipped: list[str] = []
    for name, aid_hex in targets:
        result = seedkeeper_utils.run_globalplatform(
            view, f"--delete {aid_hex} -force",
            f"Deleting {name}", None,
        )
        if result is None:
            skipped.append(name)
        else:
            deleted.append(name)

    # If none of the gp.jar deletes succeeded, this is most likely an
    # ISD-keys-rotated card. Surface as None so the caller falls back
    # to the per-applet soft-reset path.
    if not deleted and skipped:
        return None

    report: list[str] = []
    if deleted:
        report.append(f"Deleted: {', '.join(deleted)}.")
    if skipped:
        report.append(f"Skipped: {', '.join(skipped)}.")
    return report


def _attempt_soft_reset(view, state):
    """Per-applet wipe when GlobalPlatform is unavailable.

    Currently only Keycard has a cleartext self-wipe path. Satochip and
    SeedKeeper would need their PINs to drive a meaningful reset, which
    we don't want to gate the operation on — instead we report that the
    user must wipe those from a PC.
    """
    report = ["ISD keys rotated."]

    if state.keycard_installed:
        try:
            from seedsigner.helpers.keycard.client import KeycardClient
            from seedsigner.helpers.keycard.commands import factory_reset
            from seedsigner.helpers.keycard.reader import (
                release_other_smartcard_holders, wait_for_card,
            )
            release_other_smartcard_holders(view.controller)
            connection = wait_for_card(timeout_s=2.0)
            try:
                client = KeycardClient(connection)
                client.transmit(factory_reset())
                report.append("Keycard data wiped.")
            finally:
                try:
                    connection.disconnect()
                except Exception:
                    pass
        except Exception as exc:
            report.append(f"Keycard wipe failed: {exc}")
    else:
        report.append("Keycard: not installed.")

    if state.satochip_installed or state.seedkeeper_installed:
        report.append("Satochip / SeedKeeper: wipe from PC.")
    return report



class PowerOptionsView(View):
    RESET = ButtonOption("Restart", SeedSignerIconConstants.RESTART)
    POWER_OFF = ButtonOption("Power Off", SeedSignerIconConstants.POWER)

    def run(self):
        button_data = [self.RESET, self.POWER_OFF]
        selected_menu_num = self.run_screen(
            LargeButtonScreen,
            title=_("Reset / Power"),
            show_back_button=True,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        elif button_data[selected_menu_num] == self.RESET:
            return Destination(RestartView)
        
        elif button_data[selected_menu_num] == self.POWER_OFF:
            return Destination(PowerOffView)



class RestartView(View):
    def run(self):
        from seedsigner.gui.screens.screen import ResetScreen
        # Ensure any pending background settings save completes before restart.
        Settings.get_instance().flush_save()
        thread = RestartView.DoResetThread()
        thread.start()
        try:
            self.run_screen(ResetScreen)
        except Exception:
            # Stop the reset thread if the screen exits abnormally (e.g.
            # ScreenshotComplete during screenshot generation).  Broad catch
            # is intentional: whatever caused the exit, we must prevent the
            # background thread from killing the process.
            thread.stop()
            raise


    class DoResetThread(BaseThread):
        def run(self):
            import os
            import shlex
            import sys
            import time
            from subprocess import call

            # Give the screen just enough time to display the reset message before
            # exiting.
            time.sleep(0.25)

            if not self.keep_running:
                return

            # Kill the current process by its PID (reliable across all
            # Python binary names).  The shell subprocess survives the
            # parent being killed and can then start the new process.
            pid = os.getpid()
            if Settings.HOSTNAME == Settings.SEEDSIGNER_OS:
                python = shlex.quote(sys.executable)
                call(f"kill {pid}; exec {python} /opt/src/main.py", shell=True)
            else:
                call(f"kill {pid}", shell=True)



class PowerOffView(View):
    def run(self):
        from seedsigner.gui.screens.screen import PowerOffNotRequiredScreen
        from seedsigner.hardware.buttons import USING_GPIO
        import os
        import sys

        # Ensure any pending background settings save completes before power-off.
        Settings.get_instance().flush_save()

        if not USING_GPIO:
            if "PYTEST_CURRENT_TEST" not in os.environ:
                # In desktop mode, exiting the program is the safest way to "power off"
                sys.exit(0)
            return Destination(BackStackView)

        self.run_screen(PowerOffNotRequiredScreen)
        return Destination(BackStackView)



@dataclass
class NotYetImplementedView(View):
    """
        Temporary View to use during dev.
    """
    text: str = _mft("This is still on our to-do list!")


    def run(self):
        self.run_screen(
            WarningScreen,
            title=_("Work In Progress"),
            status_headline=_("Not Yet Implemented"),
            text=self.text,
            button_data=[ButtonOption("Back to Main Menu")],
        )

        return Destination(MainMenuView)



@dataclass
class ErrorView(View):
    title: str = _mft("Error")
    show_back_button: bool = True
    status_icon_name: str = SeedSignerIconConstants.ERROR
    status_headline: str = None
    text: str = None
    button_text: str = None
    next_destination: Destination = None

    def run(self):
        self.run_screen(
            ErrorScreen,
            title=self.title,
            status_icon_name=self.status_icon_name,
            status_headline=self.status_headline,
            text=self.text,
            button_data=[ButtonOption(self.button_text)],
            show_back_button=self.show_back_button,
        )
        return self.next_destination if self.next_destination else Destination(MainMenuView, clear_history=True)



@dataclass
class NetworkMismatchErrorView(ErrorView):
    derivation_path: str = None

    def __post_init__(self):
        from seedsigner.views.settings_views import SettingsEntryUpdateSelectionView

        # TRANSLATOR_NOTE: The network setting (mainnet/testnet/regtest) doesn't match the provided derivation path
        self.title = _("Network Mismatch")
        self.status_icon_name = SeedSignerIconConstants.WARNING
        self.show_back_button = False

        # TRANSLATOR_NOTE: Button option to alter a setting
        self.button_text = _("Change Setting")
        self.next_destination = Destination(SettingsEntryUpdateSelectionView, view_args=dict(attr_name=SettingsConstants.SETTING__NETWORK), clear_history=True)
        super().__post_init__()

        # TRANSLATOR_NOTE: Inserts mainnet/testnet/regtest and derivation path
        self.text = _("Current network setting ({}) doesn't match {}.").format(
            self.settings.get_value_display_name(SettingsConstants.SETTING__NETWORK),
            self.derivation_path,
        )



@dataclass
class UnhandledExceptionView(View):
    error: list[str]

    def run(self):
        self.run_screen(
            ErrorScreen,
            title=_("System Error"),
            status_headline=self.error[0],
            text=self.error[1] + "\n" + self.error[2],
            allow_text_overflow=True,  # Fit what we can, let the rest go off the edges
        )
        
        return Destination(MainMenuView, clear_history=True)



@dataclass
class OptionDisabledView(View):
    UPDATE_SETTING = ButtonOption("Update Setting")
    DONE = ButtonOption("Done")
    settings_attr: str

    def __post_init__(self):
        super().__post_init__()
        self.settings_entry = SettingsDefinition.get_settings_entry(self.settings_attr)

        # TRANSLATOR_NOTE: Inserts the name of a settings option (e.g. "Persistent Settings" is currently...)
        self.error_msg = _("\"{}\" is currently disabled in Settings.").format(
            _(self.settings_entry.display_name),
        )


    def run(self):
        button_data = [self.UPDATE_SETTING, self.DONE]
        selected_menu_num = self.run_screen(
            WarningScreen,
            title=_("Option Disabled"),
            status_headline=None,
            text=self.error_msg,
            button_data=button_data,
            show_back_button=False,
            allow_text_overflow=True,  # Fit what we can, let the rest go off the edges
        )

        if button_data[selected_menu_num] == self.UPDATE_SETTING:
            from seedsigner.views.settings_views import SettingsEntryUpdateSelectionView
            return Destination(SettingsEntryUpdateSelectionView, view_args=dict(attr_name=self.settings_attr), clear_history=True)
        else:
            return Destination(MainMenuView, clear_history=True)
