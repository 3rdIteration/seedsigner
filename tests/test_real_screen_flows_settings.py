"""
    Real-screen flow tests for Settings.

    tests/test_flows_settings.py and the all-entries loops in
    tests/test_flows_menu_navigation.py walk these views thoroughly, but mocked. Three
    of the most interesting ones are *explicitly skipped* by those loops because they
    do not behave like a plain toggle: SettingsEntryUpdateSelectionView's multiselect
    checkboxes, SettingPBKDF2IterationsView's keyboard, and LocaleSelectionView. Those
    are exactly the ones whose Screens have custom Button classes and custom input
    handling, so mocked coverage says the least about them.

    Here they run for real. Left alone deliberately: IOTestView (a GPIO input loop),
    SCARDTestView / NFCTestView (card reader and libnfc), and RestartPCSCView (os.system
    on the pcscd service) -- none of those are button-driven UI.
"""

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import FlowStep, FlowTest
from ui_driver import Back, UISession, TypeKeys, select

from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.models.settings_definition import SettingsDefinition
from seedsigner.views import settings_views
from seedsigner.views.view import MainMenuView


class SettingsFlowTest(FlowTest):

    def entry_label(self, attr_name: str) -> str:
        """The button label Settings shows for a settings attribute."""
        return SettingsDefinition.get_settings_entry(attr_name).display_name

    def advanced_steps(self) -> list:
        """
        FlowSteps from the main menu into the Advanced settings list.

        SettingsMenuView re-enters itself with a different `visibility`, so Advanced is
        the same View class a second time rather than a distinct one.
        """
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView, real_screens=True),
            FlowStep(settings_views.SettingsMenuView, real_screens=True),
        ]

    def advanced_script(self, attr: str) -> list:
        """Open Advanced, then the editor for `attr`."""
        return select(settings_views.SettingsMenuView.ADVANCED) + select(self.entry_label(attr))



class TestSettingsEntryUpdate(SettingsFlowTest):
    """The settings editor itself -- the view every settings change goes through."""

    def test_toggle_an_enabled_disabled_setting(self):
        attr = SettingsConstants.SETTING__DIRE_WARNINGS
        self.settings.set_value(attr, SettingsConstants.OPTION__ENABLED)

        session = UISession(script=(
            self.advanced_script(attr)
            + select("Disabled")
            + [Back()]  # a *changed* single-select re-enters the editor; BACK exits
        ))

        self.run_sequence(
            self.advanced_steps() + [
                FlowStep(settings_views.SettingsEntryUpdateSelectionView, real_screens=True),
                FlowStep(settings_views.SettingsEntryUpdateSelectionView, real_screens=True),
                FlowStep(settings_views.SettingsMenuView),
            ],
            ui_session=session,
        )

        assert self.settings.get_value(attr) == SettingsConstants.OPTION__DISABLED

    def test_multiselect_checkbox_toggles(self):
        """
        A multiselect entry uses CheckboxButton and re-enters itself after each
        selection, so the screen is rebuilt with updated `checked_buttons` every time.
        Deselect one script type and confirm it really left the stored list.
        """
        attr = SettingsConstants.SETTING__SCRIPT_TYPES
        entry = SettingsDefinition.get_settings_entry(attr)
        assert entry.type == SettingsConstants.TYPE__MULTISELECT

        self.settings.set_value(
            attr, [SettingsConstants.NATIVE_SEGWIT, SettingsConstants.NESTED_SEGWIT]
        )
        nested_label = dict(SettingsConstants.ALL_SCRIPT_TYPES)[SettingsConstants.NESTED_SEGWIT]

        session = UISession(script=(
            self.advanced_script(attr)
            + select(nested_label)  # untick it
            + [Back()]              # the editor re-enters itself after each toggle
        ))

        self.run_sequence(
            self.advanced_steps() + [
                FlowStep(settings_views.SettingsEntryUpdateSelectionView, real_screens=True),
                FlowStep(settings_views.SettingsEntryUpdateSelectionView, real_screens=True),
                FlowStep(settings_views.SettingsMenuView),
            ],
            ui_session=session,
        )

        remaining = self.settings.get_value(attr)
        assert SettingsConstants.NESTED_SEGWIT not in remaining
        assert SettingsConstants.NATIVE_SEGWIT in remaining

    def test_emptying_a_required_multiselect_warns(self):
        """
        Deselecting the last option of a required multiselect must reach
        SettingsSelectionRequiredWarningView rather than storing an empty list.
        """
        attr = SettingsConstants.SETTING__SCRIPT_TYPES
        self.settings.set_value(attr, [SettingsConstants.NATIVE_SEGWIT])
        only_label = dict(SettingsConstants.ALL_SCRIPT_TYPES)[SettingsConstants.NATIVE_SEGWIT]

        session = UISession(script=(
            self.advanced_script(attr)
            + select(only_label)  # untick the only remaining option
            + [Back()]            # BACK on an empty required list triggers the warning
            + select(0)           # "Return to setting"
            + select(only_label)  # tick it again so the setting is left usable
            + [Back()]
        ))

        self.run_sequence(
            self.advanced_steps() + [
                FlowStep(settings_views.SettingsEntryUpdateSelectionView, real_screens=True),
                FlowStep(settings_views.SettingsEntryUpdateSelectionView, real_screens=True),
                FlowStep(settings_views.SettingsSelectionRequiredWarningView, real_screens=True),
                FlowStep(settings_views.SettingsEntryUpdateSelectionView, real_screens=True),
                FlowStep(settings_views.SettingsEntryUpdateSelectionView, real_screens=True),
                FlowStep(settings_views.SettingsMenuView),
            ],
            ui_session=session,
        )

        assert self.settings.get_value(attr), "a required multiselect must not end up empty"



class TestPBKDF2IterationsSetting(SettingsFlowTest):
    """
    SettingPBKDF2IterationsView is a KeyboardScreen, not a list -- one of the entries
    the mocked all-entries loops skip.
    """

    def test_type_a_new_iteration_count(self):
        attr = SettingsConstants.SETTING__ENCRYPTION_ITER
        # The screen stores units of 10k and rejects anything outside 1..50, and it
        # comes up pre-filled with the current value -- hence clear_first.
        new_value = "12"

        session = UISession(script=(
            self.advanced_script(attr)
            + [TypeKeys(new_value, clear_first=True)]
        ))

        self.run_sequence(
            self.advanced_steps() + [
                FlowStep(settings_views.SettingPBKDF2IterationsView, real_screens=True),
                FlowStep(settings_views.SettingsMenuView),
            ],
            ui_session=session,
        )

        assert str(self.settings.get_value(attr)) == new_value



class TestLocaleSelection(SettingsFlowTest):
    """LocaleSelectionView -- the other entry the mocked loops skip."""

    def test_locale_list_renders_and_selects(self):
        attr = SettingsConstants.SETTING__LOCALE
        original = self.settings.get_value(attr)
        display_name = dict(SettingsConstants.ALL_LOCALES)[original]

        session = UISession(script=(
            select(self.entry_label(attr))
            + select(display_name)  # re-pick the current locale: no translation reload
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
                FlowStep(settings_views.SettingsMenuView, real_screens=True),
                FlowStep(settings_views.LocaleSelectionView, real_screens=True),
                FlowStep(settings_views.SettingsMenuView),
            ],
            ui_session=session,
        )

        assert self.settings.get_value(attr) == original



class TestSettingsInfoScreens(SettingsFlowTest):
    """
    The read-only screens under Settings. Several are plain BaseTopNavScreens with no
    button list, so they are left by the back arrow -- which is what Back() is for.
    """

    def test_version_screen(self):
        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
                FlowStep(settings_views.SettingsMenuView, real_screens=True),
                FlowStep(settings_views.VersionView, real_screens=True),
                FlowStep(settings_views.SettingsMenuView),
            ],
            ui_session=UISession(script=select(settings_views.SettingsMenuView.VERSION) + [Back()]),
        )

    def test_donate_screen(self):
        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
                FlowStep(settings_views.SettingsMenuView, real_screens=True),
                FlowStep(settings_views.DonateView, real_screens=True),
                FlowStep(settings_views.SettingsMenuView),
            ],
            ui_session=UISession(script=select(settings_views.SettingsMenuView.DONATE) + [Back()]),
        )

    def test_system_and_memory_info(self):
        for option, view in (
            (settings_views.SettingsMenuView.SYSTEM_INFO, settings_views.SystemInfoView),
            (settings_views.SettingsMenuView.MEMORY_INFO, settings_views.MemoryInfoView),
        ):
            self.run_sequence(
                [
                    FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
                    FlowStep(settings_views.SettingsMenuView, real_screens=True),
                    FlowStep(settings_views.SettingsMenuView, real_screens=True),
                    FlowStep(view, real_screens=True),
                    FlowStep(settings_views.SettingsMenuView),
                ],
                ui_session=UISession(script=(
                    select(settings_views.SettingsMenuView.HARDWARE)
                    + select(option)
                    + [Back()]
                )),
            )

    def test_hardening_report_pages(self):
        """HardeningTestView renders a PagedTextScreen; walk it and back out."""
        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
                FlowStep(settings_views.SettingsMenuView, real_screens=True),
                FlowStep(settings_views.SettingsMenuView, real_screens=True),
                FlowStep(settings_views.HardeningTestView, real_screens=True),
                FlowStep(settings_views.SettingsMenuView),
            ],
            ui_session=UISession(script=(
                select(settings_views.SettingsMenuView.ADVANCED)
                + select(settings_views.SettingsMenuView.TEST_HARDENING)
                + [Back()]
            )),
        )

    def test_load_backup_files_submenu(self):
        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
                FlowStep(settings_views.SettingsMenuView, real_screens=True),
                FlowStep(settings_views.SettingsMenuView, real_screens=True),
                FlowStep(settings_views.LoadBackupFilesSettingsView, real_screens=True),
                FlowStep(settings_views.SettingsEntryUpdateSelectionView),
            ],
            ui_session=UISession(script=(
                select(settings_views.SettingsMenuView.ADVANCED)
                + select(settings_views.SettingsMenuView.LOAD_BACKUP_FILES)
                + select(0)
            )),
        )
