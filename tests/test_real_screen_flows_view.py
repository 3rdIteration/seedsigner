"""
    Real-screen flow tests for the top-level views: the power menu, the error
    interstitials, and the testing-build Home screen.

    Two of these had no coverage at all. `RebootToLoaderView` ("Reboot to flash mode")
    is never reached by any existing test, and neither is the testing-build variant of
    MainMenuView -- when is_testing_build_enabled() is set, Home swaps its four buttons
    for I/O Test / Test Smartcard / Flash Applet / Settings, and no test has ever turned
    that flag on, so three buttons and their routing were unwalked.

    The restart and reboot views spawn threads that kill the process or drive a ctypes
    reboot. Both already short-circuit when the renderer reports it is the screenshot
    generator, which is the seam these tests use rather than patching the threads out.
"""

from unittest.mock import patch

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import FlowStep, FlowTest
from ui_driver import UISession, select

from seedsigner.gui.screens.screen import RET_CODE__POWER_BUTTON
from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.views import settings_views
from seedsigner.views.view import (
    MainMenuView,
    NotYetImplementedView,
    OptionDisabledView,
    PowerOffView,
    PowerOptionsView,
    RebootToLoaderView,
    RestartView,
)


class TestPowerOptionsFlow(FlowTest):
    """The power menu, driven on real Screens."""

    def test_power_off(self):
        session = UISession(script=select(PowerOptionsView.POWER_OFF))

        self.run_sequence(
            [
                FlowStep(MainMenuView, screen_return_value=RET_CODE__POWER_BUTTON),
                FlowStep(PowerOptionsView, real_screens=True),
                FlowStep(PowerOffView),  # returns BackStackView
                FlowStep(PowerOptionsView),
            ],
            ui_session=session,
        )
        assert session.renderer.frames, "the real power screens never rendered"

    def test_restart(self):
        session = UISession(script=select(PowerOptionsView.RESET))
        # RestartView short-circuits its process-killing thread when the renderer says
        # it is the screenshot generator -- the same seam, rather than patching the
        # thread out and testing something the device never runs.
        session.renderer.is_screenshot_generator = True

        self.run_sequence(
            [
                FlowStep(MainMenuView, screen_return_value=RET_CODE__POWER_BUTTON),
                FlowStep(PowerOptionsView, real_screens=True),
                FlowStep(RestartView, real_screens=True),
            ],
            ui_session=session,
        )

    def test_reboot_to_flash_mode_on_luckfox(self):
        """
        "Reboot to flash mode" only appears on the Luckfox profiles, and had no test at
        all -- so neither the extra button nor the third-option layout switch (three
        options fall back from LargeButtonScreen to ButtonListScreen) was ever
        exercised.
        """
        session = UISession(script=select(PowerOptionsView.REBOOT_LOADER))
        session.renderer.is_screenshot_generator = True

        with patch.object(Settings, "RUNTIME_PROFILE", PowerOptionsView.LUCKFOX_PROFILES[0]):
            self.run_sequence(
                [
                    FlowStep(MainMenuView, screen_return_value=RET_CODE__POWER_BUTTON),
                    FlowStep(PowerOptionsView, real_screens=True),
                    FlowStep(RebootToLoaderView, real_screens=True),
                ],
                ui_session=session,
            )

    def test_flash_mode_is_hidden_off_luckfox(self):
        """The same menu on a non-Luckfox profile must not offer it."""
        captured = {}

        def capture(view):
            original = view.run_screen

            def spy(screen_cls, **kwargs):
                captured["button_data"] = kwargs.get("button_data")
                return original(screen_cls, **kwargs)

            view.run_screen = spy

        with patch.object(Settings, "RUNTIME_PROFILE", "pi_zero"):
            self.run_sequence([
                FlowStep(MainMenuView, screen_return_value=RET_CODE__POWER_BUTTON),
                FlowStep(PowerOptionsView, before_run=capture,
                         button_data_selection=PowerOptionsView.POWER_OFF),
                FlowStep(PowerOffView),
                FlowStep(PowerOptionsView),
            ])

        assert PowerOptionsView.REBOOT_LOADER not in captured["button_data"]



class TestTestingBuildMainMenu(FlowTest):
    """
    Home swaps its whole button set on a testing build
    (`is_testing_build_enabled()`, view.py). No test has ever enabled it, so the
    I/O Test / Test Smartcard / Flash Applet branch was never walked.
    """

    def test_testing_build_swaps_the_home_buttons(self, monkeypatch):
        monkeypatch.setenv("SEEDSIGNER_TESTING_BUILD", "1")

        captured = {}

        def capture(view):
            original = view.run_screen

            def spy(screen_cls, **kwargs):
                captured["button_data"] = kwargs.get("button_data")
                captured["title"] = kwargs.get("title")
                return original(screen_cls, **kwargs)

            view.run_screen = spy

        self.run_sequence([
            FlowStep(MainMenuView, before_run=capture,
                     button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView),
        ])

        assert captured["button_data"] == [
            MainMenuView.IO_TEST,
            MainMenuView.TEST_SMARTCARD,
            MainMenuView.FLASH_APPLET,
            MainMenuView.SETTINGS,
        ]
        assert MainMenuView.SCAN not in captured["button_data"]

    def test_normal_build_shows_the_usual_home(self):
        captured = {}

        def capture(view):
            original = view.run_screen

            def spy(screen_cls, **kwargs):
                captured["button_data"] = kwargs.get("button_data")
                return original(screen_cls, **kwargs)

            view.run_screen = spy

        self.run_sequence([
            FlowStep(MainMenuView, before_run=capture,
                     button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView),
        ])

        assert MainMenuView.IO_TEST not in captured["button_data"]
        assert MainMenuView.SCAN in captured["button_data"]



class TestErrorInterstitials(FlowTest):
    """The shared error/notice screens, rendered for real."""

    def test_not_yet_implemented(self):
        session = UISession(script=select(0))

        self.run_sequence(
            [
                FlowStep(NotYetImplementedView, real_screens=True),
                FlowStep(MainMenuView),
            ],
            ui_session=session,
        )

    def test_option_disabled_offers_the_setting(self):
        """
        OptionDisabledView routes the user to the setting that blocked them, which is
        the branch worth checking renders and routes.
        """
        session = UISession(script=select(OptionDisabledView.UPDATE_SETTING))

        self.run_sequence(
            [
                FlowStep(
                    OptionDisabledView,
                    real_screens=True,
                ),
            ],
            initial_destination_view_args=dict(
                settings_attr=SettingsConstants.SETTING__MESSAGE_SIGNING
            ),
            ui_session=session,
        )
