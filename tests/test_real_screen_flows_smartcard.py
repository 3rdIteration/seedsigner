"""
    Real-screen flow tests for Smartcard Tools.

    smartcard_views.py is 61 View classes and 33 of them were never named in any test.
    The only operational coverage that existed is tests/test_flows_smartcard_hardware.py,
    which **skips unless a physical reader and card are present** and covers just
    SeedKeeper-save and Satochip-import; everything else was menu-entry-and-BACK in the
    mocked navigation suite.

    These need no hardware. Card-backed views go through the one seam every flow uses --
    `seedkeeper_utils.init_satochip` -- so the stand-in can later be swapped for a
    jcardsim-backed simulator running the real applets without touching these tests.

    Views here that need no card at all are covered directly: the per-applet 'Card Settings'
    submenus (they just build a ButtonListScreen) and ToolsDIYMountStatusView (it reads a log
    file).
"""

from unittest.mock import patch

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import FlowStep, FlowTest
from real_screen_fixtures import javacard_diy_patchers, satochip_connector
from ui_driver import Back, UISession, select

# tools_views must be imported first: it is a facade that star-imports smartcard_views.
from seedsigner.views import tools_views
from seedsigner.views import smartcard_views
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import MainMenuView


class SmartcardFlowTest(FlowTest):

    def setup_method(self):
        super().setup_method()
        # Each card type is behind its own setting; the menu omits any that are off.
        for setting in (
            SettingsConstants.SETTING__SMARTCARD_SUPPORT,
            SettingsConstants.SETTING__SATOCHIP_SUPPORT,
            SettingsConstants.SETTING__KEYCARD_SUPPORT,
            SettingsConstants.SETTING__SPECTER_DIY_SUPPORT,
        ):
            self.settings.set_value(setting, SettingsConstants.OPTION__ENABLED)

    def smartcard_steps(self) -> list:
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
        ]



class TestSmartcardMenuNavigation(SmartcardFlowTest):
    """
    Every top-level smartcard submenu, opened for real and backed out of. A screen that
    cannot construct shows up here rather than on a device with a card in it.
    """

    @pytest.mark.parametrize(
        "menu_option, submenu_view",
        [
            (smartcard_views.ToolsSmartcardMenuView.SATOCHIP, smartcard_views.ToolsSatochipView),
            (smartcard_views.ToolsSmartcardMenuView.KEYCARD, smartcard_views.ToolsKeycardView),
            (smartcard_views.ToolsSmartcardMenuView.SEEDKEEPER, smartcard_views.ToolsSeedkeeperView),
            (smartcard_views.ToolsSmartcardMenuView.SATODIME, smartcard_views.ToolsSatodimeView),
            (smartcard_views.ToolsSmartcardMenuView.SPECTER_DIY, smartcard_views.ToolsSpecterDIYView),
            (smartcard_views.ToolsSmartcardMenuView.Satochip_DIY, smartcard_views.ToolsSatochipDIYView),
        ],
    )
    def test_submenu_opens_and_backs_out(self, menu_option, submenu_view):
        session = UISession(script=select(menu_option) + [Back()])

        self.run_sequence(
            self.smartcard_steps() + [
                FlowStep(smartcard_views.ToolsSmartcardMenuView, real_screens=True),
                FlowStep(submenu_view, real_screens=True),
                FlowStep(smartcard_views.ToolsSmartcardMenuView),
            ],
            ui_session=session,
        )

    @pytest.mark.parametrize(
        "parent_option, parent_view, advanced_view",
        [
            (
                smartcard_views.ToolsSmartcardMenuView.SATOCHIP,
                smartcard_views.ToolsSatochipView,
                smartcard_views.ToolsSatochipAdvancedView,
            ),
            (
                smartcard_views.ToolsSmartcardMenuView.KEYCARD,
                smartcard_views.ToolsKeycardView,
                smartcard_views.ToolsKeycardAdvancedView,
            ),
        ],
    )
    def test_advanced_submenu_opens_and_backs_out(self, parent_option, parent_view, advanced_view):
        session = UISession(script=(
            select(parent_option)
            + select(parent_view.ADVANCED)
            + [Back()]
        ))

        self.run_sequence(
            self.smartcard_steps() + [
                FlowStep(smartcard_views.ToolsSmartcardMenuView, real_screens=True),
                FlowStep(parent_view, real_screens=True),
                FlowStep(advanced_view, real_screens=True),
                FlowStep(parent_view),
            ],
            ui_session=session,
        )



class TestCardSettingsSubmenus(SmartcardFlowTest):
    """
    Each applet's 'Card Settings' submenu opens for real and backs out. These host the
    functions that used to live under the removed Common Functions menu, so they must
    still construct (a ButtonListScreen with the shared-view options) without a card.
    """

    @pytest.mark.parametrize(
        "menu_option, parent_view, settings_view",
        [
            (
                smartcard_views.ToolsSmartcardMenuView.SATOCHIP,
                smartcard_views.ToolsSatochipView,
                smartcard_views.ToolsSatochipCardSettingsView,
            ),
            (
                smartcard_views.ToolsSmartcardMenuView.SEEDKEEPER,
                smartcard_views.ToolsSeedkeeperView,
                smartcard_views.ToolsSeedkeeperCardSettingsView,
            ),
            (
                smartcard_views.ToolsSmartcardMenuView.SATODIME,
                smartcard_views.ToolsSatodimeView,
                smartcard_views.ToolsSatodimeCardSettingsView,
            ),
        ],
    )
    def test_card_settings_opens_and_backs_out(self, menu_option, parent_view, settings_view):
        session = UISession(script=(
            select(menu_option)
            + select(parent_view.CARD_SETTINGS)
            + [Back()]
        ))

        self.run_sequence(
            self.smartcard_steps() + [
                FlowStep(smartcard_views.ToolsSmartcardMenuView, real_screens=True),
                FlowStep(parent_view, real_screens=True),
                FlowStep(settings_view, real_screens=True),
                FlowStep(parent_view),
            ],
            ui_session=session,
        )



class TestDIYMountStatusFlow(SmartcardFlowTest):
    """DIY Tools > Mount Status reads a log file, not a card."""

    def test_mount_status_renders(self, tmp_path):
        log = tmp_path / "diy-mount.log"
        log.write_text("mount ok\n", encoding="utf-8")

        session = UISession(script=(
            select(smartcard_views.ToolsSmartcardMenuView.Satochip_DIY)
            + select(smartcard_views.ToolsSatochipDIYView.MOUNT_STATUS)
            + select(0)
        ))

        with patch.object(smartcard_views, "DIY_MOUNT_LOG", str(log), create=True):
            self.run_sequence(
                self.smartcard_steps() + [
                    FlowStep(smartcard_views.ToolsSmartcardMenuView, real_screens=True),
                    FlowStep(smartcard_views.ToolsSatochipDIYView, real_screens=True),
                    FlowStep(smartcard_views.ToolsDIYMountStatusView, real_screens=True),
                    FlowStep(smartcard_views.ToolsSatochipDIYView),
                ],
                ui_session=session,
            )



class TestJavacardKeysFlow(SmartcardFlowTest):
    """
    DIY Tools > Card Keys. ToolsJavacardKeysView and its five children were all
    unnamed in any test; the pygp stand-in lets the menu run without a card.
    """

    def test_keys_menu_opens_and_backs_out(self):
        session = UISession(script=(
            select(smartcard_views.ToolsSmartcardMenuView.Satochip_DIY)
            + select(smartcard_views.ToolsSatochipDIYView.MANAGE_KEYS)
            + [Back()]
        ))

        patchers = javacard_diy_patchers()
        for p in patchers:
            p.start()
        try:
            self.run_sequence(
                self.smartcard_steps() + [
                    FlowStep(smartcard_views.ToolsSmartcardMenuView, real_screens=True),
                    FlowStep(smartcard_views.ToolsSatochipDIYView, real_screens=True),
                    FlowStep(smartcard_views.ToolsJavacardKeysView, real_screens=True),
                    FlowStep(smartcard_views.ToolsSatochipDIYView),
                ],
                ui_session=session,
            )
        finally:
            for p in reversed(patchers):
                p.stop()
