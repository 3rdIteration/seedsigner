from base import BaseTest

from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import tools_views


class TestSmartcardSupportToggles(BaseTest):
    def test_default_smartcard_backend_toggles_enabled(self):
        assert self.settings.get_value(SettingsConstants.SETTING__SATOCHIP_SUPPORT) == SettingsConstants.OPTION__ENABLED
        assert self.settings.get_value(SettingsConstants.SETTING__KEYCARD_SUPPORT) == SettingsConstants.OPTION__ENABLED

    def test_smartcard_menu_hides_keycard_when_disabled(self):
        self.settings.set_value(SettingsConstants.SETTING__KEYCARD_SUPPORT, SettingsConstants.OPTION__DISABLED)
        view = tools_views.ToolsSmartcardMenuView()

        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured["button_data"] = kwargs["button_data"]
            return 0

        view.run_screen = fake_run_screen
        view.run()

        assert tools_views.ToolsSmartcardMenuView.KEYCARD not in captured["button_data"]

    def test_smartcard_menu_hides_satochip_when_disabled(self):
        self.settings.set_value(SettingsConstants.SETTING__SATOCHIP_SUPPORT, SettingsConstants.OPTION__DISABLED)
        view = tools_views.ToolsSmartcardMenuView()

        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured["button_data"] = kwargs["button_data"]
            return 0

        view.run_screen = fake_run_screen
        view.run()

        assert tools_views.ToolsSmartcardMenuView.SATOCHIP not in captured["button_data"]