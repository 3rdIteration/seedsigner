from base import BaseTest

from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import tools_views
from seedsigner.views.view import Destination


class TestToolsSmartcardKeycardMenu(BaseTest):
    def test_smartcard_menu_includes_keycard_entry(self):
        self.settings.set_value(
            SettingsConstants.SETTING__KEYCARD_SUPPORT,
            SettingsConstants.OPTION__ENABLED,
        )
        view = tools_views.ToolsSmartcardMenuView()

        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured["button_data"] = kwargs["button_data"]
            return 0

        view.run_screen = fake_run_screen
        destination = view.run()

        assert destination.View_cls == tools_views.ToolsCommonView
        assert tools_views.ToolsSmartcardMenuView.KEYCARD in captured["button_data"]

    def test_selecting_keycard_routes_to_keycard_view(self):
        self.settings.set_value(
            SettingsConstants.SETTING__KEYCARD_SUPPORT,
            SettingsConstants.OPTION__ENABLED,
        )
        view = tools_views.ToolsSmartcardMenuView()

        def fake_run_screen(screen_cls, **kwargs):
            return kwargs["button_data"].index(tools_views.ToolsSmartcardMenuView.KEYCARD)

        view.run_screen = fake_run_screen
        destination: Destination = view.run()

        assert destination.View_cls == tools_views.ToolsKeycardView
