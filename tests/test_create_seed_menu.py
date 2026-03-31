from seedsigner.views import seed_views, tools_views


class _Settings:
    @staticmethod
    def get_value(key):
        if key == seed_views.SettingsConstants.SETTING__SEED_WORD_LENGTHS:
            return [12]
        return seed_views.SettingsConstants.OPTION__DISABLED


def test_create_seed_entry_hides_password_generator(monkeypatch):
    view = object.__new__(seed_views.LoadSeedView)
    view.settings = _Settings()

    captured = {}

    def fake_run_screen(self, *_args, **kwargs):
        button_data = kwargs["button_data"]
        captured["button_data"] = button_data
        return button_data.index(seed_views.LoadSeedView.CREATE)

    monkeypatch.setattr(seed_views.LoadSeedView, "run_screen", fake_run_screen)

    dest = seed_views.LoadSeedView.run(view)

    assert dest.View_cls is tools_views.ToolsMenuView
    assert dest.view_args == {"include_password_generator": False}


def test_tools_menu_hides_password_generator_when_disabled(monkeypatch):
    view = object.__new__(tools_views.ToolsMenuView)
    view.settings = _Settings()
    view.include_password_generator = False

    captured = {}

    def fake_run_screen(self, *_args, **kwargs):
        captured["button_data"] = kwargs["button_data"]
        return tools_views.RET_CODE__BACK_BUTTON

    monkeypatch.setattr(tools_views.ToolsMenuView, "run_screen", fake_run_screen)

    tools_views.ToolsMenuView.run(view)

    assert tools_views.ToolsMenuView.PASSWORD_GENERATOR not in captured["button_data"]
