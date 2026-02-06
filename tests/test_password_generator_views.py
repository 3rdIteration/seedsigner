from seedsigner.views import tools_views


def _make_roll_count_view(password_type: str, entropy_source: str):
    view = object.__new__(tools_views.ToolsPasswordDiceRollCountView)
    view.password_type = password_type
    view.strength_bits = 64
    view.random_options = {}
    view.word_separator = tools_views.PASSWORD_WORD_SEPARATOR_NONE
    view.entropy_source = entropy_source
    return view


def test_dice_roll_count_view_skips_itself_for_dice_entry():
    view = _make_roll_count_view(
        tools_views.PASSWORD_TYPE_DICEWARE_EFF_SHORT,
        tools_views.PASSWORD_ENTROPY_DICE,
    )

    dest = tools_views.ToolsPasswordDiceRollCountView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordDiceEntryView
    assert dest.skip_current_view is True


def test_dice_roll_count_view_skips_itself_for_camera_diceware():
    view = _make_roll_count_view(
        tools_views.PASSWORD_TYPE_DICEWARE_EFF_SHORT,
        tools_views.PASSWORD_ENTROPY_CAMERA,
    )

    dest = tools_views.ToolsPasswordDiceRollCountView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordGenerateView
    assert dest.skip_current_view is True
