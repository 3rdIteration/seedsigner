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


def test_password_generate_view_skips_itself_for_review_destination():
    view = object.__new__(tools_views.ToolsPasswordGenerateView)
    view.password_type = tools_views.PASSWORD_TYPE_HEX
    view.entropy_source = tools_views.PASSWORD_ENTROPY_BIP85
    view.strength_bits = 64
    view.random_options = {}
    view.roll_data = b"\x01" * 32
    view.roll_count = 0
    view.word_count = None
    view.word_separator = tools_views.PASSWORD_WORD_SEPARATOR_NONE

    dest = tools_views.ToolsPasswordGenerateView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordReviewView
    assert dest.skip_current_view is True
