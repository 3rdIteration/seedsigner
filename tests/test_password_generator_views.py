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


def test_diceware_eff_uses_fresh_entropy_seed(monkeypatch):
    view = object.__new__(tools_views.ToolsPasswordGenerateView)
    view.password_type = tools_views.PASSWORD_TYPE_DICEWARE_EFF_SHORT
    view.entropy_source = tools_views.PASSWORD_ENTROPY_HARDWARE_RNG
    view.strength_bits = 64
    view.random_options = {}
    view.roll_data = None
    view.roll_count = None
    view.word_count = 4
    view.word_separator = tools_views.PASSWORD_WORD_SEPARATOR_NONE

    captured = {}

    def fake_rolls(seed, sides, roll_count, base=1):
        captured["seed"] = seed
        captured["sides"] = sides
        captured["roll_count"] = roll_count
        return "1111222233334444"

    monkeypatch.setattr(tools_views.password_generation, "dice_rolls_from_seed", fake_rolls)
    monkeypatch.setattr(tools_views.diceware, "eff_short_map", lambda: {})
    monkeypatch.setattr(
        tools_views.diceware,
        "diceware_words_from_rolls",
        lambda rolls, _word_map, _roll_len: [rolls],
    )

    entropy_seed = b"fresh-entropy-seed"
    words = tools_views.ToolsPasswordGenerateView._diceware_words(view, entropy_bytes=entropy_seed)

    assert words == ["1111222233334444"]
    assert captured["seed"] == entropy_seed
    assert captured["sides"] == 6
    assert captured["roll_count"] == 16


def test_entropy_source_routes_diceware_dice_to_roll_entry(monkeypatch):
    view = object.__new__(tools_views.ToolsPasswordEntropySourceView)
    view.password_type = tools_views.PASSWORD_TYPE_DICEWARE_EFF_SHORT
    view.strength_bits = 64
    view.random_options = {}

    class C:
        pass

    view.controller = C()
    view.controller.hardware_rng_is_healthy = True
    view.controller.hardware_rng_failure_reason = None

    monkeypatch.setattr(
        tools_views.ToolsPasswordEntropySourceView,
        "run_screen",
        lambda self, *_args, **_kwargs: 1,
    )

    dest = tools_views.ToolsPasswordEntropySourceView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordDiceRollCountView


def test_separator_reuses_cached_entropy_without_recollect():
    view = object.__new__(tools_views.ToolsPasswordWordSeparatorView)
    view.password_type = tools_views.PASSWORD_TYPE_DICEWARE_EFF_SHORT
    view.strength_bits = 64
    view.random_options = {}
    view.entropy_source = tools_views.PASSWORD_ENTROPY_HARDWARE_RNG

    class C:
        pass

    view.controller = C()
    view.controller.password_generator_entropy_cache = {
        "password_type": tools_views.PASSWORD_TYPE_DICEWARE_EFF_SHORT,
        "strength_bits": 64,
        "entropy_source": tools_views.PASSWORD_ENTROPY_HARDWARE_RNG,
        "word_count": 4,
        "roll_data": None,
        "entropy_bytes": b"cached",
    }

    view.run_screen = lambda *_args, **_kwargs: 2

    dest = tools_views.ToolsPasswordWordSeparatorView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordGenerateView
    assert dest.skip_current_view is True
    assert dest.view_args["entropy_bytes_override"] == b"cached"
    assert dest.view_args["word_separator"] == tools_views.PASSWORD_WORD_SEPARATOR_SPACE


def test_dice_entry_routes_diceware_to_separator_and_caches(monkeypatch):
    view = object.__new__(tools_views.ToolsPasswordDiceEntryView)
    view.password_type = tools_views.PASSWORD_TYPE_DICEWARE_EFF_SHORT
    view.strength_bits = 64
    view.total_rolls = 16
    view.random_options = {}
    view.word_count = 4
    view.word_separator = tools_views.PASSWORD_WORD_SEPARATOR_NONE
    view.entropy_source = tools_views.PASSWORD_ENTROPY_DICE

    class C:
        pass

    view.controller = C()

    class FakeDiceEntryScreen:
        def __init__(self, *args, **kwargs):
            pass

        def display(self):
            return "1234123412341234"

    monkeypatch.setattr(tools_views, "ToolsDiceEntropyEntryScreen", FakeDiceEntryScreen)
    monkeypatch.setattr(tools_views.mnemonic_generation, "dice_entropy_is_sufficient", lambda _ret: True)

    dest = tools_views.ToolsPasswordDiceEntryView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordWordSeparatorView
    assert dest.skip_current_view is True
    assert view.controller.password_generator_entropy_cache["roll_data"] == "1234123412341234"


def test_separator_back_clears_cache_and_returns_entropy_source(monkeypatch):
    view = object.__new__(tools_views.ToolsPasswordWordSeparatorView)
    view.password_type = tools_views.PASSWORD_TYPE_DICEWARE_EFF_SHORT
    view.strength_bits = 64
    view.random_options = {}
    view.entropy_source = tools_views.PASSWORD_ENTROPY_DICE

    class C:
        pass

    view.controller = C()
    view.controller.password_generator_entropy_cache = {"dummy": 1}

    monkeypatch.setattr(
        tools_views.ToolsPasswordWordSeparatorView,
        "run_screen",
        lambda self, *_args, **_kwargs: tools_views.RET_CODE__BACK_BUTTON,
    )

    dest = tools_views.ToolsPasswordWordSeparatorView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordEntropySourceView
    assert view.controller.password_generator_entropy_cache is None
