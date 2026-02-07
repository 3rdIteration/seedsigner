import embit.bip32 as embit_bip32
import embit.bip85 as embit_bip85
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
    view.strength_bits = 128
    view.random_options = {}
    view.roll_data = b"\x01" * 64
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
    view.dice_sides = None
    view.roll_count = None

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


def test_dice_roll_count_view_prompts_for_sides_and_rolls(monkeypatch):
    view = _make_roll_count_view(
        tools_views.PASSWORD_TYPE_DICE_ROLLS,
        None,
    )

    class FakeRollCountScreen:
        def __init__(self, *args, **kwargs):
            pass

        def display(self):
            return "12"

    monkeypatch.setattr(
        tools_views.seed_screens,
        "SeedBIP85SelectChildIndexScreen",
        FakeRollCountScreen,
    )
    monkeypatch.setattr(
        tools_views.ToolsPasswordDiceRollCountView,
        "run_screen",
        lambda self, *_args, **_kwargs: 0,
    )

    dest = tools_views.ToolsPasswordDiceRollCountView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordEntropySourceView
    assert dest.skip_current_view is True
    assert dest.view_args["dice_sides"] == 6
    assert dest.view_args["roll_count"] == 12


def test_password_generate_view_formats_dice_rolls(monkeypatch):
    view = object.__new__(tools_views.ToolsPasswordGenerateView)
    view.password_type = tools_views.PASSWORD_TYPE_DICE_ROLLS
    view.entropy_source = tools_views.PASSWORD_ENTROPY_BIP85
    view.strength_bits = 64
    view.random_options = {}
    view.roll_data = b"\x01" * 64
    view.roll_count = 5
    view.word_count = None
    view.word_separator = tools_views.PASSWORD_WORD_SEPARATOR_NONE
    view.entropy_bytes_override = None
    view.dice_sides = 20

    monkeypatch.setattr(
        tools_views.password_generation,
        "dice_roll_values_from_seed",
        lambda *_args, **_kwargs: [1, 0, 19, 7, 3],
    )

    dest = tools_views.ToolsPasswordGenerateView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordReviewView
    assert dest.view_args["password"] == "1,0,19,7,3"


def test_dice_rolls_type_prompts_sides_and_rolls_before_entropy_source(monkeypatch):
    view = object.__new__(tools_views.ToolsPasswordGeneratorTypeView)
    monkeypatch.setattr(
        tools_views.ToolsPasswordGeneratorTypeView,
        "run_screen",
        lambda self, *_args, **_kwargs: 4,
    )

    dest = tools_views.ToolsPasswordGeneratorTypeView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordDiceRollCountView
    assert dest.view_args["password_type"] == tools_views.PASSWORD_TYPE_DICE_ROLLS
    assert dest.view_args["strength_bits"] == 64
    assert dest.view_args["entropy_source"] is None


def test_bip85_dice_rolls_uses_derived_entropy_directly(monkeypatch):
    view = object.__new__(tools_views.ToolsPasswordBIP85GenerateView)
    view.password_type = tools_views.PASSWORD_TYPE_DICE_ROLLS
    view.strength_bits = 64
    view.random_options = {}

    class SeedObj:
        seed_bytes = b"\x11" * 64

        @staticmethod
        def get_root(_network=None):
            return embit_bip32.HDKey.from_seed(SeedObj.seed_bytes)

    class Storage:
        seeds = [SeedObj()]

    class Controller:
        storage = Storage()

        @staticmethod
        def get_seed(_idx):
            return SeedObj()

    view.controller = Controller()

    class S:
        @staticmethod
        def get_value(_key):
            return "M"

    view.settings = S()

    calls = {"count": 0}

    class FakeIndexScreen:
        def __init__(self, *args, **kwargs):
            pass

        def display(self):
            calls["count"] += 1
            return "0" if calls["count"] == 1 else "10"

    monkeypatch.setattr(
        tools_views.seed_screens,
        "SeedBIP85SelectChildIndexScreen",
        FakeIndexScreen,
    )
    monkeypatch.setattr(
        tools_views.ToolsPasswordBIP85GenerateView,
        "run_screen",
        lambda self, *_args, **_kwargs: 0,
    )

    expected_entropy = bytes(range(64))

    def fake_derive_entropy(_root, app_no, params):
        assert app_no == tools_views.BIP85_APP_DICE
        assert params == [6, 10, 0]
        return expected_entropy

    monkeypatch.setattr(embit_bip85, "derive_entropy", fake_derive_entropy)

    dest = tools_views.ToolsPasswordBIP85GenerateView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordGenerateView
    assert dest.view_args["roll_data"] == expected_entropy
    assert dest.view_args["roll_count"] == 10
    assert dest.view_args["dice_sides"] == 6


def test_entropy_source_uses_precollected_dice_roll_config_for_camera(monkeypatch):
    view = object.__new__(tools_views.ToolsPasswordEntropySourceView)
    view.password_type = tools_views.PASSWORD_TYPE_DICE_ROLLS
    view.strength_bits = 64
    view.random_options = {}
    view.dice_sides = 10
    view.roll_count = 12

    class C:
        pass

    view.controller = C()
    view.controller.hardware_rng_is_healthy = True
    view.controller.hardware_rng_failure_reason = None

    monkeypatch.setattr(
        tools_views.ToolsPasswordEntropySourceView,
        "run_screen",
        lambda self, *_args, **_kwargs: 0,
    )

    dest = tools_views.ToolsPasswordEntropySourceView.run(view)

    assert dest.View_cls is tools_views.ToolsImageEntropyLivePreviewView
    assert dest.view_args["next_view_args"]["dice_sides"] == 10
    assert dest.view_args["next_view_args"]["roll_count"] == 12


def test_password_generate_view_matches_bip85_dice_spec_vector_output():
    view = object.__new__(tools_views.ToolsPasswordGenerateView)
    view.password_type = tools_views.PASSWORD_TYPE_DICE_ROLLS
    view.entropy_source = tools_views.PASSWORD_ENTROPY_BIP85
    view.strength_bits = 64
    view.random_options = {}
    view.roll_data = bytes.fromhex(
        "5e41f8f5d5d9ac09a20b8a5797a3172b28c806aead00d27e36609e2dd116a591"
        "76a738804236586f668da8a51b90c708a4226d7f92259c69f64c51124b6f6cd2"
    )
    view.roll_count = 10
    view.word_count = None
    view.word_separator = tools_views.PASSWORD_WORD_SEPARATOR_NONE
    view.entropy_bytes_override = None
    view.dice_sides = 6

    dest = tools_views.ToolsPasswordGenerateView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordReviewView
    assert dest.view_args["password"] == "1,0,0,2,0,1,5,5,2,4"


def test_bip85_dice_rolls_uses_seed_root_not_seed_bytes_none(monkeypatch):
    master_xprv = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

    view = object.__new__(tools_views.ToolsPasswordBIP85GenerateView)
    view.password_type = tools_views.PASSWORD_TYPE_DICE_ROLLS
    view.strength_bits = 64
    view.random_options = {}
    view.dice_sides = 6
    view.roll_count = 10

    class SeedObj:
        seed_bytes = None

        @staticmethod
        def get_root(_network=None):
            return embit_bip32.HDKey.from_string(master_xprv)

    class Storage:
        seeds = [SeedObj()]

    class Controller:
        storage = Storage()

        @staticmethod
        def get_seed(_idx):
            return SeedObj()

    view.controller = Controller()

    class S:
        @staticmethod
        def get_value(_key):
            return "M"

    view.settings = S()

    class FakeIndexScreen:
        def __init__(self, *args, **kwargs):
            pass

        def display(self):
            return "0"

    monkeypatch.setattr(
        tools_views.seed_screens,
        "SeedBIP85SelectChildIndexScreen",
        FakeIndexScreen,
    )

    dest = tools_views.ToolsPasswordBIP85GenerateView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordGenerateView

    gen = object.__new__(tools_views.ToolsPasswordGenerateView)
    for k, v in dest.view_args.items():
        setattr(gen, k, v)
    gen.entropy_bytes_override = None

    review_dest = tools_views.ToolsPasswordGenerateView.run(gen)
    assert review_dest.View_cls is tools_views.ToolsPasswordReviewView
    assert review_dest.view_args["password"] == "1,0,0,2,0,1,5,5,2,4"


def test_bip85_diceware_short_uses_bip85_entropy_directly(monkeypatch):
    master_xprv = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

    view = object.__new__(tools_views.ToolsPasswordBIP85GenerateView)
    view.password_type = tools_views.PASSWORD_TYPE_DICEWARE_EFF_SHORT
    view.strength_bits = 32
    view.random_options = {}
    view.controller = None

    class SeedObj:
        @staticmethod
        def get_root(_network=None):
            return embit_bip32.HDKey.from_string(master_xprv)

    class Storage:
        seeds = [SeedObj()]

    class Controller:
        storage = Storage()

        @staticmethod
        def get_seed(_idx):
            return SeedObj()

    view.controller = Controller()

    class S:
        @staticmethod
        def get_value(_key):
            return "M"

    view.settings = S()

    class FakeIndexScreen:
        def __init__(self, *args, **kwargs):
            pass

        def display(self):
            return "0"

    monkeypatch.setattr(
        tools_views.seed_screens,
        "SeedBIP85SelectChildIndexScreen",
        FakeIndexScreen,
    )

    dest = tools_views.ToolsPasswordBIP85GenerateView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordWordSeparatorView

    cached = view.controller.password_generator_entropy_cache
    assert cached["word_count"] == 4
    assert cached["entropy_bytes"] == embit_bip85.derive_entropy(
        embit_bip32.HDKey.from_string(master_xprv),
        tools_views.BIP85_APP_DICE,
        [6, 16, 0],
    )


def test_entropy_source_for_dice_rolls_excludes_dice_option(monkeypatch):
    view = object.__new__(tools_views.ToolsPasswordEntropySourceView)
    view.password_type = tools_views.PASSWORD_TYPE_DICE_ROLLS
    view.strength_bits = 64
    view.random_options = {}
    view.dice_sides = 6
    view.roll_count = 10

    class C:
        pass

    view.controller = C()
    view.controller.hardware_rng_is_healthy = True
    view.controller.hardware_rng_failure_reason = None

    # For Dice Rolls, index 1 should be System RNG (Dice option removed).
    monkeypatch.setattr(
        tools_views.ToolsPasswordEntropySourceView,
        "run_screen",
        lambda self, *_args, **_kwargs: 1,
    )

    dest = tools_views.ToolsPasswordEntropySourceView.run(view)

    assert dest.View_cls is tools_views.ToolsPasswordGenerateView
    assert dest.view_args["entropy_source"] == tools_views.PASSWORD_ENTROPY_HARDWARE_RNG
    assert dest.view_args["dice_sides"] == 6
    assert dest.view_args["roll_count"] == 10
