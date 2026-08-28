"""
Flow tests for the "calculate the final mnemonic word" tool.

This tool builds a seed the user will actually keep, so the interesting
assertion is not only that the routing is right but that the mnemonic it hands
to storage is a *valid* BIP-39 mnemonic -- the checksum word has to be computed
correctly for whichever entropy path the user took (coin flips, an explicit
word, or all-zeros).

The tests seed the pending mnemonic directly rather than walking 11 words
through ``SeedMnemonicEntryView``; the word-entry keyboard is covered elsewhere
and driving it here would bury the branch under test.
"""
from base import FlowTest, FlowStep

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.views import seed_views, tools_views
from seedsigner.views.view import MainMenuView


# The first 11 words of a known-good 12-word mnemonic; the 12th is what the
# tool computes.
ELEVEN_WORDS = "blush twice taste dawn feed second opinion lazy thumb play neglect".split()


class TestCalcFinalWordFlows(FlowTest):

    def init_pending_mnemonic(self, words=ELEVEN_WORDS, length=12):
        """Put the tool in the state it reaches after the user types 11 words."""
        self.controller.storage.init_pending_mnemonic(length)
        for i, word in enumerate(words):
            self.controller.storage.update_pending_mnemonic(word, i)

    def assert_pending_seed_is_valid(self):
        """The finished mnemonic must pass BIP-39 checksum validation."""
        seed = self.controller.storage.pending_seed
        assert seed is not None
        # Round-tripping through Seed() raises InvalidSeedException on a bad checksum.
        rebuilt = Seed(mnemonic=seed.mnemonic_list)
        assert rebuilt.seed_bytes == seed.seed_bytes

    # ------------------------------------------------------------------
    # Entry
    # ------------------------------------------------------------------

    def test_calc_final_word_entry_from_tools_menu(self):
        """Tools > Calc final word prompts for mnemonic length, then word entry."""
        self.run_sequence([
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.KEYBOARD),
            FlowStep(tools_views.ToolsCalcFinalWordNumWordsView,
                     button_data_selection=tools_views.ToolsCalcFinalWordNumWordsView.TWELVE),
            FlowStep(seed_views.SeedMnemonicEntryView),
        ])

        # Choosing "12 words" must have sized the pending mnemonic accordingly.
        assert len(self.controller.storage.pending_mnemonic) == 12

    def test_calc_final_word_num_words_back_button(self):
        """Backing out of the length picker returns to the Tools menu."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.KEYBOARD),
            FlowStep(tools_views.ToolsCalcFinalWordNumWordsView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(tools_views.ToolsMenuView),
        ])

    # ------------------------------------------------------------------
    # The three entropy sources
    # ------------------------------------------------------------------

    def test_calc_final_word_with_zeros(self):
        """Finalizing with zeros produces a valid mnemonic and can load it."""
        self.init_pending_mnemonic()

        self.run_sequence(
            sequence=[
                FlowStep(tools_views.ToolsCalcFinalWordFinalizePromptView,
                         button_data_selection=tools_views.ToolsCalcFinalWordFinalizePromptView.ZEROS),
                FlowStep(tools_views.ToolsCalcFinalWordShowFinalWordView,
                         button_data_selection=tools_views.ToolsCalcFinalWordShowFinalWordView.NEXT),
                FlowStep(tools_views.ToolsCalcFinalWordDoneView,
                         button_data_selection=tools_views.ToolsCalcFinalWordDoneView.LOAD),
                FlowStep(seed_views.SeedFinalizeView),
            ],
        )

        self.assert_pending_seed_is_valid()

    def test_calc_final_word_with_coin_flips(self):
        """
        Coin-flip entropy: a 12-word mnemonic needs 7 flips (128 total bits minus
        11 words x 11 bits).
        """
        self.init_pending_mnemonic()

        self.run_sequence(
            sequence=[
                FlowStep(tools_views.ToolsCalcFinalWordFinalizePromptView,
                         button_data_selection=tools_views.ToolsCalcFinalWordFinalizePromptView.COIN_FLIPS),
                FlowStep(tools_views.ToolsCalcFinalWordCoinFlipsView, screen_return_value="1010101"),
                FlowStep(tools_views.ToolsCalcFinalWordShowFinalWordView,
                         button_data_selection=tools_views.ToolsCalcFinalWordShowFinalWordView.NEXT),
                FlowStep(tools_views.ToolsCalcFinalWordDoneView,
                         button_data_selection=tools_views.ToolsCalcFinalWordDoneView.LOAD),
                FlowStep(seed_views.SeedFinalizeView),
            ],
        )

        self.assert_pending_seed_is_valid()

    def test_calc_final_word_coin_flips_differ_from_zeros(self):
        """
        Different coin flips must yield a different final word, otherwise the
        entropy the user supplied is being silently discarded.
        """
        def final_word_for(coin_flips):
            self.setup_method()  # fresh controller/storage per run
            self.init_pending_mnemonic()
            self.run_sequence(
                sequence=[
                    FlowStep(tools_views.ToolsCalcFinalWordFinalizePromptView,
                             button_data_selection=tools_views.ToolsCalcFinalWordFinalizePromptView.COIN_FLIPS),
                    FlowStep(tools_views.ToolsCalcFinalWordCoinFlipsView, screen_return_value=coin_flips),
                    FlowStep(tools_views.ToolsCalcFinalWordShowFinalWordView),
                ],
            )
            return self.controller.storage.pending_mnemonic[-1]

        assert final_word_for("0000000") != final_word_for("1111111")

    def test_calc_final_word_select_word_routes_to_entry(self):
        """Choosing word-selection entropy returns to the word keyboard."""
        self.init_pending_mnemonic()

        self.run_sequence(
            sequence=[
                FlowStep(tools_views.ToolsCalcFinalWordFinalizePromptView,
                         button_data_selection=tools_views.ToolsCalcFinalWordFinalizePromptView.SELECT_WORD),
                FlowStep(seed_views.SeedMnemonicEntryView),
            ],
        )

        # The last slot must be cleared so the user is entering it fresh.
        assert self.controller.storage.pending_mnemonic[-1] is None

    # ------------------------------------------------------------------
    # Done screen
    # ------------------------------------------------------------------

    def test_calc_final_word_discard(self):
        """Discarding routes to the discard confirmation, not into the seed."""
        self.init_pending_mnemonic()

        self.run_sequence(
            sequence=[
                FlowStep(tools_views.ToolsCalcFinalWordFinalizePromptView,
                         button_data_selection=tools_views.ToolsCalcFinalWordFinalizePromptView.ZEROS),
                FlowStep(tools_views.ToolsCalcFinalWordShowFinalWordView,
                         button_data_selection=tools_views.ToolsCalcFinalWordShowFinalWordView.NEXT),
                FlowStep(tools_views.ToolsCalcFinalWordDoneView,
                         button_data_selection=tools_views.ToolsCalcFinalWordDoneView.DISCARD),
                FlowStep(seed_views.SeedDiscardView),
            ],
        )

    def test_calc_final_word_done_back_button(self):
        """Backing out of the Done screen must not convert the pending mnemonic."""
        self.init_pending_mnemonic()

        self.run_sequence(
            sequence=[
                FlowStep(tools_views.ToolsCalcFinalWordFinalizePromptView,
                         button_data_selection=tools_views.ToolsCalcFinalWordFinalizePromptView.ZEROS),
                FlowStep(tools_views.ToolsCalcFinalWordShowFinalWordView,
                         button_data_selection=tools_views.ToolsCalcFinalWordShowFinalWordView.NEXT),
                FlowStep(tools_views.ToolsCalcFinalWordDoneView, screen_return_value=RET_CODE__BACK_BUTTON),
                FlowStep(tools_views.ToolsCalcFinalWordShowFinalWordView),
            ],
        )

        assert self.controller.storage.pending_seed is None

    def test_calc_final_word_24_words(self):
        """
        The 24-word path needs a different number of entropy bits than the
        12-word one, so it is worth walking separately.
        """
        twenty_three = ("abandon " * 23).split()
        self.init_pending_mnemonic(words=twenty_three, length=24)
        self.settings.set_value(SettingsConstants.SETTING__SEED_WORD_LENGTHS, [12, 24])

        self.run_sequence(
            sequence=[
                FlowStep(tools_views.ToolsCalcFinalWordFinalizePromptView,
                         button_data_selection=tools_views.ToolsCalcFinalWordFinalizePromptView.ZEROS),
                FlowStep(tools_views.ToolsCalcFinalWordShowFinalWordView,
                         button_data_selection=tools_views.ToolsCalcFinalWordShowFinalWordView.NEXT),
                FlowStep(tools_views.ToolsCalcFinalWordDoneView,
                         button_data_selection=tools_views.ToolsCalcFinalWordDoneView.LOAD),
                FlowStep(seed_views.SeedFinalizeView),
            ],
        )

        assert len(self.controller.storage.pending_seed.mnemonic_list) == 24
        self.assert_pending_seed_is_valid()
