"""
    End-to-end flow tests for the seed workflows, running the *real* Screens via
    tests.ui_driver (UISession + FlowStep(real_screens=True)) and driving them with
    scripted button input.

    Two things distinguish these from tests/test_flows_seed*.py:

    * The Screens are real, so screen-construction and input-handling bugs surface
      here instead of on-device.

    * Every workflow starts from its **real entry point** -- MainMenuView, then the
      menus a user actually walks -- rather than being dropped into the middle with a
      pre-built Seed in `initial_destination_view_args`. That shortcut is what let the
      pending-seed regression through: the mocked tests all entered the backup flow at
      SeedOptionsView with an already-finalized seed, which is precisely the branch
      that still worked, while the create-a-new-seed branch silently stopped storing
      the seed at all.

    Seed-creation tests therefore assert on `controller.storage.seeds` -- where the
    seed has to land for the Seeds menu to list it -- and not merely on which View the
    flow ended at. The broken flow ended on the right View, showing the right
    fingerprint, with nothing stored.
"""

from contextlib import contextmanager
from unittest.mock import patch

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import FlowStep, FlowTest
from ui_driver import TypeKeys, UISession, make_noise_frame, select, type_words

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.settings import SettingsConstants
from seedsigner.models.seed import Seed, Slip39Seed
from seedsigner.views import seed_views, tools_views
from seedsigner.views.view import MainMenuView


# A 12-word mnemonic used wherever a test needs to load a known seed.
MNEMONIC_12 = "blush twice taste dawn feed second opinion lazy thumb play neglect impact".split()

# 50 dice rolls (the requirement for a 12-word mnemonic). Deterministic, and varied
# enough to clear mnemonic_generation.dice_entropy_is_sufficient()'s entropy floor,
# which a run of identical rolls would not.
DICE_ROLLS_12 = ("123456" * 9)[:50]

# The first 11 words of MNEMONIC_12; the tool computes the 12th.
ELEVEN_WORDS = MNEMONIC_12[:11]


@contextmanager
def no_shuffle():
    """
    Pin SeedWordsBackupTestView's correct answer to button_data[0].

    The view shuffles its four candidate words, so without this the right answer sits
    at a random index and Select() would have to guess.
    """
    with patch("seedsigner.views.seed_views.random.shuffle", lambda seq: None):
        yield


class SeedFlowTest(FlowTest):
    """Shared setup for the seed workflows."""

    def setup_method(self):
        super().setup_method()
        # The dire warning screens are an extra interstitial on nearly every one of
        # these flows and are covered on their own in tests/test_flows_seed.py; turning
        # them off keeps each script about the workflow under test.
        self.settings.set_value(
            SettingsConstants.SETTING__DIRE_WARNINGS, SettingsConstants.OPTION__DISABLED
        )

    def store_seed(self, mnemonic=None) -> Seed:
        """A seed already loaded into storage, as if a previous flow had finalized it."""
        seed = Seed(mnemonic=mnemonic or MNEMONIC_12)
        self.controller.storage.set_pending_seed(seed)
        return self.controller.storage.finalize_pending_seed()

    def assert_one_seed_stored(self) -> Seed:
        """The flow put exactly one seed where the Seeds menu reads from."""
        seeds = self.controller.storage.seeds
        assert len(seeds) == 1, f"expected the new seed in storage.seeds, found {seeds!r}"
        assert self.controller.storage.pending_seed is None, "pending seed was not cleared"
        return seeds[0]



class TestCreateSeedFlows(SeedFlowTest):
    """
    Tools > New seed. These are the flows the pending-seed regression broke: the seed
    was generated and displayed, but never reached storage.seeds.
    """

    def dice_words_steps(self, num_words: int = 12) -> list:
        """The FlowSteps from the main menu through the last page of seed words."""
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.DICE),
            FlowStep(
                tools_views.ToolsDiceEntropyMnemonicLengthView,
                button_data_selection=tools_views.ToolsDiceEntropyMnemonicLengthView.TWELVE,
            ),
            FlowStep(tools_views.ToolsDiceEntropyEntryView, real_screens=True),
            FlowStep(seed_views.SeedWordsWarningView, is_redirect=True),
        ] + [
            FlowStep(seed_views.SeedWordsView, real_screens=True)
            for _ in range(num_words // 4)
        ]

    def test_dice_entropy_skip_backup_test_stores_seed(self):
        """
        Dice rolls > seed words > Skip the backup test > Finalize.

        The seed must end up in storage.seeds; before the is_pending_seed fix this
        flow routed to SeedOptionsView and never called finalize_pending_seed(), so
        the new seed never appeared in the Seeds menu.
        """
        session = UISession(script=(
            [TypeKeys(DICE_ROLLS_12)]
            + select(*[seed_views.SeedWordsView.NEXT] * 3)
            + select(seed_views.SeedWordsBackupTestPromptView.SKIP)
            + select(seed_views.SeedFinalizeView.FINALIZE)
        ))

        self.run_sequence(
            self.dice_words_steps() + [
                FlowStep(seed_views.SeedWordsBackupTestPromptView, real_screens=True),
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            ui_session=session,
        )

        seed = self.assert_one_seed_stored()
        assert len(seed.mnemonic_list) == 12
        assert session.renderer.frames, "the real Screens never rendered"

    def test_dice_entropy_verify_backup_test_stores_seed(self):
        """The other exit from the backup test: verify every word, then Finalize."""
        with no_shuffle():
            session = UISession(script=(
                [TypeKeys(DICE_ROLLS_12)]
                + select(*[seed_views.SeedWordsView.NEXT] * 3)
                + select(seed_views.SeedWordsBackupTestPromptView.VERIFY)
                + select(*[0] * 12)  # the real word, pinned to slot 0 by no_shuffle()
                + select(0)          # "OK" on the Backup Verified screen
                + select(seed_views.SeedFinalizeView.FINALIZE)
            ))

            self.run_sequence(
                self.dice_words_steps() + [
                    FlowStep(seed_views.SeedWordsBackupTestPromptView, real_screens=True),
                ] + [
                    FlowStep(seed_views.SeedWordsBackupTestView, real_screens=True)
                    for _ in range(12)
                ] + [
                    FlowStep(seed_views.SeedWordsBackupTestSuccessView, real_screens=True),
                    FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                    FlowStep(seed_views.SeedOptionsView),
                ],
                ui_session=session,
            )

        self.assert_one_seed_stored()

    def test_created_seed_is_listed_in_the_seeds_menu(self):
        """
        The user-visible symptom, asserted end to end: create a seed, then walk to
        Seeds and find it there.
        """
        session = UISession(script=(
            [TypeKeys(DICE_ROLLS_12)]
            + select(*[seed_views.SeedWordsView.NEXT] * 3)
            + select(seed_views.SeedWordsBackupTestPromptView.SKIP)
            + select(seed_views.SeedFinalizeView.FINALIZE)
        ))

        self.run_sequence(
            self.dice_words_steps() + [
                FlowStep(seed_views.SeedWordsBackupTestPromptView, real_screens=True),
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            ui_session=session,
        )
        seed = self.assert_one_seed_stored()

        # Now the part the user actually noticed: Seeds lists it.
        fingerprint = seed.get_fingerprint(
            self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        )
        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
                FlowStep(seed_views.SeedsMenuView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            ui_session=UISession(script=select(f"{fingerprint} (BIP39)")),
        )


class TestCameraEntropyCreateSeedFlow(SeedFlowTest):
    """
    Tools > New seed (camera). Same pending-seed path as dice, reached through the
    image-entropy views.

    ToolsImageEntropyLivePreviewView is the one step left mocked: its screen drives the
    physical camera's preview loop rather than responding to button input, so there is
    nothing for a scripted press to exercise. It is handed the real PIL frames the
    downstream hashing needs, and every screen after it is real.
    """

    def test_camera_entropy_stores_seed(self):
        from seedsigner.gui.screens.tools_screens import ToolsImageEntropyLivePreviewScreen

        frames = [
            make_noise_frame(seed=i)
            for i in range(ToolsImageEntropyLivePreviewScreen.PREVIEW_POOL_SIZE)
        ]
        final_image = make_noise_frame(seed=999).convert("RGB")

        session = UISession(script=(
            select(tools_views.ToolsImageEntropyMnemonicLengthView.TWELVE_WORDS)
            + select(*[seed_views.SeedWordsView.NEXT] * 3)
            + select(seed_views.SeedWordsBackupTestPromptView.SKIP)
            + select(seed_views.SeedFinalizeView.FINALIZE)
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
                FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.IMAGE),
                FlowStep(
                    tools_views.ToolsImageEntropyLivePreviewView,
                    screen_return_value=(frames, final_image),
                ),
                FlowStep(tools_views.ToolsImageEntropyFinalImageView, screen_return_value=0),
                FlowStep(tools_views.ToolsImageEntropyMnemonicLengthView, real_screens=True),
                FlowStep(seed_views.SeedWordsWarningView, is_redirect=True),
            ] + [
                FlowStep(seed_views.SeedWordsView, real_screens=True) for _ in range(3)
            ] + [
                FlowStep(seed_views.SeedWordsBackupTestPromptView, real_screens=True),
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            ui_session=session,
        )

        seed = self.assert_one_seed_stored()
        assert len(seed.mnemonic_list) == 12
        # The camera buffers must not outlive the flow.
        assert self.controller.image_entropy_preview_frames is None
        assert self.controller.image_entropy_final_image is None



class TestCreateSlip39SeedFlow(SeedFlowTest):
    """
    Tools > SLIP39 seed (dice). Generates a share set rather than one mnemonic, so the
    words + backup test run once per share before the seed is finalized -- the pending
    sentinel has to survive every one of those laps.
    """

    def setup_method(self):
        super().setup_method()
        self.settings.set_value(
            SettingsConstants.SETTING__SLIP39_SEEDS, SettingsConstants.OPTION__ENABLED
        )

    def test_slip39_dice_entropy_stores_seed(self):
        num_shares, threshold, words_per_share = 2, 2, 20

        # SeedSlip39CreateFromBytesView instantiates SeedBIP85SelectChildIndexScreen
        # directly rather than through run_screen(), so FlowTest can't see it; stub it
        # with the share count and threshold the user would key in.
        with patch.object(seed_views.seed_screens, "SeedBIP85SelectChildIndexScreen") as index_screen:
            index_screen.return_value.display.side_effect = [str(num_shares), str(threshold)]

            pages_per_share = words_per_share // 4
            script = [TypeKeys(DICE_ROLLS_12)]
            steps = [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
                FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SLIP39_DICE),
                FlowStep(
                    tools_views.ToolsDiceEntropyMnemonicLengthView,
                    button_data_selection=tools_views.ToolsDiceEntropyMnemonicLengthView.TWENTY,
                ),
                FlowStep(tools_views.ToolsDiceEntropyEntryView, real_screens=True),
                # Instantiates its index Screens directly, so run_screen() is never called.
                FlowStep(seed_views.SeedSlip39CreateFromBytesView, is_redirect=True),
            ]
            for share in range(num_shares):
                steps.append(FlowStep(seed_views.SeedWordsWarningView, is_redirect=True))
                steps += [
                    FlowStep(seed_views.SeedWordsView, real_screens=True)
                    for _ in range(pages_per_share)
                ]
                steps.append(FlowStep(seed_views.SeedWordsBackupTestPromptView, real_screens=True))
                script += select(*[seed_views.SeedWordsView.NEXT] * pages_per_share)
                script += select(seed_views.SeedWordsBackupTestPromptView.SKIP)
            steps += [
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ]
            script += select(seed_views.SeedFinalizeView.FINALIZE)

            self.run_sequence(steps, ui_session=UISession(script=script))

        seed = self.assert_one_seed_stored()
        assert isinstance(seed, Slip39Seed)
        assert len(seed.mnemonic_list) == num_shares



class TestCalcFinalWordFlows(SeedFlowTest):
    """
    Tools > Calc 12th/24th word. Both exits matter: Load finalizes the pending seed,
    and Discard has to clear the *pending* seed rather than trying to remove it from
    storage.seeds, where it has never been.
    """

    def init_pending_mnemonic(self, words=None, length=12):
        """The state the tool reaches once the user has typed the first 11 words."""
        words = words or ELEVEN_WORDS
        self.controller.storage.init_pending_mnemonic(length)
        for i, word in enumerate(words):
            self.controller.storage.update_pending_mnemonic(word, i)

    def calc_steps(self) -> list:
        return [
            FlowStep(
                tools_views.ToolsCalcFinalWordFinalizePromptView,
                button_data_selection=tools_views.ToolsCalcFinalWordFinalizePromptView.ZEROS,
            ),
            FlowStep(
                tools_views.ToolsCalcFinalWordShowFinalWordView,
                button_data_selection=tools_views.ToolsCalcFinalWordShowFinalWordView.NEXT,
            ),
        ]

    def test_calc_final_word_load_stores_seed(self):
        self.init_pending_mnemonic()

        session = UISession(script=(
            select(tools_views.ToolsCalcFinalWordDoneView.LOAD)
            + select(seed_views.SeedFinalizeView.FINALIZE)
        ))
        self.run_sequence(
            self.calc_steps() + [
                FlowStep(tools_views.ToolsCalcFinalWordDoneView, real_screens=True),
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            ui_session=session,
        )

        seed = self.assert_one_seed_stored()
        assert seed.mnemonic_list[:11] == ELEVEN_WORDS

    def test_calc_final_word_discard_clears_pending_seed(self):
        """
        Discard on a seed that was never stored.

        SeedDiscardView resolves `seed=None` to the pending seed, so before the
        is_pending_seed fix it took the "already stored" branch and called
        storage.seeds.remove() on a seed that is not in the list -- a ValueError that
        dropped the user into the unhandled-exception screen. Nothing caught it,
        because the existing flow test stops at SeedDiscardView without pressing
        Discard.
        """
        self.init_pending_mnemonic()

        session = UISession(script=(
            select(tools_views.ToolsCalcFinalWordDoneView.DISCARD)
            + select(seed_views.SeedDiscardView.DISCARD)
        ))
        self.run_sequence(
            self.calc_steps() + [
                FlowStep(tools_views.ToolsCalcFinalWordDoneView, real_screens=True),
                FlowStep(seed_views.SeedDiscardView, real_screens=True),
                FlowStep(MainMenuView),
            ],
            ui_session=session,
        )

        assert self.controller.storage.seeds == []
        assert self.controller.storage.pending_seed is None

    def test_calc_final_word_discard_then_keep_returns_to_finalize(self):
        """The other button on the discard warning: Keep must route back to Finalize."""
        self.init_pending_mnemonic()

        session = UISession(script=(
            select(tools_views.ToolsCalcFinalWordDoneView.DISCARD)
            + select(seed_views.SeedDiscardView.KEEP)
            + select(seed_views.SeedFinalizeView.FINALIZE)
        ))
        self.run_sequence(
            self.calc_steps() + [
                FlowStep(tools_views.ToolsCalcFinalWordDoneView, real_screens=True),
                FlowStep(seed_views.SeedDiscardView, real_screens=True),
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            ui_session=session,
        )

        self.assert_one_seed_stored()


class TestLoadSeedFlows(SeedFlowTest):
    """Seeds > Load a seed. The word-entry keyboard is real here, one word at a time."""

    def test_manual_12_word_entry_stores_seed(self):
        session = UISession(script=(
            type_words(MNEMONIC_12)
            + select(seed_views.SeedFinalizeView.FINALIZE)
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
                FlowStep(seed_views.SeedsMenuView, is_redirect=True),  # no seeds yet -> LoadSeedView
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.TYPE_12WORD),
            ] + [
                FlowStep(seed_views.SeedMnemonicEntryView, real_screens=True)
                for _ in MNEMONIC_12
            ] + [
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            ui_session=session,
        )

        seed = self.assert_one_seed_stored()
        assert seed.mnemonic_list == MNEMONIC_12

    def test_manual_entry_back_from_first_word_cancels(self):
        """
        BACK out of word #1 abandons the mnemonic instead of leaving a half-built one
        behind for the next flow to pick up.
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
            FlowStep(seed_views.SeedsMenuView, is_redirect=True),
            FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.TYPE_12WORD),
            FlowStep(seed_views.SeedMnemonicEntryView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(seed_views.LoadSeedView),
        ])

        assert self.controller.storage.pending_mnemonic_length == 0
        assert self.controller.storage.seeds == []



class TestPassphraseFlows(SeedFlowTest):
    """
    SeedFinalizeView > Add passphrase. The passphrase is typed on the real
    multi-keyboard screen, and the seed is only stored once it is reviewed.
    """

    PASSPHRASE = "hunter2"

    def test_typed_passphrase_is_applied_and_seed_stored(self):
        from seedsigner.gui.screens.seed_screens import SeedAddPassphraseScreen
        from ui_driver import plan_text_entry_script

        self.settings.set_value(
            SettingsConstants.SETTING__PASSPHRASE, SettingsConstants.OPTION__ENABLED
        )
        self.controller.storage.set_pending_seed(Seed(mnemonic=MNEMONIC_12))

        passphrase_script = plan_text_entry_script(
            SeedAddPassphraseScreen, self.PASSPHRASE, passphrase="", title="Passphrase"
        )
        session = UISession(script=(
            select(seed_views.SeedFinalizeView.TYPE_PASSPHRASE)
            + passphrase_script
            + select(seed_views.SeedReviewPassphraseView.DONE)
        ))

        self.run_sequence(
            [
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedAddPassphraseView, real_screens=True),
                FlowStep(seed_views.SeedReviewPassphraseView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            ui_session=session,
        )

        seed = self.assert_one_seed_stored()
        assert seed.passphrase == self.PASSPHRASE



class TestSeedsMenuFlows(SeedFlowTest):
    """Seeds > the in-memory seed list, and the options menu behind each entry."""

    SECOND_MNEMONIC = (
        "payment artist half drive borrow speak make crouch payment artist half drill"
    ).split()

    def fingerprint(self, seed) -> str:
        return seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))

    def test_seeds_menu_lists_every_loaded_seed(self):
        first = self.store_seed()
        second = self.store_seed(self.SECOND_MNEMONIC)

        # Pick the second entry by its own fingerprint label, so a mis-ordered or
        # mis-labelled list fails here rather than silently selecting the wrong seed.
        session = UISession(script=select(f"{self.fingerprint(second)} (BIP39)"))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
                FlowStep(seed_views.SeedsMenuView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            ui_session=session,
        )
        assert self.controller.storage.seeds == [first, second]

    def test_seed_options_to_backup_menu(self):
        seed = self.store_seed()
        session = UISession(script=(
            select(f"{self.fingerprint(seed)} (BIP39)")
            + select(seed_views.SeedOptionsView.BACKUP)
            + select(seed_views.SeedBackupView.VIEW_WORDS)
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
                FlowStep(seed_views.SeedsMenuView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView, real_screens=True),
                FlowStep(seed_views.SeedBackupView, real_screens=True),
                FlowStep(seed_views.SeedWordsWarningView, is_redirect=True),
                FlowStep(seed_views.SeedWordsView),
            ],
            ui_session=session,
        )



class TestStoredSeedBackupFlows(SeedFlowTest):
    """
    Backup > View seed words on a seed that is *already* stored.

    This is the branch the mocked tests already covered, and it must keep behaving:
    an existing seed goes back to SeedOptionsView when the backup test finishes, and
    must not be re-finalized or duplicated in storage.
    """

    def view_words_steps(self, num_words: int = 12) -> list:
        return [
            FlowStep(seed_views.SeedOptionsView, real_screens=True),
            FlowStep(seed_views.SeedBackupView, real_screens=True),
            FlowStep(seed_views.SeedWordsWarningView, is_redirect=True),
        ] + [
            FlowStep(seed_views.SeedWordsView, real_screens=True)
            for _ in range(num_words // 4)
        ]

    def view_words_script(self, pages: int = 3) -> list:
        return (
            select(seed_views.SeedOptionsView.BACKUP)
            + select(seed_views.SeedBackupView.VIEW_WORDS)
            + select(*([seed_views.SeedWordsView.NEXT] * (pages - 1) + [seed_views.SeedWordsView.DONE]))
        )

    def test_stored_seed_backup_test_does_not_duplicate_the_seed(self):
        seed = self.store_seed()

        with no_shuffle():
            session = UISession(script=(
                self.view_words_script()
                + select(seed_views.SeedWordsBackupTestPromptView.VERIFY)
                + select(*[0] * 12)
                + select(0)  # "OK" on the Backup Verified screen
            ))
            self.run_sequence(
                self.view_words_steps() + [
                    FlowStep(seed_views.SeedWordsBackupTestPromptView, real_screens=True),
                ] + [
                    FlowStep(seed_views.SeedWordsBackupTestView, real_screens=True)
                    for _ in range(12)
                ] + [
                    FlowStep(seed_views.SeedWordsBackupTestSuccessView, real_screens=True),
                    FlowStep(seed_views.SeedOptionsView),
                ],
                initial_destination_view_args=dict(seed=seed),
                ui_session=session,
            )

        assert self.controller.storage.seeds == [seed]
        assert self.controller.storage.pending_seed is None

    def test_stored_seed_backup_test_wrong_word_then_retry(self):
        seed = self.store_seed()

        with no_shuffle():
            session = UISession(script=(
                self.view_words_script()
                + select(seed_views.SeedWordsBackupTestPromptView.VERIFY)
                + select(1)  # a decoy word
                + select(seed_views.SeedWordsBackupTestMistakeView.RETRY)
                + select(*[0] * 12)
                + select(0)
            ))
            self.run_sequence(
                self.view_words_steps() + [
                    FlowStep(seed_views.SeedWordsBackupTestPromptView, real_screens=True),
                    FlowStep(seed_views.SeedWordsBackupTestView, real_screens=True),
                    FlowStep(seed_views.SeedWordsBackupTestMistakeView, real_screens=True),
                ] + [
                    FlowStep(seed_views.SeedWordsBackupTestView, real_screens=True)
                    for _ in range(12)
                ] + [
                    FlowStep(seed_views.SeedWordsBackupTestSuccessView, real_screens=True),
                    FlowStep(seed_views.SeedOptionsView),
                ],
                initial_destination_view_args=dict(seed=seed),
                ui_session=session,
            )

        assert self.controller.storage.seeds == [seed]

    def test_stored_seed_backup_test_skip(self):
        seed = self.store_seed()

        session = UISession(script=(
            self.view_words_script()
            + select(seed_views.SeedWordsBackupTestPromptView.SKIP)
        ))
        self.run_sequence(
            self.view_words_steps() + [
                FlowStep(seed_views.SeedWordsBackupTestPromptView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            initial_destination_view_args=dict(seed=seed),
            ui_session=session,
        )

        assert self.controller.storage.seeds == [seed]



class TestDiscardStoredSeedFlow(SeedFlowTest):
    """SeedOptionsView > Discard, on a seed that really is in storage."""

    def test_discard_removes_the_seed(self):
        seed = self.store_seed()

        session = UISession(script=(
            select(seed_views.SeedOptionsView.DISCARD)
            + select(seed_views.SeedDiscardView.DISCARD)
        ))
        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, real_screens=True),
                FlowStep(seed_views.SeedDiscardView, real_screens=True),
                FlowStep(MainMenuView),
            ],
            initial_destination_view_args=dict(seed=seed),
            ui_session=session,
        )

        assert self.controller.storage.seeds == []

    def test_keep_returns_to_seed_options(self):
        seed = self.store_seed()

        session = UISession(script=(
            select(seed_views.SeedOptionsView.DISCARD)
            + select(seed_views.SeedDiscardView.KEEP)
        ))
        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, real_screens=True),
                FlowStep(seed_views.SeedDiscardView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            initial_destination_view_args=dict(seed=seed),
            ui_session=session,
        )

        assert self.controller.storage.seeds == [seed]


class TestExportXpubFlow(SeedFlowTest):
    """SeedOptions > Export xpub, through to the QR on screen."""

    def test_single_sig_native_segwit_export(self):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        seed = self.store_seed()
        self.settings.set_value(
            SettingsConstants.SETTING__SCRIPT_TYPES, [SettingsConstants.NATIVE_SEGWIT]
        )
        self.settings.set_value(
            SettingsConstants.SETTING__XPUB_QR_FORMAT,
            [SettingsConstants.XPUB_QR_FORMAT__SPECTER_LEGACY],
        )

        session = UISession(script=(
            select(seed_views.SeedOptionsView.EXPORT_XPUB)
            + select(seed_views.SeedExportXpubSigTypeView.SINGLE_SIG)
            + select(0)          # "I Understand" on the export warning
            + select(0)          # confirm the derivation details
            + [K.KEY_PRESS]      # any click dismisses the QR display
            + select(0)          # decline the verify-address offer
        ))

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, real_screens=True),
                FlowStep(seed_views.SeedExportXpubSigTypeView, real_screens=True),
                # Only one script type and one QR format are enabled, so both of these
                # Views redirect straight through without drawing a Screen.
                FlowStep(seed_views.SeedExportXpubScriptTypeView, is_redirect=True),
                FlowStep(seed_views.SeedExportXpubQRFormatView, is_redirect=True),
                FlowStep(seed_views.SeedExportXpubWarningView, real_screens=True),
                FlowStep(seed_views.SeedExportXpubDetailsView, real_screens=True),
                FlowStep(seed_views.SeedExportXpubQRDisplayView, real_screens=True),
                FlowStep(seed_views.SeedExportXpubVerifyAddressView, real_screens=True),
            ],
            initial_destination_view_args=dict(seed=seed),
            ui_session=session,
        )

        # Exporting must not disturb what is loaded.
        assert self.controller.storage.seeds == [seed]



class TestTranscribeSeedQRFlow(SeedFlowTest):
    """Backup > Export as SeedQR, including the zoomed-in transcription screens."""

    def test_transcribe_seedqr_to_confirm_prompt(self):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        seed = self.store_seed()

        session = UISession(script=(
            select(seed_views.SeedOptionsView.BACKUP)
            + select(seed_views.SeedBackupView.EXPORT_SEEDQR)
            + select(0)      # standard SeedQR format
            + select(0)      # whole-QR screen: start transcribing
            + [K.KEY_PRESS]  # any click exits the zoomed-in transcription view
            + select(seed_views.SeedTranscribeSeedQRConfirmQRPromptView.DONE)
        ))

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, real_screens=True),
                FlowStep(seed_views.SeedBackupView, real_screens=True),
                FlowStep(seed_views.SeedTranscribeSeedQRFormatView, real_screens=True),
                # Dire warnings are off in this suite's setup, so this View forwards
                # straight through (the warning itself is covered in test_flows_seed.py).
                FlowStep(seed_views.SeedTranscribeSeedQRWarningView, is_redirect=True),
                FlowStep(seed_views.SeedTranscribeSeedQRWholeQRView, real_screens=True),
                FlowStep(seed_views.SeedTranscribeSeedQRZoomedInView, real_screens=True),
                FlowStep(seed_views.SeedTranscribeSeedQRConfirmQRPromptView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            initial_destination_view_args=dict(seed=seed),
            ui_session=session,
        )

        assert self.controller.storage.seeds == [seed]



class TestBip85ChildSeedFlow(SeedFlowTest):
    """
    SeedOptions > BIP-85 child seed. The child is a *new* pending seed derived from
    the parent, so it runs through the same finalize path -- and must be stored
    alongside the parent rather than replacing it.
    """

    def setup_method(self):
        super().setup_method()
        self.settings.set_value(
            SettingsConstants.SETTING__BIP85_CHILD_SEEDS, SettingsConstants.OPTION__ENABLED
        )

    def test_bip85_child_is_stored_alongside_the_parent(self):
        parent = self.store_seed()

        session = UISession(script=(
            select(seed_views.SeedOptionsView.BIP85_CHILD_SEED)
            + select(seed_views.SeedBIP85SelectNumWordsView.WORDS_12)
            + [TypeKeys("0")]  # child index, typed on the real keyboard
            + select(seed_views.SeedWordsBackupTestPromptView.FINALIZE)
            + select(seed_views.SeedFinalizeView.FINALIZE)
        ))

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, real_screens=True),
                FlowStep(seed_views.SeedBIP85SelectNumWordsView, real_screens=True),
                FlowStep(seed_views.SeedBIP85SelectChildIndexView, real_screens=True),
                FlowStep(seed_views.SeedWordsBackupTestPromptView, real_screens=True),
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            initial_destination_view_args=dict(seed=parent),
            ui_session=session,
        )

        seeds = self.controller.storage.seeds
        assert len(seeds) == 2, f"expected parent + child, got {seeds!r}"
        assert seeds[0] is parent
        assert seeds[1].mnemonic_list != parent.mnemonic_list
        assert self.controller.storage.pending_seed is None



class TestSignMessageFlow(SeedFlowTest):
    """
    SeedOptions > Sign message. The message arrives by QR, so ScanView stays mocked
    (there is no button input to drive a camera decode); every confirmation screen
    after it is real.
    """

    DERIVATION_PATH = "m/84h/0h/0h/0/0"
    MESSAGE = "I attest that I control this bitcoin address"

    def test_sign_message_confirmations(self):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K
        from seedsigner.views import scan_views

        self.settings.set_value(
            SettingsConstants.SETTING__MESSAGE_SIGNING, SettingsConstants.OPTION__ENABLED
        )
        seed = self.store_seed()

        def load_message(view):
            view.decoder.add_data(f"signmessage {self.DERIVATION_PATH} ascii:{self.MESSAGE}")

        session = UISession(script=(
            select(0)        # SeedSelectSeedView: the one loaded seed
            + select(0)      # SeedSignMessageConfirmMessageView: Next
            + select(0)      # SeedSignMessageConfirmAddressView: Sign
            + [K.KEY_PRESS]  # any click dismisses the signature QR
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
                FlowStep(scan_views.ScanView, before_run=load_message),
                FlowStep(seed_views.SeedSignMessageStartView, is_redirect=True),
                FlowStep(seed_views.SeedSelectSeedView, real_screens=True),
                FlowStep(seed_views.SeedSignMessageConfirmMessageView, real_screens=True),
                FlowStep(seed_views.SeedSignMessageConfirmAddressView, real_screens=True),
                FlowStep(seed_views.SeedSignMessageSignedMessageQRView, real_screens=True),
                FlowStep(MainMenuView),
            ],
            ui_session=session,
        )

        assert self.controller.storage.seeds == [seed]


class TestEncryptedQRFlow(SeedFlowTest):
    """Backup > Export as SeedQR > Encrypted, typing the key on the real keyboards."""

    ENCRYPTION_KEY = "swordfish"
    MNEMONIC_ID = "wallet1"

    def setup_method(self):
        super().setup_method()
        self.settings.set_value(
            SettingsConstants.SETTING__ENCRYPTED_QR, SettingsConstants.OPTION__ENABLED
        )
        # The default GCM/CBC/CTR modes route through SeedEncryptedQRnonECBModeView,
        # which collects an IV from the camera -- no button input to drive. ECB has no
        # IV, so it goes straight to the mnemonic ID prompt this test is about.
        self.settings.set_value(
            SettingsConstants.SETTING__ENCRYPTION_MODE, SettingsConstants.ENCRYPTION_MODE_ECB
        )

    def test_typed_encryption_key_and_mnemonic_id(self):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K
        from seedsigner.gui.screens.scan_screens import ScanTypeEncryptionKeyScreen
        from seedsigner.gui.screens.seed_screens import SeedEncryptedQRMnemonicIDScreen
        from ui_driver import plan_text_entry_script

        seed = self.store_seed()

        key_script = plan_text_entry_script(
            ScanTypeEncryptionKeyScreen, self.ENCRYPTION_KEY, encryptionkey=""
        )
        id_script = plan_text_entry_script(
            SeedEncryptedQRMnemonicIDScreen, self.MNEMONIC_ID, mnemonic_id=""
        )

        session = UISession(script=(
            select(seed_views.SeedOptionsView.BACKUP)
            + select(seed_views.SeedBackupView.EXPORT_SEEDQR)
            + select("Encrypted")
            + select("Type encryption key")
            + key_script
            + select(0)          # accept the reviewed encryption key
            + select("Assign custom ID")
            + id_script
            + select("Proceed")   # accept the reviewed mnemonic ID
            + select("Transcribe mode")
            + [K.KEY_PRESS]       # the zoomed-in transcription view exits on any click
        ))

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, real_screens=True),
                FlowStep(seed_views.SeedBackupView, real_screens=True),
                FlowStep(seed_views.SeedTranscribeSeedQRFormatView, real_screens=True),
                FlowStep(seed_views.SeedTranscribeSeedQRWarningView, is_redirect=True),
                FlowStep(seed_views.SeedTranscribeSeedQRWholeQRView, real_screens=True),
                FlowStep(seed_views.SeedEncryptedQRTypeEncryptionKeyView, real_screens=True),
                FlowStep(seed_views.SeedEncryptedQRReviewEncryptionKeyView, real_screens=True),
                FlowStep(seed_views.SeedEncryptedQRMnemonicIDPromptView, real_screens=True),
                FlowStep(seed_views.SeedEncryptedQRMnemonicIDEntryView, real_screens=True),
                FlowStep(seed_views.SeedEncryptedQRReviewMnemonicIDView, real_screens=True),
                FlowStep(seed_views.SeedEncryptedQRTranscribeModePromptView, real_screens=True),
                FlowStep(seed_views.SeedEncryptedQRTranscribeModeView, real_screens=True),
                FlowStep(seed_views.SeedTranscribeEncryptedQRZoomedInView, real_screens=True),
            ],
            initial_destination_view_args=dict(seed=seed),
            ui_session=session,
        )

        assert self.controller.storage.seeds == [seed]



class TestSlip39ShareFlows(SeedFlowTest):
    """Loading a SLIP-39 seed from typed shares, and regenerating shares afterwards."""

    def setup_method(self):
        super().setup_method()
        self.settings.set_value(
            SettingsConstants.SETTING__SLIP39_SEEDS, SettingsConstants.OPTION__ENABLED
        )

    @staticmethod
    def make_shares(threshold=2, count=3, extendable=True) -> list:
        import shamir_mnemonic
        return shamir_mnemonic.generate_mnemonics(
            1, [(threshold, count)], bytes.fromhex("aa" * 16), extendable=extendable
        )[0]

    def test_typed_slip39_shares_combine_into_a_stored_seed(self):
        shares = self.make_shares(threshold=2, count=3)
        first, second = shares[0].split(), shares[1].split()

        session = UISession(script=(
            select("Enter 20 words")
            + type_words(first)
            + select(seed_views.SeedSlip39MoreSharesView.ADD)
            + type_words(second)
            + select(seed_views.SeedSlip39MoreSharesView.DONE)
            + select(seed_views.SeedFinalizeView.FINALIZE)
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
                FlowStep(seed_views.SeedsMenuView, is_redirect=True),
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.TYPE_SLIP39),
                FlowStep(seed_views.SeedSlip39MnemonicStartView, real_screens=True),
            ] + [
                FlowStep(seed_views.SeedSlip39ShareEntryView, real_screens=True)
                for _ in first
            ] + [
                FlowStep(seed_views.SeedSlip39MoreSharesView, real_screens=True),
            ] + [
                FlowStep(seed_views.SeedSlip39ShareEntryView, real_screens=True)
                for _ in second
            ] + [
                FlowStep(seed_views.SeedSlip39MoreSharesView, real_screens=True),
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            ui_session=session,
        )

        seed = self.assert_one_seed_stored()
        assert isinstance(seed, Slip39Seed)

    def test_regenerate_shares_on_a_stored_slip39_seed(self):
        shares = self.make_shares(threshold=2, count=3)
        seed = Slip39Seed(mnemonics=shares[:2])
        self.controller.storage.set_pending_seed(seed)
        self.controller.storage.finalize_pending_seed()

        with patch.object(seed_views.seed_screens, "SeedBIP85SelectChildIndexScreen") as index_screen:
            index_screen.return_value.display.side_effect = ["5", "3"]

            session = UISession(script=(
                select(seed_views.SeedOptionsView.BACKUP)
                + select(seed_views.SeedBackupView.REGENERATE_SHARES)
            ))
            self.run_sequence(
                [
                    FlowStep(seed_views.SeedOptionsView, real_screens=True),
                    FlowStep(seed_views.SeedBackupView, real_screens=True),
                    # Instantiates its index Screens directly, bypassing run_screen().
                    FlowStep(seed_views.SeedSlip39RegenerateSharesView, is_redirect=True),
                    FlowStep(seed_views.SeedWordsWarningView),
                ],
                initial_destination_view_args=dict(seed=seed),
                ui_session=session,
            )

        assert len(seed.mnemonic_list) == 5
        assert self.controller.storage.seeds == [seed]



class TestElectrumSeedEntryFlow(SeedFlowTest):
    """Seeds > Load a seed > Enter Electrum seed."""

    # A real Electrum segwit seed (generated by Electrum v4.5.5); a BIP-39 phrase
    # would fail Electrum's own checksum.
    ELECTRUM_MNEMONIC = (
        "bomb congress scorpion mutual word stamp tongue valid permit salmon yellow spy"
    ).split()

    def setup_method(self):
        super().setup_method()
        self.settings.set_value(
            SettingsConstants.SETTING__ELECTRUM_SEEDS, SettingsConstants.OPTION__ENABLED
        )

    def test_electrum_entry_stores_seed(self):
        session = UISession(script=(
            select(0)  # "I Understand" on the Electrum warning
            + type_words(self.ELECTRUM_MNEMONIC)
            + select(seed_views.SeedFinalizeView.FINALIZE)
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
                FlowStep(seed_views.SeedsMenuView, is_redirect=True),
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.TYPE_ELECTRUM),
                FlowStep(seed_views.SeedElectrumMnemonicStartView, real_screens=True),
            ] + [
                FlowStep(seed_views.SeedMnemonicEntryView, real_screens=True)
                for _ in self.ELECTRUM_MNEMONIC
            ] + [
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            ui_session=session,
        )

        seed = self.assert_one_seed_stored()
        assert seed.mnemonic_list == self.ELECTRUM_MNEMONIC



class TestHardwareWalletBackupFlows(SeedFlowTest):
    """
    Seeds > Load a seed > a hardware-wallet backup on the microSD card.

    The card is a real temp directory swapped in for MicroSD.get_microsd_dir(), so the
    Views do their actual file discovery and decoding.
    """

    def setup_method(self):
        super().setup_method()
        # Each backup type is behind its own setting; LoadSeedView omits the option
        # entirely when it is disabled.
        for setting in (
            SettingsConstants.SETTING__BITBOX_BACKUP,
            SettingsConstants.SETTING__PASSPORT_BACKUP,
            SettingsConstants.SETTING__TAPSIGNER_BACKUP,
        ):
            self.settings.set_value(setting, SettingsConstants.OPTION__ENABLED)

    def use_microsd(self, monkeypatch, tmp_path):
        from seedsigner.hardware.microsd import MicroSD
        monkeypatch.setattr(MicroSD, "get_microsd_dir", staticmethod(lambda: tmp_path))
        return tmp_path

    def test_tapsigner_backup_loads_the_xprv(self, monkeypatch, tmp_path):
        from Cryptodome.Cipher import AES
        from embit import bip32

        card = self.use_microsd(monkeypatch, tmp_path)

        # A real TAPSIGNER backup: AES-CTR over "<xprv>\n<derivation path>\n".
        key_hex = "00112233445566778899aabbccddeeff"
        root = bip32.HDKey.from_seed(Seed(mnemonic=MNEMONIC_12).seed_bytes)
        plaintext = f"{root.to_base58()}\nm/84h/0h/0h\n".encode()
        cipher = AES.new(bytes.fromhex(key_hex), AES.MODE_CTR, nonce=b"", initial_value=0)
        (card / "backup.aes").write_bytes(cipher.encrypt(plaintext))

        session = UISession(script=(
            select(0)             # the one backup file on the card
            + [TypeKeys(key_hex)]  # the backup key, typed on the real keyboard
            + select(0)           # accept the summary
            + select(seed_views.SeedFinalizeView.FINALIZE)
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
                FlowStep(seed_views.SeedsMenuView, is_redirect=True),
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.TAPSIGNER_BACKUP),
                FlowStep(seed_views.SeedTapsignerBackupSelectView, real_screens=True),
                FlowStep(seed_views.SeedTapsignerBackupKeyEntryView, real_screens=True),
                FlowStep(seed_views.SeedTapsignerBackupSummaryView, real_screens=True),
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            ui_session=session,
        )

        self.assert_one_seed_stored()

    def test_passport_code_entry_screen_opens(self, monkeypatch, tmp_path):
        """
        Reaching the Passport code entry at all is the assertion here.

        Both this View and SeedTapsignerBackupKeyEntryView instantiate a bare
        KeyboardScreen, whose custom_additional_keys defaults to the
        Keyboard.ADDITIONAL_KEYS *dict*. Keyboard.__init__ iterated that expecting key
        dicts, so it read `"<code string>"["size"]` and raised TypeError before the
        screen could draw -- these two screens crashed on device. The flow backs out
        via the top nav once the keyboard is up.
        """
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        card = self.use_microsd(monkeypatch, tmp_path)
        (card / "backup.7z").write_bytes(b"not a real archive")

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
                FlowStep(seed_views.SeedsMenuView, is_redirect=True),
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.PASSPORT_BACKUP),
                FlowStep(seed_views.SeedPassportBackupSelectView, real_screens=True),
                FlowStep(seed_views.SeedPassportBackupCodeEntryView, real_screens=True),
                FlowStep(seed_views.SeedPassportBackupSelectView),
            ],
            # Pick the one backup file, then KEY_UP to the back arrow and click it.
            ui_session=UISession(script=select(0) + [K.KEY_UP, K.KEY_PRESS]),
        )

        assert self.controller.storage.seeds == []

    @pytest.mark.parametrize(
        "option, view",
        [
            ("TAPSIGNER_BACKUP", "SeedTapsignerBackupSelectView"),
            ("BITBOX_BACKUP", "SeedBitbox02BackupSelectView"),
            ("PASSPORT_BACKUP", "SeedPassportBackupSelectView"),
        ],
    )
    def test_no_backup_files_warns_instead_of_crashing(self, monkeypatch, tmp_path, option, view):
        """An empty card must reach the warning screen, not an exception."""
        self.use_microsd(monkeypatch, tmp_path)

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
                FlowStep(seed_views.SeedsMenuView, is_redirect=True),
                FlowStep(seed_views.LoadSeedView, button_data_selection=getattr(seed_views.LoadSeedView, option)),
                FlowStep(getattr(seed_views, view), real_screens=True),
                FlowStep(seed_views.LoadSeedView),
            ],
            ui_session=UISession(script=select(0)),  # "OK" on the warning
        )

        assert self.controller.storage.seeds == []


class TestScanSeedQRFlow(SeedFlowTest):
    """
    Seeds > Load a seed > Scan a SeedQR.

    The ScanView step stays mocked -- it decodes camera frames rather than button
    input -- but the finalize screens after it are real, and the seed must land in
    storage exactly as the typed and generated paths do.
    """

    def test_scanned_seedqr_is_stored(self):
        from seedsigner.views import scan_views

        def load_seedqr(view):
            # A 12-word SeedQR: eleven "abandon" indices plus the checksum word.
            view.decoder.add_data("0000" * 11 + "0003")

        session = UISession(script=select(seed_views.SeedFinalizeView.FINALIZE))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
                FlowStep(seed_views.SeedsMenuView, is_redirect=True),
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.SEED_QR),
                FlowStep(scan_views.ScanSeedQRView, before_run=load_seedqr),
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            ui_session=session,
        )

        seed = self.assert_one_seed_stored()
        assert seed.mnemonic_list[0] == "abandon"



class TestAddressVerificationFlow(SeedFlowTest):
    """
    Tools > Verify address. The address arrives by QR (ScanView stays mocked); the
    seed picker and the verification screens are real.
    """

    def test_singlesig_address_verifies_against_the_loaded_seed(self):
        from seedsigner.views import scan_views

        self.settings.set_value(
            SettingsConstants.SETTING__NETWORK, SettingsConstants.REGTEST
        )
        seed = self.store_seed(["abandon"] * 11 + ["about"])

        def load_address(view):
            # Native segwit regtest receive address at index 6 of this seed.
            view.decoder.add_data("bcrt1q4e9q5taxnsvc6m0uxv6h75mkzvnkxeqk6l90u2")

        session = UISession(script=select(0))  # the one loaded seed

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
                FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.VERIFY_ADDRESS),
                FlowStep(scan_views.ScanAddressView, before_run=load_address),
                FlowStep(seed_views.AddressVerificationStartView, is_redirect=True),
                FlowStep(seed_views.SeedSelectSeedView, real_screens=True),
                FlowStep(seed_views.SeedAddressVerificationView),
                FlowStep(seed_views.SeedAddressVerificationSuccessView),
            ],
            ui_session=session,
        )

        assert self.controller.storage.seeds == [seed]



class TestPendingSeedSentinel(SeedFlowTest):
    """
    Unit-level guards for the sentinel itself.

    `seed=None` means "the pending seed, not yet stored". Views that resolve it for
    display must hand the sentinel onward, or the last step of the flow cannot tell a
    brand new seed from one that is already in storage -- and stops storing it. These
    assert the contract directly, so a regression names the responsible View instead
    of surfacing as a puzzling end-of-flow assertion.
    """

    def pending_seed(self) -> Seed:
        seed = Seed(mnemonic=MNEMONIC_12)
        self.controller.storage.set_pending_seed(seed)
        return seed

    def test_seed_words_view_resolves_but_preserves_the_sentinel(self):
        pending = self.pending_seed()

        view = seed_views.SeedWordsView(seed=None)
        assert view.is_pending_seed is True
        assert view.seed is pending  # resolved, so the words can be displayed

        with patch.object(seed_views.SeedWordsView, "run_screen", return_value=0):
            destination = view.run()
        assert destination.view_args["seed"] is None, "the sentinel must survive this View"

    def test_seed_words_view_keeps_a_real_seed(self):
        stored = self.store_seed()

        view = seed_views.SeedWordsView(seed=stored)
        assert view.is_pending_seed is False

        with patch.object(seed_views.SeedWordsView, "run_screen", return_value=0):
            destination = view.run()
        assert destination.view_args["seed"] is stored

    def test_backup_test_view_resolves_but_preserves_the_sentinel(self):
        pending = self.pending_seed()

        view = seed_views.SeedWordsBackupTestView(seed=None, rand_seed=0)
        assert view.is_pending_seed is True
        assert view.seed is pending

        with no_shuffle(), patch.object(seed_views.SeedWordsBackupTestView, "run_screen", return_value=0):
            destination = view.run()
        assert destination.view_args["seed"] is None

    def test_backup_test_view_copies_the_confirmed_list(self):
        """
        Each Destination must carry its own list. Destination.__eq__ compares
        view_args, so a shared mutable list makes every stacked backup-test
        Destination compare equal and collapses the back stack.
        """
        self.pending_seed()

        view = seed_views.SeedWordsBackupTestView(seed=None, rand_seed=0)
        with no_shuffle(), patch.object(seed_views.SeedWordsBackupTestView, "run_screen", return_value=0):
            destination = view.run()

        assert destination.view_args["confirmed_list"] is not view.confirmed_list
        assert destination.view_args["confirmed_list"] == view.confirmed_list

    def test_discard_view_distinguishes_pending_from_stored(self):
        pending = self.pending_seed()

        view = seed_views.SeedDiscardView()
        assert view.is_pending_seed is True
        assert view.seed is pending

        stored = self.store_seed(
            "payment artist half drive borrow speak make crouch payment artist half drill".split()
        )
        assert seed_views.SeedDiscardView(seed=stored).is_pending_seed is False

    def test_discard_view_clears_a_pending_seed_without_touching_storage(self):
        """
        The pending seed is not in storage.seeds, so discarding it must call
        clear_pending_seed(); discard_seed() would raise ValueError from list.remove().
        """
        self.pending_seed()

        view = seed_views.SeedDiscardView()
        with patch.object(seed_views.SeedDiscardView, "run_screen", return_value=1):  # DISCARD
            view.run()

        assert self.controller.storage.pending_seed is None
        assert self.controller.storage.seeds == []
