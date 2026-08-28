"""
Flow tests for the seed-backup family: SLIP-39 share handling, the mnemonic
backup verification test, and BIP-85 child derivation.

These flows are the ones that read secret material -- share mnemonics, the
BIP-85 child mnemonic, the words the user is asked to confirm -- so a routing
regression here is not merely cosmetic: it can send the user through a backup
they did not actually verify, or show them the wrong share.

Two harness notes:

* Several views in this family call ``SomeScreen(...).display()`` directly
  rather than going through ``View.run_screen()``. ``FlowTest`` hooks
  ``run_screen``, so those calls are invisible to it and must be patched at the
  Screen class. A FlowStep for such a view also needs ``is_redirect=True``,
  which is what tells the harness "this view legitimately returned a
  Destination without running a Screen".
* ``SeedWordsBackupTestView`` shuffles its four candidate words, so the index of
  the correct answer is random. ``no_shuffle`` pins the real word to slot 0,
  making ``screen_return_value=0`` "answer correctly" and any other index
  "answer wrong".
"""
from contextlib import contextmanager
from unittest.mock import patch

import shamir_mnemonic

# Must import test base before the Controller
from base import FlowTest, FlowStep

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.seed import Seed, Slip39Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.views import seed_views


BIP39_MNEMONIC = "blush twice taste dawn feed second opinion lazy thumb play neglect impact".split()


@contextmanager
def no_shuffle():
    """Pin SeedWordsBackupTestView's correct answer to button_data[0]."""
    with patch("seedsigner.views.seed_views.random.shuffle", lambda seq: None):
        yield


@contextmanager
def index_screen(return_value):
    """
    Stub SeedBIP85SelectChildIndexScreen, which several views instantiate and
    ``.display()`` directly instead of via run_screen().
    """
    values = return_value if isinstance(return_value, list) else [return_value]
    with patch.object(seed_views.seed_screens, "SeedBIP85SelectChildIndexScreen") as mock:
        mock.return_value.display.side_effect = values
        yield mock


class TestSeedBackupFlows(FlowTest):

    def store_bip39_seed(self) -> Seed:
        seed = Seed(mnemonic=BIP39_MNEMONIC)
        self.controller.storage.set_pending_seed(seed)
        return self.controller.storage.finalize_pending_seed()

    def store_slip39_seed(self, extendable: bool = True, threshold: int = 2, count: int = 3) -> Slip39Seed:
        secret = bytes.fromhex("aa" * 16)
        shares = shamir_mnemonic.generate_mnemonics(
            1, [(threshold, count)], secret, extendable=extendable
        )[0]
        seed = Slip39Seed(mnemonics=shares[:threshold])
        self.controller.storage.set_pending_seed(seed)
        return self.controller.storage.finalize_pending_seed()

    # ------------------------------------------------------------------
    # SLIP-39 share regeneration
    # ------------------------------------------------------------------

    def test_slip39_regenerate_shares_flow(self):
        """
        Backup > Regenerate Shares on an extendable SLIP-39 seed should prompt for
        a share count and threshold, regenerate, and land on the words review for
        the first new share.
        """
        seed = self.store_slip39_seed(extendable=True)
        original_shares = list(seed.mnemonic_list)

        with index_screen(["5", "3"]):
            self.run_sequence(
                initial_destination_view_args=dict(seed=seed),
                sequence=[
                    FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.BACKUP),
                    FlowStep(seed_views.SeedBackupView, button_data_selection=seed_views.SeedBackupView.REGENERATE_SHARES),
                    FlowStep(seed_views.SeedSlip39RegenerateSharesView, is_redirect=True),
                    FlowStep(seed_views.SeedWordsWarningView),
                ],
            )

        # The regeneration actually happened, on the seed held in storage.
        assert len(seed.mnemonic_list) == 5
        assert seed.mnemonic_list != original_shares
        assert seed is self.controller.storage.seeds[0]

        # ...and the new shares still reconstruct the same secret.
        recovered = shamir_mnemonic.combine_mnemonics(seed.mnemonic_list[:3])
        assert recovered == seed.seed_bytes

    def test_slip39_regenerate_shares_rejects_nonextendable(self):
        """A non-extendable SLIP-39 seed cannot regenerate; it must back out."""
        seed = self.store_slip39_seed(extendable=False)
        original_shares = list(seed.mnemonic_list)

        self.run_sequence(
            initial_destination_view_args=dict(seed=seed),
            sequence=[
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.BACKUP),
                FlowStep(seed_views.SeedBackupView, button_data_selection=seed_views.SeedBackupView.REGENERATE_SHARES),
                FlowStep(seed_views.SeedSlip39RegenerateSharesView, screen_return_value=0),
                # Returns to BackStackView, which resolves to the previous view.
                FlowStep(seed_views.SeedBackupView),
            ],
        )

        assert seed.mnemonic_list == original_shares

    def test_slip39_regenerate_shares_back_out_of_share_count(self):
        """Backing out of the share-count prompt must not mutate the seed."""
        seed = self.store_slip39_seed(extendable=True)
        original_shares = list(seed.mnemonic_list)

        with index_screen(RET_CODE__BACK_BUTTON):
            self.run_sequence(
                initial_destination_view_args=dict(seed=seed),
                sequence=[
                    FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.BACKUP),
                    FlowStep(seed_views.SeedBackupView, button_data_selection=seed_views.SeedBackupView.REGENERATE_SHARES),
                    FlowStep(seed_views.SeedSlip39RegenerateSharesView, is_redirect=True),
                    FlowStep(seed_views.SeedBackupView),
                ],
            )

        assert seed.mnemonic_list == original_shares

    # ------------------------------------------------------------------
    # SLIP-39 share viewing
    # ------------------------------------------------------------------

    def test_slip39_view_words_selects_a_share_first(self):
        """
        A SLIP-39 seed has no single mnemonic, so "View seed words" must route
        through share selection and then show that share's words.
        """
        seed = self.store_slip39_seed()

        self.run_sequence(
            initial_destination_view_args=dict(seed=seed),
            sequence=[
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.BACKUP),
                FlowStep(seed_views.SeedBackupView, button_data_selection=seed_views.SeedBackupView.VIEW_WORDS),
                FlowStep(seed_views.SeedSlip39SelectShareView, screen_return_value=1),  # 2nd share
                FlowStep(seed_views.SeedWordsWarningView, screen_return_value=0),  # "I Understand"
                FlowStep(seed_views.SeedWordsView),
            ],
        )

    def test_slip39_share_selection_propagates_chosen_share(self):
        """
        The picked share index must reach the next view. If it were dropped the
        user would be shown -- and asked to back up -- the wrong share, which is
        silent and unrecoverable at restore time.
        """
        seed = self.store_slip39_seed(threshold=2, count=3)
        captured = {}

        def capture_share_index(view):
            captured["share_index"] = view.share_index
            captured["mnemonic"] = view.seed.mnemonic_list[view.share_index]

        self.run_sequence(
            initial_destination_view_args=dict(seed=seed, next_view=seed_views.SeedWordsWarningView),
            sequence=[
                FlowStep(seed_views.SeedSlip39SelectShareView, screen_return_value=1),
                FlowStep(seed_views.SeedWordsWarningView, before_run=capture_share_index,
                         screen_return_value=0),
                FlowStep(seed_views.SeedWordsView),
            ],
        )

        assert captured["share_index"] == 1
        assert captured["mnemonic"] == seed.mnemonic_list[1]

    def test_slip39_share_selection_back_button(self):
        """Backing out of share selection returns to the backup menu."""
        seed = self.store_slip39_seed()

        self.run_sequence(
            initial_destination_view_args=dict(seed=seed),
            sequence=[
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.BACKUP),
                FlowStep(seed_views.SeedBackupView, button_data_selection=seed_views.SeedBackupView.VIEW_WORDS),
                FlowStep(seed_views.SeedSlip39SelectShareView, screen_return_value=RET_CODE__BACK_BUTTON),
                FlowStep(seed_views.SeedBackupView),
            ],
        )

    # ------------------------------------------------------------------
    # Mnemonic backup verification test
    # ------------------------------------------------------------------

    def test_backup_test_all_words_correct(self):
        """Answering every word correctly reaches the success screen."""
        seed = self.store_bip39_seed()

        sequence = [
            FlowStep(seed_views.SeedWordsBackupTestPromptView,
                     button_data_selection=seed_views.SeedWordsBackupTestPromptView.VERIFY),
        ]
        # One correct answer per word; the real word is pinned to slot 0.
        sequence += [FlowStep(seed_views.SeedWordsBackupTestView, screen_return_value=0)
                     for _ in range(len(BIP39_MNEMONIC))]
        sequence.append(FlowStep(seed_views.SeedWordsBackupTestSuccessView))

        with no_shuffle():
            self.run_sequence(
                initial_destination_view_args=dict(seed=seed),
                sequence=sequence,
            )

    def test_backup_test_wrong_word_then_retry(self):
        """A wrong answer routes to the mistake screen; Try Again re-asks."""
        seed = self.store_bip39_seed()

        with no_shuffle():
            self.run_sequence(
                initial_destination_view_args=dict(seed=seed),
                sequence=[
                    FlowStep(seed_views.SeedWordsBackupTestPromptView,
                             button_data_selection=seed_views.SeedWordsBackupTestPromptView.VERIFY),
                    FlowStep(seed_views.SeedWordsBackupTestView, screen_return_value=1),  # a decoy
                    FlowStep(seed_views.SeedWordsBackupTestMistakeView,
                             button_data_selection=seed_views.SeedWordsBackupTestMistakeView.RETRY),
                    FlowStep(seed_views.SeedWordsBackupTestView),
                ],
            )

    def test_backup_test_wrong_word_then_review(self):
        """A wrong answer offers a route back to reviewing the words."""
        seed = self.store_bip39_seed()

        with no_shuffle():
            self.run_sequence(
                initial_destination_view_args=dict(seed=seed),
                sequence=[
                    FlowStep(seed_views.SeedWordsBackupTestPromptView,
                             button_data_selection=seed_views.SeedWordsBackupTestPromptView.VERIFY),
                    FlowStep(seed_views.SeedWordsBackupTestView, screen_return_value=1),
                    FlowStep(seed_views.SeedWordsBackupTestMistakeView,
                             button_data_selection=seed_views.SeedWordsBackupTestMistakeView.REVIEW),
                    FlowStep(seed_views.SeedWordsView),
                ],
            )

    def test_backup_test_skip_returns_to_seed_options(self):
        """Skipping verification on a stored seed returns to its options menu."""
        seed = self.store_bip39_seed()

        self.run_sequence(
            initial_destination_view_args=dict(seed=seed),
            sequence=[
                FlowStep(seed_views.SeedWordsBackupTestPromptView,
                         button_data_selection=seed_views.SeedWordsBackupTestPromptView.SKIP),
                FlowStep(seed_views.SeedOptionsView),
            ],
        )

    def test_backup_test_review_shows_words(self):
        """The Review option re-enters the words display."""
        seed = self.store_bip39_seed()

        self.run_sequence(
            initial_destination_view_args=dict(seed=seed),
            sequence=[
                FlowStep(seed_views.SeedWordsBackupTestPromptView,
                         button_data_selection=seed_views.SeedWordsBackupTestPromptView.REVIEW),
                FlowStep(seed_views.SeedWordsWarningView, screen_return_value=0),
                FlowStep(seed_views.SeedWordsView),
            ],
        )

    # ------------------------------------------------------------------
    # BIP-85 child derivation
    # ------------------------------------------------------------------

    def test_bip85_child_seed_flow(self):
        """Deriving a BIP-85 child walks num-words, index, then the backup prompt."""
        seed = self.store_bip39_seed()
        self.settings.set_value(SettingsConstants.SETTING__BIP85_CHILD_SEEDS, SettingsConstants.OPTION__ENABLED)

        self.run_sequence(
            initial_destination_view_args=dict(seed=seed),
            sequence=[
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.BIP85_CHILD_SEED),
                FlowStep(seed_views.SeedBIP85SelectNumWordsView,
                         button_data_selection=seed_views.SeedBIP85SelectNumWordsView.WORDS_12),
                FlowStep(seed_views.SeedBIP85SelectChildIndexView, screen_return_value="0"),
                FlowStep(seed_views.SeedWordsBackupTestPromptView),
            ],
        )

    def test_bip85_invalid_child_index_flow(self):
        """An out-of-range child index must be refused and re-prompted."""
        seed = self.store_bip39_seed()
        self.settings.set_value(SettingsConstants.SETTING__BIP85_CHILD_SEEDS, SettingsConstants.OPTION__ENABLED)

        self.run_sequence(
            initial_destination_view_args=dict(seed=seed),
            sequence=[
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.BIP85_CHILD_SEED),
                FlowStep(seed_views.SeedBIP85SelectNumWordsView,
                         button_data_selection=seed_views.SeedBIP85SelectNumWordsView.WORDS_24),
                FlowStep(seed_views.SeedBIP85SelectChildIndexView, screen_return_value=str(2**31)),
                FlowStep(seed_views.SeedBIP85InvalidChildIndexView, screen_return_value=0),
                FlowStep(seed_views.SeedBIP85SelectChildIndexView),
            ],
        )
