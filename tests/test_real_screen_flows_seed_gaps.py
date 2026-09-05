"""
    The seed views the main real-screen suite does not reach.

    tests/test_real_screen_flows_seed.py walks each seed workflow along its happy path.
    That leaves the edges: the dialogs you get for backing out, the screens that report a
    bad share or an out-of-range index, the confirm-scan outcomes, and the export paths
    behind a non-default setting. Several of these Views had never been constructed by
    any test at all.

    Where a flow needs a camera the scan step is stood in for, as elsewhere -- but the
    screens that read the *result* of that scan are real, and those are the ones being
    covered here.
"""

from unittest.mock import MagicMock, patch

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import FlowStep, FlowTest
from real_screen_fixtures import use_microsd
from ui_driver import Back, TypeKeys, UISession, select, type_words

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.views import seed_views
from seedsigner.views.view import MainMenuView


MNEMONIC_12 = "blush twice taste dawn feed second opinion lazy thumb play neglect impact".split()


class SeedGapTest(FlowTest):

    def setup_method(self):
        super().setup_method()
        self.settings.set_value(
            SettingsConstants.SETTING__DIRE_WARNINGS, SettingsConstants.OPTION__DISABLED
        )

    def store_seed(self, mnemonic=None) -> Seed:
        seed = Seed(mnemonic=mnemonic or MNEMONIC_12)
        self.controller.storage.set_pending_seed(seed)
        return self.controller.storage.finalize_pending_seed()

    def load_seed_menu(self) -> list:
        """Main menu into the "Load a seed" list."""
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
            FlowStep(seed_views.SeedsMenuView, is_redirect=True),
        ]



class TestAezeedEntry(SeedGapTest):
    """Load a seed > Enter Aezeed seed. Its warning screen was never constructed."""

    def test_aezeed_start_warns_then_enters_words(self):
        self.settings.set_value(
            SettingsConstants.SETTING__AEZEED_SEEDS, SettingsConstants.OPTION__ENABLED
        )

        self.run_sequence(
            self.load_seed_menu() + [
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.TYPE_AEZEED),
                FlowStep(seed_views.SeedAezeedMnemonicStartView, real_screens=True),
                FlowStep(seed_views.SeedMnemonicEntryView),
            ],
            ui_session=UISession(script=select(0)),
        )



class TestSlip39InvalidShare(SeedGapTest):
    """
    An invalid SLIP-39 share must say so and offer another go, rather than failing
    silently or dropping the user out of the flow.
    """

    def setup_method(self):
        super().setup_method()
        self.settings.set_value(
            SettingsConstants.SETTING__SLIP39_SEEDS, SettingsConstants.OPTION__ENABLED
        )

    def test_invalid_share_offers_a_retry(self):
        # A syntactically valid SLIP-39 word list whose checksum is wrong.
        bad_share = ["academic"] * 20

        session = UISession(script=(
            select("Enter 20 words")
            + type_words(bad_share)
            + select(0)  # "Try Again" on the invalid-share warning
        ))

        self.run_sequence(
            self.load_seed_menu() + [
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.TYPE_SLIP39),
                FlowStep(seed_views.SeedSlip39MnemonicStartView, real_screens=True),
            ] + [
                FlowStep(seed_views.SeedSlip39ShareEntryView, real_screens=True)
                for _ in bad_share
            ] + [
                FlowStep(seed_views.SeedSlip39ShareInvalidView, real_screens=True),
                FlowStep(seed_views.SeedSlip39ShareEntryView),
            ],
            ui_session=session,
        )



class TestCustomDerivationExport(SeedGapTest):
    """
    Export xpub with a custom derivation path.

    Both `SeedExportXpubCustomDerivationView` and `AccountNumberView` sit behind
    non-default settings, which is why neither had been driven.
    """

    def test_custom_derivation_path_is_typed(self):
        from seedsigner.gui.screens.seed_screens import SeedExportXpubCustomDerivationScreen
        from ui_driver import plan_keyboard_screen_script

        seed = self.store_seed()
        self.settings.set_value(
            SettingsConstants.SETTING__SCRIPT_TYPES, [SettingsConstants.CUSTOM_DERIVATION]
        )
        self.settings.set_value(
            SettingsConstants.SETTING__XPUB_QR_FORMAT,
            [SettingsConstants.XPUB_QR_FORMAT__SPECTER_LEGACY],
        )

        # The keyboard's charset is "/'0123456789" -- no letters -- and the screen
        # opens pre-filled with "m/", so only the rest of the path is typed, and
        # hardened levels are the apostrophe form.
        derivation_script = plan_keyboard_screen_script(
            SeedExportXpubCustomDerivationScreen, "48'/0'/0'/2'"
        )
        session = UISession(script=(
            select(seed_views.SeedOptionsView.EXPORT_XPUB)
            + select(seed_views.SeedExportXpubSigTypeView.SINGLE_SIG)
            + derivation_script
        ))

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, real_screens=True),
                FlowStep(seed_views.SeedExportXpubSigTypeView, real_screens=True),
                FlowStep(seed_views.SeedExportXpubScriptTypeView, is_redirect=True),
                FlowStep(seed_views.SeedExportXpubCustomDerivationView, real_screens=True),
                FlowStep(seed_views.SeedExportXpubQRFormatView),
            ],
            initial_destination_view_args=dict(seed=seed),
            ui_session=session,
        )



class TestSeedQRConfirmOutcomes(SeedGapTest):
    """
    The three ways confirming a transcribed SeedQR can end.

    `SeedTranscribeSeedQRConfirmScanView` drives a ScanScreen directly rather than
    exposing `view.decoder`, so the camera is stood in for at that one point; the three
    outcome screens after it are real, and none had ever been constructed.
    """

    def confirm_steps(self, seed) -> list:
        return [
            FlowStep(seed_views.SeedOptionsView, real_screens=True),
            FlowStep(seed_views.SeedBackupView, real_screens=True),
            FlowStep(seed_views.SeedTranscribeSeedQRFormatView, real_screens=True),
            FlowStep(seed_views.SeedTranscribeSeedQRWarningView, is_redirect=True),
            FlowStep(seed_views.SeedTranscribeSeedQRWholeQRView, real_screens=True),
            FlowStep(seed_views.SeedTranscribeSeedQRZoomedInView, real_screens=True),
            FlowStep(seed_views.SeedTranscribeSeedQRConfirmQRPromptView, real_screens=True),
        ]

    def confirm_script(self):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        return (
            select(seed_views.SeedOptionsView.BACKUP)
            + select(seed_views.SeedBackupView.EXPORT_SEEDQR)
            + select(0)      # standard SeedQR format
            + select(0)      # whole-QR screen
            + [K.KEY_PRESS]  # zoomed-in transcription exits on any click
            + select(seed_views.SeedTranscribeSeedQRConfirmQRPromptView.SCAN)
        )

    @pytest.mark.parametrize(
        "scanned_matches, outcome_view",
        [
            (True, "SeedTranscribeSeedQRConfirmSuccessView"),
            (False, "SeedTranscribeSeedQRConfirmWrongSeedView"),
        ],
    )
    def test_confirm_scan_outcome(self, scanned_matches, outcome_view):
        seed = self.store_seed()
        scanned = MNEMONIC_12 if scanned_matches else (
            "payment artist half drive borrow speak make crouch payment artist half drill".split()
        )

        decoder = MagicMock()
        decoder.is_complete = True
        decoder.is_seed = True
        decoder.get_seed_phrase.return_value = scanned

        session = UISession(script=self.confirm_script() + select(0))

        with patch("seedsigner.gui.screens.scan_screens.ScanScreen"), \
                patch("seedsigner.models.decode_qr.DecodeQR", return_value=decoder):
            self.run_sequence(
                self.confirm_steps(seed) + [
                    # Goes through run_screen(ScanScreen), so FlowTest sees the call and
                    # the mocked return stands in for the camera.
                    FlowStep(seed_views.SeedTranscribeSeedQRConfirmScanView),
                    FlowStep(getattr(seed_views, outcome_view), real_screens=True),
                ],
                initial_destination_view_args=dict(seed=seed),
                ui_session=session,
            )

    def test_confirm_scan_of_a_non_seed_qr(self):
        """Scanning something that isn't a SeedQR at all is its own outcome screen."""
        seed = self.store_seed()

        decoder = MagicMock()
        decoder.is_complete = True
        decoder.is_seed = False

        session = UISession(script=self.confirm_script() + select(0))

        with patch("seedsigner.gui.screens.scan_screens.ScanScreen"), \
                patch("seedsigner.models.decode_qr.DecodeQR", return_value=decoder):
            self.run_sequence(
                self.confirm_steps(seed) + [
                    FlowStep(seed_views.SeedTranscribeSeedQRConfirmScanView),
                    FlowStep(seed_views.SeedTranscribeSeedQRConfirmInvalidQRView, real_screens=True),
                ],
                initial_destination_view_args=dict(seed=seed),
                ui_session=session,
            )



class TestPlaintextQRExport(SeedGapTest):
    """Backup > Export as Plaintext QR -- behind a setting, so never driven."""

    def test_plaintext_qr_renders(self):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        seed = self.store_seed()
        self.settings.set_value(
            SettingsConstants.SETTING__PLAINTEXTQR, SettingsConstants.OPTION__ENABLED
        )

        session = UISession(script=(
            select(seed_views.SeedOptionsView.BACKUP)
            + select(seed_views.SeedBackupView.EXPORT_PLAINTEXTQR)
            + [K.KEY_PRESS]  # any click dismisses the QR
        ))

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, real_screens=True),
                FlowStep(seed_views.SeedBackupView, real_screens=True),
                FlowStep(seed_views.SeedExportPlaintextQRView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView),
            ],
            initial_destination_view_args=dict(seed=seed),
            ui_session=session,
        )



class TestPassphraseExitDialog(SeedGapTest):
    """
    Backing out of passphrase entry with text still typed asks whether to keep it.

    The entry screen's return value is mocked rather than typed-then-backed-out: it
    returns a dict carrying `is_back_button`, and reproducing that by driving the
    multi-keyboard is a lot of script for no extra coverage. The dialog itself -- the
    View that had never been constructed -- runs for real.
    """

    def test_exit_dialog_offers_edit_and_discard(self):
        self.settings.set_value(
            SettingsConstants.SETTING__PASSPHRASE, SettingsConstants.OPTION__ENABLED
        )
        self.controller.storage.set_pending_seed(Seed(mnemonic=MNEMONIC_12))

        session = UISession(script=select(seed_views.SeedAddPassphraseExitDialogView.EDIT))

        self.run_sequence(
            [
                FlowStep(
                    seed_views.SeedAddPassphraseView,
                    screen_return_value={"passphrase": "abc", "is_back_button": True},
                ),
                FlowStep(seed_views.SeedAddPassphraseExitDialogView, real_screens=True),
                FlowStep(seed_views.SeedAddPassphraseView),
            ],
            ui_session=session,
        )

    def test_exit_dialog_discard_clears_the_passphrase(self):
        self.settings.set_value(
            SettingsConstants.SETTING__PASSPHRASE, SettingsConstants.OPTION__ENABLED
        )
        self.controller.storage.set_pending_seed(Seed(mnemonic=MNEMONIC_12))

        session = UISession(script=select(seed_views.SeedAddPassphraseExitDialogView.DISCARD))

        self.run_sequence(
            [
                FlowStep(
                    seed_views.SeedAddPassphraseView,
                    screen_return_value={"passphrase": "abc", "is_back_button": True},
                ),
                FlowStep(seed_views.SeedAddPassphraseExitDialogView, real_screens=True),
                FlowStep(seed_views.SeedFinalizeView),
            ],
            ui_session=session,
        )

        assert self.controller.storage.pending_seed.passphrase == ""



class TestBip85InvalidChildIndex(SeedGapTest):
    """An out-of-range BIP-85 child index gets its own screen."""

    def setup_method(self):
        super().setup_method()
        self.settings.set_value(
            SettingsConstants.SETTING__BIP85_CHILD_SEEDS, SettingsConstants.OPTION__ENABLED
        )

    def test_out_of_range_index_warns(self):
        seed = self.store_seed()

        session = UISession(script=(
            select(seed_views.SeedOptionsView.BIP85_CHILD_SEED)
            + select(seed_views.SeedBIP85SelectNumWordsView.WORDS_12)
            + select(0)  # acknowledge the invalid-index warning
        ))

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, real_screens=True),
                FlowStep(seed_views.SeedBIP85SelectNumWordsView, real_screens=True),
                # This View reaches its index screen through run_screen(), so the
                # mocked return is the seam -- 2**31 is the first index out of range.
                FlowStep(seed_views.SeedBIP85SelectChildIndexView,
                         screen_return_value=str(2 ** 31)),
                FlowStep(seed_views.SeedBIP85InvalidChildIndexView, real_screens=True),
            ],
            initial_destination_view_args=dict(seed=seed),
            ui_session=session,
        )
