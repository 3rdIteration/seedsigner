"""
    Real-screen flow tests for the Tools menu.

    The password generator is the standout gap here: it had no flow test at all before
    this, only unit-level view tests, despite producing a secret the user is expected to
    keep. Address Explorer and Verify Address had deep mocked coverage but no real
    screens, and the MicroSD tools and Network Info were only ever entered and backed
    out of.

    Anything that writes to a block device is stubbed -- these tests walk the
    confirmation screens, never the `dd`.
"""

from unittest.mock import patch

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import FlowStep, FlowTest
from real_screen_fixtures import use_microsd
from ui_driver import Back, TypeKeys, UISession, select

from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
# tools_views must be imported first: it is a facade that star-imports the others,
# and reaching password_generator_views directly first hits a circular import.
from seedsigner.views import tools_views
from seedsigner.views import microsd_views, seed_views
from seedsigner.views import password_generator_views as pw_views
from seedsigner.views.view import MainMenuView


MNEMONIC_12 = "blush twice taste dawn feed second opinion lazy thumb play neglect impact".split()


class ToolsFlowTest(FlowTest):

    def setup_method(self):
        super().setup_method()
        self.settings.set_value(
            SettingsConstants.SETTING__DIRE_WARNINGS, SettingsConstants.OPTION__DISABLED
        )

    def store_seed(self) -> Seed:
        seed = Seed(mnemonic=MNEMONIC_12)
        self.controller.storage.set_pending_seed(seed)
        return self.controller.storage.finalize_pending_seed()

    def tools_steps(self, option) -> list:
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=option),
        ]



class TestPasswordGeneratorFlow(ToolsFlowTest):
    """
    Tools > Password Generator, end to end.

    This flow produces a secret the user keeps, and until now had no flow test at all.
    The System RNG entropy source needs no camera and no dice, so it exercises the
    whole chain without mocking anything.
    """

    def test_base64_password_from_system_rng(self):
        session = UISession(script=(
            select("Base64")
            + select("64 bits")
            + select("System RNG")
            + select("Next")  # review the generated password -> Next
        ))

        self.run_sequence(
            self.tools_steps(tools_views.ToolsMenuView.PASSWORD_GENERATOR) + [
                FlowStep(pw_views.ToolsPasswordGeneratorTypeView, real_screens=True),
                FlowStep(pw_views.ToolsPasswordStrengthView, real_screens=True),
                FlowStep(pw_views.ToolsPasswordEntropySourceView, real_screens=True),
                FlowStep(pw_views.ToolsPasswordGenerateView, real_screens=True),
                FlowStep(pw_views.ToolsPasswordReviewView, real_screens=True),
                FlowStep(pw_views.ToolsPasswordSaveView),
            ],
            ui_session=session,
        )

        assert session.renderer.frames, "the real password screens never rendered"

    def test_diceware_password_asks_for_a_separator(self):
        """The diceware types add a word-separator step the other types skip."""
        session = UISession(script=(
            select("Diceware-EFF Short")
            + select("64 bits")
            + select("System RNG")
            + select(0)       # separator choice
            + select("Next")  # review the generated password -> Next
        ))

        self.run_sequence(
            self.tools_steps(tools_views.ToolsMenuView.PASSWORD_GENERATOR) + [
                FlowStep(pw_views.ToolsPasswordGeneratorTypeView, real_screens=True),
                FlowStep(pw_views.ToolsPasswordStrengthView, real_screens=True),
                FlowStep(pw_views.ToolsPasswordEntropySourceView, real_screens=True),
                # Diceware needs a separator, so the RNG view routes on to that prompt.
                FlowStep(pw_views.ToolsPasswordHardwareRngEntropyView, is_redirect=True),
                FlowStep(pw_views.ToolsPasswordWordSeparatorView, real_screens=True),
                FlowStep(pw_views.ToolsPasswordGenerateView, real_screens=True),
                FlowStep(pw_views.ToolsPasswordReviewView, real_screens=True),
                FlowStep(pw_views.ToolsPasswordSaveView),
            ],
            ui_session=session,
        )

    def test_custom_type_offers_the_random_options(self):
        """
        `ToolsPasswordRandomOptionsView` is reachable only from the Custom type, and
        was one of the views never named in any test.
        """
        session = UISession(script=(
            select("Custom")
            + select("64 bits")
            + select(0) + select(0) + select(0) + select(0)  # four Yes/No prompts
        ))

        self.run_sequence(
            self.tools_steps(tools_views.ToolsMenuView.PASSWORD_GENERATOR) + [
                FlowStep(pw_views.ToolsPasswordGeneratorTypeView, real_screens=True),
                FlowStep(pw_views.ToolsPasswordStrengthView, real_screens=True),
                FlowStep(pw_views.ToolsPasswordRandomOptionsView, real_screens=True),
                FlowStep(pw_views.ToolsPasswordEntropySourceView),
            ],
            ui_session=session,
        )



class TestAddressExplorerFlow(ToolsFlowTest):
    """Tools > Address explorer, driven off an already-loaded seed."""

    def test_receive_address_list_and_detail(self):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        seed = self.store_seed()
        self.settings.set_value(
            SettingsConstants.SETTING__SCRIPT_TYPES, [SettingsConstants.NATIVE_SEGWIT]
        )

        session = UISession(script=(
            select(0)  # the loaded seed, first in the source list
            + select(tools_views.ToolsAddressExplorerAddressTypeView.RECEIVE)
            + select(0)  # the first address in the list
            + [K.KEY_PRESS]  # the address detail is a QR display: any click exits
        ))

        self.run_sequence(
            self.tools_steps(tools_views.ToolsMenuView.ADDRESS_EXPLORER) + [
                FlowStep(tools_views.ToolsAddressExplorerSelectSourceView, real_screens=True),
                # Only one script type is enabled, so the script-type prompt is skipped.
                FlowStep(seed_views.SeedExportXpubScriptTypeView, is_redirect=True),
                FlowStep(tools_views.ToolsAddressExplorerAddressTypeView, real_screens=True),
                FlowStep(tools_views.ToolsAddressExplorerAddressListView, real_screens=True),
                FlowStep(tools_views.ToolsAddressExplorerAddressView, real_screens=True),
                FlowStep(tools_views.ToolsAddressExplorerAddressListView),
            ],
            ui_session=session,
        )

        assert self.controller.storage.seeds == [seed]



class TestTextQRFlow(ToolsFlowTest):
    """
    Tools > Text QR Code. The encode path already has real-screen coverage in
    test_real_screen_flows.py; this covers the decode side and the menu itself.
    """

    TEXT = "hello from a text QR"

    def test_decode_a_scanned_text_qr(self):
        """
        Unlike ScanView, ToolsTextQRScanQRCodeView builds its own local DecodeQR and
        calls ScanScreen(...).display() directly, so there is no `view.decoder` to
        inject into. Stand in for the camera at those two points instead; the review
        screen after it is real.
        """
        from unittest.mock import MagicMock, patch

        from seedsigner.views import gpg_views

        decoder = MagicMock()
        decoder.is_complete = True
        decoder.is_nonUTF8 = False
        decoder.get_text.return_value = self.TEXT

        session = UISession(script=select("Decode QR code"))

        with patch("seedsigner.gui.screens.scan_screens.ScanScreen"), \
                patch("seedsigner.models.decode_qr.DecodeQR", return_value=decoder):
            self.run_sequence(
                self.tools_steps(tools_views.ToolsMenuView.TEXTQRCODE) + [
                    FlowStep(tools_views.ToolsTextQRView, real_screens=True),
                    FlowStep(gpg_views.ToolsTextQRScanQRCodeView, is_redirect=True),
                    FlowStep(gpg_views.ToolsTextQRReviewTextView2, real_screens=True),
                ],
                ui_session=session,
            )



class TestClearDescriptorFlow(ToolsFlowTest):
    """Tools > Clear Multisig Descriptor -- a one-screen flow with real state to check."""

    def test_clearing_removes_the_loaded_descriptor(self):
        """
        Clearing is handled inside ToolsMenuView.run() itself -- menu selection and
        the confirmation status screen are two run_screen() calls on the same View --
        so that step has to run for real rather than being mocked.
        """
        self.controller.multisig_wallet_descriptor = object()

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
                FlowStep(tools_views.ToolsMenuView, real_screens=True),
                FlowStep(MainMenuView),
            ],
            ui_session=UISession(script=(
                select(tools_views.ToolsMenuView.CLEAR_DESCRIPTOR)
                + select(0)  # acknowledge the "descriptor cleared" status screen
            )),
        )

        assert self.controller.multisig_wallet_descriptor is None



class TestMicroSDToolsFlow(ToolsFlowTest):
    """
    Tools > MicroSD Tools. Every child here wraps a destructive `dd`/`sha256sum`
    subprocess, so these walk the menus and confirmation screens and stop before any
    write -- which is also all a user can do without a card present.
    """

    def setup_method(self):
        super().setup_method()
        # Without this the menu short-circuits to its "not supported on desktop"
        # warning before reaching any of the tools. That path is covered on its own
        # in test_desktop_mode_blocks_the_tools below.
        self._desktop_patch = patch(
            "seedsigner.hardware.microsd.MicroSD.is_desktop_mode", return_value=False
        )
        self._desktop_patch.start()

        # There is no block device here, and these tools would `dd` to it if there
        # were. Reporting "no card" is the honest desktop answer and still walks the
        # views' own warning screens.
        self._device_patch = patch(
            "seedsigner.views.microsd_views.find_sd_card_device", return_value=None
        )
        self._device_patch.start()

    def teardown_method(self):
        self._device_patch.stop()
        self._desktop_patch.stop()
        super().teardown_method()

    def test_desktop_mode_blocks_the_tools(self):
        """On desktop the menu must warn and stay put rather than run `dd`."""
        self._desktop_patch.stop()
        with patch("seedsigner.hardware.microsd.MicroSD.is_desktop_mode", return_value=True):
            self.run_sequence(
                self.tools_steps(tools_views.ToolsMenuView.MICROSD) + [
                    # The warning is raised inside the menu View itself: menu
                    # selection and warning are two run_screen() calls on the same
                    # View, which then re-enters itself so the user stays put.
                    FlowStep(microsd_views.ToolsMicroSDMenuView, real_screens=True),
                    FlowStep(microsd_views.ToolsMicroSDMenuView),
                ],
                ui_session=UISession(script=(
                    select(microsd_views.ToolsMicroSDMenuView.WIPE_ZERO)
                    + select(0)  # "OK" on the unavailable warning
                )),
            )
        self._desktop_patch.start()

    def test_wipe_zero_confirmation_screen(self):
        """
        Entering the wipe tool must reach its confirmation, not start wiping. There is
        no card here, so the view stops at its own warning -- which is the screen worth
        knowing renders and takes input.
        """
        self.run_sequence(
            self.tools_steps(tools_views.ToolsMenuView.MICROSD) + [
                FlowStep(microsd_views.ToolsMicroSDMenuView, real_screens=True),
                FlowStep(microsd_views.ToolsMicroSDWipeZeroView, real_screens=True),
                FlowStep(microsd_views.ToolsMicroSDMenuView),
            ],
            ui_session=UISession(script=(
                select(microsd_views.ToolsMicroSDMenuView.WIPE_ZERO)
                + [Back()]  # leave the size picker without starting a wipe
            )),
        )

    def test_verify_image_warning_precedes_the_check(self):
        """The verify tool must put its warning up before it reads the card."""
        self.run_sequence(
            self.tools_steps(tools_views.ToolsMenuView.MICROSD) + [
                FlowStep(microsd_views.ToolsMicroSDMenuView, real_screens=True),
                FlowStep(microsd_views.ToolsMicroSDVerifyWarningView, real_screens=True),
                FlowStep(microsd_views.ToolsMicroSDVerifyView, real_screens=True),
                FlowStep(MainMenuView),
            ],
            ui_session=UISession(script=(
                select(microsd_views.ToolsMicroSDMenuView.VERIFY_IMAGE)
                + select(0)  # "I Understand" on the warning
                + select(0)  # "no card" result
            )),
        )
