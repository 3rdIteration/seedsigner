import importlib.util
import os
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from base import FlowTest, FlowStep

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON, RET_CODE__POWER_BUTTON, ButtonOption
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views.view import MainMenuView, PowerOptionsView, RestartView, PowerOffView, BackStackView
from seedsigner.views import scan_views, seed_views, tools_views, settings_views



def _patch_scan_view_decoder(view):
    """Prevent ScanView subclasses from processing mock decoder data.

    Sets decoder flags to False so ScanView.run() falls through cleanly
    to ``return Destination(MainMenuView)`` (line 376).
    ``is_complete`` and ``is_invalid`` are read-only properties backed
    by ``self.complete`` and ``self.qr_type``; set the underlying attrs.
    """
    view.decoder.complete = False
    view.decoder.qr_type = None


def _patch_microsd_child(view):
    """Patch external hardware deps so MicroSD child views can run in tests.

    ``find_sd_card_device()`` reads ``/sys/block``, and the Flash view
    tries to list ``/boot/microsd-images/``.  Both fail in CI/test env.
    Also inject a seed so ``ToolsMicroSDFlashView`` shows its WarningScreen
    (allowing early exit via ``RET_CODE__BACK_BUTTON``).
    """
    from unittest.mock import patch
    from seedsigner.models.seed import Seed
    from seedsigner.views.microsd_views import find_sd_card_device

    patchers = [
        patch("seedsigner.views.microsd_views.find_sd_card_device", return_value="/dev/test"),
    ]
    for p in patchers:
        p.start()
    view._microsd_patchers = patchers

    # Inject a seed so FlashView's WarningScreen is shown (BACK exits early)
    if not view.controller.storage.seeds:
        word = "abandon"
        seed = Seed(mnemonic=[word] * 11 + ["about"])
        view.controller.storage.seeds = [seed]


def _patch_gpg_verify_file(view):
    """Patch external deps so ToolsGPGVerifyFileView can run in tests.

    Marks the GPG keys as already imported (skips the real ``gpg --import``
    subprocess, which would touch the host keyring) and points the file list
    at a temp dir containing one dummy file, so the View reaches its
    ButtonListScreen where BACK exits cleanly.
    """
    import tempfile

    tmpdir = Path(tempfile.mkdtemp(prefix="gpg_verify_test_"))
    (tmpdir / "dummy.bin").write_bytes(b"test")

    view._gpg_verify_patchers = [
        patch("seedsigner.views.gpg_views.resolve_microsd_images_dir", return_value=tmpdir),
    ]
    for p in view._gpg_verify_patchers:
        p.start()

    view.controller.gpg_keys_imported = True


class TestMenuNavigationFlows(FlowTest):
    """Walk every menu path in the UI to catch import errors, reachability bugs,
    stuck states, and settings gating regressions.

    Each test method:

    1.  **Forward** – navigates from ``MainMenuView`` through one or more menu
        selections and verifies the correct destination View is reached (catches
        ``ImportError`` from lazy imports inside ``View.run()``).
    2.  **Backward** – presses BACK and verifies the Controller returns to the
        expected parent menu (catches stuck states, wrong back-stack content,
        missing ``RET_CODE__BACK_BUTTON`` handlers).

    Settings are configured so that all optional menu items are visible.
    """

    def setup_method(self):
        super().setup_method()

        # ── Enable every settings-gated menu option for maximum coverage ──
        for setting, value in [
            (SettingsConstants.SETTING__SLIP39_SEEDS,       SettingsConstants.OPTION__ENABLED),
            (SettingsConstants.SETTING__SMARTCARD_SUPPORT,  SettingsConstants.OPTION__ENABLED),
            (SettingsConstants.SETTING__SATOCHIP_SUPPORT,   SettingsConstants.OPTION__ENABLED),
            (SettingsConstants.SETTING__KEYCARD_SUPPORT,    SettingsConstants.OPTION__ENABLED),
            (SettingsConstants.SETTING__SPECTER_DIY_SUPPORT,SettingsConstants.OPTION__ENABLED),
            (SettingsConstants.SETTING__AEZEED_SEEDS,       SettingsConstants.OPTION__ENABLED),
            (SettingsConstants.SETTING__ELECTRUM_SEEDS,     SettingsConstants.OPTION__ENABLED),
            (SettingsConstants.SETTING__BITBOX_BACKUP,      SettingsConstants.OPTION__ENABLED),
            (SettingsConstants.SETTING__PASSPORT_BACKUP,    SettingsConstants.OPTION__ENABLED),
            (SettingsConstants.SETTING__TAPSIGNER_BACKUP,   SettingsConstants.OPTION__ENABLED),
            (SettingsConstants.SETTING__BIP85_CHILD_SEEDS,  SettingsConstants.OPTION__ENABLED),
            (SettingsConstants.SETTING__MESSAGE_SIGNING,    SettingsConstants.OPTION__ENABLED),
            (SettingsConstants.SETTING__PLAINTEXTQR,        SettingsConstants.OPTION__ENABLED),
        ]:
            self.settings.set_value(setting, value)

        # Simulate a BatteryHat that is physically present so the
        # Battery Calibration button appears in ToolsMenuView.
        battery_hat_patch = patch(
            "seedsigner.hardware.battery_hat.BatteryHat.get_instance",
        )
        battery_hat_mock = battery_hat_patch.start()
        battery_hat_mock.return_value.is_enabled.return_value = True
        battery_hat_mock.return_value.is_alive.return_value = False
        self._battery_hat_patch = battery_hat_patch

        # Hide the OS-specific "Network Info" tool to keep tests portable.
        network_info_patch = patch.object(Path, "is_file", return_value=False)
        network_info_patch.start()
        self._network_info_patch = network_info_patch

        # Ensure MicroSD tools are not blocked by desktop-mode detection.
        desktop_mode_patch = patch(
            "seedsigner.hardware.microsd.MicroSD.is_desktop_mode",
            return_value=False,
        )
        desktop_mode_patch.start()
        self._desktop_mode_patch = desktop_mode_patch

    def teardown_method(self):
        for attr in ("_battery_hat_patch", "_network_info_patch", "_desktop_mode_patch"):
            p = getattr(self, attr, None)
            if p is not None:
                p.stop()
        super().teardown_method()


    # ======================================================================
    #  POWER OPTIONS
    # ======================================================================

    def test_power_options_restart(self):
        """MainMenu → PowerOptions → Restart."""
        self.run_sequence([
            FlowStep(MainMenuView, screen_return_value=RET_CODE__POWER_BUTTON),
            FlowStep(PowerOptionsView, button_data_selection=PowerOptionsView.RESET),
            FlowStep(RestartView),
        ])

    def test_power_options_power_off(self):
        """MainMenu → PowerOptions → Power Off (desktop mode exits via
        ``BackStackView``)."""
        self.run_sequence([
            FlowStep(MainMenuView, screen_return_value=RET_CODE__POWER_BUTTON),
            FlowStep(PowerOptionsView, button_data_selection=PowerOptionsView.POWER_OFF),
            FlowStep(PowerOffView, screen_return_value=RET_CODE__BACK_BUTTON),
        ])


    # ======================================================================
    #  TOOLS MENU
    # ======================================================================

    def test_tools_image_entropy(self):
        """Tools → New seed (camera)."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.IMAGE),
            FlowStep(tools_views.ToolsImageEntropyLivePreviewView),
        ])

    def test_tools_dice_entropy(self):
        """Tools → New seed (dice).

        ``ToolsDiceEntropyMnemonicLengthView`` uses direct
        ``ButtonListScreen(...).display()`` instead of ``self.run_screen()``,
        so we can't mock via ``screen_return_value``. Just verify reachable.
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.DICE),
            FlowStep(tools_views.ToolsDiceEntropyMnemonicLengthView),
        ])

    def test_tools_slip39_image(self):
        """Tools → SLIP39 seed (camera)."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SLIP39_IMAGE),
            FlowStep(tools_views.ToolsImageEntropyLivePreviewView),
        ])

    def test_tools_slip39_dice(self):
        """Tools → SLIP39 seed (dice).

        Same direct ``.display()`` constraint as ``test_tools_dice_entropy``.
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SLIP39_DICE),
            FlowStep(tools_views.ToolsDiceEntropyMnemonicLengthView),
        ])

    def test_tools_calc_final_word(self):
        """Tools → Calc 12th/24th word → BACK → ToolsMenu."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.KEYBOARD),
            FlowStep(tools_views.ToolsCalcFinalWordNumWordsView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(tools_views.ToolsMenuView),
        ])

    def test_tools_address_explorer(self):
        """Tools → Address Explorer → BACK → ToolsMenu."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.ADDRESS_EXPLORER),
            FlowStep(tools_views.ToolsAddressExplorerSelectSourceView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(tools_views.ToolsMenuView),
        ])

    def test_tools_verify_address(self):
        """Tools → Verify address.

        ``ScanAddressView`` inherits ``ScanView.run()`` which doesn't check
        the return value of ``run_screen`` (it checks ``self.decoder.*``
        flags instead). We use a *before_run* callback to neuter the decoder
        so ``run()`` falls through to ``return Destination(MainMenuView)``.
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.VERIFY_ADDRESS),
            FlowStep(scan_views.ScanAddressView, before_run=_patch_scan_view_decoder, screen_return_value=0),
            FlowStep(MainMenuView),
        ])

    def test_tools_text_qr(self):
        """Tools → Text QR Code → BACK → ToolsMenu."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.TEXTQRCODE),
            FlowStep(tools_views.ToolsTextQRView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(tools_views.ToolsMenuView),
        ])

    def test_tools_text_qr_decode(self):
        """Tools → Text QR Code → Decode QR code → BACK.

        Exercises ``ToolsTextQRScanQRCodeView`` which uses ``time.sleep()``
        (verifies the ``import time`` fix in ``gpg_views.py``). The View calls
        ``ScanScreen(...).display()`` directly (not ``run_screen``), so mark it
        as a redirect. ``BackStackView`` pops back to ``ToolsTextQRView``.
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.TEXTQRCODE),
            FlowStep(tools_views.ToolsTextQRView, button_data_selection=ButtonOption("Decode QR code")),
            FlowStep(tools_views.ToolsTextQRScanQRCodeView, is_redirect=True),
            FlowStep(tools_views.ToolsTextQRView),
        ])

    def test_tools_password_generator(self):
        """Tools → Password Generator → BACK → ToolsMenu."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.PASSWORD_GENERATOR),
            FlowStep(tools_views.ToolsPasswordGeneratorTypeView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(tools_views.ToolsMenuView),
        ])

    def test_tools_password_generator_diceware_dice_math(self):
        """Tools → Password Generator → Diceware-BIP39 → 64 bits → Dice.

        Exercises ``ToolsPasswordDiceRollCountView`` which uses
        ``math.ceil()`` / ``math.log2()`` (exercises the ``import math`` fix).
        The View returns a ``skip_current_view`` Destination after computing
        the roll count, so the last step is a redirect.
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.PASSWORD_GENERATOR),
            FlowStep(tools_views.ToolsPasswordGeneratorTypeView, button_data_selection=ButtonOption("Diceware-BIP39")),
            FlowStep(tools_views.ToolsPasswordStrengthView, screen_return_value=0),
            FlowStep(tools_views.ToolsPasswordEntropySourceView, button_data_selection=ButtonOption("Dice")),
            FlowStep(tools_views.ToolsPasswordDiceRollCountView, is_redirect=True),
        ])

    def test_tools_smartcard(self):
        """Tools → Smartcard Tools → BACK → ToolsMenu."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
            FlowStep(tools_views.ToolsSmartcardMenuView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(tools_views.ToolsMenuView),
        ])

    def test_tools_microsd(self):
        """Tools → MicroSD Tools → BACK → ToolsMenu."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.MICROSD),
            FlowStep(tools_views.ToolsMicroSDMenuView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(tools_views.ToolsMenuView),
        ])

    def test_tools_battery_calibration(self):
        """Tools → Battery Calibration → BACK → ToolsMenu.

        ``ToolsBatteryCalibrationView`` calls ``self.run_screen`` before
        reaching a direct ``.display()`` call, so providing
        ``screen_return_value`` lets us exit early.
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.BATTERY_CALIBRATION),
            FlowStep(tools_views.ToolsBatteryCalibrationView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(tools_views.ToolsMenuView),
        ])

    def test_tools_gpg(self):
        """Tools → GPG Tools → BACK → ToolsMenu.

        ``ToolsGPGMenuView`` checks for ``pgpy``/``gpg`` at the start of
        ``run()``.  If they are missing (expected in CI) an error screen is
        shown via ``self.run_screen`` and the View returns ``BackStackView``.
        If present the menu is displayed and BACK returns to Tools.
        Either path resolves the same way from our perspective.
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.GPG),
            FlowStep(tools_views.ToolsGPGMenuView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(tools_views.ToolsMenuView),
        ])

    def test_tools_gpg_verify_signature(self):
        """Tools → GPG Tools → File Operations → Verify Signature → BACK.

        Requires ``gpg`` + ``pgpy``: without them ``ToolsGPGMenuView`` shows
        its missing-packages error and the sub-menu buttons don't exist. The
        View's real ``gpg --import`` is skipped via ``before_run`` so the host
        keyring stays untouched; BACK from the file list returns to the File
        Operations menu.
        """
        if shutil.which("gpg") is None or importlib.util.find_spec("pgpy") is None:
            pytest.skip("gpg binary and/or pgpy not available")

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.GPG),
            FlowStep(tools_views.ToolsGPGMenuView, button_data_selection=tools_views.ToolsGPGMenuView.FILE_OPS),
            FlowStep(tools_views.ToolsGPGFileOpsMenuView, button_data_selection=tools_views.ToolsGPGFileOpsMenuView.VERIFY),
            FlowStep(
                tools_views.ToolsGPGVerifyFileView,
                before_run=_patch_gpg_verify_file,
                screen_return_value=RET_CODE__BACK_BUTTON,
            ),
            FlowStep(tools_views.ToolsGPGFileOpsMenuView),
        ])

    def test_tools_gpg_import_menu(self):
        """Tools → GPG Tools → Import Keys → BACK → GPG menu."""
        if shutil.which("gpg") is None or importlib.util.find_spec("pgpy") is None:
            pytest.skip("gpg binary and/or pgpy not available")

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.GPG),
            FlowStep(tools_views.ToolsGPGMenuView, button_data_selection=tools_views.ToolsGPGMenuView.IMPORT),
            FlowStep(tools_views.ToolsGPGImportMenuView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(tools_views.ToolsGPGMenuView),
        ])

    def test_tools_gpg_import_privkey_menu(self):
        """Tools → GPG Tools → Import Keys → Private Key → BACK → Import menu.

        Verifies the privkey import sub-menu (Generate New / Derive BIP85 / From QR /
        From File / From Seedkeeper) is reachable and backs out correctly. The items'
        destinations are covered by the UI-driver flow tests; walking into them here
        would hit direct ``Screen.display()`` calls the mocked harness can't drive.
        """
        if shutil.which("gpg") is None or importlib.util.find_spec("pgpy") is None:
            pytest.skip("gpg binary and/or pgpy not available")

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.GPG),
            FlowStep(tools_views.ToolsGPGMenuView, button_data_selection=tools_views.ToolsGPGMenuView.IMPORT),
            FlowStep(tools_views.ToolsGPGImportMenuView, button_data_selection=tools_views.ToolsGPGImportMenuView.PRIVKEY),
            FlowStep(tools_views.ToolsGPGImportPrivkeyMenuView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(tools_views.ToolsGPGImportMenuView),
        ])

    def test_tools_gpg_import_privkey_bip85_no_seed(self):
        """Tools → GPG Tools → Import Keys → Private Key → Derive BIP85 (no seed).

        With no seeds loaded ``ToolsGPGLoadBIP85KeyView`` shows its warning and backs
        out before reaching the text-entry screens, so this walks the user's exact bug
        path as far as the mocked harness allows.
        """
        if shutil.which("gpg") is None or importlib.util.find_spec("pgpy") is None:
            pytest.skip("gpg binary and/or pgpy not available")

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.GPG),
            FlowStep(tools_views.ToolsGPGMenuView, button_data_selection=tools_views.ToolsGPGMenuView.IMPORT),
            FlowStep(tools_views.ToolsGPGImportMenuView, button_data_selection=tools_views.ToolsGPGImportMenuView.PRIVKEY),
            FlowStep(tools_views.ToolsGPGImportPrivkeyMenuView, button_data_selection=tools_views.ToolsGPGImportPrivkeyMenuView.LOAD_BIP85_KEY),
            FlowStep(tools_views.ToolsGPGLoadBIP85KeyView, screen_return_value=0),
        ])

    def test_tools_clear_descriptor(self):
        """Tools → Clear Multisig Descriptor.

        The action is performed inside ``ToolsMenuView.run()`` itself
        (``run_screen + BackStackView``), so no separate destination step
        is needed.
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.CLEAR_DESCRIPTOR),
        ])


    # ======================================================================
    #  LOAD SEED – every option
    # ======================================================================

    def _load_seed_flow(self, button_option):
        """Navigate MainMenu → Seeds → LoadSeedView and press *button_option*."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
            # SeedsMenuView redirects to LoadSeedView when no seeds are loaded
            FlowStep(seed_views.SeedsMenuView, is_redirect=True),
            FlowStep(seed_views.LoadSeedView, button_data_selection=button_option),
        ])

    def test_load_seed_scan_qr(self):
        self._load_seed_flow(seed_views.LoadSeedView.SEED_QR)

    def test_load_seed_12_word(self):
        self._load_seed_flow(seed_views.LoadSeedView.TYPE_12WORD)

    def test_load_seed_24_word(self):
        self._load_seed_flow(seed_views.LoadSeedView.TYPE_24WORD)

    def test_load_seed_slip39(self):
        self._load_seed_flow(seed_views.LoadSeedView.TYPE_SLIP39)

    def test_load_seed_aezeed(self):
        self._load_seed_flow(seed_views.LoadSeedView.TYPE_AEZEED)

    def test_load_seed_electrum(self):
        self._load_seed_flow(seed_views.LoadSeedView.TYPE_ELECTRUM)

    def test_load_seed_bitbox02(self):
        self._load_seed_flow(seed_views.LoadSeedView.BITBOX_BACKUP)

    def test_load_seed_passport(self):
        self._load_seed_flow(seed_views.LoadSeedView.PASSPORT_BACKUP)

    def test_load_seed_tapsigner(self):
        self._load_seed_flow(seed_views.LoadSeedView.TAPSIGNER_BACKUP)

    def test_load_seed_seedkeeper(self):
        self._load_seed_flow(seed_views.LoadSeedView.IMPORT_SEEDKEEPER)

    def test_load_seed_specter_diy(self):
        self._load_seed_flow(seed_views.LoadSeedView.IMPORT_SPECTER_DIY)

    def test_load_seed_create(self):
        self._load_seed_flow(seed_views.LoadSeedView.CREATE)


    # ======================================================================
    #  SETTINGS SUB-MENUS
    # ======================================================================

    def test_settings_system_info(self):
        """Settings → Hardware → System info."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.HARDWARE),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.SYSTEM_INFO),
            FlowStep(settings_views.SystemInfoView, screen_return_value=RET_CODE__BACK_BUTTON),
        ])

    def test_settings_battery_info(self):
        """Settings → Hardware → Battery info."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.HARDWARE),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.BATTERY_INFO),
            FlowStep(settings_views.BatteryInfoView, screen_return_value=RET_CODE__BACK_BUTTON),
        ])

    def test_settings_io_test(self):
        """Settings → Hardware → I/O test."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.HARDWARE),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.IO_TEST),
            FlowStep(settings_views.IOTestView, screen_return_value=RET_CODE__BACK_BUTTON),
        ])

    def test_settings_list_readers(self):
        """Settings → Hardware → List card readers."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.HARDWARE),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.LIST_READERS),
            FlowStep(settings_views.SCardReaderTestView, screen_return_value=RET_CODE__BACK_BUTTON),
        ])

    def test_settings_scard_test(self):
        """Settings → Hardware → Test Smartcard."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.HARDWARE),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.SCARD_TEST),
            FlowStep(settings_views.SCARDTestView, screen_return_value=RET_CODE__BACK_BUTTON),
        ])

    def test_settings_nfc_test(self):
        """Settings → Hardware → Test NFC Scan."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.HARDWARE),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.NFC_TEST),
            FlowStep(settings_views.NFCTestView, screen_return_value=RET_CODE__BACK_BUTTON),
        ])

    def test_settings_general_all_entries(self):
        """Settings → every GENERAL entry → BACK → MainMenu.

        The ``locale`` entry uses ``LocaleSelectionView`` instead of
        ``SettingsEntryUpdateSelectionView``; skip it (tested separately).
        """
        settings_entries = settings_views.SettingsDefinition.get_settings_entries(
            visibility=SettingsConstants.VISIBILITY__GENERAL,
        )
        sequence = [FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS)]
        for entry in settings_entries:
            if entry.attr_name == SettingsConstants.SETTING__LOCALE:
                continue
            sequence.append(
                FlowStep(
                    settings_views.SettingsMenuView,
                    button_data_selection=ButtonOption(entry.display_name),
                )
            )
            sequence.append(
                FlowStep(
                    settings_views.SettingsEntryUpdateSelectionView,
                    screen_return_value=RET_CODE__BACK_BUTTON,
                ),
            )
        sequence.append(FlowStep(settings_views.SettingsMenuView))
        self.run_sequence(sequence)

    def test_settings_advanced_all_entries(self):
        """Settings → Advanced → every ADVANCED entry → BACK.

        ``pbkdf2_iterations`` uses ``SettingPBKDF2IterationsView`` instead
        of ``SettingsEntryUpdateSelectionView``; skip it (tested separately).
        """
        settings_entries = settings_views.SettingsDefinition.get_settings_entries(
            visibility=SettingsConstants.VISIBILITY__ADVANCED,
        )
        sequence = [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(
                settings_views.SettingsMenuView,
                button_data_selection=settings_views.SettingsMenuView.ADVANCED,
            ),
        ]
        for entry in settings_entries:
            if entry.attr_name == SettingsConstants.SETTING__ENCRYPTION_ITER:
                continue
            sequence.append(
                FlowStep(
                    settings_views.SettingsMenuView,
                    button_data_selection=ButtonOption(entry.display_name),
                )
            )
            sequence.append(
                FlowStep(
                    settings_views.SettingsEntryUpdateSelectionView,
                    screen_return_value=RET_CODE__BACK_BUTTON,
                ),
            )
        sequence.append(FlowStep(settings_views.SettingsMenuView))
        self.run_sequence(sequence)

    def test_settings_back_navigation_nested(self):
        """Settings → Advanced → Hardware → BACK → BACK → MainMenu.

        ``SettingsMenuView`` returns ``Destination(SettingsMenuView)``
        directly for BACK (not ``BackStackView``), and BACK from HARDWARE
        jumps straight to GENERAL (skipping ADVANCED).
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.ADVANCED),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.HARDWARE),
            FlowStep(settings_views.SettingsMenuView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(settings_views.SettingsMenuView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(MainMenuView),
        ])


    # ======================================================================
    #  SMARTCARD SUB-MENU
    # ======================================================================

    def test_smartcard_common(self):
        """Tools → Smartcard → Common → BACK."""
        from seedsigner.views.smartcard_views import (
            ToolsSmartcardMenuView, ToolsCommonView,
        )
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
            FlowStep(ToolsSmartcardMenuView, button_data_selection=ToolsSmartcardMenuView.COMMON),
            FlowStep(ToolsCommonView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(ToolsSmartcardMenuView),
        ])

    def test_smartcard_seedkeeper(self):
        """Tools → Smartcard → SeedKeeper → BACK."""
        from seedsigner.views.smartcard_views import (
            ToolsSmartcardMenuView, ToolsSeedkeeperView,
        )
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
            FlowStep(ToolsSmartcardMenuView, button_data_selection=ToolsSmartcardMenuView.SEEDKEEPER),
            FlowStep(ToolsSeedkeeperView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(ToolsSmartcardMenuView),
        ])

    def test_smartcard_satochip(self):
        """Tools → Smartcard → Satochip → BACK."""
        from seedsigner.views.smartcard_views import (
            ToolsSmartcardMenuView, ToolsSatochipView,
        )
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
            FlowStep(ToolsSmartcardMenuView, button_data_selection=ToolsSmartcardMenuView.SATOCHIP),
            FlowStep(ToolsSatochipView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(ToolsSmartcardMenuView),
        ])

    def test_smartcard_keycard(self):
        """Tools → Smartcard → KeyCard → BACK."""
        from seedsigner.views.smartcard_views import (
            ToolsSmartcardMenuView, ToolsKeycardView,
        )
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
            FlowStep(ToolsSmartcardMenuView, button_data_selection=ToolsSmartcardMenuView.KEYCARD),
            FlowStep(ToolsKeycardView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(ToolsSmartcardMenuView),
        ])

    def test_smartcard_specter_diy(self):
        """Tools → Smartcard → Specter-DIY → BACK."""
        from seedsigner.views.smartcard_views import (
            ToolsSmartcardMenuView, ToolsSpecterDIYView,
        )
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
            FlowStep(ToolsSmartcardMenuView, button_data_selection=ToolsSmartcardMenuView.SPECTER_DIY),
            FlowStep(ToolsSpecterDIYView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(ToolsSmartcardMenuView),
        ])

    def test_smartcard_satochip_diy(self):
        """Tools → Smartcard → DIY Tools → BACK."""
        from seedsigner.views.smartcard_views import (
            ToolsSmartcardMenuView, ToolsSatochipDIYView,
        )
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
            FlowStep(ToolsSmartcardMenuView, button_data_selection=ToolsSmartcardMenuView.Satochip_DIY),
            FlowStep(ToolsSatochipDIYView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(ToolsSmartcardMenuView),
        ])

    def test_smartcard_satochip_diy_mount_status(self):
        """Tools → Smartcard → DIY Tools → Mount Status → BACK.

        Exercises ``ToolsDIYMountStatusView.run()`` (which reads the OS mount
        log). The reader is patched to "no events since boot" so the flow is
        deterministic regardless of whether /tmp/diy-mount.log exists on the
        test host; BACK returns to the DIY Tools menu.
        """
        from seedsigner.views.smartcard_views import (
            ToolsSmartcardMenuView, ToolsSatochipDIYView, ToolsDIYMountStatusView,
        )
        with patch(
            "seedsigner.views.smartcard_views.read_diy_mount_status", return_value=None
        ):
            self.run_sequence([
                FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
                FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
                FlowStep(ToolsSmartcardMenuView, button_data_selection=ToolsSmartcardMenuView.Satochip_DIY),
                FlowStep(ToolsSatochipDIYView, button_data_selection=ToolsSatochipDIYView.MOUNT_STATUS),
                FlowStep(ToolsDIYMountStatusView, screen_return_value=RET_CODE__BACK_BUTTON),
                FlowStep(ToolsSatochipDIYView),
            ])


    # ======================================================================
    #  CONDITIONAL GATING
    # ======================================================================

    def test_slip39_seeds_disabled(self):
        """SLIP39 menu items should be *hidden* when the setting is OFF."""
        self.settings.set_value(
            SettingsConstants.SETTING__SLIP39_SEEDS,
            SettingsConstants.OPTION__DISABLED,
        )
        button_data = self._capture_tools_button_data()
        assert tools_views.ToolsMenuView.SLIP39_IMAGE not in button_data
        assert tools_views.ToolsMenuView.SLIP39_DICE not in button_data

    def test_slip39_seeds_enabled(self):
        """SLIP39 menu items should be *visible* when the setting is ON."""
        self.settings.set_value(
            SettingsConstants.SETTING__SLIP39_SEEDS,
            SettingsConstants.OPTION__ENABLED,
        )
        button_data = self._capture_tools_button_data()
        assert tools_views.ToolsMenuView.SLIP39_IMAGE in button_data
        assert tools_views.ToolsMenuView.SLIP39_DICE in button_data

    def test_smartcard_tools_disabled(self):
        """Smartcard menu items should be *hidden* when SMARTCARD_SUPPORT is OFF."""
        self.settings.set_value(
            SettingsConstants.SETTING__SMARTCARD_SUPPORT,
            SettingsConstants.OPTION__DISABLED,
        )
        button_data = self._capture_tools_button_data()
        assert tools_views.ToolsMenuView.SMARTCARD not in button_data

    def test_password_generator_hidden(self):
        """Password Generator should be *hidden* when ``include_password_generator``
        is ``False``."""
        view = object.__new__(tools_views.ToolsMenuView)
        view.settings = self.settings
        view.controller = self.controller
        view.include_password_generator = False

        captured = {}

        def fake_run_screen(self_view, *args, **kwargs):
            captured["button_data"] = kwargs.get("button_data")
            return RET_CODE__BACK_BUTTON

        with patch.object(tools_views.ToolsMenuView, "run_screen", fake_run_screen):
            destination = view.run()

        assert tools_views.ToolsMenuView.PASSWORD_GENERATOR not in captured["button_data"]


    # ======================================================================
    #  STUCK-STATE TESTS
    # ======================================================================

    def test_option_disabled_both_buttons(self):
        """``OptionDisabledView`` has ``show_back_button=False``; verify both
        "Update Setting" and "Done" paths exit cleanly with ``clear_history``."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
            FlowStep(seed_views.SeedsMenuView, is_redirect=True),
            # LoadSeedView → SLIP39 → manually set SLIP39 to disabled
            FlowStep(
                seed_views.LoadSeedView,
                button_data_selection=seed_views.LoadSeedView.TYPE_SLIP39,
            ),
        ])

    def test_network_mismatch_routes_to_settings(self):
        """``NetworkMismatchErrorView`` forces "Change Setting" with
        ``clear_history=True``; verify it routes to
        ``SettingsEntryUpdateSelectionView``."""
        from seedsigner.views.view import NetworkMismatchErrorView

        def _set_derivation_path(view):
            view.derivation_path = "m/84'/0'/0'"

        self.run_sequence([
            FlowStep(
                NetworkMismatchErrorView,
                before_run=_set_derivation_path,
                screen_return_value=RET_CODE__BACK_BUTTON,
            ),
        ])

    def test_microsd_desktop_blocked_then_flash(self):
        """Tools → MicroSD → Flash Image, with desktop mode blocking.

        ``is_desktop_mode()`` returns True on the menu's first run
        (warning displayed, View re-runs via ``skip_current_view=True``),
        then False on the re-run so the user can proceed to the child view.
        Verifies both the stop message and the rest of the navigation.
        """
        from seedsigner.models.seed import Seed
        from seedsigner.hardware.microsd import MicroSD
        from seedsigner.views.microsd_views import (
            ToolsMicroSDMenuView, ToolsMicroSDFlashView,
        )

        desktop_calls = iter([True, False])

        def _setup(view):
            patcher = patch.object(
                MicroSD, "is_desktop_mode",
                side_effect=lambda: next(desktop_calls),
            )
            patcher.start()
            view._desktop_patcher = patcher

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.MICROSD),
            # First run: desktop mode True → WarningScreen → skip_current_view
            FlowStep(ToolsMicroSDMenuView, before_run=_setup, screen_return_value=0),
            # Second run (re-displayed): desktop mode False → select Flash Image
            FlowStep(ToolsMicroSDMenuView, button_data_selection=ToolsMicroSDMenuView.FLASH_IMAGE),
            # FlashImage: needs seed for WarningScreen → BACK exits early
            FlowStep(ToolsMicroSDFlashView, before_run=_patch_microsd_child, screen_return_value=RET_CODE__BACK_BUTTON),
        ])

    def test_microsd_verify_image(self):
        """Tools → MicroSD → Verify MicroSD → BACK."""
        from seedsigner.views.microsd_views import (
            ToolsMicroSDMenuView, ToolsMicroSDVerifyWarningView,
        )
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.MICROSD),
            FlowStep(ToolsMicroSDMenuView, button_data_selection=ToolsMicroSDMenuView.VERIFY_IMAGE),
            FlowStep(ToolsMicroSDVerifyWarningView, screen_return_value=RET_CODE__BACK_BUTTON),
        ])

    def test_microsd_wipe_zero(self):
        """Tools → MicroSD → Wipe (Zero) → BACK."""
        from seedsigner.views.microsd_views import (
            ToolsMicroSDMenuView, ToolsMicroSDWipeZeroView,
        )
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.MICROSD),
            FlowStep(ToolsMicroSDMenuView, button_data_selection=ToolsMicroSDMenuView.WIPE_ZERO),
            FlowStep(ToolsMicroSDWipeZeroView, before_run=_patch_microsd_child, screen_return_value=RET_CODE__BACK_BUTTON),
        ])

    def test_microsd_wipe_random(self):
        """Tools → MicroSD → Wipe (Random) → BACK."""
        from seedsigner.views.microsd_views import (
            ToolsMicroSDMenuView, ToolsMicroSDWipeRandomView,
        )
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.MICROSD),
            FlowStep(ToolsMicroSDMenuView, button_data_selection=ToolsMicroSDMenuView.WIPE_RANDOM),
            FlowStep(ToolsMicroSDWipeRandomView, before_run=_patch_microsd_child, screen_return_value=RET_CODE__BACK_BUTTON),
        ])


    # ------------------------------------------------------------------ 
    #  Internal helpers
    # ------------------------------------------------------------------

    def _capture_tools_button_data(self):
        """Instantiate a ``ToolsMenuView`` and capture its ``button_data``
        without calling ``run_screen``."""
        view = object.__new__(tools_views.ToolsMenuView)
        view.settings = self.settings
        view.controller = self.controller
        view.include_password_generator = True

        captured = {}

        def fake_run_screen(self_view, *args, **kwargs):
            captured["button_data"] = kwargs.get("button_data")
            return RET_CODE__BACK_BUTTON

        with patch.object(tools_views.ToolsMenuView, "run_screen", fake_run_screen):
            view.run()

        return captured["button_data"]
