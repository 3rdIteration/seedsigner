import os
from typing import Callable

from unittest.mock import PropertyMock, patch

# Must import test base before the Controller
from base import FlowTest, FlowStep

from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsDefinition, SettingsConstants
from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON, ButtonOption
from seedsigner.hardware.microsd import MicroSD
from seedsigner.views.view import MainMenuView
from seedsigner.views import scan_views, settings_views



class TestSettingsFlows(FlowTest):
    def test_persistent_settings(self):
        """ Basic flow from MainMenuView to enable/disable persistent settings """
        # Which option are we testing?
        settings_entry = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__PERSISTENT_SETTINGS)
        self.settings.set_value(SettingsConstants.SETTING__PERSISTENT_SETTINGS, SettingsConstants.OPTION__DISABLED)

        # No settings file should exist before we enable persistent settings
        assert os.path.exists(Settings.SETTINGS_FILENAME) == False

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=ButtonOption(settings_entry.display_name)),
            FlowStep(settings_views.SettingsEntryUpdateSelectionView, button_data_selection=ButtonOption(settings_entry.get_selection_option_display_name_by_value(SettingsConstants.OPTION__ENABLED))),
            FlowStep(settings_views.SettingsEntryUpdateSelectionView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(settings_views.SettingsMenuView),
        ])

        # Settings file should now exist
        self.settings.flush_save()
        assert os.path.exists(Settings.SETTINGS_FILENAME) == True


    def test_io_test(self):
        """ Basic flow from MainMenuView to I/O Test View """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.HARDWARE),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.IO_TEST),
            FlowStep(settings_views.IOTestView),
            FlowStep(settings_views.SettingsMenuView),
        ])


    def test_battery_info_unavailable(self):
        """Battery info should show an unavailable message when no monitor is detected."""
        with patch("seedsigner.hardware.battery_hat.BatteryHat") as battery_hat:
            battery_hat.get_instance.return_value.is_enabled.return_value = False

            self.run_sequence([
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
                FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.HARDWARE),
                FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.BATTERY_INFO),
                FlowStep(settings_views.BatteryInfoView),
                FlowStep(settings_views.SettingsMenuView),
            ])

    def test_system_info(self):
        """Basic flow from MainMenuView to System Info View."""
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.HARDWARE),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.SYSTEM_INFO),
            FlowStep(settings_views.SystemInfoView),
            FlowStep(settings_views.SettingsMenuView),
        ])


    def test_hardware_menu_back_returns_to_main(self):
        """Ensure BACK from Hardware settings returns to main Settings menu."""
        def assert_general(view: settings_views.SettingsMenuView):
            assert view.visibility == SettingsConstants.VISIBILITY__GENERAL

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView, button_data_selection=settings_views.SettingsMenuView.HARDWARE),
            FlowStep(settings_views.SettingsMenuView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(settings_views.SettingsMenuView, before_run=assert_general),
        ])


    def test_settingsqr(self):
        """ 
        Scanning a SettingsQR should present the success screen and then return to
        MainMenuView.
        """
        def load_persistent_settingsqr_into_decoder(view: scan_views.ScanView):
            settingsqr_data_persistent: str = "settings::v1 name=Total_noob_mode persistent=E coords=spa,spd denom=thr network=M qr_density=M xpub_export=E sigs=ss scripts=nat xpub_details=E passphrase=E camera=0 compact_seedqr=E bip85=D priv_warn=E dire_warn=E partners=E"
            view.decoder.add_data(settingsqr_data_persistent)

        def load_not_persistent_settingsqr_into_decoder(view: scan_views.ScanView):
            settingsqr_data_not_persistent: str = "settings::v1 name=Ephemeral_noob_mode persistent=D coords=spa,spd denom=thr network=M qr_density=M xpub_export=E sigs=ss scripts=nat xpub_details=E passphrase=E camera=0 compact_seedqr=E bip85=D priv_warn=E dire_warn=E partners=E"
            view.decoder.add_data(settingsqr_data_not_persistent)

        def _run_test(initial_setting_state: str, load_settingsqr_into_decoder: Callable, expected_setting_state: str):
            from seedsigner.helpers.card_probe import ProbeResult

            self.settings.set_value(SettingsConstants.SETTING__PERSISTENT_SETTINGS, initial_setting_state)
            # Home > Scan now routes through HomeScanView, which probes the
            # reader before the camera. Pretend a card is present so the
            # settings-QR scan is reachable, and stub the silent pairing
            # (it would otherwise attempt real card I/O).
            with patch(
                "seedsigner.helpers.card_probe.probe_card",
                return_value=ProbeResult(present=True, kind_match=True, initialised=True),
            ), patch(
                "seedsigner.helpers.keycard.ui_helpers.try_silent_ephemeral_pair",
                return_value=True,
            ):
                self.run_sequence([
                    FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
                    FlowStep(scan_views.HomeScanView, is_redirect=True),  # card present -> hand off to ScanView
                    FlowStep(scan_views.ScanView, before_run=load_settingsqr_into_decoder),  # simulate read message QR; ret val is ignored
                    FlowStep(settings_views.SettingsIngestSettingsQRView),   # ret val is ignored
                    FlowStep(MainMenuView),
                ])

            assert self.settings.get_value(SettingsConstants.SETTING__PERSISTENT_SETTINGS) == expected_setting_state


        # First load a SettingsQR that enables persistent settings
        self.mock_microsd.is_inserted = True
        assert MicroSD.get_instance().is_inserted is True

        _run_test(
            initial_setting_state=SettingsConstants.OPTION__DISABLED,
            load_settingsqr_into_decoder=load_persistent_settingsqr_into_decoder,
            expected_setting_state=SettingsConstants.OPTION__ENABLED
        )

        # Then one that disables it
        _run_test(
            initial_setting_state=SettingsConstants.OPTION__ENABLED,
            load_settingsqr_into_decoder=load_not_persistent_settingsqr_into_decoder,
            expected_setting_state=SettingsConstants.OPTION__DISABLED
        )

        # Now try to enable persistent settings when the SD card is not inserted
        self.mock_microsd.is_inserted = False
        assert MicroSD.get_instance().is_inserted is False

        # Have to jump through some hoops to completely simulate the SD card being
        # removed; we need Settings to restrict Persistent Settings to only allow
        # DISABLED.
        with patch('seedsigner.models.settings.Settings.HOSTNAME', new_callable=PropertyMock) as mock_hostname:
            # Must identify itself as SeedSigner OS to trigger the SD card removal logic
            mock_hostname.return_value = Settings.SEEDSIGNER_OS
            Settings.handle_microsd_state_change(MicroSD.ACTION__REMOVED)
        
        selection_options = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__PERSISTENT_SETTINGS).selection_options
        assert len(selection_options) == 1
        assert selection_options[0][0] == SettingsConstants.OPTION__DISABLED
        assert self.settings.get_value(SettingsConstants.SETTING__PERSISTENT_SETTINGS) == SettingsConstants.OPTION__DISABLED

        _run_test(
            initial_setting_state=SettingsConstants.OPTION__DISABLED,
            load_settingsqr_into_decoder=load_persistent_settingsqr_into_decoder,
            expected_setting_state=SettingsConstants.OPTION__DISABLED
        )
