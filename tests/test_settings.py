import json
import pytest
from base import BaseTest
from seedsigner.models.settings import InvalidSettingsQRData, Settings
from seedsigner.models.settings_definition import SettingsConstants
from unittest.mock import patch



class TestSettings(BaseTest):
    @classmethod
    def setup_class(cls):
        super().setup_class()
        cls.settings = Settings.get_instance()
        cls._orig_patch_pcsc = Settings.patch_pcsc_initd_script
        Settings.patch_pcsc_initd_script = lambda *a, **kw: None

    @classmethod
    def teardown_class(cls):
        Settings.patch_pcsc_initd_script = cls._orig_patch_pcsc


    def test_reset_settings(self):
        """ BaseTest.reset_settings() should wipe out any previous Settings changes """
        settings = Settings.get_instance()
        settings.set_value(SettingsConstants.SETTING__PERSISTENT_SETTINGS, SettingsConstants.OPTION__ENABLED)
        assert settings.get_value(SettingsConstants.SETTING__PERSISTENT_SETTINGS) == SettingsConstants.OPTION__ENABLED

        BaseTest.reset_settings()
        settings = Settings.get_instance()
        assert settings.get_value(SettingsConstants.SETTING__PERSISTENT_SETTINGS) == SettingsConstants.OPTION__DISABLED


    def test_parse_settingsqr_data(self):
        """
        SettingsQR parser should successfully parse a valid settingsqr input string and
        return the resulting config_name and formatted settings_update_dict.
        """
        settings_name = "Test SettingsQR"
        settingsqr_data = f"""settings::v1 name={ settings_name.replace(" ", "_") } persistent=D coords=spa,spd denom=thr network=M qr_density=M xpub_export=E sigs=ss,ms scripts=nat,nes,tr xpub_details=E passphrase=E camera=180 compact_seedqr=E bip85=D priv_warn=E dire_warn=E partners=E"""

        # First explicitly set settings that differ from the settingsqr_data
        self.settings.set_value(SettingsConstants.SETTING__COMPACT_SEEDQR, SettingsConstants.OPTION__DISABLED)
        self.settings.set_value(SettingsConstants.SETTING__DIRE_WARNINGS, SettingsConstants.OPTION__DISABLED)
        self.settings.set_value(SettingsConstants.SETTING__COORDINATORS, [SettingsConstants.COORDINATOR__BLUE_WALLET, SettingsConstants.COORDINATOR__SPARROW])

        # Now parse the settingsqr_data
        config_name, settings_update_dict = Settings.parse_settingsqr(settingsqr_data)
        assert config_name == settings_name
        self.settings.update(new_settings=settings_update_dict)

        # Now verify that the settings were updated correctly
        assert self.settings.get_value(SettingsConstants.SETTING__COMPACT_SEEDQR) == SettingsConstants.OPTION__ENABLED
        assert self.settings.get_value(SettingsConstants.SETTING__DIRE_WARNINGS) == SettingsConstants.OPTION__ENABLED

        coordinators = self.settings.get_value(SettingsConstants.SETTING__COORDINATORS)
        assert SettingsConstants.COORDINATOR__BLUE_WALLET not in coordinators
        assert SettingsConstants.COORDINATOR__SPARROW in coordinators
        assert SettingsConstants.COORDINATOR__SPECTER_DESKTOP in coordinators
    

    def test_settingsqr_version(self):
        """ SettingsQR parser should accept SettingsQR v1 and reject any others """
        settingsqr_data = "settings::v1 name=Foo"
        config_name, settings_update_dict = Settings.parse_settingsqr(settingsqr_data)

        # Accepts update with no Exceptions
        self.settings.update(new_settings=settings_update_dict)

        settingsqr_data = "settings::v2 name=Foo"
        with pytest.raises(InvalidSettingsQRData) as e:
            Settings.parse_settingsqr(settingsqr_data)
        assert "Unsupported SettingsQR version" in str(e.value)
    
        # Should also fail if version omitted
        settingsqr_data = "settings name=Foo"
        with pytest.raises(InvalidSettingsQRData) as e:
            Settings.parse_settingsqr(settingsqr_data)

        # And if "settings" is omitted entirely
        settingsqr_data = "name=Foo"
        with pytest.raises(InvalidSettingsQRData) as e:
            Settings.parse_settingsqr(settingsqr_data)


    def test_settingsqr_ignores_unrecognized_setting(self):
        """ SettingsQR parser should ignore unrecognized settings """
        settingsqr_data = "settings::v1 name=Foo favorite_food=bacon xpub_export=D"
        config_name, settings_update_dict = Settings.parse_settingsqr(settingsqr_data)

        assert "favorite_food" not in settings_update_dict
        assert "xpub_export" in settings_update_dict

        # Accepts update with no Exceptions
        self.settings.update(new_settings=settings_update_dict)


    def test_settingsqr_fails_unrecognized_option(self):
        """ SettingsQR parser should fail if a settings has an unrecognized option """
        settingsqr_data = "settings::v1 name=Foo xpub_export=Yep"
        with pytest.raises(InvalidSettingsQRData) as e:
            Settings.parse_settingsqr(settingsqr_data)
        assert "xpub_export" in str(e.value)


    def test_settingsqr_parses_line_break_separators(self):
        """ SettingsQR parser should read line breaks as acceptable separators """
        settingsqr_data = "settings::v1\nname=Foo\nsigs=ss,ms\nscripts=nat,nes,tr\nxpub_export=E\n"
        config_name, settings_update_dict = Settings.parse_settingsqr(settingsqr_data)

        assert len(settings_update_dict.keys()) == 3

        # Accepts update with no Exceptions
        self.settings.update(new_settings=settings_update_dict)

    def test_update_handles_legacy_multiselect_format(self):
        """Updating from old list-of-lists format should normalize to list of values"""
        legacy = [[opt[0], opt[1]] for opt in SettingsConstants.ALL_SMARTCARD_INTERFACES]

        with patch("os.system"), patch("time.sleep"):
            self.settings.update({
                SettingsConstants.SETTING__SMARTCARD_INTERFACES: legacy
            })

        expected = [opt[0] for opt in SettingsConstants.ALL_SMARTCARD_INTERFACES]
        assert self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_INTERFACES) == expected

    def test_update_skips_unchanged_smartcard_interfaces(self):
        """Updating with identical smartcard interfaces should not restart pcscd"""
        current = self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_INTERFACES)
        with patch("os.system") as mock_system, patch("time.sleep"):
            self.settings.update({
                SettingsConstants.SETTING__SMARTCARD_INTERFACES: current
            })

        mock_system.assert_not_called()

    def test_update_can_skip_persist(self):
        """Updating with persist=False should not trigger a save to disk"""
        from unittest.mock import patch
        with patch.object(Settings, "save") as mock_save:
            self.settings.update(
                {SettingsConstants.SETTING__BTC_DENOMINATION: SettingsConstants.BTC_DENOMINATION__THRESHOLD},
                persist=False,
            )
            mock_save.assert_not_called()

    def test_get_instance_loads_without_saving(self):
        """Loading settings from disk should not immediately write them back"""
        from unittest.mock import patch
        BaseTest.reset_settings()
        data = {SettingsConstants.SETTING__PERSISTENT_SETTINGS: SettingsConstants.OPTION__ENABLED}
        with open(Settings.SETTINGS_FILENAME, "w") as f:
            json.dump(data, f)

        with patch.object(Settings, "save") as mock_save:
            settings = Settings.get_instance()
            mock_save.assert_not_called()
            assert settings.get_value(SettingsConstants.SETTING__PERSISTENT_SETTINGS) == SettingsConstants.OPTION__ENABLED

    def test_persisted_camera_rotation_not_overwritten(self):
        """Camera rotation loaded from persisted settings must not be
        overwritten by the platform default during Settings initialization.
        """
        BaseTest.reset_settings()
        target_rotation = SettingsConstants.CAMERA_ROTATION__90
        data = {
            SettingsConstants.SETTING__PERSISTENT_SETTINGS: SettingsConstants.OPTION__ENABLED,
            SettingsConstants.SETTING__CAMERA_ROTATION: target_rotation,
        }
        with open(Settings.SETTINGS_FILENAME, "w") as f:
            json.dump(data, f)

        with patch.object(Settings, "save"):
            settings = Settings.get_instance()
            assert settings.get_value(SettingsConstants.SETTING__CAMERA_ROTATION) == target_rotation

    def test_persisted_display_config_not_overwritten(self):
        """Display configuration loaded from persisted settings must not be
        overwritten by the platform default during Settings initialization.
        """
        BaseTest.reset_settings()
        target_display = SettingsConstants.DISPLAY_CONFIGURATION__ST7789__320x240
        data = {
            SettingsConstants.SETTING__PERSISTENT_SETTINGS: SettingsConstants.OPTION__ENABLED,
            SettingsConstants.SETTING__DISPLAY_CONFIGURATION: target_display,
        }
        with open(Settings.SETTINGS_FILENAME, "w") as f:
            json.dump(data, f)

        with patch.object(Settings, "save"):
            settings = Settings.get_instance()
            assert settings.get_value(SettingsConstants.SETTING__DISPLAY_CONFIGURATION) == target_display

    def test_set_value_ignores_missing_settings_entry(self):
        """set_value should not raise if the settings entry cannot be found"""
        from seedsigner.models import settings_definition

        # Force SettingsDefinition.get_settings_entry to return None for camera device
        orig = settings_definition.USING_MOCK_GPIO
        settings_definition.USING_MOCK_GPIO = False
        try:
            current = self.settings.get_value(SettingsConstants.SETTING__CAMERA_DEVICE)
            # Should silently ignore without raising
            self.settings.set_value(SettingsConstants.SETTING__CAMERA_DEVICE, current)
            assert self.settings.get_value(SettingsConstants.SETTING__CAMERA_DEVICE) == current
        finally:
            settings_definition.USING_MOCK_GPIO = orig

    def test_settingsqr_numeric_parsing_rejects_superscript_digits(self):
        """Settings QR parser should not crash on non-ASCII digit characters.

        Python's str.isdigit() returns True for Unicode superscript digits
        (e.g. '¹²³') but int() raises ValueError on them. The parser must
        handle this gracefully by keeping the value as a string rather than
        crashing.
        """
        # camera=¹⁸⁰ uses Unicode superscript digits — old .isdigit() path
        # would pass the pre-check but crash on int('¹⁸⁰').
        # The parser should treat this as a non-numeric string value.
        superscript_180 = "\u00b9\u2078\u2070"  # ¹⁸⁰
        settingsqr_data = f"settings::v1 camera={superscript_180}"
        # Superscript digits: isdigit() == True but int() fails
        assert superscript_180.isdigit() is True  # precondition

        # Should raise InvalidSettingsQRData because the value is not a valid
        # option for "camera", but must NOT raise ValueError/crash.
        with pytest.raises(InvalidSettingsQRData):
            Settings.parse_settingsqr(settingsqr_data)
