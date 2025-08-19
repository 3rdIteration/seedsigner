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

    def test_save_skips_fsync_off_device(self, tmp_path, monkeypatch):
        """save() should avoid fsync when not running on SeedSignerOS"""
        from seedsigner.hardware.microsd import MicroSD
        settings = Settings.get_instance()
        # enable persistence without writing to disk yet
        settings.set_value(
            SettingsConstants.SETTING__PERSISTENT_SETTINGS,
            SettingsConstants.OPTION__ENABLED,
            save=False,
        )
        monkeypatch.setattr(Settings, "HOSTNAME", "devhost")
        monkeypatch.setattr(Settings, "SETTINGS_FILENAME", str(tmp_path / "settings.json"))

        class DummyMS:
            @property
            def is_inserted(self):
                return True

        monkeypatch.setattr(MicroSD, "get_instance", lambda: DummyMS())

        with patch("os.fsync") as mock_fsync:
            settings.save()
            mock_fsync.assert_not_called()
