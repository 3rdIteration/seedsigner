"""A multiselect setting given exactly one value arrives as a bare scalar.

A SettingsQR that picks a single seed word length parses as an int, passes the
review screen, and then reaches set_value(), which requires a list. The result
is the unhandled-error screen, with the keys ahead of it in the dict already
applied.
"""
# Must import base before any seedsigner modules
from base import BaseTest

from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants, SettingsDefinition


class TestSingleValueMultiselect(BaseTest):

    def test_one_seed_length_from_a_settings_qr_is_applied(self):
        settings = Settings.get_instance()

        settings.update(
            Settings.parse_settingsqr("settings::v1 name=Only_24 seedlen=24")[1],
            persist=False,
        )

        assert settings.get_value(SettingsConstants.SETTING__SEED_WORD_LENGTHS) == [24]

    def test_one_value_for_every_multiselect_setting(self, monkeypatch):
        """
        seed_word_lengths is the only int-valued multiselect today, which is why
        this surfaced there, but nothing about the bug was specific to it.
        """
        import os

        def no_commands(command):
            raise AssertionError(f"a setting ran a command on the test host: {command}")

        # Changing the smartcard interfaces powers USB ports and restarts PCSC
        # on the machine running the tests, so it is left out; any other
        # setting that runs a command fails here instead of running it.
        monkeypatch.setattr(os, "system", no_commands)
        settings = Settings.get_instance()

        for entry in SettingsDefinition.settings_entries:
            if entry.type != SettingsConstants.TYPE__MULTISELECT:
                continue
            if entry.attr_name == SettingsConstants.SETTING__SMARTCARD_INTERFACES:
                continue
            one = entry.selection_options[0]
            value = one[0] if isinstance(one, (list, tuple)) else one

            settings.update({entry.attr_name: value}, persist=False)

            assert settings.get_value(entry.attr_name) == [value], entry.attr_name
