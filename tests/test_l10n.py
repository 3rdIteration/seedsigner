from gettext import gettext as _
import os
import pytest

from base import BaseTest
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views.view import MainMenuView

# Skip these tests if translation files are unavailable
translations_path = os.path.join(os.path.dirname(__file__), "..", "src", "seedsigner", "resources", "seedsigner-translations")
if not os.path.isdir(translations_path) or not os.listdir(translations_path):
    pytest.skip("translations not present", allow_module_level=True)



class TestGettext(BaseTest):
    def test_english_as_default(self):
        # Key is available in other languages, but we get English back
        assert _("Home") == "Home"

    def test_missing_key_returns_english_key(self):
        test_str = "This is not in our translation library"
        assert _(test_str) == test_str
    

    def test_basic_spanish(self):
        settings = Settings.get_instance()
        settings.set_value(SettingsConstants.SETTING__LOCALE, SettingsConstants.LOCALE__SPANISH)
        assert _("Home") != "Home"


    def test_locale_changes(self):
        settings = Settings.get_instance()

        settings.set_value(SettingsConstants.SETTING__LOCALE, SettingsConstants.LOCALE__SPANISH)
        spanish_str = _("Home")

        settings.set_value(SettingsConstants.SETTING__LOCALE, SettingsConstants.LOCALE__ENGLISH)
        assert spanish_str != _("Home")
        assert _("Home") == "Home"



class TestButtonOption(BaseTest):
    def test_english_key_not_translated(self):
        """ ButtonOption should always return its English key, regardless of current locale setting. """
        button_option = ButtonOption("Home")
        settings = Settings.get_instance()
        settings.set_value(SettingsConstants.SETTING__LOCALE, SettingsConstants.LOCALE__SPANISH)

        assert button_option.button_label == "Home"

        brand_new_button_option = ButtonOption("Tools")
        assert brand_new_button_option.button_label == "Tools"
    

    def test_class_level_button_option_english_key_not_translated(self):
        settings = Settings.get_instance()
        settings.set_value(SettingsConstants.SETTING__LOCALE, SettingsConstants.LOCALE__SPANISH)

        class FooClass:
            HOME = ButtonOption("Home")
        
        assert FooClass.HOME.button_label == "Home"


    def test_gettext_translates_class_level_button_option(self):
        settings = Settings.get_instance()
        settings.set_value(SettingsConstants.SETTING__LOCALE, SettingsConstants.LOCALE__SPANISH)

        class BarClass:
            HOME = ButtonOption("Home")

        assert _(BarClass.HOME.button_label) != "Home"



class TestMarkForTranslation(BaseTest):
    def test_english_key_not_translated(self):
        """ _mft() should always return its English key, regardless of current locale setting. """
        mft_attr = _mft("Home")
        settings = Settings.get_instance()
        settings.set_value(SettingsConstants.SETTING__LOCALE, SettingsConstants.LOCALE__SPANISH)

        assert mft_attr == "Home"

        brand_new_mft_attr = _mft("Tools")
        assert brand_new_mft_attr == "Tools"


    def test_class_level_mft_attr_english_key_not_translated(self):
        settings = Settings.get_instance()
        settings.set_value(SettingsConstants.SETTING__LOCALE, SettingsConstants.LOCALE__SPANISH)

        class FooClass:
            home = _mft("Home")
        
        assert FooClass.home == "Home"


    def test_gettext_translates_class_level_mft_attr(self):
        settings = Settings.get_instance()
        settings.set_value(SettingsConstants.SETTING__LOCALE, SettingsConstants.LOCALE__SPANISH)

        class BarClass:
            home = _mft("Home")

        assert _(BarClass.home) != "Home"



class TestPortugueseKeycard(BaseTest):
    """European Portuguese (pt_PT) catalog regression.

    Proves end-to-end that (a) pt_PT is auto-detected from its compiled
    .mo, and (b) the newly-wrapped Keycard / feature strings actually
    resolve to their Portuguese values (i.e. the _() wrapping "took" and
    the strings vary by the selected language).
    """

    def test_pt_pt_is_detected(self):
        detected = dict(SettingsConstants.get_detected_languages())
        assert SettingsConstants.LOCALE__PORTUGUESE_PT in detected
        assert detected[SettingsConstants.LOCALE__PORTUGUESE_PT] == "Português (Portugal)"

    def test_keycard_strings_translate_to_portuguese(self):
        settings = Settings.get_instance()
        settings.set_value(SettingsConstants.SETTING__LOCALE, SettingsConstants.LOCALE__PORTUGUESE_PT)

        # Representative strings from the keycard / cards / settings flows
        # that were raw English literals before the l10n pass.
        assert _("Card locked") == "Cartão bloqueado"
        assert _("Generate key") == "Gerar chave"
        assert _("Lock card") == "Bloquear cartão"
        assert _("Insert a card first") == "Insira primeiro um cartão"

        # Card-storage feature strings.
        assert _("Storage") == "Armazenamento"
        assert _("Low space") == "Pouco espaço"
        assert "{}" in _("{}% used")
        assert _("iOS Seedkeeper may crash") == "iOS Seedkeeper pode falhar"
        assert "{}" in _("Free: {} KB")
        assert _("Free: {} KB").format("12.3") == "Livre: 12.3 KB"

        # f-string templates keep their placeholders intact post-translation.
        assert "{}" in _("Keycard · {}")
        assert _("Keycard · {}").format("Inst 1") == "Keycard · Inst 1"

    def test_strings_vary_by_language(self):
        settings = Settings.get_instance()

        settings.set_value(SettingsConstants.SETTING__LOCALE, SettingsConstants.LOCALE__PORTUGUESE_PT)
        pt = _("Generate key")

        settings.set_value(SettingsConstants.SETTING__LOCALE, SettingsConstants.LOCALE__ENGLISH)
        assert _("Generate key") == "Generate key"
        assert pt != _("Generate key")
