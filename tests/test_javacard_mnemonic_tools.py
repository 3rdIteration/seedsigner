import pytest

from seedsigner.views import tools_views


def test_normalize_bip39_mnemonic_text_normalizes_whitespace():
    text = (
        " Abandon   abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon ART "
    )
    normalized = tools_views._normalize_bip39_mnemonic_text(text)
    assert normalized.startswith("abandon abandon")
    assert normalized.endswith("art")
    assert len(normalized.split(" ")) == 24


def test_normalize_bip39_mnemonic_text_rejects_invalid_word_count():
    with pytest.raises(ValueError):
        tools_views._normalize_bip39_mnemonic_text("abandon " * 11)


def test_javacard_keys_menu_routes_to_load_mnemonic():
    view = object.__new__(tools_views.ToolsJavacardKeysView)

    def fake_run_screen(*args, **kwargs):
        for i, option in enumerate(kwargs["button_data"]):
            if option.button_label == "Load Mnemonic":
                return i
        return 0

    view.run_screen = fake_run_screen
    destination = view.run()

    assert destination.View_cls == tools_views.ToolsJavacardLoadMnemonicView


def test_javacard_keys_menu_routes_to_save_mnemonic():
    view = object.__new__(tools_views.ToolsJavacardKeysView)

    def fake_run_screen(*args, **kwargs):
        for i, option in enumerate(kwargs["button_data"]):
            if option.button_label == "Save Mnemonic":
                return i
        return 0

    view.run_screen = fake_run_screen
    destination = view.run()

    assert destination.View_cls == tools_views.ToolsJavacardSaveMnemonicView
