"""
    Construction tests for every Screen that builds a Keyboard.

    Keyboard.__init__ raises if the charset plus additional keys don't fit in
    the rows x cols layout, and screens build all of their keyboards in
    __post_init__, so any layout regression (e.g. an upstream change to a key's
    "size") crashes on-device at runtime the first time the screen is shown.
    Instantiating each screen here -- with a mocked Renderer carrying real
    canvas dimensions, as in test_tools_screens.py -- catches that class of bug
    in CI instead.

    When adding a new Screen that constructs a Keyboard, add it to SCREEN_CASES.
"""

from unittest.mock import MagicMock, patch

import pytest

# Must import test base before the Controller
from base import BaseTest


def _keyboard_layout_invariant(keyboard):
    slots = keyboard.rows * keyboard.cols
    used = len(keyboard.charset) + sum(
        key.size for row in keyboard.keys for key in row if key.is_additional_key
    )
    assert used <= slots, (
        f"Keyboard layout overflow: {used} keys need more than the "
        f"{keyboard.rows}x{keyboard.cols}={slots} available slots "
        f"(charset={len(keyboard.charset)} chars)"
    )


def _assert_all_keyboards_fit(screen):
    from seedsigner.gui.keyboard import Keyboard

    keyboards = [value for value in vars(screen).values() if isinstance(value, Keyboard)]
    assert keyboards, f"{screen.__class__.__name__} was expected to build at least one Keyboard"
    for keyboard in keyboards:
        _keyboard_layout_invariant(keyboard)


from seedsigner.gui.screens.seed_screens import (
    SeedMnemonicEntryScreen,
    SeedAddPassphraseScreen,
    SeedBIP85SelectChildIndexScreen,
    SeedExportXpubAccountNumberScreen,
    SeedExportXpubCustomDerivationScreen,
    SeedEncryptedQRMnemonicIDScreen,
)
from seedsigner.gui.screens.scan_screens import ScanTypeEncryptionKeyScreen
from seedsigner.gui.screens.settings_screens import SettingPBFDK2IterationsScreen
from seedsigner.gui.screens.tools_screens import (
    ToolsCoinFlipEntryScreen,
    ToolsDiceEntropyEntryScreen,
    ToolsTextQRTextEntryScreen,
)


SCREEN_CASES = [
    (ToolsTextQRTextEntryScreen, dict(textToEncode="hello", title="Name")),
    (ScanTypeEncryptionKeyScreen, dict()),
    (SeedAddPassphraseScreen, dict(passphrase="test phrase", title="BIP-39 Passphrase")),
    (SeedEncryptedQRMnemonicIDScreen, dict(mnemonic_id="abc123def456")),
    (SeedMnemonicEntryScreen, dict(initial_letters=["a", "b"], wordlist=["abandon", "ability"])),
    (SettingPBFDK2IterationsScreen, dict(initial_value="4096")),
    (ToolsDiceEntropyEntryScreen, dict(return_after_n_chars=50)),
    (ToolsCoinFlipEntryScreen, dict(return_after_n_chars=4)),
    (SeedBIP85SelectChildIndexScreen, dict()),
    (SeedExportXpubAccountNumberScreen, dict()),
    (SeedExportXpubCustomDerivationScreen, dict()),
]


class TestScreenConstruction(BaseTest):

    def setup_method(self):
        super().setup_method()

        from seedsigner.gui.renderer import Renderer

        self.mock_renderer = MagicMock()
        self.mock_renderer.canvas_width = 240
        self.mock_renderer.canvas_height = 240
        self.renderer_patch = patch.object(Renderer, "get_instance", return_value=self.mock_renderer)
        self.renderer_patch.start()

    def teardown_method(self):
        self.renderer_patch.stop()
        super().teardown_method()


    @pytest.mark.parametrize("screen_cls,kwargs", SCREEN_CASES, ids=[cls.__name__ for cls, _ in SCREEN_CASES])
    def test_screen_constructs_and_keyboards_fit(self, screen_cls, kwargs):
        screen = screen_cls(**kwargs)
        _assert_all_keyboards_fit(screen)
