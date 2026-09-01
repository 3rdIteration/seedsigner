"""
    End-to-end flow tests that run the *real* Screens (via tests.ui_driver.UISession and
    FlowStep.real_screens=True), driving actual button input through each screen's real
    _run() loop.

    The normal flow tests mock View.run_screen(), so Screens are never constructed or
    exercised; these tests close that gap for the highest-value user paths, including
    the GPG BIP85 private-key derivation path whose symbol keyboards used to crash at
    construction with "charset will not fit in a 4x6 layout".
"""

import importlib.util
import os
import shutil
import subprocess
import tempfile

import pytest

import base  # ensure hardware mocks
from base import BaseTest, FlowStep, FlowTest
from ui_driver import UISession, plan_keyboard_screen_script, plan_text_entry_script

from seedsigner.gui.screens.scan_screens import ScanTypeEncryptionKeyScreen
from seedsigner.gui.screens.seed_screens import SeedBIP85SelectChildIndexScreen, SeedEncryptedQRMnemonicIDScreen
from seedsigner.gui.screens.tools_screens import ToolsTextQRTextEntryScreen
from seedsigner.models.seed import Seed
from seedsigner.views import tools_views
from seedsigner.views.view import MainMenuView


MNEMONIC = "resource timber firm banner horror pupil frozen main pear direct pioneer broken grid core insane begin sister pony end debate task silk empty curious".split()

GPG_AVAILABLE = shutil.which("gpg") is not None and importlib.util.find_spec("pgpy") is not None



@pytest.fixture
def gnupghome(monkeypatch):
    """An isolated, *short*-path GNUPGHOME, exported to the environment.

    gpg-agent listens on a unix socket at ``$GNUPGHOME/S.gpg-agent``, so the
    homedir is bound by the ~108 byte ``sun_path`` limit.  pytest's ``tmp_path``
    (``.../pytest-of-<user>/pytest-<n>/<long-test-name><n>/``) blows past that on
    CI runners, and gpg then fails every secret-key operation with "failed to
    start gpg-agent ...: General error".  Rooting the keyring directly under the
    system temp dir keeps it well inside the limit.

    Yields the path already converted for whichever gpg binary is on PATH, ready
    to pass straight through as ``GNUPGHOME``.
    """
    from test_gpg_message import _msys2_path

    # ignore_cleanup_errors: on Windows a lingering gpg-agent can still hold the
    # keyring open when the test ends.
    with tempfile.TemporaryDirectory(prefix="ss-gnupg-", ignore_cleanup_errors=True) as home:
        home = _msys2_path(home)
        monkeypatch.setenv("GNUPGHOME", home)
        yield home


class TestRealScreenFlows(FlowTest):

    def test_gpg_bip85_derive_p256(self, gnupghome):
        """Tools → GPG Tools → Import Keys → Private Key → Derive BIP85 → P-256.

        The user's original bug path: before the KEY_BACKSPACE_2 fix, constructing
        ToolsTextQRTextEntryScreen's symbol keyboards raised "charset will not fit in a
        4x6 layout" on every screen of this flow. Here the name/email/expiration prompts
        are real Screens driven by scripted button presses (including keyboard swaps to
        type "@" and "."), and the derived key is really imported into an isolated GPG
        keyring via the view's actual gpg subprocess call.
        """
        if not GPG_AVAILABLE:
            pytest.skip("gpg binary and/or pgpy not available")

        from seedsigner.hardware.buttons import HardwareButtonsConstants as K
        from seedsigner.views.tools_views import BIP85_DATA

        self.controller.storage.seeds = [Seed(mnemonic=MNEMONIC)]

        name_script = plan_text_entry_script(ToolsTextQRTextEntryScreen, "Bob", title="Name")
        email_script = plan_text_entry_script(ToolsTextQRTextEntryScreen, "bob@example.com", title="Email")
        expiration_script = plan_text_entry_script(
            ToolsTextQRTextEntryScreen, "", textToEncode="2035-12-31", title="Expiration YYYY-MM-DD"
        )
        index_script = plan_keyboard_screen_script(SeedBIP85SelectChildIndexScreen, "0")

        script = (
            [K.KEY_PRESS]              # WarningScreen "experimental" → I Understand
            + index_script             # SeedBIP85SelectChildIndexScreen → key index 0
            + [K.KEY_DOWN, K.KEY_PRESS]  # Key Type list → ECC NIST P-256 (index 1)
            + name_script              # type "Bob" on the real keyboard, then save
            + email_script             # type "bob@example.com" (incl. symbols-keyboard swaps), then save
            + expiration_script        # pre-filled default date → just save
            + [K.KEY_PRESS]            # LargeIconStatusScreen "Success" → Done
        )

        session = UISession(script=script)
        bip85_data_before = set(BIP85_DATA.keys())
        try:
            self.run_sequence([
                FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
                FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.GPG),
                FlowStep(tools_views.ToolsGPGMenuView, button_data_selection=tools_views.ToolsGPGMenuView.IMPORT),
                FlowStep(tools_views.ToolsGPGImportMenuView, button_data_selection=tools_views.ToolsGPGImportMenuView.PRIVKEY),
                FlowStep(tools_views.ToolsGPGImportPrivkeyMenuView, button_data_selection=tools_views.ToolsGPGImportPrivkeyMenuView.LOAD_BIP85_KEY),
                FlowStep(tools_views.ToolsGPGLoadBIP85KeyView, real_screens=True),
            ], ui_session=session)

            # The real Screens rendered frames onto the test renderer
            assert len(session.renderer.frames) > 0

            # The derived key really exists in the isolated GPG keyring with our UID
            env = dict(os.environ, GNUPGHOME=gnupghome)
            listed = subprocess.run(
                ["gpg", "--batch", "--with-colons", "--list-secret-keys"],
                capture_output=True, text=True, env=env,
            )
            assert listed.returncode == 0, f"gpg --list-secret-keys failed (rc={listed.returncode}): {listed.stderr}"
            assert "Bob <bob@example.com>" in listed.stdout

            # The view recorded the derivation metadata for this (deterministic) key
            new_entries = set(BIP85_DATA.keys()) - bip85_data_before
            assert len(new_entries) == 1
            entry = BIP85_DATA[new_entries.pop()]
            assert entry["primary_uid"] == "Bob <bob@example.com>"
            assert entry["key_type"] == "ECC NIST P-256"
        finally:
            for fpr in set(BIP85_DATA.keys()) - bip85_data_before:
                del BIP85_DATA[fpr]


    def test_gpg_generate_new_p256(self, gnupghome):
        """Tools → GPG Tools → Import Keys → Private Key → Generate New → P-256.

        Same real-keyboard prompts as the BIP85 flow (name/email/expiration), but with a
        freshly generated key from OS CSPRNG entropy instead of seed derivation; the key
        is really imported into an isolated GPG keyring via the view's gpg subprocess call.
        """
        if not GPG_AVAILABLE:
            pytest.skip("gpg binary and/or pgpy not available")

        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        name_script = plan_text_entry_script(ToolsTextQRTextEntryScreen, "Alice", title="Name")
        email_script = plan_text_entry_script(ToolsTextQRTextEntryScreen, "alice@example.com", title="Email")
        expiration_script = plan_text_entry_script(
            ToolsTextQRTextEntryScreen, "", textToEncode="2035-12-31", title="Expiration YYYY-MM-DD"
        )

        script = (
            [K.KEY_DOWN, K.KEY_PRESS]  # Key Type list → ECC NIST P-256 (index 1)
            + name_script              # type "Alice" on the real keyboard, then save
            + email_script             # type "alice@example.com" (incl. symbols-keyboard swaps), then save
            + expiration_script        # pre-filled default date → just save
            + [K.KEY_PRESS]            # LargeIconStatusScreen "Success" → Done
        )

        session = UISession(script=script)
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.GPG),
            FlowStep(tools_views.ToolsGPGMenuView, button_data_selection=tools_views.ToolsGPGMenuView.IMPORT),
            FlowStep(tools_views.ToolsGPGImportMenuView, button_data_selection=tools_views.ToolsGPGImportMenuView.PRIVKEY),
            FlowStep(tools_views.ToolsGPGImportPrivkeyMenuView, button_data_selection=tools_views.ToolsGPGImportPrivkeyMenuView.GENERATE_NEW),
            FlowStep(tools_views.ToolsGPGGenerateKeyView, real_screens=True),
        ], ui_session=session)

        assert len(session.renderer.frames) > 0

        env = dict(os.environ, GNUPGHOME=gnupghome)
        listed = subprocess.run(
            ["gpg", "--batch", "--with-colons", "--list-secret-keys"],
            capture_output=True, text=True, env=env,
        )
        assert listed.returncode == 0, f"gpg --list-secret-keys failed (rc={listed.returncode}): {listed.stderr}"
        assert "Alice <alice@example.com>" in listed.stdout


    def test_text_qr_encode_with_symbols(self):
        """Tools → Text QR Code → Encode text, typing on the real keyboard.

        The typed text exercises uppercase (KEY1 swap), lowercase, and symbols_1
        (double KEY2 swap) keyboards plus the space additional key; the View then
        redirects to ToolsTextQRReviewTextView with the entered text intact.
        """
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        text = "Hi @Bob: 42!"
        script = plan_text_entry_script(ToolsTextQRTextEntryScreen, text, title="Text to Encode")

        session = UISession(script=script)
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.TEXTQRCODE),
            FlowStep(tools_views.ToolsTextQRView, screen_return_value=0),  # "Encode text"
            FlowStep(tools_views.ToolsTextQRTextEntryView, real_screens=True),
        ], ui_session=session)

        assert len(session.renderer.frames) > 0



class TestRealScreenKeyboardEntry(BaseTest):
    """Drive the fixed multi-keyboard entry Screens directly (no View involved)."""

    def test_scan_type_encryption_key_screen_typing(self):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        text = "s3cr3t@key"
        script = plan_text_entry_script(ScanTypeEncryptionKeyScreen, text)

        with UISession(script=script) as session:
            result = ScanTypeEncryptionKeyScreen(encryptionkey="").display()

        assert result == {"encryptionkey": text}
        assert len(session.renderer.frames) > 0


    def test_seed_encrypted_qr_mnemonic_id_screen_typing(self):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        text = "ID-42#x"
        script = plan_text_entry_script(SeedEncryptedQRMnemonicIDScreen, text)

        with UISession(script=script) as session:
            result = SeedEncryptedQRMnemonicIDScreen(mnemonic_id="").display()

        assert result == {"mnemonic_id": text}
        assert len(session.renderer.frames) > 0


    def test_text_qr_entry_screen_back_button(self):
        """KEY_UP selects the top nav; KEY_PRESS there returns is_back_button."""
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        with UISession(script=[K.KEY_UP, K.KEY_PRESS]) as session:
            result = ToolsTextQRTextEntryScreen(textToEncode="", title="Name").display()

        assert result == {"textToEncode": "", "is_back_button": True}
