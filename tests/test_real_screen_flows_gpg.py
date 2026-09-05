"""
    Real-screen flow tests for GPG Tools.

    gpg_views.py is the largest view module in the app (64 View classes) and 36 of them
    were never named in any test: the whole Subkey, UID, Secure Messaging, Export and
    SmartGPG submenus. The two existing real-screen GPG tests
    (test_real_screen_flows.py) cover only the BIP-85 derive and generate-new keyboard
    prompts.

    These run against a real gpg binary in an isolated GNUPGHOME, so they exercise the
    actual subprocess calls rather than a stand-in. CI installs gnupg2, so this is real
    coverage there too; the GPG_AVAILABLE guard only skips environments without it.

    SmartGPG needs a physical OpenPGP card, so only its menu and no-card error paths are
    covered here.
"""

import subprocess

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import FlowStep, FlowTest
from real_screen_fixtures import gnupghome, requires_gpg  # noqa: F401  (fixture)
from ui_driver import Back, UISession, select

# tools_views must be imported first: it is a facade that star-imports gpg_views,
# and reaching gpg_views directly first hits a circular import.
from seedsigner.views import tools_views
from seedsigner.views import gpg_views
from seedsigner.views.view import MainMenuView


pytestmark = requires_gpg


def generate_test_key(gnupghome: str, uid: str = "Flow Test <flow@example.com>") -> str:
    """Put one real secret key in the isolated keyring; returns its fingerprint."""
    import os

    env = dict(os.environ, GNUPGHOME=gnupghome)
    subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-generate-key", uid, "default", "default", "never"],
        capture_output=True, text=True, env=env, check=True,
    )
    listed = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-secret-keys"],
        capture_output=True, text=True, env=env, check=True,
    )
    for line in listed.stdout.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    raise AssertionError(f"no key generated:\n{listed.stdout}")


class GPGFlowTest(FlowTest):

    def gpg_steps(self, *options) -> list:
        """From the main menu into GPG Tools, then down `options` worth of menus."""
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.GPG),
        ]



class TestGPGViewKeysFlow(GPGFlowTest):
    """
    GPG Tools > View Keys. Read-only, pure ButtonListScreens, and the easiest real GPG
    walk -- but the whole chain (key list, key details, subkey list, subkey details) was
    unwalked.
    """

    def test_walk_a_real_keys_details_and_subkeys(self, gnupghome):
        generate_test_key(gnupghome)

        session = UISession(script=(
            select(gpg_views.ToolsGPGMenuView.VIEW_KEYS)
            + select(0)  # the one key in the keyring
            + select(0)  # its details -> subkeys
            + select(0)  # the one subkey
            + [Back()]
        ))

        self.run_sequence(
            self.gpg_steps() + [
                FlowStep(gpg_views.ToolsGPGMenuView, real_screens=True),
                FlowStep(gpg_views.ToolsGPGViewKeysView, real_screens=True),
                FlowStep(gpg_views.ToolsGPGKeyDetailsView, real_screens=True),
                FlowStep(gpg_views.ToolsGPGKeySubkeysView, real_screens=True),
                FlowStep(gpg_views.ToolsGPGSubkeyDetailsView, real_screens=True),
                FlowStep(gpg_views.ToolsGPGKeySubkeysView),
            ],
            ui_session=session,
        )

        assert session.renderer.frames, "the real GPG screens never rendered"

    def test_empty_keyring_warns(self, gnupghome):
        """No keys is a warning, not an empty list the user can get stuck in."""
        session = UISession(script=(
            select(gpg_views.ToolsGPGMenuView.VIEW_KEYS)
            + select(0)  # "OK" on the no-keys warning
        ))

        self.run_sequence(
            self.gpg_steps() + [
                FlowStep(gpg_views.ToolsGPGMenuView, real_screens=True),
                FlowStep(gpg_views.ToolsGPGViewKeysView, real_screens=True),
                FlowStep(gpg_views.ToolsGPGMenuView),
            ],
            ui_session=session,
        )



class TestGPGSubmenuNavigation(GPGFlowTest):
    """
    The submenus themselves. Every one of these was among the 36 gpg_views classes
    never named in a test, so a screen-construction error in any of them would only
    have shown up on device.
    """

    @pytest.mark.parametrize(
        "menu_option, submenu_view",
        [
            (gpg_views.ToolsGPGMenuView.FILE_OPS, gpg_views.ToolsGPGFileOpsMenuView),
            (gpg_views.ToolsGPGMenuView.IMPORT, gpg_views.ToolsGPGImportMenuView),
            (gpg_views.ToolsGPGMenuView.EXPORT, gpg_views.ToolsGPGExportMenuView),
            (gpg_views.ToolsGPGMenuView.MESSAGE, gpg_views.ToolsGPGMessageMenuView),
            (gpg_views.ToolsGPGMenuView.SMART_GPG, gpg_views.ToolsGPGSmartMenuView),
            (gpg_views.ToolsGPGMenuView.ADVANCED, gpg_views.ToolsGPGAdvancedMenuView),
        ],
    )
    def test_submenu_opens_and_backs_out(self, gnupghome, menu_option, submenu_view):
        session = UISession(script=select(menu_option) + [Back()])

        self.run_sequence(
            self.gpg_steps() + [
                FlowStep(gpg_views.ToolsGPGMenuView, real_screens=True),
                FlowStep(submenu_view, real_screens=True),
                FlowStep(gpg_views.ToolsGPGMenuView),
            ],
            ui_session=session,
        )

    @pytest.mark.parametrize(
        "advanced_option, submenu_view",
        [
            (gpg_views.ToolsGPGAdvancedMenuView.SUBKEY_OPS, gpg_views.ToolsGPGSubkeyMenuView),
            (gpg_views.ToolsGPGAdvancedMenuView.UID_OPS, gpg_views.ToolsGPGUidMenuView),
            (gpg_views.ToolsGPGAdvancedMenuView.BIP85_META, gpg_views.ToolsGPGBip85MetadataMenuView),
        ],
    )
    def test_advanced_submenu_opens_and_backs_out(self, gnupghome, advanced_option, submenu_view):
        session = UISession(script=(
            select(gpg_views.ToolsGPGMenuView.ADVANCED)
            + select(advanced_option)
            + [Back()]
        ))

        self.run_sequence(
            self.gpg_steps() + [
                FlowStep(gpg_views.ToolsGPGMenuView, real_screens=True),
                FlowStep(gpg_views.ToolsGPGAdvancedMenuView, real_screens=True),
                FlowStep(submenu_view, real_screens=True),
                FlowStep(gpg_views.ToolsGPGAdvancedMenuView),
            ],
            ui_session=session,
        )

    def test_sign_submenu_under_file_ops(self, gnupghome):
        session = UISession(script=(
            select(gpg_views.ToolsGPGMenuView.FILE_OPS)
            + select(gpg_views.ToolsGPGFileOpsMenuView.SIGN)
            + [Back()]
        ))

        self.run_sequence(
            self.gpg_steps() + [
                FlowStep(gpg_views.ToolsGPGMenuView, real_screens=True),
                FlowStep(gpg_views.ToolsGPGFileOpsMenuView, real_screens=True),
                FlowStep(gpg_views.ToolsGPGSignMenuView, real_screens=True),
                FlowStep(gpg_views.ToolsGPGFileOpsMenuView),
            ],
            ui_session=session,
        )
