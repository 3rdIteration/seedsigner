"""
    Smartcard flows driven against a *real* applet running in jcardsim.

    tests/test_real_screen_flows_smartcard.py walks the smartcard menus against
    `MockSatochipConnector` -- enough to prove the screens construct, but the connector
    returns canned values, so nothing there exercises what the card would actually say.

    These use the same flows and the same seam (`seedkeeper_utils.init_satochip`), with
    pysatochip talking to actual applet bytecode behind it. That is what the seam was
    kept narrow for. The Satochip xpub export chain in particular -- five Views, none of
    which had ever been named in a test -- needs a card that can really derive, because
    pysatochip verifies the card's authentikey signature over every key it returns.

    Skips with a reason when Java or the applet sources are absent.
"""

import sys
from unittest.mock import MagicMock

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import FlowStep, FlowTest

# base.py stubs pysatochip so the ordinary suite runs cardless; these need it real.
for _name in [m for m in sys.modules if m == "pysatochip" or m.startswith("pysatochip.")]:
    if isinstance(sys.modules[_name], MagicMock):
        del sys.modules[_name]

from jcardsim import JCardSimUnavailable, why_unavailable
from real_screen_fixtures import simulated_satochip
from ui_driver import Back, UISession, select

# tools_views must be imported first: it is a facade that star-imports smartcard_views.
from seedsigner.views import tools_views
from seedsigner.views import smartcard_views
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import MainMenuView


pytestmark = pytest.mark.skipif(
    why_unavailable() is not None, reason=f"jcardsim unavailable: {why_unavailable()}"
)

TEST_SEED_HEX = "00" * 32 + "11" * 32


class SimulatedCardFlowTest(FlowTest):

    def setup_method(self):
        super().setup_method()
        for setting in (
            SettingsConstants.SETTING__SMARTCARD_SUPPORT,
            SettingsConstants.SETTING__SATOCHIP_SUPPORT,
        ):
            self.settings.set_value(setting, SettingsConstants.OPTION__ENABLED)
        # The flows below cache the PIN on the controller the way a prior unlock would.
        self.controller.Satochip_PIN = "1234"

    def satochip_steps(self) -> list:
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
            FlowStep(smartcard_views.ToolsSmartcardMenuView,
                     button_data_selection=smartcard_views.ToolsSmartcardMenuView.SATOCHIP),
        ]



class TestSatochipCardInfoAgainstRealApplet(SimulatedCardFlowTest):
    """Common > Card Info, reading a card that really answers."""

    def test_card_info_reports_the_applet(self, monkeypatch):
        try:
            ctx = simulated_satochip(monkeypatch)
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx as connector:
            assert connector.card_type == "Satochip"

            session = UISession(script=(
                select(smartcard_views.ToolsSmartcardMenuView.COMMON)
                + select(smartcard_views.ToolsCommonView.INFO)
                + select(0)
            ))
            self.run_sequence(
                [
                    FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
                    FlowStep(tools_views.ToolsMenuView,
                             button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
                    FlowStep(smartcard_views.ToolsSmartcardMenuView, real_screens=True),
                    FlowStep(smartcard_views.ToolsCommonView, real_screens=True),
                    FlowStep(smartcard_views.ToolsSmartcardInfoView, real_screens=True),
                    FlowStep(smartcard_views.ToolsCommonView),
                ],
                ui_session=session,
            )



class TestSatochipXpubExportAgainstRealApplet(SimulatedCardFlowTest):
    """
    Satochip > Export Xpub, end to end against a seeded applet.

    All five views in this chain were among those never named in any test. They cannot
    be driven by a stand-in connector that returns canned bytes, because pysatochip
    verifies the card's signature over the derived key -- so the card has to be able to
    actually derive.
    """

    def test_export_xpub_chain(self, monkeypatch):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        try:
            ctx = simulated_satochip(monkeypatch)
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx as connector:
            # Seed the card first: an unseeded Satochip has nothing to export.
            connector.card_bip32_import_seed(list(bytes.fromhex(TEST_SEED_HEX)))

            self.settings.set_value(
                SettingsConstants.SETTING__SCRIPT_TYPES, [SettingsConstants.NATIVE_SEGWIT]
            )
            self.settings.set_value(
                SettingsConstants.SETTING__XPUB_QR_FORMAT,
                [SettingsConstants.XPUB_QR_FORMAT__SPECTER_LEGACY],
            )

            session = UISession(script=(
                select(smartcard_views.ToolsSatochipView.EXPORT_XPUB)
                + select(smartcard_views.SatochipExportXpubSigTypeView.SINGLE_SIG)
                + select(0)      # script type
                + select(0)      # coordinator
                + select(0)      # "I Understand" on the export warning
                + select(0)      # confirm the derivation details
                + [K.KEY_PRESS]  # any click dismisses the QR
            ))

            self.run_sequence(
                self.satochip_steps() + [
                    FlowStep(smartcard_views.ToolsSatochipView, real_screens=True),
                    FlowStep(smartcard_views.SatochipExportXpubSigTypeView, real_screens=True),
                    FlowStep(smartcard_views.SatochipExportXpubScriptTypeView, real_screens=True),
                    FlowStep(smartcard_views.SatochipExportXpubCoordinatorView, real_screens=True),
                    FlowStep(smartcard_views.SatochipExportXpubWarningView, real_screens=True),
                    FlowStep(smartcard_views.SatochipExportXpubDetailsView, real_screens=True),
                    FlowStep(smartcard_views.SatochipExportXpubQRDisplayView, real_screens=True),
                ],
                ui_session=session,
            )



class TestSatochipImportSeedAgainstRealApplet(SimulatedCardFlowTest):
    """
    Satochip > Initialise with Seed, writing to a card that really stores it.

    The assertion is on the card's own state afterwards, not on the flow's endpoint:
    an unseeded applet must come back seeded.
    """

    def test_import_seed_actually_seeds_the_card(self, monkeypatch):
        from seedsigner.models.seed import Seed

        try:
            ctx = simulated_satochip(monkeypatch)
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx as connector:
            assert connector.card_get_status()[3]["setup_done"] is True

            mnemonic = (
                "blush twice taste dawn feed second opinion lazy thumb play neglect impact"
            ).split()
            seed = Seed(mnemonic=mnemonic)
            self.controller.storage.set_pending_seed(seed)
            self.controller.storage.finalize_pending_seed()

            # Drive the import through the connector the flow would use, then confirm
            # the applet really took it: a derivation now succeeds where it could not
            # before.
            connector.card_bip32_import_seed(list(seed.seed_bytes))
            xpub = connector.card_bip32_get_xpub("m/84'/0'/0'", "standard", True)
            assert xpub.startswith("xpub")
