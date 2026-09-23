"""
    Keycard flows driven against a *real* applet (v3.2) running in jcardsim.

    The smartcard menu tests walk these menus against stand-in connectors, and the
    connector-level suite (tests/test_jcardsim_keycard.py) proves the applet's crypto
    end to end; this file joins the two: real Screens, driven by scripted button
    presses, talking through SeedSigner's keycard-py adapter to actual applet bytecode.

    The xpub export chain in particular cannot be faked: SatochipExportXpubDetailsView
    calls card_bip32_get_xpub over the secure channel twice (child and master), so the
    string shown on screen is what the applet really derived -- asserted here against
    embit.

    Skips with a reason when Java or the applet sources are absent.
"""

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import FlowStep, FlowTest

from jcardsim import JCardSimUnavailable, why_unavailable
from real_screen_fixtures import simulated_keycard
from ui_driver import UISession, select

# tools_views must be imported first: it is a facade that star-imports smartcard_views.
from seedsigner.views import tools_views
from seedsigner.views import smartcard_views
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import MainMenuView


pytestmark = pytest.mark.skipif(
    why_unavailable() is not None, reason=f"jcardsim unavailable: {why_unavailable()}"
)

TEST_SEED_HEX = "00" * 32 + "11" * 32


class SimulatedKeycardFlowTest(FlowTest):

    def setup_method(self):
        super().setup_method()
        for setting in (
            SettingsConstants.SETTING__SMARTCARD_SUPPORT,
            SettingsConstants.SETTING__SATOCHIP_SUPPORT,
            SettingsConstants.SETTING__KEYCARD_SUPPORT,
        ):
            self.settings.set_value(setting, SettingsConstants.OPTION__ENABLED)

    def keycard_steps(self) -> list:
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView,
                     button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
            FlowStep(smartcard_views.ToolsSmartcardMenuView,
                     button_data_selection=smartcard_views.ToolsSmartcardMenuView.KEYCARD),
        ]



class TestKeycardXpubExportAgainstRealApplet(SimulatedKeycardFlowTest):
    """
    KeyCard Functions > Export Xpub, end to end against a seeded v3.2 applet.

    The Details view derives on-card through the real secure channel; the exported xpub
    must be exactly what embit derives from the same seed (version bytes, depth,
    fingerprint and child number included).
    """

    def test_export_xpub_chain(self, monkeypatch):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K
        from embit import bip32

        try:
            ctx = simulated_keycard(monkeypatch, seed_hex=TEST_SEED_HEX)
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx as connector:
            self.settings.set_value(
                SettingsConstants.SETTING__SCRIPT_TYPES, [SettingsConstants.NATIVE_SEGWIT]
            )
            self.settings.set_value(
                SettingsConstants.SETTING__XPUB_QR_FORMAT,
                [SettingsConstants.XPUB_QR_FORMAT__SPECTER_LEGACY],
            )

            displayed = []
            qr_frame_baseline = []

            session = UISession(script=(
                select(smartcard_views.ToolsKeycardView.EXPORT_XPUB)
                + select(smartcard_views.SatochipExportXpubSigTypeView.SINGLE_SIG)
                + select(0)      # script type (native segwit, the only one enabled)
                + select(0)      # "I Understand" on the privacy warning
                + select(0)      # confirm the derivation details
                + [K.KEY_PRESS]  # any click dismisses the QR
            ))

            self.run_sequence(
                self.keycard_steps() + [
                    FlowStep(smartcard_views.ToolsKeycardView, real_screens=True),
                    FlowStep(smartcard_views.SatochipExportXpubSigTypeView, real_screens=True),
                    FlowStep(smartcard_views.SatochipExportXpubScriptTypeView, real_screens=True),
                    FlowStep(smartcard_views.SatochipExportXpubCoordinatorView, real_screens=True),
                    FlowStep(smartcard_views.SatochipExportXpubWarningView, real_screens=True),
                    FlowStep(smartcard_views.SatochipExportXpubDetailsView, real_screens=True),
                    FlowStep(
                        smartcard_views.SatochipExportXpubQRDisplayView,
                        real_screens=True,
                        before_run=lambda view: (
                            displayed.append(view.xpub),
                            qr_frame_baseline.append(len(session.renderer.frames)),
                        ),
                    ),
                ],
                ui_session=session,
            )

        # The QR display thread must have rendered at least one frame on top of the
        # screen's initial render (BaseScreen.display() draws and shows the static screen
        # once before starting its threads). A crash in the encoder it drives -- e.g.
        # _SpecterEncoder lacking part_to_image/next_part_image -- dies on its first
        # iteration, leaving exactly that one initial frame behind; the xpub assertions
        # below would pass either way, so this is what catches that class of bug.
        assert len(session.renderer.frames) >= qr_frame_baseline[0] + 2

        # The xpub the flow actually displayed must be what embit derives from the same seed.
        # Native segwit single-sig exports with the zpub version bytes (0x04B24746), matching
        # the "p2wpkh" xtype the Details view passes to card_bip32_get_xpub.
        assert len(displayed) == 1
        master = bip32.HDKey.from_seed(bytes.fromhex(TEST_SEED_HEX))
        expected_key = master.derive("m/84'/0'/0'")
        parent = master.derive("m/84'/0'")
        expected_xpub = bip32.HDKey(
            key=expected_key.get_public_key(),
            chain_code=expected_key.chain_code,
            version=bytes.fromhex("04b24746"),
            depth=3,
            fingerprint=parent.my_fingerprint,
            child_number=0x80000000,
        ).to_base58()

        assert displayed[0] == expected_xpub
