"""
    Satodime flows driven against a *real* applet running in jcardsim.

    The Satodime menu + views were cherry-picked from PR #66 and call the pysatochip
    ``satodime_*`` APDUs (status, keyslot status, pubkey). Those calls only mean
    something if SeedSigner's client and the applet agree on the wire format -- exactly
    the class of bug the jcardsim suites exist to catch. Everything here skips when Java
    or the Satochip-DIY sources are absent.

    Two levels:
      * connector-level -- prove the APDUs the views depend on round-trip against the applet;
      * view-level -- drive ToolsSatodimeAddressesView for real, rendering one slot screen
        and backing out (robust to whatever keyslot count / pubkey state the applet has).
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
from real_screen_fixtures import simulated_satodime
from ui_driver import Back, UISession, select

# tools_views must be imported first: it is a facade that star-imports smartcard_views.
from seedsigner.views import tools_views
from seedsigner.views import smartcard_views
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import MainMenuView


pytestmark = pytest.mark.skipif(
    why_unavailable() is not None, reason=f"jcardsim unavailable: {why_unavailable()}"
)


class SatodimeSimulatedFlowTest(FlowTest):

    def setup_method(self):
        super().setup_method()
        for setting in (
            SettingsConstants.SETTING__SMARTCARD_SUPPORT,
            SettingsConstants.SETTING__SATOCHIP_SUPPORT,
        ):
            self.settings.set_value(setting, SettingsConstants.OPTION__ENABLED)


class TestSatodimeConnectorAgainstRealApplet(SatodimeSimulatedFlowTest):
    """The APDUs the Satodime views lean on must round-trip against real bytecode."""

    def test_status_and_card_type(self, monkeypatch):
        try:
            ctx = simulated_satodime(monkeypatch)
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx as connector:
            assert connector.card_type == "Satodime"
            # These are the first three calls every Satodime view makes.
            connector.satodime_set_unlock_secret()
            connector.satodime_set_unlock_counter()
            (_, sw1, sw2, status) = connector.satodime_get_status()
            assert (sw1, sw2) == (0x90, 0x00)
            assert "max_num_keys" in status


class TestSatodimeAddressesAgainstRealApplet(SatodimeSimulatedFlowTest):
    """
    Satodime > View Deposit Addresses renders a real slot screen.

    We render exactly one slot then press BACK, which the view treats as 'stop iterating'.
    That exercises satodime_get_status + get_keyslot_status(0) + get_pubkey(0) end to end
    without depending on how many slots the applet reports or whether a given pubkey is
    initialised (the view already catches per-slot errors and shows them on screen).
    """

    def test_renders_one_slot(self, monkeypatch):
        try:
            ctx = simulated_satodime(monkeypatch)
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx as connector:
            # Skip (rather than fail) if this jcardsim build can't service the status APDU
            # or exposes no slots to render -- neither is a SeedSigner bug.
            try:
                connector.satodime_set_unlock_secret()
                connector.satodime_set_unlock_counter()
                (_, sw1, sw2, status) = connector.satodime_get_status()
            except Exception as exc:  # pragma: no cover - environment dependent
                pytest.skip(f"satodime status unsupported under jcardsim: {exc}")
            if (sw1, sw2) != (0x90, 0x00) or not status.get("max_num_keys"):
                pytest.skip("no satodime slots to render")

            session = UISession(script=(
                select(smartcard_views.ToolsSatodimeView.VIEW_ADDRESSES)
                + [Back()]  # render slot 0, then stop iterating
            ))
            self.run_sequence(
                [
                    FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
                    FlowStep(tools_views.ToolsMenuView,
                             button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
                    FlowStep(smartcard_views.ToolsSmartcardMenuView,
                             button_data_selection=smartcard_views.ToolsSmartcardMenuView.SATODIME),
                    FlowStep(smartcard_views.ToolsSatodimeView, real_screens=True),
                    FlowStep(smartcard_views.ToolsSatodimeAddressesView, real_screens=True),
                    FlowStep(smartcard_views.ToolsSatodimeView),
                ],
                ui_session=session,
            )
