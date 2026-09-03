"""
    Flow tests for ToolsSatochipEnable2FAView.

    Enabling 2FA on a Satochip card is effectively irreversible from within SeedSigner
    (nothing in the app calls card_reset_2FA_key), so the View gates the key write
    behind two explicit confirmations and treats BACK on the pairing QR screen as
    cancellation. These tests cover:

      * cancel at the first confirmation -> nothing is written to the card
      * full success path -> card_set_2FA_key called exactly once with a 20-byte key
      * card already requires 2FA -> short-circuits before any key is generated
      * (real Screens) BACK on the QR screen cancels before the write
      * (real Screens) cancel at the final confirmation after scanning cancels before the write
"""

import pytest

from base import FlowStep, FlowTest
from ui_driver import UISession

from seedsigner.helpers import seedkeeper_utils
from seedsigner.views import tools_views
from seedsigner.views.smartcard_views import (
    ToolsSatochipAdvancedView,
    ToolsSatochipEnable2FAView,
    ToolsSatochipView,
    ToolsSmartcardMenuView,
)
from seedsigner.views.view import MainMenuView


class MockSatochipConnector:
    """Spy stand-in for the pysatochip CardConnector used by the 2FA flow."""

    def __init__(self, needs_2fa=False):
        self.needs_2FA = needs_2fa
        self.set_2fa_calls = []

    def card_set_2FA_key(self, hmacsha160_key, amount_limit=0):
        self.set_2fa_calls.append((hmacsha160_key, amount_limit))
        return (b"", 0x90, 0x00)


class TestSatochipEnable2FA(FlowTest):

    def _mock_connector(self, monkeypatch, needs_2fa=False):
        connector = MockSatochipConnector(needs_2fa=needs_2fa)
        monkeypatch.setattr(seedkeeper_utils, "init_satochip", lambda *args, **kwargs: connector)
        return connector

    def _menu_steps(self):
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
            FlowStep(ToolsSmartcardMenuView, button_data_selection=ToolsSmartcardMenuView.SATOCHIP),
            FlowStep(ToolsSatochipView, button_data_selection=ToolsSatochipView.ADVANCED),
            FlowStep(ToolsSatochipAdvancedView, button_data_selection=ToolsSatochipAdvancedView.ENABLE_2FA),
        ]

    def test_cancel_at_first_confirmation_writes_nothing(self, monkeypatch):
        connector = self._mock_connector(monkeypatch)

        self.run_sequence([
            *self._menu_steps(),
            FlowStep(ToolsSatochipEnable2FAView, screen_return_value=1),  # "Cancel"
            FlowStep(ToolsSatochipAdvancedView),
        ])

        assert connector.set_2fa_calls == []

    def test_full_success_writes_key_once(self, monkeypatch):
        connector = self._mock_connector(monkeypatch)

        self.run_sequence([
            *self._menu_steps(),
            # 0 selects "Enable" on both confirmations; the QR screen's return value is ignored
            FlowStep(ToolsSatochipEnable2FAView, screen_return_value=0),
            FlowStep(ToolsSatochipAdvancedView),
        ])

        assert len(connector.set_2fa_calls) == 1
        key, amount_limit = connector.set_2fa_calls[0]
        assert isinstance(key, (bytes, bytearray)) and len(key) == 20
        assert amount_limit == 0

    def test_already_enabled_short_circuits(self, monkeypatch):
        connector = self._mock_connector(monkeypatch, needs_2fa=True)

        self.run_sequence([
            *self._menu_steps(),
            FlowStep(ToolsSatochipEnable2FAView, screen_return_value=0),
            FlowStep(ToolsSatochipAdvancedView),
        ])

        assert connector.set_2fa_calls == []


class TestSatochipEnable2FARealScreens(FlowTest):
    """Drive the real confirmation + QR Screens via UISession (real _run() input loops)."""

    def _mock_connector(self, monkeypatch):
        connector = MockSatochipConnector(needs_2fa=False)
        monkeypatch.setattr(seedkeeper_utils, "init_satochip", lambda *args, **kwargs: connector)
        return connector

    def _menu_steps(self):
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
            FlowStep(ToolsSmartcardMenuView, button_data_selection=ToolsSmartcardMenuView.SATOCHIP),
            FlowStep(ToolsSatochipView, button_data_selection=ToolsSatochipView.ADVANCED),
            FlowStep(ToolsSatochipAdvancedView, button_data_selection=ToolsSatochipAdvancedView.ENABLE_2FA),
        ]

    def test_back_on_qr_cancels_before_write(self, monkeypatch):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        connector = self._mock_connector(monkeypatch)

        script = (
            [K.KEY_PRESS]      # first confirmation -> "Enable" (index 0)
            + [K.KEY_PRESS]    # pairing instruction -> "I understand"
            + [K.KEY_LEFT]     # QR screen -> BACK cancels before anything is written
            + [K.KEY_PRESS]    # "Cancelled" info screen -> dismiss
        )

        session = UISession(script=script)
        self.run_sequence([
            *self._menu_steps(),
            FlowStep(ToolsSatochipEnable2FAView, real_screens=True),
            FlowStep(ToolsSatochipAdvancedView),
        ], ui_session=session)

        assert connector.set_2fa_calls == []
        assert len(session.renderer.frames) > 0

    def test_cancel_at_final_confirmation_after_scan(self, monkeypatch):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        connector = self._mock_connector(monkeypatch)

        script = (
            [K.KEY_PRESS]              # first confirmation -> "Enable" (index 0)
            + [K.KEY_PRESS]            # pairing instruction -> "I understand"
            + [K.KEY_PRESS]            # QR screen -> click to continue after scanning
            + [K.KEY_DOWN, K.KEY_PRESS]  # final confirmation -> "Cancel" (index 1)
            + [K.KEY_PRESS]            # "Cancelled" info screen -> dismiss
        )

        session = UISession(script=script)
        self.run_sequence([
            *self._menu_steps(),
            FlowStep(ToolsSatochipEnable2FAView, real_screens=True),
            FlowStep(ToolsSatochipAdvancedView),
        ], ui_session=session)

        assert connector.set_2fa_calls == []
        assert len(session.renderer.frames) > 0

    def test_full_success_with_real_screens(self, monkeypatch):
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        connector = self._mock_connector(monkeypatch)

        script = (
            [K.KEY_PRESS]      # first confirmation -> "Enable" (index 0)
            + [K.KEY_PRESS]    # pairing instruction -> "I understand"
            + [K.KEY_PRESS]    # QR screen -> click to continue after scanning
            + [K.KEY_PRESS]    # final confirmation -> "Enable" (index 0)
            + [K.KEY_PRESS]    # Success screen -> OK
        )

        session = UISession(script=script)
        self.run_sequence([
            *self._menu_steps(),
            FlowStep(ToolsSatochipEnable2FAView, real_screens=True),
            FlowStep(ToolsSatochipAdvancedView),
        ], ui_session=session)

        assert len(connector.set_2fa_calls) == 1
        key, amount_limit = connector.set_2fa_calls[0]
        assert isinstance(key, (bytes, bytearray)) and len(key) == 20
        assert amount_limit == 0
        assert len(session.renderer.frames) > 0
