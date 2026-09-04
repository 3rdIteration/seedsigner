"""
    Tests for the 2FA signing guard (satochip_2fa_blocks_signing).

    A Satochip card with 2FA enabled cannot sign from SeedSigner (there is no
    phone-app code flow), so both signing entry points refuse to continue and
    show a warning instead. These tests cover:

      * the helper itself (enabled / disabled / unset / attribute-missing connectors)
      * message-signing flow: selecting "Use Satochip card" with a 2FA-enabled
        card stops before the confirm screen

    The PSBT signing variant of this guard is covered by
    TestPSBTSatochip.test_satochip_2fa_enabled_blocks_signing in tests/test_flows_psbt.py.
"""

from unittest.mock import Mock

from base import BaseTest


class FakeView:
    def __init__(self):
        self.run_screen = Mock()


class Connector:
    def __init__(self, needs_2fa):
        self.needs_2FA = needs_2fa


def test_guard_blocks_signing_when_2fa_enabled():
    from seedsigner.gui.screens.screen import WarningScreen
    from seedsigner.helpers.seedkeeper_utils import satochip_2fa_blocks_signing

    view = FakeView()

    assert satochip_2fa_blocks_signing(view, Connector(needs_2fa=True)) is True

    args, kwargs = view.run_screen.call_args
    assert args[0] is WarningScreen
    assert kwargs["title"] == "2FA Enabled"
    assert "Signing while 2FA is enabled" in kwargs["text"]


def test_guard_allows_signing_when_2fa_disabled():
    from seedsigner.helpers.seedkeeper_utils import satochip_2fa_blocks_signing

    view = FakeView()

    assert satochip_2fa_blocks_signing(view, Connector(needs_2fa=False)) is False
    view.run_screen.assert_not_called()


def test_guard_allows_signing_when_needs_2fa_unset():
    """pysatochip leaves needs_2FA as None until card_get_status() has run."""
    from seedsigner.helpers.seedkeeper_utils import satochip_2fa_blocks_signing

    view = FakeView()

    assert satochip_2fa_blocks_signing(view, Connector(needs_2fa=None)) is False
    view.run_screen.assert_not_called()


def test_guard_allows_signing_when_attribute_missing():
    """The keycard backend connector has no needs_2FA attribute at all."""
    from seedsigner.helpers.seedkeeper_utils import satochip_2fa_blocks_signing

    view = FakeView()

    assert satochip_2fa_blocks_signing(view, object()) is False
    view.run_screen.assert_not_called()


class TestSatochipMessageSigning2FAGuard(BaseTest):

    def test_select_satochip_with_2fa_card_stops_before_confirm(self, monkeypatch):
        from seedsigner.controller import Controller
        from seedsigner.helpers import seedkeeper_utils
        from seedsigner.views import seed_views
        from seedsigner.views.view import BackStackView

        class MockConnector:
            needs_2FA = True

        monkeypatch.setattr(seedkeeper_utils, "init_satochip", lambda *args, **kwargs: MockConnector())

        view = seed_views.SeedSelectSeedView(flow=Controller.FLOW__SIGN_MESSAGE)
        # No seeds loaded -> button_data[0] is the SATOCHIP option; the warning
        # screen's return value is ignored by the View.
        view.run_screen = Mock(return_value=0)

        destination = view.run()

        assert destination.View_cls == BackStackView
        assert self.controller.sign_message_with_satochip is False

        args, kwargs = view.run_screen.call_args
        assert kwargs["title"] == "2FA Enabled"
