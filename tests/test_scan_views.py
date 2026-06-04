"""Unit tests for the generic ``ScanView`` routing in ``scan_views.py``.

Until this commit, the generic ScanView (Home > Scan > "SeedSigner") fell
through to ``NotYetImplementedView`` for PSBT and ``eth-sign-request``
payloads even though both Keycard flows are wired. These tests pin the
dispatch so the bug cannot regress: PSBT routes to the Keycard PSBT
review, ``eth-sign-request`` routes to the Keycard ETH overview.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def _install_hw_mocks():
    for mod in [
        "RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
        "smartcard", "smartcard.System", "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
    ]:
        sys.modules.setdefault(mod, MagicMock())


_install_hw_mocks()


def _make_scan_view(*, qr_type, is_complete=True, is_invalid=False,
                    get_psbt_ret=None, get_eth_ret=None,
                    get_eth_raises=None, is_settings=False):
    """Construct a ScanView with a stubbed decoder mirroring the fields
    the dispatch logic checks. We bypass ``__init__`` so we don't have to
    bring up the camera/decoder machinery.
    """
    from seedsigner.models.qr_type import QRType
    from seedsigner.views.scan_views import ScanView

    view = ScanView.__new__(ScanView)
    view.controller = MagicMock()
    view.run_screen = MagicMock(return_value=None)
    view.decoder = MagicMock()
    view.decoder.qr_type = qr_type
    view.decoder.is_complete = is_complete
    view.decoder.is_invalid = is_invalid
    view.decoder.is_settings = is_settings
    view.decoder.is_psbt = qr_type in {
        QRType.PSBT__UR2, QRType.PSBT__SPECTER,
        QRType.PSBT__BASE64, QRType.PSBT__BASE43,
    }
    view.decoder.is_eth_sign_request = (qr_type == QRType.ETH_SIGN_REQUEST)
    view.decoder.get_psbt = MagicMock(return_value=get_psbt_ret)
    if get_eth_raises is not None:
        view.decoder.get_eth_sign_request = MagicMock(side_effect=get_eth_raises)
    else:
        view.decoder.get_eth_sign_request = MagicMock(return_value=get_eth_ret)
    view.decoder.get_settings_data = MagicMock(return_value={})
    return view


class TestScanViewDispatch(unittest.TestCase):
    def test_psbt_routes_to_keycard_review(self):
        """A scanned PSBT in the generic ScanView lands on the Keycard
        BTC PSBT review, not on NotYetImplementedView."""
        from seedsigner.models.qr_type import QRType
        from seedsigner.views.keycard_views import ToolsKeycardBtcSignPsbtReviewView

        psbt_sentinel = object()
        view = _make_scan_view(qr_type=QRType.PSBT__BASE64, get_psbt_ret=psbt_sentinel)
        dest = view.run()

        self.assertIs(dest.View_cls, ToolsKeycardBtcSignPsbtReviewView)
        self.assertTrue(dest.skip_current_view)
        # The controller must carry the PSBT so the downstream review can
        # parse it without re-scanning.
        self.assertIs(view.controller.psbt, psbt_sentinel)

    def test_eth_sign_request_routes_to_overview(self):
        """A scanned UR eth-sign-request lands on the Keycard ETH
        overview (the start of the Sign chain)."""
        from seedsigner.models.qr_type import QRType
        from seedsigner.views.keycard_views import ToolsKeycardSignEthOverviewView

        req_sentinel = object()
        view = _make_scan_view(
            qr_type=QRType.ETH_SIGN_REQUEST,
            get_eth_ret=req_sentinel,
        )
        dest = view.run()

        self.assertIs(dest.View_cls, ToolsKeycardSignEthOverviewView)
        self.assertTrue(dest.skip_current_view)
        self.assertIs(view.controller.eth_sign_request, req_sentinel)

    def test_eth_sign_request_decode_error_surfaces_error_view(self):
        """A malformed eth-sign-request must surface a clear ErrorView,
        not crash the scan flow."""
        from seedsigner.models.qr_type import QRType
        from seedsigner.views.view import ErrorView

        view = _make_scan_view(
            qr_type=QRType.ETH_SIGN_REQUEST,
            get_eth_raises=ValueError("bad cbor"),
        )
        dest = view.run()

        self.assertIs(dest.View_cls, ErrorView)
        # And nothing was assigned to the controller.
        self.assertFalse(hasattr(view.controller, "eth_sign_request")
                         and view.controller.eth_sign_request is not None
                         and not isinstance(view.controller.eth_sign_request, MagicMock))

    def test_settings_qr_still_routes_to_ingest(self):
        """Regression: settings QR ingest must keep working (it lived in
        the same dispatch block we just refactored)."""
        from seedsigner.models.qr_type import QRType
        from seedsigner.views.settings_views import SettingsIngestSettingsQRView

        view = _make_scan_view(qr_type=QRType.SETTINGS, is_settings=True)
        dest = view.run()

        self.assertIs(dest.View_cls, SettingsIngestSettingsQRView)

    def test_unknown_qr_type_surfaces_error(self):
        """A complete decode of an unhandled qr_type must produce an
        ErrorView (not silently route to NotYetImplementedView)."""
        from seedsigner.models.qr_type import QRType
        from seedsigner.views.view import ErrorView

        view = _make_scan_view(qr_type=QRType.BITCOIN_ADDRESS)
        dest = view.run()

        self.assertIs(dest.View_cls, ErrorView)


def _make_home_scan_view(has_auth=False):
    """Build a HomeScanView bypassing __init__ with a stub controller."""
    from seedsigner.views.scan_views import HomeScanView

    view = HomeScanView.__new__(HomeScanView)
    view.controller = MagicMock()
    view.controller.has_any_keycard_auth.return_value = has_auth
    view.run_screen = MagicMock(return_value=None)
    return view


class TestHomeScanCardGate(unittest.TestCase):
    """Home > Scan checks the reader before opening the camera: no card ->
    'Insert card' error + return home; card present -> silent pair + hand
    off to the generic ScanView."""

    def _present(self):
        from seedsigner.helpers.card_probe import ProbeResult
        return ProbeResult(present=True, kind_match=True, initialised=True)

    def _absent(self):
        from seedsigner.helpers.card_probe import ProbeResult
        return ProbeResult(present=False, kind_match=False, initialised=False)

    def test_no_card_shows_error_and_returns_home(self):
        from unittest.mock import patch
        from seedsigner.views.view import MainMenuView

        view = _make_home_scan_view()
        with patch("seedsigner.helpers.card_probe.probe_card",
                   return_value=self._absent()):
            dest = view.run()

        # "Insert card" error screen shown, then snap back to Home.
        view.run_screen.assert_called_once()
        self.assertIs(dest.View_cls, MainMenuView)
        self.assertTrue(dest.clear_history)

    def test_probe_exception_treated_as_no_card(self):
        """A reader/driver hiccup must not crash — it falls through to the
        same 'Insert card' path."""
        from unittest.mock import patch
        from seedsigner.views.view import MainMenuView

        view = _make_home_scan_view()
        with patch("seedsigner.helpers.card_probe.probe_card",
                   side_effect=RuntimeError("reader exploded")):
            dest = view.run()

        view.run_screen.assert_called_once()
        self.assertIs(dest.View_cls, MainMenuView)

    def test_card_present_pairs_then_routes_to_scan(self):
        from unittest.mock import patch
        from seedsigner.views.scan_views import ScanView

        view = _make_home_scan_view(has_auth=False)
        with patch("seedsigner.helpers.card_probe.probe_card",
                   return_value=self._present()), \
             patch("seedsigner.helpers.keycard.ui_helpers.try_silent_ephemeral_pair") as mock_pair:
            dest = view.run()

        # Camera reached (no error screen), card paired silently first.
        view.run_screen.assert_not_called()
        mock_pair.assert_called_once_with(view)
        self.assertIs(dest.View_cls, ScanView)
        self.assertTrue(dest.skip_current_view)

    def test_card_present_skips_pairing_when_already_authed(self):
        """If the card was already authed this boot, don't re-pair — just
        hand off to the scanner."""
        from unittest.mock import patch
        from seedsigner.views.scan_views import ScanView

        view = _make_home_scan_view(has_auth=True)
        with patch("seedsigner.helpers.card_probe.probe_card",
                   return_value=self._present()), \
             patch("seedsigner.helpers.keycard.ui_helpers.try_silent_ephemeral_pair") as mock_pair:
            dest = view.run()

        mock_pair.assert_not_called()
        self.assertIs(dest.View_cls, ScanView)


if __name__ == "__main__":
    unittest.main()
