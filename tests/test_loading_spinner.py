"""Context-aware loading-spinner branding.

The single ``LoadingScreenThread`` is shared by every loader in the app. It
defaults to the neutral KeyCard logo; the Bitcoin and Ethereum scan/derive
flows override it so the spinner reflects the active chain. These tests lock in
that wiring without driving the (hardware-bound) render loop.
"""
import os

from seedsigner.gui.screens.screen import (
    LoadingScreenThread,
    LOADING_SPINNER_KEYCARD,
    LOADING_SPINNER_BTC,
    LOADING_SPINNER_ETH,
)


def test_spinner_presets_have_distinct_logos():
    assert LOADING_SPINNER_KEYCARD["logo_name"] == "keycard_60x60.png"
    assert LOADING_SPINNER_BTC["logo_name"] == "btc_logo_60x60.png"
    assert LOADING_SPINNER_ETH["logo_name"] == "eth_logo_60x60.png"
    # Each preset is a complete kwargs bundle for LoadingScreenThread.
    for preset in (LOADING_SPINNER_KEYCARD, LOADING_SPINNER_BTC, LOADING_SPINNER_ETH):
        assert set(preset.keys()) == {"logo_name", "arc_color", "arc_trailing_color"}
    # Distinct leading-arc colors so the chain is visually distinguishable.
    leads = {p["arc_color"] for p in (LOADING_SPINNER_KEYCARD, LOADING_SPINNER_BTC, LOADING_SPINNER_ETH)}
    assert len(leads) == 3


def test_spinner_default_is_neutral_keycard():
    t = LoadingScreenThread(text="x")
    assert t.logo_name == LOADING_SPINNER_KEYCARD["logo_name"]
    assert t.arc_color == LOADING_SPINNER_KEYCARD["arc_color"]
    assert t.arc_trailing_color == LOADING_SPINNER_KEYCARD["arc_trailing_color"]


def test_spinner_preset_override():
    t = LoadingScreenThread(text="x", **LOADING_SPINNER_BTC)
    assert t.logo_name == "btc_logo_60x60.png"
    assert t.arc_color == LOADING_SPINNER_BTC["arc_color"]
    assert t.arc_trailing_color == LOADING_SPINNER_BTC["arc_trailing_color"]


def test_spinner_logo_assets_exist():
    import seedsigner

    img_dir = os.path.join(os.path.dirname(seedsigner.__file__), "resources", "img")
    for name in ("keycard_60x60.png", "btc_logo_60x60.png", "eth_logo_60x60.png"):
        assert os.path.exists(os.path.join(img_dir, name)), f"missing asset: {name}"


def test_coin_scan_views_carry_spinner_preset():
    from seedsigner.views.keycard_views import (
        ScanEthSignRequestView,
        ToolsKeycardBtcSignPsbtScanView,
        ToolsKeycardBtcSignMessageScanView,
    )
    from seedsigner.views.scan_views import ScanView

    assert ScanEthSignRequestView.loading_spinner == LOADING_SPINNER_ETH
    assert ToolsKeycardBtcSignPsbtScanView.loading_spinner == LOADING_SPINNER_BTC
    assert ToolsKeycardBtcSignMessageScanView.loading_spinner == LOADING_SPINNER_BTC
    # The generic base scan stays neutral (None -> KeyCard default in ScanScreen).
    assert ScanView.loading_spinner is None
