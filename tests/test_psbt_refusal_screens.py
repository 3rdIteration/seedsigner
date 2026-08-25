"""
Every refusal message has to fit on a 240x240 screen.

`TextArea` does not raise when text overflows its rect -- it logs a warning and
renders past the bottom edge, straight over the button. So an overlong refusal
reason produces a visually broken screen that nothing else catches. These tests
measure the real layout and fail if a message no longer fits.
"""
import threading

from unittest.mock import patch

import pytest

from PIL import Image, ImageDraw

from seedsigner.gui.screens.screen import ButtonOption, WarningScreen
from seedsigner.models.psbt_parser import MAX_MONEY, PSBTParser
from seedsigner.views.psbt_views import PSBTOverviewView

from psbt_suite_util import REJECT_PARSER_VECTORS, suite_seed, SUITE_NETWORK, load_psbt


# The largest values that can appear in a refusal message.
MAX_INDEX = 0x7FFFFFFF
LONG_PATH = "m/48h/1h/0h/2h/2147483647/1/0"

# Stand-in for a verbose translation. Real translations of these strings run
# longer than the English source; German and Finnish are typically the worst.
VERBOSE_TIP = "Siehe Change-Gap-Limit in den Einstellungen."


class StubRenderer:
    """
    A minimal stand-in for the hardware Renderer.

    Deliberately does not reuse the screenshot generator's ScreenshotRenderer:
    that is a singleton on the shared Renderer class, and the flow tests replace
    it with a Mock, so anything built on it fails depending on test order.
    """
    def __init__(self, width: int = 240, height: int = 240):
        self.canvas_width = width
        self.canvas_height = height
        self.canvas = Image.new("RGB", (width, height))
        self.draw = ImageDraw.Draw(self.canvas)
        self.lock = threading.Lock()

    def show_image(self, *args, **kwargs):
        pass


@pytest.fixture(autouse=True)
def stub_renderer():
    """Patched per-test so nothing leaks into or out of neighbouring modules."""
    # Patched by name: screen.py and components.py both import Renderer lazily
    # inside their methods, so the canonical class is the only reliable target.
    with patch("seedsigner.gui.renderer.Renderer.get_instance",
               return_value=StubRenderer()):
        yield


def measure(text: str) -> tuple[int, int, int]:
    """Returns (box_height, line_count, text_height) for a WarningScreen body."""
    screen = WarningScreen(
        title="Invalid PSBT",
        status_headline=None,
        text=text,
        button_data=[ButtonOption("Done")],
        show_back_button=False,
    )
    text_area = [c for c in screen.components if c.__class__.__name__ == "TextArea"][-1]
    lines = len(text_area.text_lines)
    height = text_area.text_height_above_baseline * lines + text_area.line_spacing * (lines - 1)
    return text_area.height, lines, height


def assert_fits(text: str, label: str):
    box, lines, height = measure(text)
    assert height <= box, (
        f"{label}: {lines} lines, {height}px in a {box}px box — this renders over "
        f"the button. Shorten it.\n  {text!r}"
    )


class TestRefusalScreensFit:

    @pytest.mark.parametrize("vector", REJECT_PARSER_VECTORS,
                             ids=[v.name for v in REJECT_PARSER_VECTORS])
    def test_real_refusal_message_fits(self, vector):
        """The message each corpus vector actually produces."""
        from seedsigner.models.psbt_parser import InvalidPSBTError

        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(p=load_psbt(vector.name), seed=suite_seed(), network=SUITE_NETWORK)

        text = str(excinfo.value)
        tip = PSBTOverviewView.REJECT_TIPS.get(excinfo.value.code)
        if tip:
            text += "\n" + tip
        assert_fits(text, vector.name)

    def test_worst_case_values_fit(self):
        """
        The same messages with the largest values that can reach them: a 10-digit
        derivation index, a full-length multisig path, MAX_MONEY amounts.
        """
        cases = {
            "gap limit": f"Change index {MAX_INDEX} past gap limit (inputs {MAX_INDEX}).",
            "unreachable path": f"Change path {LONG_PATH} is outside this wallet.",
            "op_return": f"Output 12 burns {MAX_MONEY} sats in an OP_RETURN.",
            "amount range": f"Output 12 amount out of range: {2**64 - 1}",
            "negative fee": f"Outputs exceed inputs by {MAX_MONEY} sats",
            "reconcile": f"Amounts do not add up: {MAX_MONEY} vs {MAX_MONEY} in.",
            "sighash": "Input 12 needs sighash 0x83, not SIGHASH_ALL.",
        }
        for label, text in cases.items():
            assert_fits(text, label)

    def test_gap_limit_tip_survives_a_verbose_translation(self):
        """
        The one refusal that carries a tip is also the one with two numbers in
        it, so it has the least headroom. It must still fit once translated.
        """
        text = (f"Change index {MAX_INDEX} past gap limit (inputs {MAX_INDEX}).\n"
                f"{VERBOSE_TIP}")
        assert_fits(text, "gap limit + verbose translation")

    def test_scan_time_rejection_fits(self):
        assert_fits(
            "This transaction could not be read. It may be corrupted or malformed.",
            "scan rejection",
        )
