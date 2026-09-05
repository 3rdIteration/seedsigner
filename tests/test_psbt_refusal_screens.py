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
from seedsigner.views.psbt_views import REJECT_PRESENTATION, RejectPresentation

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
    """
    Swap in the stub for whatever Renderer the GUI will actually resolve.

    tests/base.py replaces sys.modules['seedsigner.gui.renderer'] with a MagicMock
    at import time, so the class this name refers to depends on whether a FlowTest
    module has been collected yet. Importing lazily here -- the same way screen.py
    and components.py do -- guarantees we patch the object they will use, real or
    mocked. A module-level import binds the pre-mock class and silently stops
    matching, and a dotted patch target additionally fails to resolve once that
    sys.modules entry has been swapped.

    This mirrors what tests/test_tools_screens.py does for the same reason.
    """
    from seedsigner.gui.renderer import Renderer

    with patch.object(Renderer, "get_instance", return_value=StubRenderer()):
        yield


def measure(text: str, screen_cls=None, headline=None, button_label="Done") -> tuple[int, int, int]:
    """Returns (box_height, line_count, text_height) for a refusal screen body."""
    screen = (screen_cls or WarningScreen)(
        title="Invalid PSBT",
        status_headline=headline,
        text=text,
        button_data=[ButtonOption(button_label)],
        show_back_button=False,
    )
    text_area = [c for c in screen.components if c.__class__.__name__ == "TextArea"][-1]
    lines = len(text_area.text_lines)
    height = text_area.text_height_above_baseline * lines + text_area.line_spacing * (lines - 1)
    return text_area.height, lines, height


def assert_fits(text: str, label: str, screen_cls=None, headline=None, button_label="Done"):
    box, lines, height = measure(text, screen_cls, headline, button_label)
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

        presentation = REJECT_PRESENTATION.get(excinfo.value.code, RejectPresentation())
        assert presentation.text is None, (
            f"{vector.name}: this code now renders fixed prose, so the parser's own "
            f"message is never shown; cover it in test_table_prose_fits instead.")

        text = str(excinfo.value)
        if presentation.tip:
            text += "\n" + presentation.tip
        assert_fits(text, vector.name, presentation.screen,
                    presentation.headline, presentation.button_label)

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

    def test_table_prose_fits(self):
        """
        The entries that render fixed prose instead of the parser's message. These never
        reach test_real_refusal_message_fits, and they use the dire and info screens,
        whose headline and icon eat into the same 240x240 budget.
        """
        for code, presentation in REJECT_PRESENTATION.items():
            if presentation.text is None:
                continue
            assert_fits(presentation.text, code, presentation.screen,
                        presentation.headline, presentation.button_label)


    def test_every_reject_code_has_a_reachable_destination(self):
        """
        A typo in destination_name would only surface when a user hit that refusal on
        the device, so resolve every one of them here.
        """
        from seedsigner.views import psbt_views

        for code, presentation in REJECT_PRESENTATION.items():
            assert hasattr(psbt_views, presentation.destination_name), (
                f"{code}: no View named {presentation.destination_name}")


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


class TestSyntheticRefusalMessagesFit:
    """
    Refusal messages with no corpus vector to produce them, so
    TestRefusalScreensFit's parametrization cannot reach them.
    """

    def test_undisplayable_output_message_fits(self):
        # Worst case is a large output index; the message is otherwise fixed.
        assert_fits("Output 999 script cannot be shown as an address.",
                    "UNDISPLAYABLE_OUTPUT")

    def test_unsupported_psbt_version_message_fits(self):
        assert_fits("PSBT version 4294967295 is not supported.",
                    "UNSUPPORTED_PSBT_VERSION")


class TestLocktimeDisplay:
    """
    nLockTime comes in two encodings and only one of them was ever visible.

    A timestamp locktime is compared against the clock and warned about; a
    block-height locktime was not checked at all, so an attacker wanting a long
    lock simply used the height form and the review screens said nothing. Both
    delay confirmation identically, so both are now stated on the approval
    screen.

    Heights are rendered as an approximate date rather than raw, because
    "block 1,000,000" is not actionable without a chain tip the device does not
    have. See Controller.RELEASE_BLOCK_HEIGHT.
    """

    def _parser_with(self, locktime: int, sequence: int = 0xFFFFFFFE) -> PSBTParser:
        psbt = load_psbt("NORMAL-1_p2wpkh")
        psbt.locktime = locktime
        psbt.inputs[0].sequence = sequence
        return PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)

    def test_block_height_locktime_is_rendered_as_a_date(self):
        from seedsigner.controller import Controller
        from seedsigner.views.psbt_views import PSBTFinalizeView

        # A year past the anchor should read as roughly a year past its date.
        blocks_per_year = 52_560
        parser = self._parser_with(Controller.RELEASE_BLOCK_HEIGHT + blocks_per_year)
        text = PSBTFinalizeView._locktime_text(parser)

        assert text is not None
        assert "~" in text, "a height-derived date must be marked approximate"

        import time
        expected_year = time.strftime(
            "%Y", time.gmtime(Controller.RELEASE_BLOCK_TIME + blocks_per_year * 600)
        )
        assert expected_year in text

    def test_timestamp_locktime_is_rendered_exactly(self):
        from seedsigner.views.psbt_views import PSBTFinalizeView

        parser = self._parser_with(2_000_000_000)  # 2033-05
        text = PSBTFinalizeView._locktime_text(parser)
        assert text is not None
        assert "~" not in text, "a real timestamp needs no estimation"
        assert "2033" in text

    def test_nothing_shown_when_locktime_is_inert(self):
        """Consensus ignores nLockTime when every input is final."""
        from seedsigner.views.psbt_views import PSBTFinalizeView

        parser = self._parser_with(2_000_000_000, sequence=0xFFFFFFFF)
        assert PSBTFinalizeView._locktime_text(parser) is None

    def test_nothing_shown_without_a_locktime(self):
        from seedsigner.views.psbt_views import PSBTFinalizeView

        parser = self._parser_with(0)
        assert PSBTFinalizeView._locktime_text(parser) is None

    def test_both_notices_fit_on_the_approval_screen(self):
        """
        RBF and a locktime can both apply. Neither may push the body past the
        button -- TextArea renders over it rather than raising.
        """
        from seedsigner.gui.screens.psbt_screens import PSBTFinalizeScreen

        screen = PSBTFinalizeScreen(
            button_data=[ButtonOption("Approve transaction")],
            is_rbf=True,
            locktime_text="Locked until ~Feb 2031",
        )
        content_bottom = max(
            getattr(c, "screen_y", 0) + getattr(c, "height", 0) for c in screen.components
        )
        assert content_bottom <= screen.buttons[0].screen_y, (
            f"approval screen body ({content_bottom}px) overruns the button "
            f"({screen.buttons[0].screen_y}px)"
        )


class TestBlockAnchor:
    """The anchor is advisory, so a bad file must degrade the estimate, not boot."""

    def test_falls_back_when_json_is_unreadable(self, tmp_path, monkeypatch):
        from seedsigner.controller import Controller

        before = Controller.RELEASE_BLOCK_HEIGHT
        try:
            monkeypatch.setattr(
                "seedsigner.controller.Path",
                lambda *a, **k: (_ for _ in ()).throw(OSError("nope")),
            )
            Controller._load_block_anchor()  # must not raise
        finally:
            Controller.RELEASE_BLOCK_HEIGHT = before

    def test_shipped_json_is_plausible(self):
        import json, pathlib

        path = (pathlib.Path("src/seedsigner/resources/latest-block.json"))
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["height"] > 900_000
        assert data["timestamp"] > 1_700_000_000
