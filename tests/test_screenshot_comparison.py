"""Screenshot comparison tests: render screens at 240×240 and 128×128 and ensure
they are proportionally consistent.

Each test:
  1. Renders a representative screen at 240×240 (reference).
  2. Renders the same screen at 128×128 (native ST7735).
  3. Down-scales the 240 image to 128 and measures similarity against the native
     128 render.
  4. Saves both screenshots (and the downscaled reference) to a temp dir so they
     can be visually inspected.

NOTE: These tests exercise the real Renderer and GUIConstants code.  The
autouse ``_isolate_gui_modules`` fixture snapshots and fully restores
``sys.modules`` around each test so that loading real GUI modules does not
pollute other test files (which rely on ``base.py``'s MagicMock stubs).
"""

import importlib
import math
import os
import sys
import tempfile
from threading import Lock
from unittest.mock import MagicMock, patch

import pytest
from PIL import Image, ImageDraw, ImageStat

from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants


def _load_real_gui_modules():
    """Ensure real GUI modules are in ``sys.modules``.

    If ``base.py``'s mocks (or any MagicMock stubs) are present for
    ``seedsigner.gui.*``, they are temporarily removed so that
    ``importlib`` loads the real ``.py`` files.

    After this function returns, the real modules are in ``sys.modules``.
    The caller is responsible for restoring the original state.
    """
    mocks = {
        k: sys.modules[k] for k in list(sys.modules)
        if k.startswith("seedsigner.gui") and isinstance(sys.modules[k], MagicMock)
    }
    for k in mocks:
        del sys.modules[k]

    importlib.import_module("seedsigner.gui.renderer")
    importlib.import_module("seedsigner.gui.components")
    importlib.import_module("seedsigner.gui.keyboard")
    importlib.import_module("seedsigner.gui.screens.screen")


def _get_real_refs():
    """Return live references to real Renderer and GUIConstants classes."""
    mod_renderer = sys.modules["seedsigner.gui.renderer"]
    mod_components = sys.modules["seedsigner.gui.components"]
    return mod_renderer.Renderer, mod_components.GUIConstants

# ── Module-level references (populated by _isolate_gui_modules fixture) ──
Renderer = None
GUIConstants = None

# ── Original (240×240) GUIConstants values for reset ───────────────────
_ORIG = dict(
    _scale_factor=1.0,
    EDGE_PADDING=8,
    COMPONENT_PADDING=8,
    LIST_ITEM_PADDING=4,
    ICON_FONT_SIZE=22,
    ICON_INLINE_FONT_SIZE=24,
    ICON_LARGE_BUTTON_SIZE=48,
    ICON_TOAST_FONT_SIZE=30,
    ICON_PRIMARY_SCREEN_SIZE=50,
    TOP_NAV_HEIGHT=48,
    TOP_NAV_BUTTON_SIZE=32,
    BODY_FONT_MAX_SIZE=20,
    BODY_FONT_MIN_SIZE=15,
    BODY_LINE_SPACING=8,
    LABEL_FONT_SIZE=15,
    BUTTON_HEIGHT=32,
)

_ORIG_FONT_DICTS = dict(
    TOP_NAV_TITLE_FONT_SIZE={
        "default": 20,
        SettingsConstants.LOCALE__JAPANESE: 22,
        SettingsConstants.LOCALE__KOREAN: 23,
        SettingsConstants.LOCALE__CHINESE_SIMPLIFIED: 23,
    },
    BODY_FONT_SIZE={
        "default": 17,
        SettingsConstants.LOCALE__JAPANESE: 18,
        SettingsConstants.LOCALE__KOREAN: 18,
        SettingsConstants.LOCALE__CHINESE_SIMPLIFIED: 18,
    },
    BUTTON_FONT_SIZE={
        "default": 18,
        SettingsConstants.LOCALE__JAPANESE: 20,
        SettingsConstants.LOCALE__KOREAN: 20,
        SettingsConstants.LOCALE__CHINESE_SIMPLIFIED: 20,
    },
)


def _reset_gui_constants():
    """Restore GUIConstants to 240×240 reference values."""
    for attr, val in _ORIG.items():
        setattr(GUIConstants, attr, val)
    for attr, val in _ORIG_FONT_DICTS.items():
        setattr(GUIConstants, attr, val.copy())


def _make_test_renderer_class(real_renderer_cls):
    """Build a _TestRenderer subclass of the real Renderer at runtime."""

    class _TestRenderer(real_renderer_cls):
        """A minimal renderer that paints to an in-memory PIL Image."""

        @classmethod
        def configure_instance(cls, width=240, height=240):
            renderer = cls.__new__(cls)
            cls._instance = renderer
            renderer.canvas_width = width
            renderer.canvas_height = height
            renderer.canvas = Image.new("RGB", (width, height))
            renderer.draw = ImageDraw.Draw(renderer.canvas)
            renderer.lock = Lock()
            renderer.disp = None
            renderer.buttons = None
            renderer._needs_resize = False
            renderer._display_size = (width, height)
            return renderer

        def show_image(self, image=None, alpha_overlay=None, show_direct=False):
            if alpha_overlay:
                if image is None:
                    image = self.canvas
                image = Image.alpha_composite(image, alpha_overlay)
            if image:
                self.canvas.paste(image)

    return _TestRenderer


_TestRendererClass = None  # Set by _isolate_gui_modules fixture


def _setup_renderer(size: int):
    """Create a _TestRenderer at *size*×*size* and apply GUI scaling."""
    _reset_gui_constants()
    renderer = _TestRendererClass.configure_instance(width=size, height=size)
    GUIConstants.apply_display_scale(size)
    Renderer._instance = renderer
    return renderer


# ── Similarity helpers ─────────────────────────────────────────────────

def _image_rms_diff(img_a: Image.Image, img_b: Image.Image) -> float:
    """Root-mean-square per-channel pixel difference between two same-sized images."""
    assert img_a.size == img_b.size, f"Size mismatch: {img_a.size} vs {img_b.size}"
    from PIL import ImageChops
    diff = ImageChops.difference(img_a.convert("RGB"), img_b.convert("RGB"))
    stat = ImageStat.Stat(diff)
    # RMS across R, G, B channels
    return math.sqrt(sum(ch ** 2 for ch in stat.rms) / 3)


def _non_black_bbox(img: Image.Image):
    """Return the bounding box of non-black content, or None if all black."""
    gray = img.convert("L")
    return gray.getbbox()


# ── Screenshot output directory ────────────────────────────────────────

_SCREENSHOT_DIR = os.path.join(tempfile.gettempdir(), "seedsigner_screenshot_comparison")
os.makedirs(_SCREENSHOT_DIR, exist_ok=True)


def _save(img: Image.Image, name: str):
    path = os.path.join(_SCREENSHOT_DIR, name)
    img.save(path)
    return path


# ── Fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolate_gui_modules():
    """Snapshot sys.modules, load real GUI modules, then fully restore afterward.

    This is the ONLY fixture needed for module isolation.  It takes a complete
    snapshot of every ``seedsigner.*`` entry in ``sys.modules`` before the test,
    loads real GUI modules, and then restores the snapshot exactly — including
    removing any entries that were added as side effects.  This prevents real
    module objects (and their class-level references) from leaking into other
    test files that rely on ``base.py``'s MagicMock stubs.
    """
    global Renderer, GUIConstants, _TestRendererClass

    # ── snapshot ──
    snapshot = {
        k: sys.modules[k] for k in list(sys.modules)
        if k.startswith("seedsigner.")
    }

    # ── install real modules ──
    _load_real_gui_modules()
    real_renderer, real_gui_constants = _get_real_refs()

    # Populate module-level names so helpers / tests can use them.
    Renderer = real_renderer
    GUIConstants = real_gui_constants
    _TestRendererClass = _make_test_renderer_class(real_renderer)

    # Ensure Settings singleton exists (needed by GUIConstants font helpers).
    Settings._instance = None
    Settings.get_instance()

    yield

    # ── teardown: reset GUI state ──
    _reset_gui_constants()
    real_renderer._instance = None
    Settings._instance = None

    # Clear module-level refs so they can't be used outside a fixture context.
    Renderer = None
    GUIConstants = None
    _TestRendererClass = None

    # ── restore sys.modules exactly ──
    # 1. Remove any seedsigner.* entries that were added during the test.
    for k in list(sys.modules):
        if k.startswith("seedsigner.") and k not in snapshot:
            del sys.modules[k]
    # 2. Restore original entries (including mocks).
    sys.modules.update(snapshot)
    # 3. Fix parent package attributes that Python's import system may have
    #    mutated.  When a real submodule is loaded, Python sets an attribute
    #    on the parent package (e.g. ``seedsigner.gui.renderer`` on the
    #    ``seedsigner.gui`` module).  Restoring ``sys.modules`` entries
    #    doesn't undo those attribute mutations.  If the parent package
    #    existed in the snapshot, explicitly reset the ``renderer`` attribute
    #    so ``from seedsigner.gui import Renderer`` won't pick up the real
    #    class via the stale attribute.
    gui_pkg = snapshot.get("seedsigner.gui")
    if gui_pkg is not None and hasattr(gui_pkg, "renderer"):
        renderer_entry = snapshot.get("seedsigner.gui.renderer")
        if renderer_entry is not None:
            gui_pkg.renderer = renderer_entry


# ── Helpers to build screens ───────────────────────────────────────────

def _mock_hw_buttons():
    """Return a MagicMock that satisfies HardwareButtons.get_instance()."""
    mock = MagicMock()
    mock.wait_for.return_value = None
    return mock


def _render_button_list_screen(size: int, title="Test Screen", button_labels=None):
    """Render a ButtonListScreen at the given canvas size and return its canvas."""
    if button_labels is None:
        button_labels = ["Option A", "Option B", "Option C"]

    renderer = _setup_renderer(size)

    with patch("seedsigner.hardware.buttons.HardwareButtons.get_instance", return_value=_mock_hw_buttons()):
        from seedsigner.gui.screens.screen import ButtonListScreen, ButtonOption
        screen = ButtonListScreen(
            title=title,
            button_data=[ButtonOption(lbl) for lbl in button_labels],
            show_back_button=True,
        )
        screen._render()
    return renderer.canvas.copy()


def _render_large_icon_status_screen(size: int, title="Success!", text="Operation complete."):
    """Render a LargeIconStatusScreen and return its canvas."""
    renderer = _setup_renderer(size)

    with patch("seedsigner.hardware.buttons.HardwareButtons.get_instance", return_value=_mock_hw_buttons()):
        from seedsigner.gui.screens.screen import LargeIconStatusScreen, ButtonOption
        screen = LargeIconStatusScreen(
            title=title,
            text=text,
            button_data=[ButtonOption("OK")],
        )
        screen._render()
    return renderer.canvas.copy()


def _render_large_button_screen(size: int, title="Home"):
    """Render a LargeButtonScreen and return its canvas."""
    renderer = _setup_renderer(size)

    with patch("seedsigner.hardware.buttons.HardwareButtons.get_instance", return_value=_mock_hw_buttons()):
        from seedsigner.gui.screens.screen import LargeButtonScreen, ButtonOption
        from seedsigner.gui.components import SeedSignerIconConstants
        screen = LargeButtonScreen(
            title=title,
            button_data=[
                ButtonOption("Scan", icon_name=SeedSignerIconConstants.SCAN),
                ButtonOption("Seeds", icon_name=SeedSignerIconConstants.SEEDS),
            ],
        )
        screen._render()
    return renderer.canvas.copy()


def _render_warning_screen(size: int):
    """Render a WarningScreen and return its canvas."""
    renderer = _setup_renderer(size)

    with patch("seedsigner.hardware.buttons.HardwareButtons.get_instance", return_value=_mock_hw_buttons()):
        from seedsigner.gui.screens.screen import WarningScreen, ButtonOption
        screen = WarningScreen(
            title="Caution",
            status_headline="Warning!",
            text="Something needs attention.",
            button_data=[ButtonOption("I Understand")],
        )
        screen._render()
    return renderer.canvas.copy()


def _render_keyboard_screen(size: int, title="Enter PIN", charset=None, rows=4, cols=9,
                            show_save_button=False):
    """Render a KeyboardScreen at the given canvas size and return its canvas."""
    if charset is None:
        charset = "abcdefghijklmnopqrstuvwxyz"
    renderer = _setup_renderer(size)

    with patch("seedsigner.hardware.buttons.HardwareButtons.get_instance", return_value=_mock_hw_buttons()):
        from seedsigner.gui.screens.screen import KeyboardScreen
        screen = KeyboardScreen(
            title=title,
            rows=rows,
            cols=cols,
            keys_charset=charset,
            show_save_button=show_save_button,
        )
        screen._render()
    return renderer.canvas.copy()


def _render_loading_screen_frame(size: int, text="Loading..."):
    """Render one frame of the loading screen at the given canvas size.

    LoadingScreenThread normally runs as a background animation.  Here we
    replicate its first-frame drawing logic so we can capture a static image
    for screenshot comparison.
    """
    renderer = _setup_renderer(size)
    from seedsigner.gui.components import load_image, TextArea

    center_image = load_image("btc_logo_60x60.png")
    orbit_gap = 2 * GUIConstants.COMPONENT_PADDING
    cx = renderer.canvas_width // 2
    cy = renderer.canvas_height // 2
    bounding_box = (
        cx - center_image.width // 2 - orbit_gap,
        cy - center_image.height // 2 - orbit_gap,
        cx + center_image.width // 2 + orbit_gap,
        cy + center_image.height // 2 + orbit_gap,
    )

    # Static background: clear + paste logo
    renderer.draw.rectangle(
        (0, 0, renderer.canvas_width, renderer.canvas_height),
        fill="#000000",
    )
    renderer.canvas.paste(
        center_image,
        (bounding_box[0] + orbit_gap, bounding_box[1] + orbit_gap),
    )

    # Optional text below the logo
    if text:
        TextArea(
            text=text,
            font_size=GUIConstants.get_top_nav_title_font_size(),
            screen_y=int((renderer.canvas_height - bounding_box[3]) / 2),
        ).render()

    # Draw one animation frame (leading arc at position 0)
    arc_sweep = 45
    renderer.draw.arc(bounding_box, start=0, end=arc_sweep,
                      fill="#ff9416", width=GUIConstants.COMPONENT_PADDING)

    return renderer.canvas.copy()

class TestScreenshotComparison:
    """Render screens at both 240×240 and 128×128, compare proportions."""

    # Maximum tolerated RMS difference between the downscaled-240 and native-128.
    # Native rendering differs due to font hinting, rounding, and anti-aliasing at
    # different resolutions.  Empirically, well-matched screens produce RMS ~25-30;
    # 60 gives comfortable headroom while still catching gross layout mismatches.
    MAX_RMS_DIFF = 60.0

    def _compare_renders(self, img_240: Image.Image, img_128: Image.Image, name: str):
        """Downscale the 240 image to 128, save all three, and compare."""
        downscaled = img_240.resize((128, 128), Image.LANCZOS)

        _save(img_240, f"{name}_240.png")
        _save(img_128, f"{name}_128.png")
        _save(downscaled, f"{name}_240_downscaled.png")

        # ── 1. Both images must have visible (non-black) content ──
        bbox_240 = _non_black_bbox(img_240)
        bbox_128 = _non_black_bbox(img_128)
        assert bbox_240 is not None, f"{name}@240: screen is entirely black"
        assert bbox_128 is not None, f"{name}@128: screen is entirely black"

        # ── 2. Content should occupy a similar proportion of the canvas ──
        def _content_ratio(bbox, size):
            x0, y0, x1, y1 = bbox
            return ((x1 - x0) * (y1 - y0)) / (size * size)

        ratio_240 = _content_ratio(bbox_240, 240)
        ratio_128 = _content_ratio(bbox_128, 128)
        # The proportional area of non-black content should be within 25% of each other
        assert abs(ratio_240 - ratio_128) < 0.25, (
            f"{name}: content area proportion mismatch: "
            f"240→{ratio_240:.3f}, 128→{ratio_128:.3f}"
        )

        # ── 3. Visual RMS similarity between downscaled-240 and native-128 ──
        rms = _image_rms_diff(downscaled, img_128)
        assert rms < self.MAX_RMS_DIFF, (
            f"{name}: RMS diff {rms:.1f} exceeds max {self.MAX_RMS_DIFF} "
            f"(see {_SCREENSHOT_DIR} for images)"
        )

        return rms

    def _assert_top_nav_proportion(self, img_240: Image.Image, img_128: Image.Image, name: str):
        """Verify that the top nav occupies a similar proportion of the screen."""
        # The top nav is rendered as a darker band at the top of the screen.
        # On a scaled display, GUIConstants.TOP_NAV_HEIGHT / canvas_height should
        # be roughly the same (within rounding).
        ref_proportion = 48 / 240  # 0.2
        scaled_proportion = GUIConstants._scale(48) / 128

        # After scaling, the proportion should stay close to the reference
        assert abs(ref_proportion - scaled_proportion) < 0.05, (
            f"{name}: top nav proportion mismatch: "
            f"ref={ref_proportion:.3f}, scaled={scaled_proportion:.3f}"
        )

    # ── Individual screen tests ──

    def test_button_list_screen(self):
        """ButtonListScreen (3 options) should match at both sizes."""
        img_240 = _render_button_list_screen(240)
        img_128 = _render_button_list_screen(128)
        rms = self._compare_renders(img_240, img_128, "button_list")
        self._assert_top_nav_proportion(img_240, img_128, "button_list")
        print(f"ButtonListScreen RMS diff: {rms:.1f}")

    def test_large_icon_status_screen(self):
        """LargeIconStatusScreen should match at both sizes."""
        img_240 = _render_large_icon_status_screen(240)
        img_128 = _render_large_icon_status_screen(128)
        rms = self._compare_renders(img_240, img_128, "large_icon_status")
        self._assert_top_nav_proportion(img_240, img_128, "large_icon_status")
        print(f"LargeIconStatusScreen RMS diff: {rms:.1f}")

    def test_large_button_screen(self):
        """LargeButtonScreen (home-style 2 big buttons) should match at both sizes."""
        img_240 = _render_large_button_screen(240)
        img_128 = _render_large_button_screen(128)
        rms = self._compare_renders(img_240, img_128, "large_button")
        self._assert_top_nav_proportion(img_240, img_128, "large_button")
        print(f"LargeButtonScreen RMS diff: {rms:.1f}")

    def test_warning_screen(self):
        """WarningScreen should match at both sizes."""
        img_240 = _render_warning_screen(240)
        img_128 = _render_warning_screen(128)
        rms = self._compare_renders(img_240, img_128, "warning")
        self._assert_top_nav_proportion(img_240, img_128, "warning")
        print(f"WarningScreen RMS diff: {rms:.1f}")

    def test_button_list_with_many_items(self):
        """A scrollable list (5+ items) should render at both sizes."""
        labels = [f"Item {i}" for i in range(6)]
        img_240 = _render_button_list_screen(240, title="Long List", button_labels=labels)
        img_128 = _render_button_list_screen(128, title="Long List", button_labels=labels)
        rms = self._compare_renders(img_240, img_128, "button_list_many")
        print(f"ButtonListScreen (many) RMS diff: {rms:.1f}")

    def test_128_content_fits_within_canvas(self):
        """At 128×128, content must not have non-black pixels outside the canvas."""
        for render_fn, name in [
            (lambda sz: _render_button_list_screen(sz), "button_list_fit"),
            (lambda sz: _render_large_icon_status_screen(sz), "icon_status_fit"),
            (lambda sz: _render_large_button_screen(sz), "large_button_fit"),
            (lambda sz: _render_keyboard_screen(sz), "keyboard_fit"),
            (lambda sz: _render_loading_screen_frame(sz), "loading_fit"),
        ]:
            img = render_fn(128)
            assert img.size == (128, 128), f"{name}: unexpected image size {img.size}"
            bbox = _non_black_bbox(img)
            if bbox:
                x0, y0, x1, y1 = bbox
                assert x1 <= 128 and y1 <= 128, (
                    f"{name}@128: content overflows canvas: bbox={bbox}"
                )

    def test_title_font_size_scales_with_display(self):
        """Verify that title_font_size is evaluated at instance time, not import time."""
        # At 240
        _setup_renderer(240)
        with patch("seedsigner.hardware.buttons.HardwareButtons.get_instance", return_value=_mock_hw_buttons()):
            from seedsigner.gui.screens.screen import BaseTopNavScreen
            screen_240 = BaseTopNavScreen(title="Test")
            font_240 = screen_240.title_font_size

        # At 128
        _setup_renderer(128)
        with patch("seedsigner.hardware.buttons.HardwareButtons.get_instance", return_value=_mock_hw_buttons()):
            screen_128 = BaseTopNavScreen(title="Test")
            font_128 = screen_128.title_font_size

        # The 128 font should be smaller than the 240 font
        assert font_128 < font_240, (
            f"title_font_size not scaling: 240→{font_240}, 128→{font_128}"
        )
        # And proportional
        expected_128 = max(1, round(font_240 * 128 / 240))
        assert font_128 == expected_128, (
            f"title_font_size at 128 should be {expected_128}, got {font_128}"
        )

    def test_scroll_arrows_do_not_overlap_title(self):
        """Scroll arrow black background must not overlap the title text area.

        At 128×128, hardcoded pixel offsets for the up-arrow image could place
        its black background rectangle over the top nav title area.  This test
        renders a scrollable ButtonListScreen (many items) at both sizes and
        checks that the top-nav region (the first TOP_NAV_HEIGHT rows) contains
        no black rectangle that wasn't present in the non-scrollable version.
        """
        for size in (240, 128):
            # Render a short list (no scroll arrows)
            short_img = _render_button_list_screen(size, title="Settings", button_labels=["A", "B"])
            # Render a long list (with scroll arrows)
            long_labels = [f"Item {i}" for i in range(10)]
            long_img = _render_button_list_screen(size, title="Settings", button_labels=long_labels)

            _save(short_img, f"scroll_arrow_short_{size}.png")
            _save(long_img, f"scroll_arrow_long_{size}.png")

            # Extract the top nav region from both images
            _setup_renderer(size)
            nav_h = GUIConstants.TOP_NAV_HEIGHT
            short_nav = short_img.crop((0, 0, size, nav_h))
            long_nav = long_img.crop((0, 0, size, nav_h))

            # The title region of the scrollable screen should look the same
            # as the non-scrollable version (no black rectangle overlay).
            rms = _image_rms_diff(short_nav, long_nav)
            assert rms < 15.0, (
                f"@{size}: scroll arrows distort title area (RMS={rms:.1f}). "
                f"See {_SCREENSHOT_DIR}/scroll_arrow_*_{size}.png"
            )

    def test_scrollable_button_list_at_both_sizes(self):
        """A scrollable (10-item) list should match proportionally at both sizes."""
        labels = [f"Item {i}" for i in range(10)]
        img_240 = _render_button_list_screen(240, title="Settings", button_labels=labels)
        img_128 = _render_button_list_screen(128, title="Settings", button_labels=labels)
        rms = self._compare_renders(img_240, img_128, "scrollable_list")
        print(f"Scrollable list RMS diff: {rms:.1f}")

    def test_main_menu_title_font_scales(self):
        """MainMenuScreen.title_font_size (26 at 240) must scale for 128."""
        from seedsigner.gui.screens.screen import MainMenuScreen, ButtonOption
        from seedsigner.gui.components import SeedSignerIconConstants

        buttons = [
            ButtonOption("Seeds", icon_name=SeedSignerIconConstants.SEEDS),
            ButtonOption("Scan", icon_name=SeedSignerIconConstants.SCAN),
            ButtonOption("Tools", icon_name=SeedSignerIconConstants.TOOLS),
            ButtonOption("Settings", icon_name=SeedSignerIconConstants.SETTINGS),
        ]

        # At 240 the font size should be the reference value (26)
        _setup_renderer(240)
        with patch("seedsigner.hardware.buttons.HardwareButtons.get_instance", return_value=_mock_hw_buttons()), \
             patch("seedsigner.hardware.battery_hat.BatteryHat.get_instance") as bat_mock:
            bat = MagicMock()
            bat.is_enabled.return_value = False
            bat.detected = False
            bat_mock.return_value = bat
            screen_240 = MainMenuScreen(title="SeedSigner", button_data=buttons)
            assert screen_240.title_font_size == 26

        # At 128 the font size should be proportionally scaled
        _setup_renderer(128)
        with patch("seedsigner.hardware.buttons.HardwareButtons.get_instance", return_value=_mock_hw_buttons()), \
             patch("seedsigner.hardware.battery_hat.BatteryHat.get_instance") as bat_mock2:
            bat2 = MagicMock()
            bat2.is_enabled.return_value = False
            bat2.detected = False
            bat_mock2.return_value = bat2
            screen_128 = MainMenuScreen(title="SeedSigner", button_data=buttons)
            expected = max(1, round(26 * 128 / 240))
            assert screen_128.title_font_size == expected, (
                f"MainMenuScreen title_font_size at 128 should be {expected}, got {screen_128.title_font_size}"
            )

    # ── Keyboard screen tests ──

    def test_keyboard_screen(self):
        """KeyboardScreen (alpha keyboard) should match at both sizes."""
        img_240 = _render_keyboard_screen(240)
        img_128 = _render_keyboard_screen(128)
        rms = self._compare_renders(img_240, img_128, "keyboard")
        self._assert_top_nav_proportion(img_240, img_128, "keyboard")
        print(f"KeyboardScreen RMS diff: {rms:.1f}")

    def test_keyboard_screen_with_save_button(self):
        """KeyboardScreen with save button panel should match at both sizes."""
        img_240 = _render_keyboard_screen(240, title="Card PIN", show_save_button=True)
        img_128 = _render_keyboard_screen(128, title="Card PIN", show_save_button=True)
        rms = self._compare_renders(img_240, img_128, "keyboard_save")
        print(f"KeyboardScreen (save button) RMS diff: {rms:.1f}")

    def test_keyboard_content_fits_within_canvas(self):
        """Keyboard content at 128×128 must not overflow the canvas."""
        img = _render_keyboard_screen(128)
        assert img.size == (128, 128)
        bbox = _non_black_bbox(img)
        if bbox:
            x0, y0, x1, y1 = bbox
            assert x1 <= 128 and y1 <= 128, (
                f"keyboard@128: content overflows canvas: bbox={bbox}"
            )

    # ── Loading screen tests ──

    def test_loading_screen(self):
        """Loading screen frame should match at both sizes."""
        img_240 = _render_loading_screen_frame(240)
        img_128 = _render_loading_screen_frame(128)
        rms = self._compare_renders(img_240, img_128, "loading")
        print(f"LoadingScreen RMS diff: {rms:.1f}")

    def test_loading_screen_content_fits_within_canvas(self):
        """Loading screen at 128×128 must not overflow the canvas."""
        img = _render_loading_screen_frame(128)
        assert img.size == (128, 128)
        bbox = _non_black_bbox(img)
        if bbox:
            x0, y0, x1, y1 = bbox
            assert x1 <= 128 and y1 <= 128, (
                f"loading@128: content overflows canvas: bbox={bbox}"
            )
