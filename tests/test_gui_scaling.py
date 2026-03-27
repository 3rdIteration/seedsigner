"""Tests for the GUIConstants display-scaling mechanism."""

from seedsigner.gui.components import GUIConstants


# Keep original reference values for assertions
_ORIG_EDGE_PADDING = 8
_ORIG_COMPONENT_PADDING = 8
_ORIG_TOP_NAV_HEIGHT = 48
_ORIG_BUTTON_HEIGHT = 32
_ORIG_ICON_FONT_SIZE = 22
_ORIG_ICON_INLINE_FONT_SIZE = 24
_ORIG_ICON_LARGE_BUTTON_SIZE = 48
_ORIG_ICON_PRIMARY_SCREEN_SIZE = 50
_ORIG_BODY_FONT_SIZE_DEFAULT = 17
_ORIG_BUTTON_FONT_SIZE_DEFAULT = 18
_ORIG_TOP_NAV_TITLE_FONT_SIZE_DEFAULT = 20
_ORIG_BODY_FONT_MIN_SIZE = 15


def _reset_gui_constants():
    """Restore GUIConstants to their 240x240 reference values."""
    GUIConstants._scale_factor = 1.0
    GUIConstants.EDGE_PADDING = _ORIG_EDGE_PADDING
    GUIConstants.COMPONENT_PADDING = _ORIG_COMPONENT_PADDING
    GUIConstants.LIST_ITEM_PADDING = 4
    GUIConstants.TOP_NAV_HEIGHT = _ORIG_TOP_NAV_HEIGHT
    GUIConstants.TOP_NAV_BUTTON_SIZE = 32
    GUIConstants.BUTTON_HEIGHT = _ORIG_BUTTON_HEIGHT
    GUIConstants.ICON_FONT_SIZE = _ORIG_ICON_FONT_SIZE
    GUIConstants.ICON_INLINE_FONT_SIZE = _ORIG_ICON_INLINE_FONT_SIZE
    GUIConstants.ICON_LARGE_BUTTON_SIZE = _ORIG_ICON_LARGE_BUTTON_SIZE
    GUIConstants.ICON_TOAST_FONT_SIZE = 30
    GUIConstants.ICON_PRIMARY_SCREEN_SIZE = _ORIG_ICON_PRIMARY_SCREEN_SIZE
    GUIConstants.BODY_FONT_SIZE = {
        "default": _ORIG_BODY_FONT_SIZE_DEFAULT,
    }
    GUIConstants.BUTTON_FONT_SIZE = {
        "default": _ORIG_BUTTON_FONT_SIZE_DEFAULT,
    }
    GUIConstants.TOP_NAV_TITLE_FONT_SIZE = {
        "default": _ORIG_TOP_NAV_TITLE_FONT_SIZE_DEFAULT,
    }
    GUIConstants.BODY_FONT_MAX_SIZE = _ORIG_TOP_NAV_TITLE_FONT_SIZE_DEFAULT
    GUIConstants.BODY_FONT_MIN_SIZE = _ORIG_BODY_FONT_MIN_SIZE
    GUIConstants.BODY_LINE_SPACING = _ORIG_COMPONENT_PADDING
    GUIConstants.LABEL_FONT_SIZE = _ORIG_BODY_FONT_MIN_SIZE


class TestGUIScaling:
    """Verify that apply_display_scale adjusts constants correctly."""

    def setup_method(self):
        _reset_gui_constants()

    def teardown_method(self):
        _reset_gui_constants()

    def test_scale_factor_at_240(self):
        """At reference resolution, no scaling should happen."""
        GUIConstants.apply_display_scale(240)
        assert GUIConstants._scale_factor == 1.0
        assert GUIConstants.TOP_NAV_HEIGHT == _ORIG_TOP_NAV_HEIGHT
        assert GUIConstants.BUTTON_HEIGHT == _ORIG_BUTTON_HEIGHT
        assert GUIConstants.EDGE_PADDING == _ORIG_EDGE_PADDING

    def test_scale_factor_at_128(self):
        """At 128x128, all pixel values should be proportionally scaled."""
        GUIConstants.apply_display_scale(128)
        factor = 128 / 240
        assert GUIConstants._scale_factor == factor

        # Padding
        assert GUIConstants.EDGE_PADDING == max(1, round(8 * factor))
        assert GUIConstants.COMPONENT_PADDING == max(1, round(8 * factor))
        assert GUIConstants.LIST_ITEM_PADDING == max(1, round(4 * factor))

        # Heights
        assert GUIConstants.TOP_NAV_HEIGHT == max(1, round(48 * factor))
        assert GUIConstants.BUTTON_HEIGHT == max(1, round(32 * factor))

        # Icon sizes
        assert GUIConstants.ICON_FONT_SIZE == max(1, round(22 * factor))
        assert GUIConstants.ICON_INLINE_FONT_SIZE == max(1, round(24 * factor))
        assert GUIConstants.ICON_LARGE_BUTTON_SIZE == max(1, round(48 * factor))
        assert GUIConstants.ICON_PRIMARY_SCREEN_SIZE == max(1, round(50 * factor))

        # Font sizes
        assert GUIConstants.BODY_FONT_SIZE["default"] == max(1, round(17 * factor))
        assert GUIConstants.BUTTON_FONT_SIZE["default"] == max(1, round(18 * factor))
        assert GUIConstants.TOP_NAV_TITLE_FONT_SIZE["default"] == max(1, round(20 * factor))

        # Derived values
        assert GUIConstants.BODY_FONT_MAX_SIZE == GUIConstants.TOP_NAV_TITLE_FONT_SIZE["default"]
        assert GUIConstants.BODY_LINE_SPACING == GUIConstants.COMPONENT_PADDING
        assert GUIConstants.LABEL_FONT_SIZE == GUIConstants.BODY_FONT_MIN_SIZE

    def test_scale_never_below_one(self):
        """Even at extreme downscaling, pixel values should not go below 1."""
        GUIConstants.apply_display_scale(10)  # extreme case
        assert GUIConstants.EDGE_PADDING >= 1
        assert GUIConstants.TOP_NAV_HEIGHT >= 1
        assert GUIConstants.BUTTON_HEIGHT >= 1
        assert GUIConstants.ICON_FONT_SIZE >= 1
        for v in GUIConstants.BODY_FONT_SIZE.values():
            assert v >= 1

    def test_scale_helper(self):
        """_scale should round correctly and respect the floor of 1."""
        GUIConstants._scale_factor = 0.5
        assert GUIConstants._scale(10) == 5
        assert GUIConstants._scale(3) == 2  # round(1.5) = 2
        assert GUIConstants._scale(1) == 1  # max(1, round(0.5))

    def test_scale_noop_when_factor_is_one(self):
        """_scale returns value unchanged when factor is 1.0."""
        GUIConstants._scale_factor = 1.0
        assert GUIConstants._scale(48) == 48
        assert GUIConstants._scale(8) == 8

    def test_idempotent_apply_at_reference(self):
        """Calling apply_display_scale(240) should leave values unchanged."""
        orig_top_nav = GUIConstants.TOP_NAV_HEIGHT
        orig_edge = GUIConstants.EDGE_PADDING
        GUIConstants.apply_display_scale(240)
        assert GUIConstants.TOP_NAV_HEIGHT == orig_top_nav
        assert GUIConstants.EDGE_PADDING == orig_edge
