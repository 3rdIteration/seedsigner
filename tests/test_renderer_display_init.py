import importlib.util
from pathlib import Path
from threading import Lock
from unittest.mock import MagicMock, patch

# tests/base.py replaces sys.modules['seedsigner.gui.renderer'] with a MagicMock to
# avoid hardware dependencies.  We need the real Renderer here, but we must NOT swap
# that sys.modules entry (or the seedsigner.gui package attributes): Views resolve
# `from seedsigner.gui import Renderer` at run time, and a stale real class left
# behind makes every View construction raise "Must call configure_instance() first"
# in an infinite controller error loop.  Instead, load renderer.py from its file path
# under an alias name so the canonical module entry is never touched.
_RENDERER_PATH = Path(__file__).resolve().parents[1] / "src" / "seedsigner" / "gui" / "renderer.py"

_real_renderer_module = None


def _get_real_renderer_module():
    global _real_renderer_module
    if _real_renderer_module is None:
        spec = importlib.util.spec_from_file_location("_real_seedsigner_renderer", _RENDERER_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _real_renderer_module = module
    return _real_renderer_module


from seedsigner.models.settings_definition import SettingsConstants


def _run_initialize_display(color_inverted_value: str):
    """Run the real Renderer.initialize_display() against a mocked display driver.

    Returns (mock_disp, mock_settings) for assertions.
    """
    renderer_module = _get_real_renderer_module()
    renderer = object.__new__(renderer_module.Renderer)
    renderer.lock = Lock()

    mock_settings = MagicMock()
    mock_settings.get_value.side_effect = lambda attr_name, default_if_none=False: {
        SettingsConstants.SETTING__DISPLAY_CONFIGURATION: "st7789_240x240",
        SettingsConstants.SETTING__DISPLAY_COLOR_INVERTED: color_inverted_value,
    }[attr_name]

    mock_disp = MagicMock(width=240, height=240)

    with patch.object(renderer_module.Settings, "get_instance") as mock_settings_cls, \
         patch.object(renderer_module.DisplayDriverFactory, "instantiate_display_driver", return_value=mock_disp):
        mock_settings_cls.return_value = mock_settings
        renderer.initialize_display()

    return mock_disp


def test_initialize_display_applies_inversion_when_enabled():
    """The saved 'Invert colors' setting must be applied explicitly at display
    init, not only when it is enabled."""
    mock_disp = _run_initialize_display(SettingsConstants.OPTION__ENABLED)

    mock_disp.invert.assert_called_once_with(enabled=True)


def test_initialize_display_applies_inversion_when_disabled():
    """A saved 'disabled' value must explicitly turn inversion OFF; driver init
    sequences may leave the panel inverted."""
    mock_disp = _run_initialize_display(SettingsConstants.OPTION__DISABLED)

    mock_disp.invert.assert_called_once_with(enabled=False)


def test_initialize_display_reapplies_inversion_on_driver_switch():
    """Re-initializing with a different display driver (e.g. long-press toggle or
    settings change) must re-apply the saved inversion state to the new driver."""
    renderer_module = _get_real_renderer_module()
    mock_disp_a = MagicMock(width=240, height=240)
    mock_disp_b = MagicMock(width=128, height=128)

    renderer = object.__new__(renderer_module.Renderer)
    renderer.lock = Lock()

    display_configs = iter(["st7789_240x240", "st7735_128x128"])
    mock_settings = MagicMock()

    def get_value(attr_name, default_if_none=False):
        if attr_name == SettingsConstants.SETTING__DISPLAY_CONFIGURATION:
            return next(display_configs)
        return SettingsConstants.OPTION__ENABLED

    mock_settings.get_value.side_effect = get_value

    with patch.object(renderer_module.Settings, "get_instance") as mock_settings_cls, \
         patch.object(renderer_module.DisplayDriverFactory, "instantiate_display_driver", side_effect=[mock_disp_a, mock_disp_b]):
        mock_settings_cls.return_value = mock_settings
        renderer.initialize_display()
        renderer.initialize_display()

    mock_disp_a.invert.assert_called_once_with(enabled=True)
    mock_disp_b.invert.assert_called_once_with(enabled=True)
