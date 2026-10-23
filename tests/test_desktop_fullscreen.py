"""Desktop fullscreen mode: the fixed layout is scaled to fit the native screen.

Runs headless on SDL's dummy video driver, which reports a 1024x768 desktop.
"""
import importlib
import os
import sys

import pytest

pygame = pytest.importorskip("pygame")

from PIL import Image

_BUTTONS = "seedsigner.hardware.buttons"
_DESKTOP_DISPLAY = "seedsigner.hardware.displays.desktop_display"


@pytest.fixture
def real_modules(monkeypatch):
    """Fresh, real buttons + desktop_display modules for this test.

    tests/base.py replaces ``seedsigner.hardware.buttons`` in sys.modules with
    a MagicMock for the whole session; a desktop_display imported after that
    gets mocked layout constants. Import both for real here; monkeypatch puts
    the session's modules (mocks included) back afterwards.
    """
    import seedsigner.hardware
    import seedsigner.hardware.displays

    for name in (_BUTTONS, _DESKTOP_DISPLAY):
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setattr(seedsigner.hardware, "buttons", None, raising=False)
    monkeypatch.setattr(seedsigner.hardware.displays, "desktop_display", None, raising=False)
    buttons = importlib.import_module(_BUTTONS)
    desktop_display = importlib.import_module(_DESKTOP_DISPLAY)
    return buttons, desktop_display


@pytest.fixture
def dummy_video(monkeypatch, real_modules):
    monkeypatch.setenv("SDL_VIDEODRIVER", "dummy")
    yield real_modules
    real_modules[0].HardwareButtons.set_desktop_pos_mapper(None)
    pygame.display.quit()


def _make(desktop_display, **kwargs):
    return desktop_display.DesktopDisplay(_width=240, _height=240, **kwargs)


def test_windowed_is_the_default(dummy_video, monkeypatch):
    buttons, desktop_display = dummy_video
    monkeypatch.delenv(desktop_display.FULLSCREEN_ENV, raising=False)
    disp = _make(desktop_display)
    assert disp.fullscreen is False
    assert disp.screen is None
    # (160 + 240 + 80) x 240 at scale 2
    assert disp.window.get_size() == (960, 480)
    assert buttons._DESKTOP_POS_MAPPER is None


def test_env_var_enables_fullscreen(dummy_video, monkeypatch):
    buttons, desktop_display = dummy_video
    monkeypatch.setenv(desktop_display.FULLSCREEN_ENV, "1")
    disp = _make(desktop_display)
    assert disp.fullscreen is True
    assert disp.screen.get_size() == (1024, 768)


def test_fullscreen_fits_and_centres_the_layout(dummy_video):
    buttons, desktop_display = dummy_video
    disp = _make(desktop_display, fullscreen=True)
    # The canvas keeps the windowed layout exactly; only presentation scales.
    assert disp.window.get_size() == (960, 480)
    # 1024/960 < 768/480: width-limited, aspect kept, centred vertically.
    assert disp._present_size == (1024, 512)
    assert disp._present_offset == (0, 128)

    disp.show_image(Image.new("RGB", (240, 240), (255, 0, 0)))
    # Letterbox is the panel colour; the LCD area shows the image.
    assert tuple(disp.screen.get_at((10, 10)))[:3] == desktop_display.DARK_BLUE
    lcd_center = (int(disp._present_offset[0] + 280 * 2 * 1024 / 960), 128 + 256)
    assert tuple(disp.screen.get_at(lcd_center))[:3] == (255, 0, 0)


def test_clicks_map_back_onto_the_button_rects(dummy_video):
    buttons, desktop_display = dummy_video
    disp = _make(desktop_display, fullscreen=True)
    assert buttons._DESKTOP_POS_MAPPER == disp.screen_to_canvas

    for key, (x, y, w, h) in buttons.DESKTOP_BUTTON_LAYOUT.items():
        # Centre of the button in canvas space, then where it lands on screen.
        cx, cy = (x + w / 2) * disp.scale, (y + h / 2) * disp.scale
        fit = disp._present_size[0] / disp.window.get_width()
        screen_pos = (disp._present_offset[0] + cx * fit, disp._present_offset[1] + cy * fit)
        canvas_rect = pygame.Rect(x * disp.scale, y * disp.scale, w * disp.scale, h * disp.scale)
        assert canvas_rect.collidepoint(disp.screen_to_canvas(screen_pos)), key


def test_letterbox_click_hits_no_button(dummy_video):
    buttons, desktop_display = dummy_video
    disp = _make(desktop_display, fullscreen=True)
    pos = disp.screen_to_canvas((5, 5))  # top letterbox band
    for x, y, w, h in buttons.DESKTOP_BUTTON_LAYOUT.values():
        rect = pygame.Rect(x * disp.scale, y * disp.scale, w * disp.scale, h * disp.scale)
        assert not rect.collidepoint(pos)


def test_main_fullscreen_flag_sets_env(monkeypatch):
    import main as seedsigner_main

    env = "SEEDSIGNER_DESKTOP_FULLSCREEN"
    monkeypatch.delenv(env, raising=False)

    class _StubController:
        def start(self, **kwargs):
            pass

    monkeypatch.setattr(seedsigner_main.Controller, "get_instance", classmethod(lambda cls: _StubController()))
    seedsigner_main.main(["--fullscreen"])
    assert os.environ.get(env) == "1"
