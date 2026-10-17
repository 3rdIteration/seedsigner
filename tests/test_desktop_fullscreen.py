"""Desktop fullscreen mode: the fixed layout is scaled to fit the native screen.

Runs headless on SDL's dummy video driver, which reports a 1024x768 desktop.
"""
import os

import pytest

pygame = pytest.importorskip("pygame")

from PIL import Image

import seedsigner.hardware.buttons as buttons
from seedsigner.hardware.buttons import HardwareButtons
from seedsigner.hardware.displays import desktop_display
from seedsigner.hardware.displays.desktop_display import DesktopDisplay


@pytest.fixture
def dummy_video(monkeypatch):
    monkeypatch.setenv("SDL_VIDEODRIVER", "dummy")
    yield
    HardwareButtons.set_desktop_pos_mapper(None)
    pygame.display.quit()


def _make(**kwargs):
    return DesktopDisplay(_width=240, _height=240, **kwargs)


def test_windowed_is_the_default(dummy_video, monkeypatch):
    monkeypatch.delenv(desktop_display.FULLSCREEN_ENV, raising=False)
    disp = _make()
    assert disp.fullscreen is False
    assert disp.screen is None
    # (160 + 240 + 80) x 240 at scale 2
    assert disp.window.get_size() == (960, 480)
    assert buttons._DESKTOP_POS_MAPPER is None


def test_env_var_enables_fullscreen(dummy_video, monkeypatch):
    monkeypatch.setenv(desktop_display.FULLSCREEN_ENV, "1")
    disp = _make()
    assert disp.fullscreen is True
    assert disp.screen.get_size() == (1024, 768)


def test_fullscreen_fits_and_centres_the_layout(dummy_video):
    disp = _make(fullscreen=True)
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
    disp = _make(fullscreen=True)
    assert buttons._DESKTOP_POS_MAPPER == disp.screen_to_canvas

    for key, (x, y, w, h) in buttons.DESKTOP_BUTTON_LAYOUT.items():
        # Centre of the button in canvas space, then where it lands on screen.
        cx, cy = (x + w / 2) * disp.scale, (y + h / 2) * disp.scale
        fit = disp._present_size[0] / disp.window.get_width()
        screen_pos = (disp._present_offset[0] + cx * fit, disp._present_offset[1] + cy * fit)
        canvas_rect = pygame.Rect(x * disp.scale, y * disp.scale, w * disp.scale, h * disp.scale)
        assert canvas_rect.collidepoint(disp.screen_to_canvas(screen_pos)), key


def test_letterbox_click_hits_no_button(dummy_video):
    disp = _make(fullscreen=True)
    pos = disp.screen_to_canvas((5, 5))  # top letterbox band
    for x, y, w, h in buttons.DESKTOP_BUTTON_LAYOUT.values():
        rect = pygame.Rect(x * disp.scale, y * disp.scale, w * disp.scale, h * disp.scale)
        assert not rect.collidepoint(pos)


def test_main_fullscreen_flag_sets_env(monkeypatch):
    import main as seedsigner_main

    monkeypatch.delenv(desktop_display.FULLSCREEN_ENV, raising=False)

    class _StubController:
        def start(self, **kwargs):
            pass

    monkeypatch.setattr(seedsigner_main.Controller, "get_instance", classmethod(lambda cls: _StubController()))
    seedsigner_main.main(["--fullscreen"])
    assert os.environ.get(desktop_display.FULLSCREEN_ENV) == "1"
