"""Desktop display driver that mimics the Waveshare LCD using pygame."""

from PIL import Image

import seedsigner.hardware.buttons as button_defs
from seedsigner.hardware.buttons import (
    HardwareButtons,
    DESKTOP_LEFT_WIDTH,
    DESKTOP_RIGHT_WIDTH,
)

DARK_BLUE = (0, 0, 80)


class DesktopDisplay:
    """A pygame-backed display used when running SeedSigner on a PC."""

    def __init__(self, width: int = 240, height: int = 240, scale: int = 2):
        """Create the desktop display.

        ``width`` and ``height`` describe the logical size of the emulated LCD
        while ``scale`` enlarges the window to make it easier to view on a
        desktop monitor.
        """
        try:
            import pygame  # type: ignore
        except ModuleNotFoundError as e:
            raise ModuleNotFoundError(
                "pygame is required for desktop display; install requirements-desktop.txt",
            ) from e

        # Inform the button module of the chosen dimensions so it can recalc
        # clickable regions.
        HardwareButtons.set_desktop_dimensions(width, height)
        HardwareButtons.set_desktop_scale(scale)

        self.pygame = pygame
        self.width = width
        self.height = height
        self.scale = scale
        self.left_width = DESKTOP_LEFT_WIDTH
        self.right_width = DESKTOP_RIGHT_WIDTH

        self.pygame.init()
        total_width = self.width + self.left_width + self.right_width
        # Create a window scaled up so it's easier to view on desktop
        self.window = self.pygame.display.set_mode(
            (total_width * self.scale, self.height * self.scale)
        )
        self.pygame.display.set_caption("SeedSigner Desktop Display")
        self.button_layout = button_defs.DESKTOP_BUTTON_LAYOUT
        self.font = self.pygame.font.SysFont(None, 12 * self.scale)

    def invert(self, enabled: bool = True):
        """Placeholder to match hardware API; no-op for desktop."""
        pass

    def show_image(self, image: Image.Image, x_start: int = 0, y_start: int = 0):
        """Render a PIL image to the pygame window."""
        if image.mode != "RGB":
            image = image.convert("RGB")

        pg_img = self.pygame.image.fromstring(image.tobytes(), image.size, image.mode)
        pg_img = self.pygame.transform.scale(
            pg_img, (self.width * self.scale, self.height * self.scale)
        )
        # Fill side panels, then blit the LCD contents centred between them.
        self.window.fill(DARK_BLUE)
        self.window.blit(pg_img, (self.left_width * self.scale, 0))
        self.draw_buttons()
        # Pump events to keep the window responsive even when no input is read
        self.pygame.event.pump()
        self.pygame.display.flip()

    def draw_buttons(self):
        """Render clickable button overlays alongside the simulated display."""
        left_rect = self.pygame.Rect(
            0, 0, self.left_width * self.scale, self.height * self.scale
        )
        right_rect = self.pygame.Rect(
            (self.left_width + self.width) * self.scale,
            0,
            self.right_width * self.scale,
            self.height * self.scale,
        )
        self.pygame.draw.rect(self.window, DARK_BLUE, left_rect)
        self.pygame.draw.rect(self.window, DARK_BLUE, right_rect)

        for key, (x, y, w, h) in self.button_layout.items():
            rect = self.pygame.Rect(x * self.scale, y * self.scale, w * self.scale, h * self.scale)
            self.pygame.draw.rect(self.window, (80, 80, 80), rect, border_radius=4)

            if key in (
                HardwareButtons.KEY_UP_PIN,
                HardwareButtons.KEY_DOWN_PIN,
                HardwareButtons.KEY_LEFT_PIN,
                HardwareButtons.KEY_RIGHT_PIN,
            ):
                self._draw_arrow(rect, key)
            elif key == HardwareButtons.KEY_PRESS_PIN:
                self._draw_label(rect, "OK")
            elif key == HardwareButtons.KEY1_PIN:
                self._draw_label(rect, "1")
            elif key == HardwareButtons.KEY2_PIN:
                self._draw_label(rect, "2")
            elif key == HardwareButtons.KEY3_PIN:
                self._draw_label(rect, "3")

    def _draw_label(self, rect, text):
        """Draw a centered text label inside ``rect``."""
        surf = self.font.render(text, True, (255, 255, 255))
        text_rect = surf.get_rect(center=rect.center)
        self.window.blit(surf, text_rect)

    def _draw_arrow(self, rect, key):
        """Draw a directional arrow for the given D-pad button."""
        cx, cy = rect.center
        s = rect.width // 3
        if key == HardwareButtons.KEY_UP_PIN:
            pts = [(cx, cy - s), (cx - s, cy + s), (cx + s, cy + s)]
        elif key == HardwareButtons.KEY_DOWN_PIN:
            pts = [(cx, cy + s), (cx - s, cy - s), (cx + s, cy - s)]
        elif key == HardwareButtons.KEY_LEFT_PIN:
            pts = [(cx - s, cy), (cx + s, cy - s), (cx + s, cy + s)]
        elif key == HardwareButtons.KEY_RIGHT_PIN:
            pts = [(cx + s, cy), (cx - s, cy - s), (cx - s, cy + s)]
        self.pygame.draw.polygon(self.window, (255, 255, 255), pts)
