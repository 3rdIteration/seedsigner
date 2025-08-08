from PIL import Image

from seedsigner.hardware.buttons import (
    HardwareButtons,
    DESKTOP_BUTTON_LAYOUT,
    DESKTOP_PANEL_HEIGHT,
)


class DesktopDisplay:
    """A simple pygame-based display to simulate the Waveshare LCD on desktops."""

    def __init__(self, width: int = 240, height: int = 240, scale: int = 2):
        try:
            import pygame  # type: ignore
        except ModuleNotFoundError as e:
            raise ModuleNotFoundError(
                "pygame is required for desktop display; install requirements-desktop.txt",
            ) from e

        HardwareButtons.set_desktop_scale(scale)
        self.pygame = pygame
        self.width = width
        self.height = height
        self.scale = scale
        self.panel_height = DESKTOP_PANEL_HEIGHT
        self.pygame.init()
        # Create a window scaled up so it's easier to view on desktop
        self.window = self.pygame.display.set_mode(
            (self.width * self.scale, (self.height + self.panel_height) * self.scale)
        )
        self.pygame.display.set_caption("SeedSigner Desktop Display")
        self.button_layout = DESKTOP_BUTTON_LAYOUT
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
        self.window.blit(pg_img, (0, 0))
        self.draw_buttons()
        self.pygame.display.flip()

    def draw_buttons(self):
        """Render clickable button overlays below the simulated display."""
        panel_rect = self.pygame.Rect(
            0, self.height * self.scale, self.width * self.scale, self.panel_height * self.scale
        )
        self.pygame.draw.rect(self.window, (30, 30, 30), panel_rect)

        for key, (x, y, w, h) in self.button_layout.items():
            rect = self.pygame.Rect(x * self.scale, y * self.scale, w * self.scale, h * self.scale)
            self.pygame.draw.rect(self.window, (80, 80, 80), rect, border_radius=4)

            if key == HardwareButtons.KEY_UP_PIN:
                label = "↑"
            elif key == HardwareButtons.KEY_DOWN_PIN:
                label = "↓"
            elif key == HardwareButtons.KEY_LEFT_PIN:
                label = "←"
            elif key == HardwareButtons.KEY_RIGHT_PIN:
                label = "→"
            elif key == HardwareButtons.KEY_PRESS_PIN:
                label = "OK"
            elif key == HardwareButtons.KEY1_PIN:
                label = "1"
            elif key == HardwareButtons.KEY2_PIN:
                label = "2"
            elif key == HardwareButtons.KEY3_PIN:
                label = "3"
            else:
                label = ""

            if label:
                surf = self.font.render(label, True, (255, 255, 255))
                text_rect = surf.get_rect(center=rect.center)
                self.window.blit(surf, text_rect)
