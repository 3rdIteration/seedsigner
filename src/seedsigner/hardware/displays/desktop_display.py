import pygame
from PIL import Image


class DesktopDisplay:
    """A simple pygame-based display to simulate the Waveshare LCD on desktops."""

    def __init__(self, width: int = 240, height: int = 240, scale: int = 2):
        self.width = width
        self.height = height
        self.scale = scale
        pygame.init()
        # Create a window scaled up so it's easier to view on desktop
        self.window = pygame.display.set_mode((self.width * self.scale, self.height * self.scale))
        pygame.display.set_caption("SeedSigner Desktop Display")

    def invert(self, enabled: bool = True):
        """Placeholder to match hardware API; no-op for desktop."""
        pass

    def show_image(self, image: Image.Image, x_start: int = 0, y_start: int = 0):
        """Render a PIL image to the pygame window."""
        if image.mode != "RGB":
            image = image.convert("RGB")

        pg_img = pygame.image.fromstring(image.tobytes(), image.size, image.mode)
        pg_img = pygame.transform.scale(pg_img, (self.width * self.scale, self.height * self.scale))
        self.window.blit(pg_img, (0, 0))
        pygame.display.flip()
