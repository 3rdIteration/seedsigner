"""Display driver base class and factory for selecting the appropriate display backend."""
from dataclasses import dataclass


DISPLAY_TYPE__ST7789 = "st7789"
DISPLAY_TYPE__ST7735 = "st7735"
DISPLAY_TYPE__ILI9341 = "ili9341"
DISPLAY_TYPE__ILI9486 = "ili9486"
DISPLAY_TYPE__DESKTOP = "desktop"

ALL_DISPLAY_TYPES = [
    DISPLAY_TYPE__ST7789,
    DISPLAY_TYPE__ST7735,
    DISPLAY_TYPE__ILI9341,
    DISPLAY_TYPE__ILI9486,
    DISPLAY_TYPE__DESKTOP,
]

    

@dataclass
class BaseDisplayDriver:
    _width: int
    _height: int

    # Some panels only render correct colors with the controller's inversion mode
    # switched ON (the ST7789 panels SeedSigner ships with are wired that way).  The
    # user-facing "Invert colors" setting is applied *relative* to this baseline, so
    # its default (Disabled) always means "normal colors for this panel".
    # Note: deliberately un-annotated so it stays a class attr, not a dataclass field.
    NORMAL_COLORS_REQUIRE_INVERSION = False


    def __str__(self):
        return f"DisplayDriver(display_type={getattr(self, 'display_type', None)}, width={self.width}, height={self.height})"


    @property
    def width(self):
        return self._width


    @property
    def height(self):
        return self._height


    def invert(self, enabled: bool = True):
        """
        Drive the controller's raw inversion mode (INVON/INVOFF).
        Implementation in child classes is optional.
        """
        pass


    def set_color_inversion(self, inverted: bool):
        """
        Apply the user-facing "Invert colors" setting, accounting for whether this
        panel needs the controller's inversion mode on to look normal.
        """
        self.invert(enabled=inverted != self.NORMAL_COLORS_REQUIRE_INVERSION)


    def show_image(self, image, x_start: int = 0, y_start: int = 0):
        """
        The main rendering call to the display driver.
        Must be implemented in child classes.
        """
        raise Exception("show_image() must be implemented in child classes")


    def cleanup(self):
        """
        Cleanup resources used by the display driver.
        Implementation in child classes is optional; drivers that expose a
        close() method (releasing GPIO/SPI lines) are cleaned up by default.
        """
        close_fn = getattr(self, "close", None)
        if callable(close_fn):
            close_fn()



class DisplayDriverFactory:
    """
    Manages all logic related to instantiating display drivers based on type and resolution.

    Imports for specific display drivers are done within this class to avoid circular imports.
    """

    @classmethod
    def instantiate_display_driver(cls, display_type: str = DISPLAY_TYPE__ST7789, width: int = None, height: int = None) -> BaseDisplayDriver:
        if display_type not in ALL_DISPLAY_TYPES:
            raise ValueError(f"Invalid display type: {display_type}")

        if display_type == DISPLAY_TYPE__ST7789:
            if width not in [240, 320] or height != 240:
                raise ValueError("ST7789 display only supports 240x240 or 320x240 resolutions")

            if width == 240:
                # TODO: For now the original ST7789 driver has to be used for 240x240.
                # The mpy version below renders incorrectly (almost like each row of pixels
                # is one pixel short, so the entire screen exhibits a diagonal skew).
                from seedsigner.hardware.displays.ST7789 import ST7789 as original_ST7789
                return original_ST7789(_width=width, _height=height)

            elif width == 320:
                from seedsigner.hardware.displays.st7789_mpy import ST7789 as mpy_ST7789
                # Have to swap width and height; screen is natively 240x320
                return mpy_ST7789(_width=height, _height=width)

        elif display_type == DISPLAY_TYPE__ST7735:
            if width != 128 or height != 128:
                raise ValueError("ST7735 display only supports 128x128 resolution")
            from seedsigner.hardware.displays.ST7735 import ST7735
            return ST7735(_width=width, _height=height)

        elif display_type == DISPLAY_TYPE__ILI9341:
            from seedsigner.hardware.displays.ili9341 import ILI9341
            display = ILI9341(_width=width, _height=height)
            display.begin()
            return display
        
        elif display_type == DISPLAY_TYPE__ILI9486:
            # TODO: improve performance of ili9486 driver
            raise Exception("ILI9486 display not implemented yet")

        elif display_type == DISPLAY_TYPE__DESKTOP:
            try:
                from seedsigner.hardware.displays.desktop_display import DesktopDisplay
            except ModuleNotFoundError as e:
                raise ModuleNotFoundError(
                    "Desktop display requires pygame; install requirements-desktop.txt"
                ) from e

            # Desktop display can support arbitrary sizes; defaults are handled by caller
            return DesktopDisplay(_width=width, _height=height)
