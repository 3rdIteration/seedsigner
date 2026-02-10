import array
import os
import time

import spidev
from periphery import GPIO


def _detect_luckfox_profile() -> str:
    profile = os.getenv("SEEDSIGNER_LUCKFOX_PROFILE", "").strip().lower()
    if profile in {"mini", "max"}:
        return profile

    try:
        with open("/proc/device-tree/model", "rb") as f:
            model = f.read().decode("utf-8", errors="ignore").lower()
        if "mini" in model:
            return "mini"
        if "max" in model:
            return "max"
    except FileNotFoundError:
        pass

    return "max"


class ST7789(object):
    """class for ST7789 240*240 1.3inch OLED displays."""

    # If mini wiring differs, override with env vars:
    #   SEEDSIGNER_LCD_DC_PIN / SEEDSIGNER_LCD_RST_PIN
    _PROFILE_PINS = {
        "max": {"dc": 56, "rst": 57},
        "mini": {"dc": 56, "rst": 57},
    }

    def __init__(self):
        self.width = 240
        self.height = 240

        profile = _detect_luckfox_profile()
        pins = self._PROFILE_PINS[profile]
        self._dc_pin = int(os.getenv("SEEDSIGNER_LCD_DC_PIN", pins["dc"]))
        self._rst_pin = int(os.getenv("SEEDSIGNER_LCD_RST_PIN", pins["rst"]))

        self._dc = GPIO(self._dc_pin, "out")
        self._rst = GPIO(self._rst_pin, "out")

        self._spi = spidev.SpiDev(0, 0)
        self._spi.max_speed_hz = 40000000

        self.init()

    def command(self, cmd):
        self._dc.write(False)
        self._spi.writebytes([cmd])

    def data(self, val):
        self._dc.write(True)
        self._spi.writebytes([val])

    def init(self):
        """Initialize display"""
        self.reset()

        self.command(0x36)
        self.data(0x70)

        self.command(0x3A)
        self.data(0x05)

        self.command(0xB2)
        self.data(0x0C)
        self.data(0x0C)
        self.data(0x00)
        self.data(0x33)
        self.data(0x33)

        self.command(0xB7)
        self.data(0x35)

        self.command(0xBB)
        self.data(0x19)

        self.command(0xC0)
        self.data(0x2C)

        self.command(0xC2)
        self.data(0x01)

        self.command(0xC3)
        self.data(0x12)

        self.command(0xC4)
        self.data(0x20)

        self.command(0xC6)
        self.data(0x0F)

        self.command(0xD0)
        self.data(0xA4)
        self.data(0xA1)

        self.command(0xE0)
        self.data(0xD0)
        self.data(0x04)
        self.data(0x0D)
        self.data(0x11)
        self.data(0x13)
        self.data(0x2B)
        self.data(0x3F)
        self.data(0x54)
        self.data(0x4C)
        self.data(0x18)
        self.data(0x0D)
        self.data(0x0B)
        self.data(0x1F)
        self.data(0x23)

        self.command(0xE1)
        self.data(0xD0)
        self.data(0x04)
        self.data(0x0C)
        self.data(0x11)
        self.data(0x13)
        self.data(0x2C)
        self.data(0x3F)
        self.data(0x44)
        self.data(0x51)
        self.data(0x2F)
        self.data(0x1F)
        self.data(0x1F)
        self.data(0x20)
        self.data(0x23)

        self.command(0x21)
        self.command(0x11)
        self.command(0x29)

    def reset(self):
        self._rst.write(True)
        time.sleep(0.01)
        self._rst.write(False)
        time.sleep(0.01)
        self._rst.write(True)
        time.sleep(0.01)

    def SetWindows(self, Xstart, Ystart, Xend, Yend):
        self.command(0x2A)
        self.data(0x00)
        self.data(Xstart & 0xFF)
        self.data(0x00)
        self.data((Xend - 1) & 0xFF)

        self.command(0x2B)
        self.data(0x00)
        self.data(Ystart & 0xFF)
        self.data(0x00)
        self.data((Yend - 1) & 0xFF)

        self.command(0x2C)

    def show_image(self, Image, Xstart, Ystart):
        imwidth, imheight = Image.size
        if imwidth != self.width or imheight != self.height:
            raise ValueError(f"Image must be same dimensions as display ({self.width}x{self.height}).")
        arr = array.array("H", Image.convert("BGR;16").tobytes())
        arr.byteswap()
        pix = arr.tobytes()
        self.SetWindows(0, 0, self.width, self.height)
        self._dc.write(True)
        self._spi.writebytes2(pix)

    def clear(self):
        _buffer = [0xFF] * (self.width * self.height * 2)
        self.SetWindows(0, 0, self.width, self.height)
        self._dc.write(True)
        self._spi.writebytes2(_buffer)

    def invert(self, enabled: bool = True):
        self.command(0x21 if enabled else 0x20)
