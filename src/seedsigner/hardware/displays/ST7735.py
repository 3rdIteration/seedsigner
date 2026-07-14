"""Driver for the ST7735S-based 128×128 1.44" Waveshare LCD HAT.

The ST7735S controller has an internal 132×162 frame-buffer but only 128×128
pixels are visible.  Column and row address offsets are applied in
:meth:`SetWindows` to centre the active region.

Pin wiring, SPI bus, and chip-select handling are identical to the
ST7789-based 1.3" HAT — see the ``RPI_40`` profile in ``io_config.json``.
"""

import array
import errno
import logging
import time

from dataclasses import dataclass

from periphery import GPIO, SPI

from seedsigner.hardware.displays.display_driver import BaseDisplayDriver
from seedsigner.hardware.io_config import get_hardware_pin_mapping
from seedsigner.models.settings import Settings

logger = logging.getLogger(__name__)

# The ST7735S internal RAM is 132×162 but only 128×128 are visible.
# Offsets shift the address window to the correct region.  These values
# correspond to MADCTL = 0x60 (MX + MV — landscape orientation) where
# the row/column exchange means X maps to physical rows and Y to
# physical columns.
_X_OFFSET = 1
_Y_OFFSET = 2


@dataclass
class ST7735(BaseDisplayDriver):
    """Driver for the ST7735S 128×128 1.44-inch LCD HAT.

    Note that self._width and self._height are provided by the parent
    BaseDisplayDriver class and are set during instantiation via the
    DisplayDriverFactory.
    """

    def __post_init__(self):
        # Keep SPI transfers within conservative per-message kernel limits.
        self.CHUNK_SIZE = 4096

        hardware_config = Settings.get_platform_default_hardware_config()
        pin_mapping = get_hardware_pin_mapping(hardware_config)["display"]

        self._dc = GPIO(*pin_mapping["dc"], "out")
        self._rst = GPIO(*pin_mapping["rst"], "out")
        bl_config = pin_mapping["bl"]
        if bl_config == "disabled":
            self._bl = None
        else:
            self._bl = GPIO(*bl_config, "out")
            self._bl.write(True)

        spi_bus = f"/dev/spidev{pin_mapping['spi_bus']}.{pin_mapping['spi_device']}"
        # ST7735S maximum SPI clock is ~16 MHz (datasheet typ. 15.15 MHz
        # write cycle).  Use 16 MHz for reliability.
        spi_hz = 16_000_000

        spi_extra_flags = 0
        if pin_mapping.get("cs") == "disabled":
            spi_extra_flags = 0x40  # SPI_NO_CS
            spi_mode = 3
            logger.info(
                "SPI CS mode: SPI_NO_CS (0x40), SPI Mode 3 — LCD CS tied to GND."
            )
        else:
            spi_mode = 0
            spi_device = pin_mapping.get("spi_device", 0)
            logger.warning(
                "SPI CS mode: kernel-managed CE%d GPIO — LCD CS must be "
                "asserted (wired to CE%d or tied to GND).",
                spi_device,
                spi_device,
            )

        logger.info("Initializing SPI: bus=%s at %.1f MHz", spi_bus, spi_hz / 1_000_000)
        try:
            self._spi = SPI(spi_bus, spi_mode, spi_hz, extra_flags=spi_extra_flags)
        except OSError as e:
            if e.errno == errno.EINVAL and spi_extra_flags != 0:
                logger.warning(
                    "SPI extra_flags=0x%02x rejected (EINVAL); retrying without. "
                    "SPI Mode %d still active.",
                    spi_extra_flags,
                    spi_mode,
                )
                self._spi = SPI(spi_bus, spi_mode, spi_hz, extra_flags=0)
            else:
                raise

        self._display_initialized = False

    # ------------------------------------------------------------------
    # Low-level SPI helpers
    # ------------------------------------------------------------------

    def _chunked_transfer(self, data):
        """Transfer *data* in chunks to avoid kernel buffer limits."""
        if isinstance(data, list):
            data = bytes(data)

        i = 0
        chunk_size = self.CHUNK_SIZE
        while i < len(data):
            chunk = data[i:i + chunk_size]
            try:
                self._spi.transfer(chunk)
                i += len(chunk)
            except Exception as e:
                if getattr(e, "errno", None) == errno.EMSGSIZE and chunk_size > 256:
                    chunk_size = max(256, chunk_size // 2)
                    self.CHUNK_SIZE = chunk_size
                    logger.warning(
                        "SPI message too long; reducing chunk size to %d bytes",
                        chunk_size,
                    )
                    continue
                raise

    def command(self, cmd):
        """Write a command byte."""
        self._dc.write(False)
        self._spi.transfer([cmd])

    def data(self, val):
        """Write a data byte."""
        self._dc.write(True)
        self._spi.transfer([val])

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _ensure_initialized(self):
        if not self._display_initialized:
            self.init()
            self._display_initialized = True

    def reset(self):
        """Pulse the hardware reset line."""
        self._rst.write(True)
        time.sleep(0.01)
        self._rst.write(False)
        time.sleep(0.01)
        self._rst.write(True)
        time.sleep(0.01)

    def init(self):
        """Send the ST7735S register initialisation sequence."""
        self.reset()

        # ------ Frame-rate control ------
        self.command(0xB1)  # FRMCTR1 — Normal mode
        self.data(0x01)
        self.data(0x2C)
        self.data(0x2D)

        self.command(0xB2)  # FRMCTR2 — Idle mode
        self.data(0x01)
        self.data(0x2C)
        self.data(0x2D)

        self.command(0xB3)  # FRMCTR3 — Partial mode (dot + line inversion)
        self.data(0x01)
        self.data(0x2C)
        self.data(0x2D)
        self.data(0x01)
        self.data(0x2C)
        self.data(0x2D)

        # ------ Display inversion control ------
        self.command(0xB4)  # INVCTR — column inversion
        self.data(0x07)

        # ------ Power control ------
        self.command(0xC0)  # PWCTR1
        self.data(0xA2)
        self.data(0x02)
        self.data(0x84)

        self.command(0xC1)  # PWCTR2
        self.data(0xC5)

        self.command(0xC2)  # PWCTR3 — normal mode
        self.data(0x0A)
        self.data(0x00)

        self.command(0xC3)  # PWCTR4 — idle mode
        self.data(0x8A)
        self.data(0x2A)

        self.command(0xC4)  # PWCTR5 — partial mode
        self.data(0x8A)
        self.data(0xEE)

        # ------ VCOM control ------
        self.command(0xC5)  # VMCTR1
        self.data(0x0E)

        # ------ Memory access (orientation) ------
        # 0x68 = MX | MV | BGR → landscape, same wiring as 1.3" HAT.
        # The ST7735S panel has physically BGR-ordered sub-pixels, so the
        # BGR bit (0x08) must be set for correct colour rendering.
        # Without it, red and blue channels are swapped (orange appears
        # blue, etc.).
        self.command(0x36)  # MADCTL
        self.data(0x68)

        # ------ Gamma correction ------
        self.command(0xE0)  # GAMCTRP1 — positive gamma
        self.data(0x0F)
        self.data(0x1A)
        self.data(0x0F)
        self.data(0x18)
        self.data(0x2F)
        self.data(0x28)
        self.data(0x20)
        self.data(0x22)
        self.data(0x1F)
        self.data(0x1B)
        self.data(0x23)
        self.data(0x37)
        self.data(0x00)
        self.data(0x07)
        self.data(0x02)
        self.data(0x10)

        self.command(0xE1)  # GAMCTRN1 — negative gamma
        self.data(0x0F)
        self.data(0x1B)
        self.data(0x0F)
        self.data(0x17)
        self.data(0x33)
        self.data(0x2C)
        self.data(0x29)
        self.data(0x2E)
        self.data(0x30)
        self.data(0x30)
        self.data(0x39)
        self.data(0x3F)
        self.data(0x00)
        self.data(0x07)
        self.data(0x03)
        self.data(0x10)

        # ------ Enable test command / disable RAM power-save ------
        self.command(0xF0)
        self.data(0x01)
        self.command(0xF6)
        self.data(0x00)

        # ------ Colour mode: 16-bit (65k colours) ------
        self.command(0x3A)  # COLMOD
        self.data(0x05)

        # ------ Sleep out + display on ------
        self.command(0x11)  # SLPOUT
        time.sleep(0.150)   # ≥120 ms required by datasheet

        self.command(0x29)  # DISPON

    # ------------------------------------------------------------------
    # Drawing helpers
    # ------------------------------------------------------------------

    def SetWindows(self, Xstart, Ystart, Xend, Yend):
        """Set the column / row address window with ST7735S offsets."""
        self.command(0x2A)  # CASET
        self.data(0x00)
        self.data((Xstart + _X_OFFSET) & 0xFF)
        self.data(0x00)
        self.data((Xend - 1 + _X_OFFSET) & 0xFF)

        self.command(0x2B)  # RASET
        self.data(0x00)
        self.data((Ystart + _Y_OFFSET) & 0xFF)
        self.data(0x00)
        self.data((Yend - 1 + _Y_OFFSET) & 0xFF)

        self.command(0x2C)  # RAMWR

    def show_image(self, Image, Xstart, Ystart):
        """Write a PIL Image to the display."""
        self._ensure_initialized()
        imwidth, imheight = Image.size
        if imwidth != self.width or imheight != self.height:
            raise ValueError(
                f"Image must be same dimensions as display "
                f"({self.width}x{self.height})."
            )
        # Same 24-bit RGB → 16-bit RGB565 conversion as ST7789:
        # convert to gBRG-3:5:5:3 then per-pixel byte-swap.
        arr = array.array("H", Image.convert("BGR;16").tobytes())
        arr.byteswap()
        pix = arr.tobytes()
        self.SetWindows(0, 0, self.width, self.height)
        self._dc.write(True)
        self._chunked_transfer(pix)

    def clear(self):
        """Fill the display with white."""
        self._ensure_initialized()
        _buffer = [0xFF] * (self.width * self.height * 2)
        self.SetWindows(0, 0, self.width, self.height)
        self._dc.write(True)
        self._chunked_transfer(_buffer)

    def invert(self, enabled: bool = True):
        """Toggle display colour inversion."""
        self._ensure_initialized()
        self.command(0x21 if enabled else 0x20)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def __del__(self):
        self.close()

    def close(self):
        for attr_name in ("_dc", "_rst", "_bl", "_spi"):
            resource = getattr(self, attr_name, None)
            if resource is None:
                continue
            try:
                resource.close()
            except Exception:
                pass
            setattr(self, attr_name, None)
