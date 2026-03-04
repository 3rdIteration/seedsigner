import logging
from periphery import GPIO, SPI
import time
import array
import errno

from seedsigner.models.settings import Settings
from seedsigner.hardware.io_config import get_hardware_pin_mapping

logger = logging.getLogger(__name__)

class ST7789(object):
    """class for ST7789  240*240 1.3inch OLED displays."""

    def __init__(self):
        self.width = 240
        self.height = 240
        # Keep SPI transfers within conservative per-message kernel limits.
        self.CHUNK_SIZE = 4096

        hardware_config = Settings.get_platform_default_hardware_config()
        pin_mapping = get_hardware_pin_mapping(hardware_config)["display"]

        self._dc = GPIO(*pin_mapping["dc"], "out")
        self._rst = GPIO(*pin_mapping["rst"], "out")
        self._bl = GPIO(*pin_mapping["bl"], "out")
        self._bl.write(True)

        # Initialize SPI
        spi_bus = f"/dev/spidev{pin_mapping['spi_bus']}.{pin_mapping['spi_device']}"
        spi_mode = 0
        spi_hz = 40_000_000

        # SPI_NO_CS (0x40): tell the kernel not to assert/deassert any chip-select
        # GPIO.  Use this when LCD CS is tied permanently to GND and the SBC's
        # CE pin is not wired to the LCD at all.
        spi_extra_flags = 0
        if pin_mapping.get("cs") == "disabled":
            spi_extra_flags = 0x40  # SPI_NO_CS
            logger.info(
                "SPI CS mode: SPI_NO_CS (0x40) — kernel will not manage any CE GPIO; "
                "LCD CS pin must be tied to GND."
            )
        else:
            # The kernel will drive the CE GPIO (e.g. CE0/GPIO8 for spi_device=0)
            # low before each transfer and high afterwards.  This is a pure GPIO
            # output with no electrical feedback.
            #
            # Whether the LCD receives SPI data depends entirely on its CS pin:
            #  * LCD CS tied to GND  → CS always asserted; LCD receives every byte
            #    regardless of whether CE is wired.  The display works fine even
            #    if the CE pin is not connected to the LCD at all.
            #  * LCD CS wired to CE  → LCD selected only while CE is driven low;
            #    normal kernel-managed chip-select behaviour.
            #  * LCD CS floating     → CS never reliably asserted; LCD ignores every
            #    SPI byte.  Transfers succeed in software with no error raised, but
            #    the display stays blank.  Use '"cs": "disabled"' and tie LCD CS to
            #    GND to fix this.
            spi_device = pin_mapping.get("spi_device", 0)
            logger.warning(
                "SPI CS mode: kernel-managed CE%d GPIO — the display will work "
                "correctly only if LCD CS is asserted (either wired to CE%d or "
                "tied directly to GND). If LCD CS is floating, SPI transfers "
                "silently succeed but the display will not respond. "
                "Set '\"cs\": \"disabled\"' in the display config and tie LCD CS "
                "to GND to make the configuration explicit and eliminate CE pin "
                "dependency.",
                spi_device,
                spi_device,
            )

        logger.info("Initializing SPI: bus=%s at %.1f MHz", spi_bus, spi_hz / 1_000_000)
        self._spi = SPI(spi_bus, spi_mode, spi_hz, extra_flags=spi_extra_flags)

        # Defer the LCD register initialisation sequence to the first draw call
        # (_ensure_initialized, called by show_image / clear / invert).  This
        # keeps __init__ free of SPI traffic so that the caller has a window to
        # complete any hardware setup (e.g. confirming LCD CS is asserted) before
        # the first byte is clocked out.
        self._display_initialized = False

    def _chunked_transfer(self, data):
        """Transfer data in chunks to prevent buffer overflows"""
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
                # Some kernels/drivers enforce smaller SPI message sizes.
                if getattr(e, "errno", None) == errno.EMSGSIZE and chunk_size > 256:
                    chunk_size = max(256, chunk_size // 2)
                    self.CHUNK_SIZE = chunk_size
                    logger.warning(
                        "SPI message too long; reducing chunk size to %d bytes",
                        chunk_size,
                    )
                    continue
                raise

    def _ensure_initialized(self):
        """Run the display register initialization sequence on first use.

        Deferring init() until the first draw call means that CS can be tied to
        GND at any point between the SPI bus being opened and the first frame
        being rendered — the LCD will still receive the full configuration
        sequence.
        """
        if not self._display_initialized:
            self.init()
            self._display_initialized = True

    """    Write register address and data     """
    def command(self, cmd):
        """Write register address"""
        self._dc.write(False)
        self._spi.transfer([cmd])

    def data(self, val):
        """Write data"""
        self._dc.write(True)
        self._spi.transfer([val])

    def init(self):
        """Initialize dispaly"""    
        self.reset()

        self.command(0x36)
        self.data(0x70)                 #self.data(0x00)

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
        
        self.command(0x21)  # inversion ON; 0x20 = inversion OFF

        self.command(0x11)

        self.command(0x29)

    def reset(self):
        """Reset the display"""
        self._rst.write(True)
        time.sleep(0.01)
        self._rst.write(False)
        time.sleep(0.01)
        self._rst.write(True)
        time.sleep(0.01)
        
    def SetWindows(self, Xstart, Ystart, Xend, Yend):
        #set the X coordinates
        self.command(0x2A)
        self.data(0x00)               #Set the horizontal starting point to the high octet
        self.data(Xstart & 0xff)      #Set the horizontal starting point to the low octet
        self.data(0x00)               #Set the horizontal end to the high octet
        self.data((Xend - 1) & 0xff) #Set the horizontal end to the low octet 
        
        #set the Y coordinates
        self.command(0x2B)
        self.data(0x00)
        self.data((Ystart & 0xff))
        self.data(0x00)
        self.data((Yend - 1) & 0xff )

        self.command(0x2C)    
    
    def show_image(self,Image,Xstart,Ystart):
        """Set buffer to value of Python Imaging Library image."""
        """Write display buffer to physical display"""
        self._ensure_initialized()
        imwidth, imheight = Image.size
        if imwidth != self.width or imheight != self.height:
            raise ValueError('Image must be same dimensions as display \
                ({0}x{1}).' .format(self.width, self.height))
        # convert 24-bit RGB-8:8:8 to gBRG-3:5:5:3; then per-pixel byteswap to 16-bit RGB-5:6:5
        arr = array.array("H", Image.convert("BGR;16").tobytes())
        arr.byteswap()
        pix = arr.tobytes()
        self.SetWindows ( 0, 0, self.width, self.height)
        self._dc.write(True)
        self._chunked_transfer(pix)
        
    def clear(self):
        """Clear contents of image buffer"""
        self._ensure_initialized()
        _buffer = [0xff]*(self.width * self.height * 2)
        self.SetWindows ( 0, 0, self.width, self.height)
        self._dc.write(True)
        self._chunked_transfer(_buffer)

    def invert(self, enabled: bool = True):
        """Invert how the display interprets colors"""
        self._ensure_initialized()
        self.command(0x21 if enabled else 0x20)

    def __del__(self):
        """Cleanup when object is destroyed"""
        self.close()

    def close(self):
        for attr_name in ["_dc", "_rst", "_bl", "_spi"]:
            resource = getattr(self, attr_name, None)
            if resource is None:
                continue
            try:
                resource.close()
            except Exception:
                pass
            setattr(self, attr_name, None)
