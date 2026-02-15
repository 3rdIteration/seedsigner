# Periphery Library Integration Summary

## Overview

Successfully integrated the `python-periphery` library to replace RPi.GPIO, enabling cross-platform GPIO support for Raspberry Pi, Luckfox Pico, and other platforms using Linux gpiod character devices.

## Changes Made

### Requirements (requirements-raspi.txt)

**Removed:**
- `RPi.GPIO==0.7.0` - Replaced by python-periphery
- `picamera==1.13` - Camera handling changed
- `numpy==1.25.2` - No longer needed
- `pyscard==2.3.1` - Removed
- `smbus2==0.4.3` - Removed

**Added:**
- `python-periphery==2.4.1` - Cross-platform GPIO library

**Kept:**
- `spidev==3.5` - Still needed alongside periphery

### Hardware Buttons (buttons.py)

**Before:** 463 lines with RPi.GPIO + pygame desktop simulation  
**After:** 197 lines with periphery only

**Key Changes:**
- Import: `from periphery import GPIO`
- Button initialization from Settings hardware config
- Read with `GPIO.read()` - returns False when button pressed (active low)
- Removed all desktop/pygame simulation code
- Removed RPi.GPIO 40-pin/26-pin detection logic
- Added `__del__` method for cleanup

**Usage:**
```python
# Initialize from hardware config
hardware_config = Settings.get_instance().get_value(SETTING__HARDWARE_CONFIG)
pin_mapping = ALL_HARDWARE_PIN_CONFIGS[hardware_config]["buttons"]

# Create GPIO object for each button
gpio_pin = GPIO("/dev/gpiochip1", 20, "in")

# Read state (False = pressed, True = released)
is_pressed = not gpio_pin.read()
```

### Display Drivers

**Updated Files:**
- ST7789.py
- ili9341.py
- st7789_mpy.py

**Key Changes:**
- Import: `from periphery import GPIO, SPI`
- GPIO pins initialized from hardware config settings
- SPI initialized with: `SPI("/dev/spidev0.0", mode, speed)`
- Added chunked SPI transfers to prevent buffer overflows
- Chunk size: 4096 * 12 bytes (49,152 bytes)
- Added `__del__` methods for cleanup

**Before:**
```python
import RPi.GPIO as GPIO
import spidev

GPIO.setmode(GPIO.BOARD)
GPIO.setup(dc, GPIO.OUT)
spi = spidev.SpiDev(0, 0)
```

**After:**
```python
from periphery import GPIO, SPI
from seedsigner.models.settings import Settings

pin_mapping = Settings.get_instance().get_hardware_pin_config()["display"]
dc_pin = GPIO(*pin_mapping["dc"], "out")
spi = SPI(f"/dev/spidev{pin_mapping['spi_bus']}.{pin_mapping['spi_device']}", 0, 40000000)
```

## Hardware Configuration

The platform detector automatically selects the correct hardware configuration:

| Platform | Hardware Config | GPIO Chip | SPI Device |
|----------|----------------|-----------|------------|
| Raspberry Pi 40-pin | RPI_40 | /dev/gpiochip0 | /dev/spidev0.0 |
| Raspberry Pi 26-pin | RPI_26 | /dev/gpiochip0 | /dev/spidev0.0 |
| Luckfox Pico 22-pin | FOX_22 | /dev/gpiochip1 | /dev/spidev0.0 |
| Luckfox Pico 40-pin | FOX_40 | /dev/gpiochip1 + gpiochip2 | /dev/spidev0.0 |

## Benefits

1. **Cross-Platform:** Works on Raspberry Pi, Luckfox Pico, and any platform with gpiod
2. **Cleaner Code:** Removed 266 lines of desktop simulation code
3. **No RPi.GPIO Dependency:** Eliminates Raspberry Pi-specific library
4. **Automatic Configuration:** Platform detector selects correct pins
5. **Proper Cleanup:** Resources freed with `__del__` methods
6. **Buffer Safety:** Chunked transfers prevent SPI buffer overflows

## Testing

✅ **Import Tests Pass:**
- periphery library (v2.4.1)
- buttons.py module
- ST7789.py display driver
- st7789_mpy.py display driver
- ili9341.py display driver (requires PIL)

⏸️ **Hardware Tests Needed:**
- Button press/release detection on actual hardware
- Display initialization and rendering
- SPI transfer stability
- GPIO cleanup on exit

## Attribution

Changes based on commits by **Sam Korn (kornpow)** from lightningspore/seedsigner upstream-luckfox-staging-1:

- `3a46967` - update python requirements
- `577fb19` - use periphery for button gpio
- `cd99d1a` - use periphery for the display

## Migration Notes

For users upgrading:

1. **Raspberry Pi:** Install python-periphery instead of RPi.GPIO
   ```bash
   pip install python-periphery==2.4.1
   ```

2. **Luckfox Pico:** Install python-periphery and spidev
   ```bash
   pip install python-periphery==2.4.1 spidev==3.5
   ```

3. **Platform Detection:** Settings will auto-configure hardware pins
4. **No Desktop Mode:** Desktop simulation removed (was pygame-based)

## Files Modified

1. `requirements-raspi.txt` - Updated dependencies
2. `src/seedsigner/hardware/buttons.py` - Periphery GPIO
3. `src/seedsigner/hardware/displays/ST7789.py` - Periphery GPIO/SPI
4. `src/seedsigner/hardware/displays/ili9341.py` - Periphery GPIO/SPI
5. `src/seedsigner/hardware/displays/st7789_mpy.py` - Periphery GPIO/SPI

## Lines Changed

- requirements-raspi.txt: 7 → 2 lines
- buttons.py: 463 → 197 lines (-266 lines)
- Total: -478 lines, +268 lines (net -210 lines)

## References

- python-periphery: https://github.com/vsergeev/python-periphery
- Linux gpiod: https://git.kernel.org/pub/scm/libs/libgpiod/libgpiod.git/
- kornpow's branch: https://github.com/lightningspore/seedsigner/tree/upstream-luckfox-staging-1
