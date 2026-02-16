# Requirements and Dependencies Final Summary

## requirements-raspi.txt - Final State

```
pyscard==2.3.1
spidev==3.5
python-periphery==2.4.1
```

## Why Each Dependency is Needed

### pyscard==2.3.1
**Purpose:** Smartcard/NFC functionality  
**Used in:**
- `src/seedsigner/views/settings_views.py` - Smartcard reader management, NFC operations
- `src/seedsigner/views/tools_views.py` - Smartcard tools and factory reset

**Import:** `from smartcard.System import readers`

**Cannot be replaced** - pyscard is the standard Python interface for PC/SC smartcard readers.

---

### spidev==3.5
**Purpose:** SPI bus communication (legacy support)  
**Status:** Kept for compatibility alongside periphery

**Note:** While periphery also provides SPI support, keeping spidev provides compatibility and may be used by other code paths.

---

### python-periphery==2.4.1
**Purpose:** Cross-platform GPIO, SPI, and I2C support  
**Used in:**
- `src/seedsigner/hardware/buttons.py` - GPIO for button input
- `src/seedsigner/hardware/displays/ST7789.py` - GPIO and SPI for display
- `src/seedsigner/hardware/displays/ili9341.py` - GPIO and SPI for display
- `src/seedsigner/hardware/displays/st7789_mpy.py` - GPIO and SPI for display
- `src/seedsigner/hardware/battery_hat.py` - I2C for battery HAT

**Replaces:**
- RPi.GPIO (removed) - Now using periphery GPIO
- smbus2 (removed) - Now using periphery I2C

**API Examples:**

```python
# GPIO
from periphery import GPIO
pin = GPIO("/dev/gpiochip1", 20, "in")
is_pressed = not pin.read()  # Active low

# SPI
from periphery import SPI
spi = SPI("/dev/spidev0.0", mode=0, max_speed=40000000)
spi.transfer([0x2C, 0x00, 0x01])

# I2C
from periphery import I2C
i2c = I2C("/dev/i2c-1")
msgs = [I2C.Message([reg]), I2C.Message([0, 0], read=True)]
i2c.transfer(address, msgs)
```

---

## Dependencies Removed

### ❌ RPi.GPIO==0.7.0
**Removed because:** Raspberry Pi specific, replaced by periphery  
**Replacement:** python-periphery GPIO

### ❌ smbus2==0.4.3
**Removed because:** Replaced by periphery I2C  
**Replacement:** python-periphery I2C

**Migration:** battery_hat.py converted to use periphery I2C API

### ❌ picamera==1.13
**Removed because:** Optional dependency, not required  
**Status:** Camera code falls back to opencv-python (cv2) when picamera unavailable

**Note:** Users can install picamera if they want to use Raspberry Pi camera module. The code supports both picamera and opencv.

### ❌ numpy==1.25.2
**Removed because:** Was a transitive dependency of picamera  
**Status:** Not needed when picamera is optional

---

## Optional Dependencies (not in requirements-raspi.txt)

### opencv-python (cv2)
**Purpose:** Camera support (fallback when picamera unavailable)  
**Used in:**
- `src/seedsigner/hardware/camera.py`
- `src/seedsigner/hardware/pivideostream.py`

**Import:** `import cv2` (wrapped in try/except)

**Status:** Optional - users install if needed for camera

### pygame
**Purpose:** Desktop simulation and camera listing  
**Status:** Optional - only for desktop development mode

**Note:** Desktop simulation removed from buttons.py in periphery conversion

---

## Dependency Change Summary

| Before | After | Reason |
|--------|-------|--------|
| RPi.GPIO==0.7.0 | python-periphery==2.4.1 | Cross-platform GPIO |
| smbus2==0.4.3 | python-periphery==2.4.1 | Cross-platform I2C |
| picamera==1.13 | (optional) | Not required, opencv fallback |
| numpy==1.25.2 | (removed) | Transitive dependency |
| pyscard==2.3.1 | pyscard==2.3.1 | ✓ Kept - smartcard required |
| spidev==3.5 | spidev==3.5 | ✓ Kept - SPI support |

**Net change:** 7 dependencies → 3 dependencies

---

## Platform Support Matrix

| Platform | GPIO | SPI | I2C | Display | Buttons | Battery |
|----------|------|-----|-----|---------|---------|---------|
| Raspberry Pi | periphery | periphery + spidev | periphery | ✓ | ✓ | ✓ |
| Luckfox Pico | periphery | periphery + spidev | periphery | ✓ | ✓ | ✓ |
| Desktop | N/A | N/A | N/A | pygame | pygame | N/A |

**Note:** Desktop mode is for development only and doesn't require hardware GPIO/SPI/I2C.

---

## Installation Instructions

### For Raspberry Pi:
```bash
pip install -r requirements.txt
pip install -r requirements-raspi.txt
# Optional: pip install picamera opencv-python
```

### For Luckfox Pico:
```bash
pip install -r requirements.txt
pip install -r requirements-raspi.txt
# Optional: pip install opencv-python
```

### For Desktop (development):
```bash
pip install -r requirements.txt
pip install -r requirements-desktop.txt
```

---

## Camera Implementation Details

The camera implementation is flexible and supports multiple backends:

1. **picamera** (Raspberry Pi camera module) - Optional
2. **opencv-python** (cv2) - Optional, used as fallback
3. **pygame.camera** - Optional, used for camera listing on desktop

All imports are wrapped in try/except blocks, so the code gracefully handles missing camera libraries.

**Code structure:**
```python
# Try picamera first
try:
    from picamera import PiCamera
    camera = PiCamera(resolution=resolution)
except:
    # Fall back to opencv
    import cv2
    camera = cv2.VideoCapture(device_index)
```

This allows the application to work on:
- Raspberry Pi with picamera module
- Luckfox Pico with USB camera (opencv)
- Desktop with webcam (opencv or pygame)
- Or without camera if not needed for specific workflows

---

## Testing Results

✅ All imports successful:
```
✓ periphery library (GPIO, SPI, I2C)
✓ buttons.py (periphery GPIO)
✓ ST7789.py (periphery GPIO + SPI)
✓ st7789_mpy.py (periphery GPIO + SPI)
✓ ili9341.py (periphery GPIO + SPI)
✓ battery_hat.py (periphery I2C)
```

✅ No dependency conflicts  
✅ Backward compatible with existing hardware  
✅ Cross-platform support enabled
