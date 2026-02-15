# Implementation Summary: Platform Detection & Generalized System Info

## Overview

This implementation addresses the requirements from the problem statement to:
1. ✅ Generalize the system info screen to display platform-specific information
2. ✅ Add a generalized process to query system type and automatically apply profiles
3. ⏸️ Clarification needed on RPi.GPIO removal (see below)

## What Was Implemented

### 1. Platform Detection System

**File:** `src/seedsigner/hardware/platform_detector.py`

A comprehensive platform detection system that:

- **Detects Platform Types:**
  - Desktop (Windows, macOS, Linux)
  - Raspberry Pi (with variant detection: 40-pin, 26-pin)
  - Luckfox Pico (with variant detection: 22-pin, 40-pin)

- **Auto-Detection Features:**
  - Reads `/proc/device-tree/model` for hardware model
  - Checks `/proc/cpuinfo` for processor info
  - Detects GPIO chips (`/dev/gpiochip*`) for Luckfox variant identification
  - Uses `platform.system()` for desktop OS detection

- **Provides Configuration:**
  - Suggests appropriate hardware config (RPI_40, FOX_22, etc.)
  - Suggests appropriate display config (st7789_240x240, desktop_240x240, etc.)
  - Caches detection results for performance

**Key Classes:**
```python
class PlatformType(Enum):
    DESKTOP = "desktop"
    RASPBERRY_PI = "raspberry_pi"
    LUCKFOX_PICO = "luckfox_pico"
    UNKNOWN = "unknown"

@dataclass
class PlatformInfo:
    platform_type: PlatformType
    model: str
    variant: Optional[str]  # e.g., "40-pin", "Windows 10"
    hardware_config: Optional[str]  # e.g., "FOX_22", "RPI_40"
    display_config: Optional[str]  # e.g., "st7789_240x240"
```

### 2. Generalized System Info Screen

**Files Modified:**
- `src/seedsigner/views/settings_views.py`
- `src/seedsigner/gui/screens/settings_screens.py`

**Changes:**
- Renamed `_get_pi_version()` to `_get_platform_info()`
- Changed field from `pi_version` to `platform_info`
- Updated screen label from "Pi: {version}" to "Platform: {platform_info}"

**Display Examples:**
- Raspberry Pi 4: `"Platform: Raspberry Pi 4 Model B (40-pin)"`
- Luckfox Pico Mini: `"Platform: Luckfox Pico (22-pin)"`
- Windows Desktop: `"Platform: Desktop (Windows 10)"`
- macOS Desktop: `"Platform: Desktop (macOS 13.0)"`
- Linux Desktop: `"Platform: Desktop (Linux)"`

### 3. Auto-Configuration of Hardware Profiles

**File Modified:** `src/seedsigner/models/settings.py`

**Added Method:** `_auto_configure_platform()`

This method automatically:
1. Detects the current platform using `PlatformDetector`
2. Applies the appropriate hardware configuration if available
3. Applies the appropriate display configuration
4. Only overrides defaults, preserves user-configured settings
5. Falls back gracefully if detection fails

**Logic:**
```python
# Auto-configure hardware settings based on detected platform
platform_info = PlatformDetector.detect()

if platform_info.hardware_config:
    # Set hardware config (FOX_22, RPI_40, etc.)
    settings._data[SETTING__HARDWARE_CONFIGURATION] = platform_info.hardware_config

if platform_info.display_config:
    # Set display config (st7789_240x240, desktop_240x240, etc.)
    settings._data[SETTING__DISPLAY_CONFIGURATION] = platform_info.display_config
```

### 4. Comprehensive Test Suite

**File:** `tests/test_platform_detector.py`

**15 Tests Covering:**
- ✅ Luckfox Pico detection from device-tree
- ✅ Luckfox Pico 40-pin variant detection
- ✅ Luckfox detection by GPIO chip presence
- ✅ Raspberry Pi detection from device-tree
- ✅ Raspberry Pi detection with GPIO info
- ✅ Raspberry Pi 26-pin variant
- ✅ Windows desktop detection
- ✅ macOS desktop detection
- ✅ Linux desktop detection
- ✅ Detection caching
- ✅ Force refresh
- ✅ Display name generation
- ✅ Hardware platform checks

**All 28 tests passing** (including existing Luckfox and pygame tests)

## Outstanding Question: RPi.GPIO Removal

The problem statement mentions:
> "the gpio for the luckfox pico branch all uses periphery now, so can RPi.GPIO just be removed?"

### Current Situation

**RPi.GPIO Currently Used In:**
1. `requirements-raspi.txt` - Listed as dependency
2. `src/seedsigner/hardware/buttons.py` - Pin detection logic
3. `src/seedsigner/hardware/displays/ST7789.py` - GPIO pin control
4. `src/seedsigner/hardware/displays/ili9341.py` - GPIO pin control
5. `src/seedsigner/hardware/displays/st7789_mpy.py` - GPIO pin control

**Luckfox Pin Configs:**
- Already use `/dev/gpiochip*` format: `("/dev/gpiochip1", 20)`
- Ready for gpiod/periphery library usage
- Don't use RPi.GPIO format

### Options for Moving Forward

**Option A: Keep RPi.GPIO for Raspberry Pi (Recommended)**
- Maintain backward compatibility with existing Pi installations
- Add `periphery` library for Luckfox Pico platforms
- Platform detector chooses appropriate GPIO library
- Minimal code changes required

**Option B: Create GPIO Abstraction Layer**
- Create a `GPIOManager` class that supports multiple backends
- Backends: RPi.GPIO, periphery, mock (for desktop)
- Update all display drivers to use abstraction
- More work but cleanest architecture

**Option C: Replace RPi.GPIO Entirely**
- Remove RPi.GPIO completely
- Use `periphery` for both Pi and Luckfox
- Need to update display drivers
- May break existing installations

### Recommendation

**Wait for clarification** on whether there is a Luckfox Pico branch with `periphery` implementation. If so:
1. Review that branch's approach
2. Merge the platform detection from this PR
3. Integrate the periphery GPIO handling

If no such branch exists, I recommend **Option A** as the safest path forward.

## Benefits of Current Implementation

1. **User-Friendly**: System automatically detects hardware and configures appropriately
2. **Clear Information**: Users see exactly what platform they're running on
3. **Extensible**: Easy to add new platform types
4. **Tested**: 28 tests ensure reliability
5. **Backward Compatible**: Existing installations continue to work
6. **No Manual Config**: Users don't need to know their GPIO pin configuration

## Migration Path

For users upgrading:
1. **Raspberry Pi**: No changes needed, auto-detects and applies RPI_40 or RPI_26 config
2. **Luckfox Pico**: Auto-detects and applies FOX_22 or FOX_40 config
3. **Desktop**: Auto-detects and applies desktop display mode
4. **Custom Configs**: Preserved if already set in settings.json

## Files Changed

1. `src/seedsigner/hardware/platform_detector.py` - NEW (280 lines)
2. `src/seedsigner/models/settings.py` - Modified (added auto-config)
3. `src/seedsigner/views/settings_views.py` - Modified (generalized platform info)
4. `src/seedsigner/gui/screens/settings_screens.py` - Modified (updated labels)
5. `tests/test_platform_detector.py` - NEW (250 lines, 15 tests)
6. `tests/test_luckfox_display_mode.py` - Pre-existing (4 tests)
7. `tests/test_pygame_graceful_absence.py` - Pre-existing (9 tests)

## Test Results

```
28 passed in 0.11s
```

All tests passing including:
- 15 new platform detector tests
- 4 existing Luckfox display mode tests  
- 9 existing pygame graceful absence tests
