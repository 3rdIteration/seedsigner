# Platform Detection & GPIO Refactoring Summary

## Completed Work

### 1. Platform Detection System ✅
Created a comprehensive platform detection system that:
- Automatically identifies Desktop (Windows/macOS/Linux), Raspberry Pi, or Luckfox Pico
- Auto-detects hardware variants (40-pin vs 26-pin Pi, 22-pin vs 40-pin Luckfox)
- Provides suggested hardware and display configurations
- Caches detection results for performance

### 2. Generalized System Info ✅
- Changed "Pi: {version}" to "Platform: {name}"
- Displays appropriate platform information:
  - "Raspberry Pi 4 Model B (40-pin)" on Pi
  - "Luckfox Pico (22-pin)" on Luckfox
  - "Desktop (Windows 10)" on Windows desktop
  - "Desktop (macOS 13.0)" on Mac
  - "Desktop (Linux)" on Linux desktop

### 3. Auto-Configuration ✅
- Settings automatically apply correct hardware profile based on detected platform
- No manual configuration needed for GPIO pins or display settings
- Falls back gracefully if detection fails

### 4. Comprehensive Testing ✅
- Added 15 unit tests covering all platform detection scenarios
- All tests passing

## Questions & Next Steps

### RPi.GPIO Removal
The problem statement mentions:
> "the gpio for the luckfox pico branch all uses periphery now, so can RPi.GPIO just be removed?"

**Current State:**
- RPi.GPIO is currently used in `requirements-raspi.txt`
- No `periphery` library found in current codebase
- Display drivers (ST7789, ILI9341) directly use RPi.GPIO for pin control
- Button detection uses RPi.GPIO to detect 40-pin vs 26-pin Pi boards

**Questions:**
1. Is there a separate Luckfox Pico branch that uses the `periphery` library?
2. Should we:
   - A) Keep RPi.GPIO for Raspberry Pi backward compatibility?
   - B) Replace RPi.GPIO with `periphery` library for all platforms?
   - C) Add `periphery` as an alternative and let platform detection choose?

**Recommendation:**
Without seeing the Luckfox branch, I recommend **Option C**: Add `periphery` as an optional dependency that the platform detector can use when available, while keeping RPi.GPIO for backward compatibility with existing Pi installations.

### Display Driver GPIO Abstraction
If RPi.GPIO should be removed, we need to:
1. Create a GPIO abstraction layer
2. Update ST7789.py, ILI9341.py, and st7789_mpy.py drivers
3. Support both RPi.GPIO and periphery (or gpiod) backends

This is a more invasive change that affects display drivers.

## Files Modified

1. `src/seedsigner/hardware/platform_detector.py` - NEW
   - PlatformDetector class with detection logic
   - PlatformInfo dataclass
   - PlatformType enum

2. `src/seedsigner/models/settings.py`
   - Added `_auto_configure_platform()` method
   - Auto-applies hardware profiles based on detected platform

3. `src/seedsigner/views/settings_views.py`
   - Renamed `_get_pi_version()` to `_get_platform_info()`
   - Uses PlatformDetector for platform information

4. `src/seedsigner/gui/screens/settings_screens.py`
   - Changed `pi_version` field to `platform_info`
   - Updated label from "Pi:" to "Platform:"

5. `tests/test_platform_detector.py` - NEW
   - 15 comprehensive unit tests

## Benefits

1. **User-Friendly**: No manual configuration needed - system auto-detects platform
2. **Extensible**: Easy to add support for new platforms
3. **Clear**: System info shows exactly what hardware is running
4. **Tested**: Comprehensive test coverage ensures reliability
5. **Backward Compatible**: Existing Pi installations continue to work
