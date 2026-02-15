# Luckfox Pico Desktop Mode Fix

## Problem Statement

When running SeedSigner on a Luckfox Pico, the system was attempting to use desktop mode (requiring pygame) instead of using the hardware display drivers. This caused the application to fail because pygame is not installed on the Luckfox Pico.

## Root Cause

The Luckfox Pico is a small embedded Linux device similar to Raspberry Pi, but it uses a different GPIO system:
- **Raspberry Pi**: Uses `RPi.GPIO` library
- **Luckfox Pico**: Uses `gpiod` (character device GPIO) accessed via `/dev/gpiochip*`

The original code had this logic in `src/seedsigner/models/settings.py`:

```python
if USING_MOCK_GPIO:
    settings._data[SettingsConstants.SETTING__DISPLAY_CONFIGURATION] = (
        SettingsConstants.DISPLAY_CONFIGURATION__DESKTOP__240x240
    )
```

This assumed: **"No RPi.GPIO = Desktop mode"**

However, this is incorrect for platforms like Luckfox Pico which:
- Don't have RPi.GPIO (so `USING_MOCK_GPIO = True`)
- Are still hardware devices with real displays (st7789, ili9341, etc.)
- Should NOT use desktop/pygame mode

## Solution

Changed the logic to only force desktop mode when running on **actual desktop systems**:

```python
if USING_MOCK_GPIO:
    from seedsigner.hardware.microsd import MicroSD
    if MicroSD.is_desktop_mode():
        settings._data[SettingsConstants.SETTING__DISPLAY_CONFIGURATION] = (
            SettingsConstants.DISPLAY_CONFIGURATION__DESKTOP__240x240
        )
```

Now desktop mode is forced only when **both** conditions are true:
1. `USING_MOCK_GPIO = True` (no RPi.GPIO available)
2. `MicroSD.is_desktop_mode() = True` (not on hardware platform)

### Platform Detection

`MicroSD.is_desktop_mode()` returns `False` when:
- Hostname is `seedsigner-os` (official SeedSignerOS), OR
- `/home/pi` directory exists (Raspberry Pi or Luckfox Pico development boards)

This allows Luckfox Pico (which typically has `/home/pi`) to use its configured hardware display from `settings.luckfox.json`.

## Impact

### Before Fix
| Platform | RPi.GPIO | Display Mode | Result |
|----------|----------|--------------|---------|
| Luckfox Pico | ❌ No | Desktop (forced) | ❌ **FAILS** - pygame not installed |
| Desktop PC | ❌ No | Desktop (forced) | ✅ OK |
| Raspberry Pi | ✅ Yes | Hardware | ✅ OK |
| SeedSignerOS | ✅ Yes | Hardware | ✅ OK |

### After Fix
| Platform | RPi.GPIO | Display Mode | Result |
|----------|----------|--------------|---------|
| Luckfox Pico | ❌ No | **Hardware** (from settings) | ✅ **FIXED** |
| Desktop PC | ❌ No | Desktop (forced) | ✅ OK |
| Raspberry Pi | ✅ Yes | Hardware | ✅ OK |
| SeedSignerOS | ✅ Yes | Hardware | ✅ OK |

## Files Changed

1. **src/seedsigner/models/settings.py**
   - Added `MicroSD.is_desktop_mode()` check before forcing desktop display
   - Added explanatory comments

2. **tests/test_luckfox_display_mode.py** (new)
   - Comprehensive test suite with 4 tests
   - Tests all platform scenarios

3. **tests/verify_luckfox_fix.py** (new)
   - Manual verification script
   - Demonstrates correct behavior for all platforms

## Testing

All tests pass:
```
✅ 4/4 Luckfox display mode tests
✅ 9/9 pygame graceful absence tests (no regressions)
✅ Verification script (4/4 scenarios)
✅ Security scan: 0 alerts
```

## Configuration Files

The default `settings.json` and Luckfox-specific `settings.luckfox.json` both specify:
```json
{
  "display_config": "st7789_240x240",
  "hardware_config": "FOX_22"
}
```

With this fix, these settings are now properly used on Luckfox Pico instead of being overridden to desktop mode.

## Related Issues

This fix also ensures that any other hardware platform that:
- Uses alternative GPIO libraries (not RPi.GPIO)
- Has `/home/pi` directory or runs SeedSignerOS
- Uses hardware displays

...will correctly use their configured display instead of being forced to desktop mode.
