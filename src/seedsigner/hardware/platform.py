"""Hardware platform and board-profile detection helpers.

The project primarily targets Raspberry Pi devices but can also run on desktop
or alternative ARM boards like the Luckfox Pico line. This module centralizes
platform/variant detection so hardware backends can adapt automatically.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

PLATFORM__RASPBERRY_PI = "raspberry_pi"
PLATFORM__LUCKFOX = "luckfox"
PLATFORM__DESKTOP = "desktop"

LUCKFOX_VARIANT__UNKNOWN = "unknown"
LUCKFOX_VARIANT__PICO_MINI = "luckfox-22"
LUCKFOX_VARIANT__PICO_MAX = "luckfox-40"


@dataclass(frozen=True)
class LuckfoxHardwareProfile:
    """Luckfox board profile used by hardware backends."""

    variant: str
    # libgpiod global GPIO numbers for button matrix
    key_up_pin: int
    key_down_pin: int
    key_left_pin: int
    key_right_pin: int
    key_press_pin: int
    key1_pin: int
    key2_pin: int
    key3_pin: int
    # libgpiod global GPIO numbers for display lines
    st7789_dc_pin: int
    st7789_rst_pin: int
    # preferred camera device candidates
    video_devices: tuple[str, ...]


# Both SeedSigner Luckfox carrier PCBs currently use the same wiring map.
# Keep profiles split so per-variant values can diverge later.
_LUCKFOX_BASE_PINS = dict(
    key_up_pin=58,
    key_down_pin=53,
    key_left_pin=59,
    key_right_pin=54,
    key_press_pin=52,
    key1_pin=55,
    key2_pin=43,
    key3_pin=42,
    st7789_dc_pin=56,
    st7789_rst_pin=57,
)


_LUCKFOX_PROFILE_PICO_MINI = LuckfoxHardwareProfile(
    variant=LUCKFOX_VARIANT__PICO_MINI,
    video_devices=("/dev/video11", "/dev/video12", "/dev/video0"),
    **_LUCKFOX_BASE_PINS,
)

_LUCKFOX_PROFILE_PICO_MAX = LuckfoxHardwareProfile(
    variant=LUCKFOX_VARIANT__PICO_MAX,
    video_devices=("/dev/video12", "/dev/video11", "/dev/video0"),
    **_LUCKFOX_BASE_PINS,
)


def _read_first_existing(paths: list[str]) -> str:
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                value = f.read().strip("\x00\n ")
                if value:
                    return value
        except OSError:
            continue
    return ""


def _device_model_blob() -> str:
    model = _read_first_existing([
        "/proc/device-tree/model",
        "/sys/firmware/devicetree/base/model",
    ])
    compatible = _read_first_existing([
        "/proc/device-tree/compatible",
        "/sys/firmware/devicetree/base/compatible",
    ])
    return f"{model}\n{compatible}".lower()


@lru_cache(maxsize=1)
def detect_platform() -> str:
    """Return one of the ``PLATFORM__*`` constants for this runtime."""
    forced = os.getenv("SEEDSIGNER_PLATFORM", "").strip().lower()
    if forced in {PLATFORM__RASPBERRY_PI, PLATFORM__LUCKFOX, PLATFORM__DESKTOP}:
        return forced

    model_blob = _device_model_blob()
    if "luckfox" in model_blob or "rv110" in model_blob:
        return PLATFORM__LUCKFOX

    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
            cpuinfo = f.read().lower()
        if "raspberry pi" in cpuinfo or "bcm27" in cpuinfo:
            return PLATFORM__RASPBERRY_PI
    except OSError:
        pass

    return PLATFORM__DESKTOP


@lru_cache(maxsize=1)
def detect_luckfox_variant() -> str:
    """Return detected Luckfox board variant when running on Luckfox."""
    forced = os.getenv("SEEDSIGNER_LUCKFOX_VARIANT", "").strip().lower()
    # Backward-compat aliases.
    if forced == "pico-mini":
        forced = LUCKFOX_VARIANT__PICO_MINI
    elif forced == "pico-max":
        forced = LUCKFOX_VARIANT__PICO_MAX

    if forced in {LUCKFOX_VARIANT__PICO_MINI, LUCKFOX_VARIANT__PICO_MAX}:
        return forced

    if detect_platform() != PLATFORM__LUCKFOX:
        return LUCKFOX_VARIANT__UNKNOWN

    model_blob = _device_model_blob()
    if "mini" in model_blob:
        return LUCKFOX_VARIANT__PICO_MINI
    if "max" in model_blob:
        return LUCKFOX_VARIANT__PICO_MAX

    # Conservative default: preserve current behavior if exact model text differs.
    return LUCKFOX_VARIANT__PICO_MAX


@lru_cache(maxsize=1)
def get_luckfox_profile() -> LuckfoxHardwareProfile:
    """Return hardware profile for the currently detected Luckfox variant."""
    variant = detect_luckfox_variant()
    if variant == LUCKFOX_VARIANT__PICO_MINI:
        return _LUCKFOX_PROFILE_PICO_MINI
    return _LUCKFOX_PROFILE_PICO_MAX


def is_luckfox() -> bool:
    return detect_platform() == PLATFORM__LUCKFOX


def is_raspberry_pi() -> bool:
    return detect_platform() == PLATFORM__RASPBERRY_PI
