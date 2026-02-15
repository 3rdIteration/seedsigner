"""Platform detection for SeedSigner.

This module provides centralized platform detection to identify the hardware
platform (Desktop, Raspberry Pi, Luckfox Pico, etc.) and automatically configure
appropriate GPIO and display settings.
"""

import logging
import os
import platform
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class PlatformType(Enum):
    """Enumeration of supported platform types."""
    DESKTOP = "desktop"
    RASPBERRY_PI = "raspberry_pi"
    LUCKFOX_PICO = "luckfox_pico"
    UNKNOWN = "unknown"


@dataclass
class PlatformInfo:
    """Information about the detected platform."""
    platform_type: PlatformType
    model: str
    variant: Optional[str] = None  # e.g., "40-pin", "22-pin", "Windows", "macOS"
    os_name: Optional[str] = None
    hardware_config: Optional[str] = None  # Suggested hardware config ID
    display_config: Optional[str] = None   # Suggested display config ID
    
    def get_display_name(self) -> str:
        """Get a human-readable platform name for display."""
        if self.platform_type == PlatformType.DESKTOP:
            if self.variant:
                return f"Desktop ({self.variant})"
            return "Desktop"
        elif self.platform_type == PlatformType.RASPBERRY_PI:
            return self.model
        elif self.platform_type == PlatformType.LUCKFOX_PICO:
            if self.variant:
                return f"Luckfox Pico ({self.variant})"
            return "Luckfox Pico"
        else:
            return self.model or "Unknown Platform"


class PlatformDetector:
    """Detects the current hardware platform and provides configuration."""
    
    _cached_info: Optional[PlatformInfo] = None
    
    @classmethod
    def detect(cls, force_refresh: bool = False) -> PlatformInfo:
        """Detect the current platform.
        
        Args:
            force_refresh: If True, bypass cache and re-detect platform
            
        Returns:
            PlatformInfo object with detected platform details
        """
        if cls._cached_info is not None and not force_refresh:
            return cls._cached_info
        
        info = cls._perform_detection()
        cls._cached_info = info
        logger.info(f"Detected platform: {info.platform_type.value} - {info.get_display_name()}")
        return info
    
    @classmethod
    def _perform_detection(cls) -> PlatformInfo:
        """Perform actual platform detection."""
        # Check for Luckfox Pico first (most specific)
        luckfox_info = cls._detect_luckfox_pico()
        if luckfox_info:
            return luckfox_info
        
        # Check for Raspberry Pi
        pi_info = cls._detect_raspberry_pi()
        if pi_info:
            return pi_info
        
        # Default to desktop
        return cls._detect_desktop()
    
    @classmethod
    def _detect_luckfox_pico(cls) -> Optional[PlatformInfo]:
        """Detect Luckfox Pico platform and variant."""
        model = cls._read_file("/proc/device-tree/model")
        
        # Check for Luckfox in model string
        if model and "luckfox" in model.lower():
            variant = None
            hardware_config = None
            display_config = "st7789_240x240"  # Default display
            
            # Try to detect variant based on model string or GPIO chips
            if "pico mini" in model.lower():
                variant = "22-pin"
                hardware_config = "FOX_22"
            elif "pico pro" in model.lower() or "pico plus" in model.lower():
                variant = "40-pin"
                hardware_config = "FOX_40"
            else:
                # Auto-detect based on available GPIO chips
                if os.path.exists("/dev/gpiochip2"):
                    variant = "40-pin"
                    hardware_config = "FOX_40"
                elif os.path.exists("/dev/gpiochip1"):
                    variant = "22-pin"
                    hardware_config = "FOX_22"
            
            return PlatformInfo(
                platform_type=PlatformType.LUCKFOX_PICO,
                model=model.strip(),
                variant=variant,
                os_name="Linux",
                hardware_config=hardware_config,
                display_config=display_config,
            )
        
        # Check for /home/pi with gpiochip1 (alternative detection)
        if os.path.exists("/home/pi") and os.path.exists("/dev/gpiochip1"):
            # Might be Luckfox even without device-tree/model
            cpuinfo = cls._read_file("/proc/cpuinfo")
            if cpuinfo and ("rockchip" in cpuinfo.lower() or "rk" in cpuinfo.lower()):
                variant = "40-pin" if os.path.exists("/dev/gpiochip2") else "22-pin"
                hardware_config = "FOX_40" if variant == "40-pin" else "FOX_22"
                
                return PlatformInfo(
                    platform_type=PlatformType.LUCKFOX_PICO,
                    model="Luckfox Pico (auto-detected)",
                    variant=variant,
                    os_name="Linux",
                    hardware_config=hardware_config,
                    display_config="st7789_240x240",
                )
        
        return None
    
    @classmethod
    def _detect_raspberry_pi(cls) -> Optional[PlatformInfo]:
        """Detect Raspberry Pi platform and model."""
        model = cls._read_file("/proc/device-tree/model")
        
        # Check device-tree/model first
        if model and "raspberry pi" in model.lower():
            variant = None
            hardware_config = None
            
            # Detect pin count (40-pin for Pi 2 and newer, 26-pin for older)
            try:
                # Import at runtime to avoid issues when RPi.GPIO isn't available
                import RPi.GPIO as GPIO
                if hasattr(GPIO, 'RPI_INFO') and 'P1_REVISION' in GPIO.RPI_INFO:
                    if GPIO.RPI_INFO['P1_REVISION'] == 3:
                        variant = "40-pin"
                        hardware_config = "RPI_40"
                    else:
                        variant = "26-pin"
                        hardware_config = "RPI_26"
                else:
                    # Default to 40-pin if we can't determine
                    variant = "40-pin"
                    hardware_config = "RPI_40"
            except (ImportError, AttributeError, Exception):
                # Default to 40-pin for modern Pi models when RPi.GPIO not available
                variant = "40-pin"
                hardware_config = "RPI_40"
            
            return PlatformInfo(
                platform_type=PlatformType.RASPBERRY_PI,
                model=model.strip(),
                variant=variant,
                os_name="Linux",
                hardware_config=hardware_config,
                display_config="st7789_240x240",
            )
        
        # Fallback: check /proc/cpuinfo for older Pi systems
        cpuinfo = cls._read_file("/proc/cpuinfo")
        if cpuinfo:
            for line in cpuinfo.split('\n'):
                if line.startswith("Model"):
                    model_str = line.split(":", 1)[-1].strip()
                    if "raspberry pi" in model_str.lower():
                        return PlatformInfo(
                            platform_type=PlatformType.RASPBERRY_PI,
                            model=model_str,
                            variant="40-pin",
                            os_name="Linux",
                            hardware_config="RPI_40",
                            display_config="st7789_240x240",
                        )
        
        return None
    
    @classmethod
    def _detect_desktop(cls) -> PlatformInfo:
        """Detect desktop platform (Windows, macOS, Linux)."""
        system = platform.system()
        
        if system == "Windows":
            variant = f"Windows {platform.release()}"
        elif system == "Darwin":
            variant = f"macOS {platform.mac_ver()[0]}"
        elif system == "Linux":
            # Try to get distribution info
            try:
                import distro
                variant = f"{distro.name()} {distro.version()}"
            except (ImportError, Exception):
                # Fall back to just "Linux" if distro detection fails
                variant = "Linux"
        else:
            variant = system
        
        return PlatformInfo(
            platform_type=PlatformType.DESKTOP,
            model=f"{platform.machine()} {platform.processor()}".strip(),
            variant=variant,
            os_name=system,
            hardware_config=None,  # No hardware GPIO on desktop
            display_config="desktop_240x240",
        )
    
    @classmethod
    def _read_file(cls, filepath: str) -> Optional[str]:
        """Read a file and return its contents, or None if not available."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return None
    
    @classmethod
    def is_hardware_platform(cls) -> bool:
        """Check if running on actual hardware (not desktop)."""
        info = cls.detect()
        return info.platform_type in [PlatformType.RASPBERRY_PI, PlatformType.LUCKFOX_PICO]
    
    @classmethod
    def get_hostname_check(cls) -> str:
        """Get hostname for legacy compatibility checks."""
        return platform.uname()[1]
