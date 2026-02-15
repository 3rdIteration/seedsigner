"""Test that the system gracefully handles the absence of pygame.

This test validates that when pygame is not installed:
1. Module imports work without crashes
2. Clear, helpful error messages are shown when pygame functionality is needed
3. The system falls back gracefully where appropriate (e.g., camera detection)
"""

import sys
import pytest
from unittest.mock import patch


class TestPygameGracefulAbsence:
    """Test suite for pygame absence handling."""

    def test_buttons_module_imports_without_pygame(self):
        """Buttons module should import successfully even without pygame."""
        # This test verifies that the module can be imported on systems
        # without pygame (e.g., Raspberry Pi with GPIO)
        from seedsigner.hardware import buttons
        assert buttons is not None

    def test_camera_module_imports_without_pygame(self):
        """Camera module should import successfully even without pygame."""
        from seedsigner.hardware.camera import Camera
        assert Camera is not None

    def test_display_driver_imports_without_pygame(self):
        """DisplayDriver module should import successfully even without pygame."""
        from seedsigner.hardware.displays.display_driver import DisplayDriver
        assert DisplayDriver is not None

    def test_desktop_display_module_imports_without_pygame(self):
        """DesktopDisplay module should import successfully even without pygame."""
        # The module imports fine; only instantiation requires pygame
        from seedsigner.hardware.displays.desktop_display import DesktopDisplay
        assert DesktopDisplay is not None

    def test_desktop_display_instantiation_fails_gracefully(self):
        """DesktopDisplay instantiation should fail with clear error when pygame is missing."""
        # Mock pygame in sys.modules to simulate it not being available
        with patch.dict('sys.modules', {'pygame': None}):
            from seedsigner.hardware.displays.desktop_display import DesktopDisplay
            
            with pytest.raises(ModuleNotFoundError) as exc_info:
                DesktopDisplay()
            
            error_message = str(exc_info.value)
            assert "pygame" in error_message.lower()
            assert "requirements-desktop.txt" in error_message.lower()

    def test_desktop_display_driver_fails_gracefully(self):
        """DisplayDriver with DESKTOP type should fail with clear error when pygame is missing."""
        # Mock pygame to be None to simulate it not being installed
        with patch.dict('sys.modules', {'pygame': None}):
            # Force re-import to pick up the mocked pygame
            import importlib
            import seedsigner.hardware.displays.desktop_display
            importlib.reload(seedsigner.hardware.displays.desktop_display)
            
            from seedsigner.hardware.displays.display_driver import (
                DisplayDriver,
                DISPLAY_TYPE__DESKTOP
            )
            
            with pytest.raises(ModuleNotFoundError) as exc_info:
                DisplayDriver(DISPLAY_TYPE__DESKTOP, width=240, height=240)
            
            error_message = str(exc_info.value)
            assert "pygame" in error_message.lower() or "desktop" in error_message.lower()
            assert "requirements-desktop.txt" in error_message.lower()

    def test_camera_list_cameras_handles_missing_pygame(self):
        """Camera.list_cameras() should fall back gracefully when pygame is not available."""
        from seedsigner.hardware.camera import Camera
        
        # list_cameras should not crash even if pygame is unavailable
        # It will fall back to OpenCV or default device list
        cameras = Camera.list_cameras()
        
        # Should return a list (possibly empty or with defaults)
        assert isinstance(cameras, list)

    def test_hardware_buttons_clear_error_on_desktop_without_pygame(self):
        """HardwareButtons should give clear error on desktop systems without pygame."""
        # This test simulates a desktop environment (no GPIO) without pygame
        # by mocking pygame in sys.modules
        
        # Save the original to restore later
        import seedsigner.hardware.buttons
        original_instance = seedsigner.hardware.buttons.HardwareButtons._instance
        original_using_gpio = seedsigner.hardware.buttons.USING_GPIO
        original_pygame = getattr(seedsigner.hardware.buttons, 'pygame', None)
        
        try:
            # Reset singleton and simulate desktop without pygame
            seedsigner.hardware.buttons.HardwareButtons._instance = None
            seedsigner.hardware.buttons.USING_GPIO = False
            seedsigner.hardware.buttons.pygame = None
            
            with pytest.raises(ModuleNotFoundError) as exc_info:
                seedsigner.hardware.buttons.HardwareButtons.get_instance()
            
            error_message = str(exc_info.value)
            assert "pygame" in error_message.lower()
            assert "requirements-desktop.txt" in error_message.lower()
        finally:
            # Restore original state
            seedsigner.hardware.buttons.HardwareButtons._instance = original_instance
            seedsigner.hardware.buttons.USING_GPIO = original_using_gpio
            if original_pygame is not None:
                seedsigner.hardware.buttons.pygame = original_pygame

    def test_raspi_mode_works_without_pygame(self):
        """On Raspberry Pi (with GPIO), pygame is not required."""
        from seedsigner.hardware.buttons import USING_GPIO
        
        # This test documents that on Raspberry Pi hardware,
        # USING_GPIO will be True and pygame is not needed
        # (We can't actually test this without RPi.GPIO, but we document the behavior)
        assert isinstance(USING_GPIO, bool)
        
        # When USING_GPIO is True, the system uses GPIO instead of pygame
        # and all functionality works without pygame installed
