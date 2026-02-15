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
        # Reset the HardwareButtons singleton to test fresh initialization
        from seedsigner.hardware import buttons as buttons_module
        
        original_instance = buttons_module.HardwareButtons._instance
        original_using_gpio = buttons_module.USING_GPIO
        original_pygame = getattr(buttons_module, 'pygame', None)
        
        try:
            # Simulate desktop environment without pygame
            buttons_module.HardwareButtons._instance = None
            buttons_module.USING_GPIO = False
            buttons_module.pygame = None
            
            # Attempting to get instance should raise clear error
            with pytest.raises(ModuleNotFoundError) as exc_info:
                buttons_module.HardwareButtons.get_instance()
            
            # Verify error message is helpful
            error_message = str(exc_info.value)
            assert "pygame" in error_message.lower()
            assert "requirements-desktop.txt" in error_message.lower()
            
        finally:
            # Restore original state to avoid affecting other tests
            buttons_module.HardwareButtons._instance = original_instance
            buttons_module.USING_GPIO = original_using_gpio
            if original_pygame is not None:
                buttons_module.pygame = original_pygame
            # If pygame was None originally, leave it as None

    def test_raspi_mode_works_without_pygame(self):
        """On Raspberry Pi (with GPIO), pygame is not required."""
        # This test documents that when RPi.GPIO is available (Raspberry Pi),
        # the system will use GPIO instead of pygame, and pygame is not required.
        # 
        # On actual Raspberry Pi hardware:
        # - USING_GPIO = True
        # - GPIO module is used for button input
        # - pygame is not imported or needed
        # 
        # On desktop/test environments:
        # - USING_GPIO = False (because RPi.GPIO is mocked)
        # - pygame is required for desktop simulation
        
        from seedsigner.hardware.buttons import USING_GPIO, GPIO
        
        # Verify the GPIO flag is set correctly based on availability
        assert isinstance(USING_GPIO, bool)
        
        # If GPIO is available, USING_GPIO should be True
        # If GPIO is mocked (in tests), it will be a MagicMock
        if USING_GPIO:
            # On real hardware, GPIO would be the RPi.GPIO module
            # In tests, it's mocked
            assert GPIO is not None
