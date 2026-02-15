"""Test that Luckfox Pico and similar platforms don't force desktop mode.

This test validates that platforms like Luckfox Pico, which don't have RPi.GPIO
but do have hardware displays, are not forced into desktop/pygame mode.
"""

import os
import pytest
from unittest.mock import patch, MagicMock


class TestLuckfoxDisplayMode:
    """Test suite for Luckfox Pico display mode handling."""

    def test_luckfox_does_not_force_desktop_mode(self):
        """Luckfox Pico (with /home/pi but no RPi.GPIO) should not force desktop mode."""
        # Simulate Luckfox Pico environment:
        # - No RPi.GPIO available (USING_MOCK_GPIO = True)
        # - Has /home/pi directory (hardware platform)
        # - Should use display config from settings.json, not force desktop mode
        
        # Mock the environment
        with patch('seedsigner.models.settings.USING_MOCK_GPIO', True):
            # Reset settings instance to test fresh initialization
            from seedsigner.models.settings import Settings
            from seedsigner.models.settings_definition import SettingsConstants
            
            original_instance = Settings._instance
            try:
                Settings._instance = None
                
                # Simulate /home/pi exists (Luckfox/RPi dev board)
                with patch('os.path.exists', side_effect=lambda p: p == "/home/pi"):
                    with patch('builtins.open', MagicMock()):
                        with patch('json.load', return_value={
                            SettingsConstants.SETTING__DISPLAY_CONFIGURATION: "st7789_240x240"
                        }):
                            # Get settings instance - should not force desktop mode
                            settings = Settings.get_instance()
                            
                            # Verify display config is NOT forced to desktop
                            # It should use what was loaded from settings file
                            display_config = settings.get_value(
                                SettingsConstants.SETTING__DISPLAY_CONFIGURATION
                            )
                            
                            # Should NOT be desktop mode (should be st7789 from loaded settings)
                            assert display_config != SettingsConstants.DISPLAY_CONFIGURATION__DESKTOP__240x240
                            assert "st7789" in display_config
            
            finally:
                Settings._instance = original_instance

    def test_desktop_system_forces_desktop_mode(self):
        """True desktop systems (no /home/pi, no RPi.GPIO) should force desktop mode."""
        # Simulate actual desktop environment:
        # - No RPi.GPIO available (USING_MOCK_GPIO = True)
        # - No /home/pi directory
        # - Should force desktop display mode
        
        with patch('seedsigner.models.settings.USING_MOCK_GPIO', True):
            from seedsigner.models.settings import Settings
            from seedsigner.models.settings_definition import SettingsConstants
            
            original_instance = Settings._instance
            try:
                Settings._instance = None
                
                # Mock environment - no /home/pi (desktop)
                with patch('os.path.exists', return_value=False):
                    with patch('platform.uname', return_value=['', 'test-desktop', '', '', '']):
                        with patch('builtins.open', MagicMock()):
                            with patch('json.load', return_value={}):
                                settings = Settings.get_instance()
                                
                                # On desktop, should force desktop display mode
                                display_config = settings.get_value(
                                    SettingsConstants.SETTING__DISPLAY_CONFIGURATION
                                )
                                
                                assert display_config == SettingsConstants.DISPLAY_CONFIGURATION__DESKTOP__240x240
            
            finally:
                Settings._instance = original_instance

    def test_raspberry_pi_with_gpio_uses_settings(self):
        """Raspberry Pi with RPi.GPIO should use display config from settings."""
        # When RPi.GPIO is available, USING_MOCK_GPIO = False
        # Should not force any display mode
        
        with patch('seedsigner.models.settings.USING_MOCK_GPIO', False):
            from seedsigner.models.settings import Settings
            from seedsigner.models.settings_definition import SettingsConstants
            
            original_instance = Settings._instance
            try:
                Settings._instance = None
                
                with patch('os.path.exists', return_value=True):  # /home/pi exists
                    with patch('builtins.open', MagicMock()):
                        with patch('json.load', return_value={
                            SettingsConstants.SETTING__DISPLAY_CONFIGURATION: "st7789_320x240"
                        }):
                            settings = Settings.get_instance()
                            
                            # Should use config from settings, not force desktop
                            display_config = settings.get_value(
                                SettingsConstants.SETTING__DISPLAY_CONFIGURATION
                            )
                            
                            assert display_config == "st7789_320x240"
                            assert display_config != SettingsConstants.DISPLAY_CONFIGURATION__DESKTOP__240x240
            
            finally:
                Settings._instance = original_instance

    def test_is_desktop_mode_detection(self):
        """Test MicroSD.is_desktop_mode() correctly identifies platforms."""
        from seedsigner.hardware.microsd import MicroSD
        from collections import namedtuple
        
        # Create proper uname_result named tuple
        UnameResult = namedtuple('uname_result', 
                                 ['system', 'node', 'release', 'version', 'machine'])
        
        # Test 1: /home/pi exists -> Not desktop mode
        with patch('os.path.exists', return_value=True):
            uname_luckfox = UnameResult('Linux', 'luckfox', '', '', '')
            with patch('platform.uname', return_value=uname_luckfox):
                assert MicroSD.is_desktop_mode() == False
        
        # Test 2: SeedSignerOS hostname -> Not desktop mode
        with patch('os.path.exists', return_value=False):
            uname_seedsigner = UnameResult('Linux', 'seedsigner-os', '', '', '')
            with patch('platform.uname', return_value=uname_seedsigner):
                from seedsigner.models.settings import Settings
                with patch.object(Settings, 'HOSTNAME', 'seedsigner-os'):
                    assert MicroSD.is_desktop_mode() == False
        
        # Test 3: No /home/pi, different hostname -> Desktop mode
        with patch('os.path.exists', return_value=False):
            uname_desktop = UnameResult('Linux', 'my-laptop', '', '', '')
            with patch('platform.uname', return_value=uname_desktop):
                assert MicroSD.is_desktop_mode() == True
