# Shopping List

This document outlines the hardware components needed to build a SeedSigner device. The components are organized by category for easier procurement.

## Main Board and Camera

The main computing platform and camera are typically used together:

- **Raspberry Pi** (any model with GPIO 40-pin header):
  - Raspberry Pi Zero 1.3 (recommended, no WiFi/Bluetooth)
  - Raspberry Pi Zero W or Zero 2 W (with WiFi/Bluetooth, can be used but requires disabling hardware)
  - Raspberry Pi 1 Model B/B+
  - Raspberry Pi 2 Model B
  - Raspberry Pi 3 Model B
  - Raspberry Pi 4 Model B
  - Raspberry Pi 400

- **Luckfox Pico Boards**:
  - Luckfox Pico Mini (requires adaptor board)
  - Luckfox Pico Pro/Max (requires adaptor board) 
  - Luckfox Pico Pi

Note: The Luckfox Pico Mini and Pro/Max models require an adaptor board that can be obtained from:
- https://github.com/3rdIteration/seedsigner-luckfox-pico/tree/master/hardware-kicad
- Or from my webstore
- A compatible "Plus Hat" is also available as an alternative

- **Libre Computer La Frite**:
  - Libre Computer La Frite AML-S805X-AC

- **Compatible Cameras**:
  - Pi Zero-compatible camera (tested with Aokin / AuviPal 5MP 1080p with OV5647 Sensor)
  - SC3336 Camera (for Luckfox Pico boards)
  - USB Camera (for Libre Computer La Frite)

- **Note**: Raspberry Pi 1 is also compatible but requires a hardware modification to the Waveshare LCD Hat

## Display

- **Waveshare 1.3" 240x240 LCD HAT** (MUST be the 240x240 version!)
  - The display must have a resolution of 240x240 pixels
  - Various Waveshare boards look similar but are NOT COMPATIBLE
  - Standard Waveshare/RPi-style assignments for GPIO40 header

- **SeedSigner Plus Hat** (2.8 inch 320x240)
  - Alternative display option with different screen size
  - Schematics available at: https://github.com/3rdIteration/seedsigner-hardware/tree/main/display_hats

## Additional Hardware Support (Smartcard Integration)

The SeedSigner fork supports additional hardware for smartcard integration:

### Smartcard Hat (SEC1210 connected via UART)
- Smartcard Hat with SEC1210 reader connected via GPIO
- Ready-made boards available from third-party vendors
- Schematics and design files available in this repository: ../electronics/SmartcardHat/

### USB Smart Card Readers
- Any USB smart card reader compatible with PC/SC services
- Contact or contactless readers supported
- Note: ACS ACR 122U reader is unreliable for flashing applets and may brick cards

### GPIO NFC Connected Smart Card Readers
- PN532 NFC V3 module (low cost, ~$5 on Aliexpress)
- Can be connected via available IO pins using GPIO splitters or header connections

### USB Phoenix Type "Sim Readers"
- Compatible with OpenCT for older Blue "Sim Readers"
- Requires manual installation and configuration of OpenCT software

All of the parts can also be sourced from my webstore here: https://cryptoguide.tips/shop/

3D printed cases are available in the "enclosures" section of this repository.