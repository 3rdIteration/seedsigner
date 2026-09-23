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

Notes:
* You may need to solder the 40 GPIO pins (20 pins per row) to the Raspberry Pi Zero board. If you don't want to solder, most stores offer the board "with headers" already soldered on.
* The Pi Zero "W" or "2W" is often easier to find but has wifi/Bluetooth hardware. You can still use these boards and can optionally [disable the wifi/Bluetooth hardware](https://github.com/DesobedienteTecnologico/rpi_disable_wifi_and_bt_by_hardware).
* Raspberry Pi 1 is also compatible, but will require a [hardware modification to the Waveshare LCD Hat](./legacy_hardware.md).

- **Luckfox Pico Boards**:
  - Luckfox Pico Mini
  - Luckfox Pico Pro/Max
  - Luckfox Pico Pi

There are three ways to build a SeedSigner around a Luckfox Pico:

1. **Luckfox Pico Mini / Pro/Max with an adaptor board** — the Pico plugs into a small adaptor PCB that presents a standard Raspberry Pi-style 40-pin header, so it can use the same Waveshare display hats as a Pi build. Adaptor boards are available from:
   - https://github.com/3rdIteration/seedsigner-luckfox-pico/tree/master/hardware-kicad
   - Or from my webstore
   - 3D-printable cases: [`enclosures/luckfox_pico/seedsigner-luckfox-pico-mini-max-case/`](../enclosures/luckfox_pico/seedsigner-luckfox-pico-mini-max-case/)
2. **SeedSigner-Plus Smartcard Pico (all-in-one)** — a single board for the Luckfox Pico Mini that combines the display, joystick/buttons and the SEC1210 smartcard interface, so no separate display or smartcard hat is needed. Design files: [`electronics/SeedSigner-Plus-smartcard-luckfoxpicozero/`](../electronics/SeedSigner-Plus-smartcard-luckfoxpicozero/); matching case: [`enclosures/luckfox_pico/plus-hat-smartcard-pico-zero/`](../enclosures/luckfox_pico/plus-hat-smartcard-pico-zero/)
3. **Luckfox Pico Pi** — supported directly.

A "Plus Hat" (see Display below) can also be used in place of the Waveshare display hat with the adaptor-board and Pico Pi options.

- **Libre Computer La Frite**:
  - Libre Computer La Frite AML-S805X-AC

- **Compatible Cameras**:
  - Pi Zero-compatible camera (tested with Aokin / AuviPal 5MP 1080p with OV5647 Sensor)
  - SC3336 Camera (for Luckfox Pico boards)
  - USB Camera (for Libre Computer La Frite)
    - [0.3MP Pixel USB Camera Module](https://www.hbvcamera.com/0-3mp-pixel-usb-cameras/usb-cmos-camera-module-for-advertising-machine.html)
    - GC0307 USB Camera:
      - [AliExpress](https://www.aliexpress.com/item/1005008187236223.html)
      - [Cryptoguide](https://cryptoguide.tips/product/gc0307-usb-camera-module/)

- **Note**: Raspberry Pi 1 is also compatible but requires a hardware modification to the Waveshare LCD Hat

## Display

- **Waveshare 1.3" 240x240 LCD HAT** (MUST be the 240x240 version!)
  - The display must have a resolution of 240x240 pixels
  - Various Waveshare boards look similar but are NOT COMPATIBLE
  - Standard Waveshare/RPi-style assignments for GPIO40 header
  - [Waveshare 1.3" 240x240 LCD HAT wiki page](https://www.waveshare.com/wiki/1.3inch_LCD_HAT)

- **SeedSigner Plus Hat** (2.8 inch 320x240)
  - Alternative display option with different screen size
  - Schematics available at: https://github.com/3rdIteration/seedsigner-hardware/tree/main/display_hats
  - The same 2.8" display module is used on the all-in-one SeedSigner-Plus Smartcard Pico (Luckfox) board above

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