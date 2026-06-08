# Libre Computer La Frite Enclosure

This enclosure design is specifically for the Libre Computer La Frite platform.

## Hardware Requirements

The Libre Computer La Frite requires a specific USB camera module and adaptor:

- **USB Camera Module**: This case supports camera modules like the [0.3MP Pixel USB Camera Module](https://www.hbvcamera.com/0-3mp-pixel-usb-cameras/usb-cmos-camera-module-for-advertising-machine.html) or the [GC0307 USB Camera](https://www.aliexpress.com/item/1005005655012400.html) (both compatible with the La Frite platform).

- **USB Adaptor**: The case requires the USB adaptor PCB from the electronics folder. This adaptor converts the La Frite's GPIO signals to USB for camera connectivity.
  - Adaptor location: `electronics/usb-plug-pcb/`

## Wiring Information

A photo demonstrating how this hardware is wired can be found in the documentation images:
- `docs/img/low_profile_usb_camera.jpg`
- `docs/img/gc0307_usb_camera.jpg` (new GC0307 camera option)

This image shows the correct wiring configuration between the Libre Computer La Frite and the USB camera module using the provided adaptor board.
