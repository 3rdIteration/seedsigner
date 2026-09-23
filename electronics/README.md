# Electronics

This folder contains hardware design files for SeedSigner electronics projects. Source files are provided in a range of formats including KiCad, Circuitmaker, and EasyEDA.

## SEC1210 Smartcard Hat

The [`SmartcardHat/`](SmartcardHat/) folder contains the design files for a CCID/PCSC compatible Smart Card interface hat that connects over UART through a standard Raspberry Pi GPIO header (using the SEC1210-URT or SEC1210-UR2 serial interface). It also provides a USB-C socket for powering the device. Available in full-sized card, SIM-sized card, and dual-slot variants. See the [SmartcardHat readme](SmartcardHat/readme.md) for full details.

## SeedSignerPlus Display Hat

The SeedSignerPlus display hat design files are maintained in a separate repository:

👉 [**seedsigner-hardware — SeedSignerPlus Display Hat**](https://github.com/3rdIteration/seedsigner-hardware/tree/main/display_hats/plus_hat)

## SeedSignerPlus + Smartcard Combo Hat

The [`SeedSigner+ Smartcard combo hat/`](SeedSigner+%20Smartcard%20combo%20hat/) folder contains the design files for a hat that integrates the SeedSignerPlus display hat and the Smartcard hat functionality into a single board.

## SeedSigner-Plus Smartcard Pico (Luckfox Pico Mini)

The [`SeedSigner-Plus-smartcard-luckfoxpicozero/`](SeedSigner-Plus-smartcard-luckfoxpicozero/) folder contains the design files for a single-board SeedSigner carrier for the Luckfox Pico Mini. It combines a 2.8" SPI display, joystick/buttons, and a CCID/PCSC smart card interface (SEC1210 over UART) on one board. The Pico Mini can be soldered directly to the PCB or mounted on an 11-pin 2.54 mm pin header. See the [readme](SeedSigner-Plus-smartcard-luckfoxpicozero/readme.md) for details; a matching 3D-printable enclosure lives in [`enclosures/luckfox_pico/plus-hat-smartcard-pico-zero/`](../enclosures/luckfox_pico/plus-hat-smartcard-pico-zero/).

Smaller Luckfox Pico carrier boards that present a standard Raspberry Pi-style 40-pin header (for use with existing Waveshare display hats) are maintained in the [`seedsigner-luckfox-pico`](https://github.com/3rdIteration/seedsigner-luckfox-pico) repository — the [Pico Mini v2](https://github.com/3rdIteration/seedsigner-luckfox-pico/tree/master/hardware-kicad/seedsigner-luckfox-pico-mini-v2) and [Pico Max v2](https://github.com/3rdIteration/seedsigner-luckfox-pico/tree/master/hardware-kicad/seedsigner-luckfox-pico-max-v2). The existing Pico enclosures under [`enclosures/luckfox_pico/`](../enclosures/luckfox_pico/) are designed for those two boards.
