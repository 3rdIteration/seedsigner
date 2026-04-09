# Electronics

This folder contains hardware design files for SeedSigner electronics projects. Source files are provided in a range of formats including KiCad, Circuitmaker, and EasyEDA.

## SEC1210 Smartcard Hat

The [`SmartcardHat/`](SmartcardHat/) folder contains the design files for a CCID/PCSC compatible Smart Card interface hat that connects over UART through a standard Raspberry Pi GPIO header (using the SEC1210-URT or SEC1210-UR2 serial interface). It also provides a USB-C socket for powering the device. Available in full-sized card, SIM-sized card, and dual-slot variants. See the [SmartcardHat readme](SmartcardHat/readme.md) for full details.

## Phoenix UART Smartcard Reader

The [`PhoenixReader/`](PhoenixReader/) folder contains the design for a minimal, low-cost Phoenix-type smartcard reader that connects directly to the Raspberry Pi hardware UART via the GPIO header. It uses only JLCPCB basic parts (a 74HC04 hex inverter, an MMBT2222A transistor, a crystal, and standard passives — ~15 components total, under $1 BOM cost). Supports T=0 protocol via the OpenCT phoenix driver. See the [PhoenixReader readme](PhoenixReader/readme.md) for the full schematic, BOM, and build notes.

## SeedSignerPlus Display Hat

The SeedSignerPlus display hat design files are maintained in a separate repository:

👉 [**seedsigner-hardware — SeedSignerPlus Display Hat**](https://github.com/3rdIteration/seedsigner-hardware/tree/main/display_hats/plus_hat)

## SeedSignerPlus + Smartcard Combo Hat

The [`SeedSigner+ Smartcard combo hat/`](SeedSigner+%20Smartcard%20combo%20hat/) folder contains the design files for a hat that integrates the SeedSignerPlus display hat and the Smartcard hat functionality into a single board.
