# Hardware Shopping and Assembly

This page covers choosing, buying and assembling the hardware for a SeedSigner. For the software side, start with the [Quick starts](./README.md#quick-starts).

## Choose a platform

- **Raspberry Pi** (any model with a 40-pin GPIO header) — the classic build. Use a Waveshare 1.3" 240x240 LCD HAT or the SeedSigner Plus Hat.
- **Luckfox Pico** — three routes:
  - **Pico Mini / Pro-Max + adaptor board** — the adaptor presents a standard Raspberry Pi-style 40-pin header, so it works with existing Waveshare display hats. Design files: [seedsigner-luckfox-pico](https://github.com/3rdIteration/seedsigner-luckfox-pico/tree/master/hardware-kicad).
  - **SeedSigner-Plus Smartcard Pico (all-in-one)** — a single board for the Luckfox Pico Mini with the 2.8" display, buttons and SEC1210 smartcard interface. [Board design files](https://github.com/3rdIteration/seedsigner/tree/dev/electronics/SeedSigner-Plus-smartcard-luckfoxpicozero).
  - **Luckfox Pico Pi**.
- **Libre Computer La Frite** AML-S805X-AC (USB camera).

## Shopping list

See the [Shopping List](./shopping_list.md) for the full component list, including the parts available from the [Crypto Guide store](https://cryptoguide.tips/shop/).

At a minimum you need:

- A main board (Raspberry Pi / Luckfox Pico / La Frite)
- A compatible camera
- A supported display (or the all-in-one SeedSigner-Plus Smartcard Pico)
- A microSD card
- For smartcard features: a smartcard reader (e.g. the SEC1210 hat) and JavaCards

## Boards, cameras and displays

- Main boards and cameras: [Shopping List → Main Board and Camera](./shopping_list.md#main-board-and-camera)
- Displays: [Shopping List → Display](./shopping_list.md#display) and the display table in [Hardware platform support](./hardware_platform_support.md)
- Pin mappings and profiles: [IO config](./io_config.md)

## Smartcard hardware

- [Smartcard integration and installation](./smartcard_support_installation.md) — readers and wiring
- [Electronics designs](https://github.com/3rdIteration/seedsigner/tree/dev/electronics) — smartcard hats and the all-in-one Luckfox board
- [Bundled JavaCard applets](./javacard_applets.md) — what to flash onto a card

## Cases and assembly

Free 3D-printable cases live in the [`enclosures/`](https://github.com/3rdIteration/seedsigner/tree/dev/enclosures) folder:

- **Raspberry Pi Zero** — Open Pill, Orange Pill, Rugged Pill, Simple Pill and more
- **Luckfox Pico Mini/Max adaptor boards** — [`seedsigner-luckfox-pico-mini-max-case`](https://github.com/3rdIteration/seedsigner/tree/dev/enclosures/luckfox_pico/seedsigner-luckfox-pico-mini-max-case)
- **SeedSigner-Plus Smartcard Pico** — [`plus-hat-smartcard-pico-zero`](https://github.com/3rdIteration/seedsigner/tree/dev/enclosures/luckfox_pico/plus-hat-smartcard-pico-zero) (the camera is held with 2x M2 6–8 mm screws; the body and faceplate depend on the mounting method and board revision)

Ready-made cases and kits are also sold at the [Crypto Guide store](https://cryptoguide.tips/shop/).

## Related hardware docs

- [Battery](./battery.md) — battery monitoring hardware
- [Legacy hardware](./legacy_hardware.md) — older Raspberry Pi revisions
