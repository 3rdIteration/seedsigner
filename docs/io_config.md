# IO Config Reference

This document summarizes the hardware mappings in `src/seedsigner/hardware/io_config.json` and how to add new profiles.

## GPIO40 Header (Raspberry Pi style physical pinout)

The table below uses standard 40-pin physical numbering and highlights:
- Waveshare 1.3" LCD HAT signals (`DC`, `RST`, `BL`, keys)
- UART (e.g., SEC1210 smart card reader)
- I2C (e.g., NFC reader, battery monitor, or touchscreen interface)
- Power / Ground

<div align="center">

| Left Pin | Left Signal |  | Right Signal | Right Pin |
|---:|---|:---:|:---|:---|
| 1 | 3V3 | │ │ | 5V | 2 |
| 3 | GPIO2 / SDA1 | │ │ | 5V | 4 |
| 5 | GPIO3 / SCL1 | │ │ | GND | 6 |
| 7 | GPIO4 | │ │ | GPIO14 / TXD0 | 8 |
| 9 | GND | │ │ | GPIO15 / RXD0 | 10 |
| 11 | GPIO17 | │ │ | GPIO18 | 12 |
| 13 | GPIO27 (`RST`, `LCD-RST`) | │ │ | GND | 14 |
| 15 | GPIO22 | │ │ | GPIO23 | 16 |
| 17 | 3V3 | │ │ | GPIO24 (`BL`, `LCD-BL`) | 18 |
| 19 | GPIO10 / MOSI (`LCD-MOSI`) | │ │ | GND | 20 |
| 21 | GPIO9 / MISO | │ │ | GPIO25 (`DC`, `LCD-DC`) | 22 |
| 23 | GPIO11 / SCLK (`LCD-SCLK`) | │ │ | GPIO8 / CE0 (`LCD-CS`) | 24 |
| 25 | GND | │ │ | GPIO7 / CE1 | 26 |
| 27 | GPIO0 / ID_SD | │ │ | GPIO1 / ID_SC | 28 |
| 29 | GPIO5 (`KEY_LEFT`) | │ │ | GND | 30 |
| 31 | GPIO6 (`KEY_UP`) | │ │ | GPIO12 | 32 |
| 33 | GPIO13 (`KEY_PRESS`) | │ │ | GND | 34 |
| 35 | GPIO19 (`KEY_DOWN`) | │ │ | GPIO16 (`KEY3`) | 36 |
| 37 | GPIO26 (`KEY_RIGHT`) | │ │ | GPIO20 (`KEY2`) | 38 |
| 39 | GND | │ │ | GPIO21 (`KEY1`) | 40 |

</div>


## Waveshare SPI display pin notes

For the Waveshare 1.3" LCD HAT on a GPIO40 header:
- `SPI0_MOSI`: pin `19` (`GPIO10`)
- `SPI0_SCLK`: pin `23` (`GPIO11`)
- `SPI0_CE0`: pin `24` (`GPIO8`)
- `DC`: pin `22` (`GPIO25`)
- `RST`: pin `13` (`GPIO27`)
- `BL`: pin `18` (`GPIO24`)
- Power: pin `1` (`3V3`)
- Ground: e.g. pin `6` (`GND`)

These are the standard Waveshare/RPi-style assignments that the `RPI_40` profile follows.

---

## Hardware profile mapping summary

Values shown are exactly how mappings are stored in `io_config.json`.

| Profile | Runtime profile | Display (`dc/rst/bl`) | Buttons | Camera |
|---|---|---|---|---|
| `RPI_40` | `rpi_40` | `[25] / [27] / [24]` | `KEY_UP [6,"pull_up"]`, `KEY_DOWN [19,"pull_up"]`, `KEY_LEFT [5,"pull_up"]`, `KEY_RIGHT [26,"pull_up"]`, `KEY_PRESS [13,"pull_up"]`, `KEY1 [21,"pull_up"]`, `KEY2 [20,"pull_up"]`, `KEY3 [16,"pull_up"]` | `/dev/video0`, `1280x720`, `YUYV`, `4fps` |
| `RPI_26` | `rpi_26` | `[25] / [27] / [24]` | `KEY_UP [3,"pull_up"]`, `KEY_DOWN [17,"pull_up"]`, `KEY_LEFT [2,"pull_up"]`, `KEY_RIGHT [22,"pull_up"]`, `KEY_PRESS [4,"pull_up"]`, `KEY1 [23,"pull_up"]`, `KEY2 [18,"pull_up"]`, `KEY3 [14,"pull_up"]` | `/dev/video0`, `1280x720`, `YUYV`, `4fps` |
| `FOX_22` | `luckfox_22` | `[20] / [19] / [11]` | `KEY_UP [25]`, `KEY_DOWN [27]`, `KEY_LEFT [24]`, `KEY_RIGHT [22]`, `KEY_PRESS [26]`, `KEY1 [23]`, `KEY2 [4]`, `KEY3 [21]` | `/dev/video12`, `800x600`, `GREY`, `6fps` |
| `FOX_40` | `luckfox_40` | `[24] / [25] / [8]` | `KEY_UP [58]`, `KEY_DOWN [53]`, `KEY_LEFT [59]`, `KEY_RIGHT [54]`, `KEY_PRESS [52]`, `KEY1 [55]`, `KEY2 [43]`, `KEY3 [42]` | `/dev/video12`, `800x600`, `GREY`, `6fps` |
| `FOX_PI` | `luckfox_pi` | `[27] / [24] / [6]` | `KEY_UP [26,"pull_up"]`, `KEY_DOWN [20,"pull_up"]`, `KEY_LEFT [1,"pull_up"]`, `KEY_RIGHT [25,"pull_up"]`, `KEY_PRESS [0,"pull_up"]`, `KEY1 [17,"pull_up"]`, `KEY2 [27,"pull_up"]`, `KEY3 [23,"pull_up"]` | `/dev/video12`, `800x600`, `GREY`, `6fps` |

---

## Supported pin selector formats

`buttons` currently accepts all of the following:
- `[chip, line]`
- `[chip, line, "pull_up"]`
- `[line]`
- `[line, "pull_up"]`
- `line`

`display` selectors are consumed directly by `periphery.GPIO(...)` and therefore can be either chip/line or a global line selector.

---

## How to add a new hardware profile

1. Add a new model entry to `src/seedsigner/hardware/io_config.json`:
   - `platform`, `variant`, `shortname`, `runtime_profile`, `regex`
   - `display`, `buttons`, `camera`
2. Use a unique `runtime_profile` and `shortname`.
3. Ensure regexes are specific enough to avoid matching unrelated boards.
4. Prefer adding pull-up bias on button inputs where hardware is active-low.
5. Add/update tests in:
   - `tests/test_io_config_profiles.py`
   - `tests/test_luckfox_camera_backend.py` (if runtime profile affects camera handling)
6. Validate locally:
   - `python -m json.tool src/seedsigner/hardware/io_config.json`
   - `pytest -q tests/test_io_config_profiles.py tests/test_luckfox_camera_backend.py`
