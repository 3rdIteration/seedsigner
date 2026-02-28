# Hardware Platform Support

SeedSigner supports multiple hardware platforms via runtime profile detection and
per-platform IO mappings.

For a consolidated per-profile mapping table and GPIO40 header reference, see `docs/io_config.md`.

## Where platform support is defined

- `src/seedsigner/hardware/io_config.json`
  - Source of truth for supported models, detection regex patterns, and IO pin maps.
- `src/seedsigner/hardware/io_config.py`
  - Loads platform definitions and resolves runtime profile to hardware profile.
- `src/seedsigner/models/settings.py`
  - Detects runtime profile from `/proc/device-tree/model`.
  - Applies platform defaults for hardware profile, display config, and camera rotation.

## How detection works

1. Device model string is read from `/proc/device-tree/model`.
2. Regex patterns in `io_config.json` are matched to select a `runtime_profile`.
3. Runtime profile is mapped to a hardware profile (`shortname`, e.g. `RPI_40`).
4. Hardware profile pin mappings are used by hardware modules (display, buttons, camera).

## Supported platform profiles

Current profiles in `io_config.json`:

- `RPI_40` (Raspberry Pi 40-pin variants, includes Zero/Zero W/Zero 2 W and newer Pis)
- `RPI_26` (legacy Raspberry Pi 26-pin variants)
- `FOX_22` (Luckfox Pico 22-pin)
- `FOX_40` (Luckfox Pico 40-pin)
- `FOX_PI` (Luckfox Pico Pi)

## Button GPIO mapping format

Button mappings live under each model's `buttons` object.

Accepted entry formats:

- `[gpiochip_path, line]`
  - Example: `["/dev/gpiochip1", 25]`
- `[gpiochip_path, line, bias]`
  - Example: `["/dev/gpiochip0", 6, "pull_up"]`
- `[line]` (platforms using global line numbering with periphery)
  - Example: `[58]`
- `[line, bias]`
  - Example: `[6, "pull_up"]`

`bias` is optional. When present as the last string element (e.g.
`[chip, line, "pull_up"]` or `[line, "pull_up"]`), it is passed to
`periphery.GPIO(..., bias=<value>)`. When absent, input GPIO is opened
without an explicit bias.

For Raspberry Pi profiles (`RPI_40`, `RPI_26`), button entries are configured
with inline `"pull_up"` bias to match active-low button reads.

## IO mapping summary by profile

This is a quick reference summary of the mappings currently defined in
`src/seedsigner/hardware/io_config.json`.

### `RPI_40`

- Display:
  - `dc`: `["/dev/gpiochip0", 25]`
  - `rst`: `["/dev/gpiochip0", 27]`
  - `bl`: `["/dev/gpiochip0", 24]`
  - SPI: `bus 0`, `device 0`
- Buttons (all with `"pull_up"`):
  - `KEY_UP`: `["/dev/gpiochip0", 6, "pull_up"]`
  - `KEY_DOWN`: `["/dev/gpiochip0", 19, "pull_up"]`
  - `KEY_LEFT`: `["/dev/gpiochip0", 5, "pull_up"]`
  - `KEY_RIGHT`: `["/dev/gpiochip0", 26, "pull_up"]`
  - `KEY_PRESS`: `["/dev/gpiochip0", 13, "pull_up"]`
  - `KEY1`: `["/dev/gpiochip0", 21, "pull_up"]`
  - `KEY2`: `["/dev/gpiochip0", 20, "pull_up"]`
  - `KEY3`: `["/dev/gpiochip0", 16, "pull_up"]`
- Camera:
  - Device: `/dev/video0`
  - Resolution: `1280x720`
  - Pixel format: `YUYV`
  - Framerate: `4`

### `RPI_26`

- Display:
  - `dc`: `["/dev/gpiochip0", 25]`
  - `rst`: `["/dev/gpiochip0", 27]`
  - `bl`: `["/dev/gpiochip0", 24]`
  - SPI: `bus 0`, `device 0`
- Buttons (all with `"pull_up"`):
  - `KEY_UP`: `["/dev/gpiochip0", 3, "pull_up"]`
  - `KEY_DOWN`: `["/dev/gpiochip0", 17, "pull_up"]`
  - `KEY_LEFT`: `["/dev/gpiochip0", 2, "pull_up"]`
  - `KEY_RIGHT`: `["/dev/gpiochip0", 22, "pull_up"]`
  - `KEY_PRESS`: `["/dev/gpiochip0", 4, "pull_up"]`
  - `KEY1`: `["/dev/gpiochip0", 23, "pull_up"]`
  - `KEY2`: `["/dev/gpiochip0", 18, "pull_up"]`
  - `KEY3`: `["/dev/gpiochip0", 14, "pull_up"]`
- Camera:
  - Device: `/dev/video0`
  - Resolution: `1280x720`
  - Pixel format: `YUYV`
  - Framerate: `4`

### `FOX_22`

- Display:
  - `dc`: `["/dev/gpiochip1", 20]`
  - `rst`: `["/dev/gpiochip1", 19]`
  - `bl`: `["/dev/gpiochip1", 11]`
  - SPI: `bus 0`, `device 0`
- Buttons:
  - `KEY_UP`: `["/dev/gpiochip1", 25]`
  - `KEY_DOWN`: `["/dev/gpiochip1", 27]`
  - `KEY_LEFT`: `["/dev/gpiochip1", 24]`
  - `KEY_RIGHT`: `["/dev/gpiochip1", 22]`
  - `KEY_PRESS`: `["/dev/gpiochip1", 26]`
  - `KEY1`: `["/dev/gpiochip1", 23]`
  - `KEY2`: `["/dev/gpiochip0", 4]`
  - `KEY3`: `["/dev/gpiochip1", 21]`
- Camera:
  - Device: `/dev/video12`
  - Pixel format: `NV12`
  - Framerate: `10`

### `FOX_40`

- Display:
  - `dc`: `["/dev/gpiochip1", 24]` (`pin 19`, `GPIO1_D0_d`)
  - `rst`: `["/dev/gpiochip1", 25]` (`pin 20`, `GPIO1_D1_d`)
  - `bl`: `["/dev/gpiochip2", 8]` (`pin 17`, `GPIO2_B0_d`)
  - SPI: `bus 0`, `device 0`
- Buttons:
  - `KEY_UP`: `[58]` (`pin 9`, `GPIO1_D2_d`)
  - `KEY_DOWN`: `[53]` (`pin 6`, `GPIO1_C5_d`)
  - `KEY_LEFT`: `[59]` (`pin 10`, `GPIO1_D3_d`)
  - `KEY_RIGHT`: `[54]` (`pin 5`, `GPIO1_C6_d`)
  - `KEY_PRESS`: `[52]` (`pin 7`, `GPIO1_C4_d`)
  - `KEY1`: `[55]` (`pin 4`, `GPIO1_C7_d`)
  - `KEY2`: `[43]` (`pin 2`, `GPIO1_B3_d`)
  - `KEY3`: `[42]` (`pin 1`, `GPIO1_B2_d`)
- Camera:
  - Device: `/dev/video12`
  - Pixel format: `NV12`
  - Framerate: `10`

### `FOX_PI`

- Display:
  - `dc`: `["/dev/gpiochip1", 27]`
  - `rst`: `["/dev/gpiochip1", 24]`
  - `bl`: `["/dev/gpiochip2", 6]`
  - SPI: `bus 0`, `device 0`
- Buttons (all with `"pull_up"`):
  - `KEY_UP`: `["/dev/gpiochip3", 26, "pull_up"]`
  - `KEY_DOWN`: `["/dev/gpiochip1", 20, "pull_up"]`
  - `KEY_LEFT`: `["/dev/gpiochip0", 1, "pull_up"]`
  - `KEY_RIGHT`: `["/dev/gpiochip3", 25, "pull_up"]`
  - `KEY_PRESS`: `["/dev/gpiochip0", 0, "pull_up"]`
  - `KEY1`: `["/dev/gpiochip4", 17, "pull_up"]`
  - `KEY2`: `["/dev/gpiochip3", 27, "pull_up"]`
  - `KEY3`: `["/dev/gpiochip1", 23, "pull_up"]`
- Camera:
  - Device: `/dev/video12`
  - Pixel format: `GREY`
  - Framerate: `6`
