# IO Config Reference

This document summarizes the hardware mappings in `src/seedsigner/hardware/io_config.json` and how to add new profiles.

## GPIO40 Header (Raspberry Pi style physical pinout)

The table below uses standard 40-pin physical numbering and highlights:
- Waveshare 1.3" LCD HAT signals (`DC`, `RST`, `BL`, keys)
- UART (`UART-TX`, `UART-RX`; e.g., SEC1210 smart card reader)
- I2C (`I2C-SDA`, `I2C-SCL`; e.g., NFC reader, battery monitor, or touchscreen interface)
- Power / Ground

<div align="center">

| Left Pin | Left Signal |  | Right Signal | Right Pin |
|---:|---|:---:|:---|:---|
| 1 | 3V3 | │ │ | 5V | 2 |
| 3 | GPIO2 / SDA1 (`I2C-SDA`) | │ │ | 5V | 4 |
| 5 | GPIO3 / SCL1 (`I2C-SCL`) | │ │ | GND | 6 |
| 7 | GPIO4 | │ │ | GPIO14 / TXD0 (`UART-TX`) | 8 |
| 9 | GND | │ │ | GPIO15 / RXD0 (`UART-RX`) | 10 |
| 11 | GPIO17 | │ │ | GPIO18 | 12 |
| 13 | GPIO27 (`LCD-RST`) | │ │ | GND | 14 |
| 15 | GPIO22 | │ │ | GPIO23 | 16 |
| 17 | 3V3 | │ │ | GPIO24 (`LCD-BL`) | 18 |
| 19 | GPIO10 / MOSI (`LCD-MOSI`) | │ │ | GND | 20 |
| 21 | GPIO9 / MISO | │ │ | GPIO25 (`LCD-DC`) | 22 |
| 23 | GPIO11 / SCLK (`LCD-SCLK`) | │ │ | GPIO8 / CE0 (`LCD-CS`) | 24 |
| 25 | GND | │ │ | GPIO7 / CE1 | 26 |
| 27 | GPIO0 / ID_SD (`I2C0-SDA`) | │ │ | GPIO1 / ID_SC (`I2C0-SCL`) | 28 |
| 29 | GPIO5 (`KEY_LEFT`) | │ │ | GND | 30 |
| 31 | GPIO6 (`KEY_UP`) | │ │ | GPIO12 | 32 |
| 33 | GPIO13 (`KEY_PRESS`) | │ │ | GND | 34 |
| 35 | GPIO19 (`KEY_DOWN`) | │ │ | GPIO16 (`KEY3`) | 36 |
| 37 | GPIO26 (`KEY_RIGHT`) | │ │ | GPIO20 (`KEY2`) | 38 |
| 39 | GND | │ │ | GPIO21 (`KEY1`) | 40 |

</div>


## Waveshare SPI display pin notes

The Waveshare 1.3" LCD HAT (ST7789, 240×240) and 1.44" LCD HAT (ST7735S,
128×128) share the same GPIO40 header pinout:
- `SPI0_MOSI`: pin `19` (`GPIO10`)
- `SPI0_SCLK`: pin `23` (`GPIO11`)
- `CS` / `LCD-CS` (`SPI0_CE0`): pin `24` (`GPIO8`)
- `DC`: pin `22` (`GPIO25`)
- `RST`: pin `13` (`GPIO27`)
- `BL`: pin `18` (`GPIO24`)
- Power: pin `1` (`3V3`)
- Ground: e.g. pin `6` (`GND`)

Both HATs use the same `RPI_40` hardware profile — the only difference is the
display driver setting:

| HAT | Display setting | Driver |
|-----|----------------|--------|
| 1.3" LCD HAT (240×240) | `st7789_240x240` (default) | `ST7789.py` |
| 1.44" LCD HAT (128×128) | `st7735_128x128` | `ST7735.py` |

To use the 1.44" HAT, change the **Display type** setting to `st7735 128x128`
(or use a SettingsQR with `disp_conf=st7735_128x128`).

### CS and the three wiring options

When `"cs"` is **not** set to `"disabled"`, the kernel manages the CE GPIO
(e.g. CE0/GPIO8 for `spi_device: 0`) as a pure output — it drives the pin low
before each transfer and high afterwards.  What matters for the display is the
**LCD CS pin state**, which is determined by whichever path you choose:

| LCD CS wiring | CE wiring | Display works? | Notes |
|---|---|---|---|
| Tied to GND | Not connected to LCD | ✅ Yes | LCD always selected; CE is irrelevant. Use `"cs": "disabled"`. |
| Tied to GND | Connected to LCD CS | ⚠️ Risky | GND and CE fight when CE goes high. Do not do this. |
| Wired to CE0 | CE0 connected to LCD CS | ✅ Yes | Standard HAT wiring; default config. |
| Floating | CE0 not wired to LCD | ❌ No | **Silent failure** — SPI transfers succeed in software but LCD ignores all bytes. |

> **Key insight:** if the LCD CS pin is **permanently tied to GND**, the LCD is
> always selected and will receive every SPI byte regardless of whether the SBC's
> CE pin is connected.  The CE pin becomes irrelevant.  In this case the
> `spidev` device (e.g. `/dev/spidev0.0`) still works, but you should add
> `"cs": "disabled"` to make the configuration explicit and to prevent the kernel
> from driving the CE GPIO unnecessarily.

> **Silent failure:** if LCD CS is **floating** (not tied to GND and not wired to
> CE), every `SPI.transfer()` call succeeds in software — no exception, no
> `errno` — but the LCD ignores every byte.  The display stays blank with no
> error.  The driver logs a `WARNING` at startup when kernel-managed CS is active
> to alert you to this risk.

### CS tied to ground (no GPIO chip-select)

If there are no other devices on the SPI bus, the simplest and most robust
wiring is to tie the LCD CS pin directly to GND.  Leave the SBC CE pin
unconnected (or simply don't wire it to the LCD).  Then add `"cs": "disabled"`
to the `display` section of the profile:

```json
"display": {
  "dc":  ["/dev/gpiochip0", 25],
  "rst": ["/dev/gpiochip0", 27],
  "bl":  ["/dev/gpiochip0", 24],
  "spi_bus": 0,
  "spi_device": 0,
  "cs": "disabled"
}
```

When `"cs": "disabled"` is present the driver opens the SPI device with the
`SPI_NO_CS` kernel flag (`0x40`), which prevents the kernel from asserting or
de-asserting any CE GPIO.  The display is always selected via the hardwired
ground connection, and the RST line handles the hardware reset during
initialisation.

If the display is blank and you are using kernel-managed CS, check:
1. The CE pin is physically connected to the LCD CS pin, **or** LCD CS is tied to GND.
2. The correct `spi_device` index matches the CE pin used (e.g. `0` → CE0/GPIO8,
   `1` → CE1/GPIO7 on a Raspberry Pi).
3. If there is only one device on the bus, prefer `"cs": "disabled"` + LCD CS to GND.

---

## Hardware profile mapping summary

Values shown are exactly how mappings are stored in `io_config.json`.

| Profile | Runtime profile | Display (`dc/rst/bl`) | Buttons | Camera |
|---|---|---|---|---|
| `RPI_40` | `rpi_40` | `["/dev/gpiochip0",25] / ["/dev/gpiochip0",27] / ["/dev/gpiochip0",24]` | `KEY_UP ["/dev/gpiochip0",6,"pull_up"]`, `KEY_DOWN ["/dev/gpiochip0",19,"pull_up"]`, `KEY_LEFT ["/dev/gpiochip0",5,"pull_up"]`, `KEY_RIGHT ["/dev/gpiochip0",26,"pull_up"]`, `KEY_PRESS ["/dev/gpiochip0",13,"pull_up"]`, `KEY1 ["/dev/gpiochip0",21,"pull_up"]`, `KEY2 ["/dev/gpiochip0",20,"pull_up"]`, `KEY3 ["/dev/gpiochip0",16,"pull_up"]` | `480x480`, `4fps` |
| `RPI_26` | `rpi_26` | `["/dev/gpiochip0",25] / ["/dev/gpiochip0",27] / ["/dev/gpiochip0",24]` | `KEY_UP ["/dev/gpiochip0",3,"pull_up"]`, `KEY_DOWN ["/dev/gpiochip0",17,"pull_up"]`, `KEY_LEFT ["/dev/gpiochip0",2,"pull_up"]`, `KEY_RIGHT ["/dev/gpiochip0",22,"pull_up"]`, `KEY_PRESS ["/dev/gpiochip0",4,"pull_up"]`, `KEY1 ["/dev/gpiochip0",23,"pull_up"]`, `KEY2 ["/dev/gpiochip0",18,"pull_up"]`, `KEY3 ["/dev/gpiochip0",14,"pull_up"]` | `480x480`, `4fps` |
| `FOX_22` | `luckfox_22` | `["/dev/gpiochip1",20] / ["/dev/gpiochip1",19] / "disabled"` | `KEY_UP ["/dev/gpiochip1",25,"pull_up"]`, `KEY_DOWN ["/dev/gpiochip1",23,"pull_up"]`, `KEY_LEFT ["/dev/gpiochip1",24,"pull_up"]`, `KEY_RIGHT ["/dev/gpiochip0",4,"pull_up"]`, `KEY_PRESS ["/dev/gpiochip1",22,"pull_up"]`, `KEY1 ["/dev/gpiochip4",16,"pull_up"]`, `KEY2 ["/dev/gpiochip4",17,"pull_up"]`, `KEY3 ["/dev/gpiochip1",21,"pull_up"]` | `/dev/video12`, `GREY`, `6fps` |
| `FOX_40` | `luckfox_40` | `["/dev/gpiochip2",8] / ["/dev/gpiochip1",24] / ["/dev/gpiochip1",25]` | `KEY_UP ["/dev/gpiochip2",9,"pull_up"]`, `KEY_DOWN ["/dev/gpiochip1",26,"pull_up"]`, `KEY_LEFT ["/dev/gpiochip1",19,"pull_up"]`, `KEY_RIGHT ["/dev/gpiochip1",20,"pull_up"]`, `KEY_PRESS ["/dev/gpiochip1",27,"pull_up"]`, `KEY1 ["/dev/gpiochip1",23,"pull_up"]`, `KEY2 ["/dev/gpiochip1",22,"pull_up"]`, `KEY3 ["/dev/gpiochip1",21,"pull_up"]` | `/dev/video12`, `GREY`, `6fps` |
| `FOX_PI` | `luckfox_pi` | `["/dev/gpiochip1",27] / ["/dev/gpiochip1",24] / ["/dev/gpiochip2",6]` | `KEY_UP ["/dev/gpiochip3",25,"pull_up"]`, `KEY_DOWN ["/dev/gpiochip0",1,"pull_up"]`, `KEY_LEFT ["/dev/gpiochip3",26,"pull_up"]`, `KEY_RIGHT ["/dev/gpiochip0",0,"pull_up"]`, `KEY_PRESS ["/dev/gpiochip1",20,"pull_up"]`, `KEY1 ["/dev/gpiochip4",17,"pull_up"]`, `KEY2 ["/dev/gpiochip3",27,"pull_up"]`, `KEY3 ["/dev/gpiochip1",23,"pull_up"]` | `/dev/video12`, `GREY`, `6fps` |
| `LC_LAFRITE` | `lc_lafrite` | `["/dev/gpiochip1",79] / ["/dev/gpiochip1",20] / ["/dev/gpiochip1",25]` | `KEY_UP ["/dev/gpiochip0",2,"pull_up"]`, `KEY_DOWN ["/dev/gpiochip1",86,"pull_up"]`, `KEY_LEFT ["/dev/gpiochip1",76,"pull_up"]`, `KEY_RIGHT ["/dev/gpiochip1",84,"pull_up"]`, `KEY_PRESS ["/dev/gpiochip1",85,"pull_up"]`, `KEY1 ["/dev/gpiochip1",83,"pull_up"]`, `KEY2 ["/dev/gpiochip1",82,"pull_up"]`, `KEY3 ["/dev/gpiochip1",81,"pull_up"]` | `/dev/video1`, `1280x720`, `YUYV`, `4fps` |

> **Note:** Raspberry Pi profiles use explicit `/dev/gpiochip0` selectors for display and button pins and do not include a `pixelformat` camera setting.
> PiCamera uses its own capture format (always RGB) and the OpenCV fallback
> handles pixel format conversion internally, so a V4L2-style `pixelformat`
> field is not applicable. The `pixelformat` setting is only used by Luckfox
> and other V4L2-based camera backends.

> **Luckfox Pico note:** GPIO pins on Luckfox Pico boards often require
> additional configuration beyond what is possible in python-periphery or
> standard Linux GPIO tools. See the
> [Luckfox startup workflow — GPIO button configuration](https://github.com/3rdIteration/seedsigner-luckfox-pico/blob/master/docs/LUCKFOX_STARTUP_WORKFLOW.md#gpio-button-configuration)
> documentation for details.

---

## Supported pin selector formats

`buttons` currently accepts all of the following:
- `[chip, line]`
- `[chip, line, "pull_up"]`
- `[line]`
- `[line, "pull_up"]`
- `line`
- `"disabled"` — the button will not be initialized and will never register as pressed

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

