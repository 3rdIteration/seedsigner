# Phoenix UART Smartcard Reader for Raspberry Pi

A minimal, low-cost Phoenix-type smartcard reader that connects directly to the Raspberry Pi hardware UART via the GPIO header. Uses the OpenCT phoenix driver to provide PC/SC access to ISO 7816 contact smartcards (T=0 protocol).

This is a much simpler and cheaper alternative to the [SEC1210-based SmartcardHat](../SmartcardHat/). The trade-off is that it only supports T=0 (not T=1), requires OpenCT (which must be built from source), and has no CCID-level features like automatic protocol negotiation or hardware-level secure channel support. See [Limitations](#limitations-vs-sec1210-smartcard-hat) below.

## Circuit Overview

The circuit has three functional blocks:

1. **Clock oscillator** — 3.579545 MHz crystal with a 74HC04 inverter gate as a Pierce oscillator, providing the ISO 7816 CLK signal to the card.
2. **Half-duplex I/O bridge** — An NPN transistor (MMBT2222A) driven by a spare 74HC04 inverter gate converts the Pi's separate TX/RX UART lines into the card's single bidirectional I/O line.
3. **Card power, reset, and decoupling** — 3.3V from the Pi GPIO header powers the card, with a GPIO pin controlling the card RST line.

All active components (the 74HC04 and MMBT2222A) are JLCPCB basic parts. All passives are standard 0805 values that are also JLCPCB basic. The 3.579545 MHz crystal (HC-49S) may be classified as an extended part at JLCPCB depending on current stock, but it is a very common, inexpensive crystal.

Total BOM cost (excluding card socket and GPIO header): **well under $1 USD**.

## Schematic

```
                         VCC (3.3V, from Pi GPIO Pin 1)
                          |
                          +--[C5 100nF]--GND          (bulk decoupling)
                          |
              +-----------+-----------------------------+------------------+
              |           |                             |                  |
             [R4]        [R6]                          VCC               VCC
             10K         10K                            |                  |
          (pull-up)   (pull-up)                        [C3]              [C4]
              |           |                           100nF              100nF
              |           |                             |                  |
              |           +--- Card RST (ISO-C2)        GND               GND
              |           |                      (card decoup)       (IC1 decoup)
              |          [R5]
              |          100R
              |           |
              |       Pi GPIO4 (Pin 7)  ---- Card Reset control
              |
  Card I/O (ISO-C7) ---+
              |    |
              |   [R7]
              |   100R
              |    |
              |   Pi RXD / GPIO15 (Pin 10)
              |
           Collector
              |
          Q1 (MMBT2222A, SOT-23)
              |
           Emitter
              |
             GND
              |
           Base
              |
             [R3]
             10K
              |
          IC1 Pin 6 (Gate 3 output: TX inverter)
              |
          IC1 Pin 5 (Gate 3 input) ---- Pi TXD / GPIO14 (Pin 8)


  ===== Clock Oscillator (Pierce) =====

          +--------[R1 1MΩ]--------+
          |       (feedback)        |
          |                         |
   IC1 Pin 1 (1A) --------> IC1 Pin 2 (1Y)     [Gate 1: oscillator]
          |                         |
         [C1]                      [C2]
         33pF                      33pF
          |                         |
          +----[Y1 3.579545MHz]----+
          |                         |
         GND                       GND


   IC1 Pin 2 ---- IC1 Pin 3 (2A)               [buffered clock]
                         |
                  IC1 Pin 4 (2Y)
                         |
                        [R2]
                        100R
                         |
                    Card CLK (ISO-C3)


  ===== IC1 74HC04D (SOIC-14) Pin Assignments =====

   Pin 14: VCC (3.3V)          Pin 7: GND
   Pin  1: 1A  (crystal in)    Pin  2: 1Y (crystal out / oscillator)
   Pin  3: 2A  (buffer in)     Pin  4: 2Y (buffer out → card CLK)
   Pin  5: 3A  (Pi TXD in)     Pin  6: 3Y (inverted → Q1 base)
   Pin  9: 4A  → GND           Pin  8: 4Y (unused output, float)
   Pin 11: 5A  → GND           Pin 10: 5Y (unused output, float)
   Pin 13: 6A  → GND           Pin 12: 6Y (unused output, float)


  ===== ISO 7816 Card Pinout (card pin labels use "ISO-" prefix) =====

   ISO-C1 (VCC)  ---- 3.3V
   ISO-C2 (RST)  ---- Pi GPIO4 through R5/R6
   ISO-C3 (CLK)  ---- IC1 Pin 4 (2Y) through R2
   ISO-C5 (GND)  ---- GND
   ISO-C7 (I/O)  ---- Q1 collector / Pi RXD through R7 / R4 pull-up
   ISO-C4, ISO-C6, ISO-C8 -- Not connected (unused for modern Javacards)


  ===== Raspberry Pi GPIO Header Connections =====

   Pin  1 (3.3V)        → VCC
   Pin  6 (GND)         → GND
   Pin  7 (GPIO4)       → Card RST (through R5)
   Pin  8 (GPIO14/TXD)  → IC1 Pin 5 (TX inverter input)
   Pin 10 (GPIO15/RXD)  → Card I/O (through R7)
```

## How It Works

### Half-Duplex I/O Bridge

A smartcard has a single bidirectional I/O line (half-duplex), but the Pi UART has separate TX and RX pins. The circuit merges them:

**Pi transmitting to card:**
- Pi TXD idles HIGH → inverter output LOW → Q1 OFF → I/O pulled HIGH by R4 (correct idle state ✓)
- Pi TXD sends start bit (LOW) → inverter output HIGH → Q1 ON → Q1 pulls I/O LOW (correct ✓)
- Data bits follow the same pattern: the inverter + NPN combination makes TX non-inverting to the card I/O line

**Card transmitting to Pi:**
- Card pulls I/O LOW (start bit) → Pi RXD sees LOW through R7 ✓
- Card releases I/O → R4 pulls it HIGH → Pi RXD sees HIGH ✓
- The Pi also sees an echo of its own transmitted data on RX (since I/O is connected to both). The OpenCT driver handles this.

### Why the Inverter is Needed

The NPN transistor in common-emitter configuration is inherently inverting: a HIGH base turns it ON, pulling the collector LOW. Without the 74HC04 inverter gate, the Pi's idle-HIGH TX state would keep the transistor ON, holding the card I/O LOW — the wrong idle state.

In classic RS-232 Phoenix designs, this inversion isn't needed because the RS-232 line is connected directly to the transistor base: RS-232 mark/idle is a *negative* voltage, which keeps the NPN OFF. Since we're using a TTL-level UART, we add the inverter to achieve the same result.

### Clock Oscillator

The 74HC04 Gate 1 is configured as a Pierce oscillator with the 3.579545 MHz crystal. This frequency gives a default baud rate of:

    Baud = 3,579,545 / 372 = **9,623 baud** (≈ 9600)

Gate 2 buffers the clock output before driving it to the card through the 100Ω series resistor R2.

Since we already need the 74HC04 for the clock oscillator, we use a spare gate (Gate 3) for the TX inverter at no additional cost.

## Bill of Materials

| Ref | Value | Package | LCSC Part # | Type | Notes |
|-----|-------|---------|-------------|------|-------|
| IC1 | 74HC04D | SOIC-14 | C5590 | Basic | Hex inverter (NXP) |
| Q1 | MMBT2222A | SOT-23 | C2150 | Basic | NPN transistor |
| Y1 | 3.579545 MHz | HC-49S | C12674 | Ext* | Crystal oscillator |
| R1 | 1MΩ | 0805 | C17514 | Basic | Oscillator feedback |
| R2 | 100Ω | 0805 | C17408 | Basic | CLK series resistor |
| R3 | 10KΩ | 0805 | C17414 | Basic | Q1 base resistor |
| R4 | 10KΩ | 0805 | C17414 | Basic | Card I/O pull-up |
| R5 | 100Ω | 0805 | C17408 | Basic | RST series protection |
| R6 | 10KΩ | 0805 | C17414 | Basic | Card RST pull-up |
| R7 | 100Ω | 0805 | C17408 | Basic | RXD series protection |
| C1 | 33pF | 0805 | C1663 | Basic | Crystal load cap |
| C2 | 33pF | 0805 | C1663 | Basic | Crystal load cap |
| C3 | 100nF | 0805 | C49678 | Basic | Card VCC decoupling |
| C4 | 100nF | 0805 | C49678 | Basic | IC1 VCC decoupling |
| C5 | 100nF | 0805 | C49678 | Basic | Bulk VCC decoupling |

\* The 3.579545 MHz crystal may be classified as "Extended" at JLCPCB rather than "Basic". It is the standard NTSC colour burst crystal and is extremely common/cheap. If JLCPCB does not stock it, any 3.579545 MHz HC-49S crystal from another supplier will work.

**Connectors (not included in JLCPCB SMT assembly):**

| Ref | Description | Notes |
|-----|-------------|-------|
| J1 | 2×20 pin GPIO header or stacking header | Connects to Pi. Adafruit 4079 for stacking. |
| J2 | ISO 7816 card socket (full-size or SIM) | Any standard contact card socket |

**Component totals:** 2 ICs/transistors, 7 resistors (3 unique values), 5 capacitors (2 unique values), 1 crystal = **15 components**

## Alternative: GPIO Clock (No Crystal Needed)

If you want an even simpler circuit, you can eliminate the crystal oscillator entirely (Y1, R1, C1, C2, and IC1 Gate 1+2) by using the Raspberry Pi's hardware clock output on **GPIO4 (GPCLK0)**:

```bash
# Configure GPIO4 to output ~3.58 MHz using PLLD (500 MHz / 140 = 3.571 MHz)
# This is within the ±2% tolerance allowed by ISO 7816
sudo raspi-gpio set 4 a0  # Set GPIO4 to ALT0 (GPCLK0)
```

With this approach, the card CLK connects directly to GPIO4 (through a 100Ω series resistor), and you'd use a different GPIO for RST (e.g., GPIO17/Pin 11). The 74HC04 is still needed for the TX inverter (Gate 3), but you'd only populate the IC, R3, R7, R4, R5, R6, C3, C4, C5, and Q1 — **10 components total**.

**Trade-off:** The GPIO clock uses a fractional divider which adds slight jitter. Most modern Javacards tolerate this, but the crystal approach is more universally reliable. The GPIO clock frequency also varies by Pi model (different PLL sources), so you'd need to verify the achievable frequency on your specific hardware.

## Software Configuration

### Raspberry Pi UART Setup

Add to `/boot/config.txt`:
```
enable_uart=1
dtoverlay=disable-bt
```

This frees the hardware UART (`/dev/ttyAMA0`) from Bluetooth and makes it available on GPIO14/15.

### OpenCT Configuration

The Phoenix reader uses the OpenCT driver with the Pi's hardware UART. Follow the [OpenCT installation instructions](../../docs/smartcard_support_installation.md#openct-and-genericold-blue-sim-readers-optional-get-a-more-modern-smart-card-reader-if-possible) but configure the device path for the hardware UART instead of USB:

Edit `/usr/local/etc/openct.conf`:
```
reader phoenix {
    driver = phoenix;
    device = serial:/dev/ttyAMA0;
};
```

Note: The existing `phoenix-usb` smartcard interface option (defined in `src/seedsigner/models/settings_definition.py` as `SMARTCARD_INTERFACE_PHOENIX`) configures OpenCT for `/dev/ttyUSB0`. For this direct UART Phoenix reader, you would either:
1. Add a new smartcard interface option (`phoenix-uart`) in `settings_definition.py` that points OpenCT to `/dev/ttyAMA0`
2. Or manually edit `/usr/local/etc/openct.conf` to point the device to `serial:/dev/ttyAMA0`

### Card Reset GPIO

The card RST line is controlled by GPIO4 (or whichever GPIO you connect). OpenCT handles the reset sequence, but you may also need to configure the GPIO as an output and toggle it during initialization:

```bash
# Set GPIO4 as output, drive HIGH to release reset
raspi-gpio set 4 op dh
# Drive LOW to assert reset
raspi-gpio set 4 op dl
# Release reset (card begins ATR)
raspi-gpio set 4 op dh
```

**Important:** The GPIO pin used for RST depends on which clock option you chose:
- **Crystal oscillator design (default):** GPIO4 (Pin 7) is used for RST as shown above.
- **GPIO Clock alternative:** GPIO4 is repurposed for clock output (GPCLK0), so you must use a different GPIO for RST — e.g., GPIO17 (Pin 11). Update the commands above to reference GPIO17 instead of GPIO4.

## Limitations vs SEC1210 SmartCard Hat

| Feature | Phoenix Reader (this design) | SEC1210 SmartCard Hat |
|---------|-----------------------------|-----------------------|
| Protocol | T=0 only | T=0 and T=1 |
| Driver | OpenCT (must build from source) | Standard Linux CCID (libccid) |
| Auto-detection | No (manual init each boot) | Yes (auto-detected by pcscd) |
| Clock generation | Crystal oscillator on PCB | Internal to SEC1210 |
| CCID compliance | No (OpenCT bridges to PC/SC) | Yes (native CCID over UART) |
| Voltage negotiation | Fixed 3.3V only | Class A/B/C auto-negotiation |
| APDU size (T=0) | 256 bytes max (envelope wrapping for larger) | 256 bytes T=0, unlimited T=1 chaining |
| Reliability | Can enter bugged state (see troubleshooting) | Robust hardware state machine |
| Component count | ~15 | ~35 |
| BOM cost (SMT parts) | < $1 | ~$5–8 |
| Secure channel overhead | Higher (T=0 chaining for encrypted APDUs) | Lower (T=1 block chaining) |

### Key Protocol Limitations (T=0 vs T=1)

**T=0** is character-oriented: each byte is acknowledged individually with per-byte even parity. **T=1** is block-oriented: data is sent in blocks with CRC/LRC checksums. The practical differences:

- **Throughput**: T=0 is slower for large data transfers due to per-byte acknowledgment overhead
- **Error recovery**: T=0 retransmits individual bytes; T=1 retransmits entire blocks with resynchronization and abort support
- **APDU size**: T=0 is limited to 256-byte data fields. Extended APDUs (needed for large SeedKeeper payloads) require envelope wrapping by the middleware. T=1 supports native extended APDUs via block chaining
- **Waiting time**: T=1 has WTX (waiting time extension) allowing the card to request more time for slow operations (crypto, PBKDF2). T=0 has a fixed timeout
- **Cancellation**: T=1 supports S-block ABORT for clean mid-transfer cancellation. T=0 requires a card reset

For SeedKeeper use cases (storing/retrieving BIP39 seeds with secure channel encryption), these limitations are manageable but mean slightly slower operations and more fragile error recovery compared to the SEC1210 hat.

## Assembly Notes

This is a very simple circuit that can be built on:
- **Perfboard/stripboard** — solder the components point-to-point with hookup wire to a GPIO header
- **Custom PCB** — the production_files directory contains a BOM in JLCPCB format
- **Breadboard** — for prototyping, use DIP adapters for the SOT-23 transistor and SOIC-14 IC

All 0805 passives are generous enough for hand soldering. The SOIC-14 (74HC04D) and SOT-23 (MMBT2222A) are also straightforward to hand solder.

## Troubleshooting

**Card not responding after OpenCT start:**
- Verify UART is free: `ls -la /dev/ttyAMA0` should show the device. If Bluetooth is using it, double-check `dtoverlay=disable-bt` in config.txt.
- Check GPIO4 is driving RST correctly: the card needs RST to go HIGH after power-up and clock are stable.
- Verify clock output with an oscilloscope or frequency counter. The crystal should oscillate at 3.579545 MHz.

**Garbled data / communication errors:**
- The I/O pull-up (R4) value matters. If the card can't pull the line LOW against R4 + the idle TX source, try increasing R4 to 47KΩ.
- Ensure the Pi UART baud rate matches: `stty -F /dev/ttyAMA0 9600`
- Check that no other process has the UART open: `fuser /dev/ttyAMA0`

**OpenCT enters bugged state (continuous activity on I/O):**
- Power cycle the Pi completely (disconnect power, wait 5 seconds, reconnect).
- This is a known issue with the Phoenix protocol — see the [troubleshooting section](../../docs/smartcard_support_installation.md#troubleshooting-connection-issues-with-openctusb-sim-readers) in the main smartcard docs.
