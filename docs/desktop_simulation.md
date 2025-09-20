# Desktop Simulation Mode

SeedSigner can run on a standard PC for development and testing. This mode uses your
computer's display and camera and is **not** intended for handling real
seeds or private keys.

## Installation

1. Install the Python requirements:
   ```bash
   python -m pip install --no-deps -r requirements.txt
   python -m pip install --no-deps -r requirements-desktop.txt
   ```
2. Run the application:
   ```bash
   python src/main.py
   ```

On start-up a warning splash screen reminds you that desktop mode is for
testing only.

## Controls

The Waveshare HAT's physical buttons are mapped to your keyboard:

| Hardware button | Keyboard key |
|-----------------|--------------|
| Up              | Up Arrow     |
| Down            | Down Arrow   |
| Left            | Left Arrow   |
| Right           | Right Arrow  |
| Center          | Enter/Return |
| Key 1           | `1`          |
| Key 2           | `2`          |
| Key 3           | `3`          |

A row of clickable on‑screen buttons is also displayed beneath the
simulated screen. Clicking these buttons is equivalent to pressing the
associated keys.

## Camera selection

Desktop mode can use any camera recognised by your operating system. The
active device can be selected from the **Settings → Hardware** menu,
which presents a drop-down list of the detected cameras by name.

The display can simulate either a 240×240 or 320×240 screen. Choose the
desired size from **Settings → Hardware → Display type**.
