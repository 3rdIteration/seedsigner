# Raspberry Pi OS Local Dev Build Instructions

Since v0.6.0, official releases use our custom [SeedSigner OS](https://github.com/SeedSigner/seedsigner-os/). However, project contributors looking to do rapid development cycles can use any recent standard Raspberry Pi OS image. This guide was tested with `raspios_arm64 2025-12-04`.

The setup no longer requires manual Python compilation or a specific old OS image.

The installation process requires an internet connection on the Pi to download the necessary libraries and code.  
If your Pi does not have onboard Wi-Fi, you have two options:

1. Run these steps on a separate Raspberry Pi with onboard Wi-Fi, then move the SD card to the target Pi when complete.
2. OR configure the Pi directly by relaying through your computer's internet connection over USB. See instructions [here](usb_relay.md).

Use the Pi's onboard Wi-Fi only if you are setting up a local development environment, never for real funds or binary image creation.

For the following steps you'll need to either connect a keyboard & monitor to the Raspberry Pi or SSH into it.

## Flash the OS image

Use [Raspberry Pi Imager](https://www.raspberrypi.com/software/) to write a recent Raspberry Pi OS (or Raspberry Pi OS Lite) image to a microSD card (4 GB or larger). The 64-bit (arm64) image is recommended.

## Configure the Pi

Launch the Raspberry Pi's System Configuration tool:
```bash
sudo raspi-config
```

Set the following:
* `Interface Options`:
    * `SPI`: enable
    * `I2C`: enable (optional, only needed for I2C-based displays)
* `Interface Options` → `Serial Port`:
    * Disable the login shell over the serial port
    * Keep the serial port hardware enabled

When you exit the System Configuration tool, reboot when prompted and then continue.

## Install system dependencies
```bash
sudo apt update && sudo apt install -y \
    git \
    libzbar0 \
    libpcsclite-dev \
    python3-pip \
    --no-install-recommends
```

## Clone SeedSigner
```bash
git clone --recursive https://github.com/3rdIteration/seedsigner
cd seedsigner
```

## Install Python dependencies
```bash
pip3 install -r requirements.txt
pip3 install -r requirements-raspi.txt
```

If you encounter permission errors, use `pip3 install --break-system-packages` or install inside a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-raspi.txt
```

## Run SeedSigner
```bash
python src/main.py
```

