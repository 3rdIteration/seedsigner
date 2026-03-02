# Dev Device Setup Instructions

## Raspberry Pi

Since v0.6.0, official releases use our custom [SeedSigner OS](https://github.com/SeedSigner/seedsigner-os/). However, project contributors looking to do rapid development cycles can use any recent standard Raspberry Pi OS image. This guide was tested with `raspios_arm64 2025-12-04`.

The setup no longer requires manual Python compilation or a specific old OS image.

The installation process requires an internet connection on the Pi to download the necessary libraries and code.  
If your Pi does not have onboard Wi-Fi, you have two options:

1. Run these steps on a separate Raspberry Pi with onboard Wi-Fi, then move the SD card to the target Pi when complete.
2. OR configure the Pi directly by relaying through your computer's internet connection over USB. See instructions [here](usb_relay.md).

Use the Pi's onboard Wi-Fi only if you are setting up a local development environment, never for real funds or binary image creation.

For the following steps you'll need to either connect a keyboard & monitor to the Raspberry Pi or SSH into it.

### Flash the OS image

Use [Raspberry Pi Imager](https://www.raspberrypi.com/software/) to write a recent Raspberry Pi OS (or Raspberry Pi OS Lite) image to a microSD card (4 GB or larger). Either the 32-bit or 64-bit image will work, but older devices like the Pi Zero, Pi1 or Pi2 will require a 32-bit Raspberry Pi OS image.

### Configure the Pi

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

### Install system dependencies
```bash
sudo apt update && sudo apt install -y \
    git \
    libzbar0 \
    libpcsclite-dev \
    python3-pip \
    --no-install-recommends
```

### Clone SeedSigner
```bash
git clone --recursive https://github.com/3rdIteration/seedsigner
cd seedsigner
```

### Install Python dependencies
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

### Run SeedSigner
```bash
python src/main.py
```


## Libre Computer La Frite (AML-S805X-AC) on Raspberry Pi OS 12

When running on Raspberry Pi OS 12 (Bookworm) on La Frite, SPI0 CS0 may be
claimed by `spi-nor` and not exposed as `/dev/spidev0.0` by default.

### Prerequisites

```bash
sudo apt update
sudo apt install -y libzbar0
```

### Enable La Frite SPI overlays for pin 24 (CS0)

```bash
cd ~/libretech-wiring-tool
make

# DMI auto-detection may fail on this board, so pass VENDOR/BOARD explicitly.
sudo VENDOR=libre-computer BOARD=aml-s805x-ac ./ldto merge spi-cc-1cs spi-cc-1cs-spidev
```

Reboot after merge.

### Persistently bind `spi0.0` to `spidev`

Create `/etc/systemd/system/spi0-spidev.service`:

```ini
[Unit]
Description=Bind SPI0 CS0 to spidev for SeedSigner
After=systemd-modules-load.service
DefaultDependencies=no
Before=multi-user.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'modprobe spidev; echo spidev > /sys/bus/spi/devices/spi0.0/driver_override || true; [ -e /sys/bus/spi/drivers/spi-nor/unbind ] && echo spi0.0 > /sys/bus/spi/drivers/spi-nor/unbind || true; [ -e /sys/bus/spi/drivers/spidev/bind ] && echo spi0.0 > /sys/bus/spi/drivers/spidev/bind || true'

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now spi0-spidev.service
```

Verify:

```bash
ls -l /dev/spidev0.0
python3 -c "from pyzbar import pyzbar; print('pyzbar_ok')"
```

Then run:

```bash
cd ~/seedsigner
python3 src/main.py
```

### USB webcam support

Install webcam dependencies:

```bash
sudo apt install -y v4l-utils python3-opencv
```

Verify the camera is detected:

```bash
v4l2-ctl --list-devices
v4l2-ctl -d /dev/video0 --list-formats-ext
python3 -c "import cv2; print(cv2.__version__)"
```

On La Frite, `/dev/video0` is often the Amlogic decoder and the USB webcam is
typically `/dev/video1`. Confirm with `v4l2-ctl --list-devices` and use the USB
camera node in `io_config.json`.

Run the SeedSigner I/O test and verify camera capture from the UI:

```bash
cd ~/seedsigner
python3 src/main.py --iotest
```

