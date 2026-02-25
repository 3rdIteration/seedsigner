# Raspberry Pi OS Local Dev Build Instructions

## Obtain the OS Image

Use Raspberry Pi Imager Software: Raspberry Pi OS Lite Bookworm

Make sure to increase the SPI buffer size
`nano /bootfs/cmdline.txt`

```
"spidev.bufsiz=250000"

# set buffer size on the fly
sudo rmmod spidev
# Reload with new buffer size (e.g., 65536 bytes)
sudo modprobe spidev bufsiz=65536
```

`nano /bootfs/config.txt`

```
dtparam=i2c_arm=on
dtparam=spi=on

camera_auto_detect=0
dtoverlay=ov5647
```


## Install dependencies
```bash
# enable SPI
sudo raspi-config

sudo apt update && sudo apt upgrade -y

sudo apt install -y \
    git \
    libzbar0 \
    zlib1g-dev \
    libjpeg-dev \
    libopenjp2-7 \
    --no-install-recommends

sudo apt install -y python3-venv python3-pip

# Clone Seedsigner at LightningSpore fork
git clone https://github.com/lightningspore/seedsigner.git
cd seedsigner
git checkout upstream-luckfox-staging-1

# Install UV (python tool)
# curl -LsSf https://astral.sh/uv/install.sh | sh
# source $HOME/.local/bin/env

# Create a isolated Python installation
# uv python install 3.11
# uv python list
# uv venv --managed-python

python3 -m venv .venv
source .venv/bin/activate

uv pip install -i https://piwheels.org/simple \
    -r requirements.txt \
    -r requirements-raspi.txt


pip install opencv-python==4.7.0.72 -i https://piwheels.org/simple
```

```
export DISABLE_TIFF=1
export DISABLE_WEBP=1
```
libtiff5-dev


```

sudo apt install libopenblas-dev liblapack3 liblapack-dev
sudo apt install libopenblas-dev liblapack-dev libblas-dev
sudo apt install libatlas3-base libatlas-base-dev


sudo apt install libgtk-3-0 libgdk-pixbuf2.0-0 libglib2.0-0

```

uv pip install --reinstall --no-binary pillow pillow==10.0.1
uv pip install --reinstall --no-binary numpy numpy==1.25.2 -v


uv pip install pytest



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



