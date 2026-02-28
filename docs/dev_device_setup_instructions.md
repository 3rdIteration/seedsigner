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





