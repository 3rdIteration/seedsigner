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


## Configure auto-start at boot

To have SeedSigner start automatically when the Raspberry Pi boots, create a `systemd` service:
```bash
sudo nano /etc/systemd/system/seedsigner.service
```

Add the following contents. If you are not using the username `pi`, replace `pi` in the three places below with your username:
```ini
[Unit]
Description=Seedsigner

[Service]
User=pi
WorkingDirectory=/home/pi/seedsigner
ExecStart=/usr/bin/python3 src/main.py
StandardOutput=null
StandardError=null
Restart=no

[Install]
WantedBy=multi-user.target
```

_Note: `Restart=no` ensures that if the code crashes, systemd will not keep restarting it._

Use `CTRL-X` and `y` to exit and save changes.

Enable the service to start at boot:
```bash
sudo systemctl enable seedsigner.service
```

Now reboot the Raspberry Pi:
```bash
sudo reboot
```

After the Raspberry Pi reboots, the SeedSigner splash screen should appear on the LCD display (it may take up to 60 seconds).

#### Optional: kill the auto-start process on SSH login
When testing new code on the device, you may want to automatically kill the running SeedSigner instance each time you SSH in. Add the following to `~/.profile`:
```bash
nano ~/.profile
```

Add at the end:
```bash
# Find the SeedSigner process and kill it
kill $(ps aux | grep '[m]ain.py' | awk '{print $2}') 2>/dev/null || true
```


## Local testing and development

### Run specific branches or PRs
The default branch is `dev`. If you want to run a specific release tag or a specific branch:
```bash
# release tag for v0.6.0:
git checkout 0.6.0
```

And if you want to test a pull request (PR), for example PR #123:
```bash
git fetch origin pull/123/head:pr_123
git checkout pr_123
```

where `pr_123` is any name you want to give to the new branch in your local repo that will hold the PR.


### Change the host name
For those who will use the SeedSigner installation for testing/development, it can be helpful to change the system's host name so it doesn't potentially conflict with other Raspberry Pis that may already be present on your network. (For those who don't plan to use the installation for testing or development, you can skip this portion of the process.) To change the host name first edit the "hostname" with the command:

```bash
sudo nano /etc/hostname
```

and change "raspberrypi" to "seedsigner" (or another name). Use `CTRL-X` and `y` to exit and save changes.

You'll also need to edit the "hosts" file with the command:
```bash
sudo nano /etc/hosts
```

and change "raspberrypi" to "seedsigner" (or the other name you previously chose). Use `CTRL-X` and `y` to exit and save changes.

### Set a static IP
Your local machine that `ssh`s into the SeedSigner can sometimes get confused if you're connecting to different SeedSigners that are all identified as `pi@seedsigner.local`. In this case it helps to set a static ip and just `ssh` directly to that instead.

First find your current `nameserver`:
```bash
sudo cat /etc/resolv.conf
```

This is the address of your local machine that is connected to your SeedSigner via USB (or it'll be the WiFi router's address if you're using a Raspberry Pi with WiFi and are keeping it enabled for `ssh` access).

Set a static IP: `sudo nano /etc/dhcpcd.conf` and add to the end:
```
interface usb0
static ip_address=192.168.1.200/24
static routers=192.168.1.254
static domain_name_servers=192.168.1.254
```

* `interface` will be `usb0` for USB connections; `wlan0` for WiFi.
* `static ip_address` is the IP address you want the SeedSigner to use. It should match the `nameserver` IP you found above for all but the last part of the IP (note: the `/24` should always be included as-is).
* `static routers` should be your `nameserver` IP.
* `static domain_name_servers` should also be the `nameserver` IP.

`CTRL-X` and `y` to save changes.

After your next reboot, access this SeedSigner using its new static IP:
```bash
# Use the static IP you set above:
ssh pi@192.168.1.200

# But the hostname will still work, too:
ssh pi@seedsigner.local
```

### More convenient `ssh` access:
Power SeedSigner devs will find themselves connecting to a lot of different SeedSigners. This can cause headaches with `ssh`'s built-in protections; a different device that uses the same `ssh` credentials is normally a potential spoofing attack. But we're doing this to ourselves on purpose and so we can carve out exceptions.

On your local machine, run `nano ~/.ssh/config` and add to the end:
```conf
host seedsigner.local
 StrictHostKeyChecking no
 UserKnownHostsFile /dev/null
 User pi
 LogLevel QUIET

# Set this to the static IP you set above:
host 192.168.1.200
 StrictHostKeyChecking no
 UserKnownHostsFile /dev/null
 User pi
 LogLevel QUIET
```

The first entry prevents warnings for the default `pi@seedsigner.local` connections.

The second entry does the same for a specific static IP; you'll want this if you configure all your SeedSigners to use the same static IP.

`CTRL-X` and `y` to save changes.


#### Bypass `ssh` password
You can also configure the SeedSigner so that you don't have to enter the `pi` password when you `ssh` in.

run `ssh-copy-id` with the same values that you connect via `ssh`:
```bash
ssh-copy-id pi@seedsigner.local

# or if you're connecting over static IP, something like:
ssh-copy-id pi@192.168.1.200
```

You'll be prompted to enter the password to complete it.

_Note: If you don't have any ssh keys on your local machine, you'll need to create a set with `ssh-keygen -t ed25519 -C "your_email@example.com"`. Then try running `ssh-copy-id` again._


## Disable WiFi/Bluetooth when using other Raspberry Pi boards
If you plan to use your installation on a Raspberry Pi that is not a Zero version 1.3, but rather on a Raspberry Pi that has WiFi and Bluetooth capabilities, it is a good idea to disable the following WiFi & Bluetooth, as well as other relevant services (assuming you are not creating this installation for testing/development purposes). Enter the following commands to disable WiFi, Bluetooth, & other relevant services:
```bash
sudo systemctl disable bluetooth.service
sudo systemctl disable wpa_supplicant.service
sudo systemctl disable dhcpcd.service
sudo systemctl disable sshd.service
sudo systemctl disable networking.service
sudo systemctl disable dphys-swapfile.service
sudo ifconfig wlan0 down
```

Please note that if you are using WiFi to connect/interact with your Raspberry Pi, the last command will sever that connection.

You can now safely power the Raspberry Pi off from the SeedSigner main menu.

If you do not plan to use your installation for testing/development, it is also a good idea to disable WiFi and Bluetooth by editing the config.txt file found in the installation's "boot" partition. You can add the following text to the end of that file with any simple text editor (Windows: Notepad, Mac: TextEdit, Linux: nano):
```ini
dtoverlay=disable-bt
dtoverlay=pi3-disable-wifi
```

If you used option #2 above and don't plan to continue to access your SeedSigner via SSH over USB, it is a good idea to reverse the steps you took to enable it -- those instructions can be found near the end of [this guide](usb_relay.md).

Please remember that it can take up to a minute for the GUI to appear when powering your SeedSigner on.


### Optional: Run the tests
see: [tests/README.md](../tests/README.md)