# Android Build

This repository includes an experimental Android build that wraps the SeedSigner
core using Kivy. The phone's display, camera and touchscreen act as replacements
for the original hardware.

## Prerequisites

* Python 3.10 or newer
* [Buildozer](https://github.com/kivy/buildozer) (`pip install buildozer`)
* Android SDK/NDK (automatically downloaded the first time buildozer runs)

On Debian based distributions you can install the base packages and buildozer
with:

```bash
sudo apt update
sudo apt install python3 python3-pip git openjdk-8-jdk
pip install buildozer
```

## Building

From the project root run:

```bash
buildozer android debug
```

The resulting APK will be placed in the `bin/` directory. Install it on your
device with:

```bash
adb install bin/SeedSigner-0.0.1-debug.apk
```

Launching the app will show the SeedSigner display on screen and allow using the
phone camera and touchscreen as input.
