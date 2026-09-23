## Debugging a Crash for Advanced (Technical) Users

These instructions help users provide crash exception and traceback logs to developers
to aid troubleshooting.

### Testnet vs Mainnet

Whenever possible, recreate a crash in testnet. This avoids accidentally revealing
private information about yourself, your Bitcoin transactions, or losing funds.

### Network-Connected SeedSigner

For development and testing, we recommend network access via SSH to view crash logs.
Follow [these](usb_relay.md) instructions to set up a USB relay for internet access. On
a Raspberry Pi Zero W you can also connect to WiFi.

### Airgapped Debugging Setup

For mainnet use, do not connect your device to a network. Instead connect an HDMI
display (no internet) and a USB keyboard. This requires an HDMI adapter and a micro
USB-to-USB-A adapter. Plug both in before powering on SeedSigner. The password for the
SeedSigner `pi` user is `raspberry`.

### Debugging Steps

Once signed in as `pi` (HDMI or SSH):

1. Enable the **debug** setting. This fork stores settings in `settings.json`, not the
   old `settings.ini`.

   - On SeedSigner OS the file lives under the writable data directory, e.g.
     `/mnt/microsd/settings.json` (Pi-style builds) or `/mnt/sdcard/settings.json`
     (Luckfox). On a development checkout it is `settings.json` in the source
     directory.
   - Set `"debug": "E"`:

     ```json
     "debug": "E"
     ```

   - You can also flip it through a SettingsQR. Save a copy and then restart the app.

2. Stop the SeedSigner systemd process:

   ```bash
   sudo systemctl stop seedsigner.service
   ```

3. Start the Python app manually from the source directory:

   ```bash
   cd seedsigner/src
   python3 main.py
   ```

SeedSigner should now be running with debug logging. Keep it connected to the display
and keyboard, recreate the crash, and the traceback will be shown on the HDMI display
(and written to the logs).

> The fork also has a **Test hardening** and **Memory info** screen under
> Settings → Hardware for additional diagnostics.
