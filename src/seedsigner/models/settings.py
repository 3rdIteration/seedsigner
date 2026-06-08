import gettext
import logging
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import threading

from typing import List

from seedsigner.hardware.io_config import (
    detect_runtime_profile,
    get_hardware_pin_mapping,
    get_hardware_profile_label,
    runtime_profile_to_hardware_profile,
)
from seedsigner.models.settings_definition import SettingsConstants, SettingsDefinition
from seedsigner.models.singleton import Singleton

logger = logging.getLogger(__name__)


def _read_device_model() -> str:
    model_path = "/proc/device-tree/model"
    try:
        with open(model_path, "r", encoding="utf-8") as model_file:
            return model_file.read().strip().lower()
    except Exception:
        return ""


def _detect_gpio_backend() -> str:
    try:
        from periphery import GPIO as _GPIO  # noqa: F401
        return "periphery"
    except Exception:
        return "mock"


def _detect_runtime_profile(_hostname: str) -> str:
    model = _read_device_model()
    detected_profile = detect_runtime_profile(model)
    if detected_profile:
        return detected_profile
    return "desktop"


def _get_rpi_type() -> str:
    model = _read_device_model()
    if not model:
        return "Unknown"
    return model.title()


def _is_i2c_device_detected(address_hex: str, bus_candidates: tuple[int, ...] = (1, 0)) -> bool:
    """
    Probe I2C buses for a specific address using i2cdetect.

    Returns False if i2cdetect isn't available or probing fails.
    """
    if not shutil.which("i2cdetect"):
        return False

    normalized = address_hex.lower().replace("0x", "")
    for bus_number in bus_candidates:
        dev_path = f"/dev/i2c-{bus_number}"
        if not os.path.exists(dev_path):
            continue
        try:
            result = subprocess.run(
                ["i2cdetect", "-y", str(bus_number), f"0x{normalized}", f"0x{normalized}"],
                capture_output=True,
                text=True,
                check=False,
                timeout=1,
            )
            if result.returncode != 0:
                continue
            if f" {normalized} " in f" {result.stdout.lower()} ":
                logger.info("Detected I2C device at 0x%s on /dev/i2c-%s", normalized, bus_number)
                return True
        except Exception:
            continue
    return False


def _maybe_activate_pn532_on_startup(settings_obj: "Settings") -> None:
    """
    Ensure IFD-NFC is activated on startup when PN532 is configured and detected.
    """
    try:
        sc_interfaces = settings_obj._data.get(SettingsConstants.SETTING__SMARTCARD_INTERFACES, [])
        if "pn532" not in sc_interfaces:
            return

        if not shutil.which("ifdnfc-activate"):
            logger.debug("Skipping PN532 startup activation: ifdnfc-activate not found")
            return

        # PN532 I2C default address in libnfc/ifdnfc setups.
        if not _is_i2c_device_detected("0x24"):
            logger.debug("Skipping PN532 startup activation: PN532 not detected on I2C")
            return

        subprocess.run(["ifdnfc-activate", "yes"], check=False)
        logger.info("Activated PN532 IFD-NFC on startup")
    except Exception as e:
        logger.warning("PN532 startup activation failed: %s", e)


def _get_system_type_and_variant(runtime_profile: str, hardware_config: str | None) -> tuple[str, str]:
    system_type_map = {
        "desktop": "Desktop",
        "rpi_26": "Raspberry Pi",
        "rpi_40": "Raspberry Pi",
        "luckfox_22": "Luckfox Pico",
        "luckfox_40": "Luckfox Pico",
        "luckfox_pi": "Luckfox Pico",
        "lc_lafrite": "Libre Computer",
    }
    system_type = system_type_map.get(runtime_profile, "Unknown")

    model = _read_device_model()
    if model:
        return system_type, model.title()

    if hardware_config:
        hardware_label = get_hardware_profile_label(hardware_config)
        if hardware_label:
            return system_type, hardware_label

    return system_type, "Unknown"


class InvalidSettingsQRData(Exception):
    pass


class Settings(Singleton):
    HOSTNAME = platform.uname()[1]
    SEEDSIGNER_OS = "seedsigner-os"
    RUNTIME_PROFILE = _detect_runtime_profile(HOSTNAME)
    SETTINGS_FILENAME = "/mnt/microsd/settings.json" if HOSTNAME == SEEDSIGNER_OS else "settings.json"
    SU_COMMAND_PREFIX = "" if HOSTNAME == SEEDSIGNER_OS else "sudo "

    # Background save delay in seconds.  After `save()` is called the actual
    # disk write is deferred by this amount so that rapid-fire settings
    # changes (e.g. user scrolling through options) are coalesced into a
    # single write.
    _SAVE_DELAY_SECONDS: float = 5.0

    @classmethod
    def get_default_settings_filename(cls) -> str:
        filename = "settings.json"
        if os.path.exists(filename):
            return filename
        src_filename = os.path.join("src", filename)
        if os.path.exists(src_filename):
            return src_filename
        return filename

    @classmethod
    def get_platform_default_hardware_config(cls) -> str | None:
        return runtime_profile_to_hardware_profile(cls.RUNTIME_PROFILE)

    @classmethod
    def get_platform_default_display_config(cls) -> str:
        profile_map = {
            "desktop": SettingsConstants.DISPLAY_CONFIGURATION__DESKTOP__240x240,
            "rpi_26": SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240,
            "rpi_40": SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240,
            "luckfox_22": SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240,
            "luckfox_40": SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240,
            "luckfox_pi": SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240,
            "lc_lafrite": SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240,
        }
        return profile_map.get(cls.RUNTIME_PROFILE, SettingsConstants.DISPLAY_CONFIGURATION__DESKTOP__240x240)

    @classmethod
    def get_platform_default_camera_rotation(cls) -> int:
        profile_map = {
            "rpi_26": 180,
            "rpi_40": 180,
            "luckfox_22": 270,
            "luckfox_40": 270,
            "luckfox_pi": 270,
            "desktop": 180,
        }
        return profile_map.get(cls.RUNTIME_PROFILE, 180)

    @classmethod
    def get_instance(cls):
        # This is the only way to access the one and only instance
        if cls._instance is None:
            # Instantiate the one and only instance
            settings = cls.__new__(cls)
            cls._instance = settings

            settings._data = SettingsDefinition.get_defaults()

            # Compute platform-detected defaults once, upfront.
            platform_defaults = {
                SettingsConstants.SETTING__DISPLAY_CONFIGURATION: Settings.get_platform_default_display_config(),
                SettingsConstants.SETTING__CAMERA_ROTATION: Settings.get_platform_default_camera_rotation(),
            }

            # Load user-persisted or template settings.
            loaded = None
            if os.path.exists(Settings.SETTINGS_FILENAME):
                with open(Settings.SETTINGS_FILENAME) as settings_file:
                    loaded = json.load(settings_file)
            else:
                # Fall back to default template settings on first run.
                # Flow/unit tests expect deterministic in-code defaults rather than
                # user-facing template overrides from src/settings.json.
                if "PYTEST_CURRENT_TEST" not in os.environ and "pytest" not in sys.modules:
                    template_path = Settings.get_default_settings_filename()
                    if os.path.exists(template_path):
                        with open(template_path) as settings_file:
                            loaded = json.load(settings_file)

            if loaded is not None:
                # Platform defaults fill gaps the user/template hasn't
                # explicitly set; user settings take priority.
                for key, value in platform_defaults.items():
                    loaded.setdefault(key, value)
                settings.update(loaded, persist=False)
            else:
                # No settings file — apply platform defaults over code
                # defaults directly.
                for key, value in platform_defaults.items():
                    settings._data[key] = value

            # Setup multilanguage support
            path = os.path.join(
                pathlib.Path(__file__).parent.resolve().parent.resolve(),
                "resources",
                "seedsigner-translations",
                "l10n"
            )
            gettext.bindtextdomain('messages', localedir=path)
            gettext.textdomain('messages')

            # Load default/persistent locale setting
            settings.load_locale()

            # Ensure PN532 is activated when configured and physically present.
            _maybe_activate_pn532_on_startup(settings)

            detected_hardware = Settings.get_platform_default_hardware_config()

            system_type, system_variant = _get_system_type_and_variant(
                Settings.RUNTIME_PROFILE,
                detected_hardware,
            )
            logger.info(
                "System detection: type=%s variant=%s runtime_profile=%s hardware_profile=%s hostname=%s model=%s gpio_backend=%s",
                system_type,
                system_variant,
                Settings.RUNTIME_PROFILE,
                detected_hardware or "n/a",
                Settings.HOSTNAME,
                _read_device_model() or "unknown",
                _detect_gpio_backend(),
            )
            logger.info(
                "Auto-configured defaults: hardware=%s display=%s camera_rotation=%s",
                detected_hardware or "n/a",
                settings._data.get(SettingsConstants.SETTING__DISPLAY_CONFIGURATION, "n/a"),
                settings._data.get(SettingsConstants.SETTING__CAMERA_ROTATION, "n/a"),
            )
            if detected_hardware:
                pin_mapping = get_hardware_pin_mapping(detected_hardware)
                logger.info(
                    "GPIO map (%s): display=%s buttons=%s camera=%s",
                    detected_hardware,
                    pin_mapping.get("display"),
                    pin_mapping.get("buttons"),
                    pin_mapping.get("camera"),
                )

        return cls._instance


    @classmethod
    def parse_settingsqr(cls, data: str) -> tuple[str, dict]:
        """
        Parses SettingsQR data and returns a tuple of (config_name, settings_dict).

        The resulting settings config can be applied by calling `Settings.update(settings_dict)`.
        """
        if not data.startswith("settings::"):
            raise InvalidSettingsQRData()

        version = data.split()[0].split("::")[1]
        if version != "v1":
            raise InvalidSettingsQRData(f"Unsupported SettingsQR version: {version}")
        
        # Start parsing key/value settings at the nth split() index
        split_index = 1

        # handle optional "name" attr
        config_name = None
        if "name=" in data.split()[1]:
            config_name = data.split("name=")[1].split()[0].replace("_", " ")
            split_index += 1

        updated_settings = {}
        for entry in data.split()[split_index:]:
            abbreviated_name, value = entry.split("=")

            # Parse multi-value settings; numeric-ize where needed.
            # Use try/except instead of .isdigit() because .isdigit() returns
            # True for non-ASCII Unicode digit characters (e.g. superscript ¹²³)
            # that int()/float() cannot convert, causing a ValueError.
            if "," in value:
                values_updated = []
                for v in value.split(","):
                    try:
                        v = float(v) if "." in v else int(v)
                    except ValueError:
                        pass
                    values_updated.append(v)
                value = values_updated
            else:
                try:
                    value = float(value) if "." in value else int(value)
                except ValueError:
                    pass
            
            # Replace abbreviated name with full attr_name
            settings_entry = SettingsDefinition.get_settings_entry_by_abbreviated_name(abbreviated_name)
            if not settings_entry:
                logger.info(f"Ignoring unrecognized attribute: {abbreviated_name}")
                continue

            # Validate value(s) against SettingsDefinition's valid options
            if type(value) is not list:
                values = [value]
            else:
                values = value
            for v in values:
                if v not in [opt[0] for opt in settings_entry.selection_options]:
                    if settings_entry.attr_name == SettingsConstants.SETTING__PERSISTENT_SETTINGS and v == SettingsConstants.OPTION__ENABLED:
                        # Special case: trying to enable Persistent Settings when 
                        # DISABLED is the only option allowed (because the SD card is not
                        # inserted. Explicitly set to DISABLED.
                        value = SettingsConstants.OPTION__DISABLED
                        break
                    raise InvalidSettingsQRData(f"""{abbreviated_name} = '{v}' is not valid""")

            updated_settings[settings_entry.attr_name] = value

        return (config_name, updated_settings)


    def __str__(self):
        return json.dumps(self._data, indent=4)
    

    # ------------------------------------------------------------------
    # Background-save infrastructure
    # ------------------------------------------------------------------
    # These class-level defaults are safe because Settings is a strict
    # Singleton (enforced by the Singleton base class).  They are set to
    # per-instance values by _ensure_save_infra().
    _save_lock: threading.Lock = None
    _save_timer: threading.Timer = None

    def _ensure_save_infra(self):
        """Lazily create the lock/timer infrastructure."""
        if self._save_lock is None:
            self._save_lock = threading.Lock()

    def _reset_save_infra(self):
        """Cancel any pending timer and reset internal state.

        Intended for test isolation only.
        """
        if self._save_timer is not None:
            self._save_timer.cancel()
        self._save_lock = None
        self._save_timer = None

    def _do_write_to_disk(self):
        """Write settings JSON to microSD with flush+fsync.

        Caller **must** hold ``_save_lock``.
        """
        try:
            from seedsigner.hardware.microsd import MicroSD
            if self._data[SettingsConstants.SETTING__PERSISTENT_SETTINGS] == SettingsConstants.OPTION__ENABLED and MicroSD.get_instance().is_inserted:
                data_snapshot = dict(self._data)
                with open(Settings.SETTINGS_FILENAME, 'w') as settings_file:
                    json.dump(data_snapshot, settings_file, indent=4)
                    settings_file.flush()
                    os.fsync(settings_file.fileno())
        except Exception:
            logger.exception("Background settings save failed")

    def _write_to_disk(self):
        """Lock-protected wrapper used as the Timer callback."""
        with self._save_lock:
            self._do_write_to_disk()

    def save(self):
        """Schedule a deferred write to disk.

        The actual I/O is performed on a background daemon thread after a
        short delay so that rapid successive calls (e.g. user toggling
        several options) are coalesced into a single disk write, keeping
        the UI responsive.
        """
        self._ensure_save_infra()
        with self._save_lock:
            # Cancel any previously scheduled write; the new timer will
            # capture the latest _data state.
            if self._save_timer is not None:
                self._save_timer.cancel()
            timer = threading.Timer(self._SAVE_DELAY_SECONDS, self._write_to_disk)
            timer.daemon = True
            # Assign before start() so flush_save/save can always cancel.
            self._save_timer = timer
            timer.start()

    def flush_save(self):
        """Block until any pending background save completes.

        Call this before shutdown / microSD removal to guarantee the
        latest settings have been persisted.  If no save is pending this
        is a no-op.
        """
        self._ensure_save_infra()
        with self._save_lock:
            if self._save_timer is not None:
                self._save_timer.cancel()
                self._save_timer = None
                # Write synchronously while still holding the lock so no
                # new timer can slip in between the cancel and the write.
                self._do_write_to_disk()


    def update(self, new_settings: dict, persist: bool = True):
        """
            Replaces the current settings with the incoming dict.

            If a setting is missing from `new_settings`:
                * Hidden settings that have a value remain as-is.
                * All other missing settings are set to their default value.
        """
        for entry in SettingsDefinition.settings_entries:
            if entry.attr_name not in new_settings:
                if entry.visibility == SettingsConstants.VISIBILITY__HIDDEN and entry.attr_name in self._data:
                    # Preserve existing hidden values
                    new_settings[entry.attr_name] = self._data[entry.attr_name]
                else:
                    # Setting is missing; insert default
                    new_settings[entry.attr_name] = entry.default_value

            else:
                # Clean the incoming data, if necessary
                if entry.type == SettingsConstants.TYPE__MULTISELECT:
                    if type(new_settings[entry.attr_name]) == str:
                        # Break comma-separated SettingsQR input into List
                        new_settings[entry.attr_name] = new_settings[entry.attr_name].split(",")
                    elif (
                        type(new_settings[entry.attr_name]) == list
                        and len(new_settings[entry.attr_name]) > 0
                        and type(new_settings[entry.attr_name][0]) in [list, tuple]
                    ):
                        # Handle legacy format where selection options were stored
                        # as [value, label] pairs.
                        new_settings[entry.attr_name] = [v[0] for v in new_settings[entry.attr_name]]

        for key, value in new_settings.items():
            # Defer writing to disk until all values have been applied to avoid
            # repeatedly touching the microSD card during initialization or
            # bulk updates.
            self.set_value(key, value, save=False)

        # Persist once after all settings have been updated, if requested.
        if persist:
            self.save()



    def set_value(self, attr_name: str, value: any, save: bool = True):
        """
            Updates the attr's current value.

            Note that for multiselect, the value must be a List.
        """
        if attr_name not in self._data:
            # Outdated settings
            logger.debug("Setting %s not recognized. Ignoring.", attr_name)
            return

        settings_entry = SettingsDefinition.get_settings_entry(attr_name)
        if not settings_entry:
            # Settings entry may be unavailable on this platform
            logger.debug("Setting %s not found. Ignoring.", attr_name)
            return

        if settings_entry.type == SettingsConstants.TYPE__MULTISELECT:
            if type(value) != list:
                raise Exception(f"value must be a List for {attr_name}")

        # Skip processing if the incoming value is identical to the current
        # value. This prevents unnecessary side-effects (like restarting
        # services) when loading persistent settings that match defaults.
        if attr_name in self._data:
            current_value = self._data[attr_name]
            if settings_entry.type == SettingsConstants.TYPE__MULTISELECT:
                if sorted(current_value) == sorted(value):
                    return
            else:
                if current_value == value:
                    return
        
        # Special handling for toggling persistence
        if attr_name == SettingsConstants.SETTING__PERSISTENT_SETTINGS and value == SettingsConstants.OPTION__DISABLED:
            try:
                os.remove(self.SETTINGS_FILENAME)
                logger.info(f"Removed {self.SETTINGS_FILENAME}")
            except:
                logger.info(f"{self.SETTINGS_FILENAME} not found to be removed")

         # Special handling for enabling Smartcard readers
        if attr_name == SettingsConstants.SETTING__SMARTCARD_INTERFACES:
            import time
            import seedsigner
            #from seedsigner.gui.screens.screen import LoadingScreenThread, WarningScreen
            
            logger.debug("Smartcard Interface Changed")
            logger.debug("Value: %s", value)
            # Update PCSC ignore list (Needed for IFD-NFC, but also add ability to disable SEC1210 or other readers if required)
            pcscd_ignore_devices = []
            if 'pn532' not in value:
                pcscd_ignore_devices.append("IFD-NFC")
            if 'sec1210' not in value:
                pcscd_ignore_devices.append("SEC1210")
            if 'phoenix-usb' not in value:
                pcscd_ignore_devices.append("OpenCT")

            # PCSC supports filtering unwanted devices, but this is done through an environment variable
            # and also requires a restart of PCSC (So it's pretty simple to just edit the init.d file)
            logger.debug("Updating PCSC Ignore List to: %s", ':'.join(pcscd_ignore_devices))

            # Only do this on SeedSignerOS, not on dev environment
            if self.HOSTNAME == self.SEEDSIGNER_OS:
                self.patch_pcsc_initd_script(':'.join(pcscd_ignore_devices))

            #PCSC is restarted at the end

            # Basically just check through a a bunch of possible USB hubs and ports and enable/disable them all (Should cover all RPi models, RPi4 has lots of USB ports...)
            if not any('usb' in d for d in value) and any('usb' in d for d in self._data[attr_name]):
                logger.debug("Disabling USB")
                rpi_type = _get_rpi_type()
                try:
                    self.loading_screen = seedsigner.gui.screens.screen.LoadingScreenThread(text="Disabling USB Ports")
                    self.loading_screen.start()
                except:
                    pass
 
                # Different Raspberry Pi models have different port config, see
                # https://github.com/mvp/uhubctl?tab=readme-ov-file#raspberry-pi-b2b3b
                if "Zero" in rpi_type: # For RPi0, 02w
                    os.system(self.SU_COMMAND_PREFIX + "uhubctl -l 1 -a 0")
                    
                elif "Pi 4" in rpi_type: # For RPi4 
                    os.system(self.SU_COMMAND_PREFIX + "uhubctl -l 2 -a 0")
                    os.system(self.SU_COMMAND_PREFIX + "uhubctl -l 3 -a 0")
                    os.system(self.SU_COMMAND_PREFIX + "uhubctl -l 1-1 -a 0")
                
                else:
                    # For Raspberry Pi B+,2B,3B, 3B+
                    os.system(self.SU_COMMAND_PREFIX + "uhubctl -l 1-1 -p 2 -a 0")
                
                try:
                    self.loading_screen.stop()
                except:
                    pass

            if any('usb' in d for d in value) and not any('usb' in d for d in self._data[attr_name]):
                logger.debug("Enabling USB")
                rpi_type = _get_rpi_type()
                try:
                    self.loading_screen = seedsigner.gui.screens.screen.LoadingScreenThread(text="Enabling USB Ports")
                    self.loading_screen.start()
                except:
                    pass

                # Different Raspberry Pi models have different port config, see
                # https://github.com/mvp/uhubctl?tab=readme-ov-file#raspberry-pi-b2b3b
                 
                if "Zero" in rpi_type: # For RPi0, 02w
                    os.system(self.SU_COMMAND_PREFIX + "uhubctl -l 1 -a 1")
                    
                elif "Pi 4" in rpi_type: # For RPi4 
                    os.system(self.SU_COMMAND_PREFIX + "uhubctl -l 2 -a 1")
                    os.system(self.SU_COMMAND_PREFIX + "uhubctl -l 3 -a 1")
                    os.system(self.SU_COMMAND_PREFIX + "uhubctl -l 1-1 -a 1")
                
                else:
                    # For Raspberry Pi B+,2B,3B, 3B+
                    os.system(self.SU_COMMAND_PREFIX + "uhubctl -l 1-1 -p 2 -a 1")

                time.sleep(1)
                # Restart PCSC at the end

                try:
                    self.loading_screen.stop()

                    if "Zero" in rpi_type or "Model A" in rpi_type: # For RPi0, 02w or model A devices
                        screen = seedsigner.gui.screens.screen.WarningScreen(
                            title="Notice",
                            status_headline=None,
                            text="Enabling USB ports on this device requires a device restart (Full power cycle)",
                            show_back_button=False
                        )
                        screen.display()

                    if "Unknown" in rpi_type: # For unknown RPi devices
                        screen = seedsigner.gui.screens.screen.WarningScreen(
                            title="Notice",
                            status_headline="Unable to detect RPi Model",
                            text="Enabling USB ports on this device likely requires a restart (Full power cycle)",
                            show_back_button=False
                        )
                        screen.display()

                except:
                    pass


            # Execution order matters here if swithing from Phoenix to PN532, basically we want to disable phoenix first and then enable PN532
            if "phoenix-usb" in value and "phoenix-usb" not in self._data[attr_name]:
                logger.debug("Phoenix Enabled")
                try:
                    self.loading_screen = seedsigner.gui.screens.screen.LoadingScreenThread(text="Starting OpenCT")
                    self.loading_screen.start()
                except:
                    pass

                os.system(self.SU_COMMAND_PREFIX + "openct-control init") # OpenCT needs a bit of time to get going before restarting PCSCD (At least two seconds) to work reliabily
                time.sleep(3)

                try:
                    self.loading_screen.stop()
                except:
                    pass

            if "phoenix-usb" not in value and "phoenix-usb" in self._data[attr_name]:
                logger.debug("Phoenix Disabled")
                try:
                    self.loading_screen = seedsigner.gui.screens.screen.LoadingScreenThread(text="Stopping OpenCT")
                    self.loading_screen.start()
                except:
                    pass
                
                os.system(self.SU_COMMAND_PREFIX + "openct-control shutdown")
                time.sleep(3)

                try:
                    self.loading_screen.stop()
                except:
                    pass

            if "pn532" in value and "pn532" not in self._data[attr_name]:
                try:
                    self.loading_screen = seedsigner.gui.screens.screen.LoadingScreenThread(text="Enabling PN532")
                    self.loading_screen.start()
                except:
                    pass
                logger.debug("PN532 Enabled")
                os.system("ifdnfc-activate yes")
                try:
                    self.loading_screen.stop()
                except:
                    pass

            if "pn532" not in value and "pn532" in self._data[attr_name]:
                try:
                    self.loading_screen = seedsigner.gui.screens.screen.LoadingScreenThread(text="Disabling PN532")
                    self.loading_screen.start()
                except:
                    pass
                logger.debug("PN532 Disabled")
                os.system("ifdnfc-activate no")
                try:
                    self.loading_screen.stop()
                except:
                    pass

            # Restart PCSC (Just do this all the time if anything has changed)
            try:
                self.loading_screen = seedsigner.gui.screens.screen.LoadingScreenThread(text="Restarting PCSC")
                self.loading_screen.start()
            except:
                pass
            if self.HOSTNAME == self.SEEDSIGNER_OS:
                os.system("/etc/init.d/S01pcscd stop")
                time.sleep(1)
                os.system("/etc/init.d/S01pcscd start")
            else:
                os.system("sudo service pcscd stop")
                time.sleep(1)
                os.system("sudo service pcscd start")
            try:
                self.loading_screen.stop()
            except:
                pass

        self._data[attr_name] = value

        # Persist if requested. Skipping saves is useful during startup when
        # settings are loaded from disk; saving each key individually could
        # cause unnecessary microSD activity and long boot times on the Pi.
        if save:
            self.save()

        # Special handling for localization
        if attr_name == SettingsConstants.SETTING__LOCALE:
            self.load_locale()


    def patch_pcsc_initd_script(self, desired_value, path="/etc/init.d/S01pcscd"):
        import re

        with open(path, "r") as f:
            content = f.read()

        # Step 1: Remove global PCSCLITE_FILTER_IGNORE_READER_NAMES definitions
        content = re.sub(
            r'(?m)^\s*PCSCLITE_FILTER_IGNORE_READER_NAMES=.*\n^\s*export\s+PCSCLITE_FILTER_IGNORE_READER_NAMES\s*\n?',
            '',
            content
        )

        # Step 2: Patch start() and restart() functions only
        def patch_function_block(func_name, content):
            pattern = re.compile(
                rf'({func_name}\s*\(\)\s*{{)(.*?)(^\s*PCSCLITE_FILTER_IGNORE_READER_NAMES=.*?\n^\s*export\s+PCSCLITE_FILTER_IGNORE_READER_NAMES\s*\n?)?',
                re.DOTALL | re.MULTILINE
            )

            def replacer(match):
                header = match.group(1)
                body = match.group(2)
                # Remove old variable lines inside function body
                body = re.sub(
                    r'(?m)^\s*PCSCLITE_FILTER_IGNORE_READER_NAMES=.*\n^\s*export\s+PCSCLITE_FILTER_IGNORE_READER_NAMES\s*\n?',
                    '',
                    body
                )
                insert = (
                    f'    PCSCLITE_FILTER_IGNORE_READER_NAMES="{desired_value}"\n'
                    f'    export PCSCLITE_FILTER_IGNORE_READER_NAMES\n'
                )
                return f"{header}\n{insert}{body}"

            return pattern.sub(replacer, content, count=1)

        content = patch_function_block("start", content)
        content = patch_function_block("restart", content)

        with open(path, "w") as f:
            f.write(content)

        logger.debug("Environment variable set in 'start()' and 'restart()', and removed from global scope.")

    def get_value(self, attr_name: str, default_if_none: bool = None):
        """
            Returns the attr's current value.

            Note that for multiselect, the current value is a List.
        """
        if attr_name not in self._data:
            if default_if_none:
                return SettingsDefinition.get_settings_entry(attr_name).default_value

            raise Exception(f"Setting for {attr_name} not found")
        return self._data[attr_name]


    def get_value_display_name(self, attr_name: str) -> str:
        """
            Figures out the mapping from value to display_name for the current value's
            tuple(value, display_name) definition, if it's defined that way.
            
            If the selection_options are defined as simple strings, we just return the
            string.

            Cannot be used for multiselect (use get_multiselect_value_display_names
            instead) or free entry types (there is no tuple mapping).
        """
        if attr_name not in self._data:
            raise Exception(f"Setting for {attr_name} not found")
        settings_entry = SettingsDefinition.get_settings_entry(attr_name)
        if settings_entry.type in [SettingsConstants.TYPE__FREE_ENTRY, SettingsConstants.TYPE__MULTISELECT]:
            raise Exception(f"Unsupported SettingsEntry.type: {settings_entry.type}")
        return settings_entry.get_selection_option_display_name_by_value(value=self._data[attr_name])
    

    def get_multiselect_value_display_names(self, attr_name: str) -> List[str]:
        """
            Returns a List of all the selected values' display_names.
        """
        if attr_name not in self._data:
            raise Exception(f"Setting for {attr_name} not found")
        settings_entry = SettingsDefinition.get_settings_entry(attr_name)
        if settings_entry.type != SettingsConstants.TYPE__MULTISELECT:
            raise Exception(f"Unsupported SettingsEntry.type: {settings_entry.type}")

        display_names = []
        # Iterate through the selection_options list in order to preserve intended sort
        # order when adding which options are selected.
        for value, display_name in settings_entry.selection_options:
            if value in self._data[attr_name]:
                display_names.append(display_name)
        return display_names


    def load_locale(self):
        locale = self.get_value(SettingsConstants.SETTING__LOCALE)
        os.environ['LANGUAGE'] = locale

        # Re-initialize with the new locale
        logger.debug("Set LANGUAGE locale to %s", os.environ.get('LANGUAGE', ''))



    """
        Intentionally keeping the properties very limited to avoid an expectation of
        boilerplate property code for every SettingsEntry.

        It's more cumbersome, but instead use:

        Settings.get_instance().get_value(SettingsConstants.SETTING__MY_SETTING_ATTR)
    """
    @property
    def debug(self) -> bool:
        return self._data[SettingsConstants.SETTING__DEBUG] == SettingsConstants.OPTION__ENABLED


    def handle_microsd_state_change(action: str):
        """
        Enables/Disables the Persistent Settings option based on the MicroSD card state.
        """
        from seedsigner.hardware.microsd import MicroSD

        if Settings.HOSTNAME == Settings.SEEDSIGNER_OS:
            if action == MicroSD.ACTION__INSERTED:
                # SD card was just inserted.
                # Restore persistent settings back to defaults
                entry = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__PERSISTENT_SETTINGS)
                entry.selection_options = SettingsConstants.OPTIONS__ENABLED_DISABLED
                entry.help_text = SettingsConstants.PERSISTENT_SETTINGS__SD_INSERTED__HELP_TEXT

                # If a settings file exists, load it without persisting again. This
                # avoids unnecessary disk writes during boot and when cards are
                # re-inserted.
                if os.path.exists(Settings.SETTINGS_FILENAME):
                    settings = Settings.get_instance()
                    if settings.get_value(SettingsConstants.SETTING__PERSISTENT_SETTINGS) != SettingsConstants.OPTION__ENABLED:
                        with open(Settings.SETTINGS_FILENAME) as settings_file:
                            settings.update(json.load(settings_file), persist=False)

            elif action == MicroSD.ACTION__REMOVED:
                # SD card was just removed.
                # Set persistent settings to disabled value directly
                Settings.get_instance()._data[SettingsConstants.SETTING__PERSISTENT_SETTINGS] = SettingsConstants.OPTION__DISABLED

                # set persistent settings to only have disabled as an option, adding additional help text that microSD is removed
                entry = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__PERSISTENT_SETTINGS)
                entry.selection_options = SettingsConstants.OPTIONS__ONLY_DISABLED
                entry.help_text = SettingsConstants.PERSISTENT_SETTINGS__SD_REMOVED__HELP_TEXT
            
            else:
                raise Exception(f"Invalid MicroSD action: {action}")
