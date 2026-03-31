import json
import logging
import time
from pathlib import Path

try:
    from smbus2 import SMBus  # type: ignore
except Exception:  # pragma: no cover - smbus2 isn't available on all platforms
    SMBus = None

try:
    from periphery import I2C  # type: ignore
except Exception:  # pragma: no cover - periphery isn't available on all platforms
    I2C = None


class BusVoltageRange:
    RANGE_16V = 0x00
    RANGE_32V = 0x01


class Gain:
    DIV_1_40MV = 0x00
    DIV_2_80MV = 0x01
    DIV_4_160MV = 0x02
    DIV_8_320MV = 0x03


class ADCResolution:
    ADCRES_9BIT_1S = 0x00
    ADCRES_10BIT_1S = 0x01
    ADCRES_11BIT_1S = 0x02
    ADCRES_12BIT_1S = 0x03
    ADCRES_12BIT_2S = 0x09
    ADCRES_12BIT_4S = 0x0A
    ADCRES_12BIT_8S = 0x0B
    ADCRES_12BIT_16S = 0x0C
    ADCRES_12BIT_32S = 0x0D
    ADCRES_12BIT_64S = 0x0E
    ADCRES_12BIT_128S = 0x0F


class Mode:
    POWERDOW = 0x00
    SVOLT_TRIGGERED = 0x01
    BVOLT_TRIGGERED = 0x02
    SANDBVOLT_TRIGGERED = 0x03
    ADCOFF = 0x04
    SVOLT_CONTINUOUS = 0x05
    BVOLT_CONTINUOUS = 0x06
    SANDBVOLT_CONTINUOUS = 0x07

from seedsigner.models.singleton import Singleton
from seedsigner.models.threads import BaseThread

logger = logging.getLogger(__name__)


class _PeripherySMBusCompat:
    """Minimal SMBus-compatible adapter over periphery I2C."""

    def __init__(self, bus_number: int):
        self._i2c = I2C(f"/dev/i2c-{bus_number}")

    def read_word_data(self, addr: int, reg: int) -> int:
        write_msg = I2C.Message([reg & 0xFF])
        read_msg = I2C.Message([0x00, 0x00], read=True)
        self._i2c.transfer(addr, [write_msg, read_msg])
        read_buffer = bytes(read_msg.data)
        # Emulate smbus2 read_word_data() ordering (little-endian host word).
        # INA219 values are big-endian on wire; caller handles byte-swap.
        return (read_buffer[1] << 8) | read_buffer[0]

    def write_i2c_block_data(self, addr: int, reg: int, data: list[int]) -> None:
        payload = [reg & 0xFF] + [value & 0xFF for value in data]
        self._i2c.transfer(addr, [I2C.Message(payload)])

    def close(self) -> None:
        self._i2c.close()


class BatteryHat(Singleton, BaseThread):
    """Simple interface for the Waveshare UPS HAT (C) using INA219."""

    I2C_BUS = 1
    I2C_BUS_CANDIDATES = (1,)
    I2C_ADDR = 0x43  # INA219 address for Waveshare UPS HAT (C)
    I2C_ADDR_CANDIDATES = (0x43,)

    REG_CONFIG = 0x00
    REG_SHUNT_VOLTAGE = 0x01
    REG_BUS_VOLTAGE = 0x02
    REG_POWER = 0x03
    REG_CURRENT = 0x04
    REG_CALIBRATION = 0x05

    MIN_VOLTAGE = 3.3
    MAX_VOLTAGE = 4.2

    UPDATE_PERIOD = 60  # seconds
    DEFAULT_DISCHARGE_CURVE = [
        {"percent": 100, "voltage": 4.032},
        {"percent": 95, "voltage": 3.9804},
        {"percent": 90, "voltage": 3.9676},
        {"percent": 85, "voltage": 3.952},
        {"percent": 80, "voltage": 3.936},
        {"percent": 75, "voltage": 3.905},
        {"percent": 70, "voltage": 3.8652},
        {"percent": 65, "voltage": 3.8334},
        {"percent": 60, "voltage": 3.8136},
        {"percent": 55, "voltage": 3.7858},
        {"percent": 50, "voltage": 3.7619},
        {"percent": 45, "voltage": 3.732},
        {"percent": 40, "voltage": 3.6927},
        {"percent": 35, "voltage": 3.6356},
        {"percent": 30, "voltage": 3.5775},
        {"percent": 25, "voltage": 3.531},
        {"percent": 20, "voltage": 3.4904},
        {"percent": 15, "voltage": 3.4433},
        {"percent": 10, "voltage": 3.3991},
        {"percent": 5, "voltage": 3.3313},
        {"percent": 0, "voltage": 2.98},
    ]

    @classmethod
    def reset_instance(cls):
        if cls._instance:
            try:
                if cls._instance.is_alive():
                    cls._instance.stop()
                    cls._instance.join()
            except Exception:
                pass
            cls._instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            instance = cls.__new__(cls)
            BaseThread.__init__(instance)
            cls._instance = instance
            instance._bus = None
            instance.percent = None
            instance.detected = False
            instance.enabled = SMBus is not None or I2C is not None
            instance._curve_data = None
            instance._curve_label = None
            instance._addr = cls.I2C_ADDR
            instance._bus_number = cls.I2C_BUS
            instance._configured = False
        return cls._instance

    def initialize(self) -> bool:
        if not self.enabled:
            return False
        self.detected = self.detect_hat()
        if not self.detected:
            self.enabled = False
            return self.enabled
        try:
            self.set_calibration_16V_5A()
            self._configured = True
        except Exception as e:
            logger.warning(f"Battery calibration failed during init: {e}")
        return self.enabled

    def is_enabled(self) -> bool:
        return self.enabled

    @classmethod
    def get_discharge_log_path(cls):
        from seedsigner.hardware.microsd import MicroSD

        return MicroSD.get_microsd_dir() / "battery_discharge_log.csv"

    @classmethod
    def get_discharge_curve_path(cls):
        from seedsigner.hardware.microsd import MicroSD

        return MicroSD.get_microsd_dir() / "custom_battery_discharge_curve.json"

    def _open_bus(self):
        if not self.enabled:
            return
        if self._bus is None:
            if SMBus is None and I2C is None:
                logger.warning("No I2C backend available (smbus2/periphery)")
                self.enabled = False
                return

            if SMBus is not None:
                try:
                    self._bus = SMBus(self._bus_number)
                    return
                except (FileNotFoundError, OSError) as e:
                    logger.warning(f"I2C bus /dev/i2c-{self._bus_number} not available via smbus2: {e}")
                    self._bus = None

            if I2C is not None:
                try:
                    self._bus = _PeripherySMBusCompat(self._bus_number)
                    return
                except (FileNotFoundError, OSError) as e:
                    logger.warning(f"I2C bus /dev/i2c-{self._bus_number} not available via periphery: {e}")
                    self._bus = None

    def _close_bus(self) -> None:
        if self._bus is not None:
            try:
                self._bus.close()
            except Exception:
                pass
            self._bus = None

    def _read_register(self, reg: int) -> int:
        self._open_bus()
        if not self._bus:
            return 0
        raw = self._bus.read_word_data(self._addr, reg)
        return ((raw & 0xFF) << 8) | (raw >> 8)

    def _write_register(self, reg: int, value: int) -> None:
        self._open_bus()
        if not self._bus:
            return
        data = [value >> 8 & 0xFF, value & 0xFF]
        self._bus.write_i2c_block_data(self._addr, reg, data)

    def set_calibration_16V_5A(self):
        self._current_lsb = 0.1524
        self._power_lsb = 0.003048
        self._cal_value = 26868
        self._write_register(self.REG_CALIBRATION, self._cal_value)
        config = (
            BusVoltageRange.RANGE_16V << 13
            | Gain.DIV_2_80MV << 11
            | ADCResolution.ADCRES_12BIT_32S << 7
            | ADCResolution.ADCRES_12BIT_32S << 3
            | Mode.SANDBVOLT_CONTINUOUS
        )
        self._write_register(self.REG_CONFIG, config)

    def detect_hat(self) -> bool:
        for bus_number in self.I2C_BUS_CANDIDATES:
            self._bus_number = bus_number
            self._close_bus()
            self._open_bus()
            if not self._bus:
                continue
            for addr in self.I2C_ADDR_CANDIDATES:
                try:
                    # Presence probe: if register read succeeds, device responds.
                    # This intentionally avoids strict value checks that can cause
                    # false negatives on some boards during early startup.
                    self._bus.read_word_data(addr, self.REG_CONFIG)
                    self._addr = addr
                    logger.info(f"Battery HAT detected at /dev/i2c-{bus_number}, address 0x{addr:02x}")
                    return True
                except Exception:
                    continue
        logger.info("Battery HAT not detected on probed I2C buses/addresses")
        return False

    def read_voltage(self) -> float:
        self._open_bus()
        if not self._bus:
            return None
        try:
            raw = self._read_register(self.REG_BUS_VOLTAGE)
            raw >>= 3  # drop CNVR and OVF and LSBs
            return raw * 0.004  # each bit = 4mV
        except Exception as e:
            logger.warning(f"Voltage read failed: {e}")
            return None

    def read_shunt_voltage(self) -> float:
        self._open_bus()
        if not self._bus:
            return None
        try:
            raw = self._read_register(self.REG_SHUNT_VOLTAGE)
            if raw > 32767:
                raw -= 65536
            return raw * 0.01  # mV
        except Exception as e:
            logger.warning(f"Shunt voltage read failed: {e}")
            return None

    def read_current(self) -> float:
        self._open_bus()
        if not self._bus:
            return None
        try:
            raw = self._read_register(self.REG_CURRENT)
            if raw > 32767:
                raw -= 65536
            return raw * self._current_lsb  # mA
        except Exception as e:
            logger.warning(f"Current read failed: {e}")
            return None

    def read_power(self) -> float:
        self._open_bus()
        if not self._bus:
            return None
        try:
            raw = self._read_register(self.REG_POWER)
            if raw > 32767:
                raw -= 65536
            return raw * self._power_lsb  # W
        except Exception as e:
            logger.warning(f"Power read failed: {e}")
            return None

    def read_percentage(self) -> float:
        voltage = self.read_voltage()
        if voltage is None:
            return None
        curve = self._load_discharge_curve()
        if curve:
            pct = self._percent_from_curve(voltage, curve)
            if pct is not None:
                return max(0, min(100, pct))
        pct = (voltage - self.MIN_VOLTAGE) / (self.MAX_VOLTAGE - self.MIN_VOLTAGE) * 100
        return max(0, min(100, pct))

    def load_discharge_curve(self) -> None:
        curve = self._load_curve_from_path(self.get_discharge_curve_path())
        if curve:
            return
        self._curve_data = list(self.DEFAULT_DISCHARGE_CURVE)
        self._curve_label = "default"

    def _load_curve_from_path(self, curve_path: Path) -> list[dict] | None:
        if not curve_path.exists():
            return None
        try:
            with curve_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(f"Failed to load discharge curve: {exc}")
            return None
        curve = data.get("curve")
        if not isinstance(curve, list):
            return None
        self._curve_data = curve
        self._curve_label = curve_path.name
        return curve

    def _load_discharge_curve(self) -> list[dict] | None:
        if self._curve_data is None:
            self.load_discharge_curve()
        return self._curve_data

    def _percent_from_curve(self, voltage: float, curve: list[dict]) -> float | None:
        points = []
        for entry in curve:
            try:
                points.append((float(entry["voltage"]), float(entry["percent"])))
            except (KeyError, TypeError, ValueError):
                continue
        if len(points) < 2:
            return None
        points.sort(key=lambda item: item[0])
        if voltage <= points[0][0]:
            return points[0][1]
        if voltage >= points[-1][0]:
            return points[-1][1]
        for idx in range(1, len(points)):
            low_v, low_p = points[idx - 1]
            high_v, high_p = points[idx]
            if voltage <= high_v:
                if high_v == low_v:
                    return low_p
                t = (voltage - low_v) / (high_v - low_v)
                return low_p + t * (high_p - low_p)
        return None

    def get_curve_label(self) -> str | None:
        return self._curve_label

    def _load_discharge_log_entries(self, log_path: Path) -> list[tuple[float, float]]:
        entries: list[tuple[float, float]] = []
        try:
            with log_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    parts = line.strip().split(",")
                    if len(parts) < 2:
                        continue
                    try:
                        timestamp = float(parts[0])
                        voltage = float(parts[1])
                    except ValueError:
                        continue
                    entries.append((timestamp, voltage))
        except OSError as exc:
            logger.warning(f"Failed to read battery discharge log: {exc}")
        return entries

    def _generate_discharge_curve(self, entries: list[tuple[float, float]], step: int) -> list[dict]:
        entries.sort(key=lambda item: item[0])
        start_time = entries[0][0]
        end_time = entries[-1][0]
        duration = end_time - start_time
        if duration <= 0:
            return []

        curve: list[dict] = []
        idx = 0
        for percent in range(100, -1, -step):
            target_time = start_time + (1 - percent / 100) * duration
            while idx < len(entries) - 2 and entries[idx + 1][0] < target_time:
                idx += 1
            low_t, low_v = entries[idx]
            high_t, high_v = entries[min(idx + 1, len(entries) - 1)]
            if high_t == low_t:
                voltage = low_v
            else:
                t = (target_time - low_t) / (high_t - low_t)
                voltage = low_v + t * (high_v - low_v)
            curve.append({"percent": percent, "voltage": round(voltage, 4)})
        return curve

    def process_discharge_log(self, step: int = 5) -> bool:
        log_path = self.get_discharge_log_path()
        if not log_path.exists():
            return False

        entries = self._load_discharge_log_entries(log_path)
        if len(entries) < 2:
            log_path.unlink(missing_ok=True)
            return False

        curve = self._generate_discharge_curve(entries, step)
        if not curve:
            log_path.unlink(missing_ok=True)
            return False

        curve_path = self.get_discharge_curve_path()
        curve_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "source_log": log_path.name,
            "curve": curve,
        }
        try:
            with curve_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        except OSError as exc:
            logger.warning(f"Failed to write discharge curve: {exc}")
            return False
        log_path.unlink(missing_ok=True)
        return True

    def run(self):
        while self.keep_running:
            self.detected = self.detect_hat()
            if self.detected:
                try:
                    # Configure the INA219 once
                    if not self._configured:
                        self.set_calibration_16V_5A()
                        self._configured = True
                except Exception as e:
                    logger.warning(f"Calibration failed: {e}")
                percent = self.read_percentage()
                if percent is not None:
                    self.percent = percent
            for _ in range(self.UPDATE_PERIOD):
                if not self.keep_running:
                    break
                time.sleep(1)

    def get_percent(self) -> float:
        return self.percent

    def get_voltage(self) -> float:
        return self.read_voltage()

    def get_current(self) -> float:
        return self.read_current()

    def get_power(self) -> float:
        return self.read_power()
