import logging
import time

try:
    from smbus2 import SMBus  # type: ignore
except Exception:  # pragma: no cover - smbus2 isn't available on all platforms
    SMBus = None


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


class BatteryHat(Singleton, BaseThread):
    """Simple interface for the Waveshare UPS HAT (C) using INA219."""

    I2C_BUS = 1
    I2C_ADDR = 0x43  # INA219 address for Waveshare UPS HAT (C)

    REG_CONFIG = 0x00
    REG_SHUNT_VOLTAGE = 0x01
    REG_BUS_VOLTAGE = 0x02
    REG_POWER = 0x03
    REG_CURRENT = 0x04
    REG_CALIBRATION = 0x05

    MIN_VOLTAGE = 3.3
    MAX_VOLTAGE = 4.2

    UPDATE_PERIOD = 60  # seconds

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
        return cls._instance

    def _open_bus(self):
        if self._bus is None:
            if SMBus is None:
                logger.warning("smbus2 not available")
                return
            try:
                self._bus = SMBus(self.I2C_BUS)
            except FileNotFoundError:
                logger.warning("I2C bus not available")
                self._bus = None

    def _read_register(self, reg: int) -> int:
        self._open_bus()
        if not self._bus:
            return 0
        raw = self._bus.read_word_data(self.I2C_ADDR, reg)
        return ((raw & 0xFF) << 8) | (raw >> 8)

    def _write_register(self, reg: int, value: int) -> None:
        self._open_bus()
        if not self._bus:
            return
        data = [value >> 8 & 0xFF, value & 0xFF]
        self._bus.write_i2c_block_data(self.I2C_ADDR, reg, data)

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
        self._open_bus()
        if not self._bus:
            return False
        try:
            # Attempt to read from INA219 configuration register
            self._bus.read_word_data(self.I2C_ADDR, self.REG_CONFIG)
            return True
        except Exception:
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
        pct = (voltage - self.MIN_VOLTAGE) / (self.MAX_VOLTAGE - self.MIN_VOLTAGE) * 100
        pct = max(0, min(100, pct))
        return pct

    def run(self):
        while self.keep_running:
            self.detected = self.detect_hat()
            if self.detected:
                try:
                    # Configure the INA219 once
                    if not hasattr(self, "_configured"):
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
