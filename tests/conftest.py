import sys
from unittest.mock import MagicMock

# Mock hardware-dependent modules so unit tests can run without them
sys.modules.setdefault('RPi', MagicMock())
sys.modules.setdefault('RPi.GPIO', MagicMock())
sys.modules.setdefault('pyzbar', MagicMock())
sys.modules.setdefault('pyzbar.pyzbar', MagicMock())
sys.modules.setdefault('pysatochip', MagicMock())
sys.modules.setdefault('pysatochip.JCconstants', MagicMock())
sys.modules.setdefault('pysatochip.util', MagicMock())
sys.modules.setdefault('pysatochip.CardConnector', MagicMock())
sys.modules.setdefault('smbus2', MagicMock())
sys.modules.setdefault('smartcard', MagicMock())
sys.modules.setdefault('smartcard.System', MagicMock())

# Provide a dummy BatteryHat implementation used by the controller
class DummyBatteryHat(MagicMock):
    @classmethod
    def get_instance(cls):
        if not hasattr(cls, '_instance'):
            cls._instance = cls()
            cls._instance.is_alive.return_value = False
        return cls._instance

    @classmethod
    def reset_instance(cls):
        cls._instance = None

    def initialize(self):
        return True

    def is_enabled(self):
        return True

    def start(self):
        pass
    def stop(self):
        pass
    def join(self, *a, **k):
        pass
    def get_percent(self):
        return None

sys.modules['seedsigner.hardware.battery_hat'] = MagicMock(BatteryHat=DummyBatteryHat)
