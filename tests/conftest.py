import sys
from unittest.mock import MagicMock

import pytest

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
# Only mock smartcard if pyscard isn't installed — otherwise hardware tests
# (test_smartcard_hardware.py) can use the real module via pygp.
try:
    import smartcard  # noqa: F401
except ImportError:
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


@pytest.fixture(scope="session", autouse=True)
def _base_module_single_identity():
    """Ensure tests/base.py executes at most once per pytest process.

    Both `import base` and `import tests.base` load tests/base.py; if both forms
    appear in one run, the second import re-executes the module body under a new
    identity and reinstalls fresh MagicMocks into sys.modules while modules
    imported earlier keep references to the first pass's mocks. That split-brain
    state broke HardwareButtonsConstants identity checks in test_tools_screens.py
    (full-suite runs only). Use `import base` in all test files.
    """
    yield
    base = sys.modules.get("base")
    if base is None:
        return
    tests_base = sys.modules.get("tests.base")
    assert tests_base is None or tests_base is base, (
        "tests/base.py was imported under two module identities ('base' and "
        "'tests.base'); use `import base` in all test files"
    )
