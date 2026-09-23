import sys
from unittest.mock import MagicMock

import pytest

# Mock hardware-dependent modules so unit tests can run without them
sys.modules.setdefault('RPi', MagicMock())
sys.modules.setdefault('RPi.GPIO', MagicMock())
# Only mock pyzbar if it cannot really be imported (e.g. the native zbar library is
# missing). A blanket MagicMock makes DecodeQR.is_qr_scanner_available() lie -- it
# reports "available" while extract_qr_data() silently decodes nothing, which breaks
# any test that exercises real QR decoding (see test_real_screen_flows_satodime_simulated.py).
try:
    from pyzbar import pyzbar  # noqa: F401
except Exception:
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


def pytest_report_header(config):
    """
    Print the jcardsim preconditions and the runner's RAM at the top of the run.

    Every simulated card is a JVM, so how much RAM is free decides whether the applet
    suites run or skip; reporting it once is clearer than inferring it from mid-run skips.
    """
    try:
        from jcardsim.simulator import (
            available_ram_mb,
            min_free_ram_mb,
            total_ram_mb,
            why_unavailable,
        )
    except Exception as exc:  # test-support import only; never break collection
        return f"jcardsim: unavailable ({exc})"

    reason = why_unavailable()
    if reason:
        return f"jcardsim: unavailable ({reason})"

    available = available_ram_mb()
    guard = min_free_ram_mb()
    if available is None:
        return f"jcardsim: available (free RAM unknown, JVM guard {guard}MB)"

    total = total_ram_mb()
    total_str = f" of {total}MB" if total is not None else ""
    note = " -- below guard, JVM tests will skip" if available < guard else ""
    return f"jcardsim: available ({available}MB free{total_str}, JVM guard {guard}MB){note}"


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """
    Report "the simulator cannot run here" as a skip wherever it is raised.

    jcardsim's SimulatedCard refuses to start under memory pressure and raises
    JCardSimUnavailable. That happens inside a fixture or a context manager's __enter__ --
    outside the test's own try/except -- so it would otherwise be a hard failure even
    though the suite is designed to skip when the simulator is unavailable (AGENTS.md).
    """
    outcome = yield
    report = outcome.get_result()
    if report.outcome != "failed" or call.excinfo is None:
        return

    from jcardsim import JCardSimUnavailable

    if not call.excinfo.errisinstance(JCardSimUnavailable):
        return

    report.outcome = "skipped"
    report.longrepr = (str(item.fspath), 0, str(call.excinfo.value))


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
