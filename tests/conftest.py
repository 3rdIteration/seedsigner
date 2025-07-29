import os
import sys
from pathlib import Path
from subprocess import Popen
import time
import pytest
from unittest.mock import MagicMock


def pytest_addoption(parser):
    parser.addoption(
        "--use-jcardsim",
        action="store_true",
        default=False,
        help="Run tests using jCardSim instead of mocking pysatochip and smartcard",
    )


def pytest_configure(config):
    use_jcardsim = config.getoption("--use-jcardsim") or os.environ.get("USE_JCARDSIM")

    if not use_jcardsim:
        # Mock hardware-dependent modules so unit tests can run without them
        for name in [
            'RPi',
            'RPi.GPIO',
            'pyzbar',
            'pyzbar.pyzbar',
            'pysatochip',
            'pysatochip.JCconstants',
            'pysatochip.util',
            'pysatochip.CardConnector',
            'smbus2',
            'smartcard',
            'smartcard.System',
        ]:
            sys.modules.setdefault(name, MagicMock())

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

        def start(self):
            pass
        def stop(self):
            pass
        def join(self, *a, **k):
            pass
        def get_percent(self):
            return None

    sys.modules['seedsigner.hardware.battery_hat'] = MagicMock(BatteryHat=DummyBatteryHat)


@pytest.fixture(scope="session")
def jcardsim_emulator(pytestconfig):
    """Start jCardSim emulator if requested."""

    use_jcardsim = pytestconfig.getoption("--use-jcardsim") or os.environ.get("USE_JCARDSIM")
    if not use_jcardsim:
        pytest.skip("jcardsim emulator not enabled")

    jar = os.environ.get("JCARDSIM_JAR", "jcardsim.jar")
    cap_path = Path(__file__).resolve().parents[1] / "tools" / "javacard-cap" / "SeedKeeper.cap"

    # Start local pcscd so pyscard can connect
    pcscd = Popen(["pcscd", "-f"])
    time.sleep(1)

    jproc = Popen(["java", "-jar", jar, str(cap_path)])

    try:
        from smartcard.System import readers
        timeout = time.time() + 20
        while time.time() < timeout:
            if readers():
                break
            if jproc.poll() is not None:
                raise RuntimeError("jCardSim terminated early")
            time.sleep(0.5)
        else:
            jproc.terminate()
            jproc.wait()
            raise RuntimeError("Timeout waiting for jCardSim")

        yield jproc
    finally:
        jproc.terminate()
        jproc.wait()
        pcscd.terminate()
        pcscd.wait()
