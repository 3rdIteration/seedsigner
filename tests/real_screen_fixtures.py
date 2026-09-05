"""
    Shared hardware stand-ins for the real-screen flow suites
    (``test_real_screen_flows*.py``).

    Each of these existed in exactly one test file before; they live here so the
    per-area suites reuse one stand-in rather than growing their own slightly
    different copy. Nothing here mocks a *View* or a *Screen* -- the point of these
    suites is that the real ones run. These only stand in for the things a desktop
    test run genuinely does not have: a smartcard, a microSD card, a camera.

    **The card seam matters.** `satochip_connector()` patches
    ``seedkeeper_utils.init_satochip``, which is the single point every card-backed
    flow goes through. Tests must not reach past it into connector internals: keeping
    that one seam is what lets the backend be swapped later for a jcardsim-backed
    simulator running the real applets, without rewriting any test.
"""

import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

# Must import test base before the Controller (sets up the hardware module mocks)
import base  # noqa: F401


# ---------------------------------------------------------------------------
# Smartcard
# ---------------------------------------------------------------------------

class MockSatochipConnector:
    """
    Spy stand-in for the pysatochip ``CardConnector``.

    Records what the flow asked the card to do so a test can assert on the write
    that matters (or on there having been none), and returns the ``(data, sw1, sw2)``
    shape the real connector returns.
    """

    def __init__(self, needs_2fa=False, label="TestCard", is_seeded=True):
        self.needs_2FA = needs_2fa
        self.card_label = label
        self.is_seeded = is_seeded
        # Call logs, for assertions
        self.set_2fa_calls = []
        self.pin_changes = []
        self.label_changes = []
        self.reset_calls = 0

    def card_set_2FA_key(self, hmacsha160_key, amount_limit=0):
        self.set_2fa_calls.append((hmacsha160_key, amount_limit))
        return (b"", 0x90, 0x00)

    def card_change_PIN(self, pin_nbr, old_pin, new_pin):
        self.pin_changes.append((pin_nbr, old_pin, new_pin))
        return (b"", 0x90, 0x00)

    def card_set_label(self, label):
        self.label_changes.append(label)
        return True

    def card_get_label(self):
        return (b"", 0x90, 0x00, self.card_label)

    def card_reset_factory(self):
        self.reset_calls += 1
        return (b"", 0xFF, 0x00)


@contextmanager
def satochip_connector(monkeypatch, **kwargs):
    """
    Make every card-backed flow talk to a `MockSatochipConnector`.

    Patches the one seam (`seedkeeper_utils.init_satochip`) rather than any
    connector internal -- see the module docstring.
    """
    from seedsigner.helpers import seedkeeper_utils

    connector = MockSatochipConnector(**kwargs)
    monkeypatch.setattr(seedkeeper_utils, "init_satochip", lambda *a, **kw: connector)
    yield connector


@contextmanager
def simulated_satochip(monkeypatch, applet: str = "satochip", setup_pin: str = "1234"):
    """
    Put a *real* Satochip applet behind `init_satochip`, running in jcardsim.

    This is the upgrade `satochip_connector` was written to allow: the flows under test
    are unchanged, but the connector they get is pysatochip talking to actual applet
    bytecode rather than a stand-in returning canned values. Status words, PIN state and
    on-card derivation are all the applet's own.

    Skips (via JCardSimUnavailable) when Java or the applet sources are absent.
    """
    import sys
    from unittest.mock import MagicMock as _MagicMock

    # base.py stubs pysatochip so the ordinary suite runs cardless; we need it real.
    for name in [m for m in sys.modules if m == "pysatochip" or m.startswith("pysatochip.")]:
        if isinstance(sys.modules[name], _MagicMock):
            del sys.modules[name]

    from jcardsim import open_card
    from jcardsim.pcsc_shim import patched_pcsc

    from seedsigner.helpers import seedkeeper_utils

    with open_card(applet) as card:
        card.select()
        with patched_pcsc(card):
            from pysatochip.CardConnector import CardConnector

            connector = CardConnector(card_filter=[applet])
            if setup_pin:
                pin = list(setup_pin.encode())
                connector.card_setup(5, 1, pin, pin, 5, 1, pin, pin, 32, 32, 0x01, 0x01, 0x01)
                connector.set_pin(0, pin)
                connector.card_verify_PIN()

            monkeypatch.setattr(
                seedkeeper_utils, "init_satochip", lambda *a, **kw: connector
            )
            yield connector



class FakePyGP:
    """
    Stand-in for the ``pygp`` native module used by the JavaCard DIY views.

    Reports one installed applet (Satochip) so the uninstall flow reaches its applet
    picker, and accepts every card operation without touching hardware.
    """

    SECURITY_LEVEL_C_MAC = 1

    def terminal(self): pass
    def card(self): pass
    def auth(self, **kwargs): pass
    def get_loaded_package_aids(self): return ["5361746F43686970"]
    def get_package_module_map(self): return {}
    def get_installed_application_aids(self): return []
    def delete_package(self, aid): pass
    def install_capfile(self, *args, **kwargs): return {}
    def get_cap_info(self, path): raise AssertionError("not expected in this flow")


def javacard_diy_patchers(cap_dir=None) -> list:
    """Context managers that let the JavaCard DIY views run without a card."""
    patchers = [
        patch.dict(sys.modules, {"pygp": FakePyGP()}),
        patch("seedsigner.helpers.seedkeeper_utils.restart_pn532"),
    ]
    if cap_dir is not None:
        patchers += [
            patch("seedsigner.views.smartcard_views._get_internal_cap_dir", return_value=cap_dir),
            patch("seedsigner.hardware.microsd.MicroSD.get_microsd_dir", return_value=cap_dir.parent),
        ]
    return patchers


# ---------------------------------------------------------------------------
# microSD
# ---------------------------------------------------------------------------

def use_microsd(monkeypatch, tmp_path: Path) -> Path:
    """Point `MicroSD.get_microsd_dir()` at a real temp directory."""
    from seedsigner.hardware.microsd import MicroSD

    monkeypatch.setattr(MicroSD, "get_microsd_dir", staticmethod(lambda: tmp_path))
    return tmp_path


# ---------------------------------------------------------------------------
# GPG
# ---------------------------------------------------------------------------

def gpg_is_available() -> bool:
    import importlib.util
    import shutil

    return shutil.which("gpg") is not None and importlib.util.find_spec("pgpy") is not None


GPG_AVAILABLE = gpg_is_available()

requires_gpg = pytest.mark.skipif(
    not GPG_AVAILABLE, reason="gpg binary and/or pgpy not available"
)


@pytest.fixture
def gnupghome(monkeypatch):
    """An isolated, *short*-path GNUPGHOME, exported to the environment.

    gpg-agent listens on a unix socket at ``$GNUPGHOME/S.gpg-agent``, so the homedir
    is bound by the ~108 byte ``sun_path`` limit. pytest's ``tmp_path`` blows past
    that on CI runners and gpg then fails every secret-key operation with "failed to
    start gpg-agent ...: General error". Rooting the keyring directly under the system
    temp dir keeps it well inside the limit.
    """
    from test_gpg_message import _msys2_path

    # ignore_cleanup_errors: on Windows a lingering gpg-agent can still hold the
    # keyring open when the test ends.
    with tempfile.TemporaryDirectory(prefix="ss-gnupg-", ignore_cleanup_errors=True) as home:
        home = _msys2_path(home)
        monkeypatch.setenv("GNUPGHOME", home)
        yield home


# ---------------------------------------------------------------------------
# Seed helpers reused across suites
# ---------------------------------------------------------------------------

@contextmanager
def no_shuffle():
    """
    Pin `SeedWordsBackupTestView`'s correct answer to ``button_data[0]``.

    The view shuffles its four candidate words, so without this the right answer sits
    at a random index and `Select()` would have to guess.
    """
    with patch("seedsigner.views.seed_views.random.shuffle", lambda seq: None):
        yield


@contextmanager
def index_screen(return_value):
    """
    Stub `SeedBIP85SelectChildIndexScreen`, which several views instantiate and
    ``.display()`` directly instead of going through ``run_screen()`` -- so FlowTest
    cannot see them and the FlowStep needs ``is_redirect=True``.
    """
    from seedsigner.views import seed_views

    values = return_value if isinstance(return_value, list) else [return_value]
    with patch.object(seed_views.seed_screens, "SeedBIP85SelectChildIndexScreen") as mock:
        mock.return_value.display.side_effect = values
        yield mock
