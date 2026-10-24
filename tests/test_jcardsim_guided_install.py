"""
    The guided-install and PIN-retry paths of ``init_satochip``, against real applet
    bytecode in jcardsim and SeedSigner's real pysatochip client.

    jcardsim has no GlobalPlatform card manager, so the install itself cannot run here
    (``install_applet_cap`` is covered with a fake pygp in test_smartcard_guided_install).
    Everything either side of it does: the SELECT-only probe, the wrong-card refusal,
    the blank-applet PIN setup that follows an install, and re-entering a wrong PIN
    against the status words and exceptions the applet and pysatochip really produce.
"""

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401

# base.py replaces pysatochip with MagicMocks so the ordinary suite can run without a
# card. These tests need the real library, so drop the stubs before anything imports it.
for _name in [m for m in sys.modules if m == "pysatochip" or m.startswith("pysatochip.")]:
    if isinstance(sys.modules[_name], MagicMock):
        del sys.modules[_name]

from jcardsim import JCardSimUnavailable, SimulatedCard, resolve_applet, why_unavailable
from jcardsim.pcsc_shim import patched_pcsc


pytestmark = pytest.mark.skipif(
    why_unavailable() is not None, reason=f"jcardsim unavailable: {why_unavailable()}"
)


def _reload_seedkeeper_utils():
    """seedkeeper_utils may have bound the pysatochip stubs at import; rebind it."""
    import importlib
    from seedsigner.helpers import seedkeeper_utils
    return importlib.reload(seedkeeper_utils)


@pytest.fixture
def seedkeeper_utils(monkeypatch):
    utils = _reload_seedkeeper_utils()

    class NoLoadingScreen:
        def __init__(self, *a, **k):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(utils, "LoadingScreenThread", NoLoadingScreen)
    yield utils
    _reload_seedkeeper_utils()


def simulated(applet_name):
    try:
        spec, classes = resolve_applet(applet_name)
    except JCardSimUnavailable as exc:
        pytest.skip(str(exc))
    return SimulatedCard(spec, classes)


def make_view(responses=()):
    screens = []
    replies = iter(responses)

    def run_screen(screen_cls, **kwargs):
        screens.append(kwargs.get("title"))
        return next(replies, 0)

    controller = SimpleNamespace(
        Satochip_Connector=None,
        smartcard_backend_preference="pysatochip",
        Satochip_PIN=None,
        Satochip_Last_UID_SHA1=None,
        javacard_keys=None,
    )
    return SimpleNamespace(controller=controller, run_screen=run_screen, screens=screens)


def queue(monkeypatch, utils, name, values):
    asked = []
    replies = iter(values)

    def prompt(view, title, **kwargs):
        asked.append(title)
        return next(replies)

    monkeypatch.setattr(utils, name, prompt)
    return asked


def test_probe_identifies_simulated_applet(seedkeeper_utils):
    with simulated("seedkeeper_v02") as card, patched_pcsc(card):
        reader, found = seedkeeper_utils.probe_card_applets()
    assert found == {"satochip": False, "seedkeeper": True, "satodime": False}


def test_satochip_in_seedkeeper_flow_is_named_not_installed_over(monkeypatch, seedkeeper_utils):
    installs = []
    monkeypatch.setattr(seedkeeper_utils, "install_applet_cap", lambda *a, **k: installs.append(a))
    # On real PC/SC, pysatochip's insert observer SELECTs only the filtered applet and
    # drops the card when that fails, so connecting raises. The shim hands pysatochip
    # the card without that SELECT, so reproduce the real failure here; the probe and
    # the offer then run for real against the simulated Satochip.
    monkeypatch.setattr(seedkeeper_utils, "_init_card_connector",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("Card Initialization must be satisfied")))
    queue(monkeypatch, seedkeeper_utils, "prompt_for_new_pin", [])  # must never be reached
    view = make_view()

    with simulated("satochip") as card, patched_pcsc(card):
        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is None

    assert view.screens == ["Wrong Card"]
    assert installs == []


def test_blank_applet_after_install_goes_straight_to_pin_setup(monkeypatch, seedkeeper_utils):
    """The card the reconnect finds after an install: set up, never asked for an old PIN."""
    real_init = seedkeeper_utils._init_card_connector
    calls = []

    def missing_then_installed(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("Card Initialization must be satisfied")  # applet absent
        return real_init(*args, **kwargs)

    monkeypatch.setattr(seedkeeper_utils, "_init_card_connector", missing_then_installed)
    monkeypatch.setattr(seedkeeper_utils, "offer_missing_applet_install",
                        lambda view, f: seedkeeper_utils.APPLET_OFFER__INSTALLED)
    asked_old = queue(monkeypatch, seedkeeper_utils, "prompt_for_pin", [])
    asked_new = queue(monkeypatch, seedkeeper_utils, "prompt_for_new_pin", ["1234"])
    view = make_view()

    with simulated("seedkeeper_v02") as card, patched_pcsc(card):
        connector = seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"])
        assert connector is not None
        assert connector.card_get_status()[3]["setup_done"]

    assert asked_old == []
    assert asked_new == ["New Card PIN"]
    assert view.controller.Satochip_PIN == list(b"1234")


def test_wrong_pin_from_real_applet_reprompts(monkeypatch, seedkeeper_utils):
    queue(monkeypatch, seedkeeper_utils, "prompt_for_new_pin", ["1234"])
    with simulated("seedkeeper_v02") as card, patched_pcsc(card):
        # Set the card up first, then start a fresh session as a later flow would.
        assert seedkeeper_utils.init_satochip(make_view(), init_card_filter=["seedkeeper"]) is not None

        asked = queue(monkeypatch, seedkeeper_utils, "prompt_for_pin", ["0000", "1234"])
        view = make_view()
        connector = seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"])

    assert connector is not None
    assert asked == ["Card PIN", "Card PIN"]
    assert view.screens == ["Incorrect PIN"]
    assert view.controller.Satochip_PIN == list(b"1234")
