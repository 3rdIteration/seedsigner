"""
Regression tests for the PyGP BaseException crash.

PyGP <=0.2a raised bare ``BaseException`` from every card operation. Since
``except Exception`` does not catch ``BaseException``, a routine card error
(no card seated, wrong key, flaky reader) escaped the view's handler, escaped
the Controller loop, and killed the process -- the user saw a black screen with
no message and no log.

These tests deliberately raise ``BaseException``, the original broken type, so
they keep proving the views are defensive no matter what PyGP raises next.
"""

import sys
from types import SimpleNamespace

import pytest

from seedsigner.views import smartcard_views
from seedsigner.helpers import seedkeeper_utils


CARD_ERROR = "Failed to connect, please check the card."


class SpyLoadingScreen:
    """Stand-in for LoadingScreenThread that records start/stop calls."""

    instances = []

    def __init__(self, text=None):
        self.text = text
        self.started = False
        self.stopped = False
        SpyLoadingScreen.instances.append(self)

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()
        return False


class FakePyGP:
    """Fake pygp module whose named methods raise bare BaseException."""

    SECURITY_LEVEL_C_MAC = 1
    SECURITY_LEVEL_C_DEC_C_MAC = 3

    def __init__(self, failing, packages=None):
        self.failing = set(failing)
        self._packages = packages if packages is not None else ["536565644B6565706572"]

    def _maybe_fail(self, name):
        if name in self.failing:
            raise BaseException(CARD_ERROR)

    def terminal(self):
        self._maybe_fail("terminal")

    def card(self):
        self._maybe_fail("card")

    def auth(self, **kwargs):
        self._maybe_fail("auth")

    def get_loaded_package_aids(self):
        self._maybe_fail("get_loaded_package_aids")
        return list(self._packages)

    def get_package_module_map(self):
        self._maybe_fail("get_package_module_map")
        return {}

    def get_installed_application_aids(self):
        self._maybe_fail("get_installed_application_aids")
        return []

    def delete_package(self, aid):
        self._maybe_fail("delete_package")

    def install_capfile(self, *args, **kwargs):
        self._maybe_fail("install_capfile")
        return {}

    def get_cap_info(self, path):
        self._maybe_fail("get_cap_info")
        return SimpleNamespace(get_aid=lambda: "AABBCC")


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    SpyLoadingScreen.instances = []
    monkeypatch.setattr(
        "seedsigner.gui.screens.screen.LoadingScreenThread", SpyLoadingScreen
    )
    monkeypatch.setattr(
        smartcard_views,
        "logger",
        SimpleNamespace(
            info=lambda *a, **k: None,
            warning=lambda *a, **k: None,
            error=lambda *a, **k: None,
        ),
    )
    monkeypatch.setattr(seedkeeper_utils, "restart_pn532", lambda *a, **k: None)


def _make_uninstall_view(monkeypatch, fake, screens):
    view = object.__new__(smartcard_views.ToolsDIYUninstallAppletView)
    view.settings = SimpleNamespace(get_value=lambda *a, **k: [])
    view.controller = SimpleNamespace(javacard_keys=None)
    monkeypatch.setitem(sys.modules, "pygp", fake)

    def fake_run_screen(screen_cls, **kwargs):
        screens.append((screen_cls.__name__, kwargs))
        return 0

    view.run_screen = fake_run_screen
    return view


@pytest.mark.parametrize("failing_call", ["terminal", "card", "get_loaded_package_aids"])
def test_uninstall_survives_baseexception_while_listing(monkeypatch, failing_call):
    """A card error while listing applets must show a screen, not propagate."""
    screens = []
    view = _make_uninstall_view(monkeypatch, FakePyGP(failing=[failing_call]), screens)

    # Must not raise -- this is the crash being regression-tested.
    destination = view.run()

    assert destination is not None
    titles = [kwargs.get("title") for _, kwargs in screens]
    assert "Smartcard Error" in titles, f"no error screen shown; got {titles}"

    # And the spinner must not be left running.
    assert all(s.stopped for s in SpyLoadingScreen.instances if s.started)


def test_uninstall_survives_baseexception_on_delete(monkeypatch):
    """A card error during the actual delete must show 'Failed', not propagate."""
    screens = []
    view = _make_uninstall_view(monkeypatch, FakePyGP(failing=["delete_package"]), screens)

    destination = view.run()

    assert destination is not None
    titles = [kwargs.get("title") for _, kwargs in screens]
    assert "Failed" in titles, f"no failure screen shown; got {titles}"
    assert "Success" not in titles

    # The delete block previously had no `finally`, so the spinner leaked while
    # still holding the renderer lock.
    assert all(s.stopped for s in SpyLoadingScreen.instances if s.started)


def test_uninstall_never_returns_silently(monkeypatch):
    """
    Listing failing non-fatally used to leave package_aids AND error_message
    both None, so the view returned to the menu having shown nothing at all.
    """
    screens = []
    view = _make_uninstall_view(
        monkeypatch, FakePyGP(failing=["get_loaded_package_aids"]), screens
    )

    view.run()

    assert screens, "view returned to the menu without showing anything"


def _make_install_view(monkeypatch, tmp_path, fake, screens):
    from seedsigner.hardware import microsd

    cap_dir = tmp_path / "javacard-cap"
    cap_dir.mkdir()
    (cap_dir / "SeedKeeper-v0.2.cap").touch()
    monkeypatch.setattr(
        smartcard_views, "_get_internal_cap_dir", lambda: tmp_path / "nonexistent"
    )
    monkeypatch.setattr(microsd.MicroSD, "get_microsd_dir", lambda: tmp_path)

    view = object.__new__(smartcard_views.ToolsDIYInstallAppletView)
    view.settings = SimpleNamespace(get_value=lambda *a, **k: [])
    view.controller = SimpleNamespace(javacard_keys=None)
    monkeypatch.setitem(sys.modules, "pygp", fake)

    responses = iter([0, 1])

    def fake_run_screen(screen_cls, **kwargs):
        screens.append((screen_cls.__name__, kwargs))
        try:
            return next(responses)
        except StopIteration:
            return 0

    view.run_screen = fake_run_screen
    return view


def test_install_survives_baseexception(monkeypatch, tmp_path):
    """The install view must report a card error rather than propagating."""
    screens = []
    view = _make_install_view(
        monkeypatch, tmp_path, FakePyGP(failing=["install_capfile"]), screens
    )

    destination = view.run()

    assert destination is not None
    titles = [kwargs.get("title") for _, kwargs in screens]
    assert "Failed" in titles, f"no failure screen shown; got {titles}"


def test_install_rollback_does_not_raise_unbound_local(monkeypatch, tmp_path):
    """
    The rollback path references cap_path, which is only bound once an applet
    file has been chosen. A failure before that point must still report the real
    error instead of raising UnboundLocalError.
    """

    class EarlyFail(FakePyGP):
        def card(self):
            raise BaseException("SCARD_E_NOT_TRANSACTED")

    screens = []
    view = _make_install_view(monkeypatch, tmp_path, EarlyFail(failing=[]), screens)

    destination = view.run()

    assert destination is not None
    texts = [str(kwargs.get("text", "")) for _, kwargs in screens]
    assert not any("UnboundLocalError" in t for t in texts)
