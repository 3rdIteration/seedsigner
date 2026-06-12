from types import SimpleNamespace

from seedsigner.views import tools_views
from seedsigner.hardware import microsd
from seedsigner.helpers import seedkeeper_utils
import sys

def test_seedkeeper_install_defaults_to_8k(monkeypatch, tmp_path):
    view = object.__new__(tools_views.ToolsDIYInstallAppletView)
    view.settings = SimpleNamespace(get_value=lambda *a, **k: [])

    cap_dir = tmp_path / "javacard-cap"
    cap_dir.mkdir()
    (cap_dir / "SeedKeeper-v0.2.cap").touch()

    monkeypatch.setattr(microsd.MicroSD, "get_microsd_dir", lambda: tmp_path)

    captured = {}
    storage_screen_kwargs = {}

    class FakePyGP:
        SECURITY_LEVEL_C_MAC = 1
        def terminal(self): pass
        def card(self): pass
        def auth(self, **kwargs): pass
        def install_capfile(self, *args, **kwargs):
            captured["cmd"] = kwargs.get("application_specific_parameters")
            return []
    
    monkeypatch.setitem(sys.modules, "pygp", FakePyGP())
    monkeypatch.setattr(tools_views, "logger", SimpleNamespace(info=lambda *a, **k: print(*a), warning=lambda *a, **k: print(*a), error=lambda *a, **k: print(*a)))

    responses = iter([0, 1])

    def fake_run_screen(*args, **kwargs):
        try:
            response = next(responses)
        except StopIteration:
            response = 0

        if "button_data" in kwargs and any(
            option.button_label.endswith("(default)") for option in kwargs["button_data"]
        ):
            storage_screen_kwargs.update(kwargs)

        return response

    view.run_screen = fake_run_screen

    view.run()

    assert captured["cmd"] == "1FFF"
    assert storage_screen_kwargs.get("selected_button") == 1

    storage_labels = [option.button_label for option in storage_screen_kwargs.get("button_data", [])]
    assert "64 KB" in storage_labels
    assert "128 KB" not in storage_labels


def test_seedkeeper_install_respects_selected_storage(monkeypatch, tmp_path):
    view = object.__new__(tools_views.ToolsDIYInstallAppletView)
    view.settings = SimpleNamespace(get_value=lambda *a, **k: [])

    cap_dir = tmp_path / "javacard-cap"
    cap_dir.mkdir()
    (cap_dir / "SeedKeeper-v0.2.cap").touch()

    monkeypatch.setattr(microsd.MicroSD, "get_microsd_dir", lambda: tmp_path)

    captured = {}

    class FakePyGP:
        SECURITY_LEVEL_C_MAC = 1
        def terminal(self): pass
        def card(self): pass
        def auth(self, **kwargs): pass
        def install_capfile(self, *args, **kwargs):
            captured["cmd"] = kwargs.get("application_specific_parameters")
            return []
    
    monkeypatch.setitem(sys.modules, "pygp", FakePyGP())
    monkeypatch.setattr(tools_views, "logger", SimpleNamespace(info=lambda *a, **k: print(*a), warning=lambda *a, **k: print(*a), error=lambda *a, **k: print(*a)))

    responses = iter([0, 3])

    def fake_run_screen(*args, **kwargs):
        try:
            return next(responses)
        except StopIteration:
            return 0

    view.run_screen = fake_run_screen

    view.run()

    assert captured["cmd"] == "7FFF"


def test_seedkeeper_install_supports_largest_storage(monkeypatch, tmp_path):
    view = object.__new__(tools_views.ToolsDIYInstallAppletView)
    view.settings = SimpleNamespace(get_value=lambda *a, **k: [])

    cap_dir = tmp_path / "javacard-cap"
    cap_dir.mkdir()
    (cap_dir / "SeedKeeper-v0.2.cap").touch()

    monkeypatch.setattr(microsd.MicroSD, "get_microsd_dir", lambda: tmp_path)

    captured = {}

    class FakePyGP:
        SECURITY_LEVEL_C_MAC = 1
        def terminal(self): pass
        def card(self): pass
        def auth(self, **kwargs): pass
        def install_capfile(self, *args, **kwargs):
            captured["cmd"] = kwargs.get("application_specific_parameters")
            return []
    
    monkeypatch.setitem(sys.modules, "pygp", FakePyGP())
    monkeypatch.setattr(tools_views, "logger", SimpleNamespace(info=lambda *a, **k: print(*a), warning=lambda *a, **k: print(*a), error=lambda *a, **k: print(*a)))

    responses = iter([0, 4])

    def fake_run_screen(*args, **kwargs):
        try:
            return next(responses)
        except StopIteration:
            return 0

    view.run_screen = fake_run_screen

    view.run()

    assert captured["cmd"] == "FFFF"

