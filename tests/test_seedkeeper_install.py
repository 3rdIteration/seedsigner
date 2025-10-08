from types import SimpleNamespace

from seedsigner.views import tools_views
from seedsigner.hardware import microsd
from seedsigner.helpers import seedkeeper_utils

def test_seedkeeper_install_defaults_to_8k(monkeypatch, tmp_path):
    view = object.__new__(tools_views.ToolsDIYInstallAppletView)
    view.settings = SimpleNamespace(get_value=lambda *a, **k: [])

    cap_dir = tmp_path / "javacard-cap"
    cap_dir.mkdir()
    (cap_dir / "SeedKeeper-v0.2.cap").touch()

    monkeypatch.setattr(microsd.MicroSD, "get_microsd_dir", lambda: tmp_path)

    captured = {}
    storage_screen_kwargs = {}

    def fake_run_globalplatform(self_obj, command, loadingText, successtext):
        captured["cmd"] = command
        return "ok"

    monkeypatch.setattr(seedkeeper_utils, "run_globalplatform", fake_run_globalplatform)
    monkeypatch.setattr(tools_views, "logger", SimpleNamespace(info=lambda *a, **k: None))

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

    assert "--params 1FFF" in captured["cmd"]
    assert storage_screen_kwargs.get("selected_button") == 1

    storage_labels = [option.button_label for option in storage_screen_kwargs.get("button_data", [])]
    assert "64 KB" in storage_labels
    assert "128 KB" in storage_labels


def test_seedkeeper_install_respects_selected_storage(monkeypatch, tmp_path):
    view = object.__new__(tools_views.ToolsDIYInstallAppletView)
    view.settings = SimpleNamespace(get_value=lambda *a, **k: [])

    cap_dir = tmp_path / "javacard-cap"
    cap_dir.mkdir()
    (cap_dir / "SeedKeeper-v0.2.cap").touch()

    monkeypatch.setattr(microsd.MicroSD, "get_microsd_dir", lambda: tmp_path)

    captured = {}

    def fake_run_globalplatform(self_obj, command, loadingText, successtext):
        captured["cmd"] = command
        return "ok"

    monkeypatch.setattr(seedkeeper_utils, "run_globalplatform", fake_run_globalplatform)
    monkeypatch.setattr(tools_views, "logger", SimpleNamespace(info=lambda *a, **k: None))

    responses = iter([0, 3])

    def fake_run_screen(*args, **kwargs):
        try:
            return next(responses)
        except StopIteration:
            return 0

    view.run_screen = fake_run_screen

    view.run()

    assert "--params 7FFF" in captured["cmd"]


def test_seedkeeper_install_supports_largest_storage(monkeypatch, tmp_path):
    view = object.__new__(tools_views.ToolsDIYInstallAppletView)
    view.settings = SimpleNamespace(get_value=lambda *a, **k: [])

    cap_dir = tmp_path / "javacard-cap"
    cap_dir.mkdir()
    (cap_dir / "SeedKeeper-v0.2.cap").touch()

    monkeypatch.setattr(microsd.MicroSD, "get_microsd_dir", lambda: tmp_path)

    captured = {}

    def fake_run_globalplatform(self_obj, command, loadingText, successtext):
        captured["cmd"] = command
        return "ok"

    monkeypatch.setattr(seedkeeper_utils, "run_globalplatform", fake_run_globalplatform)
    monkeypatch.setattr(tools_views, "logger", SimpleNamespace(info=lambda *a, **k: None))

    responses = iter([0, 5])

    def fake_run_screen(*args, **kwargs):
        try:
            return next(responses)
        except StopIteration:
            return 0

    view.run_screen = fake_run_screen

    view.run()

    assert "--params 1FFFF" in captured["cmd"]

