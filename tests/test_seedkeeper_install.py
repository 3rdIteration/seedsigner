from types import SimpleNamespace

from seedsigner.views import tools_views
from seedsigner.hardware import microsd
from seedsigner.helpers import seedkeeper_utils

def test_seedkeeper_install_adds_params(monkeypatch, tmp_path):
    view = object.__new__(tools_views.ToolsDIYInstallAppletView)
    view.settings = SimpleNamespace(get_value=lambda *a, **k: [])
    view.run_screen = lambda *a, **k: 0

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

    view.run()

    assert "--params 1FFF" in captured["cmd"]

