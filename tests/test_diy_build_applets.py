import json

from seedsigner.views import smartcard_views


def test_generate_build_xml_contains_only_safe_elements():
    config = {name: dict(spec) for name, spec in smartcard_views._JAVACARD_APPLETS.items()}
    xml = smartcard_views._generate_javacard_build_xml(
        config, "other", "/tmp/out"
    )

    # Only the trusted build structure is present.
    assert "<project" in xml
    assert "<target" in xml
    assert "<javacard>" in xml
    assert "<cap " in xml
    assert "<applet " in xml

    # No arbitrary/executable tasks may ever be emitted.
    for forbidden in ("<exec", "<script", "<delete", "<copy", "<move", "<import", "<macrodef"):
        assert forbidden not in xml

    # The only taskdef is the trusted ant-javacard.jar.
    assert "ant-javacard.jar" in xml
    # Sources/jckit are the trusted constants, never user-influenced.
    # Normalize path separators so the assertion holds on Windows test runners
    # as well as the Linux devices this actually runs on.
    normalized = xml.replace("\\", "/")
    assert "Satochip-DIY/sdks/jc304_kit" in normalized
    assert "Satochip-DIY/applets/satochip/src/org/satochip/applet" in normalized


def test_generate_build_xml_honors_validated_overrides():
    config = {
        "satochip": {
            "sources_rel": smartcard_views._JAVACARD_APPLETS["satochip"]["sources_rel"],
            "applet_class": "org.satochip.applet.CardEdge",
            "aid": "00112233445566778899AABBCCDDEEFF",
            "version": "9.9",
            "out": "SatoChip-built-0.12.cap",
        }
    }
    xml = smartcard_views._generate_javacard_build_xml(config, "other", "/tmp/out")
    assert 'aid="00112233445566778899AABBCCDDEEFF"' in xml
    assert 'version="9.9"' in xml
    # Applet instance AID is package AID + "00".
    assert 'aid="00112233445566778899AABBCCDDEEFF00"' in xml


def test_load_config_defaults_when_no_file(tmp_path):
    config = smartcard_views._load_javacard_build_config(tmp_path)
    assert set(config.keys()) == set(smartcard_views._JAVACARD_APPLETS.keys())


def test_load_config_ignores_malicious_entries(tmp_path):
    malicious = {
        "applets": ["satochip", "totally-unknown-applet"],
        "overrides": {
            "satochip": {
                # Invalid AID (too short) and invalid version must be ignored.
                "aid": "../../../../etc/passwd",
                "version": "not-a-version",
                # Unknown keys must be ignored.
                "sources": "/etc",
                "jckit": "/evil",
            }
        },
        # Unknown top-level keys must be ignored.
        "exec": "rm -rf /",
    }
    (tmp_path / smartcard_views._JAVACARD_BUILD_CONF_FILENAME).write_text(
        json.dumps(malicious), encoding="utf-8"
    )

    config = smartcard_views._load_javacard_build_config(tmp_path)

    # Only known applets are kept; unknown entry is dropped.
    assert "totally-unknown-applet" not in config
    assert "satochip" in config
    # Invalid overrides are NOT applied; trusted defaults remain.
    spec = config["satochip"]
    assert spec["aid"] == smartcard_views._JAVACARD_APPLETS["satochip"]["aid"]
    assert spec["version"] == smartcard_views._JAVACARD_APPLETS["satochip"]["version"]
    assert "sources" not in spec


def test_load_config_applies_valid_overrides(tmp_path):
    conf = {
        "applets": ["seedkeeper"],
        "overrides": {
            "seedkeeper": {
                "aid": "AABBCCDDEEFF00112233445566778899",
                "version": "3.1",
            }
        },
    }
    (tmp_path / smartcard_views._JAVACARD_BUILD_CONF_FILENAME).write_text(
        json.dumps(conf), encoding="utf-8"
    )

    config = smartcard_views._load_javacard_build_config(tmp_path)
    assert set(config.keys()) == {"seedkeeper"}
    assert config["seedkeeper"]["aid"] == "AABBCCDDEEFF00112233445566778899"
    assert config["seedkeeper"]["version"] == "3.1"


def test_build_view_never_runs_sudo_or_user_xml(monkeypatch, tmp_path):
    import subprocess

    from seedsigner.hardware import microsd as microsd_mod

    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = list(cmd)
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="BUILD SUCCESSFUL", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(microsd_mod.MicroSD, "get_microsd_dir", lambda: tmp_path)

    # A malicious javacard-build.xml sitting on the card must be inert.
    (tmp_path / "javacard-build.xml").write_text(
        '<project><target name="build"><exec executable="/bin/rm"/></target></project>',
        encoding="utf-8",
    )

    class FakeLoadingScreen:
        def __init__(self, *a, **k):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    import seedsigner.gui.screens.screen as screen_mod

    monkeypatch.setattr(screen_mod, "LoadingScreenThread", FakeLoadingScreen)

    view = object.__new__(smartcard_views.ToolsDIYBuildAppletsView)
    view.run_screen = lambda *a, **k: None
    view.run()

    cmd = captured["cmd"]
    # No sudo, and we never point ANT at a user-supplied microSD build file.
    assert "sudo" not in cmd
    assert str(tmp_path / "javacard-build.xml") not in cmd
    # The -f argument must be a generated temp file, not the microSD path.
    f_index = cmd.index("-f")
    build_arg = cmd[f_index + 1]
    assert build_arg != str(tmp_path / "javacard-build.xml")
    assert "javacard-build.xml" not in build_arg or build_arg.startswith(str(tmp_path))
