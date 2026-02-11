import pytest

from seedsigner.helpers.globalplatform_native import (
    GlobalPlatformNativeError,
    GlobalPlatformNativeRunner,
)


def test_parse_install_with_create_and_key():
    parsed = GlobalPlatformNativeRunner.parse_command(
        "--key 00112233445566778899AABBCCDDEEFF --install /tmp/a.cap --create d27600012401"
    )
    assert parsed.install_path == "/tmp/a.cap"
    assert parsed.create_aid == "D27600012401"
    assert parsed.key_hex == "00112233445566778899AABBCCDDEEFF"


def test_parse_lock_keys():
    parsed = GlobalPlatformNativeRunner.parse_command(
        "--key default --lock 1111 2222 3333"
    )
    assert parsed.lock_keys == ("1111", "2222", "3333")
    assert parsed.key_hex is None


def test_run_list_formats_pkg_lines(monkeypatch):
    class FakeBackend:
        def list_packages(self, verbose=True):
            return [("A0000001", "App1"), ("A0000002", "App2")]

    monkeypatch.setattr(
        "seedsigner.helpers.globalplatform_native._PyGlobalPlatformBackend", FakeBackend
    )
    output = GlobalPlatformNativeRunner().run("-l -v")
    assert "PKG: A0000001 (|App1|)" in output
    assert "PKG: A0000002 (|App2|)" in output


def test_run_rejects_unsupported_command(monkeypatch):
    class FakeBackend:
        pass

    monkeypatch.setattr(
        "seedsigner.helpers.globalplatform_native._PyGlobalPlatformBackend", FakeBackend
    )
    with pytest.raises(GlobalPlatformNativeError):
        GlobalPlatformNativeRunner().run("--apdu 00A40400")
