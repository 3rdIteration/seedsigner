import pytest

from seedsigner.views import tools_views


def test_system_entropy_salt_handles_missing_getloadavg(monkeypatch):
    monkeypatch.delattr(tools_views.os, "getloadavg", raising=False)

    salt = tools_views._system_entropy_salt()

    assert isinstance(salt, bytes)
    assert len(salt) > 0


def test_derive_system_rng_entropy_rejects_low_entropy_rng(monkeypatch):
    monkeypatch.setattr(tools_views, "_read_secure_rng_bytes", lambda n=64: b"\x00" * n)

    with pytest.raises(ValueError, match="System RNG entropy too low"):
        tools_views._derive_hardware_rng_entropy_bytes()


def test_derive_system_rng_entropy_rejects_bad_final_output(monkeypatch):
    monkeypatch.setattr(tools_views, "_read_secure_rng_bytes", lambda n=64: bytes(range(n)))

    class _FakeHash:
        def digest(self):
            return b"\xAA" * 32

    monkeypatch.setattr(tools_views.hashlib, "sha256", lambda _: _FakeHash())

    with pytest.raises(ValueError, match="derived entropy failed health checks"):
        tools_views._derive_hardware_rng_entropy_bytes()
