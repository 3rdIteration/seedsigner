from types import SimpleNamespace

import pytest

from seedsigner.helpers import seedkeeper_utils
from seedsigner.helpers.keycard_connector import KeycardSatochipConnector


class MockTransport:
    def connect(self):
        return None

    def disconnect(self):
        return None


class MockConstants:
    class PairingMode:
        EPHEMERAL = 1


def _make_connector(monkeypatch, inner_cls):
    monkeypatch.setattr(
        "seedsigner.helpers.keycard_connector.get_keycard_class",
        lambda: (inner_cls, MockConstants),
    )
    return KeycardSatochipConnector.create(card_filter=["satochip"])


def _card_setup(connector, **kwargs):
    return connector.card_setup(
        5,
        1,
        list(b"123456"),
        list(range(16)),
        1,
        1,
        list(range(16)),
        list(range(16)),
        32,
        0,
        1,
        1,
        1,
        **kwargs,
    )


def test_card_setup_passes_duress_pin_to_init(monkeypatch):
    captured = {}

    class MockInner:
        def __init__(self):
            self.transport = MockTransport()

        def select(self):
            return type("Info", (), {"instance_uid": b""})

        def init(self, pin, puk, pairing_secret, duress_pin=None, pin_limit=None):
            captured["pin"] = pin
            captured["duress_pin"] = duress_pin
            captured["pin_limit"] = pin_limit

    connector = _make_connector(monkeypatch, MockInner)
    response, sw1, sw2 = _card_setup(connector, duress_pin="654321")

    assert (response, sw1, sw2) == ([], 0x90, 0x00)
    assert captured["pin"] == "123456"
    assert captured["duress_pin"] == "654321"
    # pin_tries_0 (5) is forwarded as the PIN retry limit
    assert captured["pin_limit"] == 5


def test_card_setup_without_duress_uses_plain_init(monkeypatch):
    captured = {}

    class MockInner:
        def __init__(self):
            self.transport = MockTransport()

        def select(self):
            return type("Info", (), {"instance_uid": b""})

        def init(self, pin, puk, pairing_secret):
            captured["args"] = (pin, puk)

    connector = _make_connector(monkeypatch, MockInner)
    response, sw1, sw2 = _card_setup(connector)

    assert (response, sw1, sw2) == ([], 0x90, 0x00)
    assert captured["args"][0] == "123456"


def test_card_setup_rejects_duress_pin_equal_to_main_pin(monkeypatch):
    class MockInner:
        def __init__(self):
            self.transport = MockTransport()

        def select(self):
            return type("Info", (), {"instance_uid": b""})

        def init(self, *args, **kwargs):
            raise AssertionError("init should not be reached")

    connector = _make_connector(monkeypatch, MockInner)
    with pytest.raises(ValueError, match="differ from the main PIN"):
        _card_setup(connector, duress_pin="123456")


def test_card_setup_rejects_invalid_duress_pin(monkeypatch):
    class MockInner:
        def __init__(self):
            self.transport = MockTransport()

        def select(self):
            return type("Info", (), {"instance_uid": b""})

        def init(self, *args, **kwargs):
            raise AssertionError("init should not be reached")

    connector = _make_connector(monkeypatch, MockInner)
    with pytest.raises(ValueError, match="exactly 6 digits"):
        _card_setup(connector, duress_pin="12345")


def test_card_setup_reports_outdated_keycard_py(monkeypatch):
    class MockInner:
        def __init__(self):
            self.transport = MockTransport()

        def select(self):
            return type("Info", (), {"instance_uid": b""})

        def init(self, pin, puk, pairing_secret):
            raise AssertionError("should be called with duress kwargs")

    connector = _make_connector(monkeypatch, MockInner)
    with pytest.raises(ValueError, match="update keycard-py"):
        _card_setup(connector, duress_pin="654321")


def _patch_pin_screens(monkeypatch, entries):
    """Feed successive PIN entries to prompt_for_pin and swallow warnings."""
    entry_iter = iter(entries)

    class FakeScreen:
        def __init__(self, title=None, **kwargs):
            self.title = title

        def display(self):
            value = next(entry_iter)
            if value is None:
                return {"is_back_button": True}
            return {"passphrase": value}

    monkeypatch.setattr(
        seedkeeper_utils, "seed_screens", SimpleNamespace(SeedAddPassphraseScreen=FakeScreen)
    )


def test_prompt_for_new_pin_requires_matching_confirmation(monkeypatch):
    _patch_pin_screens(monkeypatch, ["123456", "654321", "123456", "123456"])
    warnings = []
    parent = SimpleNamespace(run_screen=lambda *a, **k: warnings.append(k.get("title", "")) or 0)

    result = seedkeeper_utils.prompt_for_new_pin(
        parent, "New Card PIN", numeric_only=True, exact_length=6
    )

    assert result == "123456"
    assert "PIN Mismatch" in warnings


def test_prompt_for_new_pin_back_button_aborts(monkeypatch):
    _patch_pin_screens(monkeypatch, ["123456", None])
    parent = SimpleNamespace(run_screen=lambda *a, **k: 0)

    result = seedkeeper_utils.prompt_for_new_pin(
        parent, "New Card PIN", numeric_only=True, exact_length=6
    )

    assert result is None
