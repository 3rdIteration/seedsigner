import pytest

from seedsigner.helpers import seedkeeper_utils


class DummyConnector:
    pass


def test_init_card_connector_prefers_keycard_when_forced(monkeypatch):
    monkeypatch.setenv("SEEDSIGNER_SMARTCARD_BACKEND", "keycard")

    called = {}

    def mock_create(card_filter=None):
        called["filter"] = card_filter
        return DummyConnector()

    monkeypatch.setattr(seedkeeper_utils.KeycardSatochipConnector, "create", mock_create)

    connector = seedkeeper_utils._init_card_connector(["satochip"])

    assert isinstance(connector, DummyConnector)
    assert called["filter"] == ["satochip"]


def test_init_card_connector_auto_falls_back_to_keycard(monkeypatch):
    monkeypatch.setenv("SEEDSIGNER_SMARTCARD_BACKEND", "auto")
    monkeypatch.setattr(
        seedkeeper_utils,
        "_init_legacy_connector",
        lambda init_card_filter: (_ for _ in ()).throw(RuntimeError("legacy failed")),
    )
    monkeypatch.setattr(
        seedkeeper_utils.KeycardSatochipConnector,
        "create",
        lambda card_filter=None: DummyConnector(),
    )

    connector = seedkeeper_utils._init_card_connector(["satochip"])
    assert isinstance(connector, DummyConnector)


def test_init_card_connector_auto_keeps_legacy_error_for_non_satochip(monkeypatch):
    monkeypatch.setenv("SEEDSIGNER_SMARTCARD_BACKEND", "auto")
    monkeypatch.setattr(
        seedkeeper_utils,
        "_init_legacy_connector",
        lambda init_card_filter: (_ for _ in ()).throw(RuntimeError("legacy failed")),
    )

    with pytest.raises(RuntimeError, match="legacy failed"):
        seedkeeper_utils._init_card_connector(["seedkeeper"])


def test_init_card_connector_respects_explicit_backend_preference(monkeypatch):
    monkeypatch.setenv("SEEDSIGNER_SMARTCARD_BACKEND", "auto")

    called = {}

    def mock_create(card_filter=None):
        called["filter"] = card_filter
        return DummyConnector()

    monkeypatch.setattr(seedkeeper_utils.KeycardSatochipConnector, "create", mock_create)

    connector = seedkeeper_utils._init_card_connector(
        ["satochip"],
        backend_preference="keycard",
    )

    assert isinstance(connector, DummyConnector)
    assert called["filter"] == ["satochip"]


def test_keycard_connector_uses_default_pairing_password(monkeypatch):
    from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

    monkeypatch.delenv("SEEDSIGNER_KEYCARD_PAIRING_PASSWORD", raising=False)

    created = {}

    class MockTransport:
        def connect(self):
            return None

        def disconnect(self):
            return None

    class MockInner:
        def __init__(self):
            self.transport = MockTransport()

        def select(self):
            return type("Info", (), {"instance_uid": b""})

    class MockConstants:
        class PairingMode:
            EPHEMERAL = 1

    MockConnectorCls = (MockInner, MockConstants)
    monkeypatch.setattr(
        "seedsigner.helpers.keycard_connector.get_keycard_class",
        lambda: MockConnectorCls,
    )

    connector = KeycardSatochipConnector.create(card_filter=["satochip"])
    created["pairing_password"] = connector._pairing_password

    assert created["pairing_password"] == KeycardSatochipConnector.DEFAULT_PAIRING_PASSWORD


def test_keycard_connector_env_var_overrides_default_pairing_password(monkeypatch):
    from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

    monkeypatch.setenv("SEEDSIGNER_KEYCARD_PAIRING_PASSWORD", "custom-secret")

    created = {}

    class MockTransport:
        def connect(self):
            return None

        def disconnect(self):
            return None

    class MockInner:
        def __init__(self):
            self.transport = MockTransport()

        def select(self):
            return type("Info", (), {"instance_uid": b""})

    class MockConstants:
        class PairingMode:
            EPHEMERAL = 1

    monkeypatch.setattr(
        "seedsigner.helpers.keycard_connector.get_keycard_class",
        lambda: (MockInner, MockConstants),
    )

    connector = KeycardSatochipConnector.create(card_filter=["satochip"])
    created["pairing_password"] = connector._pairing_password

    assert created["pairing_password"] == "custom-secret"
