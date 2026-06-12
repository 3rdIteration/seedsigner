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


def test_keycard_card_setup_normalizes_puk_for_init(monkeypatch):
    from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

    captured = {}

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

        def init(self, pin, puk, pairing_secret):
            captured["pin"] = pin
            captured["puk"] = puk
            captured["pairing_secret"] = pairing_secret

    class MockConstants:
        class PairingMode:
            EPHEMERAL = 1

    monkeypatch.setattr(
        "seedsigner.helpers.keycard_connector.get_keycard_class",
        lambda: (MockInner, MockConstants),
    )

    connector = KeycardSatochipConnector.create(card_filter=["satochip"])
    response, sw1, sw2 = connector.card_setup(
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
    )

    assert (response, sw1, sw2) == ([], 0x90, 0x00)
    assert captured["pin"] == "123456"
    assert len(captured["puk"]) == 12
    assert captured["puk"].isdigit()


def test_show_incorrect_pin_warning_uses_attempts_from_status_word():
    class FakeParent:
        def __init__(self):
            self.calls = []

        def run_screen(self, _screen, **kwargs):
            self.calls.append(kwargs)
            return 0

    parent = FakeParent()

    seedkeeper_utils.show_incorrect_pin_warning(parent, sw1=0x63, sw2=0xC3)

    assert len(parent.calls) == 1
    assert parent.calls[0]["title"] == "Incorrect PIN"
    assert "3 attempts remaining" in parent.calls[0]["text"]


def test_get_pin_attempts_left_reads_connector_status_when_sw_missing():
    class FakeConnector:
        def card_get_status(self):
            return ([], 0x90, 0x00, {"PIN0_remaining_tries": 2})

    attempts = seedkeeper_utils.get_pin_attempts_left(connector=FakeConnector())
    assert attempts == 2


def test_keycard_status_prefers_key_initialized_over_initialized(monkeypatch):
    from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

    class MockTransport:
        def connect(self):
            return None

        def disconnect(self):
            return None

    class MockInner:
        is_initialized = True

        def __init__(self):
            self.transport = MockTransport()
            self.status = {
                "initialized": False,
                "key_initialized": True,
            }
            self.get_key_path = []

        def select(self):
            return type("Info", (), {"instance_uid": b""})

        def pair(self, _pairing_password):
            return (0, b"k" * 32)

        def open_secure_channel(self, _pairing_index, _pairing_key):
            return None

    class MockConstants:
        class PairingMode:
            EPHEMERAL = 1

    monkeypatch.setattr(
        "seedsigner.helpers.keycard_connector.get_keycard_class",
        lambda: (MockInner, MockConstants),
    )

    connector = KeycardSatochipConnector.create(card_filter=["satochip"])
    _resp, sw1, sw2, status = connector.card_get_status()

    assert (sw1, sw2) == (0x90, 0x00)
    assert status["key_initialized"] is True
    assert status["is_seeded"] is True


def test_keycard_status_uses_select_key_uid_as_seeded_signal(monkeypatch):
    from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

    class MockTransport:
        def connect(self):
            return None

        def disconnect(self):
            return None

    class MockInner:
        is_initialized = True

        def __init__(self):
            self.transport = MockTransport()
            self.status = {
                "initialized": False,
                "key_initialized": False,
            }
            self.get_key_path = []

        def select(self):
            return type(
                "Info",
                (),
                {
                    "instance_uid": b"",
                    "key_uid": b"\x01" * 32,
                },
            )

        def pair(self, _pairing_password):
            return (0, b"k" * 32)

        def open_secure_channel(self, _pairing_index, _pairing_key):
            return None

    class MockConstants:
        class PairingMode:
            EPHEMERAL = 1

    monkeypatch.setattr(
        "seedsigner.helpers.keycard_connector.get_keycard_class",
        lambda: (MockInner, MockConstants),
    )

    connector = KeycardSatochipConnector.create(card_filter=["satochip"])
    _resp, sw1, sw2, status = connector.card_get_status()

    assert (sw1, sw2) == (0x90, 0x00)
    assert status["key_initialized"] is True
    assert status["is_seeded"] is True


def test_keycard_import_seed_falls_back_to_extended_ecc_on_6985(monkeypatch):
    from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

    class MockTransport:
        def connect(self):
            return None

        def disconnect(self):
            return None

    class MockInner:
        is_initialized = True

        def __init__(self):
            self.transport = MockTransport()
            self.status = {"PIN0_remaining_tries": 3}
            self.get_key_path = []
            self.load_calls = []

        def select(self):
            return type("Info", (), {"instance_uid": b""})

        def pair(self, _pairing_password):
            return (0, b"k" * 32)

        def open_secure_channel(self, _pairing_index, _pairing_key):
            return None

        def verify_pin(self, _pin_text):
            return True

        def remove_key(self):
            return None

        def load_key(self, key_type, **kwargs):
            self.load_calls.append((key_type, kwargs))

            class SwError(Exception):
                def __init__(self, sw):
                    super().__init__(f"SW={sw:04X}")
                    self.sw = sw

            # Simulate firmware rejecting BIP39 seed import but accepting
            # EXTENDED_ECC import of root key + chain code.
            if key_type == MockConstants.LoadKeyType.BIP39_SEED:
                raise SwError(0x6985)
            return b""

    class MockConstants:
        class PairingMode:
            EPHEMERAL = 1

        class LoadKeyType:
            BIP39_SEED = 3
            EXTENDED_ECC = 2

    monkeypatch.setattr(
        "seedsigner.helpers.keycard_connector.get_keycard_class",
        lambda: (MockInner, MockConstants),
    )

    connector = KeycardSatochipConnector.create(card_filter=["satochip"])
    connector.pin = list(b"123456")
    _resp, sw1, sw2 = connector.card_bip32_import_seed(b"\x01" * 64)

    assert (sw1, sw2) == (0x90, 0x00)
    assert connector._card.load_calls[0][0] == MockConstants.LoadKeyType.BIP39_SEED
    assert connector._card.load_calls[1][0] == MockConstants.LoadKeyType.BIP39_SEED
    assert connector._card.load_calls[2][0] == MockConstants.LoadKeyType.EXTENDED_ECC
    assert len(connector._card.load_calls[2][1]["public_key"]) == 65
    assert len(connector._card.load_calls[2][1]["private_key"]) == 32
    assert len(connector._card.load_calls[2][1]["chain_code"]) == 32


def test_keycard_import_seed_remove_key_then_bip39_retry_succeeds(monkeypatch):
    from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

    class MockTransport:
        def connect(self):
            return None

        def disconnect(self):
            return None

    class MockInner:
        is_initialized = True

        def __init__(self):
            self.transport = MockTransport()
            self.status = {"PIN0_remaining_tries": 3}
            self.get_key_path = []
            self.load_calls = []
            self.bip39_attempts = 0
            self.remove_calls = 0

        def select(self):
            return type("Info", (), {"instance_uid": b""})

        def pair(self, _pairing_password):
            return (0, b"k" * 32)

        def open_secure_channel(self, _pairing_index, _pairing_key):
            return None

        def verify_pin(self, _pin_text):
            return True

        def remove_key(self):
            self.remove_calls += 1
            return None

        def load_key(self, key_type, **kwargs):
            self.load_calls.append((key_type, kwargs))

            class SwError(Exception):
                def __init__(self, sw):
                    super().__init__(f"SW={sw:04X}")
                    self.sw = sw

            if key_type == MockConstants.LoadKeyType.BIP39_SEED:
                self.bip39_attempts += 1
                if self.bip39_attempts == 1:
                    raise SwError(0x6985)
            return b""

    class MockConstants:
        class PairingMode:
            EPHEMERAL = 1

        class LoadKeyType:
            BIP39_SEED = 3
            EXTENDED_ECC = 2

    monkeypatch.setattr(
        "seedsigner.helpers.keycard_connector.get_keycard_class",
        lambda: (MockInner, MockConstants),
    )

    connector = KeycardSatochipConnector.create(card_filter=["satochip"])
    connector.pin = list(b"123456")
    _resp, sw1, sw2 = connector.card_bip32_import_seed(b"\x01" * 64)

    assert (sw1, sw2) == (0x90, 0x00)
    assert connector._card.remove_calls == 1
    assert connector._card.bip39_attempts == 2


def test_keycard_import_seed_does_not_reverify_pin_when_already_verified(monkeypatch):
    from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

    class MockTransport:
        def connect(self):
            return None

        def disconnect(self):
            return None

    class MockInner:
        is_initialized = True

        def __init__(self):
            self.transport = MockTransport()
            self.status = {"PIN0_remaining_tries": 3}
            self.get_key_path = []
            self.is_pin_verified = False
            self.verify_calls = 0

        def select(self):
            return type("Info", (), {"instance_uid": b""})

        def pair(self, _pairing_password):
            return (0, b"k" * 32)

        def open_secure_channel(self, _pairing_index, _pairing_key):
            return None

        def verify_pin(self, _pin_text):
            self.verify_calls += 1
            self.is_pin_verified = True
            return True

        def load_key(self, _key_type, **_kwargs):
            return b""

    class MockConstants:
        class PairingMode:
            EPHEMERAL = 1

        class LoadKeyType:
            BIP39_SEED = 3
            EXTENDED_ECC = 2

    monkeypatch.setattr(
        "seedsigner.helpers.keycard_connector.get_keycard_class",
        lambda: (MockInner, MockConstants),
    )

    connector = KeycardSatochipConnector.create(card_filter=["satochip"])
    connector.pin = list(b"123456")

    # First verify during connection/login flow.
    _resp, sw1, sw2 = connector.card_verify_PIN()
    assert (sw1, sw2) == (0x90, 0x00)

    # Import should not send a second VERIFY PIN APDU when session is already verified.
    _resp, sw1, sw2 = connector.card_bip32_import_seed(b"\x02" * 64)
    assert (sw1, sw2) == (0x90, 0x00)
    assert connector._card.verify_calls == 1


def test_keycard_import_seed_returns_sw_when_extended_fallback_fails(monkeypatch):
    from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

    class MockTransport:
        def connect(self):
            return None

        def disconnect(self):
            return None

    class MockInner:
        is_initialized = True

        def __init__(self):
            self.transport = MockTransport()
            self.status = {"PIN0_remaining_tries": 3}
            self.get_key_path = []

        def select(self):
            return type("Info", (), {"instance_uid": b""})

        def pair(self, _pairing_password):
            return (0, b"k" * 32)

        def open_secure_channel(self, _pairing_index, _pairing_key):
            return None

        def verify_pin(self, _pin_text):
            return True

        def remove_key(self):
            return None

        def load_key(self, key_type, **_kwargs):
            class SwError(Exception):
                def __init__(self, sw):
                    super().__init__(f"SW={sw:04X}")
                    self.sw = sw

            # Force both BIP39 attempts and EXTENDED_ECC fallback to fail.
            if key_type == MockConstants.LoadKeyType.BIP39_SEED:
                raise SwError(0x6985)
            raise SwError(0x6985)

    class MockConstants:
        class PairingMode:
            EPHEMERAL = 1

        class LoadKeyType:
            BIP39_SEED = 3
            EXTENDED_ECC = 2

    monkeypatch.setattr(
        "seedsigner.helpers.keycard_connector.get_keycard_class",
        lambda: (MockInner, MockConstants),
    )

    connector = KeycardSatochipConnector.create(card_filter=["satochip"])
    connector.pin = list(b"123456")
    _resp, sw1, sw2 = connector.card_bip32_import_seed(b"\x01" * 64)

    assert (sw1, sw2) == (0x69, 0x85)
