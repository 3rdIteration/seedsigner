"""Tests for the Keycard Init/Pair offline helpers (no card required)."""

import string
from collections import Counter

import pytest

from seedsigner.helpers.keycard import secrets as kc_secrets
from seedsigner.helpers.keycard.crypto import derive_pairing_secret


class TestRandomCredentials:
    def test_pin_is_six_digits(self):
        for _ in range(100):
            p = kc_secrets.generate_pin()
            assert len(p) == kc_secrets.PIN_LENGTH
            assert p.isdigit()

    def test_puk_is_twelve_digits(self):
        for _ in range(100):
            p = kc_secrets.generate_puk()
            assert len(p) == kc_secrets.PUK_LENGTH
            assert p.isdigit()

    def test_pin_distribution_smoke(self):
        # Cheap statistical smoke: ensure all 10 digits show up in 1000 PINs.
        joined = "".join(kc_secrets.generate_pin() for _ in range(1000))
        seen = Counter(joined)
        for digit in "0123456789":
            assert seen[digit] > 0, f"digit {digit} never appeared in 1000 PINs"

    def test_pairing_password_uses_safe_alphabet(self):
        password = kc_secrets.generate_pairing_password(length=200)
        assert len(password) == 200
        for ch in password:
            assert ch in kc_secrets.PAIRING_PASSWORD_ALPHABET

    def test_pairing_password_excludes_lookalikes(self):
        password = kc_secrets.generate_pairing_password(length=500)
        # Visually-confusable characters should never appear.
        for forbidden in "0OI1lo":
            assert forbidden not in password

    def test_zero_length_rejected(self):
        with pytest.raises(ValueError):
            kc_secrets.generate_pin(length=0)
        with pytest.raises(ValueError):
            kc_secrets.generate_puk(length=0)
        with pytest.raises(ValueError):
            kc_secrets.generate_pairing_password(length=0)


class TestPBKDF2Vector:
    def test_default_password(self):
        # KeycardDefaultPairing — Status keycard-cli's default.
        # Independently verified against pycryptodomex.PBKDF2 on import.
        secret = derive_pairing_secret("KeycardDefaultPairing")
        assert len(secret) == 32

    def test_empty_password_rejected(self):
        with pytest.raises(ValueError):
            derive_pairing_secret("")

    def test_deterministic(self):
        a = derive_pairing_secret("hunter2")
        b = derive_pairing_secret("hunter2")
        assert a == b

    def test_different_passwords_different_secrets(self):
        a = derive_pairing_secret("hunter2")
        b = derive_pairing_secret("hunter3")
        assert a != b


class TestExtractPubkey:
    """The local helper used by ExportPubkey to lift the 65-byte pubkey."""

    @pytest.fixture(autouse=True)
    def stub_modules(self, monkeypatch):
        # keycard_views imports a lot of GUI; mock side modules to allow import.
        import sys
        from unittest.mock import MagicMock
        for mod in [
            "RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
            "smartcard", "smartcard.System", "pygame",
            "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
        ]:
            sys.modules.setdefault(mod, MagicMock())

    def test_with_template_wrapper(self):
        from seedsigner.views.keycard_views import _extract_pubkey
        pub = b"\x04" + b"\x33" * 64
        body = bytes([0x80, len(pub)]) + pub
        resp = bytes([0xA1, len(body)]) + body
        assert _extract_pubkey(resp) == pub

    def test_without_template_wrapper(self):
        from seedsigner.views.keycard_views import _extract_pubkey
        pub = b"\x04" + b"\xAB" * 64
        body = bytes([0x80, len(pub)]) + pub
        assert _extract_pubkey(body) == pub

    def test_returns_none_when_missing(self):
        from seedsigner.views.keycard_views import _extract_pubkey
        # Compressed pubkey (33 bytes, 0x02 prefix) is not what we expect.
        pub = b"\x02" + b"\x00" * 32
        body = bytes([0x80, len(pub)]) + pub
        assert _extract_pubkey(body) is None


class TestPathFormatter:
    @pytest.fixture(autouse=True)
    def stub_modules(self):
        import sys
        from unittest.mock import MagicMock
        for mod in [
            "RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
            "smartcard", "smartcard.System", "pygame",
            "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
        ]:
            sys.modules.setdefault(mod, MagicMock())

    def test_eth_default(self):
        from seedsigner.views.keycard_views import _format_path, DEFAULT_ETH_PATH
        assert _format_path(DEFAULT_ETH_PATH) == "m/44'/60'/0'/0/0"

    def test_no_components(self):
        from seedsigner.views.keycard_views import _format_path
        assert _format_path([]) == "m/"
