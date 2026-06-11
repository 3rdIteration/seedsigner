from binascii import b2a_base64
from types import SimpleNamespace

import pytest

from embit import bip32

from seedsigner.helpers import embit_utils
from seedsigner.helpers.satochip_signer import (
    sign_message_with_satochip,
    verify_satochip_message_address,
)
from seedsigner.models.settings_definition import SettingsConstants


class DummyKey:
    def get_public_key_bytes(self, compressed=True):
        return b"\x02" + b"\x00" * 32


class DummyConnector:
    def __init__(self, authentikey_available: bool = True, xpub: str | None = None):
        authentikey = object() if authentikey_available else None
        self.parser = SimpleNamespace(authentikey=authentikey)
        self._authentikey_response = authentikey
        self._xpub = xpub

    def card_bip32_get_authentikey(self):
        if self._authentikey_response is not None:
            self.parser.authentikey = self._authentikey_response
        return self._authentikey_response

    def card_bip32_get_extendedkey(self, path):
        return DummyKey(), b""

    def card_bip32_get_xpub(self, path, xtype, is_mainnet):
        if self._xpub is None:
            raise Exception("xpub unavailable")
        return self._xpub

    def card_sign_message(self, keynbr, pubkey, message, hmac=None):
        compsig = b"\x01" * 65
        return None, 0x90, 0x00, compsig


class DummyDigestConnector(DummyConnector):
    requires_message_digest = True

    def card_sign_message(self, keynbr, pubkey, message, hmac=None):
        assert isinstance(message, bytes)
        assert len(message) == 32
        compsig = b"\x02" * 65
        return None, 0x90, 0x00, compsig


def test_sign_message_with_satochip_returns_base64_signature():
    connector = DummyConnector()
    sig = sign_message_with_satochip("m/84'/0'/0'/0/0", "hello", connector)
    assert sig == b2a_base64(b"\x01" * 65).strip().decode()


def test_sign_message_with_satochip_accepts_hardened_notation_without_m_prefix():
    connector = DummyConnector()
    sig = sign_message_with_satochip("84h/0h/0h/0/0", "hello", connector)
    assert sig == b2a_base64(b"\x01" * 65).strip().decode()


def test_sign_message_with_digest_backend_hashes_message_first():
    connector = DummyDigestConnector()
    sig = sign_message_with_satochip("m/84'/0'/0'/0/0", "hello", connector)
    assert sig == b2a_base64(b"\x02" * 65).strip().decode()


def test_sign_message_with_satochip_raises_when_authentikey_missing():
    connector = DummyConnector(authentikey_available=False)
    with pytest.raises(Exception) as exc:
        sign_message_with_satochip("m/84'/0'/0'/0/0", "hello", connector)
    assert "authentikey" in str(exc.value)


def test_verify_satochip_message_address_accepts_receive_address():
    seed = bytes(range(32))
    root = bip32.HDKey.from_seed(seed)
    wallet = root.derive("m/84h/0h/0h")
    xpub = wallet.to_public()
    expected_address = embit_utils.get_single_sig_address(
        xpub=xpub,
        script_type=SettingsConstants.NATIVE_SEGWIT,
        index=5,
        is_change=False,
        embit_network="main",
    )
    addr_format = {
        "wallet_derivation_path": "m/84h/0h/0h",
        "is_change": False,
        "index": 5,
        "script_type": SettingsConstants.NATIVE_SEGWIT,
        "network": SettingsConstants.MAINNET,
    }
    connector = DummyConnector(xpub=xpub.to_base58())

    verify_satochip_message_address(connector, addr_format, expected_address)


def test_verify_satochip_message_address_rejects_mismatch():
    seed = bytes(range(32))
    root = bip32.HDKey.from_seed(seed)
    wallet = root.derive("m/84h/0h/0h")
    xpub = wallet.to_public()
    addr_format = {
        "wallet_derivation_path": "m/84h/0h/0h",
        "is_change": True,
        "index": 0,
        "script_type": SettingsConstants.NATIVE_SEGWIT,
        "network": SettingsConstants.MAINNET,
    }
    connector = DummyConnector(xpub=xpub.to_base58())

    with pytest.raises(Exception) as exc:
        verify_satochip_message_address(connector, addr_format, "bc1qnotavalidaddress")
    assert "Satochip card" in str(exc.value)

