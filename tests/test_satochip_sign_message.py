from binascii import b2a_base64

from seedsigner.helpers.satochip_signer import sign_message_with_satochip


class DummyKey:
    def get_public_key_bytes(self, compressed=True):
        return b"\x02" + b"\x00" * 32


class DummyConnector:
    def card_bip32_get_extendedkey(self, path):
        return DummyKey(), b""

    def card_sign_message(self, keynbr, pubkey, message, hmac=None):
        compsig = b"\x01" * 65
        return None, 0x90, 0x00, compsig


def test_sign_message_with_satochip_returns_base64_signature():
    connector = DummyConnector()
    sig = sign_message_with_satochip("m/84'/0'/0'/0/0", "hello", connector)
    assert sig == b2a_base64(b"\x01" * 65).strip().decode()


def test_sign_message_with_satochip_accepts_hardened_notation_without_m_prefix():
    connector = DummyConnector()
    sig = sign_message_with_satochip("84h/0h/0h/0/0", "hello", connector)
    assert sig == b2a_base64(b"\x01" * 65).strip().decode()

