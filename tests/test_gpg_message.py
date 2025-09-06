"""Tests for helpers.gpg_message"""
from pgpy import PGPKey, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags

from seedsigner.helpers.gpg_message import encrypt_message, decrypt_message
from seedsigner.models.encode_qr import UrBytesQrEncoder
from seedsigner.helpers.ur2.ur_decoder import URDecoder
from urtypes.bytes import Bytes
from seedsigner.models.settings import SettingsConstants


def test_encrypt_decrypt_roundtrip():
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    uid = PGPUID.new("Test User", email="test@example.com")
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications})

    plaintext = "SeedSigner test message"
    ciphertext = encrypt_message(str(key.pubkey), plaintext)
    decrypted = decrypt_message(str(key), ciphertext)

    assert decrypted == plaintext


def test_encrypt_qr_roundtrip():
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    uid = PGPUID.new("Test User", email="test@example.com")
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications})

    plaintext = "SeedSigner QR test"
    ciphertext = encrypt_message(str(key.pubkey), plaintext)

    encoder = UrBytesQrEncoder(
        data=ciphertext.encode(),
        qr_density=SettingsConstants.DENSITY__MEDIUM,
    )
    decoder = URDecoder()
    while not decoder.is_complete():
        part = encoder.next_part()
        assert decoder.receive_part(part)
    ur = decoder.result_message()
    decoded_ciphertext = Bytes.from_cbor(ur.cbor).data.decode()

    decrypted = decrypt_message(str(key), decoded_ciphertext)
    assert decrypted == plaintext
