"""Tests for helpers.gpg_message"""
from pgpy import PGPKey, PGPUID, PGPMessage
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
    raw = Bytes.from_cbor(ur.cbor).data
    if isinstance(raw, (bytes, bytearray)):
        decoded_ciphertext = raw.decode()
    else:
        decoded_ciphertext = raw

    decrypted = decrypt_message(str(key), decoded_ciphertext)
    assert decrypted == plaintext


def test_sign_encrypt_decrypt_roundtrip():
    recipient = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    recipient_uid = PGPUID.new("Recipient", email="rcpt@example.com")
    recipient.add_uid(recipient_uid, usage={KeyFlags.EncryptCommunications})

    signer = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    signer_uid = PGPUID.new("Signer", email="sign@example.com")
    signer.add_uid(signer_uid, usage={KeyFlags.Sign})

    plaintext = "SeedSigner signed message"
    ciphertext = encrypt_message(
        str(recipient.pubkey), plaintext, signkey_blob=str(signer)
    )

    # decrypt using helper
    assert decrypt_message(str(recipient), ciphertext) == plaintext

    # verify signature
    dec_msg = recipient.decrypt(PGPMessage.from_blob(ciphertext))
    assert signer.pubkey.verify(dec_msg)


def test_sign_only_roundtrip():
    signer = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    signer_uid = PGPUID.new("Signer", email="sign@example.com")
    signer.add_uid(signer_uid, usage={KeyFlags.Sign})

    plaintext = "SeedSigner sign only"
    signed_msg = encrypt_message(None, plaintext, signkey_blob=str(signer))

    # decrypt_message should return the original message even without a key
    assert decrypt_message(None, signed_msg) == plaintext

    # verify signature
    assert signer.pubkey.verify(PGPMessage.from_blob(signed_msg))
