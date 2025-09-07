"""Tests for helpers.gpg_message"""
import pytest
from pgpy import PGPKey, PGPUID, PGPMessage
from pgpy.constants import PubKeyAlgorithm, KeyFlags, EllipticCurveOID

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
    decrypted, signer, verified = decrypt_message(str(key), ciphertext)

    assert decrypted == plaintext
    assert signer is None
    assert not verified


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

    decrypted, signer, verified = decrypt_message(str(key), decoded_ciphertext)
    assert decrypted == plaintext
    assert signer is None
    assert not verified


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
    decrypted, signer_fpr, verified = decrypt_message(
        str(recipient), ciphertext, pubkey_blobs=[str(signer.pubkey)]
    )
    assert decrypted == plaintext
    assert signer_fpr == signer.fingerprint
    assert verified


def test_sign_only_roundtrip():
    signer = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    signer_uid = PGPUID.new("Signer", email="sign@example.com")
    signer.add_uid(signer_uid, usage={KeyFlags.Sign})

    plaintext = "SeedSigner sign only"
    signed_msg = encrypt_message(None, plaintext, signkey_blob=str(signer))

    # decrypt_message should return the original message even without a key
    decrypted, signer_fpr, verified = decrypt_message(
        None, signed_msg, pubkey_blobs=[str(signer.pubkey)]
    )
    assert decrypted == plaintext
    assert signer_fpr == signer.fingerprint
    assert verified


def test_unverified_signature():
    signer = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    signer_uid = PGPUID.new("Signer", email="sign@example.com")
    signer.add_uid(signer_uid, usage={KeyFlags.Sign})

    plaintext = "SeedSigner unverified sign"
    signed_msg = encrypt_message(None, plaintext, signkey_blob=str(signer))

    decrypted, signer_fpr, verified = decrypt_message(None, signed_msg)
    assert decrypted == plaintext
    assert signer_fpr == signer.fingerprint
    assert not verified


@pytest.mark.parametrize(
    "key_type",
    ["rsa", "p256", "brainpoolp256r1", "secp256k1", "ed25519"],
)
def test_encrypt_decrypt_roundtrip_key_types(key_type):
    """Round-trip test for message encryption/decryption across key types."""
    try:
        if key_type == "rsa":
            key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
            uid = PGPUID.new("Test", email="test@example.com")
            key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications})
        elif key_type == "p256":
            key = PGPKey.new(PubKeyAlgorithm.ECDSA, EllipticCurveOID.NIST_P256)
            uid = PGPUID.new("Test", email="test@example.com")
            key.add_uid(uid, usage={KeyFlags.Sign})
            sub = PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.NIST_P256)
            key.add_subkey(sub, usage={KeyFlags.EncryptCommunications})
        elif key_type == "brainpoolp256r1":
            key = PGPKey.new(PubKeyAlgorithm.ECDSA, EllipticCurveOID.Brainpool_P256)
            uid = PGPUID.new("Test", email="test@example.com")
            key.add_uid(uid, usage={KeyFlags.Sign})
            sub = PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Brainpool_P256)
            key.add_subkey(sub, usage={KeyFlags.EncryptCommunications})
        elif key_type == "secp256k1":
            key = PGPKey.new(PubKeyAlgorithm.ECDSA, EllipticCurveOID.SECP256K1)
            uid = PGPUID.new("Test", email="test@example.com")
            key.add_uid(uid, usage={KeyFlags.Sign})
            sub = PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.SECP256K1)
            key.add_subkey(sub, usage={KeyFlags.EncryptCommunications})
        elif key_type == "ed25519":
            key = PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
            uid = PGPUID.new("Test", email="test@example.com")
            key.add_uid(uid, usage={KeyFlags.Sign})
            sub = PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519)
            key.add_subkey(sub, usage={KeyFlags.EncryptCommunications})
        else:
            raise ValueError(key_type)
    except Exception as exc:
        pytest.skip(f"{key_type} keys unsupported: {exc}")

    plaintext = f"SeedSigner {key_type} test"
    ciphertext = encrypt_message(str(key.pubkey), plaintext)
    decrypted, signer, verified = decrypt_message(str(key), ciphertext)

    assert decrypted == plaintext
    assert signer is None
    assert not verified
