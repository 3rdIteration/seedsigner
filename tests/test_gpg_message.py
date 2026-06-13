"""Tests for helpers.gpg_message"""
import sys
import pytest
from pgpy import PGPKey, PGPUID, PGPMessage
from pgpy.constants import PubKeyAlgorithm, KeyFlags, EllipticCurveOID

from seedsigner.helpers.gpg_message import encrypt_message, decrypt_message
from seedsigner.models.encode_qr import UrBytesQrEncoder
from seedsigner.helpers.ur2.ur_decoder import URDecoder
from urtypes.bytes import Bytes
from seedsigner.models.settings import SettingsConstants


def _msys2_path(path: str) -> str:
    """Convert a Windows path to MSYS2 format for GNUPGHOME if needed.

    On Windows CI the GPG binary ships with Git-for-Windows and runs under
    MSYS2.  It expects POSIX-style paths (``/c/Users/...``) but Python's
    ``tempfile`` returns native Windows paths (``C:\\Users\\...``).

    Native Windows GPG (e.g. Gpg4win at C:\\Program Files\\GnuPG\\bin\\gpg.EXE)
    expects native Windows paths, so we only convert when the binary is from
    Git for Windows / MSYS2.
    """
    if sys.platform == "win32":
        import shutil

        gpg_path = shutil.which("gpg") or ""
        # Only convert to MSYS2 style if GPG is from Git for Windows
        if not ("Git" in gpg_path or "msys" in gpg_path.lower()):
            return path  # Native Windows GPG — keep native paths

        path = path.replace("\\", "/")
        # Convert drive letter, e.g. "C:/Users/..." → "/c/Users/..."
        if len(path) >= 2 and path[1] == ":":
            path = "/" + path[0].lower() + path[2:]
    return path


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
        # Duplicate fragments may be encountered in animated QR streams but
        # should still be treated as successfully received parts.
        if not decoder.is_complete():
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


def test_encrypt_decrypt_binary_roundtrip():
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    uid = PGPUID.new("Test", email="test@example.com")
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications})

    plaintext = bytes(range(256))
    ciphertext = encrypt_message(str(key.pubkey), plaintext)
    decrypted, signer, verified = decrypt_message(str(key), ciphertext)

    assert isinstance(decrypted, bytes)
    assert decrypted == plaintext
    assert signer is None
    assert not verified


# ---------------------------------------------------------------------------
# BIP85-derived key message roundtrip tests
# ---------------------------------------------------------------------------

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


@pytest.mark.parametrize(
    "key_type",
    ["ed25519", "p256", "brainpoolp256r1", "secp256k1", "rsa2048"],
)
def test_bip85_key_encrypt_decrypt_roundtrip(key_type):
    """Encrypt/decrypt using a BIP85-derived key for each supported type."""
    from tools.bip85_pgp import create_bip85_pgp_key

    try:
        key = create_bip85_pgp_key(
            mnemonic=MNEMONIC,
            key_index=0,
            primary_type=key_type,
            name="Test",
            email="test@example.com",
            subkey_type=key_type,
        )
    except Exception as exc:
        pytest.skip(f"{key_type} generation unsupported: {exc}")

    plaintext = f"BIP85 {key_type} encrypt test"
    ciphertext = encrypt_message(str(key.pubkey), plaintext)
    decrypted, signer, verified = decrypt_message(str(key), ciphertext)

    assert decrypted == plaintext
    assert signer is None
    assert not verified


@pytest.mark.parametrize(
    "key_type",
    ["ed25519", "p256", "brainpoolp256r1", "secp256k1", "rsa2048"],
)
def test_bip85_key_sign_roundtrip(key_type):
    """Sign-only using a BIP85-derived key for each supported type."""
    from tools.bip85_pgp import create_bip85_pgp_key

    try:
        key = create_bip85_pgp_key(
            mnemonic=MNEMONIC,
            key_index=0,
            primary_type=key_type,
            name="Test",
            email="test@example.com",
            subkey_type=key_type,
        )
    except Exception as exc:
        pytest.skip(f"{key_type} generation unsupported: {exc}")

    plaintext = f"BIP85 {key_type} sign test"
    signed_msg = encrypt_message(None, plaintext, signkey_blob=str(key))
    decrypted, signer_fpr, verified = decrypt_message(
        None, signed_msg, pubkey_blobs=[str(key.pubkey)]
    )

    assert decrypted == plaintext
    assert signer_fpr is not None
    assert verified


@pytest.mark.parametrize(
    "key_type",
    ["ed25519", "p256", "brainpoolp256r1", "secp256k1", "rsa2048"],
)
def test_bip85_key_sign_encrypt_decrypt_roundtrip(key_type):
    """Full sign+encrypt+decrypt using a BIP85-derived key."""
    from tools.bip85_pgp import create_bip85_pgp_key

    try:
        key = create_bip85_pgp_key(
            mnemonic=MNEMONIC,
            key_index=0,
            primary_type=key_type,
            name="Test",
            email="test@example.com",
            subkey_type=key_type,
        )
    except Exception as exc:
        pytest.skip(f"{key_type} generation unsupported: {exc}")

    plaintext = f"BIP85 {key_type} sign+encrypt test"
    ciphertext = encrypt_message(
        str(key.pubkey), plaintext, signkey_blob=str(key)
    )
    decrypted, signer_fpr, verified = decrypt_message(
        str(key), ciphertext, pubkey_blobs=[str(key.pubkey)]
    )

    assert decrypted == plaintext
    assert signer_fpr is not None
    assert verified


@pytest.mark.parametrize(
    "key_type",
    ["ed25519", "p256", "brainpoolp256r1", "secp256k1", "rsa2048"],
)
def test_bip85_key_gpg_export_roundtrip(key_type):
    """End-to-end: generate BIP85 key, import to GPG, export, sign+encrypt."""
    import subprocess
    import tempfile
    import os
    import shutil

    from tools.bip85_pgp import create_bip85_pgp_key

    if not shutil.which("gpg"):
        pytest.skip("gpg binary not available")

    try:
        key = create_bip85_pgp_key(
            mnemonic=MNEMONIC,
            key_index=0,
            primary_type=key_type,
            name="Test",
            email="test@example.com",
            subkey_type=key_type,
        )
    except Exception as exc:
        pytest.skip(f"{key_type} generation unsupported: {exc}")

    with tempfile.TemporaryDirectory() as gnupghome:
        env = {**os.environ, "GNUPGHOME": _msys2_path(gnupghome)}

        # Import into GPG (same way the UI does)
        result = subprocess.run(
            ["gpg", "--batch", "--import"],
            input=str(key).encode(),
            capture_output=True,
            env=env,
        )
        assert result.returncode == 0, f"Import failed: {result.stderr.decode()}"

        # Export public key
        pub_export = subprocess.run(
            ["gpg", "--armor", "--export", str(key.fingerprint)],
            capture_output=True,
            text=True,
            env=env,
        )
        assert pub_export.returncode == 0
        pub_blob = pub_export.stdout

        # Export secret key
        sec_export = subprocess.run(
            ["gpg", "--armor", "--export-secret-keys", str(key.fingerprint)],
            capture_output=True,
            text=True,
            env=env,
        )
        assert sec_export.returncode == 0
        sec_blob = sec_export.stdout

        # Encrypt with GPG-exported public key
        plaintext = f"GPG roundtrip {key_type} test"
        ciphertext = encrypt_message(pub_blob, plaintext)
        decrypted, _, _ = decrypt_message(sec_blob, ciphertext)
        assert decrypted == plaintext

        # Sign with GPG-exported secret key
        signed = encrypt_message(None, plaintext, signkey_blob=sec_blob)
        decrypted, signer_fpr, verified = decrypt_message(
            None, signed, pubkey_blobs=[pub_blob]
        )
        assert decrypted == plaintext
        assert signer_fpr is not None
        assert verified

        # Sign + encrypt
        ciphertext = encrypt_message(
            pub_blob, plaintext, signkey_blob=sec_blob
        )
        decrypted, signer_fpr, verified = decrypt_message(
            sec_blob, ciphertext, pubkey_blobs=[pub_blob]
        )
        assert decrypted == plaintext
        assert verified


@pytest.mark.parametrize(
    "key_type",
    ["ed25519", "p256", "brainpoolp256r1", "rsa2048"],
)
def test_generate_new_gpg_export_roundtrip(key_type):
    """End-to-end: PGPKey.new with subkeys → GPG import → export → sign+encrypt.

    This mirrors the exact workflow in ToolsGPGGenerateKeyView: generate a
    primary key with subkeys, import into GPG, then use the GPG-exported keys
    for the secure message sign/encrypt operations.
    """
    import subprocess
    import tempfile
    import os
    import shutil

    from pgpy.constants import (
        PubKeyAlgorithm,
        KeyFlags,
        HashAlgorithm,
        SymmetricKeyAlgorithm,
        CompressionAlgorithm,
        EllipticCurveOID,
    )
    from datetime import datetime, timezone, timedelta

    if not shutil.which("gpg"):
        pytest.skip("gpg binary not available")

    # Generate key the same way ToolsGPGGenerateKeyView does
    if key_type == "ed25519":
        alg, param = PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519
    elif key_type == "p256":
        alg, param = PubKeyAlgorithm.ECDSA, EllipticCurveOID.NIST_P256
    elif key_type == "brainpoolp256r1":
        alg, param = PubKeyAlgorithm.ECDSA, EllipticCurveOID.Brainpool_P256
    elif key_type == "rsa2048":
        alg, param = PubKeyAlgorithm.RSAEncryptOrSign, 2048
    else:
        raise ValueError(key_type)

    try:
        master_key = PGPKey.new(alg, param)
    except Exception as exc:
        pytest.skip(f"{key_type} unsupported: {exc}")

    uid = PGPUID.new("GenTest", email="gen@example.com")
    expires = timedelta(days=365)
    master_key.add_uid(
        uid,
        usage={KeyFlags.Certify, KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
        expires=expires,
    )

    # Add subkeys matching ToolsGPGGenerateKeyView logic
    if alg == PubKeyAlgorithm.RSAEncryptOrSign:
        sub_enc = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, param)
    elif alg == PubKeyAlgorithm.EdDSA:
        sub_enc = PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519)
    else:
        sub_enc = PGPKey.new(PubKeyAlgorithm.ECDH, param)

    master_key.add_subkey(
        sub_enc,
        usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
        expires=expires,
    )

    with tempfile.TemporaryDirectory() as gnupghome:
        env = {**os.environ, "GNUPGHOME": _msys2_path(gnupghome)}

        result = subprocess.run(
            ["gpg", "--batch", "--import"],
            input=str(master_key).encode(),
            capture_output=True,
            env=env,
        )
        assert result.returncode == 0, f"Import failed: {result.stderr.decode()}"

        pub_export = subprocess.run(
            ["gpg", "--armor", "--export", str(master_key.fingerprint)],
            capture_output=True, text=True, env=env,
        )
        assert pub_export.returncode == 0
        pub_blob = pub_export.stdout

        sec_export = subprocess.run(
            ["gpg", "--armor", "--export-secret-keys", str(master_key.fingerprint)],
            capture_output=True, text=True, env=env,
        )
        assert sec_export.returncode == 0
        sec_blob = sec_export.stdout

        # PGPy automatically selects ECDH/RSA subkey for encryption
        plaintext = f"Generate-new {key_type} roundtrip"
        ciphertext = encrypt_message(pub_blob, plaintext)
        decrypted, _, _ = decrypt_message(sec_blob, ciphertext)
        assert decrypted == plaintext

        # PGPy uses primary key (or signing subkey) for signing
        signed = encrypt_message(None, plaintext, signkey_blob=sec_blob)
        decrypted, signer_fpr, verified = decrypt_message(
            None, signed, pubkey_blobs=[pub_blob]
        )
        assert decrypted == plaintext
        assert signer_fpr is not None
        assert verified

        # Sign + encrypt combined
        ciphertext = encrypt_message(
            pub_blob, plaintext, signkey_blob=sec_blob
        )
        decrypted, signer_fpr, verified = decrypt_message(
            sec_blob, ciphertext, pubkey_blobs=[pub_blob]
        )
        assert decrypted == plaintext
        assert verified
