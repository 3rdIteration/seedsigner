"""Cryptographic primitives required by the Status Keycard secure channel."""

from __future__ import annotations

import os

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256, SHA512
from Cryptodome.Protocol.KDF import PBKDF2


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def sha256(data: bytes) -> bytes:
    h = SHA256.new()
    h.update(data)
    return h.digest()


def sha512(data: bytes) -> bytes:
    h = SHA512.new()
    h.update(data)
    return h.digest()


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 128/192/256 bits")
    if len(iv) != 16:
        raise ValueError("AES-CBC IV must be 16 bytes")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(_pkcs7_pad(plaintext, 16))


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) % 16 != 0:
        raise ValueError("ciphertext length must be a multiple of 16")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain = cipher.decrypt(ciphertext)
    return _pkcs7_unpad(plain, 16)


def aes_cbc_block(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Encrypt ``data`` (must be 16-byte aligned) with AES-CBC, return last block.

    Used for the Keycard MAC (first block of CBC with the MAC key over the framed payload).
    """
    if len(data) == 0 or len(data) % 16 != 0:
        raise ValueError("data must be a non-empty multiple of 16 bytes")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(data)
    return encrypted[-16:]


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data:
        raise ValueError("cannot unpad empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("invalid PKCS#7 padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS#7 padding bytes")
    return data[:-pad_len]


# Salt and iteration count are the keycard-cli / keycard-shell defaults.
# Compatible with cards initialised via those tools.
PAIRING_PASSWORD_SALT = b"Keycard Pairing Password Salt"
PAIRING_PASSWORD_ITERATIONS = 50000


def derive_pairing_secret(password: str) -> bytes:
    """Derive the 32-byte pairing secret from a user password.

    Matches the convention used by Status keycard-cli: PBKDF2-HMAC-SHA256
    with salt ``Keycard Pairing Password Salt`` and 50000 iterations.
    """
    if not password:
        raise ValueError("password must not be empty")
    return PBKDF2(
        password.encode("utf-8"),
        PAIRING_PASSWORD_SALT,
        dkLen=32,
        count=PAIRING_PASSWORD_ITERATIONS,
        hmac_hash_module=SHA256,
    )


def secp256k1_generate_keypair() -> tuple[bytes, bytes]:
    """Return (priv32, pub65) where pub is uncompressed (0x04 prefix)."""
    from embit.util import secp256k1

    while True:
        priv = os.urandom(32)
        try:
            secp256k1.ec_seckey_verify(priv)
            break
        except Exception:
            continue
    pub_obj = secp256k1.ec_pubkey_create(priv)
    pub = secp256k1.ec_pubkey_serialize(pub_obj, secp256k1.EC_UNCOMPRESSED)
    return priv, bytes(pub)


def secp256k1_ecdh(priv32: bytes, peer_pub: bytes) -> bytes:
    """Compute the raw ECDH shared secret (libsecp256k1 default hash).

    libsecp256k1's ``ecdh`` returns SHA256(0x02|0x03 || x).  For the
    Status Keycard handshake we need the *raw* X coordinate (32 bytes).
    Therefore we use the multiply-and-extract path via ``ec_pubkey_tweak_mul``.
    """
    from embit.util import secp256k1

    if len(priv32) != 32:
        raise ValueError("private key must be 32 bytes")
    pub_obj = secp256k1.ec_pubkey_parse(peer_pub)
    secp256k1.ec_pubkey_tweak_mul(pub_obj, priv32)
    serialised = secp256k1.ec_pubkey_serialize(pub_obj, secp256k1.EC_UNCOMPRESSED)
    return bytes(serialised[1:33])  # X coordinate
