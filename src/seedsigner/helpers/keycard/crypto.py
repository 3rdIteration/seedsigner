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
    """AES-256-CBC encrypt with ISO/IEC 9797-1 method 2 padding.

    The Status Keycard applet uses ``Cipher.ALG_AES_CBC_ISO9797_M2``
    (see ``Crypto.java`` line 82). ISO9797-M2 always appends ``0x80``
    followed by zero bytes up to the next block boundary — even when
    the plaintext is already block-aligned, in which case a full
    16-byte padding block is added.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 128/192/256 bits")
    if len(iv) != 16:
        raise ValueError("AES-CBC IV must be 16 bytes")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(_iso9797_m2_pad(plaintext, 16))


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-256-CBC decrypt and strip ISO/IEC 9797-1 method 2 padding."""
    if len(ciphertext) % 16 != 0:
        raise ValueError("ciphertext length must be a multiple of 16")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain = cipher.decrypt(ciphertext)
    return _iso9797_m2_unpad(plain)


def aes_cbc_block(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Encrypt ``data`` (must be 16-byte aligned) with AES-CBC, return last block.

    Used for the Keycard MAC (first block of CBC with the MAC key over the framed payload).
    """
    if len(data) == 0 or len(data) % 16 != 0:
        raise ValueError("data must be a non-empty multiple of 16 bytes")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(data)
    return encrypted[-16:]


def _iso9797_m2_pad(data: bytes, block_size: int) -> bytes:
    """ISO/IEC 9797-1 method 2 (a.k.a. bit-padding): append 0x80 and zero
    pad to block boundary. Always adds at least one byte; if ``data``
    is already block-aligned a full padding block is appended.
    """
    pad_len = block_size - (len(data) % block_size)
    return data + b"\x80" + b"\x00" * (pad_len - 1)


def _iso9797_m2_unpad(data: bytes) -> bytes:
    """Strip ISO/IEC 9797-1 method 2 padding.

    Walks the trailing bytes back from the end: skips ``0x00`` bytes and
    expects a single ``0x80`` marker. Raises if the marker is missing
    or the search exceeds one block boundary back from the end.
    """
    if not data:
        raise ValueError("cannot unpad empty data")
    i = len(data) - 1
    # Padding can be at most 16 bytes (one block) and the 0x80 must be
    # within that window.
    limit = max(0, len(data) - 16)
    while i >= limit and data[i] == 0x00:
        i -= 1
    if i < limit or data[i] != 0x80:
        raise ValueError("invalid ISO9797-M2 padding")
    return data[:i]


# Salt and iteration count are the keycard-cli / keycard-shell defaults.
# Compatible with cards initialised via those tools.
PAIRING_PASSWORD_SALT = b"Keycard Pairing Password Salt"
PAIRING_PASSWORD_ITERATIONS = 50000

# Hard-coded 32-byte pairing secret used by the keycard-shell hardware
# wallet firmware (https://github.com/keycard-tech/keycard-shell). When
# keycard-shell initialises a card it writes this PSK directly as the
# pairing secret — there is *no* PBKDF2 derivation. Any device wanting
# to pair with a keycard-shell-initialised card must use these 32 bytes
# verbatim. Source: ``app/keycard/keycard.c`` in keycard-shell.
KEYCARD_SHELL_DEFAULT_PSK = bytes([
    0x67, 0x5d, 0xea, 0xbb, 0x0d, 0x7c, 0x72, 0x4b,
    0x4a, 0x36, 0xca, 0xad, 0x0e, 0x28, 0x08, 0x26,
    0x15, 0x9e, 0x89, 0x88, 0x6f, 0x70, 0x82, 0x53,
    0x5d, 0x43, 0x1e, 0x92, 0x48, 0x48, 0xbc, 0xf1,
])


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
