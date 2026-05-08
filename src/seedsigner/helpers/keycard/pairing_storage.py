"""Encrypted persistence of a Keycard ``PairingInfo`` on the microSD card.

Threat model
------------
The pairing key is a long-term shared secret between a specific card and
this device.  Anyone who can read the persisted blob *and* knows the
user's pairing password can talk to the card (still subject to the PIN).

We therefore encrypt the blob with AES-256-GCM under a key derived from
the same pairing password (PBKDF2-HMAC-SHA256, 50000 iter, separate
domain salt from the one used to derive the on-card pairing secret).
The user enters that password once per boot.

File layout
-----------
``[version:1] [salt:16] [nonce:12] [tag:16] [ciphertext:N]``

Plaintext payload::

    [pairing_index:1]
    [pairing_key:32]
    [instance_uid_len:1]
    [instance_uid:N]   -- UID from the SELECT response, 16 bytes for status keycard

The instance UID lets us refuse to load a blob that doesn't match the
card currently in the reader.
"""

from __future__ import annotations

import logging
import os
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import PBKDF2

from .secure_channel import PairingInfo

logger = logging.getLogger(__name__)

STORAGE_VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KDF_ITERATIONS = 50000
KDF_SALT_DOMAIN = b"Keycard Pairing Storage v1"

DEFAULT_FILENAME = "keycard_pairing.bin"


class PairingStorageError(Exception):
    pass


@dataclass(frozen=True)
class StoredPairing:
    pairing: PairingInfo
    instance_uid: bytes


def encrypt_pairing(password: str, pairing: PairingInfo, instance_uid: bytes) -> bytes:
    if len(pairing.pairing_key) != 32:
        raise ValueError("pairing key must be 32 bytes")
    if not 0 <= pairing.pairing_index <= 0xFF:
        raise ValueError("pairing index must fit in one byte")
    if len(instance_uid) > 0xFF:
        raise ValueError("instance UID too long")
    password = _normalise_password(password)
    payload = (
        bytes([pairing.pairing_index])
        + pairing.pairing_key
        + bytes([len(instance_uid)])
        + bytes(instance_uid)
    )
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_storage_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    try:
        return bytes([STORAGE_VERSION]) + salt + nonce + tag + ciphertext
    finally:
        # Best-effort wipe of the derived key.
        if isinstance(key, (bytes, bytearray)):
            try:
                _zero_bytes(key)
            except Exception:
                pass


def decrypt_pairing(password: str, blob: bytes) -> StoredPairing:
    if len(blob) < 1 + SALT_LEN + NONCE_LEN + TAG_LEN + 1:
        raise PairingStorageError("blob too short")
    if blob[0] != STORAGE_VERSION:
        raise PairingStorageError(f"unsupported storage version {blob[0]}")
    password = _normalise_password(password)
    cursor = 1
    salt = blob[cursor:cursor + SALT_LEN]; cursor += SALT_LEN
    nonce = blob[cursor:cursor + NONCE_LEN]; cursor += NONCE_LEN
    tag = blob[cursor:cursor + TAG_LEN]; cursor += TAG_LEN
    ciphertext = blob[cursor:]
    key = _derive_storage_key(password, salt)
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except (ValueError, KeyError) as exc:
        raise PairingStorageError(f"decryption failed: {exc}") from exc
    finally:
        if isinstance(key, (bytes, bytearray)):
            try:
                _zero_bytes(key)
            except Exception:
                pass

    if len(plaintext) < 34:
        raise PairingStorageError("plaintext truncated")
    pairing_index = plaintext[0]
    pairing_key = bytes(plaintext[1:33])
    uid_len = plaintext[33]
    if len(plaintext) < 34 + uid_len:
        raise PairingStorageError("instance UID truncated")
    instance_uid = bytes(plaintext[34:34 + uid_len])
    return StoredPairing(
        pairing=PairingInfo(pairing_index=pairing_index, pairing_key=pairing_key),
        instance_uid=instance_uid,
    )


def get_storage_path(filename: str = DEFAULT_FILENAME) -> Path:
    """Path to the persisted blob; created lazily on first save."""
    from seedsigner.hardware.microsd import MicroSD
    return MicroSD.get_microsd_dir() / filename


def save(password: str, pairing: PairingInfo, instance_uid: bytes,
         path: Optional[Path] = None) -> Path:
    blob = encrypt_pairing(password, pairing, instance_uid)
    target = path or get_storage_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_bytes(blob)
    os.replace(tmp, target)
    try:
        os.chmod(target, 0o600)
    except Exception:
        # best-effort; vfat (microSD) typically ignores POSIX modes
        pass
    return target


def load(password: str, path: Optional[Path] = None) -> Optional[StoredPairing]:
    target = path or get_storage_path()
    if not target.exists():
        return None
    try:
        blob = target.read_bytes()
    except OSError as exc:
        raise PairingStorageError(f"could not read {target}: {exc}") from exc
    return decrypt_pairing(password, blob)


def remove(path: Optional[Path] = None) -> bool:
    target = path or get_storage_path()
    try:
        target.unlink()
        return True
    except FileNotFoundError:
        return False


def _normalise_password(password: str) -> str:
    if not password:
        raise ValueError("password must not be empty")
    return unicodedata.normalize("NFKD", password)


def _derive_storage_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(
        password.encode("utf-8"),
        KDF_SALT_DOMAIN + salt,
        dkLen=32,
        count=KDF_ITERATIONS,
        hmac_hash_module=SHA256,
    )


def _zero_bytes(b) -> None:
    if isinstance(b, bytearray):
        for i in range(len(b)):
            b[i] = 0
