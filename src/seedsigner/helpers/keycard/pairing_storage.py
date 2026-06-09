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
    [label_tag:1=0x01] [label_len:1] [label_slot:16]  -- optional trailer, fixed 18 bytes

The instance UID lets us refuse to load a blob that doesn't match the
card currently in the reader.

The label trailer is still written for every new blob (always empty
now — instance naming was removed) and is *optional* on read: blobs
written before the trailer existed, or by older firmware that set a
name, both decode without error. The slot is constant length so the
on-disk ciphertext size is independent of any legacy name.
"""

from __future__ import annotations

import hashlib
import logging
import os
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

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

# Optional plaintext trailer: tag byte + length byte + fixed slot.
LABEL_TAG = 0x01
LABEL_MAX_LEN = 16  # bytes of UTF-8; the slot is always this size, zero-padded.
LABEL_TRAILER_LEN = 2 + LABEL_MAX_LEN  # 18

DEFAULT_FILENAME = "keycard_pairing.bin"  # legacy single-card file
PER_UID_PREFIX = "keycard_pairing_"
PER_UID_SUFFIX = ".bin"
FINGERPRINT_LEN_HEX = 16  # 8 bytes of SHA-256(instance_uid)


class PairingStorageError(Exception):
    pass


@dataclass(frozen=True)
class StoredPairing:
    pairing: PairingInfo
    instance_uid: bytes
    label: Optional[str] = None


def encrypt_pairing(
    password: str,
    pairing: PairingInfo,
    instance_uid: bytes,
    label: str = "",
) -> bytes:
    if len(pairing.pairing_key) != 32:
        raise ValueError("pairing key must be 32 bytes")
    if not 0 <= pairing.pairing_index <= 0xFF:
        raise ValueError("pairing index must fit in one byte")
    if len(instance_uid) > 0xFF:
        raise ValueError("instance UID too long")
    password = _normalise_password(password)
    # The trailer carries the optional user-assigned instance name. It is a
    # constant-size slot, so an empty ``label`` reproduces the byte-identical
    # blob older firmware wrote (and stays forward/backward compatible).
    payload = (
        bytes([pairing.pairing_index])
        + pairing.pairing_key
        + bytes([len(instance_uid)])
        + bytes(instance_uid)
        + _build_label_trailer(_encode_label(label))
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
    label = _parse_label_trailer(plaintext[34 + uid_len:])
    return StoredPairing(
        pairing=PairingInfo(pairing_index=pairing_index, pairing_key=pairing_key),
        instance_uid=instance_uid,
        label=label,
    )


def get_storage_path(filename: str = DEFAULT_FILENAME) -> Path:
    """Path to the persisted blob; created lazily on first save."""
    from seedsigner.hardware.microsd import MicroSD
    return MicroSD.get_microsd_dir() / filename


def fingerprint_for_uid(instance_uid: bytes) -> str:
    """Hex fingerprint used in per-UID filenames.

    Truncated SHA-256 so the filename does not leak the raw instance UID
    in FAT directory listings.
    """
    if not instance_uid:
        raise ValueError("instance_uid must not be empty")
    return hashlib.sha256(bytes(instance_uid)).hexdigest()[:FINGERPRINT_LEN_HEX]


def _path_for_uid(instance_uid: bytes, *, base_dir: Optional[Path] = None) -> Path:
    fp = fingerprint_for_uid(instance_uid)
    filename = f"{PER_UID_PREFIX}{fp}{PER_UID_SUFFIX}"
    if base_dir is not None:
        return base_dir / filename
    return get_storage_path(filename)


@dataclass(frozen=True)
class StoredFingerprint:
    """One entry returned by :func:`list_pairings` for the Forget UI."""
    fingerprint: str  # hex; "" for the legacy single-card file
    path: Path
    is_legacy: bool


def list_pairings(*, base_dir: Optional[Path] = None) -> List[StoredFingerprint]:
    """Return all pairing files known to this device.

    Includes the legacy ``keycard_pairing.bin`` if present so the Forget
    UI can clean it up explicitly.
    """
    if base_dir is None:
        try:
            base_dir = get_storage_path().parent
        except Exception:
            return []
    out: List[StoredFingerprint] = []
    if not base_dir.exists():
        return out
    for entry in sorted(base_dir.iterdir()):
        if not entry.is_file():
            continue
        name = entry.name
        if name == DEFAULT_FILENAME:
            out.append(StoredFingerprint(fingerprint="", path=entry, is_legacy=True))
        elif name.startswith(PER_UID_PREFIX) and name.endswith(PER_UID_SUFFIX):
            fp = name[len(PER_UID_PREFIX):-len(PER_UID_SUFFIX)]
            if len(fp) == FINGERPRINT_LEN_HEX and all(c in "0123456789abcdef" for c in fp):
                out.append(StoredFingerprint(fingerprint=fp, path=entry, is_legacy=False))
    return out


def save(password: str, pairing: PairingInfo, instance_uid: bytes,
         path: Optional[Path] = None, label: str = "") -> Path:
    """Persist a pairing.

    With ``path`` explicit (test path) writes there. Otherwise writes to
    the per-UID file and, if a legacy single-card file exists, removes
    it so we don't keep stale duplicates.

    ``label`` is the optional user-assigned instance name (defaults to
    empty, so existing callers keep writing nameless blobs).
    """
    blob = encrypt_pairing(password, pairing, instance_uid, label)
    if path is None:
        target = _path_for_uid(instance_uid)
        legacy = get_storage_path()
    else:
        target = path
        legacy = None
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_bytes(blob)
    os.replace(tmp, target)
    try:
        os.chmod(target, 0o600)
    except Exception:
        # best-effort; vfat (microSD) typically ignores POSIX modes
        pass
    if legacy is not None and legacy != target and legacy.exists():
        try:
            legacy.unlink()
        except Exception:
            logger.exception("could not remove legacy pairing file %s", legacy)
    return target


def set_label(password: str, instance_uid: bytes, label: str,
              path: Optional[Path] = None) -> Path:
    """Re-write an existing pairing blob with a new instance name.

    Loads the per-UID blob (verifying the password), then re-encrypts it
    in place, preserving ``pairing_index`` / ``pairing_key`` /
    ``instance_uid`` and changing only the label slot.

    Raises ``PairingStorageError`` if no blob exists for this instance, or
    if the password does not decrypt it (the wrong password makes
    :func:`load` raise from :func:`decrypt_pairing`).
    """
    stored = load(password, instance_uid=instance_uid, path=path)
    if stored is None:
        raise PairingStorageError("no saved pairing for this instance")
    return save(password, stored.pairing, stored.instance_uid,
                path=path, label=label)


def load(password: str, instance_uid: Optional[bytes] = None,
         path: Optional[Path] = None) -> Optional[StoredPairing]:
    """Load a stored pairing.

    Resolution order:
    * ``path`` explicit → that file (used by tests).
    * ``instance_uid`` given → ``_path_for_uid(instance_uid)`` first,
      then legacy ``keycard_pairing.bin`` if its stored UID matches.
    * Neither → legacy file (back-compat with old callers).

    Returns ``None`` if no candidate file exists, or if the legacy fallback
    decodes to a different UID.
    """
    if path is not None:
        if not path.exists():
            return None
        try:
            blob = path.read_bytes()
        except OSError as exc:
            raise PairingStorageError(f"could not read {path}: {exc}") from exc
        return decrypt_pairing(password, blob)

    if instance_uid is not None:
        target = _path_for_uid(instance_uid)
        if target.exists():
            try:
                blob = target.read_bytes()
            except OSError as exc:
                raise PairingStorageError(f"could not read {target}: {exc}") from exc
            return decrypt_pairing(password, blob)
        # Fallback to legacy file: only if its embedded UID matches.
        legacy = get_storage_path()
        if not legacy.exists():
            return None
        try:
            blob = legacy.read_bytes()
        except OSError as exc:
            raise PairingStorageError(f"could not read {legacy}: {exc}") from exc
        stored = decrypt_pairing(password, blob)
        if stored.instance_uid != bytes(instance_uid):
            return None
        return stored

    # No UID and no path → legacy single-file behaviour.
    legacy = get_storage_path()
    if not legacy.exists():
        return None
    try:
        blob = legacy.read_bytes()
    except OSError as exc:
        raise PairingStorageError(f"could not read {legacy}: {exc}") from exc
    return decrypt_pairing(password, blob)


def remove(instance_uid: Optional[bytes] = None,
           path: Optional[Path] = None) -> bool:
    """Remove one stored pairing.

    Resolution order: ``path`` → ``instance_uid`` → legacy file.
    """
    if path is not None:
        target = path
    elif instance_uid is not None:
        target = _path_for_uid(instance_uid)
    else:
        target = get_storage_path()
    try:
        target.unlink()
        return True
    except FileNotFoundError:
        return False


def remove_all(*, base_dir: Optional[Path] = None) -> int:
    """Remove every pairing file (per-UID + legacy). Returns count removed."""
    removed = 0
    for entry in list_pairings(base_dir=base_dir):
        try:
            entry.path.unlink()
            removed += 1
        except FileNotFoundError:
            pass
        except OSError:
            logger.exception("could not remove pairing file %s", entry.path)
    return removed


def _encode_label(label: str) -> bytes:
    """NFC-normalise and UTF-8 encode an instance name, clamped to the slot.

    Truncation is codepoint-safe: we never split a multi-byte character,
    so the stored bytes always decode back to valid UTF-8.
    """
    if not label:
        return b""
    normalised = unicodedata.normalize("NFC", label)
    encoded = normalised.encode("utf-8")
    if len(encoded) <= LABEL_MAX_LEN:
        return encoded
    # Trim to the last whole codepoint that fits within the slot.
    truncated = encoded[:LABEL_MAX_LEN]
    while truncated:
        try:
            truncated.decode("utf-8")
            return truncated
        except UnicodeDecodeError:
            truncated = truncated[:-1]
    return b""


def _build_label_trailer(label_bytes: bytes) -> bytes:
    """Fixed-length trailer: ``[tag:1][len:1][slot:LABEL_MAX_LEN]``.

    ``slot`` is the label bytes right-padded with ``0x00`` to a constant
    size so the on-disk ciphertext length is independent of label
    presence / length.
    """
    if len(label_bytes) > LABEL_MAX_LEN:
        raise ValueError("label too long")
    slot = label_bytes + b"\x00" * (LABEL_MAX_LEN - len(label_bytes))
    return bytes([LABEL_TAG, len(label_bytes)]) + slot


def _parse_label_trailer(trailer: bytes) -> Optional[str]:
    """Decode a label trailer; return ``None`` if absent or malformed.

    Older blobs (written before labels existed) have no trailer bytes,
    so a short or missing trailer is a normal backward-compat path, not
    an error.
    """
    if len(trailer) < LABEL_TRAILER_LEN:
        return None
    if trailer[0] != LABEL_TAG:
        return None
    label_len = trailer[1]
    if label_len > LABEL_MAX_LEN:
        return None
    if label_len == 0:
        return None
    try:
        return trailer[2:2 + label_len].decode("utf-8")
    except UnicodeDecodeError:
        return None


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
