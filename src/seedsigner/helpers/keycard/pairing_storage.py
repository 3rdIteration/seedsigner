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

The label trailer is written for every new blob (since v1) but is
*optional* on read: blobs written before the label trailer existed
have no trailer bytes and decode with ``label=None``. The label slot
is constant length (16 bytes, zero-padded) so the on-disk ciphertext
size does not leak whether a name was set.
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

# Per-UID plaintext wallet name. Labels are display strings, not
# secrets — they exist so the user can tell their cards apart in the
# UI. Stored separately from the encrypted pairing blob so it works
# uniformly for v3.2+ ephemeral cards (no on-disk blob) and avoids
# asking the user for a pairing password just to rename a wallet.
LABEL_FILE_PREFIX = "keycard_label_"
LABEL_FILE_SUFFIX = ".txt"
LABEL_FILE_MAGIC = b"kclbl1\n"


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
    label: Optional[str] = None,
) -> bytes:
    if len(pairing.pairing_key) != 32:
        raise ValueError("pairing key must be 32 bytes")
    if not 0 <= pairing.pairing_index <= 0xFF:
        raise ValueError("pairing index must fit in one byte")
    if len(instance_uid) > 0xFF:
        raise ValueError("instance UID too long")
    label_bytes = _encode_label(label)
    password = _normalise_password(password)
    payload = (
        bytes([pairing.pairing_index])
        + pairing.pairing_key
        + bytes([len(instance_uid)])
        + bytes(instance_uid)
        + _build_label_trailer(label_bytes)
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


def _label_path_for_uid(instance_uid: bytes, *,
                       base_dir: Optional[Path] = None) -> Path:
    fp = fingerprint_for_uid(instance_uid)
    filename = f"{LABEL_FILE_PREFIX}{fp}{LABEL_FILE_SUFFIX}"
    if base_dir is not None:
        return base_dir / filename
    return get_storage_path(filename)


def save_label_only(instance_uid: bytes, label: Optional[str], *,
                    base_dir: Optional[Path] = None) -> Path:
    """Persist a wallet name in a per-UID plaintext file.

    Labels are display strings, not secrets — plaintext storage is
    sufficient and avoids forcing the user to enter a pairing password
    just to rename a wallet (which doesn't work at all for v3.2+
    ephemeral cards, since they have no on-disk pairing blob).

    Passing ``label=None`` or ``""`` deletes any existing file.
    """
    target = _label_path_for_uid(instance_uid, base_dir=base_dir)
    if not label:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        return target
    encoded = label.encode("utf-8")
    if len(encoded) > LABEL_MAX_LEN:
        raise ValueError(f"label exceeds {LABEL_MAX_LEN} UTF-8 bytes")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_bytes(LABEL_FILE_MAGIC + encoded)
    os.replace(tmp, target)
    try:
        os.chmod(target, 0o600)
    except Exception:
        pass
    return target


def load_label_only(instance_uid: bytes, *,
                    base_dir: Optional[Path] = None) -> Optional[str]:
    """Read the per-UID label file. ``None`` if absent or malformed."""
    target = _label_path_for_uid(instance_uid, base_dir=base_dir)
    if not target.exists():
        return None
    try:
        data = target.read_bytes()
    except OSError:
        return None
    if not data.startswith(LABEL_FILE_MAGIC):
        return None
    encoded = data[len(LABEL_FILE_MAGIC):]
    if not encoded:
        return None
    if len(encoded) > LABEL_MAX_LEN:
        return None
    try:
        decoded = encoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return decoded if decoded else None


def remove_label_only(instance_uid: bytes, *,
                      base_dir: Optional[Path] = None) -> bool:
    """Delete the per-UID label file if present."""
    target = _label_path_for_uid(instance_uid, base_dir=base_dir)
    try:
        target.unlink()
        return True
    except FileNotFoundError:
        return False


def remove_all_label_only(*, base_dir: Optional[Path] = None) -> int:
    """Delete every per-UID label file. Returns the count removed."""
    if base_dir is None:
        try:
            base_dir = get_storage_path().parent
        except Exception:
            return 0
    if not base_dir.exists():
        return 0
    removed = 0
    for entry in sorted(base_dir.iterdir()):
        if not entry.is_file():
            continue
        name = entry.name
        if name.startswith(LABEL_FILE_PREFIX) and name.endswith(LABEL_FILE_SUFFIX):
            try:
                entry.unlink()
                removed += 1
            except FileNotFoundError:
                pass
            except OSError:
                logger.exception("could not remove label file %s", entry)
    return removed


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
         path: Optional[Path] = None, label: Optional[str] = None) -> Path:
    """Persist a pairing.

    With ``path`` explicit (test path) writes there. Otherwise writes to
    the per-UID file and, if a legacy single-card file exists, removes
    it so we don't keep stale duplicates.
    """
    blob = encrypt_pairing(password, pairing, instance_uid, label=label)
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


def update_label(password: str, instance_uid: bytes,
                 new_label: Optional[str]) -> Path:
    """Re-encrypt the per-UID blob with a new label, keeping pairing intact.

    Raises ``PairingStorageError`` if the blob cannot be loaded (no file,
    wrong password) and lets ``OSError`` propagate to the caller so the
    UI can surface microSD-missing failures.
    """
    stored = load(password, instance_uid=instance_uid)
    if stored is None:
        raise PairingStorageError("no stored pairing for this card")
    return save(password, stored.pairing, instance_uid, label=new_label)


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


def _encode_label(label: Optional[str]) -> bytes:
    """Return the UTF-8 bytes of ``label`` (empty if None) and enforce cap."""
    if label is None or label == "":
        return b""
    encoded = label.encode("utf-8")
    if len(encoded) > LABEL_MAX_LEN:
        raise ValueError(f"label exceeds {LABEL_MAX_LEN} UTF-8 bytes")
    return encoded


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
