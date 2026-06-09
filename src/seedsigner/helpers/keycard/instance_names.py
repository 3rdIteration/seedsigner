"""User-assigned Keycard instance names, stored plaintext on the microSD.

Names are **not** secret material, so they live in a single JSON file on the
microSD, separate from the encrypted pairing blob. This is deliberate: v3.2+
cards pair *ephemerally* (nothing about the pairing ever touches disk), so the
name cannot live in the pairing blob — it would simply never persist. A
standalone file works for every card (ephemeral or persistent) because it only
needs the ``instance_uid`` from the SELECT response, not a saved pairing.

File: ``<microSD>/keycard_instance_names.json`` — an object mapping a
fingerprint of the ``instance_uid`` to the name. The fingerprint (not the raw
UID) is used as the key so the file does not expose the on-card UID.

Gating: like ``settings.json`` (also plaintext on the card), naming is only
available when ``SETTING__PERSISTENT_SETTINGS`` is *Enabled* and a microSD is
inserted (:func:`is_enabled`). When it is not, names are neither written nor
read — instances fall back to the ``Inst N`` label.

Privacy tradeoff: the name is readable by anyone who reads the microSD. This is
the same exposure class as ``settings.json``. Do not put anything sensitive in
an instance name (no "decoy"/duress hints) — see the stealth notes in
CLAUDE.md.
"""

import hashlib
import json
import logging
import os
import unicodedata
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

FILENAME = "keycard_instance_names.json"
NAME_MAX_LEN = 16  # characters (NFC), matches the Rename keyboard cap
FINGERPRINT_LEN_HEX = 16  # 8 bytes of SHA-256(instance_uid)


def is_enabled() -> bool:
    """True when names may be read/written: Persistent Settings on + microSD in."""
    from seedsigner.hardware.microsd import MicroSD
    from seedsigner.models.settings import Settings
    from seedsigner.models.settings_definition import SettingsConstants

    if Settings.get_instance().get_value(
        SettingsConstants.SETTING__PERSISTENT_SETTINGS
    ) != SettingsConstants.OPTION__ENABLED:
        return False
    return MicroSD.get_instance().is_inserted


def fingerprint_for_uid(instance_uid: bytes) -> str:
    """Stable, UID-non-revealing key for the JSON map."""
    return hashlib.sha256(bytes(instance_uid)).hexdigest()[:FINGERPRINT_LEN_HEX]


def _path() -> Path:
    from seedsigner.hardware.microsd import MicroSD
    return MicroSD.get_microsd_dir() / FILENAME


def normalise_name(name: str) -> str:
    """NFC-normalise, strip, and clamp a typed name to ``NAME_MAX_LEN`` chars."""
    if not name:
        return ""
    return unicodedata.normalize("NFC", name).strip()[:NAME_MAX_LEN]


def _read_all(path: Optional[Path]) -> dict:
    target = path if path is not None else _path()
    if not target.exists():
        return {}
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except Exception:
        logger.exception("could not read instance names file %s", target)
        return {}
    return data if isinstance(data, dict) else {}


def _write_all(data: dict, path: Optional[Path]) -> None:
    target = path if path is not None else _path()
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, target)
    try:
        os.chmod(target, 0o600)
    except Exception:
        # best-effort; vfat (microSD) typically ignores POSIX modes
        pass


def get_name(instance_uid: bytes, *, path: Optional[Path] = None) -> Optional[str]:
    """Return the stored name for ``instance_uid``, or ``None``.

    Returns ``None`` when naming is gated off (unless an explicit ``path`` is
    given, which bypasses the gate for tests).
    """
    if instance_uid is None:
        return None
    if path is None and not is_enabled():
        return None
    name = _read_all(path).get(fingerprint_for_uid(instance_uid))
    return name if isinstance(name, str) and name else None


def set_name(instance_uid: bytes, name: str, *, path: Optional[Path] = None) -> None:
    """Persist (or, when ``name`` is empty, clear) the name for ``instance_uid``."""
    if instance_uid is None:
        raise ValueError("instance_uid must not be None")
    data = _read_all(path)
    fp = fingerprint_for_uid(instance_uid)
    cleaned = normalise_name(name)
    if cleaned:
        data[fp] = cleaned
    else:
        data.pop(fp, None)
    _write_all(data, path)


def remove_name(instance_uid: bytes, *, path: Optional[Path] = None) -> None:
    """Drop the stored name for ``instance_uid`` (e.g. on factory reset)."""
    if instance_uid is None:
        return
    data = _read_all(path)
    if data.pop(fingerprint_for_uid(instance_uid), None) is not None:
        _write_all(data, path)
