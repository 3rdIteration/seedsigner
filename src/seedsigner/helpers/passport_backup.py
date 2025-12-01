import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class PassportBackupError(Exception):
    """Raised when a Passport backup cannot be processed."""


@dataclass
class PassportBackupDetails:
    mnemonic: list[str]
    chain: Optional[str] = None
    firmware: Optional[str] = None
    xfp: Optional[str] = None


def _format_backup_code(code: str) -> str:
    digits = [c for c in code if c.isdigit()]
    if len(digits) != 20:
        raise PassportBackupError("Backup code must include exactly 20 digits.")

    parts = ["".join(digits[i : i + 4]) for i in range(0, 20, 4)]
    return "-".join(parts)


def _extract_backup_text(path: Path, password: str) -> str:
    if not path.is_file():
        raise PassportBackupError("Backup file not found.")

    try:
        proc = subprocess.run(
            ["7za", "x", "-so", f"-p{password}", str(path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise PassportBackupError("p7zip (7za) is not installed.") from exc

    if proc.returncode != 0:
        msg = proc.stderr.decode(errors="ignore").strip() or "Unable to decrypt backup."
        raise PassportBackupError(msg)

    return proc.stdout.decode("utf-8", errors="ignore")


def _parse_backup_text(text: str) -> PassportBackupDetails:
    if not text.strip():
        raise PassportBackupError("Backup content is empty.")

    values: dict[str, object] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, raw_value = line.split("=", 1)
        key = key.strip()
        raw_value = raw_value.strip()

        try:
            value = json.loads(raw_value)
        except json.JSONDecodeError as exc:
            raise PassportBackupError(f"Invalid JSON value for '{key}'.") from exc

        values[key] = value

    mnemonic = values.get("mnemonic")
    if not mnemonic:
        raise PassportBackupError("Mnemonic not found in backup.")
    if not isinstance(mnemonic, str):
        raise PassportBackupError("Mnemonic value is invalid.")

    words = mnemonic.split()
    if len(words) not in (12, 18, 24):
        raise PassportBackupError("Unsupported mnemonic length in backup.")

    return PassportBackupDetails(
        mnemonic=words,
        chain=values.get("chain") if isinstance(values.get("chain"), str) else None,
        firmware=values.get("fw_version") if isinstance(values.get("fw_version"), str) else None,
        xfp=values.get("xfp") if isinstance(values.get("xfp"), str) else None,
    )


def decode_passport_backup(path: Path, backup_code: str) -> PassportBackupDetails:
    """Decode a Passport backup using the supplied backup code."""

    formatted_code = _format_backup_code(backup_code)
    text = _extract_backup_text(path, formatted_code)
    return _parse_backup_text(text)
