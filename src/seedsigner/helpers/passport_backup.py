import io
import json
from dataclasses import dataclass
from typing import Optional

import py7zr


class PassportBackupError(Exception):
    pass


@dataclass
class PassportBackupDetails:
    mnemonic: list[str]
    firmware_version: Optional[str] = None
    firmware_date: Optional[str] = None


def _parse_backup_text(text: str) -> PassportBackupDetails:
    if not text:
        raise PassportBackupError("Backup file is empty")

    mnemonic: Optional[list[str]] = None
    fw_version: Optional[str] = None
    fw_date: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        try:
            parsed_value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise PassportBackupError(f"Unable to parse backup line: {line}") from exc

        if key == "mnemonic":
            if isinstance(parsed_value, str):
                mnemonic = parsed_value.split()
            elif isinstance(parsed_value, list):
                mnemonic = [str(word) for word in parsed_value]
        elif key == "fw_version":
            fw_version = parsed_value if isinstance(parsed_value, str) else str(parsed_value)
        elif key == "fw_date":
            fw_date = parsed_value if isinstance(parsed_value, str) else str(parsed_value)

    if not mnemonic:
        raise PassportBackupError("Mnemonic not found in backup")

    return PassportBackupDetails(
        mnemonic=mnemonic,
        firmware_version=fw_version,
        firmware_date=fw_date,
    )


def load_passport_backup_from_text(text: str) -> PassportBackupDetails:
    return _parse_backup_text(text)


def load_passport_backup_from_7z(data: bytes, password: str) -> PassportBackupDetails:
    if not password:
        raise PassportBackupError("Backup password is required to decrypt the file")

    try:
        with py7zr.SevenZipFile(io.BytesIO(data), mode="r", password=password) as archive:
            names = archive.getnames()
            if not names:
                raise PassportBackupError("Backup archive is empty")

            with archive.open(names[0], "r") as f:
                content = f.read()
    except py7zr.Bad7zFile as exc:
        raise PassportBackupError("Invalid or corrupted backup archive") from exc
    except py7zr.PasswordRequired:
        raise PassportBackupError("Backup password is required")
    except py7zr.PasswordError as exc:
        raise PassportBackupError("Incorrect backup password") from exc
    except Exception as exc:  # pragma: no cover - defensive
        raise PassportBackupError("Failed to read backup archive") from exc

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PassportBackupError("Backup content is not valid UTF-8") from exc

    return _parse_backup_text(text)
