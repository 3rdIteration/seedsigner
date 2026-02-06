from pathlib import Path

from Cryptodome.Cipher import AES


class TapsignerBackupError(Exception):
    """Raised when a TAPSIGNER backup cannot be processed."""


def decode_tapsigner_backup(path: Path, backup_key_hex: str) -> tuple[str, str | None]:
    if not path.is_file():
        raise TapsignerBackupError("Backup file not found.")

    key_hex = backup_key_hex.strip().lower()
    if len(key_hex) != 32:
        raise TapsignerBackupError("Backup key must be 32 hex characters.")

    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise TapsignerBackupError("Backup key is not valid hex.") from exc

    encrypted = path.read_bytes()
    if not encrypted:
        raise TapsignerBackupError("Backup file is empty.")

    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=0)
    decrypted = cipher.decrypt(encrypted)

    text = decrypted.decode("utf-8", errors="ignore").replace("\r", "")
    lines = [line.strip() for line in text.split("\n") if line.strip()]

    if not lines:
        raise TapsignerBackupError("Backup decrypt failed.")

    xprv = lines[0]
    if not xprv.startswith("xprv"):
        raise TapsignerBackupError("Backup does not contain an xprv.")

    derivation_path = lines[1] if len(lines) > 1 else None
    return xprv, derivation_path

