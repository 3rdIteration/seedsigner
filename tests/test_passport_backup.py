import json
import shutil
import subprocess
from pathlib import Path

import pytest

from seedsigner.helpers.passport_backup import (
    PassportBackupDetails,
    PassportBackupError,
    decode_passport_backup,
)


pytestmark = pytest.mark.skipif(shutil.which("7z") is None, reason="p7zip not installed")


def _create_backup_archive(tmp_path: Path, password: str, mnemonic: str) -> Path:
    backup_text = "\n".join(
        [
            "# Passport backup file! DO NOT CHANGE.",
            "mnemonic = " + json.dumps(mnemonic),
            "chain = " + json.dumps("BTC"),
            "xfp = " + json.dumps("12345678"),
            "fw_version = " + json.dumps("1.0.0"),
            "# EOF",
        ]
    )

    backup_txt = tmp_path / "passport-backup.txt"
    backup_txt.write_text(backup_text)

    archive_path = tmp_path / "passport-backup.7z"
    subprocess.run(
        [
            "7z",
            "a",
            "-t7z",
            f"-p{password}",
            str(archive_path),
            str(backup_txt),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    return archive_path


def test_decode_passport_backup(tmp_path):
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    password = "1111-2222-3333-4444-5555"
    archive = _create_backup_archive(tmp_path, password, mnemonic)

    details = decode_passport_backup(archive, password)

    assert isinstance(details, PassportBackupDetails)
    assert details.mnemonic == mnemonic.split()
    assert details.chain == "BTC"
    assert details.firmware == "1.0.0"
    assert details.xfp == "12345678"


def test_invalid_password_raises(tmp_path):
    mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    archive = _create_backup_archive(tmp_path, "9999-8888-7777-6666-5555", mnemonic)

    with pytest.raises(PassportBackupError):
        decode_passport_backup(archive, "0000-0000-0000-0000-0000")
