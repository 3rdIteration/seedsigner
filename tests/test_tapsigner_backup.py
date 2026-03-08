from pathlib import Path

import pytest
from Cryptodome.Cipher import AES

from seedsigner.helpers.tapsigner_backup import TapsignerBackupError, decode_tapsigner_backup


def test_decode_tapsigner_backup(tmp_path: Path):
    key_hex = "00112233445566778899aabbccddeeff"
    key = bytes.fromhex(key_hex)
    plaintext = b"xprv123456789\nm/84h/0h/0h\n"

    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=0)
    encrypted = cipher.encrypt(plaintext)

    backup = tmp_path / "test.aes"
    backup.write_bytes(encrypted)

    xprv, path = decode_tapsigner_backup(backup, key_hex)
    assert xprv == "xprv123456789"
    assert path == "m/84h/0h/0h"


def test_decode_tapsigner_backup_wrong_key(tmp_path: Path):
    key_hex = "00112233445566778899aabbccddeeff"
    wrong_key_hex = "ffeeddccbbaa99887766554433221100"
    key = bytes.fromhex(key_hex)
    plaintext = b"xprv123456789\nm/84h/0h/0h\n"

    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=0)
    encrypted = cipher.encrypt(plaintext)

    backup = tmp_path / "test.aes"
    backup.write_bytes(encrypted)

    with pytest.raises(TapsignerBackupError, match="Unable to decrypt backup. Check backup key."):
        decode_tapsigner_backup(backup, wrong_key_hex)
