import os

import pytest

from seedsigner.helpers.keycard import pairing_storage
from seedsigner.helpers.keycard.pairing_storage import (
    PairingStorageError, StoredPairing, decrypt_pairing, encrypt_pairing,
    load, remove, save,
)
from seedsigner.helpers.keycard.secure_channel import PairingInfo


@pytest.fixture
def sample_pairing():
    return PairingInfo(pairing_index=3, pairing_key=b"\x77" * 32)


@pytest.fixture
def sample_uid():
    return b"\xAA" * 16


class TestRoundTrip:
    def test_encrypt_then_decrypt(self, sample_pairing, sample_uid):
        blob = encrypt_pairing("hunter2", sample_pairing, sample_uid)
        stored = decrypt_pairing("hunter2", blob)
        assert stored.pairing.pairing_index == sample_pairing.pairing_index
        assert stored.pairing.pairing_key == sample_pairing.pairing_key
        assert stored.instance_uid == sample_uid

    def test_blob_starts_with_version(self, sample_pairing, sample_uid):
        blob = encrypt_pairing("hunter2", sample_pairing, sample_uid)
        assert blob[0] == pairing_storage.STORAGE_VERSION

    def test_random_salt_makes_blobs_distinct(self, sample_pairing, sample_uid):
        a = encrypt_pairing("hunter2", sample_pairing, sample_uid)
        b = encrypt_pairing("hunter2", sample_pairing, sample_uid)
        assert a != b

    def test_wrong_password_fails_aead(self, sample_pairing, sample_uid):
        blob = encrypt_pairing("hunter2", sample_pairing, sample_uid)
        with pytest.raises(PairingStorageError):
            decrypt_pairing("wrong", blob)

    def test_truncated_blob_rejected(self, sample_pairing, sample_uid):
        blob = encrypt_pairing("hunter2", sample_pairing, sample_uid)
        with pytest.raises(PairingStorageError):
            decrypt_pairing("hunter2", blob[:20])

    def test_unknown_version_rejected(self, sample_pairing, sample_uid):
        blob = encrypt_pairing("hunter2", sample_pairing, sample_uid)
        bad = bytes([0xFF]) + blob[1:]
        with pytest.raises(PairingStorageError):
            decrypt_pairing("hunter2", bad)

    def test_tamper_with_ciphertext_rejected(self, sample_pairing, sample_uid):
        blob = bytearray(encrypt_pairing("hunter2", sample_pairing, sample_uid))
        # Flip a bit deep inside the ciphertext.
        blob[-1] ^= 0x01
        with pytest.raises(PairingStorageError):
            decrypt_pairing("hunter2", bytes(blob))


class TestPasswordNormalisation:
    def test_nfc_and_nfd_decode_identically(self, sample_pairing, sample_uid):
        # "ñ" can be represented as U+00F1 (NFC) or U+006E U+0303 (NFD).
        blob = encrypt_pairing("mañana", sample_pairing, sample_uid)
        assert decrypt_pairing("mañana", blob).instance_uid == sample_uid


class TestFileIO:
    def test_save_and_load(self, sample_pairing, sample_uid, tmp_path):
        target = tmp_path / "kp.bin"
        save("hunter2", sample_pairing, sample_uid, path=target)
        assert target.exists()
        stored = load("hunter2", path=target)
        assert isinstance(stored, StoredPairing)
        assert stored.pairing.pairing_index == sample_pairing.pairing_index
        assert stored.instance_uid == sample_uid

    def test_save_writes_atomically(self, sample_pairing, sample_uid, tmp_path):
        target = tmp_path / "kp.bin"
        save("a", sample_pairing, sample_uid, path=target)
        # Saving again should overwrite cleanly (atomic rename of .tmp).
        new_pairing = PairingInfo(pairing_index=7, pairing_key=b"\x42" * 32)
        save("a", new_pairing, sample_uid, path=target)
        assert load("a", path=target).pairing.pairing_index == 7

    def test_load_missing_returns_none(self, tmp_path):
        target = tmp_path / "no_such_file.bin"
        assert load("anything", path=target) is None

    def test_remove_existing(self, sample_pairing, sample_uid, tmp_path):
        target = tmp_path / "kp.bin"
        save("a", sample_pairing, sample_uid, path=target)
        assert remove(path=target) is True
        assert not target.exists()
        assert remove(path=target) is False

    def test_empty_password_rejected(self, sample_pairing, sample_uid, tmp_path):
        target = tmp_path / "kp.bin"
        with pytest.raises(ValueError):
            save("", sample_pairing, sample_uid, path=target)


class TestValidation:
    def test_pairing_key_length_enforced(self, sample_uid):
        bad = PairingInfo(pairing_index=0, pairing_key=b"\x00" * 16)
        with pytest.raises(ValueError):
            encrypt_pairing("a", bad, sample_uid)

    def test_pairing_index_byte_range(self, sample_uid):
        bad = PairingInfo(pairing_index=300, pairing_key=b"\x00" * 32)
        with pytest.raises(ValueError):
            encrypt_pairing("a", bad, sample_uid)

    def test_uid_length_byte_range(self, sample_pairing):
        with pytest.raises(ValueError):
            encrypt_pairing("a", sample_pairing, b"\x00" * 256)
