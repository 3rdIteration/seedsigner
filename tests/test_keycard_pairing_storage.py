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


# ---------------------------------------------------------------------------
# Multi-card features (per-UID storage, list, remove, legacy fallback)
# ---------------------------------------------------------------------------


@pytest.fixture
def storage_dir(tmp_path, monkeypatch):
    """Patch ``get_storage_path`` to point at a per-test directory."""
    base = tmp_path / "storage"
    base.mkdir()

    def _fake_get(filename=pairing_storage.DEFAULT_FILENAME):
        return base / filename

    monkeypatch.setattr(pairing_storage, "get_storage_path", _fake_get)
    return base


class TestFingerprint:
    def test_deterministic(self):
        a = pairing_storage.fingerprint_for_uid(b"\xAA" * 16)
        b = pairing_storage.fingerprint_for_uid(b"\xAA" * 16)
        assert a == b

    def test_distinct_for_different_uids(self):
        a = pairing_storage.fingerprint_for_uid(b"\xAA" * 16)
        b = pairing_storage.fingerprint_for_uid(b"\xBB" * 16)
        assert a != b
        assert len(a) == pairing_storage.FINGERPRINT_LEN_HEX
        assert len(b) == pairing_storage.FINGERPRINT_LEN_HEX

    def test_rejects_empty_uid(self):
        with pytest.raises(ValueError):
            pairing_storage.fingerprint_for_uid(b"")


class TestMultiCardStorage:
    def test_save_two_cards_load_each_independently(self, sample_pairing, storage_dir):
        uid_a = b"\xAA" * 16
        uid_b = b"\xBB" * 16
        pair_b = PairingInfo(pairing_index=7, pairing_key=b"\x42" * 32)

        pa = pairing_storage.save("pw", sample_pairing, uid_a)
        pb = pairing_storage.save("pw", pair_b, uid_b)
        assert pa != pb
        assert pa.exists() and pb.exists()

        loaded_a = pairing_storage.load("pw", instance_uid=uid_a)
        loaded_b = pairing_storage.load("pw", instance_uid=uid_b)
        assert loaded_a.pairing.pairing_index == sample_pairing.pairing_index
        assert loaded_b.pairing.pairing_index == 7
        assert loaded_a.instance_uid == uid_a
        assert loaded_b.instance_uid == uid_b

    def test_list_pairings_returns_all(self, sample_pairing, storage_dir):
        uid_a = b"\xAA" * 16
        uid_b = b"\xBB" * 16
        pairing_storage.save("pw", sample_pairing, uid_a)
        pairing_storage.save("pw", sample_pairing, uid_b)

        entries = pairing_storage.list_pairings(base_dir=storage_dir)
        fps = sorted(e.fingerprint for e in entries)
        expected = sorted([
            pairing_storage.fingerprint_for_uid(uid_a),
            pairing_storage.fingerprint_for_uid(uid_b),
        ])
        assert fps == expected
        for e in entries:
            assert not e.is_legacy

    def test_remove_specific_uid_keeps_others(self, sample_pairing, storage_dir):
        uid_a = b"\xAA" * 16
        uid_b = b"\xBB" * 16
        pairing_storage.save("pw", sample_pairing, uid_a)
        pairing_storage.save("pw", sample_pairing, uid_b)

        assert pairing_storage.remove(instance_uid=uid_a) is True
        # Second call returns False (nothing left for A).
        assert pairing_storage.remove(instance_uid=uid_a) is False
        # B still loadable.
        loaded = pairing_storage.load("pw", instance_uid=uid_b)
        assert loaded is not None

    def test_remove_all_clears_directory(self, sample_pairing, storage_dir):
        pairing_storage.save("pw", sample_pairing, b"\xAA" * 16)
        pairing_storage.save("pw", sample_pairing, b"\xBB" * 16)
        # Also drop a legacy file in the same dir.
        pairing_storage.save("pw", sample_pairing, b"\xCC" * 16,
                             path=storage_dir / pairing_storage.DEFAULT_FILENAME)

        count = pairing_storage.remove_all(base_dir=storage_dir)
        assert count >= 2
        assert pairing_storage.list_pairings(base_dir=storage_dir) == []

    def test_load_with_uid_returns_none_when_nothing_saved(self, storage_dir):
        assert pairing_storage.load("pw", instance_uid=b"\xAA" * 16) is None


class TestLegacyMigration:
    def test_load_with_uid_falls_back_to_legacy_when_uid_matches(
        self, sample_pairing, storage_dir,
    ):
        uid = b"\xAA" * 16
        legacy_path = storage_dir / pairing_storage.DEFAULT_FILENAME
        # Hand-write the legacy file (no per-UID file present).
        pairing_storage.save("pw", sample_pairing, uid, path=legacy_path)

        loaded = pairing_storage.load("pw", instance_uid=uid)
        assert loaded is not None
        assert loaded.pairing.pairing_index == sample_pairing.pairing_index

    def test_load_with_uid_returns_none_when_legacy_uid_mismatches(
        self, sample_pairing, storage_dir,
    ):
        legacy_path = storage_dir / pairing_storage.DEFAULT_FILENAME
        pairing_storage.save("pw", sample_pairing, b"\xAA" * 16, path=legacy_path)

        loaded = pairing_storage.load("pw", instance_uid=b"\xBB" * 16)
        assert loaded is None

    def test_save_after_legacy_load_removes_legacy_file(
        self, sample_pairing, storage_dir,
    ):
        uid = b"\xAA" * 16
        legacy_path = storage_dir / pairing_storage.DEFAULT_FILENAME
        pairing_storage.save("pw", sample_pairing, uid, path=legacy_path)
        assert legacy_path.exists()

        # Save without explicit path uses per-UID file AND removes legacy.
        new_pair = PairingInfo(pairing_index=9, pairing_key=b"\x33" * 32)
        per_uid_path = pairing_storage.save("pw", new_pair, uid)
        assert per_uid_path != legacy_path
        assert per_uid_path.exists()
        assert not legacy_path.exists()


class TestRemoveBackwardsCompat:
    def test_remove_with_path_still_works(self, sample_pairing, storage_dir):
        target = storage_dir / "kp_explicit.bin"
        pairing_storage.save("pw", sample_pairing, b"\xAA" * 16, path=target)
        assert pairing_storage.remove(path=target) is True
        assert not target.exists()

    def test_remove_no_args_targets_legacy(self, sample_pairing, storage_dir):
        legacy = storage_dir / pairing_storage.DEFAULT_FILENAME
        pairing_storage.save("pw", sample_pairing, b"\xAA" * 16, path=legacy)
        assert pairing_storage.remove() is True
        assert not legacy.exists()


# ---------------------------------------------------------------------------
# Blob format (instance naming lives in a separate microSD JSON file now —
# the label trailer is always empty, but the read path stays backward-
# compatible with older blobs that set a name)
# ---------------------------------------------------------------------------


class TestBlobFormat:
    def test_round_trip_label_always_none(self, sample_pairing, sample_uid):
        # Instance naming moved to instance_names.py; blobs always decode with
        # label=None.
        blob = encrypt_pairing("pw", sample_pairing, sample_uid)
        stored = decrypt_pairing("pw", blob)
        assert stored.label is None
        assert stored.pairing.pairing_key == sample_pairing.pairing_key
        assert stored.instance_uid == sample_uid

    def test_blob_length_stable(self, sample_pairing, sample_uid):
        # The empty label trailer keeps the on-disk size constant across
        # writes (only the random salt/nonce differ, both fixed length).
        a = encrypt_pairing("pw", sample_pairing, sample_uid)
        b = encrypt_pairing("pw", sample_pairing, sample_uid)
        assert len(a) == len(b)


class TestLegacyBlobNoTrailer:
    def test_legacy_blob_loads_with_label_none(self, sample_pairing, sample_uid):
        """A blob produced by the pre-label format must still decrypt cleanly.

        We construct one by hand: encrypt the exact plaintext that the old
        version emitted (no trailer bytes).
        """
        from Cryptodome.Cipher import AES

        password = pairing_storage._normalise_password("pw")
        salt = os.urandom(pairing_storage.SALT_LEN)
        nonce = os.urandom(pairing_storage.NONCE_LEN)
        key = pairing_storage._derive_storage_key(password, salt)
        legacy_payload = (
            bytes([sample_pairing.pairing_index])
            + sample_pairing.pairing_key
            + bytes([len(sample_uid)])
            + bytes(sample_uid)
        )
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(legacy_payload)
        legacy_blob = (
            bytes([pairing_storage.STORAGE_VERSION]) + salt + nonce + tag + ciphertext
        )

        stored = decrypt_pairing("pw", legacy_blob)
        assert stored.label is None
        assert stored.instance_uid == sample_uid
        assert stored.pairing.pairing_index == sample_pairing.pairing_index

    def test_legacy_blob_with_name_still_loads(self, sample_pairing, sample_uid):
        """A blob written by older firmware that DID set a wallet name must
        still load — pairing + UID intact — even though naming was removed.

        We hand-build a blob whose trailer carries a populated label.
        """
        from Cryptodome.Cipher import AES

        password = pairing_storage._normalise_password("pw")
        salt = os.urandom(pairing_storage.SALT_LEN)
        nonce = os.urandom(pairing_storage.NONCE_LEN)
        key = pairing_storage._derive_storage_key(password, salt)
        name = b"Cold Wallet"
        trailer = (
            bytes([pairing_storage.LABEL_TAG, len(name)])
            + name
            + b"\x00" * (pairing_storage.LABEL_MAX_LEN - len(name))
        )
        payload = (
            bytes([sample_pairing.pairing_index])
            + sample_pairing.pairing_key
            + bytes([len(sample_uid)])
            + bytes(sample_uid)
            + trailer
        )
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        blob = (
            bytes([pairing_storage.STORAGE_VERSION]) + salt + nonce + tag + ciphertext
        )

        stored = decrypt_pairing("pw", blob)
        assert stored.instance_uid == sample_uid
        assert stored.pairing.pairing_key == sample_pairing.pairing_key
        # The old name still decodes from the trailer (nothing reads it now,
        # but the load must not fail on its presence).
        assert stored.label == "Cold Wallet"
