import json

from seedsigner.helpers.keycard import instance_names

UID = b"\xAB" * 16
UID2 = b"\xCD" * 16


def test_set_get_round_trip(tmp_path):
    p = tmp_path / "names.json"
    instance_names.set_name(UID, "Cold", path=p)
    assert instance_names.get_name(UID, path=p) == "Cold"


def test_missing_returns_none(tmp_path):
    p = tmp_path / "names.json"
    assert instance_names.get_name(UID, path=p) is None  # file absent
    instance_names.set_name(UID, "A", path=p)
    assert instance_names.get_name(UID2, path=p) is None  # different UID


def test_two_instances_independent(tmp_path):
    p = tmp_path / "names.json"
    instance_names.set_name(UID, "One", path=p)
    instance_names.set_name(UID2, "Two", path=p)
    assert instance_names.get_name(UID, path=p) == "One"
    assert instance_names.get_name(UID2, path=p) == "Two"


def test_name_trimmed_and_clamped(tmp_path):
    p = tmp_path / "names.json"
    instance_names.set_name(UID, "  Trim  ", path=p)
    assert instance_names.get_name(UID, path=p) == "Trim"
    instance_names.set_name(UID, "X" * 40, path=p)
    assert instance_names.get_name(UID, path=p) == "X" * instance_names.NAME_MAX_LEN


def test_empty_or_whitespace_name_clears(tmp_path):
    p = tmp_path / "names.json"
    instance_names.set_name(UID, "Cold", path=p)
    instance_names.set_name(UID, "   ", path=p)  # whitespace-only → clear
    assert instance_names.get_name(UID, path=p) is None


def test_remove_name(tmp_path):
    p = tmp_path / "names.json"
    instance_names.set_name(UID, "Cold", path=p)
    instance_names.remove_name(UID, path=p)
    assert instance_names.get_name(UID, path=p) is None


def test_keyed_by_fingerprint_not_raw_uid(tmp_path):
    p = tmp_path / "names.json"
    instance_names.set_name(UID, "Cold", path=p)
    data = json.loads(p.read_text())
    assert UID.hex() not in data  # raw UID is not written to disk
    assert instance_names.fingerprint_for_uid(UID) in data


def test_corrupt_file_is_ignored(tmp_path):
    p = tmp_path / "names.json"
    p.write_text("not valid json {{")
    assert instance_names.get_name(UID, path=p) is None
    # A subsequent set overwrites the garbage cleanly.
    instance_names.set_name(UID, "Cold", path=p)
    assert instance_names.get_name(UID, path=p) == "Cold"


def test_get_name_gated_off_returns_none(monkeypatch):
    # Without an explicit path, get_name honours is_enabled().
    monkeypatch.setattr(instance_names, "is_enabled", lambda: False)
    assert instance_names.get_name(UID) is None


def test_none_uid_is_safe(tmp_path):
    p = tmp_path / "names.json"
    assert instance_names.get_name(None, path=p) is None
    instance_names.remove_name(None, path=p)  # no-op, no raise
