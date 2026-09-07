"""
Tests for the MicroSD known-checksums data file and its loader helpers.

The json is maintained by .github/scripts/update_microsd_checksums.py (see
.github/workflows/update-microsd-checksums.yml); these tests pin its shape,
the zero-wiped marker, and coverage of the latest official release images
(issue #410: verification silently broke when hashes stopped being updated).
"""
import hashlib
import json

import base  # noqa: F401 — installs hardware mocks before seedsigner imports

from seedsigner.views.microsd_views import _load_known_checksums, _format_image_name

PREFIX_SIZE = 4 * 1024 * 1024
ZERO_WIPED_PREFIX = "bb9f8df61474d25e71fa00722318cd387396ca1736605e1248821cc0de3d3af8"
ZERO_WIPED_FULL = "5809d4ec68138c737b1b000db4c6ec60983e94544efd893bdfa40ebf19af60f4"


class TestKnownChecksums:
    def test_bundled_file_loads(self):
        prefix_size, images = _load_known_checksums()
        assert prefix_size == PREFIX_SIZE
        assert len(images) > 0
        for checksum, entry in images.items():
            assert len(checksum) == 64
            assert all(c in "0123456789abcdef" for c in checksum)
            assert isinstance(entry, dict)
            assert entry.get("name")
            assert entry.get("source_repo")
            assert entry.get("size_bytes", 0) >= prefix_size
            assert isinstance(entry.get("sha256"), str)
            assert len(entry["sha256"]) == 64

    def test_zero_wiped_entry_matches_zeros(self):
        prefix_size, images = _load_known_checksums()
        entry = images.get(ZERO_WIPED_PREFIX)
        assert entry is not None
        assert entry["name"] == "Zero Wiped (First 26MB)"
        assert entry["size_bytes"] == 26 * 1024 * 1024
        assert entry["sha256"] == ZERO_WIPED_FULL
        assert hashlib.sha256(b"\x00" * PREFIX_SIZE).hexdigest() == ZERO_WIPED_PREFIX
        assert hashlib.sha256(b"\x00" * 26 * 1024 * 1024).hexdigest() == ZERO_WIPED_FULL

    def test_latest_official_release_covered(self):
        _, images = _load_known_checksums()
        names = [e["name"] for e in images.values()]
        v087 = [n for n in names if "0.8.7" in n]
        assert len(v087) >= 4, f"official 0.8.7 images missing: {v087}"

    def test_bundled_file_is_valid_json_with_schema(self):
        import seedsigner.views.microsd_views as mv
        from pathlib import Path
        path = Path(mv.__file__).parent.parent / "resources" / "microsd-known-checksums.json"
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data["prefix_size"] == PREFIX_SIZE
        assert isinstance(data["images"], dict)
        for meta in data["images"].values():
            assert isinstance(meta, dict)
            assert meta.get("name")
            assert meta.get("source_repo")
            assert meta.get("size_bytes", 0) >= PREFIX_SIZE
            assert isinstance(meta.get("sha256"), str)
            assert len(meta["sha256"]) == 64

    def test_all_prefix_hashes_unique(self):
        _, images = _load_known_checksums()
        assert len(images) == len(set(images.keys()))

    def test_missing_file_returns_empty(self, tmp_path):
        prefix_size, images = _load_known_checksums(tmp_path / "nonexistent.json")
        assert prefix_size is None
        assert images == {}

    def test_corrupt_file_returns_empty(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{ this is not json", encoding="utf-8")
        prefix_size, images = _load_known_checksums(bad)
        assert prefix_size is None
        assert images == {}

    def test_non_dict_entries_are_skipped(self, tmp_path):
        good = "a" * 64
        p = tmp_path / "mixed.json"
        p.write_text(json.dumps({
            "prefix_size": PREFIX_SIZE,
            "images": {"bb": "just a string", good: {"name": "ok", "source_repo": "test", "size_bytes": PREFIX_SIZE, "sha256": good}},
        }), encoding="utf-8")
        prefix_size, images = _load_known_checksums(p)
        assert prefix_size == PREFIX_SIZE
        assert images == {good: {"name": "ok", "source_repo": "test", "size_bytes": PREFIX_SIZE, "sha256": good}}


class TestFormatImageName:
    def test_strips_common_affixes(self):
        assert _format_image_name("seedsigner_os.0.8.5.pi0.img") == "0.8.5.pi0"

    def test_plain_name_kept(self):
        lines = _format_image_name("Zero Wiped (First 26MB)").split("\n")
        assert "".join(lines) == "Zero Wiped (First 26MB)"

    def test_fits_without_ellipsis(self):
        name = "seedsigner_os.SeSi-0.8.7_ShSi-B12_.pi0-smartcard.img"
        lines = _format_image_name(name).split("\n")
        assert len(lines) <= 3
        assert all(len(line) <= 20 for line in lines)
        assert not lines[-1].endswith("...")

    def test_overlong_name_truncated_with_ellipsis(self):
        name = "seedsigner_os." + "x" * 80 + ".img"
        lines = _format_image_name(name).split("\n")
        assert len(lines) == 3
        assert all(len(line) <= 20 for line in lines)
        assert lines[-1].endswith("...")