"""
Tests for the MicroSD known-checksums data file and its loader helpers.

The json is maintained by .github/scripts/update_microsd_checksums.py (see
.github/workflows/update-microsd-checksums.yml); these tests pin its shape,
the zero-wiped marker, and coverage of the latest official release images
(issue #410: verification silently broke when hashes stopped being updated).
"""
import hashlib
import json

# Import base FIRST: it installs the hardware/renderer mocks into sys.modules
# before any seedsigner import (see tests/conftest.py single-identity note).
import base  # noqa: F401

from seedsigner.views.microsd_views import _load_known_checksums, _format_image_name

ZERO_WIPED_HASH = "5809d4ec68138c737b1b000db4c6ec60983e94544efd893bdfa40ebf19af60f4"
READ_BYTES = 26 * 1024 * 1024


class TestKnownChecksums:
    def test_bundled_file_loads(self):
        known = _load_known_checksums()
        assert len(known) > 0
        for checksum, name in known.items():
            assert len(checksum) == 64
            assert all(c in "0123456789abcdef" for c in checksum)
            assert isinstance(name, str) and name

    def test_zero_wiped_entry_matches_26mib_of_zeros(self):
        known = _load_known_checksums()
        assert ZERO_WIPED_HASH in known
        assert hashlib.sha256(b"\x00" * READ_BYTES).hexdigest() == ZERO_WIPED_HASH

    def test_latest_official_release_covered(self):
        names = list(_load_known_checksums().values())
        v087 = [n for n in names if "0.8.7" in n]
        assert len(v087) >= 4, f"official 0.8.7 images missing from known checksums: {v087}"

    def test_bundled_file_is_valid_json_with_schema(self):
        import seedsigner.views.microsd_views as mv
        from pathlib import Path
        path = Path(mv.__file__).parent.parent / "resources" / "microsd-known-checksums.json"
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert isinstance(data["images"], dict)
        for meta in data["images"].values():
            assert isinstance(meta, dict)
            assert meta.get("name")
            assert "source_repo" in meta

    def test_missing_file_returns_empty(self, tmp_path):
        assert _load_known_checksums(tmp_path / "nonexistent.json") == {}

    def test_corrupt_file_returns_empty(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{ this is not json", encoding="utf-8")
        assert _load_known_checksums(bad) == {}

    def test_non_dict_entries_are_skipped(self, tmp_path):
        good = "a" * 64
        p = tmp_path / "mixed.json"
        p.write_text(json.dumps({"images": {"bb": "just a string", good: {"name": "ok"}}}), encoding="utf-8")
        assert _load_known_checksums(p) == {good: "ok"}


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

    def test_real_long_name_fits_three_lines(self):
        name = "seedsigner_os.SeSi-0.8.7_ShSi-B12-pre_.lafrite-smartcard-dev.img"
        lines = _format_image_name(name).split("\n")
        assert len(lines) == 3
        assert all(len(line) <= 20 for line in lines)

    def test_overlong_name_truncated_with_ellipsis(self):
        name = "seedsigner_os." + "x" * 80 + ".img"
        lines = _format_image_name(name).split("\n")
        assert len(lines) == 3
        assert all(len(line) <= 20 for line in lines)
        assert lines[-1].endswith("...")
