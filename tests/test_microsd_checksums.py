"""
Tests for the MicroSD known-checksums data file and its loader helpers.

The json is maintained by .github/scripts/update_microsd_checksums.py (see
.github/workflows/update-microsd-checksums.yml); these tests pin its shape,
the zero-wiped marker, coverage of the latest official release images, and
the dirty-state fallback (issue #410).
"""
import hashlib
import json

PREFIX_SIZE = 4 * 1024 * 1024
ZERO_WIPED_PREFIX = "bb9f8df61474d25e71fa00722318cd387396ca1736605e1248821cc0de3d3af8"
ZERO_WIPED_FULL = "5809d4ec68138c737b1b000db4c6ec60983e94544efd893bdfa40ebf19af60f4"

# Path to the bundled resource file, found relative to this test file.
JSON_PATH = (__file__ and None)  # computed in each test
_RESOURCE_PATH = None


def _json_path():
    global _RESOURCE_PATH
    if _RESOURCE_PATH is None:
        from pathlib import Path
        _RESOURCE_PATH = Path(__file__).resolve().parent.parent / "src" / \
            "seedsigner" / "resources" / "microsd-known-checksums.json"
    return _RESOURCE_PATH


def _load_raw():
    """Load the bundled JSON directly (avoids seedsigner module imports)."""
    with open(_json_path(), encoding="utf-8") as fh:
        return json.load(fh)


class TestKnownChecksums:
    def test_bundled_file_loads(self):
        """Verify the JSON can be parsed and every entry has the correct shape."""
        data = _load_raw()
        assert data["prefix_size"] == PREFIX_SIZE
        for checksum, entry in data["images"].items():
            assert len(checksum) == 64
            assert all(c in "0123456789abcdef" for c in checksum)
            assert isinstance(entry, dict)
            assert entry.get("name")
            assert entry.get("source_repo")
            assert entry.get("size_bytes", 0) >= PREFIX_SIZE
            assert isinstance(entry.get("sha256"), str)
            assert len(entry["sha256"]) == 64
            assert isinstance(entry.get("volatile_offsets"), list)
            assert isinstance(entry.get("alt_prefix_hashes"), list)
            for ah in entry["alt_prefix_hashes"]:
                assert len(ah) == 64
                assert all(c in "0123456789abcdef" for c in ah)

    def test_zero_wiped_entry_matches_zeros(self):
        data = _load_raw()
        entry = data["images"].get(ZERO_WIPED_PREFIX)
        assert entry is not None
        assert entry["name"] == "Zero Wiped (First 26MB)"
        assert entry["size_bytes"] == 26 * 1024 * 1024
        assert entry["sha256"] == ZERO_WIPED_FULL
        assert entry["volatile_offsets"] == []
        assert entry["alt_prefix_hashes"] == []
        assert hashlib.sha256(b"\x00" * PREFIX_SIZE).hexdigest() == ZERO_WIPED_PREFIX
        assert hashlib.sha256(b"\x00" * 26 * 1024 * 1024).hexdigest() == ZERO_WIPED_FULL

    def test_latest_official_release_covered(self):
        data = _load_raw()
        names = [e["name"] for e in data["images"].values() if isinstance(e, dict)]
        v087 = [n for n in names if "0.8.7" in n]
        assert len(v087) >= 4, f"official 0.8.7 images missing from checksums: {v087}"

    def test_all_hashes_unique(self):
        data = _load_raw()
        all_h = set(data["images"].keys())
        for entry in data["images"].values():
            all_h.update(entry.get("alt_prefix_hashes", []))
        expected = len(data["images"]) + sum(
            len(e.get("alt_prefix_hashes", [])) for e in data["images"].values()
        )
        assert len(all_h) == expected, "collision between pristine and alt hashes"

    def test_volatile_offsets_within_image(self):
        data = _load_raw()
        for checksum, entry in data["images"].items():
            for off in entry.get("volatile_offsets", []):
                assert 0 <= off < entry["size_bytes"], (
                    f"{checksum[:12]}: offset {off} outside size {entry['size_bytes']}"
                )

    def test_missing_file_returns_empty(self, tmp_path):
        from seedsigner.views.microsd_views import _load_known_checksums
        prefix_size, pristine, alt = _load_known_checksums(tmp_path / "nonexistent.json")
        assert prefix_size is None
        assert pristine == {}
        assert alt == {}

    def test_corrupt_file_returns_empty(self, tmp_path):
        from seedsigner.views.microsd_views import _load_known_checksums
        bad = tmp_path / "bad.json"
        bad.write_text("{ this is not json", encoding="utf-8")
        prefix_size, pristine, alt = _load_known_checksums(bad)
        assert prefix_size is None
        assert pristine == {}
        assert alt == {}

    def test_non_dict_entries_skipped(self, tmp_path):
        from seedsigner.views.microsd_views import _load_known_checksums
        good = "a" * 64
        p = tmp_path / "mixed.json"
        p.write_text(json.dumps({
            "prefix_size": PREFIX_SIZE,
            "images": {"bb": "just a string", good: {"name": "ok", "source_repo": "test", "size_bytes": PREFIX_SIZE, "sha256": good, "volatile_offsets": [], "alt_prefix_hashes": []}},
        }), encoding="utf-8")
        prefix_size, pristine, alt = _load_known_checksums(p)
        assert prefix_size == PREFIX_SIZE
        assert good in pristine
        assert pristine[good]["name"] == "ok"

    def test_dirty_prefix_in_alt_map(self, tmp_path):
        """When alt prefixes exist, they should be reachable via the alt map."""
        # Build a minimal JSON with one entry that has an alt prefix hash
        fake_pristine = "b" * 64
        fake_alt = "c" * 64
        p = tmp_path / "with_alts.json"
        p.write_text(json.dumps({
            "prefix_size": PREFIX_SIZE,
            "images": {
                fake_pristine: {
                    "name": "test",
                    "source_repo": "test",
                    "tag": "test",
                    "size_bytes": PREFIX_SIZE,
                    "sha256": fake_pristine,
                    "volatile_offsets": [],
                    "alt_prefix_hashes": [fake_alt],
                }
            },
        }), encoding="utf-8")
        from seedsigner.views.microsd_views import _load_known_checksums
        prefix_size, pristine, alt = _load_known_checksums(p)
        assert fake_pristine in pristine
        assert fake_alt in alt
        assert alt[fake_alt]["name"] == "test"


class TestZeroVolatileInPlace:
    def test_zeros_single_byte(self):
        from seedsigner.views.microsd_views import _zero_volatile_in_place
        buf = bytearray(b"abcdef")
        _zero_volatile_in_place(buf, [3])
        assert buf == b"abc\x00ef"

    def test_zeros_multiple_offsets(self):
        from seedsigner.views.microsd_views import _zero_volatile_in_place
        buf = bytearray(b"abcdefgh")
        _zero_volatile_in_place(buf, [1, 5])
        assert buf == b"a\x00cde\x00gh"

    def test_offsets_outside_range_ignored(self):
        from seedsigner.views.microsd_views import _zero_volatile_in_place
        buf = bytearray(b"abc")
        _zero_volatile_in_place(buf, [10, 100])
        assert buf == b"abc"

    def test_zeros_with_offset_base(self):
        from seedsigner.views.microsd_views import _zero_volatile_in_place
        buf = bytearray(b"xyz")
        _zero_volatile_in_place(buf, [10], buf_start=10)
        assert buf == b"\x00yz"
        _zero_volatile_in_place(buf, [11], buf_start=10)
        assert buf == b"\x00\x00z"


class TestFormatImageName:
    def test_strips_common_affixes(self):
        from seedsigner.views.microsd_views import _format_image_name
        assert _format_image_name("seedsigner_os.0.8.5.pi0.img") == "0.8.5.pi0"

    def test_plain_name_kept(self):
        from seedsigner.views.microsd_views import _format_image_name
        lines = _format_image_name("Zero Wiped (First 26MB)").split("\n")
        assert "".join(lines) == "Zero Wiped (First 26MB)"

    def test_fits_without_ellipsis(self):
        from seedsigner.views.microsd_views import _format_image_name
        name = "seedsigner_os.SeSi-0.8.7_ShSi-B12_.pi0-smartcard.img"
        lines = _format_image_name(name).split("\n")
        assert len(lines) <= 3
        assert all(len(line) <= 20 for line in lines)
        assert not lines[-1].endswith("...")

    def test_overlong_name_truncated_with_ellipsis(self):
        from seedsigner.views.microsd_views import _format_image_name
        name = "seedsigner_os." + "x" * 80 + ".img"
        lines = _format_image_name(name).split("\n")
        assert len(lines) == 3
        assert all(len(line) <= 20 for line in lines)
        assert lines[-1].endswith("...")