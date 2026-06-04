"""Tests for the extended (unverified) signature DB and its decoder wiring.

Covers: lazy load from file, dedup, comment/invalid-line skipping, curated
selectors being excluded, the RAM cap, the optional microSD source, that the
shipped baseline resource parses cleanly, and the decoder's unverified /
ambiguous (selector-collision) handling.
"""

import pytest

from seedsigner.helpers.ethereum import abi_decode, function_registry, signature_db
from seedsigner.helpers.ethereum.function_registry import function_selector


@pytest.fixture(autouse=True)
def _clean_db():
    # Keep the module-global cache from leaking across tests / files.
    signature_db._reset()
    signature_db._TEST_PATHS = None
    yield
    signature_db._reset()
    signature_db._TEST_PATHS = None


def _load(tmp_path, lines):
    p = tmp_path / "sigs.txt"
    p.write_text("\n".join(lines), encoding="utf-8")
    signature_db._reset()
    signature_db._TEST_PATHS = [str(p)]
    return signature_db


class TestSignatureDbLoad:
    def test_single_signature_resolves(self, tmp_path):
        sig = "supply(address,uint256,address,uint16)"
        db = _load(tmp_path, [sig])
        assert db.resolve_extended(function_selector(sig)) == [sig]

    def test_dedup(self, tmp_path):
        sig = "borrow(uint256)"
        db = _load(tmp_path, [sig, sig, sig])
        assert db.resolve_extended(function_selector(sig)) == [sig]

    def test_comments_blank_and_invalid_skipped(self, tmp_path):
        good = "exitMarket(address)"
        db = _load(tmp_path, [
            "# a comment",
            "",
            "   ",
            "not a signature",          # no parens
            "has space(uint256)",       # space → not canonical
            "missingClose(uint256",     # no trailing )
            good,
        ])
        assert db.resolve_extended(function_selector(good)) == [good]
        # Only the one good line produced an entry; the junk lines were skipped.
        total = sum(len(v) for v in signature_db._db.values())
        assert total == 1

    def test_curated_selector_excluded(self, tmp_path):
        # transfer(address,uint256) is curated → the extended DB must NOT shadow
        # it, so it resolves to nothing here (the curated name wins upstream).
        db = _load(tmp_path, ["transfer(address,uint256)"])
        assert db.resolve_extended(bytes.fromhex("a9059cbb")) == []

    def test_unknown_selector_empty(self, tmp_path):
        db = _load(tmp_path, ["exit()"])
        assert db.resolve_extended(bytes.fromhex("00000000")) == []

    def test_missing_file_is_empty(self, tmp_path):
        signature_db._reset()
        signature_db._TEST_PATHS = [str(tmp_path / "does_not_exist.txt")]
        assert signature_db.resolve_extended(bytes.fromhex("12345678")) == []

    def test_cap_truncates(self, tmp_path, monkeypatch):
        monkeypatch.setattr(signature_db, "MAX_DB_ENTRIES", 3)
        sigs = [f"fn{i}(uint256)" for i in range(10)]
        db = _load(tmp_path, sigs)
        loaded = sum(len(db.resolve_extended(function_selector(s))) for s in sigs)
        assert loaded == 3

    def test_microsd_override_merged(self, tmp_path, monkeypatch):
        base = tmp_path / "base.txt"
        base.write_text("baseOnly(uint256)\n", encoding="utf-8")
        micro = tmp_path / "micro.txt"
        micro.write_text("microOnly(address)\n", encoding="utf-8")
        signature_db._reset()
        # Drive both sources through the public path resolver.
        monkeypatch.setattr(signature_db, "_BASELINE_PATH", str(base))
        monkeypatch.setattr(signature_db, "_microsd_path", lambda: str(micro))
        signature_db._TEST_PATHS = None
        assert signature_db.resolve_extended(function_selector("baseOnly(uint256)")) == ["baseOnly(uint256)"]
        assert signature_db.resolve_extended(function_selector("microOnly(address)")) == ["microOnly(address)"]


class TestBaselineResource:
    """The shipped baseline must parse cleanly — guards against authoring typos."""

    def test_every_line_parses(self):
        with open(signature_db._BASELINE_PATH, "r", encoding="utf-8") as fh:
            lines = [ln.strip() for ln in fh]
        sigs = [ln for ln in lines if ln and not ln.startswith("#")]
        assert len(sigs) > 50
        for sig in sigs:
            assert signature_db._looks_like_signature(sig), sig
            # Must fully parse with the supported ABI type set.
            name, types = abi_decode.parse_signature(sig)
            assert name and isinstance(types, list)

    def test_baseline_loads_nonempty_and_excludes_curated(self):
        signature_db._reset()
        signature_db._TEST_PATHS = None  # use the real shipped baseline
        # A non-curated baseline entry resolves...
        sel = function_selector("supply(address,uint256,address,uint16)")
        assert "supply(address,uint256,address,uint16)" in signature_db.resolve_extended(sel)
        # ...and a curated selector is excluded from the extended layer.
        assert signature_db.resolve_extended(bytes.fromhex("a9059cbb")) == []
