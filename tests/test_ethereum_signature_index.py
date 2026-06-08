"""Tests for the bundled binary selector index (full-4byte-scale coverage).

Covers: binary-search correctness + boundaries, selector-collision gathering,
corrupt/missing-file safety (must never raise — signing proceeds blind), the
build-time generator round-trip + determinism, the resolve_all union with the
text DB, and the verified high-value protocol selectors (1inch / 0x / Seaport /
CowSwap) added to the curated registry.
"""

import importlib.util
import os
import struct
import zlib

import pytest

from seedsigner.helpers.ethereum import signature_db as sdb
from seedsigner.helpers.ethereum import calldata_decoder, function_registry
from seedsigner.helpers.ethereum.function_registry import function_selector


# --- load the build-machine generator as a module ---------------------------
_SCRIPT = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "scripts", "build_eth_signature_index.py")
)
_spec = importlib.util.spec_from_file_location("build_eth_signature_index", _SCRIPT)
build_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_mod)
build = build_mod.build


@pytest.fixture(autouse=True)
def _clean():
    sdb._reset()
    sdb._TEST_PATHS = []                 # text layer off unless a test opts in
    sdb._TEST_INDEX_PATHS = None
    yield
    sdb._reset()
    sdb._TEST_PATHS = None
    sdb._TEST_INDEX_PATHS = None


# --- low-level file crafting (mirrors the on-disk format independently) ------

def _make(records):
    """records: list of (selector:bytes4, signature:str) -> (index_bytes, blob_bytes)."""
    recs = sorted(records, key=lambda r: (r[0], r[1]))
    body = bytearray()
    pos = {}
    for _sel, sig in recs:
        if sig not in pos:
            pos[sig] = len(body)
            body += sig.encode("ascii")
    blob = struct.pack("<4sHHII", sdb._BLOB_MAGIC, 1, 0, len(pos), 0) + bytes(body)
    crc = zlib.crc32(blob) & 0xFFFFFFFF
    rec = bytearray()
    for sel, sig in recs:
        rec += sel + struct.pack("<II", sdb._BLOB_HEADER_SIZE + pos[sig],
                                 len(sig.encode("ascii")))
    idx = struct.pack("<4sHHIII12x", sdb._INDEX_MAGIC, 1, sdb._INDEX_RECORD_SIZE,
                      len(recs), len(blob), crc) + bytes(rec)
    return idx, blob


def _write(tmp_path, idx, blob, name="a"):
    ip = tmp_path / f"{name}.idx"
    bp = tmp_path / f"{name}.blob"
    ip.write_bytes(idx)
    bp.write_bytes(blob)
    return str(ip), str(bp)


def _install(tmp_path, records):
    idx, blob = _make(records)
    ip, bp = _write(tmp_path, idx, blob)
    sdb._reset()
    sdb._TEST_INDEX_PATHS = (ip, bp)
    return ip, bp


def _sel(b):
    return bytes.fromhex(b)


class TestBinarySearch:
    def test_single_hit_and_miss(self, tmp_path):
        _install(tmp_path, [
            (_sel("00000001"), "a(uint256)"),
            (_sel("0000beef"), "b(address)"),
            (_sel("ffffffff"), "c(bool)"),
        ])
        assert sdb.resolve_bundled(_sel("0000beef")) == ["b(address)"]
        assert sdb.resolve_bundled(_sel("12345678")) == []

    def test_first_and_last_record(self, tmp_path):
        _install(tmp_path, [
            (_sel("00000000"), "first(uint256)"),
            (_sel("11111111"), "mid(address)"),
            (_sel("ffffffff"), "last(bool)"),
        ])
        assert sdb.resolve_bundled(_sel("00000000")) == ["first(uint256)"]
        assert sdb.resolve_bundled(_sel("ffffffff")) == ["last(bool)"]

    def test_empty_index(self, tmp_path):
        _install(tmp_path, [])
        assert sdb.resolve_bundled(_sel("00000000")) == []

    def test_wrong_length_selector(self, tmp_path):
        _install(tmp_path, [(_sel("00000001"), "a(uint256)")])
        assert sdb.resolve_bundled(b"\x00\x00") == []


class TestCollisions:
    def test_all_candidates_returned(self, tmp_path):
        s = _sel("12345678")
        _install(tmp_path, [
            (s, "foo(uint256)"),
            (s, "bar(address)"),
            (_sel("00000001"), "other(bool)"),
        ])
        got = sdb.resolve_bundled(s)
        assert sorted(got) == ["bar(address)", "foo(uint256)"]

    def test_decode_marks_ambiguous(self, tmp_path):
        s = _sel("12345678")
        _install(tmp_path, [(s, "foo(uint256)"), (s, "bar(address)")])
        d = calldata_decoder.decode_calldata(s + b"\x00" * 32)
        assert d.ambiguous and d.verified is False and len(d.candidates) == 2

    def test_candidate_cap(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sdb, "_MAX_CANDIDATES", 4)
        s = _sel("aaaaaaaa")
        _install(tmp_path, [(s, f"poison{i}(uint256)") for i in range(20)])
        assert len(sdb.resolve_bundled(s)) == 4


class TestSafety:
    """A missing or corrupt index must never raise — return [] and sign blind."""

    def test_missing_files(self, tmp_path):
        sdb._reset()
        sdb._TEST_INDEX_PATHS = (str(tmp_path / "no.idx"), str(tmp_path / "no.blob"))
        assert sdb.resolve_bundled(_sel("00000001")) == []
        assert sdb._index_state == "absent"

    def test_bad_index_magic(self, tmp_path):
        idx, blob = _make([(_sel("00000001"), "a(uint256)")])
        idx = b"XXXX" + idx[4:]
        ip, bp = _write(tmp_path, idx, blob)
        sdb._reset()
        sdb._TEST_INDEX_PATHS = (ip, bp)
        assert sdb.resolve_bundled(_sel("00000001")) == []
        assert sdb._index_state == "bad"

    def test_bad_blob_magic(self, tmp_path):
        idx, blob = _make([(_sel("00000001"), "a(uint256)")])
        blob = b"YYYY" + blob[4:]
        ip, bp = _write(tmp_path, idx, blob)
        sdb._reset()
        sdb._TEST_INDEX_PATHS = (ip, bp)
        assert sdb.resolve_bundled(_sel("00000001")) == []
        assert sdb._index_state == "bad"

    def test_index_size_mismatch(self, tmp_path):
        idx, blob = _make([(_sel("00000001"), "a(uint256)")])
        idx = idx[:-4]  # truncate one record's tail
        ip, bp = _write(tmp_path, idx, blob)
        sdb._reset()
        sdb._TEST_INDEX_PATHS = (ip, bp)
        assert sdb.resolve_bundled(_sel("00000001")) == []

    def test_blob_size_mismatch(self, tmp_path):
        idx, blob = _make([(_sel("00000001"), "a(uint256)")])
        blob = blob + b"\x00"  # blob longer than header says
        ip, bp = _write(tmp_path, idx, blob)
        sdb._reset()
        sdb._TEST_INDEX_PATHS = (ip, bp)
        assert sdb.resolve_bundled(_sel("00000001")) == []

    def test_blob_crc_mismatch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sdb, "_VERIFY_BLOB_CRC", True)  # off by default
        idx, blob = _make([(_sel("00000001"), "abcd(uint256)")])
        blob = blob[:-1] + bytes([blob[-1] ^ 0xFF])  # flip a body byte
        ip, bp = _write(tmp_path, idx, blob)
        sdb._reset()
        sdb._TEST_INDEX_PATHS = (ip, bp)
        assert sdb.resolve_bundled(_sel("00000001")) == []
        assert sdb._index_state == "bad"

    def test_out_of_range_offset_skips_record(self, tmp_path):
        # Two records for two selectors; corrupt the first record's offset to
        # point past the blob. That record is skipped; the other still resolves.
        recs = [(_sel("00000001"), "a(uint256)"), (_sel("00000002"), "b(address)")]
        idx, blob = _make(recs)
        # Rewrite record 0's (offset,len) to a huge offset.
        base = sdb._INDEX_HEADER_SIZE + 0 * sdb._INDEX_RECORD_SIZE
        bad = idx[:base + 4] + struct.pack("<II", 10 ** 9, 9) + idx[base + 12:]
        ip, bp = _write(tmp_path, bad, blob)
        sdb._reset()
        sdb._TEST_INDEX_PATHS = (ip, bp)
        assert sdb.resolve_bundled(_sel("00000001")) == []      # corrupt one skipped
        assert sdb.resolve_bundled(_sel("00000002")) == ["b(address)"]


class TestGeneratorRoundTrip:
    def _dump(self, tmp_path, lines):
        p = tmp_path / "sigs.txt"
        p.write_text("\n".join(lines), encoding="utf-8")
        return str(p)

    def test_round_trip(self, tmp_path):
        inp = self._dump(tmp_path, [
            "poolSupply(address,uint256,address,uint16)",
            "borrow(uint256)",
        ])
        out_i = str(tmp_path / "i.bin")
        out_b = str(tmp_path / "b.bin")
        build(inp, out_i, out_b, verbose=False)
        sdb._reset()
        sdb._TEST_INDEX_PATHS = (out_i, out_b)
        for sig in ("poolSupply(address,uint256,address,uint16)", "borrow(uint256)"):
            assert sdb.resolve_bundled(function_selector(sig)) == [sig]

    def test_dedup_comments_and_invalid_skipped(self, tmp_path):
        inp = self._dump(tmp_path, [
            "# comment",
            "",
            "has space(uint256)",        # not canonical
            "missingClose(uint256",      # no )
            "exit()",
            "exit()",                    # dup
        ])
        out_i = str(tmp_path / "i.bin")
        out_b = str(tmp_path / "b.bin")
        n_records, n_distinct, _, _ = build(inp, out_i, out_b, verbose=False)
        assert n_records == 1 and n_distinct == 1
        sdb._reset()
        sdb._TEST_INDEX_PATHS = (out_i, out_b)
        assert sdb.resolve_bundled(function_selector("exit()")) == ["exit()"]

    def test_curated_excluded(self, tmp_path):
        inp = self._dump(tmp_path, ["transfer(address,uint256)", "borrow(uint256)"])
        out_i = str(tmp_path / "i.bin")
        out_b = str(tmp_path / "b.bin")
        n_records, _, _, _ = build(inp, out_i, out_b, verbose=False)
        assert n_records == 1  # transfer is curated -> dropped
        sdb._reset()
        sdb._TEST_INDEX_PATHS = (out_i, out_b)
        assert sdb.resolve_bundled(bytes.fromhex("a9059cbb")) == []

    def test_deterministic_output(self, tmp_path):
        inp = self._dump(tmp_path, ["b(uint256)", "a(address)", "c(bool)", "a(address)"])
        i1, b1 = str(tmp_path / "i1"), str(tmp_path / "b1")
        i2, b2 = str(tmp_path / "i2"), str(tmp_path / "b2")
        build(inp, i1, b1, verbose=False)
        build(inp, i2, b2, verbose=False)
        assert open(i1, "rb").read() == open(i2, "rb").read()
        assert open(b1, "rb").read() == open(b2, "rb").read()


class TestResolveAllUnion:
    def test_union_of_layers(self, tmp_path):
        # binary index carries one selector; text DB carries another.
        bin_sig = "alpha(uint256)"
        txt_sig = "poolSupply(address,uint256,address,uint16)"
        _install(tmp_path, [(function_selector(bin_sig), bin_sig)])
        txt = tmp_path / "t.txt"
        txt.write_text(txt_sig + "\n", encoding="utf-8")
        sdb._TEST_PATHS = [str(txt)]
        assert sdb.resolve_all(function_selector(bin_sig)) == [bin_sig]
        assert sdb.resolve_all(function_selector(txt_sig)) == [txt_sig]

    def test_dedup_across_layers(self, tmp_path):
        sig = "poolSupply(address,uint256,address,uint16)"
        sel = function_selector(sig)
        _install(tmp_path, [(sel, sig)])
        txt = tmp_path / "t.txt"
        txt.write_text(sig + "\n", encoding="utf-8")
        sdb._TEST_PATHS = [str(txt)]
        assert sdb.resolve_all(sel) == [sig]   # same sig in both -> once

    def test_binary_only_selector_is_unverified(self, tmp_path):
        sig = "someFunc(uint256)"
        sel = function_selector(sig)
        _install(tmp_path, [(sel, sig)])
        d = calldata_decoder.decode_calldata(sel + b"\x00" * 32)
        assert d.known and d.verified is False and d.name == "someFunc"
        pages = calldata_decoder.render_pages(d)
        assert any("someFunc (unverified)" in t for t, _ in pages)

    def test_curated_never_reaches_binary_tier(self, tmp_path):
        # Even if the binary index somehow carried a curated selector, the
        # decoder consults the curated registry first, so the trusted name wins.
        sel = bytes.fromhex("a9059cbb")  # transfer(address,uint256)
        _install(tmp_path, [(sel, "evilTransfer(address,uint256)")])
        d = calldata_decoder.decode_calldata(
            sel + b"\x00" * 12 + b"\x11" * 20 + (1000).to_bytes(32, "big"))
        assert d.known and d.verified is True and d.name == "transfer"


class TestCuratedProtocolSelectors:
    """The newly-added verified protocol entries must reproduce their known
    on-chain selectors and decode as verified."""

    ANCHORS = {
        "12aa3caf": "swap",
        "0502b1c5": "unoswap",
        "f78dc253": "unoswapTo",
        "415565b0": "transformERC20",
        "13d79a0b": "settle",
        "ec6cb13f": "setPreSignature",
        "15337bc0": "invalidateOrder",
        "322bba21": "createOrder",
        "7bc41b96": "invalidateOrder",
        "fb0f3ee1": "fulfillBasicOrder",
        "00000000": "fulfillBasicOrder_efficient_6GL6yc",
        "b3a34c4c": "fulfillOrder",
        "e7acab24": "fulfillAdvancedOrder",
        "ed98a574": "fulfillAvailableOrders",
        "87201b41": "fulfillAvailableAdvancedOrders",
        "a8174404": "matchOrders",
        "f2d12b12": "matchAdvancedOrders",
        # --- popular-dApp pack (corroborated against the bundled 4byte set) ---
        # Uniswap Universal Router
        "3593564c": "execute",
        "24856bc3": "execute",
        # Permit2
        "2b67b570": "permit",
        "2a2d80d1": "permit",
        "36c78516": "transferFrom",
        "cc53287f": "lockdown",
        # Safe (Gnosis Safe)
        "6a761202": "execTransaction",
        "d4d9bdcd": "approveHash",
        "0d582f13": "addOwnerWithThreshold",
        "f8dc5dd9": "removeOwner",
        "e318b52b": "swapOwner",
        "694e80c3": "changeThreshold",
        "610b5925": "enableModule",
        "e009cfde": "disableModule",
        # Aave V3 Pool
        "617ba037": "supply",
        "69328dec": "withdraw",
        "a415bcad": "borrow",
        "573ade81": "repay",
        "5a3b74b9": "setUserUseReserveAsCollateral",
        # Compound III (Comet)
        "f2b9fdb8": "supply",
        "f3fef3a3": "withdraw",
        "4232cd63": "supplyTo",
        "c3b35a7e": "withdrawTo",
        # Lido
        "a1903eab": "submit",
        "ea598cb0": "wrap",
        "de0e9a3e": "unwrap",
        # ENS
        "f14fcbc8": "commit",
        "acf1a841": "renew",
        "74694a2b": "register",
        "d5fa2b00": "setAddr",
        "c47f0027": "setName",
        # Curve
        "3df02124": "exchange",
        "5b41b908": "exchange",
        "0b4c7e4d": "add_liquidity",
        "4515cef3": "add_liquidity",
        "5b36389c": "remove_liquidity",
        # 0x classic VIP swaps
        "d9627aa4": "sellToUniswap",
        "3598d8ab": "sellEthForTokenToUniswapV3",
        "803ba26d": "sellTokenForEthToUniswapV3",
        "6af479b2": "sellTokenForTokenToUniswapV3",
        # ERC-4626
        "94bf804d": "mint",
    }

    def test_selectors_and_names(self):
        for hexsel, name in self.ANCHORS.items():
            entry = function_registry.resolve(bytes.fromhex(hexsel))
            assert entry is not None, f"{name} ({hexsel}) not registered"
            assert entry.name == name
            # Self-verifying: the canonical signature reproduces the selector.
            assert function_registry.function_selector(entry.signature) == bytes.fromhex(hexsel)

    def test_decodes_verified(self):
        # transformERC20 has simple-enough params to fully decode.
        sig = ("transformERC20(address,address,uint256,uint256,(uint32,bytes)[])")
        sel = function_registry.function_selector(sig)
        d = calldata_decoder.decode_calldata(sel + b"\x00" * 32)
        # Even if params don't fully decode, the name is verified (not blind).
        assert d.known and d.verified is True and d.name == "transformERC20"
