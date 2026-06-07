"""Tests for the offline Ethereum calldata / typed-data decoder.

Covers: ABI decode correctness (static, dynamic arrays, tuples, bytes/string),
adversarial hardening (truncation, oversized lengths, bad offsets — must raise,
never OOM/crash), the selector registry, token/chain reference data, and the
screen-page renderers.
"""

import pytest

from seedsigner.helpers.ethereum import abi_decode, chains, tokens
from seedsigner.helpers.ethereum.abi_decode import (
    decode_parameters, parse_signature, parse_type, type_str,
)
from seedsigner.helpers.ethereum import calldata_decoder
from seedsigner.helpers.ethereum.calldata_decoder import (
    decode_calldata, render_pages, pages_for_calldata, render_typed_data_pages,
)
from seedsigner.helpers.ethereum import function_registry
from seedsigner.helpers.ethereum.function_registry import (
    function_selector, resolve, KIND_TRANSFER, KIND_APPROVE, KIND_SWAP, KIND_GENERIC,
)


# --- encoding helpers -------------------------------------------------------

def w(n: int) -> bytes:
    return int(n).to_bytes(32, "big")


def aw(hex40: str) -> bytes:
    """address word: 12 zero bytes + 20-byte address."""
    return bytes(12) + bytes.fromhex(hex40)


A = "1111111111111111111111111111111111111111"
B = "2222222222222222222222222222222222222222"
C = "3333333333333333333333333333333333333333"
USDC = bytes.fromhex("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")


@pytest.fixture(autouse=True)
def _isolate_signature_db():
    # Decoder tests assert on curated/blind behaviour and must be independent of
    # whatever extended text DB or bundled binary index ships in resources/.
    # Turn both extended layers OFF by default; tests that exercise the extended
    # path patch resolve_all explicitly.
    from seedsigner.helpers.ethereum import signature_db
    signature_db._reset()
    signature_db._TEST_PATHS = []                 # no text baseline / microSD
    signature_db._TEST_INDEX_PATHS = ("/nonexistent/idx", "/nonexistent/blob")
    yield
    signature_db._reset()
    signature_db._TEST_PATHS = None
    signature_db._TEST_INDEX_PATHS = None


# --- type parsing -----------------------------------------------------------

class TestTypeParsing:
    def test_scalar(self):
        assert type_str(parse_type("uint256")) == "uint256"
        assert type_str(parse_type("uint")) == "uint256"
        assert type_str(parse_type("address")) == "address"
        assert type_str(parse_type("bytes32")) == "bytes32"

    def test_array_and_tuple(self):
        assert type_str(parse_type("address[]")) == "address[]"
        assert type_str(parse_type("uint256[2][3]")) == "uint256[2][3]"
        assert type_str(parse_type("(address,uint256)")) == "(address,uint256)"

    def test_signature(self):
        name, types = parse_signature("transfer(address,uint256)")
        assert name == "transfer"
        assert [type_str(t) for t in types] == ["address", "uint256"]

    @pytest.mark.parametrize("bad", ["uint257", "bytes33", "uint7", "ufixed128", ""])
    def test_rejects_unsupported(self, bad):
        with pytest.raises(ValueError):
            parse_type(bad)


# --- decode correctness -----------------------------------------------------

class TestDecodeStatic:
    def test_transfer(self):
        _, types = parse_signature("transfer(address,uint256)")
        data = aw(A) + w(1000)
        to, amount = decode_parameters(types, data)
        assert to == bytes.fromhex(A)
        assert amount == 1000

    def test_transfer_from_three_args(self):
        _, types = parse_signature("transferFrom(address,address,uint256)")
        frm, to, amount = decode_parameters(types, aw(A) + aw(B) + w(42))
        assert (frm, to, amount) == (bytes.fromhex(A), bytes.fromhex(B), 42)

    def test_bool_and_int(self):
        _, types = parse_signature("f(bool,int256)")
        flag, signed = decode_parameters(types, w(1) + w((1 << 256) - 5))
        assert flag is True
        assert signed == -5


class TestDecodeDynamic:
    def test_v2_swap_with_path_array(self):
        _, types = parse_signature(
            "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"
        )
        offset = 5 * 32
        head = w(1000) + w(900) + w(offset) + aw(C) + w(12345)
        tail = w(2) + aw(A) + aw(B)
        values = decode_parameters(types, head + tail)
        assert values[0] == 1000
        assert values[1] == 900
        assert values[2] == [bytes.fromhex(A), bytes.fromhex(B)]
        assert values[3] == bytes.fromhex(C)
        assert values[4] == 12345

    def test_string(self):
        _, types = parse_signature("f(string)")
        payload = b"hello"
        data = w(0x20) + w(len(payload)) + payload + bytes(32 - len(payload))
        (s,) = decode_parameters(types, data)
        assert s == "hello"

    def test_bytes(self):
        _, types = parse_signature("f(bytes)")
        payload = bytes.fromhex("deadbeef")
        data = w(0x20) + w(len(payload)) + payload + bytes(28)
        (b,) = decode_parameters(types, data)
        assert b == payload


class TestDecodeTuple:
    def test_v3_exact_input_single(self):
        sig = "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))"
        _, types = parse_signature(sig)
        inner = aw(A) + aw(B) + w(3000) + aw(C) + w(10 ** 18) + w(5 * 10 ** 17) + w(0)
        (params,) = decode_parameters(types, inner)
        assert params[0] == bytes.fromhex(A)   # tokenIn
        assert params[1] == bytes.fromhex(B)   # tokenOut
        assert params[2] == 3000               # fee
        assert params[3] == bytes.fromhex(C)   # recipient
        assert params[4] == 10 ** 18           # amountIn


# --- adversarial hardening --------------------------------------------------

class TestHardening:
    def test_truncated_data_raises(self):
        _, types = parse_signature("transfer(address,uint256)")
        with pytest.raises(ValueError):
            decode_parameters(types, aw(A))  # missing the amount word

    def test_oversized_array_length_raises_not_oom(self):
        _, types = parse_signature("f(address[])")
        data = w(0x20) + w((1 << 256) - 1)  # claims 2^256-1 elements
        with pytest.raises(ValueError):
            decode_parameters(types, data)

    def test_array_count_exceeds_data_raises(self):
        _, types = parse_signature("f(uint256[])")
        data = w(0x20) + w(1000)  # claims 1000 elements but no element data
        with pytest.raises(ValueError):
            decode_parameters(types, data)

    def test_offset_out_of_bounds_raises(self):
        _, types = parse_signature("f(bytes)")
        data = w(10 ** 9)  # offset way past the data
        with pytest.raises(ValueError):
            decode_parameters(types, data)

    def test_array_over_cap_raises(self):
        _, types = parse_signature("f(uint256[])")
        # length within data math but above MAX_ARRAY_ELEMENTS would need huge
        # data; instead assert the cap constant guards the loop directly.
        count = abi_decode.MAX_ARRAY_ELEMENTS + 1
        data = w(0x20) + w(count) + bytes(32 * count)
        with pytest.raises(ValueError):
            decode_parameters(types, data)


# --- decode_calldata never raises -------------------------------------------

class TestDecodeCalldata:
    def test_empty_returns_none(self):
        assert decode_calldata(b"") is None

    def test_short_data_is_blind(self):
        d = decode_calldata(b"\x01\x02\x03")
        assert d is not None and d.known is False

    def test_unknown_selector_is_blind(self):
        d = decode_calldata(bytes.fromhex("deadbeef") + w(1))
        assert d.known is False

    def test_known_transfer(self):
        data = function_selector("transfer(address,uint256)") + aw(A) + w(1000)
        d = decode_calldata(data, chain_id=1, to_address=USDC)
        assert d.known and d.name == "transfer" and d.kind == KIND_TRANSFER
        labels = [p[0] for p in d.params]
        assert labels == ["to", "amount"]

    def test_param_decode_failure_flags_error_not_crash(self):
        # Valid selector, truncated params.
        data = function_selector("transfer(address,uint256)") + aw(A)
        d = decode_calldata(data)
        assert d.known and d.decode_error

    def test_never_raises_on_garbage(self):
        for junk in [b"\xff" * 3, b"\x00" * 200, bytes(range(256))]:
            assert decode_calldata(junk) is not None


# --- registry ---------------------------------------------------------------

class TestRegistry:
    def test_known_selectors(self):
        assert function_selector("transfer(address,uint256)") == bytes.fromhex("a9059cbb")
        assert function_selector("approve(address,uint256)") == bytes.fromhex("095ea7b3")
        assert function_selector("transferFrom(address,address,uint256)") == bytes.fromhex("23b872dd")

    def test_resolve_curated(self):
        e = resolve(bytes.fromhex("a9059cbb"))
        assert e.name == "transfer" and e.kind == KIND_TRANSFER
        assert e.param_names == ["to", "amount"]

    def test_resolve_long_tail_generic(self):
        e = resolve(function_selector("mint(address,uint256)"))
        assert e is not None and e.kind == KIND_GENERIC and e.param_names is None

    def test_resolve_unknown(self):
        # NB: 0x00000000 is NOT unknown — it's Seaport's
        # fulfillBasicOrder_efficient_6GL6yc (curated). Use a true sentinel.
        assert resolve(bytes.fromhex("99887766")) is None

    def test_swap_is_swap_kind(self):
        e = resolve(function_selector(
            "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"))
        assert e.kind == KIND_SWAP


# --- tokens / chains --------------------------------------------------------

class TestReferenceData:
    def test_chain_label_known(self):
        assert chains.chain_label(1) == "Ethereum (1)"
        assert chains.chain_label(8453) == "Base (8453)"

    def test_chain_label_unknown(self):
        assert chains.chain_label(999999) == "chain 999999"

    def test_token_lookup(self):
        assert tokens.lookup_token(1, USDC) == ("USDC", 6)
        assert tokens.lookup_token(1, bytes(20)) is None
        assert tokens.lookup_token(999, USDC) is None

    @pytest.mark.parametrize("raw,dec,expected", [
        (5_000_000, 6, "5 USDC"),
        (1_234_500, 6, "1.2345 USDC"),
        (10 ** 18, 18, "1 USDC"),
        (5, 0, "5 USDC"),
    ])
    def test_format_amount(self, raw, dec, expected):
        assert tokens.format_token_amount(raw, "USDC", dec) == expected


# --- rendering --------------------------------------------------------------

class TestRendering:
    def test_transfer_pages_token_aware(self):
        data = function_selector("transfer(address,uint256)") + aw(A) + w(5_000_000)
        pages = pages_for_calldata(data, chain_id=1, to_address=USDC)
        bodies = "\n".join(b for _, b in pages)
        assert "5 USDC" in bodies
        assert any("transfer" in t for t, _ in pages)

    def test_unlimited_approve(self):
        data = function_selector("approve(address,uint256)") + aw(B) + w((1 << 256) - 1)
        pages = pages_for_calldata(data, chain_id=1, to_address=USDC)
        assert any("UNLIMITED" in b for _, b in pages)

    def test_blind_page(self):
        pages = pages_for_calldata(bytes.fromhex("deadbeef") + w(0))
        assert pages and pages[0][0] == "Blind signing"
        assert "deadbeef" in pages[0][1]

    def test_empty_calldata_no_pages(self):
        assert pages_for_calldata(b"") == []

    def test_swap_path_summary(self):
        offset = 5 * 32
        head = w(1000) + w(900) + w(offset) + aw(C) + w(12345)
        tail = w(2) + aw(A) + aw(B)
        data = function_selector(
            "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"
        ) + head + tail
        pages = pages_for_calldata(data, chain_id=1)
        bodies = "\n".join(b for _, b in pages)
        assert "→" in bodies  # path first → last

    def test_extended_single_match_is_unverified(self, monkeypatch):
        from seedsigner.helpers.ethereum import signature_db
        sig = "supply(address,uint256,address,uint16)"
        sel = function_selector(sig)
        # Force the extended layer to return exactly this signature.
        monkeypatch.setattr(signature_db, "resolve_all",
                            lambda s: [sig] if s == sel else [])
        data = sel + aw(A) + w(1000) + aw(B) + w(7)
        d = decode_calldata(data)
        assert d.known and d.verified is False and d.name == "supply"
        pages = render_pages(d)
        assert any("supply (unverified)" in t for t, _ in pages)

    def test_extended_collision_is_ambiguous(self, monkeypatch):
        from seedsigner.helpers.ethereum import signature_db
        sel = bytes.fromhex("12345678")
        monkeypatch.setattr(signature_db, "resolve_all",
                            lambda s: ["foo(uint256)", "bar(address)"] if s == sel else [])
        d = decode_calldata(sel + w(1))
        assert d.ambiguous and d.verified is False and len(d.candidates) == 2
        pages = render_pages(d)
        assert pages[0][0] == "Ambiguous"
        assert "2 possible" in pages[0][1]

    def test_extended_miss_is_blind(self, monkeypatch):
        from seedsigner.helpers.ethereum import signature_db
        monkeypatch.setattr(signature_db, "resolve_all", lambda s: [])
        d = decode_calldata(bytes.fromhex("deadbeef") + w(0))
        assert d.known is False

    def test_typed_data_pages(self):
        typed = {
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}],
                "Mail": [{"name": "contents", "type": "string"}],
            },
            "primaryType": "Mail",
            "domain": {"name": "Ether Mail",
                       "verifyingContract": "0x" + C},
            "message": {"contents": "Hello, Bob!"},
        }
        pages = render_typed_data_pages(typed)
        all_text = "\n".join(t + b for t, b in pages)
        assert "Mail" in all_text
        assert "Ether Mail" in all_text
        assert "Hello, Bob!" in all_text
