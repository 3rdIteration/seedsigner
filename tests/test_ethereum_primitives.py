import pytest

from seedsigner.helpers.ethereum import rlp
from seedsigner.helpers.ethereum.address import pubkey_to_address, to_checksum_address
from seedsigner.helpers.ethereum.keccak import keccak256


class TestKeccak:
    def test_empty(self):
        assert keccak256(b"").hex() == (
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        )

    def test_abc(self):
        assert keccak256(b"abc").hex() == (
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        )


class TestRLPEncode:
    @pytest.mark.parametrize(
        "value,expected_hex",
        [
            (b"", "80"),
            (b"\x00", "00"),
            (b"\x7f", "7f"),
            (b"\x80", "8180"),
            (b"dog", "83646f67"),
            (b"\x04\x00", "82" + "0400"),
        ],
    )
    def test_bytes(self, value, expected_hex):
        assert rlp.encode(value).hex() == expected_hex

    def test_long_string(self):
        s = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit"
        out = rlp.encode(s)
        assert out[0] == 0xB8
        assert out[1] == len(s)
        assert out[2:] == s

    def test_empty_list(self):
        assert rlp.encode([]).hex() == "c0"

    def test_string_list(self):
        assert rlp.encode([b"cat", b"dog"]).hex() == "c88363617483646f67"

    def test_set_theoretic_three(self):
        # the canonical "set theoretical representation of three"
        assert (
            rlp.encode([[], [[]], [[], [[]]]]).hex() == "c7c0c1c0c3c0c1c0"
        )

    def test_int_helpers(self):
        assert rlp.encode_int(0) == b""
        assert rlp.encode_int(15) == b"\x0f"
        assert rlp.encode_int(1024) == b"\x04\x00"
        assert rlp.encode(rlp.encode_int(0)).hex() == "80"
        assert rlp.encode(rlp.encode_int(15)).hex() == "0f"
        assert rlp.encode(rlp.encode_int(1024)).hex() == "820400"

    def test_negative_int_rejected(self):
        with pytest.raises(ValueError):
            rlp.encode_int(-1)


class TestRLPDecode:
    @pytest.mark.parametrize(
        "encoded_hex,expected",
        [
            ("80", b""),
            ("00", b"\x00"),
            ("7f", b"\x7f"),
            ("83646f67", b"dog"),
            ("c0", []),
            ("c88363617483646f67", [b"cat", b"dog"]),
            ("c7c0c1c0c3c0c1c0", [[], [[]], [[], [[]]]]),
        ],
    )
    def test_roundtrip(self, encoded_hex, expected):
        assert rlp.decode(bytes.fromhex(encoded_hex)) == expected
        assert rlp.encode(expected).hex() == encoded_hex

    def test_decode_int(self):
        assert rlp.decode_int(b"") == 0
        assert rlp.decode_int(b"\x0f") == 15
        assert rlp.decode_int(b"\x04\x00") == 1024

    def test_decode_int_leading_zero_rejected(self):
        with pytest.raises(rlp.RLPDecodingError):
            rlp.decode_int(b"\x00\x01")

    def test_decode_trailing_bytes_rejected(self):
        with pytest.raises(rlp.RLPDecodingError):
            rlp.decode(bytes.fromhex("80") + b"\x00")


class TestEIP55:
    @pytest.mark.parametrize(
        "checksummed",
        [
            "0x52908400098527886E0F7030069857D2E4169EE7",
            "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
            "0xde709f2102306220921060314715629080e2fb77",
            "0x27b1fdb04752bbc536007a920d24acb045561c26",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ],
    )
    def test_checksum_round_trip(self, checksummed):
        assert to_checksum_address(checksummed.lower()) == checksummed

    def test_from_bytes(self):
        addr = bytes.fromhex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
        assert (
            to_checksum_address(addr) == "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        )


class TestPubkeyToAddress:
    def test_known_vector(self):
        # Ethereum yellow paper / test_account vector:
        #  privkey 0xc85ef7d79691fe79573b1a7064c19c1a98...  (well-known test)
        # We use a self-consistent vector: pubkey from secp256k1 generator
        # Known: G * 1 = G, address derived from generator's uncompressed pubkey.
        gx = bytes.fromhex(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        gy = bytes.fromhex(
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        )
        pub = b"\x04" + gx + gy
        addr = pubkey_to_address(pub)
        # checksummed address of secp256k1 generator point
        assert (
            to_checksum_address(addr)
            == "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        )

    def test_64_byte_form(self):
        pub64 = bytes(64)
        pub65 = b"\x04" + pub64
        assert pubkey_to_address(pub64) == pubkey_to_address(pub65)

    def test_invalid_length_rejected(self):
        with pytest.raises(ValueError):
            pubkey_to_address(bytes(33))
        with pytest.raises(ValueError):
            pubkey_to_address(b"\x02" + bytes(64))
