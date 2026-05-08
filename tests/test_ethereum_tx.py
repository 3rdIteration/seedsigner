import pytest

from seedsigner.helpers.ethereum import eip712, rlp
from seedsigner.helpers.ethereum.personal_sign import personal_sign_hash
from seedsigner.helpers.ethereum.tx_eip1559 import EIP1559Tx
from seedsigner.helpers.ethereum.tx_legacy import LegacyTx


class TestLegacyEIP155:
    """Vectors from EIP-155, https://eips.ethereum.org/EIPS/eip-155."""

    TX = LegacyTx(
        nonce=9,
        gas_price=20 * 10**9,
        gas_limit=21000,
        to=bytes.fromhex("3535353535353535353535353535353535353535"),
        value=10**18,
        data=b"",
        chain_id=1,
    )

    def test_signing_hash(self):
        assert (
            self.TX.signing_hash().hex()
            == "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
        )

    def test_signing_bytes_decodes_back(self):
        decoded = rlp.decode(self.TX.signing_bytes())
        assert isinstance(decoded, list)
        assert len(decoded) == 9  # 6 fields + chainId, 0, 0
        assert rlp.decode_int(decoded[0]) == 9
        assert rlp.decode_int(decoded[6]) == 1  # chainId

    def test_serialize_signed_v(self):
        # EIP-155 spec example: v=37 for chainId=1 with recovery_id=0
        out = self.TX.serialize_signed(
            recovery_id=0,
            r=(1).to_bytes(32, "big"),
            s=(1).to_bytes(32, "big"),
        )
        decoded = rlp.decode(out)
        assert rlp.decode_int(decoded[6]) == 37  # 0 + 1*2 + 35


class TestLegacyPreEIP155:
    def test_v_27_28(self):
        tx = LegacyTx(
            nonce=0, gas_price=1, gas_limit=21000,
            to=b"\x00" * 20, value=0, data=b"", chain_id=None,
        )
        signed = tx.serialize_signed(0, (1).to_bytes(32, "big"), (1).to_bytes(32, "big"))
        decoded = rlp.decode(signed)
        assert rlp.decode_int(decoded[6]) == 27

        signed = tx.serialize_signed(1, (1).to_bytes(32, "big"), (1).to_bytes(32, "big"))
        decoded = rlp.decode(signed)
        assert rlp.decode_int(decoded[6]) == 28


class TestEIP1559:
    def test_envelope_starts_with_type_byte(self):
        tx = EIP1559Tx(
            chain_id=1, nonce=0,
            max_priority_fee_per_gas=10**9,
            max_fee_per_gas=20 * 10**9,
            gas_limit=21000,
            to=b"\x35" * 20, value=10**18, data=b"",
        )
        assert tx.signing_bytes()[0] == 0x02
        assert len(tx.signing_hash()) == 32

    def test_round_trip_no_access_list(self):
        tx = EIP1559Tx(
            chain_id=1, nonce=7,
            max_priority_fee_per_gas=2 * 10**9,
            max_fee_per_gas=30 * 10**9,
            gas_limit=21000,
            to=bytes.fromhex("0102030405060708090a0b0c0d0e0f1011121314"),
            value=42, data=b"",
        )
        body = tx.signing_bytes()
        decoded = rlp.decode(body[1:])
        assert isinstance(decoded, list)
        assert len(decoded) == 9
        assert rlp.decode_int(decoded[0]) == 1
        assert rlp.decode_int(decoded[1]) == 7
        assert decoded[8] == []  # empty access list

    def test_signed_tx_y_parity_validates(self):
        tx = EIP1559Tx(
            chain_id=1, nonce=0,
            max_priority_fee_per_gas=1, max_fee_per_gas=2,
            gas_limit=21000, to=b"\x00" * 20, value=0,
        )
        with pytest.raises(ValueError):
            tx.serialize_signed(2, b"\x01" * 32, b"\x01" * 32)

    def test_access_list_validates(self):
        with pytest.raises(ValueError):
            EIP1559Tx(
                chain_id=1, nonce=0,
                max_priority_fee_per_gas=1, max_fee_per_gas=2,
                gas_limit=21000, to=b"\x00" * 20, value=0,
                access_list=[(b"\x00" * 19, [])],  # bad address length
            )


class TestEIP712:
    """Canonical "Mail" example from EIP-712, https://eips.ethereum.org/EIPS/eip-712."""

    TYPED_DATA = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"},
            ],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"},
            ],
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
        },
        "message": {
            "from": {
                "name": "Cow",
                "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
            },
            "to": {
                "name": "Bob",
                "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
            },
            "contents": "Hello, Bob!",
        },
    }

    def test_encode_type_mail(self):
        assert eip712.encode_type(self.TYPED_DATA["types"], "Mail") == (
            b"Mail(Person from,Person to,string contents)Person(string name,address wallet)"
        )

    def test_type_hash_mail(self):
        # keccak256 of encode_type, which is itself asserted in test_encode_type_mail
        assert eip712.type_hash(self.TYPED_DATA["types"], "Mail").hex() == (
            "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
        )

    def test_domain_separator(self):
        types = self.TYPED_DATA["types"]
        sep = eip712.hash_struct(types, "EIP712Domain", self.TYPED_DATA["domain"])
        assert sep.hex() == (
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
        )

    def test_struct_hash_mail(self):
        types = self.TYPED_DATA["types"]
        h = eip712.hash_struct(types, "Mail", self.TYPED_DATA["message"])
        assert h.hex() == (
            "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
        )

    def test_signing_hash(self):
        assert eip712.signing_hash(self.TYPED_DATA).hex() == (
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        )


class TestPersonalSign:
    def test_known_short_message(self):
        # eth_account: encode_defunct(text='hello').body matches
        h = personal_sign_hash(b"hello")
        assert h.hex() == (
            "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750"
        )
