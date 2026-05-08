import json
from unittest.mock import MagicMock

import pytest

from seedsigner.helpers.ethereum.keccak import keccak256
from seedsigner.helpers.ethereum.personal_sign import personal_sign_hash
from seedsigner.helpers.ethereum.tx_legacy import LegacyTx
from seedsigner.helpers.ethereum.ur_codec import (
    CryptoKeypath, DATA_TYPE_LEGACY_TX, DATA_TYPE_PERSONAL_MESSAGE,
    DATA_TYPE_TYPED_DATA, DATA_TYPE_TYPED_TX, EthSignRequest,
)
from seedsigner.helpers.keycard_signer import (
    compute_v, signing_hash_for,
)


def make_request(data_type: int, sign_data: bytes, chain_id: int = 1) -> EthSignRequest:
    return EthSignRequest(
        request_id=b"\x12" * 16,
        sign_data=sign_data,
        data_type=data_type,
        chain_id=chain_id,
        derivation_path=CryptoKeypath(components=[44 | 0x80000000, 60 | 0x80000000, 0]),
    )


class TestSigningHash:
    def test_legacy_eip155_matches_direct_hash(self):
        tx = LegacyTx(
            nonce=9, gas_price=20 * 10**9, gas_limit=21000,
            to=bytes.fromhex("3535353535353535353535353535353535353535"),
            value=10**18, data=b"", chain_id=1,
        )
        req = make_request(DATA_TYPE_LEGACY_TX, tx.signing_bytes(), chain_id=1)
        assert signing_hash_for(req).hex() == (
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
        )

    def test_typed_tx_envelope(self):
        # sign_data here is just an arbitrary blob — verify keccak passes through
        envelope = b"\x02" + b"\xab" * 50
        req = make_request(DATA_TYPE_TYPED_TX, envelope)
        assert signing_hash_for(req) == keccak256(envelope)

    def test_personal_message(self):
        req = make_request(DATA_TYPE_PERSONAL_MESSAGE, b"hello")
        assert signing_hash_for(req) == personal_sign_hash(b"hello")

    def test_typed_data_eip712(self):
        typed = {
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
                "name": "Ether Mail", "version": "1", "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            },
            "message": {
                "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
                "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
                "contents": "Hello, Bob!",
            },
        }
        req = make_request(DATA_TYPE_TYPED_DATA, json.dumps(typed).encode("utf-8"))
        assert signing_hash_for(req).hex() == (
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        )

    def test_unsupported_data_type(self):
        req = make_request(99, b"\x00")
        with pytest.raises(ValueError):
            signing_hash_for(req)


class TestComputeV:
    def test_legacy_eip155_chain_1(self):
        req = make_request(DATA_TYPE_LEGACY_TX, b"\x00", chain_id=1)
        assert compute_v(req, 0) == 37
        assert compute_v(req, 1) == 38

    def test_legacy_eip155_chain_42(self):
        req = make_request(DATA_TYPE_LEGACY_TX, b"\x00", chain_id=42)
        assert compute_v(req, 0) == 119

    def test_legacy_pre_eip155(self):
        req = make_request(DATA_TYPE_LEGACY_TX, b"\x00", chain_id=0)
        assert compute_v(req, 0) == 27
        assert compute_v(req, 1) == 28

    def test_eip1559_y_parity(self):
        req = make_request(DATA_TYPE_TYPED_TX, b"\x02", chain_id=1)
        assert compute_v(req, 0) == 0
        assert compute_v(req, 1) == 1

    def test_typed_data_27_28(self):
        req = make_request(DATA_TYPE_TYPED_DATA, b"{}", chain_id=1)
        assert compute_v(req, 0) == 27
        assert compute_v(req, 1) == 28

    def test_personal_27_28(self):
        req = make_request(DATA_TYPE_PERSONAL_MESSAGE, b"x", chain_id=1)
        assert compute_v(req, 0) == 27
        assert compute_v(req, 1) == 28
