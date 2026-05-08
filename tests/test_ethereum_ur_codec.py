import os

import pytest

from seedsigner.helpers.ethereum.ur_codec import (
    CryptoKeypath, DATA_TYPE_LEGACY_TX, DATA_TYPE_PERSONAL_MESSAGE,
    DATA_TYPE_TYPED_DATA, DATA_TYPE_TYPED_TX,
    EthSignature, EthSignRequest,
)


@pytest.fixture
def basic_request():
    return EthSignRequest(
        request_id=b"\x12" * 16,
        sign_data=b"\xaa\xbb\xcc\xdd",
        data_type=DATA_TYPE_LEGACY_TX,
        chain_id=1,
        derivation_path=CryptoKeypath(
            components=[44 | 0x80000000, 60 | 0x80000000, 0 | 0x80000000, 0, 0],
            source_fingerprint=b"\xde\xad\xbe\xef",
        ),
        address=b"\x35" * 20,
        origin="metamask",
    )


class TestEthSignRequestRoundTrip:
    def test_minimal(self):
        req = EthSignRequest(
            request_id=os.urandom(16),
            sign_data=b"\xaa",
            data_type=DATA_TYPE_PERSONAL_MESSAGE,
            chain_id=1,
            derivation_path=CryptoKeypath(components=[0]),
        )
        back = EthSignRequest.from_cbor(req.to_cbor())
        assert back.request_id == req.request_id
        assert back.sign_data == req.sign_data
        assert back.data_type == req.data_type
        assert back.chain_id == req.chain_id
        assert back.derivation_path.components == req.derivation_path.components
        assert back.address is None
        assert back.origin is None

    def test_full(self, basic_request):
        back = EthSignRequest.from_cbor(basic_request.to_cbor())
        assert back.request_id == basic_request.request_id
        assert back.sign_data == basic_request.sign_data
        assert back.data_type == basic_request.data_type
        assert back.chain_id == basic_request.chain_id
        assert back.derivation_path.components == basic_request.derivation_path.components
        assert back.derivation_path.source_fingerprint == basic_request.derivation_path.source_fingerprint
        assert back.address == basic_request.address
        assert back.origin == basic_request.origin

    def test_invalid_request_id_length(self):
        with pytest.raises(ValueError):
            EthSignRequest(
                request_id=b"\x00" * 8,  # bad length
                sign_data=b"\x01",
                data_type=DATA_TYPE_LEGACY_TX,
                chain_id=1,
                derivation_path=CryptoKeypath(components=[]),
            ).to_cbor()


class TestKeypathHardenedFlags:
    def test_hardened_round_trip(self):
        comps = [
            44 | 0x80000000,
            60 | 0x80000000,
            0  | 0x80000000,
            0,
            17,
        ]
        path = CryptoKeypath(components=comps)
        cbor = path.to_cbor_value()
        # Re-encode through a request to push the value through the dict serialiser
        req = EthSignRequest(
            request_id=b"\x00" * 16, sign_data=b"\x00",
            data_type=1, chain_id=1, derivation_path=path,
        )
        back = EthSignRequest.from_cbor(req.to_cbor())
        assert back.derivation_path.components == comps


class TestUrTransport:
    """Verify the codec round-trips through a real BC-UR fountain."""

    def test_through_ur_encoder_decoder(self, basic_request):
        from urtypes.cbor.data import Mapping  # noqa: F401  (sanity import)
        from seedsigner.helpers.ur2.ur import UR
        from seedsigner.helpers.ur2.ur_decoder import URDecoder
        from seedsigner.helpers.ur2.ur_encoder import UREncoder

        ur = UR("eth-sign-request", basic_request.to_cbor())
        encoder = UREncoder(ur=ur, max_fragment_len=200)
        decoder = URDecoder()
        for _ in range(5):
            decoder.receive_part(encoder.next_part())
            if decoder.is_complete():
                break
        assert decoder.is_complete()
        cbor = decoder.result_message().cbor
        back = EthSignRequest.from_cbor(cbor)
        assert back.sign_data == basic_request.sign_data
        assert back.derivation_path.components == basic_request.derivation_path.components


class TestEthSignature:
    def test_round_trip(self):
        sig = EthSignature(
            request_id=b"\x77" * 16,
            signature=b"\x11" * 32 + b"\x22" * 32 + bytes([37]),
            origin="metamask",
        )
        back = EthSignature.from_cbor(sig.to_cbor())
        assert back.request_id == sig.request_id
        assert back.signature == sig.signature
        assert back.origin == sig.origin

    def test_too_short_rejected(self):
        with pytest.raises(ValueError):
            EthSignature(
                request_id=b"\x00" * 16, signature=b"\x00" * 64,
            ).to_cbor()
