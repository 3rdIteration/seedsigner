from seedsigner.views.seed_views import SeedKeeperSelectView


def test_decode_seedkeeper_text_supports_v2_two_byte_length_prefix():
    xprv = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
    payload = len(xprv.encode("utf-8")).to_bytes(2, "big") + xprv.encode("utf-8")

    assert SeedKeeperSelectView._decode_seedkeeper_text(payload.hex()) == xprv


def test_extract_xprv_from_legacy_masterseed_subtype_zero_payload():
    xprv = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
    payload = bytes([len(xprv.encode("utf-8"))]) + xprv.encode("utf-8")

    assert SeedKeeperSelectView._extract_xprv_from_masterseed_secret(payload.hex()) == xprv
