from embit import bip32, bip85

from seedsigner.helpers.bip85_drng import BIP85DRNG
from seedsigner.helpers.password_generation import dice_rolls_from_seed

MASTER_XPRV = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"


def test_bip85_drng_vector_matches_spec():
    root = bip32.HDKey.from_string(MASTER_XPRV)
    entropy = bip85.derive_entropy(root, 0, [0])
    assert (
        entropy.hex()
        == "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
    )

    drng = BIP85DRNG.new(entropy)
    assert (
        drng.read(80).hex()
        == "b78b1ee6b345eae6836c2d53d33c64cdaf9a696487be81b03e822dc84b3f1cd883d7559e53d175f243e4c349e822a957bbff9224bc5dde9492ef54e8a439f6bc8c7355b87a925a37ee405a7502991111"
    )


def test_bip85_dice_vector_matches_spec():
    root = bip32.HDKey.from_string(MASTER_XPRV)
    entropy = bip85.derive_entropy(root, 89101, [6, 10, 0])
    assert (
        entropy.hex()
        == "5e41f8f5d5d9ac09a20b8a5797a3172b28c806aead00d27e36609e2dd116a59176a738804236586f668da8a51b90c708a4226d7f92259c69f64c51124b6f6cd2"
    )

    assert dice_rolls_from_seed(entropy, sides=6, roll_count=10, base=0) == "1002015524"


def test_bip85_xprv_vector_matches_spec():
    root = bip32.HDKey.from_string(MASTER_XPRV)
    entropy = bip85.derive_entropy(root, 32, [0])

    # BIP-0085 XPRV vector publishes the private-key half of the HMAC output.
    assert entropy[32:].hex() == "ead0b33988a616cf6a497f1c169d9e92562604e38305ccd3fc96f2252c177682"
    assert (
        bip85.derive_xprv(root, 0).to_base58()
        == "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"
    )
