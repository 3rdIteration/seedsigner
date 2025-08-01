import json
import os
import pytest
from seedsigner.models.seed import Slip39Seed
from embit import bip32
from embit.networks import NETWORKS

VECTORS_PATH = os.path.join(os.path.dirname(__file__), 'data', 'shamir_vectors.json')

@pytest.mark.parametrize('desc,mnemonics,secret_hex,xprv', json.load(open(VECTORS_PATH)))
def test_vectors(desc, mnemonics, secret_hex, xprv):
    """Verify official SLIP-39 vectors using :class:`Slip39Seed`."""
    if not secret_hex:
        with pytest.raises(Exception):
            Slip39Seed(mnemonics=mnemonics, slip39_passphrase="TREZOR")
        return

    seed = Slip39Seed(mnemonics=mnemonics, slip39_passphrase="TREZOR")
    assert seed.seed_bytes.hex() == secret_hex
    root = bip32.HDKey.from_seed(seed.seed_bytes, version=NETWORKS["main"]["xprv"])
    assert root.to_base58() == xprv
