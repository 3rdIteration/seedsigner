import json
import os
import pytest
import shamir_mnemonic
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

    # Initialize without passphrase and apply it later
    seed2 = Slip39Seed(mnemonics=mnemonics)
    seed2.set_slip39_passphrase("TREZOR")
    assert seed2.seed_bytes == seed.seed_bytes
    assert seed2.master_secret == seed.master_secret

    if seed2.extendable:
        new_shares = seed2.regenerate_shares(seed2._member_threshold, len(seed2.mnemonic_list))
        combined = shamir_mnemonic.combine_mnemonics(
            new_shares[: seed2._member_threshold], b"TREZOR"
        )
        assert combined == seed2.master_secret
