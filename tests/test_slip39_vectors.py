import json
import os
import pytest
import shamir_mnemonic

VECTORS_PATH = os.path.join(os.path.dirname(__file__), 'data', 'shamir_vectors.json')

@pytest.mark.parametrize('desc,mnemonics,secret_hex,xprv', json.load(open(VECTORS_PATH)))
def test_vectors(desc, mnemonics, secret_hex, xprv):
    if secret_hex:
        combined = shamir_mnemonic.combine_mnemonics(mnemonics, b"TREZOR")
        assert combined.hex() == secret_hex
    else:
        with pytest.raises(Exception):
            shamir_mnemonic.combine_mnemonics(mnemonics)
