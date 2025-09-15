import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent / "tools"))
import bip85_pgp


def test_generate_pgp_key_and_export():
    mnemonic = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    key = bip85_pgp.create_bip85_pgp_key(
        mnemonic,
        key_index=0,
        key_type="p256",
        name="Tester",
        email="test@example.com",
        additional_sets=1,
    )
    assert key.fingerprint == "774AC53EC1414765F27F04AE58FD4133E660EE68"
    assert len(key.subkeys) == 6
    pub = bip85_pgp.export_public_key(key)
    priv = bip85_pgp.export_private_key(key)
    assert pub.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert priv.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
