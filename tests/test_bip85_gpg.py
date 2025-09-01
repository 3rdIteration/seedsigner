from embit import bip32
from seedsigner.models.seed import Seed
from seedsigner.views.tools_views import bip85_rsa_from_root, bip85_secp256k1_from_root

MNEMONIC = "resource timber firm banner horror pupil frozen main pear direct pioneer broken grid core insane begin sister pony end debate task silk empty curious".split()


def test_bip85_rsa_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_rsa_from_root(root, 1024, 0)
    assert key.size_in_bits() == 1024
    assert key.n == int(
        "d5ddf7786d30bf996b024d1a70aff00354c658ed60479c732343abcaa6b86749c28ee25200f923b1e56b89ba7cb3b4187360781d95651a221880f161c366bab91122762386b6895b38d7b46ed860ac00f12f782a138e92154388927721d0e8a05921ec35d042d64ebd0beaafe819a4af10cb6cc1225fbad35e06c906ffaecd6d",
        16,
    )


def test_bip85_rsa_large_key():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_rsa_from_root(root, 4096, 0)
    assert key.size_in_bits() == 4096


def test_bip85_secp256k1_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_secp256k1_from_root(root, 0)
    assert int.from_bytes(key.secret, "big") == int(
        "cefbb3197f44cbcd28ca548e7d6c22e2b67f497caeebb71fa91d1cc6ab78e502", 16
    )
