from embit import bip32
from seedsigner.models.seed import Seed
from seedsigner.views.tools_views import (
    bip85_brainpoolp256r1_from_root,
    bip85_p256_from_root,
    bip85_rsa_from_root,
    bip85_secp256k1_from_root,
)

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


def test_bip85_rsa_3072_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_rsa_from_root(root, 3072, 0)
    assert key.size_in_bits() == 3072
    assert key.n == int(
        "d75e35129fd00e06a4b26894c11d7c420d1b758d18190857ce100e3a7720a1a57fee5820ee5332bf2fe8c7d336acbeb44b6543f01a162c3304c970e20924f495"
        "09936ee727cbd07b39a091340e5518a72ad6dafe181014109a1b8d8db0bd94cf5bda97ee713dd90ef4acebee6f7f747362dc0deb86fa93ef76ab7ec884381fac"
        "eda19721939b39f7a6c25ea4ba58f8a430b1d6ba7b2d3dd994c93096f206e1a95ef2a872299a302718510869fb27d6bbfe0d27801d6f05465e8bb8d748aa55db"
        "235268644ffe5cf16d4d5d6ee8e51a16072bba3e3c1d1075f20061e62562ab7bc267f6be05fb2d56e4e477653c2b22cd88b849ee69cbf4fdcf8d297ce2f804dd"
        "0545cfc9f533997e5f5df984c9de844597674ba349bf6a8770a6f6e86a9cbaee6134b4349d226acc80101b31f80888cbb0113b138a79e2d5467af2a21991d0a8"
        "307247fcaa44fb123248e848edfcb1306878e1020fc5832bc2213241caa30b2309d5bc9ea3e0f47275f2a2299fa9bed5faa8256fbf9e0fa253e3a1defa034685",
        16,
    )


def test_bip85_secp256k1_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_secp256k1_from_root(root, 0)
    assert int(key.s) == int(
        "cefbb3197f44cbcd28ca548e7d6c22e2b67f497caeebb71fa91d1cc6ab78e502", 16
    )


def test_bip85_p256_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_p256_from_root(root, 0)
    assert int(key.s) == int(
        "ef959a78fb241496d3b56bf1307f142a1c4b141b7bdb6ec95afc11f66eafad2f", 16
    )


def test_bip85_brainpoolp256r1_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_brainpoolp256r1_from_root(root, 0)
    assert int(key.s) == int(
        "6f48a0f8172149dd27c6d18e43017e2083e3dcf9ac58144ca054e4e86a7d3a24", 16
    )
