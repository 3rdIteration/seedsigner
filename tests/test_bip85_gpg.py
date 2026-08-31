import pytest
import sys
import base  # ensure hardware mocks
import os
import shutil
from embit import bip32, bip85
from seedsigner.models.seed import Seed, XprvSeed
from seedsigner.controller import Controller
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON, WarningScreen
from seedsigner.views import tools_views
from seedsigner.views.tools_views import (
    MIN_RSA_KEY_BITS,
    BIP85_GPG_ECC_APP,
    bip85_brainpoolp256r1_from_root,
    bip85_brainpoolp384r1_from_root,
    bip85_brainpoolp512r1_from_root,
    bip85_ed25519_from_root,
    bip85_p256_from_root,
    bip85_p384_from_root,
    bip85_p521_from_root,
    bip85_rsa_from_root,
    bip85_secp256k1_from_root,
    bip85_add_subkeys,
    _bip85_subkey_specs,
    parse_secret_key_list,
    parse_subkey_list,
    parse_uid_list,
    filter_deletable_subkeys,
    BIP85_GPG_CREATED_TS,
    BIP85_DATA,
    bip85_save_data,
    bip85_load_data,
    _select_import_algo,
    bip85_verify_existing,
    _normalize_date_input,
)
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.helpers.bip85_drng import BIP85DRNG

pytestmark = pytest.mark.skipif(
    sys.platform in ("darwin", "win32") or shutil.which("gpg") is None,
    reason="requires working GnuPG2"
)

MNEMONIC = "resource timber firm banner horror pupil frozen main pear direct pioneer broken grid core insane begin sister pony end debate task silk empty curious".split()

# BIP85 GPG RSA entropy vectors, using the BIP85-spec RSA derivation path
# m/83696968'/828365'/{key_bits}'/{index}' (v4, back in line with the B8 scheme).
# Derived via embit bip85.derive_entropy(root, 828365, [bits, index]).
LIBWALLY_RSA_MASTER_XPRV = (
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
)
BIP85_GPG_RSA_VECTORS = [
    (
        "e3ff02b1f0b934357cc0952225bb0e90081005b0cc992c5ed22f6fb8e9c628a3a0f138f9324e33ed4ba7250e43dd66d725a4e4c683dcf5a3b4015b82bcf71934",
        2048,
        0,
    ),
    (
        "b1b4d03eb9826aeb2fabc4529dc37da5eaaa9072d3e2b7e69da79862e2b9cd8131dbb5a9001612239cd96310f6be0417bd39c39500bf8a99ba5df32571866fe6",
        2048,
        1,
    ),
    (
        "9bd8cb61fea01892ffd981b4da7aae22f32c9641e49c48104682e249a98f7911ed55035a52e085938291d64e34537e9cc0b730f42ae9183b5ddaac33a55764ea",
        3072,
        0,
    ),
    (
        "fc49330db1352558f615651ae8d7840b083cce5c9e731e349847569d3813a3f7f605b5d66b178bf19fdd04bd7f48d2ddb07e16793703d17ee06c86e49e19a896",
        3072,
        1,
    ),
    (
        "12a499947a142ee3ede9c0960061383f2564b5cc569327d0dd22f7887094676f2e5d5785cd4eb683990d12209ebf6f39a5c1b5e217ea66710260e99fbe4b2be3",
        4096,
        0,
    ),
    (
        "a6fdf91d4f4a0cadaf3d20d638744b574306725aababa0ab7136f8f8b88c5a4c5ca6104646d695cd95a72ad15e6e6912e263762eab951bfcea8e9939ed7c03f4",
        4096,
        1,
    ),
    (
        "b3a0baa54a6fa75363e2bc0809dafd20eacea8b4d0fba9ef26f9ea9c471e135c53c1f787fd6a7a02bf736bed620d44e5b4465856fae6c2ef2d620b730098f8e9",
        8192,
        0,
    ),
    (
        "1b5f1ae261e9e36039cd7d55d25e71934a4f0a2fdd2d93b2f73fbd272d04257d6eba8f6ff6bc1ffe1d58f68b707b794e54e983e2f573991bb776b48b8ed9a1ca",
        8192,
        1,
    ),
]


def test_bip85_drng_vector():
    root = bip32.HDKey.from_string(
        "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
    )
    entropy = bip85.derive_entropy(root, 0, [0])
    assert entropy.hex() == (
        "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0"
        "0b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
    )
    drng = BIP85DRNG.new(entropy)
    assert drng.read(80).hex() == (
        "b78b1ee6b345eae6836c2d53d33c64cdaf9a696487be81b03e822dc84b3f1cd8"
        "83d7559e53d175f243e4c349e822a957bbff9224bc5dde9492ef54e8a439f6bc"
        "8c7355b87a925a37ee405a7502991111"
    )


def test_bip85_rsa_entropy_vectors_match_libwally():
    root = bip32.HDKey.from_string(LIBWALLY_RSA_MASTER_XPRV)
    for expected, bits, index in BIP85_GPG_RSA_VECTORS:
        entropy = bip85.derive_entropy(root, tools_views.BIP85_GPG_APP, [bits, index])
        assert entropy.hex() == expected


# ── Cross-implementation reference vectors ──────────────────────────────────
# These vectors use the common xprv from the BIP85 spec test vectors.
# Any BIP85-GPG implementation MUST derive identical entropy, DRNG output,
# and key material for the same master key and path.
#
# For RSA, PyCryptodome's RSA.generate(bits, randfunc=drng.read) is the
# reference algorithm as implied by the BIP85 spec's example code
# (``RSA.generate_key(4096, drng_reader.read)``).
#
# Master xprv:
#   xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLH
#   RdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb

CROSS_IMPL_XPRV = LIBWALLY_RSA_MASTER_XPRV

CROSS_IMPL_ECC_VECTORS = [
    # (key_type, key_bits, expected_entropy_hex, expected_private_hex)
    (
        tools_views.BIP85_GPG_KEY_TYPE_BRAINPOOL,
        256,
        "99f74d7072aac4946462a3ab99fd6b55f509ab321321f27813dee383a98aa541"
        "bd4cc82136d56b4d67eefe32919243b077eed26874218f5df567ac07568756bf",
        "99f74d7072aac4946462a3ab99fd6b55f509ab321321f27813dee383a98aa541",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_BRAINPOOL,
        384,
        "6ef5e7ea71ca14fe1a89f741fbaa4bedf8f59584c6fa9372e1b0c2e4516d7949"
        "e61a2311e9bfc9dd5372221d7192f8a2957c1571f96be2f774cc5fee8adcd911",
        "6ef5e7ea71ca14fe1a89f741fbaa4bedf8f59584c6fa9372e1b0c2e4516d7949"
        "e61a2311e9bfc9dd5372221d7192f8a2",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_BRAINPOOL,
        512,
        "af5ef50a4f3277f4f57e714cba3caae61ca19bc2a4bfeba4b6726ef319a67427"
        "f317d91ed72948abc6f96a77008acad7ee6b3585e6b0beaef76a2ab9f52f75f1",
        "048157517348b369b5a98a9e8672aede51710e0ef0f61995e00ed228a9736bb7"
        "9dd97cdd8a8022928573095d80deba90d0b96204de52e3d141e294375886758a",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_CURVE25519,
        256,
        "0321683e4d481bb6b5bac0585dbb06689827b9d6db3c530b5f6c31e20c52e444"
        "7059dbf3076cbd982cb90e2054f098a5cad5496528a5a7542b09b5b3e5394dbb",
        "0321683e4d481bb6b5bac0585dbb06689827b9d6db3c530b5f6c31e20c52e444",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_SECP256K1,
        256,
        "9ba495532c0251a4a8bd0986c0bff07a413a9204881603ace0df8474f3af7e19"
        "e622cf1b4da077d26ecfc972f2b84069b50a4c11680fecc4afb2af8b74c68913",
        "9ba495532c0251a4a8bd0986c0bff07a413a9204881603ace0df8474f3af7e19",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_NIST,
        256,
        "60e76b9f4a447d4aa4f025c488b598c773b6e0b668e2f7b71bdafb62a0fb7303"
        "950b05c2834a8d62d155239e9f78ef26c36e23ab4f4ea894aaa685ef41b89d38",
        "60e76b9f4a447d4aa4f025c488b598c773b6e0b668e2f7b71bdafb62a0fb7303",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_NIST,
        384,
        "0ca78fc4de4da1969056cb3b2f84006b05b14af0728e80c6b64c0f377b0fe5bb"
        "bc948fc22c4e4159cef87bafa9941933ce7c06b0fd57a144ae03fd704f403fa6",
        "0ca78fc4de4da1969056cb3b2f84006b05b14af0728e80c6b64c0f377b0fe5bb"
        "bc948fc22c4e4159cef87bafa9941933",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_NIST,
        521,
        "ae8a24dfe0384325ab79ed862516c7cb364b1380743fe0ee68fad8e2d5661996"
        "4166197f2a412121976b24a1d8ad8fcf6168fcb1addb882e7ca84e93b47dec43",
        "001df6eb998fadfb515abc005427aad7828469740ce6a2b8e1ee8f3a2fc5076b"
        "98305406191e5589c6a96c79c620cf87ec948a2db4c2119e2e045e4fb4537cc3c6f0",
    ),
]

# Expected RSA-2048 n value for path m/83696968'/828365'/2048'/0'
# generated via PyCryptodome RSA.generate(2048, randfunc=drng.read) using the
# BIP85-spec (v4) RSA derivation path.
CROSS_IMPL_RSA2048_N = int(
    "d8561115a08e16b3c491b634673f57e14e4c76a918fb052f64cf73da48e987246d6aa01e2ce6ec18cabfef03e2ae820266c524f6db6aad2bc6a0c2b94ab86483e01d99cf07432958a6f56c313e39bee25e30b4f5bf0576b65d4d1bd94dbb7f259e8e59c005f132968ea5b679906f82b9f3fb5febd5f6819ff200e3dbe06622b04fef08c8e5fa3f0a290dc0859521ee0879c7bdc27159d6486875c2c21237abfd96f8659779836a4fe5560c79918ab64df5f285677a27616b5f4523f3b6c3d867fedf4616d456dd4ad477ea06efa2bf8e72d0274d51a2058dc1d5ae97e238f7ab30ec168204d15d5e294be7942b1177398de2b0c19a5b89e9795958db56055319",
    16,
)


def test_cross_impl_ecc_entropy_vectors():
    """Entropy values for ECC key types match reference vectors."""
    root = bip32.HDKey.from_string(CROSS_IMPL_XPRV)
    for key_type, key_bits, expected_entropy, _ in CROSS_IMPL_ECC_VECTORS:
        entropy = bip85.derive_entropy(
            root, tools_views.BIP85_GPG_ECC_APP, [key_type, key_bits, 0]
        )
        assert entropy.hex() == expected_entropy, (
            f"Entropy mismatch for key_type={key_type}, key_bits={key_bits}"
        )


def test_cross_impl_ecc_private_key_vectors():
    """Derived ECC private key scalars match reference vectors."""
    root = bip32.HDKey.from_string(CROSS_IMPL_XPRV)
    derivers = {
        (tools_views.BIP85_GPG_KEY_TYPE_CURVE25519, 256): lambda r: bip85_ed25519_from_root(r, 0),
        (tools_views.BIP85_GPG_KEY_TYPE_SECP256K1, 256): lambda r: bip85_secp256k1_from_root(r, 0),
        (tools_views.BIP85_GPG_KEY_TYPE_NIST, 256): lambda r: bip85_p256_from_root(r, 0),
        (tools_views.BIP85_GPG_KEY_TYPE_NIST, 384): lambda r: bip85_p384_from_root(r, 0),
        (tools_views.BIP85_GPG_KEY_TYPE_NIST, 521): lambda r: bip85_p521_from_root(r, 0),
        (tools_views.BIP85_GPG_KEY_TYPE_BRAINPOOL, 256): lambda r: bip85_brainpoolp256r1_from_root(r, 0),
        (tools_views.BIP85_GPG_KEY_TYPE_BRAINPOOL, 384): lambda r: bip85_brainpoolp384r1_from_root(r, 0),
        (tools_views.BIP85_GPG_KEY_TYPE_BRAINPOOL, 512): lambda r: bip85_brainpoolp512r1_from_root(r, 0),
    }
    for key_type, key_bits, _, expected_private_hex in CROSS_IMPL_ECC_VECTORS:
        key = derivers[(key_type, key_bits)](root)
        actual = int(key.s)
        expected = int(expected_private_hex, 16)
        assert actual == expected, (
            f"Private key mismatch for key_type={key_type}, key_bits={key_bits}: "
            f"got {hex(actual)}, expected {hex(expected)}"
        )


def test_cross_impl_rsa2048_key():
    """RSA-2048 key n-value matches reference vector.

    This pins PyCryptodome's RSA.generate() output for deterministic
    cross-implementation verification.  The BIP85 spec implies
    PyCryptodome by its example: ``RSA.generate_key(4096, drng_reader.read)``.
    """
    root = bip32.HDKey.from_string(CROSS_IMPL_XPRV)
    key = bip85_rsa_from_root(root, 2048, 0)
    assert key.n == CROSS_IMPL_RSA2048_N


def test_xprv_seed_produces_same_bip85_gpg_keys():
    """XprvSeed.get_root() must produce the same BIP85 GPG keys as the
    equivalent mnemonic-derived Seed.  This is the bug that caused the user
    to see different RSA keys when loading an xprv directly into SeedSigner
    versus providing a mnemonic to bipsea."""
    seed = Seed(mnemonic=MNEMONIC)
    root_from_mnemonic = bip32.HDKey.from_seed(seed.seed_bytes)
    xprv_str = root_from_mnemonic.to_base58()
    xprv_seed = XprvSeed(xprv_str)

    root_from_xprv = xprv_seed.get_root()

    # The roots must derive identical BIP85 entropy
    entropy_mn = bip85.derive_entropy(root_from_mnemonic, tools_views.BIP85_GPG_APP, [2048, 0])
    entropy_xp = bip85.derive_entropy(root_from_xprv, tools_views.BIP85_GPG_APP, [2048, 0])
    assert entropy_mn == entropy_xp, "XprvSeed BIP85 entropy must match mnemonic Seed"

    # RSA key must be identical
    rsa_mn = bip85_rsa_from_root(root_from_mnemonic, 2048, 0)
    rsa_xp = bip85_rsa_from_root(root_from_xprv, 2048, 0)
    assert rsa_mn.n == rsa_xp.n, "XprvSeed RSA key n-value must match mnemonic Seed"

    # ECC key must be identical
    ecc_mn = bip85_secp256k1_from_root(root_from_mnemonic, 0)
    ecc_xp = bip85_secp256k1_from_root(root_from_xprv, 0)
    assert int(ecc_mn.s) == int(ecc_xp.s), "XprvSeed secp256k1 key must match mnemonic Seed"


def test_bip85_rsa_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_rsa_from_root(root, 2048, 0)
    assert key.size_in_bits() == MIN_RSA_KEY_BITS
    assert key.n == int(
        "c50bee42220c0162164154c147b661aff9ac6b56e9f1a470db1fdba5ba82338113c5734135bb49d7a4e248b2927324dcd2d5493d385543145177a79cb0a7cdea8c8b31f493d24a7bdeb0cdd0c7ef3685e34c7f5776d2f86d6b3b935bf2d5d3edcbb5c338314444eba19c2c128e935cfaa217fde3fbcab3d2dfdc9a7d9dbf9ca5d1f9cd58f862d8158d0de7fb5c8935ea52547d662bbe1e484752b2104e8d337a4794f9c2b2b0b6c4afcb4bf88c304644c0b134355f39228619091fe7fbe612f0005216b441edce575dbf639710c73eab6da71f980bb2a412b19fbceeca3b56756a62d29e12cbfbb1a6025f4059a9ea5ce6b537e2f06bb589a5e24b22a6f77b95",
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
        "c3cfd8332fde9f8ec605520f687c11f250b0eedfd695aa3170f3eb242c15e0be769a1120f9c81c30615e3a5f3a0c50aa399df15f2d3a8554a0d698c5c86cacfbbce160c8bf6e7f581f9ad16885cbe5aeffeddc8ff66c16a16b6f429da765b98adbdd4554e0ec322206fc8c9b780f3527f2b93aa3075bde1fb735829e41f5f42be6ee7dc0d28f570c394e7610f44b85ba452a933e2405a3a72cdf8d33577a85fb5bb35b2cd0c2d7c6f3309c4ca47aab8eb094d31db982c91e9ea9c8f369827d73c4a53f943c15dfff791b33aa2d60173f13dc437cee05222b288726cea9d02eefff111a74714655ed6c048c27ff1a3264732d2952a233c42b640ec93bc214a39eef342b285c828ae00d2082fae2bef26e88a6fc0650939beeeb518feea3b79576a54afe640146eb0d9fb0bcd12d14d7dea6aed79527243a182f6bf83d9b6128582b87eddecfb99d8969c779314e8334e7580204ac25ae734035b45510268d6fb8964a4f74ae7ca5ff2cabf0553c374d760d600da4472d09a42a81844844346525",
        16,
    )


def test_bip85_secp256k1_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_secp256k1_from_root(root, 0)
    assert int(key.s) == int(
        "f529e2f3cad2cf9802b0a1a79ca1c4cdd28c949e0aa308be5b00a222e4a4660d", 16
    )


def test_bip85_p256_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_p256_from_root(root, 0)
    assert int(key.s) == int(
        "e0838b1c92a21848c8c8ee04955731a43e2a7ad494686009a0036ab213900d53", 16
    )


def test_bip85_brainpoolp256r1_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_brainpoolp256r1_from_root(root, 0)
    assert int(key.s) == int(
        "5923cca8bd2306497a639aa3f12015e05625280248773074a74d74ba56a14a5d", 16
    )


def test_bip85_ed25519_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_ed25519_from_root(root, 0)
    assert int(key.s) == int(
        "68119ed59fc9ce4e36df33fa7b72aaa35ea770157c354cc6563fdc07f4bfa56f", 16
    )


def test_bip85_ed25519_sub_index_progression():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    first = bip85_ed25519_from_root(root, 0, 0, "EdDSA")
    later = bip85_ed25519_from_root(root, 0, 3, "EdDSA")
    repeat = bip85_ed25519_from_root(root, 0, 3, "EdDSA")
    assert int(first.s) != int(later.s)
    assert int(later.s) == int(repeat.s)


def test_bip85_p384_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_p384_from_root(root, 0)
    assert int(key.s) == int(
        "e36559c29f42335d87e41e20fc5b1dd38ff25c1c95f82a485306a5d4857e17a9"
        "488e9d2d434ba2caacb8d37010b17954", 16
    )


def test_bip85_p521_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_p521_from_root(root, 0)
    assert int(key.s) == int(
        "91248ae2a5b591de85b6b5b085e86c4994ac83f4713a15167d9929d544e9fd67"
        "3535b0f5d1ac83b7cfcc777093f998232f9963420f4b87451d0387475d90be1f0a", 16
    )


def test_bip85_brainpoolp384r1_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_brainpoolp384r1_from_root(root, 0)
    # This mnemonic's entropy exceeds the curve order, exercising the
    # out-of-range fallback: (d % (order - 1)) + 1.
    assert int(key.s) == int(
        "57581fcdb322ce09f3b8078febca048573aa62a4ad6a2c4d10f24a9225dbea1b"
        "eee20410bfced8c9caf1fdcb0a9199a5", 16
    )


def test_bip85_brainpoolp512r1_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_brainpoolp512r1_from_root(root, 0)
    assert int(key.s) == int(
        "53f9a8f68b6374e98fc002923c1b246876fa747f15445642c222fa92ce8ecae4"
        "685eabb88b47376281cc9bfe0918f5e3041a9397d54ab45b2cb03fe0e9284043", 16
    )


def test_bip85_gpg_mixed_subkeys_deterministic():
    import datetime
    from pgpy import PGPKey, PGPUID
    from pgpy.pgp import PrivKeyV4, PrivSubKeyV4
    from pgpy.constants import (
        PubKeyAlgorithm,
        KeyFlags,
        HashAlgorithm,
        SymmetricKeyAlgorithm,
        CompressionAlgorithm,
    )
    from pgpy.packet import fields
    from pgpy.packet.types import MPI
    from Cryptodome.PublicKey import RSA

    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    created = datetime.datetime.fromtimestamp(
        BIP85_GPG_CREATED_TS, tz=datetime.timezone.utc
    )
    pk = PrivKeyV4()
    pk.pkalg = PubKeyAlgorithm.ECDSA
    pk.keymaterial = bip85_p256_from_root(root, 0)
    pk.created = created
    pk.update_hlen()
    pgp_key = PGPKey()
    pgp_key._key = pk
    uid = PGPUID.new("Test", email="test@example.com")
    pgp_key.add_uid(
        uid,
        usage={KeyFlags.Certify, KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
        created=created,
    )
    for sub_index, pkalg, usage, alg in _bip85_subkey_specs("nistp256"):
        subpkt = PrivSubKeyV4()
        subpkt.pkalg = pkalg
        subpkt.keymaterial = bip85_p256_from_root(root, 0, sub_index, alg)
        subpkt.created = created
        subpkt.update_hlen()
        subkey = PGPKey()
        subkey._key = subpkt
        pgp_key.add_subkey(
            subkey,
            usage=usage,
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB],
            created=created,
        )

    def rsa_to_privpacket(rsa_key: RSA.RsaKey):
        priv = fields.RSAPriv()
        priv.n = MPI(rsa_key.n)
        priv.e = MPI(rsa_key.e)
        priv.d = MPI(rsa_key.d)
        priv.p = MPI(rsa_key.p)
        priv.q = MPI(rsa_key.q)
        priv.u = MPI(pow(rsa_key.p, -1, rsa_key.q))
        priv._compute_chksum()
        return priv

    for sub_index, pkalg, usage in _bip85_subkey_specs("rsa2048"):
        subpkt = PrivSubKeyV4()
        subpkt.pkalg = pkalg
        rsa_sub = bip85_rsa_from_root(root, 2048, 1, sub_index)
        subpkt.keymaterial = rsa_to_privpacket(rsa_sub)
        subpkt.created = created
        subpkt.update_hlen()
        subkey = PGPKey()
        subkey._key = subpkt
        pgp_key.add_subkey(
            subkey,
            usage=usage,
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB],
            created=created,
        )

    assert pgp_key.fingerprint == "6C79741D392914BFE19CFEB4DF9ED6BE0F21ABC4"
    fingerprints = [str(sk.fingerprint).replace(" ", "") for sk in pgp_key.subkeys.values()]
    assert fingerprints == [
        "6093F744D09D51C230F0F498675FDABF1B809BF5",
        "85BC69CB49E4D0DA251250C4724713A741F680C4",
        "AD7644301EC93FE89E884F22C7F0741C8576F571",
        "0938B62C0B8FE641FE528A8411A26272C153E6CF",
        "9696B4AAFCA808BFFDE2A04AD2CA980F3652A5D4",
        "07A435FD12E96F72C09B31966577C9E71A248706",
    ]


def test_bip85_load_key_deterministic(monkeypatch):
    from pgpy import PGPKey

    seed = Seed(mnemonic=MNEMONIC)

    captured = {}

    def fake_run(cmd, input=None, capture_output=False, text=False, **kwargs):
        captured["armored"] = input
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        return R()

    monkeypatch.setattr("subprocess.run", fake_run)

    from seedsigner.gui.screens import seed_screens, tools_screens

    class DummyIndexScreen:
        def __init__(self, *args, **kwargs):
            pass
        def display(self):
            return "0"

    monkeypatch.setattr(
        seed_screens,
        "SeedBIP85SelectChildIndexScreen",
        DummyIndexScreen,
    )

    inputs = iter([
        {"textToEncode": "Test"},
        {"textToEncode": "t@example.com"},
        {"textToEncode": ""},
    ])

    class DummyTextEntry:
        def __init__(self, textToEncode="", title=""):
            pass
        def display(self):
            return next(inputs)

    monkeypatch.setattr(
        tools_screens,
        "ToolsTextQRTextEntryScreen",
        DummyTextEntry,
    )

    class DummyLoading:
        def __init__(self, text=""):
            pass
        def start(self):
            pass
        def stop(self):
            pass

    from seedsigner.gui.screens import screen as screen_mod
    monkeypatch.setattr(screen_mod, "LoadingScreenThread", DummyLoading)

    def fake_run_screen(self, screen, **kwargs):
        if kwargs.get("title") == "Key Type":
            return 0
        return 0

    monkeypatch.setattr(tools_views.ToolsGPGLoadBIP85KeyView, "run_screen", fake_run_screen)

    controller = type(
        "C",
        (),
        {
            "storage": type("S", (), {"seeds": [seed]})(),
            "get_seed": lambda self, idx: seed,
            "VERSION": Controller.VERSION,
        },
    )()
    from seedsigner.models.settings_definition import SettingsConstants
    settings = type(
        "S",
        (),
        {"get_value": lambda self, x: SettingsConstants.MAINNET},
    )()

    view = object.__new__(tools_views.ToolsGPGLoadBIP85KeyView)
    view.controller = controller
    view.settings = settings

    tools_views.BIP85_DATA.clear()
    tools_views.ToolsGPGLoadBIP85KeyView.run(view)
    fpr1 = PGPKey.from_blob(captured["armored"])[0].fingerprint

    inputs = iter([
        {"textToEncode": "Test"},
        {"textToEncode": "t@example.com"},
        {"textToEncode": ""},
    ])
    class DummyTextEntry2:
        def __init__(self, textToEncode="", title=""):
            pass
        def display(self):
            return next(inputs)

    monkeypatch.setattr(
        tools_screens,
        "ToolsTextQRTextEntryScreen",
        DummyTextEntry2,
    )
    captured.clear()
    tools_views.ToolsGPGLoadBIP85KeyView.run(view)
    fpr2 = PGPKey.from_blob(captured["armored"])[0].fingerprint

    assert fpr1 == fpr2


def test_bip85_add_subkeys_index_sequential(monkeypatch):
    import datetime, subprocess
    from pgpy import PGPKey, PGPUID
    from pgpy.pgp import PrivKeyV4
    from pgpy.constants import (
        PubKeyAlgorithm,
        KeyFlags,
        HashAlgorithm,
        SymmetricKeyAlgorithm,
        CompressionAlgorithm,
    )

    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    created = datetime.datetime.fromtimestamp(
        BIP85_GPG_CREATED_TS, tz=datetime.timezone.utc
    )
    pk = PrivKeyV4()
    pk.pkalg = PubKeyAlgorithm.ECDSA
    pk.keymaterial = bip85_p256_from_root(root, 0)
    pk.created = created
    pk.update_hlen()
    pgp_key = PGPKey()
    pgp_key._key = pk
    uid = PGPUID.new("Test", email="t@example.com")
    pgp_key.add_uid(
        uid,
        usage={KeyFlags.Certify, KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
        created=created,
    )

    def fake_run(cmd, capture_output=False, text=False, input=None):
        class Result:
            def __init__(self, stdout=""):
                self.stdout = stdout
                self.returncode = 0

        if "--export-secret-keys" in cmd:
            return Result(str(pgp_key))
        return Result()

    monkeypatch.setattr(subprocess, "run", fake_run)

    added1 = bip85_add_subkeys(pgp_key.fingerprint, "ed25519", 0, 0, seed)
    added2 = bip85_add_subkeys(pgp_key.fingerprint, "secp256k1", 1, 3, seed)
    added3 = bip85_add_subkeys(pgp_key.fingerprint, "p256", 2, 6, seed)
    assert [a["index"] for a in added1] == [0, 1, 2]
    assert [a["index"] for a in added2] == [3, 4, 5]
    assert [a["index"] for a in added3] == [6, 7, 8]


def test_bip85_verify_existing_supports_cv25519():
    import datetime
    from pgpy import PGPKey
    from pgpy.pgp import PrivKeyV4, PrivSubKeyV4
    from pgpy.constants import PubKeyAlgorithm

    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    created = datetime.datetime.fromtimestamp(
        BIP85_GPG_CREATED_TS, tz=datetime.timezone.utc
    )

    pk = PrivKeyV4()
    pk.pkalg = PubKeyAlgorithm.EdDSA
    pk.keymaterial = bip85_ed25519_from_root(root, 0)
    pk.created = created
    pk.update_hlen()
    primary = PGPKey()
    primary._key = pk

    subkeys = []
    for sub_index, pkalg, usage, alg_name in _bip85_subkey_specs("ed25519"):
        subpkt = PrivSubKeyV4()
        subpkt.pkalg = pkalg
        subpkt.keymaterial = bip85_ed25519_from_root(root, 0, sub_index, alg_name)
        subpkt.created = created
        subpkt.update_hlen()
        subkey = PGPKey()
        subkey._key = subpkt
        curve = "cv25519" if alg_name == "ECDH" else "ed25519"
        subkeys.append(
            {
                "idx": sub_index + 1,
                "fpr": subkey.fingerprint,
                "algo": str(pkalg.value),
                "curve": curve,
                "bits": "255",
            }
        )

    assert bip85_verify_existing(
        seed,
        primary.fingerprint,
        0,
        BIP85_GPG_CREATED_TS,
        "22",
        "255",
        "ed25519",
        subkeys,
    )




def test_bip85_verify_existing_supports_cv25519_with_xprv_seed():
    import datetime
    from pgpy import PGPKey
    from pgpy.pgp import PrivKeyV4, PrivSubKeyV4
    from pgpy.constants import PubKeyAlgorithm

    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    xprv_seed = XprvSeed(root.to_base58())
    created = datetime.datetime.fromtimestamp(
        BIP85_GPG_CREATED_TS, tz=datetime.timezone.utc
    )

    pk = PrivKeyV4()
    pk.pkalg = PubKeyAlgorithm.EdDSA
    pk.keymaterial = bip85_ed25519_from_root(root, 0)
    pk.created = created
    pk.update_hlen()
    primary = PGPKey()
    primary._key = pk

    subkeys = []
    for sub_index, pkalg, usage, alg_name in _bip85_subkey_specs("ed25519"):
        subpkt = PrivSubKeyV4()
        subpkt.pkalg = pkalg
        subpkt.keymaterial = bip85_ed25519_from_root(root, 0, sub_index, alg_name)
        subpkt.created = created
        subpkt.update_hlen()
        subkey = PGPKey()
        subkey._key = subpkt
        curve = "cv25519" if alg_name == "ECDH" else "ed25519"
        subkeys.append(
            {
                "idx": sub_index + 1,
                "fpr": subkey.fingerprint,
                "algo": str(pkalg.value),
                "curve": curve,
                "bits": "255",
            }
        )

    assert bip85_verify_existing(
        xprv_seed,
        primary.fingerprint,
        0,
        BIP85_GPG_CREATED_TS,
        "22",
        "255",
        "ed25519",
        subkeys,
    )


def test_parse_secret_key_list_primary_fingerprint_only():
    output = "\n".join(
        [
            "sec:-:0:0:::0::::::23::0:",
            "fpr:::::::::PRIMARYFPR:",
            "uid::::Test User:::::::",
            "ssb:-:0:0:::0::::::23::0:",
            "fpr:::::::::SUBKEYFPR:",
        ]
    )
    keys = parse_secret_key_list(output)
    assert keys[0]["fpr"] == "PRIMARYFPR"


def test_parse_secret_key_list_includes_created():
    output = "\n".join(
        [
            f"sec:-:0:0:KEYID:{BIP85_GPG_CREATED_TS}:0::::::23::0:",
            "fpr:::::::::PRIMARYFPR:",
            f"uid:u::::{BIP85_GPG_CREATED_TS}::HASH::Test User::::::::0:",
        ]
    )
    keys = parse_secret_key_list(output)
    assert keys[0]["created"] == BIP85_GPG_CREATED_TS


def test_parse_subkey_list_extracts_fingerprint():
    output = "\n".join(
        [
            "ssb:-:2048:1:::0::::::s::",
            "fpr:::::::::SUBFPR1:",
            "ssb:-:256:19:::0::::::e::::nistp256:",
            "fpr:::::::::SUBFPR2:",
        ]
    )
    subs = parse_subkey_list(output)
    assert subs[0]["fpr"] == "SUBFPR1"
    assert subs[1]["fpr"] == "SUBFPR2"
    assert subs[0]["idx"] == 1
    assert subs[1]["idx"] == 2
    assert subs[0]["algo"] == "1"
    assert subs[0]["bits"] == "2048"
    assert subs[0]["curve"] == ""
    assert subs[1]["algo"] == "19"
    assert subs[1]["bits"] == "256"
    assert subs[1]["curve"] == "nistp256"


def test_parse_uid_list_extracts_uids():
    output = "\n".join(
        [
            "sec:-:0:0:KEYID:::0::::::23::0:",
            "fpr:::::::::PRIMARYFPR:",
            "uid:::::::::User One::",
            "uid:::::::::User Two::",
        ]
    )
    uids = parse_uid_list(output)
    assert uids[0]["uid"] == "User One"
    assert uids[0]["idx"] == 1
    assert uids[1]["uid"] == "User Two"
    assert uids[1]["idx"] == 2


def test_add_uid_preserves_primary(tmp_path):
    from subprocess import run

    gnupg_home = tmp_path / "gnupg"
    gnupg_home.mkdir()
    os.chmod(gnupg_home, 0o700)
    env = {**os.environ, "GNUPGHOME": str(gnupg_home)}

    run(
        [
            "gpg",
            "--batch",
            "--passphrase",
            "",
            "--pinentry-mode",
            "loopback",
            "--quick-gen-key",
            "tester@example.com",
        ],
        env=env,
        check=True,
    )

    result = run(
        ["gpg", "--list-secret-keys", "--with-colons"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    keys = parse_secret_key_list(result.stdout)
    fpr = keys[0]["fpr"]
    primary = keys[0]["uid"]

    run(
        [
            "gpg",
            "--batch",
            "--quick-add-uid",
            fpr,
            "Another User <alt@example.com>",
        ],
        env=env,
        check=True,
    )
    run(
        ["gpg", "--batch", "--quick-set-primary-uid", fpr, primary],
        env=env,
        check=True,
    )

    result = run(
        ["gpg", "--list-secret-keys", "--with-colons", fpr],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    uids = parse_uid_list(result.stdout)
    assert uids[0]["uid"] == primary


def test_uid_menu_includes_set_primary_option(monkeypatch):
    from seedsigner.views import tools_views

    captured = {}

    def fake_run_screen(self, screen, *args, **kwargs):
        captured["labels"] = [b.button_label for b in kwargs.get("button_data", [])]
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(tools_views.ToolsGPGUidMenuView, "run_screen", fake_run_screen)
    view = tools_views.ToolsGPGUidMenuView()
    view.run()
    assert "Set Primary User ID" in captured["labels"]


def test_set_primary_uid_sets_selected_uid(tmp_path, monkeypatch):
    import subprocess
    from seedsigner.views import tools_views

    gnupg_home = tmp_path / "gnupg"
    gnupg_home.mkdir()
    os.chmod(gnupg_home, 0o700)
    env = {**os.environ, "GNUPGHOME": str(gnupg_home)}

    subprocess.run(
        [
            "gpg",
            "--batch",
            "--passphrase",
            "",
            "--pinentry-mode",
            "loopback",
            "--quick-gen-key",
            "tester@example.com",
        ],
        env=env,
        check=True,
    )

    result = subprocess.run(
        ["gpg", "--list-secret-keys", "--with-colons"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    keys = parse_secret_key_list(result.stdout)
    fpr = keys[0]["fpr"]

    subprocess.run(
        ["gpg", "--batch", "--quick-add-uid", fpr, "Another <alt@example.com>"],
        env=env,
        check=True,
    )

    subprocess.run(
        ["gpg", "--batch", "--quick-set-primary-uid", fpr, "tester@example.com"],
        env=env,
        check=True,
    )

    real_run = subprocess.run

    def fake_run(cmd, *args, **kwargs):
        kwargs.setdefault("env", env)
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", fake_run)

    def fake_run_screen(self, screen, *args, **kwargs):
        title = kwargs.get("title")
        if title == "Select Key":
            return 0
        if title == "Set Primary User ID":
            return 1
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(tools_views.ToolsGPGSetPrimaryUidView, "run_screen", fake_run_screen)

    view = tools_views.ToolsGPGSetPrimaryUidView()
    view.run()

    result = real_run(
        ["gpg", "--list-secret-keys", "--with-colons", fpr],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    uids = parse_uid_list(result.stdout)
    assert uids[0]["uid"] == "Another <alt@example.com>"


def test_load_bip85_key_selects_seed(monkeypatch):
    from seedsigner.views import tools_views

    controller = Controller.get_instance()
    original = list(controller.storage.seeds)
    controller.storage.seeds = [Seed(mnemonic=MNEMONIC), Seed(mnemonic=MNEMONIC)]

    responses = iter([0, 1])
    screens = []
    captured = {}

    def fake_run_screen(self, screen, *args, **kwargs):
        screens.append(screen)
        if kwargs.get("title") == "Key Type":
            captured["key_type_options"] = [
                button.button_label for button in kwargs.get("button_data", [])
            ]
            return RET_CODE__BACK_BUTTON
        return next(responses)

    class DummyIndexScreen:
        def __init__(self, *args, **kwargs):
            pass

        def display(self):
            return "0"

    monkeypatch.setattr(tools_views.ToolsGPGLoadBIP85KeyView, "run_screen", fake_run_screen)
    monkeypatch.setattr(
        tools_views.seed_screens, "SeedBIP85SelectChildIndexScreen", DummyIndexScreen
    )

    # The view now indexes controller.storage.seeds directly rather than going
    # through a Controller lookup, so capture the selection at the list instead.
    class CapturingSeedList(list):
        def __getitem__(self, index):
            captured["idx"] = index
            return super().__getitem__(index)

    controller.storage.seeds = CapturingSeedList(controller.storage.seeds)

    view = tools_views.ToolsGPGLoadBIP85KeyView()
    try:
        view.run()
    finally:
        controller.storage.seeds = original

    assert captured["idx"] == 1
    assert screens[0] == WarningScreen
    assert screens[1] == tools_views.seed_screens.SeedSelectSeedScreen
    assert captured["key_type_options"] == [
        "ECC Ed25519",
        "ECC NIST P-256",
        "ECC Brainpool P-256",
        "RSA 2048",
        "RSA 3072",
        "RSA 4096",
        "ECC secp256k1",
    ]


def test_load_bip85_key_warning_always_shown(monkeypatch):
    from seedsigner.views import tools_views

    controller = Controller.get_instance()
    original = list(controller.storage.seeds)
    controller.storage.seeds = [Seed(mnemonic=MNEMONIC)]

    responses = iter([0])
    screens = []
    captured = {}

    def fake_run_screen(self, screen, *args, **kwargs):
        screens.append(screen)
        if kwargs.get("title") == "Key Type":
            captured["key_type_options"] = [
                button.button_label for button in kwargs.get("button_data", [])
            ]
            return RET_CODE__BACK_BUTTON
        return next(responses)

    class DummyIndexScreen:
        def __init__(self, *args, **kwargs):
            pass

        def display(self):
            return "0"

    monkeypatch.setattr(tools_views.ToolsGPGLoadBIP85KeyView, "run_screen", fake_run_screen)
    monkeypatch.setattr(
        tools_views.seed_screens, "SeedBIP85SelectChildIndexScreen", DummyIndexScreen
    )

    view = tools_views.ToolsGPGLoadBIP85KeyView()

    try:
        view.run()
    finally:
        controller.storage.seeds = original

    assert screens and screens[0] == WarningScreen
    assert captured["key_type_options"] == [
        "ECC Ed25519",
        "ECC NIST P-256",
        "ECC Brainpool P-256",
        "RSA 2048",
        "RSA 3072",
        "RSA 4096",
        "ECC secp256k1",
    ]


def test_bip85_key_type_choices_include_all():
    """``_bip85_key_type_choices(include_all=True)`` returns every type."""
    from seedsigner.views.tools_views import _bip85_key_type_choices

    choices = _bip85_key_type_choices(include_all=True)
    codes = [code for _, code in choices]
    assert "p384" in codes
    assert "p521" in codes
    assert "brainpoolp384r1" in codes
    assert "brainpoolp512r1" in codes
    assert len(codes) == len(SettingsConstants.ALL_GPG_KEY_TYPES)
    assert set(codes) == {code for code, _ in SettingsConstants.ALL_GPG_KEY_TYPES}


def test_bip85_key_type_choices_respects_setting(monkeypatch):
    """``_bip85_key_type_choices()`` filters by ``SETTING__GPG_KEY_TYPES``."""
    from seedsigner.views.tools_views import _bip85_key_type_choices
    from seedsigner.models.settings import Settings

    settings = Settings.get_instance()
    original = settings.get_value(SettingsConstants.SETTING__GPG_KEY_TYPES)
    settings.set_value(SettingsConstants.SETTING__GPG_KEY_TYPES, ["rsa2048"])
    try:
        choices = _bip85_key_type_choices()
        assert choices == [("RSA 2048", "rsa2048")]
    finally:
        settings.set_value(SettingsConstants.SETTING__GPG_KEY_TYPES, original)


def test_bip85_key_type_choices_default_matches_generate_new():
    """Default GPG key types match the original Generate New menu types."""
    from seedsigner.views.tools_views import _bip85_key_type_choices

    choices = _bip85_key_type_choices()
    codes = [code for _, code in choices]
    assert codes == [
        "ed25519",
        "p256",
        "brainpoolp256r1",
        "rsa2048",
        "rsa3072",
        "rsa4096",
        "secp256k1",
    ]


def test_filter_deletable_subkeys_bip85_only_latest():
    BIP85_DATA.clear()
    fpr = "P"
    BIP85_DATA[fpr] = {
        "primary_fpr": fpr,
        "seed_fpr": "S",
        "index": 0,
        "key_type": "ECC NIST P-256",
        "ss_version": Controller.VERSION,
        "uids": [],
        "subkeys": [
            {"index": 0, "type": "ECDH ECC NIST P-256", "fingerprint": "A"},
            {"index": 1, "type": "ECDSA ECC NIST P-256", "fingerprint": "B"},
        ],
        "revocations": [],
    }
    bip85_subs = [
        {"fpr": "A", "caps": "e", "idx": 1, "created": 0},
        {"fpr": "B", "caps": "s", "idx": 2, "created": 0},
    ]
    filtered = filter_deletable_subkeys(fpr, bip85_subs)
    assert len(filtered) == 1 and filtered[0]["idx"] == 2

    BIP85_DATA.clear()
    non_bip85 = [
        {"fpr": "A", "caps": "e", "idx": 1, "created": 0},
        {"fpr": "B", "caps": "s", "idx": 2, "created": 1},
    ]
    filtered2 = filter_deletable_subkeys("Z", non_bip85)
    assert len(filtered2) == 2


def test_bip85_save_and_load(tmp_path):
    BIP85_DATA.clear()
    fpr = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
    BIP85_DATA[fpr] = {
        "primary_fpr": fpr,
        "seed_fpr": "seedfpr",
        "index": 0,
        "key_type": "ECC NIST P-256",
        "ss_version": Controller.VERSION,
        "uids": ["User <user@example.com>"],
        "primary_uid": "User <user@example.com>",
        "subkeys": [{"index": 0, "type": "ECDH ECC NIST P-256", "fingerprint": "A"}],
        "revocations": ["A"],
    }
    bip85_save_data(tmp_path)
    assert (tmp_path / f"BIP85_{fpr[:4]}_{fpr[-4:]}.json").exists()
    BIP85_DATA.clear()
    bip85_load_data(tmp_path)
    assert BIP85_DATA[fpr]["seed_fpr"] == "seedfpr"
    assert BIP85_DATA[fpr]["key_type"] == "ECC NIST P-256"
    assert BIP85_DATA[fpr]["uids"][0] == "User <user@example.com>"
    assert BIP85_DATA[fpr]["primary_uid"] == "User <user@example.com>"
    assert BIP85_DATA[fpr]["subkeys"][0]["type"] == "ECDH ECC NIST P-256"


def test_bip85_save_same_seed_multiple_keys(tmp_path):
    """Two BIP85 keys derived from the same seed must both be saved and restored."""
    BIP85_DATA.clear()
    seed_fpr = "S" * 40
    fpr_a = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
    fpr_b = "B2C3D4E5F6A708192A3B4C5D6E7F8091ABCDEF01"
    BIP85_DATA[fpr_a] = {
        "primary_fpr": fpr_a,
        "seed_fpr": seed_fpr,
        "index": 0,
        "key_type": "ECC NIST P-256",
        "ss_version": Controller.VERSION,
        "uids": ["User A <a@example.com>"],
        "primary_uid": "User A <a@example.com>",
        "subkeys": [],
        "revocations": [],
    }
    BIP85_DATA[fpr_b] = {
        "primary_fpr": fpr_b,
        "seed_fpr": seed_fpr,
        "index": 1,
        "key_type": "RSA 3072",
        "ss_version": Controller.VERSION,
        "uids": ["User B <b@example.com>"],
        "primary_uid": "User B <b@example.com>",
        "subkeys": [],
        "revocations": [],
    }

    bip85_save_data(tmp_path)
    files = sorted(f.name for f in tmp_path.glob("*.json"))
    assert files == [f"BIP85_{fpr_a[:4]}_{fpr_a[-4:]}.json", f"BIP85_{fpr_b[:4]}_{fpr_b[-4:]}.json"]

    BIP85_DATA.clear()
    bip85_load_data(tmp_path)
    assert set(BIP85_DATA.keys()) == {fpr_a, fpr_b}
    assert BIP85_DATA[fpr_a]["index"] == 0
    assert BIP85_DATA[fpr_b]["index"] == 1


@pytest.mark.parametrize(
    "ss_version,expected_version",
    [
        ("SS0.8.6+Satochip+Earthdiver-B4", "v1"),
        ("SeSi-0.8.6+ShSi-B8", "v1"),
        ("SeSi-0.8.7+ShSi-B9", "v2"),
        ("SeSi-0.8.7+ShSi-B10", "v2"),
        ("SeSi-0.8.7+ShSi-B11", "v3"),
        ("SeSi-0.8.7+ShSi-B12", "v3"),
        ("SeSi-0.8.7+ShSi-B13", "v4"),
        ("SeSi-0.8.7+ShSi-B99", "v4"),
        ("garbage", "v4"),
        (None, "v4"),
    ],
)
def test_bip85_version_from_ss_version(ss_version, expected_version):
    from seedsigner.views.tools_views import _bip85_version_from_ss_version

    assert _bip85_version_from_ss_version(ss_version) == expected_version


def test_bip85_import_sets_version_from_ss_version():
    import json
    from seedsigner.views.tools_views import bip85_import_json, BIP85_DATA

    BIP85_DATA.clear()
    entries = [
        {
            "primary_fpr": "A" * 40,
            "seed_fpr": "B",
            "index": 1,
            "key_type": "RSA 2048",
            "ss_version": "SeSi-0.8.7+ShSi-B9",
            "uids": ["u"],
            "primary_uid": "u",
            "subkeys": [],
            "revocations": [],
        },
        {
            "primary_fpr": "C" * 40,
            "seed_fpr": "D",
            "index": 2,
            "key_type": "ECC NIST P-256",
            "ss_version": "SeSi-0.8.6+ShSi-B8",
            "uids": ["v"],
            "primary_uid": "v",
            "subkeys": [],
            "revocations": [],
        },
        {
            "primary_fpr": "E" * 40,
            "seed_fpr": "F",
            "index": 3,
            "key_type": "ECC secp256k1",
            "ss_version": "SeSi-0.8.7+ShSi-B13",
            "uids": ["w"],
            "primary_uid": "w",
            "subkeys": [],
            "revocations": [],
        },
    ]
    bip85_import_json(json.dumps(entries))
    assert BIP85_DATA["A" * 40]["bip85_version"] == "v2"
    assert BIP85_DATA["C" * 40]["bip85_version"] == "v1"
    assert BIP85_DATA["E" * 40]["bip85_version"] == "v4"


def test_bip85_import_preserves_existing_version():
    import json
    from seedsigner.views.tools_views import bip85_import_json, BIP85_DATA

    BIP85_DATA.clear()
    entry = {
        "primary_fpr": "9" * 40,
        "seed_fpr": "S",
        "index": 0,
        "key_type": "RSA 2048",
        "ss_version": "SeSi-0.8.6+ShSi-B8",
        "bip85_version": "v4",  # explicit; should not be overwritten by ss_version
        "uids": ["x"],
        "primary_uid": "x",
        "subkeys": [],
        "revocations": [],
    }
    bip85_import_json(json.dumps([entry]))
    assert BIP85_DATA["9" * 40]["bip85_version"] == "v4"


def test_load_bip85_data_from_microsd(monkeypatch, tmp_path):
    from pathlib import Path
    from seedsigner.views import gpg_views

    captured = {}

    def fake_bip85_load_data(path):
        captured["path"] = Path(path)

    monkeypatch.setattr(gpg_views, "bip85_load_data", fake_bip85_load_data)
    monkeypatch.setattr(
        gpg_views, "resolve_microsd_images_dir", lambda: tmp_path / "microsd-images"
    )

    def fake_run_screen(self, *args, **kwargs):
        return 0  # Select "From MicroSD"

    monkeypatch.setattr(
        gpg_views.ToolsGPGLoadBip85DataView, "run_screen", fake_run_screen
    )

    view = gpg_views.ToolsGPGLoadBip85DataView()
    view.run()

    expected = tmp_path / "microsd-images"
    assert captured["path"] == expected


def test_bip85_save_to_qr(monkeypatch):
    from seedsigner.gui.screens.screen import ButtonListScreen, QRDisplayScreen, WarningScreen
    from seedsigner.models.encode_qr import UrBytesQrEncoder
    import json

    BIP85_DATA.clear()
    fpr = "F"
    BIP85_DATA[fpr] = {
        "primary_fpr": fpr,
        "seed_fpr": "S",
        "index": 0,
        "key_type": "ECC NIST P-256",
        "ss_version": Controller.VERSION,
        "uids": [],
        "subkeys": [],
        "revocations": [],
    }

    captured = {}

    def fake_run_screen(self, screen, *args, **kwargs):
        if screen == ButtonListScreen:
            return 1  # select To QR
        if screen == WarningScreen:
            return 0  # start QR display
        if screen == QRDisplayScreen:
            captured["encoder"] = kwargs["qr_encoder"]
            return RET_CODE__BACK_BUTTON
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(tools_views.ToolsGPGSaveBip85DataView, "run_screen", fake_run_screen)
    view = tools_views.ToolsGPGSaveBip85DataView()
    view.run()
    encoder = captured["encoder"]
    assert isinstance(encoder, UrBytesQrEncoder)
    data = json.loads(encoder.data.decode())[0]
    assert data["primary_fpr"] == fpr


def test_bip85_save_to_microsd_logs_path(monkeypatch, tmp_path):
    from seedsigner.gui.screens.screen import ButtonListScreen, WarningScreen
    from seedsigner.views import gpg_views

    BIP85_DATA.clear()
    BIP85_DATA["F"] = {
        "primary_fpr": "F",
        "seed_fpr": "S",
        "index": 0,
        "key_type": "ECC NIST P-256",
        "ss_version": Controller.VERSION,
        "uids": [],
        "subkeys": [],
        "revocations": [],
    }

    captured = {}

    def fake_run_screen(self, screen, *args, **kwargs):
        if screen == ButtonListScreen:
            return 0  # select To MicroSD
        if screen == WarningScreen:
            return 0
        return 0

    def fake_save(path):
        captured["path"] = path

    logs = []

    def fake_log(msg, *args):
        logs.append(msg % args)

    monkeypatch.setattr(gpg_views.ToolsGPGSaveBip85DataView, "run_screen", fake_run_screen)
    monkeypatch.setattr(gpg_views, "bip85_save_data", fake_save)
    monkeypatch.setattr(gpg_views.logger, "info", fake_log)
    monkeypatch.setattr(
        gpg_views, "resolve_microsd_images_dir", lambda: tmp_path / "microsd-images"
    )

    view = gpg_views.ToolsGPGSaveBip85DataView()
    view.controller.storage.seeds = []
    view.run()

    expected_path = tmp_path / "microsd-images"
    assert captured["path"] == expected_path
    assert any(str(expected_path) in entry for entry in logs)


def test_bip85_save_to_seedkeeper(monkeypatch):
    from seedsigner.gui.screens.screen import ButtonListScreen

    class DummyConnector:
        def __init__(self):
            self.saved = None
            self.last_label = None

        def card_get_status(self):
            return (None, None, None, {"protocol_minor_version": 2})

        def make_header(self, t, rights, label):
            self.last_label = label
            return "00" * 20

        def seedkeeper_import_secret(self, secret_dic):
            self.saved = secret_dic

        def seedkeeper_get_status(self):
            return (None, None, None, {"free_memory": 4096})

    dummy = DummyConnector()
    monkeypatch.setattr(
        tools_views.seedkeeper_utils, "init_satochip", lambda *a, **k: dummy
    )

    BIP85_DATA.clear()
    BIP85_DATA["F"] = {
        "primary_fpr": "F",
        "seed_fpr": "S",
        "index": 0,
        "key_type": "ECC NIST P-256",
        "ss_version": Controller.VERSION,
        "uids": [],
        "subkeys": [],
        "revocations": [],
    }

    def fake_run_screen(self, screen, *args, **kwargs):
        if screen == ButtonListScreen:
            return 2  # select To Seedkeeper
        return 0

    monkeypatch.setattr(tools_views.ToolsGPGSaveBip85DataView, "run_screen", fake_run_screen)
    view = tools_views.ToolsGPGSaveBip85DataView()
    view.run()
    assert dummy.saved is not None
    assert dummy.last_label is not None
    assert dummy.last_label.startswith("BIP85-GPG-")


def test_bip85_seedkeeper_import_format():
    import json, binascii

    data_json = json.dumps(
        [
            {
                "primary_fpr": "F",
                "seed_fpr": "S",
                "index": 0,
                "key_type": "ECC NIST P-256",
                "uids": [],
                "subkeys": [],
                "revocations": [],
            }
        ]
    )
    secret_hex = (
        len(data_json.encode()).to_bytes(2, "big") + data_json.encode()
    ).hex()
    BIP85_DATA.clear()
    decoded = binascii.unhexlify(secret_hex)[2:]
    tools_views.bip85_import_json(decoded.decode())
    assert BIP85_DATA["F"]["seed_fpr"] == "S"
    assert BIP85_DATA["F"]["key_type"] == "ECC NIST P-256"


def test_advanced_menu_has_bip85_data_options(monkeypatch):
    buttons = {}

    def fake_run_screen(*args, **kwargs):
        buttons["labels"] = [b.button_label for b in kwargs["button_data"]]
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(
        tools_views.ToolsGPGAdvancedMenuView, "run_screen", fake_run_screen
    )
    view = tools_views.ToolsGPGAdvancedMenuView()
    view.run()
    assert "BIP85 Metadata" in buttons["labels"]


def test_bip85_metadata_menu_has_options(monkeypatch):
    buttons = {}

    def fake_run_screen(*args, **kwargs):
        buttons["labels"] = [b.button_label for b in kwargs["button_data"]]
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(
        tools_views.ToolsGPGBip85MetadataMenuView, "run_screen", fake_run_screen
    )
    view = tools_views.ToolsGPGBip85MetadataMenuView()
    view.run()
    assert "Save BIP85 Data" in buttons["labels"]
    assert "Load BIP85 Data" in buttons["labels"]
    assert "Rebuild BIP85 Key" in buttons["labels"]


def test_gpg_menu_has_view_keys_option(monkeypatch):
    buttons = {}

    def fake_run_screen(*args, **kwargs):
        buttons["labels"] = [b.button_label for b in kwargs["button_data"]]
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(
        tools_views.ToolsGPGMenuView, "run_screen", fake_run_screen
    )
    view = tools_views.ToolsGPGMenuView()
    view.run()
    assert "View Keys" in buttons["labels"]


def test_view_keys_no_keys(monkeypatch):
    import subprocess

    call_idx = [0]

    def fake_run(cmd, *a, **kw):
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)

    screens = []

    def fake_run_screen(*args, **kwargs):
        screens.append(kwargs.get("title", args[1].__name__ if len(args) > 1 else ""))
        return 0

    monkeypatch.setattr(
        tools_views.ToolsGPGViewKeysView, "run_screen", fake_run_screen
    )
    view = tools_views.ToolsGPGViewKeysView()
    view.run()
    assert "View Keys" in screens


def test_view_keys_with_key(monkeypatch):
    import subprocess

    colon_output = (
        "sec:-:255:22:81D909D9534ED202:1231006505:::-:::scESCA:::+::ed25519:::0:\n"
        "fpr:::::::::DFA07C169B1513F3485769A581D909D9534ED202:\n"
        "uid:-::::1231006505::ABC::Test User <test@example.com>::::::::::0:\n"
        "ssb:-:255:18:C8088EF1E47500B1:1231006505::::::e:::+::cv25519::\n"
        "fpr:::::::::0FAA3F5D0FCEC3E74A357659C8088EF1E47500B1:\n"
    )

    def fake_run(cmd, *a, **kw):
        class R:
            returncode = 0
            stdout = colon_output
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)

    screens = []

    def fake_run_screen(*args, **kwargs):
        title = kwargs.get("title", "")
        screens.append(title)
        if title == "View Keys":
            return 0  # select first key
        return 0

    monkeypatch.setattr(
        tools_views.ToolsGPGViewKeysView, "run_screen", fake_run_screen
    )
    view = tools_views.ToolsGPGViewKeysView()
    dest = view.run()

    assert "View Keys" in screens
    # The view now delegates to ToolsGPGKeyDetailsView
    assert dest.View_cls is tools_views.ToolsGPGKeyDetailsView
    assert dest.view_args["fpr"] == "DFA07C169B1513F3485769A581D909D9534ED202"


def test_key_details_shows_subkeys_button(monkeypatch):
    import subprocess

    colon_output = (
        "sec:-:255:22:81D909D9534ED202:1231006505:::-:::scESCA:::+::ed25519:::0:\n"
        "fpr:::::::::DFA07C169B1513F3485769A581D909D9534ED202:\n"
        "uid:-::::1231006505::ABC::Test User <test@example.com>::::::::::0:\n"
        "ssb:-:255:18:C8088EF1E47500B1:1231006505::::::e:::+::cv25519::\n"
        "fpr:::::::::0FAA3F5D0FCEC3E74A357659C8088EF1E47500B1:\n"
    )

    def fake_run(cmd, *a, **kw):
        class R:
            returncode = 0
            stdout = colon_output
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)

    screen_kwargs = []

    def fake_run_screen(*args, **kwargs):
        screen_kwargs.append(kwargs)
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(
        tools_views.ToolsGPGKeyDetailsView, "run_screen", fake_run_screen
    )
    view = tools_views.ToolsGPGKeyDetailsView(
        fpr="DFA07C169B1513F3485769A581D909D9534ED202"
    )
    view.run()

    detail_kw = screen_kwargs[-1]
    # Full fingerprint in blocks of 4 hex chars
    assert "DFA0 7C16 9B15 13F3 4857 69A5 81D9 09D9 534E D202" in detail_kw["text"]
    assert "EdDSA" in detail_kw["text"]
    # Subkey count should NOT be in the text (removed per requirements)
    assert "Subkeys:" not in detail_kw["text"]
    # No green tick icon
    assert detail_kw.get("status_icon_size") == 0
    # Back button enabled
    assert detail_kw.get("show_back_button") is True
    # Subkeys button present
    btn_labels = [b.button_label for b in detail_kw["button_data"]]
    assert "Subkeys" in btn_labels


def test_key_details_no_subkeys_no_subkeys_button(monkeypatch):
    import subprocess

    colon_output = (
        "sec:-:255:22:81D909D9534ED202:1231006505:::-:::scESCA:::+::ed25519:::0:\n"
        "fpr:::::::::DFA07C169B1513F3485769A581D909D9534ED202:\n"
        "uid:-::::1231006505::ABC::Test User <test@example.com>::::::::::0:\n"
    )

    def fake_run(cmd, *a, **kw):
        class R:
            returncode = 0
            stdout = colon_output
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)

    screen_kwargs = []

    def fake_run_screen(*args, **kwargs):
        screen_kwargs.append(kwargs)
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(
        tools_views.ToolsGPGKeyDetailsView, "run_screen", fake_run_screen
    )
    view = tools_views.ToolsGPGKeyDetailsView(
        fpr="DFA07C169B1513F3485769A581D909D9534ED202"
    )
    view.run()

    detail_kw = screen_kwargs[-1]
    btn_labels = [b.button_label for b in detail_kw["button_data"]]
    assert "Subkeys" not in btn_labels
    assert "Back" in btn_labels


def test_view_keys_filters_subkey_fprs(monkeypatch):
    """If GPG lists a subkey fingerprint as a separate sec entry, it should be
    filtered out so only genuine primary keys appear in the View Keys list."""
    import subprocess

    # Simulate GPG output where the subkey fingerprint also appears as a
    # separate sec entry (some GPG configurations may do this).
    colon_output = (
        "sec:-:255:22:81D909D9534ED202:1231006505:::-:::scESCA:::+::ed25519:::0:\n"
        "fpr:::::::::DFA07C169B1513F3485769A581D909D9534ED202:\n"
        "uid:-::::1231006505::ABC::Test User <test@example.com>::::::::::0:\n"
        "ssb:-:255:18:C8088EF1E47500B1:1231006505::::::e:::+::cv25519::\n"
        "fpr:::::::::0FAA3F5D0FCEC3E74A357659C8088EF1E47500B1:\n"
        "sec:-:255:18:C8088EF1E47500B1:1231006505:::-:::e:::+::cv25519:::0:\n"
        "fpr:::::::::0FAA3F5D0FCEC3E74A357659C8088EF1E47500B1:\n"
    )

    def fake_run(cmd, *a, **kw):
        class R:
            returncode = 0
            stdout = colon_output
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)

    screen_kwargs = []

    def fake_run_screen(*args, **kwargs):
        screen_kwargs.append(kwargs)
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(
        tools_views.ToolsGPGViewKeysView, "run_screen", fake_run_screen
    )
    view = tools_views.ToolsGPGViewKeysView()
    view.run()

    # Only 1 button should appear (the primary key), not 2
    btn_labels = [b.button_label for b in screen_kwargs[0]["button_data"]]
    assert len(btn_labels) == 1
    assert "Test User" in btn_labels[0]


def test_key_subkeys_view(monkeypatch):
    import subprocess

    colon_output = (
        "sec:-:255:22:81D909D9534ED202:1231006505:::-:::scESCA:::+::ed25519:::0:\n"
        "fpr:::::::::DFA07C169B1513F3485769A581D909D9534ED202:\n"
        "uid:-::::1231006505::ABC::Test User <test@example.com>::::::::::0:\n"
        "ssb:-:255:18:C8088EF1E47500B1:1231006505::::::e:::+::cv25519::\n"
        "fpr:::::::::0FAA3F5D0FCEC3E74A357659C8088EF1E47500B1:\n"
        "ssb:-:256:19:AABB112233445566:1231006505::::::s::::nistp256:\n"
        "fpr:::::::::AABB112233445566AABB112233445566AABB1122:\n"
    )

    def fake_run(cmd, *a, **kw):
        class R:
            returncode = 0
            stdout = colon_output
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)

    screen_kwargs = []

    def fake_run_screen(*args, **kwargs):
        screen_kwargs.append(kwargs)
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(
        tools_views.ToolsGPGKeySubkeysView, "run_screen", fake_run_screen
    )
    view = tools_views.ToolsGPGKeySubkeysView(
        fpr="DFA07C169B1513F3485769A581D909D9534ED202"
    )
    view.run()

    assert screen_kwargs[0]["title"] == "Subkeys"
    btn_labels = [b.button_label for b in screen_kwargs[0]["button_data"]]
    assert len(btn_labels) == 2
    # First subkey: cv25519 with encrypt capability
    assert "[E]" in btn_labels[0]
    # Second subkey: nistp256 with sign capability
    assert "[S]" in btn_labels[1]


def test_key_subkeys_view_select_navigates_to_subkey_details(monkeypatch):
    import subprocess

    colon_output = (
        "sec:-:255:22:81D909D9534ED202:1231006505:::-:::scESCA:::+::ed25519:::0:\n"
        "fpr:::::::::DFA07C169B1513F3485769A581D909D9534ED202:\n"
        "uid:-::::1231006505::ABC::Test User <test@example.com>::::::::::0:\n"
        "ssb:-:255:18:C8088EF1E47500B1:1231006505::::::e:::+::cv25519::\n"
        "fpr:::::::::0FAA3F5D0FCEC3E74A357659C8088EF1E47500B1:\n"
    )

    def fake_run(cmd, *a, **kw):
        class R:
            returncode = 0
            stdout = colon_output
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)

    def fake_run_screen(*args, **kwargs):
        return 0  # select first subkey

    monkeypatch.setattr(
        tools_views.ToolsGPGKeySubkeysView, "run_screen", fake_run_screen
    )
    view = tools_views.ToolsGPGKeySubkeysView(
        fpr="DFA07C169B1513F3485769A581D909D9534ED202"
    )
    dest = view.run()

    assert dest.View_cls is tools_views.ToolsGPGSubkeyDetailsView
    assert dest.view_args["primary_fpr"] == "DFA07C169B1513F3485769A581D909D9534ED202"
    assert dest.view_args["subkey_fpr"] == "0FAA3F5D0FCEC3E74A357659C8088EF1E47500B1"


def test_subkey_details_view(monkeypatch):
    import subprocess

    colon_output = (
        "sec:-:255:22:81D909D9534ED202:1231006505:::-:::scESCA:::+::ed25519:::0:\n"
        "fpr:::::::::DFA07C169B1513F3485769A581D909D9534ED202:\n"
        "uid:-::::1231006505::ABC::Test User <test@example.com>::::::::::0:\n"
        "ssb:-:255:18:C8088EF1E47500B1:1231006505::::::e:::+::cv25519::\n"
        "fpr:::::::::0FAA3F5D0FCEC3E74A357659C8088EF1E47500B1:\n"
    )

    def fake_run(cmd, *a, **kw):
        class R:
            returncode = 0
            stdout = colon_output
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)

    screen_kwargs = []

    def fake_run_screen(*args, **kwargs):
        screen_kwargs.append(kwargs)
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(
        tools_views.ToolsGPGSubkeyDetailsView, "run_screen", fake_run_screen
    )
    view = tools_views.ToolsGPGSubkeyDetailsView(
        primary_fpr="DFA07C169B1513F3485769A581D909D9534ED202",
        subkey_fpr="0FAA3F5D0FCEC3E74A357659C8088EF1E47500B1",
    )
    view.run()

    detail_kw = screen_kwargs[-1]
    assert detail_kw["title"] == "Subkey Details"
    # Full fingerprint in blocks of 4
    assert "0FAA 3F5D 0FCE C3E7 4A35 7659 C808 8EF1 E475 00B1" in detail_kw["text"]
    assert "ECDH" in detail_kw["text"]
    assert "Encrypt" in detail_kw["text"]
    assert detail_kw.get("show_back_button") is True


def test_rebuild_bip85_key(monkeypatch):
    from seedsigner.views import gpg_views

    controller = Controller.get_instance()
    seed = Seed(mnemonic=MNEMONIC)
    original = controller.storage.seeds
    controller.storage.seeds = [seed]
    fpr = seed.get_fingerprint()
    tools_views.BIP85_DATA.clear()
    tools_views.BIP85_DATA["X"] = {
        "primary_fpr": "X",
        "seed_fpr": fpr,
        "index": 1,
        "key_type": "ECC NIST P-256",
        "ss_version": Controller.VERSION,
        "uids": ["Other <o@b.com>", "Primary <a@b.com>"],
        "primary_uid": "Primary <a@b.com>",
        "subkeys": [
            {"index": 0, "type": "ECDH ECC NIST P-256", "fingerprint": "F0"},
            {"index": 1, "type": "ECDSA ECC NIST P-256", "fingerprint": "F1"},
            {"index": 2, "type": "ECDSA ECC NIST P-256", "fingerprint": "F2"},
            {"index": 3, "type": "RSA 2048", "fingerprint": "F3"},
            {"index": 4, "type": "RSA 2048", "fingerprint": "F4"},
            {"index": 5, "type": "RSA 2048", "fingerprint": "F5"},
        ],
        "revocations": [],
    }
    # round-trip export/import
    data_json = tools_views.bip85_export_json()
    tools_views.BIP85_DATA.clear()
    tools_views.bip85_import_json(data_json)

    captured = {}

    def fake_run_screen(self, *args, **kwargs):
        if args[0].__name__ == "ButtonListScreen":
            captured["labels"] = [b.button_label for b in kwargs["button_data"]]
            return 0
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(
        gpg_views.ToolsGPGRebuildBip85KeyView, "run_screen", fake_run_screen
    )

    def fake_run(cmd, input=None, capture_output=False):
        captured["cmd"] = cmd
        class Result:
            returncode = 0
        return Result()

    monkeypatch.setattr(gpg_views.subprocess, "run", fake_run)

    added = []
    import pgpy

    real_add_uid = pgpy.PGPKey.add_uid

    def fake_add_uid(self, uid, selfsign=True, **prefs):
        label = uid.name
        if uid.email:
            label += f" <{uid.email}>"
        added.append((label, prefs.get("primary", False)))
        if len(self._uids) == 0:
            return real_add_uid(self, uid, selfsign=selfsign, **prefs)
        return None

    monkeypatch.setattr(pgpy.PGPKey, "add_uid", fake_add_uid)

    calls = []
    real = gpg_views.bip85_p256_from_root

    def fake_p256(root, key_index, sub_index=None, alg=None, version=None):
        calls.append(("p256", key_index, sub_index, alg))
        return real(root, key_index, sub_index, alg, version)

    monkeypatch.setattr(gpg_views, "bip85_p256_from_root", fake_p256)

    rsa_calls = []
    real_rsa = gpg_views.bip85_rsa_from_root

    def fake_rsa(root, bits, key_index, sub_index=None, version=None):
        rsa_calls.append((bits, key_index, sub_index))
        return real_rsa(root, bits, key_index, sub_index, version)

    monkeypatch.setattr(gpg_views, "bip85_rsa_from_root", fake_rsa)

    verify_called = {}

    def fake_verify(seed, fingerprint, key_index, created_ts, primary_algo, primary_bits, primary_curve, subkeys, version=None):
        verify_called["subkeys"] = subkeys
        return True

    monkeypatch.setattr(gpg_views, "bip85_verify_existing", fake_verify)

    view = gpg_views.ToolsGPGRebuildBip85KeyView()
    try:
        view.run()
    finally:
        controller.storage.seeds = original

    assert captured["cmd"] == ["gpg", "--batch", "--import"]
    expected = [
        ("p256", 1, None, None),
        ("p256", 0, 0, "ECDH"),
        ("p256", 0, 1, "ECDSA"),
        ("p256", 0, 2, "ECDSA"),
    ]
    assert calls == expected
    assert rsa_calls == [(2048, 1, 0), (2048, 1, 1), (2048, 1, 2)]
    assert verify_called["subkeys"] == [
        {"idx": 1, "algo": "18", "bits": "", "curve": "nistp256", "fpr": "F0"},
        {"idx": 2, "algo": "19", "bits": "", "curve": "nistp256", "fpr": "F1"},
        {"idx": 3, "algo": "19", "bits": "", "curve": "nistp256", "fpr": "F2"},
        {"idx": 4, "algo": "1", "bits": "2048", "curve": "", "fpr": "F3"},
        {"idx": 5, "algo": "1", "bits": "2048", "curve": "", "fpr": "F4"},
        {"idx": 6, "algo": "1", "bits": "2048", "curve": "", "fpr": "F5"},
    ]
    assert added == [
        ("Primary <a@b.com>", True),
        ("Other <o@b.com>", False),
    ]


def test_bip85_subkey_specs_include_sign_for_auth():
    from pgpy.constants import KeyFlags

    specs = _bip85_subkey_specs("ed25519")
    auth_flags = specs[1][2]
    assert KeyFlags.Authentication in auth_flags
    assert KeyFlags.Sign in auth_flags


def test_bip85_subkey_specs_aliases():
    assert _bip85_subkey_specs("p256") == _bip85_subkey_specs("nistp256")
    assert _bip85_subkey_specs("brainpoolP256r1") == _bip85_subkey_specs(
        "brainpoolp256r1"
    )


def test_select_import_algo_uses_selected_subkeys():
    subkeys = [
        {"fpr": "A", "algo": "1", "curve": ""},
        {"fpr": "B", "algo": "19", "curve": "nistp256"},
    ]
    algo, curve = _select_import_algo("1", "", subkeys, ["B"])
    assert algo == "19" and curve == "nistp256"


def test_select_import_algo_mixed_types_error():
    subkeys = [
        {"fpr": "A", "algo": "1", "curve": ""},
        {"fpr": "B", "algo": "19", "curve": "nistp256"},
    ]
    with pytest.raises(ValueError):
        _select_import_algo("1", "", subkeys, ["A", "B"])


def test_gpg_quick_addkey_uses_loopback(monkeypatch):
    from seedsigner.views import tools_views

    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd

        class Dummy:
            returncode = 0

        return Dummy()

    monkeypatch.setattr(tools_views.subprocess, "run", fake_run)
    tools_views.gpg_quick_addkey("FPR", "rsa2048", "encrypt")
    assert captured["cmd"][:6] == [
        "gpg",
        "--batch",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
    ]
    assert captured["cmd"][6:] == [
        "--quick-addkey",
        "FPR",
        "rsa2048",
        "encrypt",
    ]


def test_gpg_edit_subkey_invokes_edit(monkeypatch):
    from seedsigner.views import tools_views

    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = kwargs.get("input")
        class Dummy:
            returncode = 0
        return Dummy()

    monkeypatch.setattr(tools_views.subprocess, "run", fake_run)
    tools_views.gpg_edit_subkey("FPR", 2, "revkey")
    assert captured["cmd"] == [
        "gpg",
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--command-fd",
        "0",
        "--status-fd",
        "2",
        "--edit-key",
        "FPR",
    ]
    assert (
        captured["input"]
        == "key 2\nrevkey\ny\n0\n\ny\nsave\n"
    )


def test_loose_add_subkeys_uses_pgpy(monkeypatch):
    from types import SimpleNamespace
    from seedsigner.views import tools_views

    new_calls = []
    state = {"add": 0, "unlock": 0}

    def fake_new(pkalg, curve):
        new_calls.append((pkalg, curve))
        return SimpleNamespace(_key=SimpleNamespace(created=None, update_hlen=lambda: None))

    from contextlib import contextmanager

    class MainKey:
        def __init__(self):
            self._key = SimpleNamespace(created=None)
            self.expires_at = None
            self.is_protected = True

        def unlock(self, passphrase):
            state["unlock"] += 1

            @contextmanager
            def cm():
                yield

            return cm()

        def add_subkey(self, subkey, **kwargs):
            state["add"] += 1

    def fake_from_blob(data):
        return MainKey(), None

    import pgpy

    monkeypatch.setattr(
        pgpy,
        "PGPKey",
        SimpleNamespace(new=fake_new, from_blob=fake_from_blob),
    )

    def fake_run(cmd, *args, **kwargs):
        class R:
            returncode = 0
            stdout = ""

        return R()

    monkeypatch.setattr("seedsigner.views.tools_views.subprocess.run", fake_run)

    assert tools_views.loose_add_subkeys("FPR", "secp256k1")
    assert len(new_calls) == 3
    assert state["add"] == 3
    assert state["unlock"] == 1


def test_gpg_export_selected_subkeys_filters(monkeypatch):
    from seedsigner.views import tools_views

    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        class R:
            returncode = 0
            stdout = "data"

        return R()

    monkeypatch.setattr(tools_views.subprocess, "run", fake_run)
    tools_views.gpg_export_selected_subkeys("FPR", ["A" * 40, "B" * 40, "C" * 40])
    cmd = captured["cmd"]
    assert cmd == [
        "gpg",
        "--armor",
        "--export-options=export-minimal",
        "--export-secret-subkeys",
        "FPR",
        "AAAAAAAAAAAAAAAA!",
        "BBBBBBBBBBBBBBBB!",
        "CCCCCCCCCCCCCCCC!",
    ]


def test_add_subkeys_auto_bip85_index(monkeypatch):
    from seedsigner.views import gpg_views

    # Mock gpg list outputs: first call lists one BIP85 key, second shows three subkeys
    def fake_run(cmd, *args, **kwargs):
        class R:
            returncode = 0

            def __init__(self, stdout=""):
                self.stdout = stdout

        if cmd[:3] == ["gpg", "--list-secret-keys", "--with-colons"]:
            if len(cmd) == 3:
                return R(
                    "sec:-:0:0:KEYID:0:0:::::::\n"
                    f"fpr:::::::::FPR:\n"
                    f"uid:u::::{gpg_views.BIP85_GPG_CREATED_TS}::H::User::::::::\n"
                )
            else:
                return R(
                    "sec:-:0:0:KEYID:0:::::::\n" + "ssb:-:0:0:::0:::::::\n" * 3
                )
        return R()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)

    gpg_views.BIP85_DATA["FPR"] = {
        "primary_fpr": "FPR",
        "seed_fpr": "seedfpr",
        "index": 0,
        "key_type": "ECC NIST P-256",
        "ss_version": Controller.VERSION,
        "uids": ["User"],
        "primary_uid": "User",
        "subkeys": [
            {"index": 0, "type": "ECDH ECC NIST P-256", "fingerprint": "A"},
            {"index": 1, "type": "ECDSA ECC NIST P-256", "fingerprint": "B"},
            {"index": 2, "type": "ECDSA ECC NIST P-256", "fingerprint": "C"},
        ],
        "revocations": [],
    }

    captured = {}

    def fake_bip85_add_subkeys(fpr, alg, key_index, start_index, seed, version=None):
        captured["key_index"] = key_index
        captured["start_index"] = start_index
        captured["seed"] = seed
        return []

    monkeypatch.setattr(gpg_views, "bip85_add_subkeys", fake_bip85_add_subkeys)

    def fake_verify(seed, fingerprint, key_index, created_ts, primary_algo, primary_bits, primary_curve, subkeys, version=None):
        captured["verified_seed"] = seed
        captured["verified_key_index"] = key_index
        return True

    monkeypatch.setattr(gpg_views, "bip85_verify_existing", fake_verify)

    class DummyLoading:
        def __init__(self, text=""):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(
        "seedsigner.gui.screens.screen.LoadingScreenThread", DummyLoading
    )

    class SeedObj:
        seed_bytes = b"\x00" * 64
        def get_fingerprint(self, network=None):
            return "seedfpr"

    seed_obj = SeedObj()

    # Simulate selecting the only key and ECC NIST P-256 type
    def fake_run_screen(self, screen, **kwargs):
        assert kwargs.get("text") != "Choose seed for BIP85 subkeys"
        if kwargs.get("title") == "Select Key":
            return 0
        if kwargs.get("title") == "Key Type":
            return 0
        return 0

    monkeypatch.setattr(gpg_views.ToolsGPGAddSubkeysView, "run_screen", fake_run_screen)

    view = object.__new__(gpg_views.ToolsGPGAddSubkeysView)
    ControllerClass = type(
        "C",
        (),
        {
            "storage": type("S", (), {"seeds": [seed_obj]})(),
            "get_seed": lambda self, idx: seed_obj,
        },
    )
    view.controller = ControllerClass()
    view.settings = type("Set", (), {"get_value": lambda self, x: None})()
    gpg_views.ToolsGPGAddSubkeysView.run(view)
    assert captured["key_index"] == 1
    assert captured["start_index"] == 3
    assert captured["seed"] is seed_obj
    assert captured["verified_seed"] is seed_obj
    assert captured["verified_key_index"] == 0


def test_add_subkeys_registry_index_correction(monkeypatch):
    from seedsigner.views import gpg_views

    class R:
        def __init__(self, stdout=""):
            self.stdout = stdout

    def fake_run(cmd, capture_output=True, text=True):
        if cmd[:3] == ["gpg", "--list-secret-keys", "--with-colons"]:
            if len(cmd) == 3:
                return R(
                    "sec:-:0:0:KEYID:0:0:::::::\n"
                    f"fpr:::::::::FPR:\n"
                    f"uid:u::::{gpg_views.BIP85_GPG_CREATED_TS}::H::User::::::::\n"
                )
            return R(
                "sec:-:0:0:KEYID:0:::::::\n" + "ssb:-:0:0:::0:::::::\n" * 3
            )
        return R()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)

    gpg_views.BIP85_DATA["FPR"] = {
        "primary_fpr": "FPR",
        "seed_fpr": "seedfpr",
        "index": 1,
        "key_type": "ECC NIST P-256",
        "ss_version": Controller.VERSION,
        "uids": ["User"],
        "primary_uid": "User",
        "subkeys": [],
        "revocations": [],
    }

    calls = []

    def fake_bip85_add_subkeys(fpr, alg, key_index, start_index, seed, version=None):
        calls.append(("add", key_index, start_index))
        return []

    monkeypatch.setattr(gpg_views, "bip85_add_subkeys", fake_bip85_add_subkeys)

    def fake_verify(seed, fingerprint, key_index, created_ts, primary_algo, primary_bits, primary_curve, subkeys, version=None):
        calls.append(("verify", key_index))
        return key_index == 0

    monkeypatch.setattr(gpg_views, "bip85_verify_existing", fake_verify)

    class DummyLoading:
        def __init__(self, text=""):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(
        "seedsigner.gui.screens.screen.LoadingScreenThread", DummyLoading
    )

    class SeedObj:
        seed_bytes = b"\x00" * 64
        def get_fingerprint(self, network=None):
            return "seedfpr"

    seed_obj = SeedObj()

    def fake_run_screen(self, screen, **kwargs):
        assert kwargs.get("text") != "Choose seed for BIP85 subkeys"
        if kwargs.get("title") == "Select Key":
            return 0
        if kwargs.get("title") == "Key Type":
            return 0
        return 0

    monkeypatch.setattr(gpg_views.ToolsGPGAddSubkeysView, "run_screen", fake_run_screen)

    view = object.__new__(gpg_views.ToolsGPGAddSubkeysView)
    ControllerClass = type(
        "C",
        (),
        {
            "storage": type("S", (), {"seeds": [seed_obj]})(),
            "get_seed": lambda self, idx: seed_obj,
        },
    )
    view.controller = ControllerClass()
    view.settings = type("Set", (), {"get_value": lambda self, x: None})()
    gpg_views.ToolsGPGAddSubkeysView.run(view)

    assert calls[0] == ("verify", 1)
    assert calls[1] == ("verify", 0)
    assert calls[2] == ("add", 1, 3)
    assert gpg_views.BIP85_DATA["FPR"]["index"] == 0


def test_add_subkeys_missing_seed(monkeypatch):
    from seedsigner.views import gpg_views

    class R:
        def __init__(self, stdout=""):
            self.stdout = stdout

    def fake_run(cmd, capture_output=True, text=True):
        if cmd[:3] == ["gpg", "--list-secret-keys", "--with-colons"]:
            if len(cmd) == 3:
                return R(
                    "sec:-:0:0:KEYID:0:0:::::::\n"
                    + f"fpr:::::::::FPR:\n"
                    + f"uid:u::::{gpg_views.BIP85_GPG_CREATED_TS}::H::User::::::::\n"
                )
            return R(
                    "sec:-:0:0:KEYID:0:::::::\n" + "ssb:-:0:0:::0:::::::\n" * 3
            )
        return R()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)

    gpg_views.BIP85_DATA["FPR"] = {
        "primary_fpr": "FPR",
        "seed_fpr": "seedfpr",
        "index": 0,
        "key_type": "ECC NIST P-256",
        "ss_version": Controller.VERSION,
        "uids": ["User"],
        "primary_uid": "User",
        "subkeys": [
            {"index": 0, "type": "ECDH ECC NIST P-256", "fingerprint": "A"},
            {"index": 1, "type": "ECDSA ECC NIST P-256", "fingerprint": "B"},
            {"index": 2, "type": "ECDSA ECC NIST P-256", "fingerprint": "C"},
        ],
        "revocations": [],
    }

    called = {"add": False, "warning": None}

    def fake_bip85_add_subkeys(*args, **kwargs):
        called["add"] = True
        return []

    monkeypatch.setattr(gpg_views, "bip85_add_subkeys", fake_bip85_add_subkeys)

    class SeedObj:
        def get_fingerprint(self, network=None):
            return "other"

    seed_obj = SeedObj()

    def fake_run_screen(self, screen, **kwargs):
        if kwargs.get("title") == "Select Key":
            return 0
        if kwargs.get("title") == "Key Type":
            return 0
        if kwargs.get("text") == "Required seed not loaded":
            called["warning"] = kwargs.get("text")
            return 0
        assert kwargs.get("text") != "Choose seed for BIP85 subkeys"
        return 0

    monkeypatch.setattr(tools_views.ToolsGPGAddSubkeysView, "run_screen", fake_run_screen)

    view = object.__new__(tools_views.ToolsGPGAddSubkeysView)
    ControllerClass = type(
        "C",
        (),
        {
            "storage": type("S", (), {"seeds": [seed_obj]})(),
        },
    )
    view.controller = ControllerClass()
    view.settings = type("Set", (), {"get_value": lambda self, x: None})()
    tools_views.ToolsGPGAddSubkeysView.run(view)
    assert not called["add"]
    assert called["warning"] == "Required seed not loaded"


def test_delete_subkeys_bip85_only_latest(monkeypatch):
    import subprocess
    from seedsigner.views import tools_views

    ts = tools_views.BIP85_GPG_CREATED_TS

    def fake_run(cmd, *args, **kwargs):
        class R:
            returncode = 0

            def __init__(self, stdout=""):
                self.stdout = stdout

        if cmd[:3] == ["gpg", "--list-secret-keys", "--with-colons"]:
            if len(cmd) == 3:
                return R(
                    f"sec:-:0:0:KEYID:0:0:::::::\n"
                    f"fpr:::::::::FPR:\n"
                    f"uid:u::::{ts}::H::User::::::::\n"
                )
            return R(
                "sec:-:0:0:KEYID:0:::::::\n"
                f"ssb:-:0:0::{ts}::::::e:::::\n"
                "fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n"
                f"ssb:-:0:0::{ts}::::::s:::::\n"
                "fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:\n"
                f"ssb:-:0:0::{ts}::::::e:::::\n"
                "fpr:::::::::CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:\n"
            )
        return R()

    tools_views.BIP85_DATA["FPR"] = {
        "primary_fpr": "FPR",
        "seed_fpr": "seedfpr",
        "index": 0,
        "key_type": "ECC NIST P-256",
        "ss_version": Controller.VERSION,
        "uids": ["User"],
        "primary_uid": "User",
        "subkeys": [
            {
                "index": 0,
                "type": "ECDH ECC NIST P-256",
                "fingerprint": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
            {
                "index": 1,
                "type": "ECDSA ECC NIST P-256",
                "fingerprint": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            },
            {
                "index": 2,
                "type": "ECDSA ECC NIST P-256",
                "fingerprint": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            },
        ],
        "revocations": [],
    }

    monkeypatch.setattr(subprocess, "run", fake_run)

    captured = {}

    def fake_run_screen(self, screen, **kwargs):
        if kwargs.get("title") == "WARNING":
            return 0
        if kwargs.get("title") == "Select Key":
            return 0
        if kwargs.get("title") == "Delete Subkeys":
            captured["labels"] = [b.button_label for b in kwargs["button_data"]]
            return RET_CODE__BACK_BUTTON
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(tools_views.ToolsGPGDeleteSubkeysView, "run_screen", fake_run_screen)

    view = object.__new__(tools_views.ToolsGPGDeleteSubkeysView)
    tools_views.ToolsGPGDeleteSubkeysView.run(view)

    assert captured["labels"] == ["CCCCCCCC [e]", "Done"]


def test_delete_subkeys_non_bip85_lists_all(monkeypatch):
    import subprocess
    from seedsigner.views import tools_views

    tools_views.BIP85_DATA.clear()

    def fake_run(cmd, *args, **kwargs):
        class R:
            returncode = 0

            def __init__(self, stdout=""):
                self.stdout = stdout

        if cmd[:3] == ["gpg", "--list-secret-keys", "--with-colons"]:
            if len(cmd) == 3:
                return R(
                    "sec:-:0:0:KEYID:0:0:::::::\n"
                    "fpr:::::::::FPR:\n"
                    "uid:u::::0::H::User::::::::\n"
                )
            return R(
                "sec:-:0:0:KEYID:0:::::::\n"
                "ssb:-:0:0::1::::::e:::::\n"
                "fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n"
                "ssb:-:0:0::2::::::s:::::\n"
                "fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:\n"
                "ssb:-:0:0::3::::::e:::::\n"
                "fpr:::::::::CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:\n"
            )
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)

    captured = {}

    def fake_run_screen(self, screen, **kwargs):
        if kwargs.get("title") == "WARNING":
            return 0
        if kwargs.get("title") == "Select Key":
            return 0
        if kwargs.get("title") == "Delete Subkeys":
            captured["labels"] = [b.button_label for b in kwargs["button_data"]]
            return RET_CODE__BACK_BUTTON
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(tools_views.ToolsGPGDeleteSubkeysView, "run_screen", fake_run_screen)

    view = object.__new__(tools_views.ToolsGPGDeleteSubkeysView)
    tools_views.ToolsGPGDeleteSubkeysView.run(view)

    assert captured["labels"] == [
        "AAAAAAAA [e]",
        "BBBBBBBB [s]",
        "CCCCCCCC [e]",
        "Done",
    ]


def test_smartpgp_import_filters_subkeys(monkeypatch):
    import types, sys, datetime as dt
    from pgpy.constants import KeyFlags, EllipticCurveOID

    # Stub out the smartcard modules to avoid dependency on actual hardware libs
    sc = types.ModuleType("smartcard")
    sc_exc = types.ModuleType("smartcard.Exceptions")
    class NoCardException(Exception):
        pass
    sc_exc.NoCardException = NoCardException
    sc_sys = types.ModuleType("smartcard.System")
    sc_sys.readers = lambda: []
    sc_util = types.ModuleType("smartcard.util")
    sc_util.toHexString = lambda data: ""
    sc.Exceptions = sc_exc
    sc.System = sc_sys
    sc.util = sc_util
    sys.modules.update({
        "smartcard": sc,
        "smartcard.Exceptions": sc_exc,
        "smartcard.System": sc_sys,
        "smartcard.util": sc_util,
    })

    from seedsigner.helpers import smartpgp_import

    captured = {}

    def fake_run(cmd, capture_output=True, check=True):
        captured["cmd"] = cmd
        class Res:
            stdout = b"dummy"
        return Res()

    monkeypatch.setattr(smartpgp_import, "run", fake_run)

    sk_fpr = "F" * 40

    class KM:
        oid = EllipticCurveOID.NIST_P256
        s = 1
        class P:
            x = 1
            y = 1
        p = P()

    class Sub:
        def __init__(self):
            self.key_flags = {KeyFlags.Sign}
            self.fingerprint = sk_fpr
            self.created = dt.datetime(2020, 1, 1)
            self._key = type("K", (), {"keymaterial": KM})()

    class Key:
        def __init__(self):
            self.subkeys = {"a": Sub()}

    monkeypatch.setattr(smartpgp_import.pgpy.PGPKey, "from_blob", lambda data: (Key(), None))

    class DummyCtx:
        def __init__(self):
            self.admin_pin = None
        def connect(self):
            pass
        def verify_admin_pin(self):
            pass
        def cmd_switch_crypto(self, curve, role):
            pass
        def cmd_put_key(self, role, pub=None, priv=None, *, components=None):
            pass
        def cmd_put_data(self, tag, value):
            pass

    ctx_calls = {}
    class Ctx(DummyCtx):
        def cmd_put_key(self, role, pub=None, priv=None, *, components=None):
            ctx_calls["role"] = role
    monkeypatch.setattr(smartpgp_import, "CardConnectionContext", lambda: Ctx())

    assert smartpgp_import.import_keys_with_smartpgp("PRIFPR", "1234", {"s": sk_fpr})
    cmd = captured["cmd"]
    assert "--export-secret-subkeys" in cmd
    assert "--export-secret-key" not in cmd
    assert cmd[-1] == "FFFFFFFFFFFFFFFF!"
    assert ctx_calls["role"] == "sig"


def test_smartpgp_import_bad_admin_pin(monkeypatch):
    import types, sys, datetime as dt
    from pgpy.constants import KeyFlags, EllipticCurveOID
    import pytest

    sc = types.ModuleType("smartcard")
    sc_exc = types.ModuleType("smartcard.Exceptions")
    class NoCardException(Exception):
        pass
    sc_exc.NoCardException = NoCardException
    sc_sys = types.ModuleType("smartcard.System")
    sc_sys.readers = lambda: []
    sc_util = types.ModuleType("smartcard.util")
    sc_util.toHexString = lambda data: ""
    sc.Exceptions = sc_exc
    sc.System = sc_sys
    sc.util = sc_util
    sys.modules.update({
        "smartcard": sc,
        "smartcard.Exceptions": sc_exc,
        "smartcard.System": sc_sys,
        "smartcard.util": sc_util,
    })

    from seedsigner.helpers import smartpgp_import

    def fake_run(cmd, capture_output=True, check=True):
        class Res:
            stdout = b"dummy"
        return Res()

    monkeypatch.setattr(smartpgp_import, "run", fake_run)

    sk_fpr = "F" * 40

    class KM:
        oid = EllipticCurveOID.NIST_P256
        s = 1
        class P:
            x = 1
            y = 1
        p = P()

    class Sub:
        def __init__(self):
            self.key_flags = {KeyFlags.Sign}
            self.fingerprint = sk_fpr
            self.created = dt.datetime(2020, 1, 1)
            self._key = type("K", (), {"keymaterial": KM})()

    class Key:
        def __init__(self):
            self.subkeys = {"a": Sub()}

    monkeypatch.setattr(smartpgp_import.pgpy.PGPKey, "from_blob", lambda data: (Key(), None))

    class BadCtx:
        def __init__(self):
            self.admin_pin = None
        def connect(self):
            pass
        def verify_admin_pin(self):
            raise smartpgp_import.AdminPINFailed

    monkeypatch.setattr(smartpgp_import, "CardConnectionContext", lambda: BadCtx())

    with pytest.raises(smartpgp_import.SmartPGPAdminPinError):
        smartpgp_import.import_keys_with_smartpgp("PRIFPR", "badpin", {"s": sk_fpr})


def test_import_key_to_card_view_reports_bad_admin_pin(monkeypatch):
    import subprocess
    from types import MethodType, SimpleNamespace

    from seedsigner.helpers.smartpgp.highlevel import AdminPINFailed

    sec_parts = [
        "sec",
        "",
        "256",
        "22",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "sca",
        "",
        "",
        "",
        "",
        "nistp256",
    ]
    sub_parts = [
        "ssb",
        "",
        "256",
        "22",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "sea",
        "",
        "",
        "",
        "",
        "nistp256",
    ]
    fpr_primary = ["fpr", "", "", "", "", "", "", "", "", "PRIMARYFPR"]
    fpr_sub = ["fpr", "", "", "", "", "", "", "", "", "SUBFPR"]
    gpg_list_output = "\n".join(
        ":".join(parts)
        for parts in (sec_parts, fpr_primary, sub_parts, fpr_sub)
    )

    class DummyResult:
        def __init__(self, stdout="", stderr="", returncode=0):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    def fake_run(cmd, *args, **kwargs):
        cmd_tuple = tuple(cmd)
        if len(cmd_tuple) >= 3 and cmd_tuple[0] == "gpgconf" and cmd_tuple[2] == "scdaemon":
            return DummyResult()
        if len(cmd_tuple) >= 2 and cmd_tuple[0] == "gpg" and cmd_tuple[1] == "--card-status":
            return DummyResult(stdout="", stderr="", returncode=0)
        if "--list-secret-keys" in cmd:
            return DummyResult(stdout=gpg_list_output, stderr="", returncode=0)
        return DummyResult()

    monkeypatch.setattr(subprocess, "run", fake_run)
    disconnect_calls = []

    def fake_disconnect(controller):
        disconnect_calls.append(controller)

    monkeypatch.setattr(
        tools_views.seedkeeper_utils,
        "disconnect_smartcard_connections",
        fake_disconnect,
    )

    class RejectingCtx:
        def __init__(self):
            self.admin_pin = None

        def connect(self):
            pass

        def verify_admin_pin(self):
            raise AdminPINFailed()

    monkeypatch.setattr(
        "seedsigner.helpers.smartpgp.highlevel.CardConnectionContext",
        RejectingCtx,
    )

    view = object.__new__(tools_views.ToolsGPGImportKeyToCardView)
    view.fingerprint = "PRIMARYFPR"
    view.selected_subkeys = ["SUBFPR"]
    view.controller = SimpleNamespace(GPG_Admin_PIN="badpin", Satochip_Connector=None)
    view.loading_screen = None

    captured = {}

    def fake_run_screen(self, screen_cls, **kwargs):
        captured["screen"] = screen_cls
        captured["kwargs"] = kwargs
        return 0

    view.run_screen = MethodType(fake_run_screen, view)

    result = tools_views.ToolsGPGImportKeyToCardView.run(view)

    assert isinstance(result, tools_views.Destination)
    assert result.View_cls is tools_views.BackStackView
    assert captured["kwargs"]["text"] == "Incorrect admin PIN"
    assert view.controller.GPG_Admin_PIN is None
    assert disconnect_calls
    assert disconnect_calls[-1] is view.controller


def test_import_key_to_card_view_fallback_bad_admin_pin(monkeypatch):
    import subprocess
    from types import MethodType, SimpleNamespace

    from seedsigner.helpers import seedkeeper_utils, smartpgp_import
    from seedsigner.views import gpg_views

    sec_parts = [
        "sec",
        "",
        "3072",
        "1",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "sca",
        "",
        "",
        "",
        "",
        "",
    ]
    sub_parts = [
        "ssb",
        "",
        "3072",
        "1",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "sea",
        "",
        "",
        "",
        "",
        "",
    ]
    fpr_primary = ["fpr", "", "", "", "", "", "", "", "", "PRIMARYFPR"]
    fpr_sub = ["fpr", "", "", "", "", "", "", "", "", "SUBFPR"]
    gpg_list_output = "\n".join(
        ":".join(parts)
        for parts in (sec_parts, fpr_primary, sub_parts, fpr_sub)
    )

    class DummyResult:
        def __init__(self, stdout="", stderr="", returncode=0):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    def fake_run(cmd, *args, capture_output=True, text=True, input=None, **kwargs):
        cmd_tuple = tuple(cmd)
        if len(cmd_tuple) >= 3 and cmd_tuple[0] == "gpgconf" and cmd_tuple[2] == "scdaemon":
            return DummyResult()
        if len(cmd_tuple) >= 2 and cmd_tuple[0] == "gpg" and cmd_tuple[1] == "--card-status":
            return DummyResult(stdout="", stderr="", returncode=0)
        if "--list-secret-keys" in cmd:
            return DummyResult(stdout=gpg_list_output, stderr="", returncode=0)
        if "--edit-key" in cmd:
            return DummyResult(stdout="", stderr="Bad PIN", returncode=2)
        return DummyResult()

    monkeypatch.setattr(subprocess, "run", fake_run)

    disconnect_calls = []

    def fake_disconnect(controller):
        disconnect_calls.append(controller)

    monkeypatch.setattr(
        seedkeeper_utils,
        "disconnect_smartcard_connections",
        fake_disconnect,
    )

    def raising_import(*args, **kwargs):
        raise smartpgp_import.SmartPGPAdminPinError()

    monkeypatch.setattr(
        smartpgp_import,
        "import_keys_with_smartpgp",
        raising_import,
    )

    view = object.__new__(gpg_views.ToolsGPGImportKeyToCardView)
    view.fingerprint = "PRIMARYFPR"
    view.selected_subkeys = {"s": "SUBFPR"}
    view.controller = SimpleNamespace(GPG_Admin_PIN="badpin", Satochip_Connector=None)
    view.loading_screen = None

    captured = {}

    def fake_run_screen(self, screen_cls, **kwargs):
        captured["text"] = kwargs.get("text")
        return 0

    view.run_screen = MethodType(fake_run_screen, view)

    result = gpg_views.ToolsGPGImportKeyToCardView.run(view)

    assert isinstance(result, gpg_views.Destination)
    assert result.View_cls is gpg_views.BackStackView
    assert captured.get("text") == "Incorrect admin PIN"
    assert view.controller.GPG_Admin_PIN is None
    assert len(disconnect_calls) >= 2
    assert disconnect_calls[-1] is view.controller


def test_smartpgp_import_rsa_sets_key_type(monkeypatch):
    import types, sys, datetime as dt
    import pgpy
    from pgpy.constants import KeyFlags, PubKeyAlgorithm

    sc = types.ModuleType("smartcard")
    sc_exc = types.ModuleType("smartcard.Exceptions")
    class NoCardException(Exception):
        pass
    sc_exc.NoCardException = NoCardException
    sc_sys = types.ModuleType("smartcard.System")
    sc_sys.readers = lambda: []
    sc_util = types.ModuleType("smartcard.util")
    sc_util.toHexString = lambda data: ""
    sc.Exceptions = sc_exc
    sc.System = sc_sys
    sc.util = sc_util
    sys.modules.update({
        "smartcard": sc,
        "smartcard.Exceptions": sc_exc,
        "smartcard.System": sc_sys,
        "smartcard.util": sc_util,
    })

    from seedsigner.helpers import smartpgp_import

    captured = {}

    def fake_run(cmd, capture_output=True, check=True):
        captured["cmd"] = cmd
        class Res:
            stdout = b"dummy"
        return Res()

    monkeypatch.setattr(smartpgp_import, "run", fake_run)

    rsa_key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    rsa_key.add_uid(pgpy.PGPUID.new("Test"), usage={KeyFlags.Sign})
    km = rsa_key._key.keymaterial

    sk_fpr = "A" * 40

    class Sub:
        def __init__(self):
            self.key_flags = {KeyFlags.Sign}
            self.fingerprint = sk_fpr
            self.created = dt.datetime(2020, 1, 1)
            self._key = type("K", (), {"keymaterial": km})()

    class Key:
        def __init__(self):
            self.subkeys = {"s": Sub()}

    monkeypatch.setattr(smartpgp_import.pgpy.PGPKey, "from_blob", lambda data: (Key(), None))

    class DummyCtx:
        def __init__(self):
            self.admin_pin = None
            self.switch_calls = []
            self.put_calls = []
        def connect(self):
            pass
        def verify_admin_pin(self):
            pass
        def cmd_switch_crypto(self, alg, role):
            self.switch_calls.append((alg, role))
        def cmd_put_key(self, role, pub=None, priv=None, *, components=None):
            self.put_calls.append((role, components))
        def cmd_put_data(self, tag, value):
            pass

    ctx = DummyCtx()
    monkeypatch.setattr(smartpgp_import, "CardConnectionContext", lambda: ctx)

    assert smartpgp_import.import_keys_with_smartpgp("PRIFPR", "1234", {"s": sk_fpr})
    assert captured["cmd"][-1] == "AAAAAAAAAAAAAAAA!"
    assert ctx.switch_calls == [("rsa2048", "sig")]
    assert len(ctx.put_calls) == 1
    role, components = ctx.put_calls[0]
    assert role == "sig"
    tags = [tag for tag, _ in components]
    assert tags == [0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97]
    lengths = [len(bytes(comp)) for _, comp in components]
    assert lengths[0] == 3
    assert lengths[1] == lengths[2] == lengths[3] == lengths[4] == lengths[5]
    assert lengths[6] == lengths[1] * 2


# --- _normalize_date_input tests ---

@pytest.mark.parametrize("input_str,expected", [
    ("2035-12-31", "2035-12-31"),           # normal ASCII
    (" 2035-12-31 ", "2035-12-31"),         # leading/trailing whitespace
    ("2035-12-31\n", "2035-12-31"),         # trailing newline
    ("\t2035-12-31\t", "2035-12-31"),       # tabs
    ("2035\uff0d12\uff0d31", "2035-12-31"), # fullwidth hyphen
    ("2035\u201312\u201331", "2035-12-31"), # en-dash
    ("2035\u201412\u201431", "2035-12-31"), # em-dash
    ("2035\u221212\u221231", "2035-12-31"), # Unicode minus sign
    ("", ""),                                # empty string
    ("   ", ""),                              # whitespace-only
])
def test_normalize_date_input(input_str, expected):
    assert _normalize_date_input(input_str) == expected


@pytest.mark.parametrize("input_str", [
    "2035-12-31",
    " 2035-12-31 ",
    "2035-12-31\n",
    "2035\uff0d12\uff0d31",  # fullwidth hyphen
    "2035\u201312\u201331",  # en-dash
    "2035\u201412\u201431",  # em-dash
    "2035\u221212\u221231",  # Unicode minus sign
])
def test_normalize_date_input_parses_as_valid_date(input_str):
    from datetime import datetime
    normalized = _normalize_date_input(input_str)
    dt = datetime.strptime(normalized, "%Y-%m-%d")
    assert dt.year == 2035 and dt.month == 12 and dt.day == 31
