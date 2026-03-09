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

# BIP85 GPG RSA entropy vectors sourced from libwally-core's test suite:
# https://github.com/ElementsProject/libwally-core/blob/master/src/test/test_bip85.py
LIBWALLY_RSA_MASTER_XPRV = (
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
)
BIP85_GPG_RSA_VECTORS = [
    (
        "2b9380df43421f46b5c38e13ea80612ff53488bc5d272e86d493ee1eecf738bb7b50e4978b7352f95772f1211483b0e6bba86c544a946b10d76ed493b8c2e01f",
        1024,
        0,
    ),
    (
        "b34c06698228ce7a531dd292e76a4fbde1238659588e70714e1a7558a6df54e533034ba4d29ff42133db54af37520ba6724e3d3cd7e98329d6a0e4806e166bf0",
        1024,
        1,
    ),
    (
        "98c4fb6d76f203e8828bdfd28416edca7a83a9b203901f7ad31f056cda8b3c25b19e5fd2aa642ca0abb9ed8bebf3d141af6c76b28a19eba624bdc6f8a76ce138",
        2048,
        0,
    ),
    (
        "fad7641f55ce91a45a7ff36a7d8ebcac34b28778fd9f98abeba7afd24e0ff80ac9aaff7c8c728fbca5ebb893e0f7b9bce9b62f15c977044ad9cd05685044189e",
        2048,
        1,
    ),
    (
        "ed98d9cd1919fbcf73f5e3d2496b9bc43f869ffe5e27e6d55dc740eb9039ec545f084037e189ced93d0e71f70a3bcc0fa76560b98f685d2725b8345e1be50e01",
        3072,
        0,
    ),
    (
        "750caeee45c70b71a0297532a22e73f03a38bf226ffa95bc52969d98a586ee5913c7e9d9514d87455e6530c46d277ff67995a56e484bcefdcb662a1bb1d57d43",
        3072,
        1,
    ),
    (
        "2d2ef3335dc51e7a0642bfe86fba0bb4e8401b703d8d679bb1a31d75f8a81f1fd52b20b2eae50ef6e0378b8755f4f0426c68b54f11edc0c848e017e81bb2ad87",
        4096,
        0,
    ),
    (
        "02b18073332b3486f1ef0bad015bdbe695595b8b3ed5ea5b4d9e54b54670e7a8011dd69b888f5042f9ae8d9f658708f786314458ba0c0078339789c50f78085b",
        4096,
        1,
    ),
    (
        "c966fcf60d5ede0515ef2c51dbe300b1e67e448049fa1a63770a104f0d52ab173f9891a6345f9d0993452d7a0ba446ada5c69c8cd07a656829df9bb26f6ca29f",
        8192,
        0,
    ),
    (
        "b8f8456044ebc18a964ef05dae81d88c6f602823d8c0415a912ed58095244562f459781c142aa723bb29092b08ce22efc648e631c6b9fdb46ffad845c893a27f",
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
        entropy = bip85.derive_entropy(root, tools_views.BIP85_GPG_APP, [tools_views.BIP85_GPG_KEY_TYPE_RSA, bits, index])
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
        tools_views.BIP85_GPG_KEY_TYPE_CURVE25519,
        256,
        "0e90b553528cd97a033c282f54cf72c1020adaec205d5c0e57e9f2556d06fea6"
        "83618e4be8f91e7e059647f9d6373eb8b5f535e7ba4097cfb3e93c4957843614",
        "0e90b553528cd97a033c282f54cf72c1020adaec205d5c0e57e9f2556d06fea6",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_SECP256K1,
        256,
        "f3bb8b3d6b81fbd202c34b59ce7e97c83969e9b5733b936de16c51119c7a4823"
        "9ddf66729ef5e4df97ea39471f05a89f070869b3f9d72d69f3ae8bd7ee4fb6b3",
        "f3bb8b3d6b81fbd202c34b59ce7e97c83969e9b5733b936de16c51119c7a4823",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_NIST,
        256,
        "f52586f58521916b9f28b0058be86effcde82e571eabada9e3f63c6f67752ff1"
        "2a4d3bf2fffe0f147164945691605a58f28f6bded869c38b3db9f0e577d83728",
        "f52586f58521916b9f28b0058be86effcde82e571eabada9e3f63c6f67752ff1",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_NIST,
        384,
        "830005ea400f7a03c27aa06a9728fe311c9a48dc31bd417f07b96c69edc73d25"
        "baa00d04b9dbbe6f42539b06d9ef1ba62ed73d4a3a992302aae09e17e0d9f42f",
        "830005ea400f7a03c27aa06a9728fe311c9a48dc31bd417f07b96c69edc73d25"
        "baa00d04b9dbbe6f42539b06d9ef1ba6",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_NIST,
        521,
        "3524b3cbe60eb78a156dae44674702f69381afe5292d6d15d7801b7e530f2a06"
        "16b7b876c0ba85d6e675587fdc0ce2242ad00252493ec9c3a024217d1e2aa954",
        "a9b5a5af6b4c45ea509e838cb55a0043412b49781c54a68931395be4b27550b1"
        "c60b3aa7814c9ba4093c7c0b3f72b5e21856317b97eb156533b42e36ae8f2bf157",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_BRAINPOOL,
        256,
        "97ee4490d89bf257e9a038e2af12824fba47fec721970ca1fc1c094650d2716d"
        "75491402530776ba31d215fac6c2de0cb6661f1d380b682e20246bf962cdf385",
        "97ee4490d89bf257e9a038e2af12824fba47fec721970ca1fc1c094650d2716d",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_BRAINPOOL,
        384,
        "3fa833db4195fbd7a9c4e3f6fdb65ffb8951c5c65ca0cce441a4410e11aa96fc"
        "b094ed8c1fb5317448ae098ca9cae2c351b513e47d1b74e4c80c1facdf7b0a5a",
        "3fa833db4195fbd7a9c4e3f6fdb65ffb8951c5c65ca0cce441a4410e11aa96fc"
        "b094ed8c1fb5317448ae098ca9cae2c3",
    ),
    (
        tools_views.BIP85_GPG_KEY_TYPE_BRAINPOOL,
        512,
        "985f0131503109fc7fb2ab15e6a86846888e4b9a9f4f11f0d7b30dba4570cf8c"
        "c728a4c8ce9bbeb9b9819fbe924bb2d6d71a9c8332635cfb5db5008364f3a43a",
        "985f0131503109fc7fb2ab15e6a86846888e4b9a9f4f11f0d7b30dba4570cf8c"
        "c728a4c8ce9bbeb9b9819fbe924bb2d6d71a9c8332635cfb5db5008364f3a43a",
    ),
]

# Expected RSA-2048 n value for path m/83696968'/828365'/0'/2048'/0'
# generated via PyCryptodome RSA.generate(2048, randfunc=drng.read).
CROSS_IMPL_RSA2048_N = int(
    "c76c90074ba3f2e487c5d7714bdade9e1c6e4beafb3c1d1246ed9d0a5607a15d"
    "58608bc5aec96db6160920c8327487311bc9f799d9bb312e489e2296d3e93ceb"
    "322bf5d8ede6f989713e1ecc3b03ad146186aaba5af50656f3c29babb7b792da"
    "8e6e1ffc6521af425965faeb5c94bd18d1526d77d8b51f501d029fb59a26384b"
    "0269ddb36c79ee8764d0e2d09222eb9f9bfd0a7ae6be35f71e63743cdca8983e"
    "bd7e712b2b38c8ea84fcb950bd851b882642eb05a0578c346057d9eeb7fa3218"
    "eefcdb9b19aa11e8a1364e81de2a54940496a302c1958a99f6bf3b7b8154d0b4"
    "c800081a8311b5b4182ed3e057af0e1010232b2e04fdc1edf5cf37978ac75cb9",
    16,
)


def test_cross_impl_ecc_entropy_vectors():
    """Entropy values for ECC key types match reference vectors."""
    root = bip32.HDKey.from_string(CROSS_IMPL_XPRV)
    for key_type, key_bits, expected_entropy, _ in CROSS_IMPL_ECC_VECTORS:
        entropy = bip85.derive_entropy(
            root, tools_views.BIP85_GPG_APP, [key_type, key_bits, 0]
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
    entropy_mn = bip85.derive_entropy(root_from_mnemonic, tools_views.BIP85_GPG_APP, [0, 2048, 0])
    entropy_xp = bip85.derive_entropy(root_from_xprv, tools_views.BIP85_GPG_APP, [0, 2048, 0])
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
    key = bip85_rsa_from_root(root, 1024, 0)
    assert key.size_in_bits() == MIN_RSA_KEY_BITS
    assert key.n == int(
        "cf61fb06f3fea3d33e2671cf1f8c9878760864c63ae73e7c9b9f8a912740368a1fa4dc416a5d98e825ce08adcbc57eb3f6032079aea83da0bae61ac544a11c23ced82227cab51c2f72cf163c77ef77607fc2fb6e959a83baceb94d0a70fe8662d9d8180748e7240b2440ceb85240280ef1c83e19c19c9dc7bb8f5a60904a0a3cbf6fec290da4210900c07a52ef1c2380947bd373291aaafffd598fde0dd6b9ce6f24b70a4714092b16a377190e6b80f447412e7b0e9bece88a94c3a0f6854715947980de09d463343939733704679787f7622928c28bce92e11298cb54b87694284d50645e56cc51fb9411b026723adb05f68037d040e8448f7762507309a1c7",
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
        "b338ff5ea63036e2dea2cc9037f8c3147d47c539ced2a20ca5d979186e8269ea9ab538c584cbfa5171d34f79e9e5e33aaf6ed24e436b55d2dca362e50c11003c32a7293c78c54c0d89bddb0b4a97257fe619ac320af247d2f45cc59d6a5587e764419021abba5a10cc79c1a2b410da9e4d656731bcd48c3b3a2ead9824504cc8c751a688c3b3b9d7977c8f5b9b70c4b60eac295446a6c145dc2ca723d9ee557b2200737b4b5116467f8344b00a22a2954875b629e63fc27b17429041ccf95b4ae077d2cdd3227d32135d94e05130f404975a8bf7b4bbcfbbc1f9bcaa6886374e4899988d0c7b1d471906c210159543e07b297081e1ea6eca074e79558904a179eaa1c96e26a32c09a39df2c08eff672c7d9759768f657698dfd63621937056dcff02ac99ac8ebcc5dc5bff93fc5de20f768eb6660a9e755b1eb059b135c6dec968cda8877c362c7b97ce899403b2a43e7e2c86ca5355f371a8cd01582df8900d76159ef5a298fde9845378efd11798c7c2ee1f9450d7b1edc120c0c3a379913d",
        16,
    )


def test_bip85_secp256k1_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_secp256k1_from_root(root, 0)
    assert int(key.s) == int(
        "dd4eebe20675d3649e8f188a14a8832fb473cfcea029cf755fb4f7b715ea9d23", 16
    )


def test_bip85_p256_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_p256_from_root(root, 0)
    assert int(key.s) == int(
        "dc9b40d295b20fa87aa7414d5aa1db8b12bc850587fa0ed172f71ee620062114", 16
    )


def test_bip85_brainpoolp256r1_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_brainpoolp256r1_from_root(root, 0)
    assert int(key.s) == int(
        "904a67c2b20820d8bf98be62a24a2cddcd9674ecd0943bb5e10d7b50fd02806c", 16
    )


def test_bip85_ed25519_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_ed25519_from_root(root, 0)
    assert int(key.s) == int(
        "9c2c35e872ee9112ae0235c811c12b5187d8e4ce77c5b8595e1da0f787dc4caa", 16
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
        "61296e8ee7b08b639c56babb292a0bdaf352ceacd37b33c5a51a3da82d8d8434f7f42353fb8ec82e79599824889cb582", 16
    )


def test_bip85_p521_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_p521_from_root(root, 0)
    assert int(key.s) == int(
        "6700224442c326298a3fd6b3df9c4c05068a4c7df2bc3b2f3fee647d46355d34"
        "7905692be4b690c1ca19357f40dfa3f1f1c788a1ff55fa8c992873fabdf75f25c7", 16
    )


def test_bip85_brainpoolp384r1_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_brainpoolp384r1_from_root(root, 0)
    # This mnemonic's entropy exceeds the curve order, exercising the
    # out-of-range fallback: (d % (order - 1)) + 1.
    assert int(key.s) == int(
        "5ff15e7affe063458500ebe3cb883388cc0c01a395d59b2b198bb34ea0b8c95f8399ff0197c45bd1d8e7a09babb60f14", 16
    )


def test_bip85_brainpoolp512r1_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_brainpoolp512r1_from_root(root, 0)
    assert int(key.s) == int(
        "2b26f4734a1408d42ed2dcdb04415346da82db6c9bc62d972091f6136e7ded1a9317676f6924c6d05b506026eb04bcb444cfd3368c8a046765c517c50a862c4d", 16
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

    assert pgp_key.fingerprint == "BDC8DB33B793C02FC5E295B2CC44522B14B5A8B6"
    fingerprints = [str(sk.fingerprint).replace(" ", "") for sk in pgp_key.subkeys.values()]
    assert fingerprints == [
        "55C54A4B6382B313B4539C3B781215E4F91451F9",
        "55BDCFA487CCE02A07460F3ED2944F2EC019B5DF",
        "AC3DE112686C83BB26A4587DF18933B6CEE6D463",
        "49902AF8AE102DC986233CB6626F4106A6AB1355",
        "94D620C2FC7DD25BAEC027FA106DAD2E7177CFB7",
        "E3C9FEA1785D2A00CCAC373BB8AC66BF71D074F0",
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

    responses = iter([1])
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

    def fake_get_seed(idx):
        captured["idx"] = idx
        return controller.storage.seeds[idx]

    monkeypatch.setattr(controller, "get_seed", fake_get_seed)

    view = tools_views.ToolsGPGLoadBIP85KeyView()
    try:
        view.run()
    finally:
        controller.storage.seeds = original

    assert captured["idx"] == 1
    assert screens[0] == tools_views.seed_screens.SeedSelectSeedScreen
    assert WarningScreen not in screens
    assert captured["key_type_options"] == ["RSA 2048", "RSA 3072", "RSA 4096"]


def test_load_bip85_key_warning_when_ecc_enabled(monkeypatch):
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
    base_settings = view.settings

    class DummySettings:
        def __init__(self, base):
            self._base = base

        def get_value(self, attr_name):
            if attr_name == SettingsConstants.SETTING__BIP85_ECC_KEYS:
                return SettingsConstants.OPTION__ENABLED
            return self._base.get_value(attr_name)

    view.settings = DummySettings(base_settings)

    try:
        view.run()
    finally:
        controller.storage.seeds = original
        view.settings = base_settings

    assert screens and screens[0] == WarningScreen
    assert captured["key_type_options"] == [
        "ECC Ed25519",
        "ECC NIST P-256",
        "ECC NIST P-384",
        "ECC NIST P-521",
        "ECC Brainpool P-256",
        "ECC Brainpool P-384",
        "ECC Brainpool P-512",
        "RSA 2048",
        "RSA 3072",
        "RSA 4096",
        "ECC secp256k1",
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
    fpr = "F"
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
    assert (tmp_path / "BIP85_seedfpr.json").exists()
    BIP85_DATA.clear()
    bip85_load_data(tmp_path)
    assert BIP85_DATA[fpr]["seed_fpr"] == "seedfpr"
    assert BIP85_DATA[fpr]["key_type"] == "ECC NIST P-256"
    assert BIP85_DATA[fpr]["uids"][0] == "User <user@example.com>"
    assert BIP85_DATA[fpr]["primary_uid"] == "User <user@example.com>"
    assert BIP85_DATA[fpr]["subkeys"][0]["type"] == "ECDH ECC NIST P-256"


def test_load_bip85_data_from_microsd(monkeypatch, tmp_path):
    from pathlib import Path

    captured = {}

    def fake_bip85_load_data(path):
        captured["path"] = Path(path)

    monkeypatch.setattr(tools_views, "bip85_load_data", fake_bip85_load_data)
    monkeypatch.setattr(
        tools_views.MicroSD, "get_microsd_dir", lambda: tmp_path
    )

    def fake_run_screen(self, *args, **kwargs):
        return 0  # Select "From MicroSD"

    monkeypatch.setattr(
        tools_views.ToolsGPGLoadBip85DataView, "run_screen", fake_run_screen
    )

    view = tools_views.ToolsGPGLoadBip85DataView()
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
    from seedsigner.hardware import microsd

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

    monkeypatch.setattr(tools_views.ToolsGPGSaveBip85DataView, "run_screen", fake_run_screen)
    monkeypatch.setattr(tools_views, "bip85_save_data", fake_save)
    monkeypatch.setattr(tools_views.logger, "info", fake_log)
    monkeypatch.setattr(microsd.MicroSD, "get_microsd_dir", lambda: tmp_path)

    view = tools_views.ToolsGPGSaveBip85DataView()
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
    assert "81D909D9534ED202" in detail_kw["text"]
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


def test_rebuild_bip85_key(monkeypatch):
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
        tools_views.ToolsGPGRebuildBip85KeyView, "run_screen", fake_run_screen
    )

    def fake_run(cmd, input=None, capture_output=False):
        captured["cmd"] = cmd
        class Result:
            returncode = 0
        return Result()

    monkeypatch.setattr(tools_views.subprocess, "run", fake_run)

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
    real = tools_views.bip85_p256_from_root

    def fake_p256(root, key_index, sub_index=None, alg=None):
        calls.append(("p256", key_index, sub_index, alg))
        return real(root, key_index, sub_index, alg)

    monkeypatch.setattr(tools_views, "bip85_p256_from_root", fake_p256)

    rsa_calls = []
    real_rsa = tools_views.bip85_rsa_from_root

    def fake_rsa(root, bits, key_index, sub_index=None):
        rsa_calls.append((bits, key_index, sub_index))
        return real_rsa(root, bits, key_index, sub_index)

    monkeypatch.setattr(tools_views, "bip85_rsa_from_root", fake_rsa)

    verify_called = {}

    def fake_verify(seed, fingerprint, key_index, created_ts, primary_algo, primary_bits, primary_curve, subkeys):
        verify_called["subkeys"] = subkeys
        return True

    monkeypatch.setattr(tools_views, "bip85_verify_existing", fake_verify)

    view = tools_views.ToolsGPGRebuildBip85KeyView()
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
    import seedsigner.views.tools_views as tools_views

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
                    f"uid:u::::{tools_views.BIP85_GPG_CREATED_TS}::H::User::::::::\n"
                )
            else:
                return R(
                    "sec:-:0:0:KEYID:0:::::::\n" + "ssb:-:0:0:::0:::::::\n" * 3
                )
        return R()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)

    tools_views.BIP85_DATA["FPR"] = {
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

    def fake_bip85_add_subkeys(fpr, alg, key_index, start_index, seed):
        captured["key_index"] = key_index
        captured["start_index"] = start_index
        captured["seed"] = seed
        return []

    monkeypatch.setattr(tools_views, "bip85_add_subkeys", fake_bip85_add_subkeys)

    def fake_verify(seed, fingerprint, key_index, created_ts, primary_algo, primary_bits, primary_curve, subkeys):
        captured["verified_seed"] = seed
        captured["verified_key_index"] = key_index
        return True

    monkeypatch.setattr(tools_views, "bip85_verify_existing", fake_verify)

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

    monkeypatch.setattr(tools_views.ToolsGPGAddSubkeysView, "run_screen", fake_run_screen)

    view = object.__new__(tools_views.ToolsGPGAddSubkeysView)
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
    tools_views.ToolsGPGAddSubkeysView.run(view)
    assert captured["key_index"] == 1
    assert captured["start_index"] == 3
    assert captured["seed"] is seed_obj
    assert captured["verified_seed"] is seed_obj
    assert captured["verified_key_index"] == 0


def test_add_subkeys_registry_index_correction(monkeypatch):
    import seedsigner.views.tools_views as tools_views

    class R:
        def __init__(self, stdout=""):
            self.stdout = stdout

    def fake_run(cmd, capture_output=True, text=True):
        if cmd[:3] == ["gpg", "--list-secret-keys", "--with-colons"]:
            if len(cmd) == 3:
                return R(
                    "sec:-:0:0:KEYID:0:0:::::::\n"
                    f"fpr:::::::::FPR:\n"
                    f"uid:u::::{tools_views.BIP85_GPG_CREATED_TS}::H::User::::::::\n"
                )
            return R(
                "sec:-:0:0:KEYID:0:::::::\n" + "ssb:-:0:0:::0:::::::\n" * 3
            )
        return R()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)

    tools_views.BIP85_DATA["FPR"] = {
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

    def fake_bip85_add_subkeys(fpr, alg, key_index, start_index, seed):
        calls.append(("add", key_index, start_index))
        return []

    monkeypatch.setattr(tools_views, "bip85_add_subkeys", fake_bip85_add_subkeys)

    def fake_verify(seed, fingerprint, key_index, created_ts, primary_algo, primary_bits, primary_curve, subkeys):
        calls.append(("verify", key_index))
        return key_index == 0

    monkeypatch.setattr(tools_views, "bip85_verify_existing", fake_verify)

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

    monkeypatch.setattr(tools_views.ToolsGPGAddSubkeysView, "run_screen", fake_run_screen)

    view = object.__new__(tools_views.ToolsGPGAddSubkeysView)
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
    tools_views.ToolsGPGAddSubkeysView.run(view)

    assert calls[0] == ("verify", 1)
    assert calls[1] == ("verify", 0)
    assert calls[2] == ("add", 1, 3)
    assert tools_views.BIP85_DATA["FPR"]["index"] == 0


def test_add_subkeys_missing_seed(monkeypatch):
    class R:
        def __init__(self, stdout=""):
            self.stdout = stdout

    def fake_run(cmd, capture_output=True, text=True):
        if cmd[:3] == ["gpg", "--list-secret-keys", "--with-colons"]:
            if len(cmd) == 3:
                return R(
                    "sec:-:0:0:KEYID:0:0:::::::\n"
                    + f"fpr:::::::::FPR:\n"
                    + f"uid:u::::{tools_views.BIP85_GPG_CREATED_TS}::H::User::::::::\n"
                )
            return R(
                    "sec:-:0:0:KEYID:0:::::::\n" + "ssb:-:0:0:::0:::::::\n" * 3
            )
        return R()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)

    tools_views.BIP85_DATA["FPR"] = {
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

    monkeypatch.setattr(tools_views, "bip85_add_subkeys", fake_bip85_add_subkeys)

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

    from seedsigner.helpers import smartpgp_import

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
        tools_views.seedkeeper_utils,
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

    view = object.__new__(tools_views.ToolsGPGImportKeyToCardView)
    view.fingerprint = "PRIMARYFPR"
    view.selected_subkeys = {"s": "SUBFPR"}
    view.controller = SimpleNamespace(GPG_Admin_PIN="badpin", Satochip_Connector=None)
    view.loading_screen = None

    captured = {}

    def fake_run_screen(self, screen_cls, **kwargs):
        captured["text"] = kwargs.get("text")
        return 0

    view.run_screen = MethodType(fake_run_screen, view)

    result = tools_views.ToolsGPGImportKeyToCardView.run(view)

    assert isinstance(result, tools_views.Destination)
    assert result.View_cls is tools_views.BackStackView
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
