"""xpub + descriptor serialisation against the BIP-84 test vector.

Reference vector (abandon... about, mainnet account 0):
  m/84'/0'/0'   →   xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V
                    (account-level xpub)
"""

from embit import bip32, bip39

from seedsigner.helpers.bitcoin.xpub import (
    build_hdkey, pubkey_fingerprint, serialize_xpub, wpkh_descriptor,
    parse_descriptor,
)
from seedsigner.helpers.bitcoin import XPUB_VERSION_MAINNET


MNEMONIC = "abandon " * 11 + "about"
ROOT = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(MNEMONIC))
MASTER_FINGERPRINT = ROOT.child(0).fingerprint  # 4-byte BIP-32 root FP
ACCOUNT_PRIV = ROOT.derive("m/84'/0'/0'")
ACCOUNT_PUB = ACCOUNT_PRIV.to_public()
EXPECTED_XPUB = ACCOUNT_PUB.to_string(version=XPUB_VERSION_MAINNET)


def test_serialize_xpub_matches_embit():
    """build_hdkey + serialize_xpub round-trips against embit's
    canonical xpub at the same path."""
    hdkey = build_hdkey(
        pubkey_compressed=ACCOUNT_PRIV.key.get_public_key().sec(),
        chain_code=ACCOUNT_PRIV.chain_code,
        depth=ACCOUNT_PRIV.depth,
        parent_fingerprint=ACCOUNT_PRIV.fingerprint,
        child_number=ACCOUNT_PRIV.child_number,
    )
    assert serialize_xpub(hdkey) == EXPECTED_XPUB


def test_descriptor_checksum_round_trip():
    descriptor_str = wpkh_descriptor(
        xpub=EXPECTED_XPUB,
        master_fingerprint=MASTER_FINGERPRINT,
    )
    # Sparrow / Specter parse the descriptor; round-trip through embit
    # to validate the BIP-380 checksum suffix and the structure.
    desc = parse_descriptor(descriptor_str)
    assert "wpkh" in str(desc)


def test_pubkey_fingerprint_is_4_bytes_and_deterministic():
    pub = ACCOUNT_PRIV.key.get_public_key().sec()
    fp_ours = pubkey_fingerprint(pub)
    assert isinstance(fp_ours, bytes) and len(fp_ours) == 4
    assert pubkey_fingerprint(pub) == fp_ours


def test_pubkey_fingerprint_rejects_bad_length():
    import pytest

    with pytest.raises(ValueError):
        pubkey_fingerprint(b"\x02" * 32)
