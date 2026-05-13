"""Unit tests for the P2WPKH address helper.

The BIP-84 test vectors live at
https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki — derived
from the "abandon... about" mnemonic at ``m/84'/0'/0'/0/0`` and
``m/84'/0'/0'/0/1`` on mainnet.
"""

from embit import bip32, bip39

from seedsigner.helpers.bitcoin.address import pubkey_to_p2wpkh_address


# BIP-84 reference vectors (mainnet, account 0).
MNEMONIC = "abandon " * 11 + "about"
ROOT_SEED = bip39.mnemonic_to_seed(MNEMONIC)
ROOT_KEY = bip32.HDKey.from_seed(ROOT_SEED)


def _addr_at(path: str) -> str:
    return pubkey_to_p2wpkh_address(ROOT_KEY.derive(path).key.sec())


def test_bip84_receive_address_0():
    # m/84'/0'/0'/0/0 → bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
    assert _addr_at("m/84'/0'/0'/0/0") == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"


def test_bip84_receive_address_1():
    assert _addr_at("m/84'/0'/0'/0/1") == "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"


def test_bip84_change_address_0():
    assert _addr_at("m/84'/0'/0'/1/0") == "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"


def test_rejects_uncompressed_pubkey():
    import pytest

    fake = b"\x04" + b"\x00" * 64
    with pytest.raises(ValueError):
        pubkey_to_p2wpkh_address(fake)


def test_rejects_wrong_length():
    import pytest

    with pytest.raises(ValueError):
        pubkey_to_p2wpkh_address(b"\x02" * 32)
