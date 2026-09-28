"""
Silent Payments (BIP-352) receive keys, for exporting a scan-only wallet.

Only what the Seed options export needs: the account's address, and its private
scan key in the form Sparrow imports. There are no labels, and the spend private
key never leaves this module.

TODO: move this into embit once embit ships Silent Payments support (0.8.0 has
none).
"""
from embit import bech32
from embit.bip32 import HARDENED_INDEX as H

from seedsigner.models.settings_definition import SettingsConstants


# BIP-352 coin types. Regtest is left out on purpose: wallets don't agree on its
# address prefix (Sparrow uses "sprt"), so the export is offered on mainnet and
# testnet only.
COIN_TYPES = {SettingsConstants.MAINNET: 0, SettingsConstants.TESTNET: 1}


def _master_root(seed, network: str):
    """The seed's BIP-32 master key. Raises ValueError if it can't export here."""
    if network not in COIN_TYPES:
        raise ValueError("Silent Payments needs mainnet or testnet")
    if seed.script_override:
        # Electrum and Aezeed seeds are pinned to a single script type.
        raise ValueError("This seed type has no Silent Payments account")
    root = seed.get_root(network)
    if root.depth != 0:
        # Below the master, both the fingerprint and the m/352' path would be wrong.
        raise ValueError("Silent Payments needs a master key, not a derived xprv")
    return root


def is_supported(seed, network: str) -> bool:
    try:
        _master_root(seed, network)
    except ValueError:
        return False
    return True


def derivation_path(network: str) -> str:
    return "m/352'/%d'/0'" % COIN_TYPES[network]


def _keys(seed, network: str):
    """The (scan, spend) private keys: m/352'/coin'/0'/1'/0 and m/352'/coin'/0'/0'/0."""
    account = _master_root(seed, network).derive([H + 352, H + COIN_TYPES[network], H + 0])
    return account.derive([H + 1, 0]).key, account.derive([H + 0, 0]).key


def _bech32m(hrp: str, payload: bytes) -> str:
    # embit's bech32.encode() only does segwit programs (bech32 for v0, up to 40
    # bytes), so build the data part here: version 0, then the payload in 5-bit groups.
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [0] + bech32.convertbits(payload, 8, 5))


def address(seed, network: str) -> str:
    """The account's sp1... address (tsp1... on testnet), without labels."""
    scan, spend = _keys(seed, network)
    hrp = "sp" if network == SettingsConstants.MAINNET else "tsp"
    return _bech32m(hrp, scan.sec() + spend.sec())


def scan_key_export(seed, network: str) -> str:
    """
    The account's private scan key as Sparrow's SeedSigner import reads it:
    "[fingerprint/352h/coinh/0h]spscan1...", a BIP-392 key expression with its
    origin (Sparrow adds the sp(...) itself). It can't spend, but whoever holds it
    sees every payment to this wallet.
    """
    scan, spend = _keys(seed, network)
    hrp = "spscan" if network == SettingsConstants.MAINNET else "tspscan"
    return "[%s/352h/%dh/0h]%s" % (
        seed.get_fingerprint(network),
        COIN_TYPES[network],
        _bech32m(hrp, scan.secret + spend.sec()),
    )
