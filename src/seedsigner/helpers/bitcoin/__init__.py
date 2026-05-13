"""Bitcoin primitives for the Keycard-driven BTC flow.

Mirrors ``helpers/ethereum/``. Used by the Tools > Keycard > Bitcoin
views and by ``keycard_btc_signer.py``. MVP scope: BIP-84 P2WPKH
single-sig (mainnet only). Multisig P2WSH / wrapped P2SH (BIP-49) /
taproot P2TR are deliberately out of scope until the single-sig path
is shipping; the module layout already mirrors ``keycard-shell``'s
input-type discriminator so adding them later does not require a
refactor.
"""

from __future__ import annotations

# BIP-84 mainnet defaults. The account path (``m/84'/0'/0'``) is the
# canonical export point — derived xpub here gets wrapped into a
# ``wpkh([fp/84h/0h/0h]xpub.../<0;1>/*)`` descriptor that watch-only
# wallets (Sparrow, Specter, BlueWallet, Nunchuk) ingest unchanged.
DEFAULT_BTC_ACCOUNT_PATH = "m/84'/0'/0'"

# Per-address default used as a smoke-test target. Real signing
# derives each input's path from the PSBT, this constant is only the
# fallback when no derivation is supplied.
DEFAULT_BTC_PATH = "m/84'/0'/0'/0/0"

# Mainnet xpub version bytes (BIP-32). We deliberately emit a neutral
# ``xpub`` plus a descriptor instead of ``zpub``: more wallets accept
# the descriptor form, and adding a ``zpub`` toggle later is trivial.
XPUB_VERSION_MAINNET = b"\x04\x88\xB2\x1E"

# Mainnet bech32 HRP for native segwit addresses.
BECH32_HRP_MAINNET = "bc"

__all__ = [
    "DEFAULT_BTC_ACCOUNT_PATH",
    "DEFAULT_BTC_PATH",
    "XPUB_VERSION_MAINNET",
    "BECH32_HRP_MAINNET",
]
