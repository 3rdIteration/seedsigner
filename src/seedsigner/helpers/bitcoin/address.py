"""P2WPKH (BIP-84 native segwit) address derivation.

Uses ``embit.script.p2wpkh`` so we share the codepath the rest of the
firmware exercises (descriptor display, PSBT parsing) instead of
rolling our own bech32 encoder. Mainnet only at MVP; the helper
accepts a ``hrp`` argument to keep testnet pluggable later.
"""

from __future__ import annotations

from embit import ec, script
from embit.networks import NETWORKS

from . import BECH32_HRP_MAINNET


def pubkey_to_p2wpkh_address(pubkey_compressed: bytes, hrp: str = BECH32_HRP_MAINNET) -> str:
    """Return a P2WPKH bech32 address for the given compressed pubkey.

    ``pubkey_compressed`` must be 33 bytes (``0x02``/``0x03`` prefix + X).
    """
    if len(pubkey_compressed) != 33 or pubkey_compressed[0] not in (0x02, 0x03):
        raise ValueError("expected 33-byte compressed secp256k1 pubkey")

    if hrp == BECH32_HRP_MAINNET:
        network = NETWORKS["main"]
    else:
        # Reserved for future testnet/signet support.
        raise ValueError(f"unsupported bech32 hrp: {hrp}")

    # ``embit.script.p2wpkh`` wants a key object exposing ``.sec()``;
    # wrap the raw bytes in a PublicKey.
    pub = ec.PublicKey.parse(pubkey_compressed)
    return script.p2wpkh(pub).address(network)
