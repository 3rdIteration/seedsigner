from __future__ import annotations

from embit.psbt import PSBT
from embit.bip32 import HARDENED
from embit.util import secp256k1


def _format_path(derivation: list[int]) -> str:
    """Convert a list of BIP32 indices to string path"""
    path = "m"
    for index in derivation:
        hardened = index & HARDENED
        index &= ~HARDENED
        suffix = "'" if hardened else ""
        path += f"/{index}{suffix}"
    return path


def sign_psbt_with_satochip(psbt: PSBT, connector) -> int:
    """Sign the given PSBT using a connected Satochip card.

    Returns the number of signatures added.
    """
    signed = 0
    for i, inp in enumerate(psbt.inputs):
        if len(inp.bip32_derivations) == 0:
            continue
        for pubkey, deriv in inp.bip32_derivations.items():
            path = _format_path(deriv.derivation)
            try:
                key, chaincode = connector.card_bip32_get_extendedkey(path)
                card_pub = key.get_public_key_bytes(compressed=True)
            except Exception:
                continue
            if card_pub != pubkey:
                continue
            tx_hash = psbt.sighash(i)
            sig, sw1, sw2 = connector.card_sign_transaction_hash(0xFF, list(tx_hash), None)
            if sw1 != 0x90 or sw2 != 0x00:
                continue
            sig_der = bytes(sig)
            # ensure low-S signature
            sig_obj = secp256k1.ecdsa_signature_parse_der(sig_der)
            sig_norm = secp256k1.ecdsa_signature_normalize(sig_obj)
            sig_der = secp256k1.ecdsa_signature_serialize_der(sig_norm)
            inp.partial_sigs[pubkey] = sig_der + b"\x01"
            signed += 1
            break
    return signed
