from __future__ import annotations

from binascii import b2a_base64
import logging

from embit.ec import PublicKey
from embit.psbt import PSBT
from embit.util import secp256k1
from seedsigner.helpers.iso7816 import format_sw_error

try:
    # Constant introduced in newer embit versions
    from embit.bip32 import HARDENED_INDEX  # type: ignore
except ImportError:  # pragma: no cover - support older embit releases
    HARDENED_INDEX = 0x80000000

logger = logging.getLogger(__name__)

def _format_path(derivation: list[int]) -> str:
    """Convert a list of BIP32 indices to string path"""
    path = "m"
    for index in derivation:
        hardened = bool(index & HARDENED_INDEX)
        index &= ~HARDENED_INDEX
        suffix = "'" if hardened else ""
        path += f"/{index}{suffix}"
    return path


def format_path_string(path: str) -> str:
    """Normalize a BIP32 path string for Satochip expectations.

    Satochip's ``CardConnector`` only accepts hardened markers as an
    apostrophe (``'``) and requires a leading ``m/``. SeedSigner uses
    ``h`` to denote hardened indices and may omit the master prefix, so
    we convert here.
    """

    if path is None:
        return "m"
    path = path.strip()
    if path.startswith("m/"):
        path = path[2:]
    path = path.replace("H", "'").replace("h", "'")
    if path == "" or path == "m":
        return "m"
    return "m/" + path


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
                card_pub = PublicKey.parse(
                    key.get_public_key_bytes(compressed=True)
                )
            except Exception:
                continue
            if card_pub != pubkey:
                continue
            tx_hash = psbt.sighash(i)
            sig, sw1, sw2 = connector.card_sign_transaction_hash(0xFF, list(tx_hash), None)
            if sw1 != 0x90 or sw2 != 0x00:
                logger.warning("Satochip signing failed: %s", format_sw_error(sw1, sw2))
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


def sign_message_with_satochip(derivation_path: str, message: str, connector) -> str:
    """Sign an arbitrary message using a connected Satochip card.

    Args:
        derivation_path: BIP32 derivation path for the signing key ("m/84'/0'/0'/0/0").
        message: Message to be signed.
        connector: Active Satochip ``CardConnector`` instance.

    Returns:
        Base64 encoded compact signature string.
    """

    path = format_path_string(derivation_path)
    key, _chaincode = connector.card_bip32_get_extendedkey(path)
    _resp, sw1, sw2, compsig = connector.card_sign_message(0xFF, key, message)
    if sw1 != 0x90 or sw2 != 0x00 or not compsig:
        raise Exception(
            f"Failed to sign message with Satochip: {format_sw_error(sw1, sw2)}"
        )
    return b2a_base64(compsig).strip().decode()
