from __future__ import annotations

from binascii import b2a_base64
import logging
import os
import random

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

    To obfuscate potential chosen-nonce attacks, a random number of dummy
    signing requests are issued prior to signing the real transaction. In
    addition, roughly half of the inputs that require a signature are signed
    twice with one of the signatures randomly selected and the other
    discarded.

    Returns the number of signatures added to ``psbt``.
    """
    signed = 0

    # Determine which inputs are signable so we can randomly pick some for
    # double-signing.
    signable_indices: list[int] = []
    for i, inp in enumerate(psbt.inputs):
        if len(inp.bip32_derivations) == 0:
            continue
        for pubkey, deriv in inp.bip32_derivations.items():
            path = _format_path(deriv.derivation)
            try:
                key, _chaincode = connector.card_bip32_get_extendedkey(path)
                card_pub = PublicKey.parse(
                    key.get_public_key_bytes(compressed=True)
                )
            except Exception:
                continue
            if card_pub == pubkey:
                signable_indices.append(i)
                break

    double_count = len(signable_indices) // 2
    double_indices = set(random.sample(signable_indices, double_count)) if double_count else set()

    # Issue 1-3 dummy signing requests and discard the results.
    for _ in range(random.randint(1, 3)):
        dummy_hash = os.urandom(32)
        try:
            connector.card_sign_transaction_hash(0xFF, list(dummy_hash), None)
        except Exception:
            pass

    # Now sign the actual PSBT inputs.
    for i, inp in enumerate(psbt.inputs):
        if len(inp.bip32_derivations) == 0:
            continue
        for pubkey, deriv in inp.bip32_derivations.items():
            path = _format_path(deriv.derivation)
            try:
                key, _chaincode = connector.card_bip32_get_extendedkey(path)
                card_pub = PublicKey.parse(
                    key.get_public_key_bytes(compressed=True)
                )
            except Exception:
                continue
            if card_pub != pubkey:
                continue

            tx_hash = psbt.sighash(i)

            sig, sw1, sw2 = None, None, None
            if i in double_indices:
                # Sign twice and randomly keep one signature to obfuscate nonce usage.
                first = None
                second = None
                try:
                    first = connector.card_sign_transaction_hash(0xFF, list(tx_hash), None)
                except Exception:
                    pass
                try:
                    second = connector.card_sign_transaction_hash(0xFF, list(tx_hash), None)
                except Exception:
                    pass
                chosen = random.choice([first, second])
                if chosen is None:
                    chosen = first if second is None else second
                sig, sw1, sw2 = chosen if chosen is not None else (None, None, None)
            else:
                sig, sw1, sw2 = connector.card_sign_transaction_hash(0xFF, list(tx_hash), None)
            if sw1 != 0x90 or sw2 != 0x00:
                if sw1 is None or sw2 is None:
                    logger.warning("Satochip signing failed")
                else:
                    logger.warning(
                        "Satochip signing failed: %s", format_sw_error(sw1, sw2)
                    )
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
