from __future__ import annotations

from binascii import b2a_base64
import logging
import os
import random
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError

from embit.ec import PublicKey
from embit.psbt import PSBT
from embit.util import secp256k1
from seedsigner.helpers.iso7816 import format_sw_error
from seedsigner.models.settings import Settings, SettingsConstants

try:  # pragma: no cover - pysatochip optional at runtime
    from pysatochip import ecc as pysatochip_ecc
except ImportError:  # pragma: no cover - pysatochip not installed
    pysatochip_ecc = None
else:  # pragma: no cover - behaviour validated via unit tests
    if not hasattr(pysatochip_ecc.ECPubkey, "_seedsigner_safe_eq"):
        _orig_eq = pysatochip_ecc.ECPubkey.__eq__

        def _safe_eq(self, other):
            if not isinstance(other, pysatochip_ecc.ECPubkey):
                return False
            return _orig_eq(self, other)

        pysatochip_ecc.ECPubkey.__eq__ = _safe_eq
        pysatochip_ecc.ECPubkey._seedsigner_safe_eq = True

try:
    # Constant introduced in newer embit versions
    from embit.bip32 import HARDENED_INDEX  # type: ignore
except ImportError:  # pragma: no cover - support older embit releases
    HARDENED_INDEX = 0x80000000

logger = logging.getLogger(__name__)


def _call_with_timeout(func, timeout: float, *args):
    """Execute ``func`` with the provided timeout and log duration."""
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func, *args)
        try:
            return future.result(timeout=timeout)
        finally:
            elapsed = time.monotonic() - start
            logger.info("Satochip %s took %.3fs", func.__name__, elapsed)

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
    signing requests are issued before and after signing the real
    transaction. These dummy requests, like actual inputs, may themselves
    be signed multiple times based on the configured probability and
    maximum dummy count. For each real PSBT input that the card can sign
    there is a configurable chance that additional signatures will be
    generated, and the signature ultimately included in the PSBT is
    randomly selected from among all signatures produced for that input.
    Each signing attempt is limited to a configurable timeout.

    Returns the number of signatures added to ``psbt``.
    """
    settings = Settings.get_instance()
    timeout = settings.get_value(SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT)
    pre_dummy_max = settings.get_value(
        SettingsConstants.SETTING__SATOCHIP_MAX_PRE_DUMMIES
    )
    post_dummy_max = settings.get_value(
        SettingsConstants.SETTING__SATOCHIP_MAX_POST_DUMMIES
    )
    in_tx_dummy_max = settings.get_value(
        SettingsConstants.SETTING__SATOCHIP_MAX_IN_TX_DUMMIES
    )
    dummy_prob = (
        settings.get_value(SettingsConstants.SETTING__SATOCHIP_DUMMY_PROBABILITY) / 100
    )
    signed = 0

    # Issue 0-N dummy signing requests and discard the results. Each dummy
    # request may itself trigger extra signatures according to the configured
    # per-input dummy probability and maximum count.
    pre_dummy_count = random.randint(0, pre_dummy_max)
    logger.info("Pre-signing dummy signatures: %d", pre_dummy_count)
    for _ in range(pre_dummy_count):
        dummy_hash = os.urandom(32)
        extra = random.randint(1, in_tx_dummy_max) if random.random() < dummy_prob else 0
        for _ in range(1 + extra):
            try:
                _call_with_timeout(
                    connector.card_sign_transaction_hash,
                    timeout,
                    0xFF,
                    list(dummy_hash),
                    None,
                )
            except Exception:
                pass

    # Now sign the actual PSBT inputs. To avoid leaking the original
    # ordering, process the inputs in a random sequence. Signatures are
    # still written back to their original input index so the final PSBT
    # ordering matches the caller's expectations.
    indices = list(range(len(psbt.inputs)))
    random.shuffle(indices)
    for i in indices:
        inp = psbt.inputs[i]
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

            extra_sigs = (
                random.randint(1, in_tx_dummy_max) if random.random() < dummy_prob else 0
            )
            if extra_sigs:
                logger.info(
                    "Input %d selected for dummy signing: %d dummy signatures",
                    i,
                    extra_sigs,
                )
            else:
                logger.info("Input %d not selected for dummy signing", i)
            results: list[tuple | None] = []
            for _ in range(1 + extra_sigs):
                try:
                    results.append(
                        _call_with_timeout(
                            connector.card_sign_transaction_hash,
                            timeout,
                            0xFF,
                            list(tx_hash),
                            None,
                        )
                    )
                except TimeoutError:
                    logger.warning("Satochip signing timed out")
                    results.append(None)
                except Exception:
                    results.append(None)
            chosen = random.choice(results) if results else None
            if chosen is None:
                for res in results:
                    if res is not None:
                        chosen = res
                        break
            sig, sw1, sw2 = chosen if chosen is not None else (None, None, None)
            if sw1 != 0x90 or sw2 != 0x00:
                if sw1 is None or sw2 is None:
                    logger.warning("Satochip signing failed")
                else:
                    logger.warning(
                        "Satochip signing failed: %s", format_sw_error(sw1, sw2)
                    )
                continue
            sig_der = bytes(sig)
            # ensure low-S signature; gracefully handle normalization errors
            try:
                sig_obj = secp256k1.ecdsa_signature_parse_der(sig_der)
                sig_norm = secp256k1.ecdsa_signature_normalize(sig_obj)
                sig_der = secp256k1.ecdsa_signature_serialize_der(sig_norm)
            except Exception as e:
                logger.warning("Failed to normalize Satochip signature: %s", e)
            inp.partial_sigs[pubkey] = sig_der + b"\x01"
            signed += 1
            break

    # Issue 0-N dummy signing requests after signing completes, again applying
    # the per-input dummy settings to potentially sign each dummy hash multiple
    # times before discarding all results.
    post_dummy_count = random.randint(0, post_dummy_max)
    logger.info("Post-signing dummy signatures: %d", post_dummy_count)
    for _ in range(post_dummy_count):
        dummy_hash = os.urandom(32)
        extra = random.randint(1, in_tx_dummy_max) if random.random() < dummy_prob else 0
        for _ in range(1 + extra):
            try:
                _call_with_timeout(
                    connector.card_sign_transaction_hash,
                    timeout,
                    0xFF,
                    list(dummy_hash),
                    None,
                )
            except Exception:
                pass
    return signed


def sign_message_with_satochip(derivation_path: str, message: str, connector) -> str:
    """Sign an arbitrary message using a connected Satochip card.

    Args:
        derivation_path: BIP32 derivation path for the signing key ("m/84'/0'/0'/0/0").
        message: Message to be signed.
        connector: Active Satochip ``CardConnector`` instance.

    Returns:
        Base64 encoded compact signature string.

    Signing requests time out according to configuration.
    """

    settings = Settings.get_instance()
    timeout = settings.get_value(SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT)
    path = format_path_string(derivation_path)
    key, _chaincode = connector.card_bip32_get_extendedkey(path)
    try:
        _resp, sw1, sw2, compsig = _call_with_timeout(
            connector.card_sign_message, timeout, 0xFF, key, message
        )
    except TimeoutError:
        raise Exception("Satochip signing timed out")
    if sw1 != 0x90 or sw2 != 0x00 or not compsig:
        raise Exception(
            f"Failed to sign message with Satochip: {format_sw_error(sw1, sw2)}"
        )
    return b2a_base64(compsig).strip().decode()
