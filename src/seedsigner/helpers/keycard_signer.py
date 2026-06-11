from __future__ import annotations

import os
import random
from concurrent.futures import TimeoutError

from embit.psbt import PSBT
from embit.util import secp256k1

from seedsigner.helpers.iso7816 import format_sw_error
from seedsigner.helpers.satochip_signer import _call_with_timeout, _format_path
from seedsigner.models.settings import Settings, SettingsConstants

import logging

logger = logging.getLogger(__name__)


def sign_psbt_with_keycard(psbt: PSBT, connector) -> int:
    """Sign PSBT inputs with a Keycard backend.

    Keycard shells may reject pubkey export for arbitrary child paths with
    SW=6982. For single-derivation inputs, this signer falls back to path-based
    signing by setting the connector's current derivation path directly.
    """

    settings = Settings.get_instance()
    timeout = settings.get_value(SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT)
    pre_dummy_max = settings.get_value(SettingsConstants.SETTING__SATOCHIP_MAX_PRE_DUMMIES)
    post_dummy_max = settings.get_value(SettingsConstants.SETTING__SATOCHIP_MAX_POST_DUMMIES)
    in_tx_dummy_max = settings.get_value(SettingsConstants.SETTING__SATOCHIP_MAX_IN_TX_DUMMIES)
    dummy_prob = settings.get_value(SettingsConstants.SETTING__SATOCHIP_DUMMY_PROBABILITY) / 100

    signed = 0

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

    indices = list(range(len(psbt.inputs)))
    random.shuffle(indices)
    for i in indices:
        inp = psbt.inputs[i]
        if len(inp.bip32_derivations) == 0:
            logger.debug("Keycard signer input %d: skipped (no bip32 derivations)", i)
            continue

        matched_or_fallback = False
        for pubkey, deriv in inp.bip32_derivations.items():
            path = _format_path(deriv.derivation)
            logger.info(
                "Keycard signer input %d: attempting derive path=%s fp=%s",
                i,
                path,
                getattr(deriv, "fingerprint", b"").hex() if getattr(deriv, "fingerprint", None) is not None else "unknown",
            )

            # Keycard backend: path-based fallback for single-derivation inputs.
            if len(inp.bip32_derivations) == 1:
                try:
                    setattr(connector, "_last_path", path)
                    matched_or_fallback = True
                    logger.info(
                        "Keycard signer input %d: using path-sign fallback path=%s",
                        i,
                        path,
                    )
                except Exception as e:
                    logger.info(
                        "Keycard signer input %d: path-sign fallback failed path=%s error=%s",
                        i,
                        path,
                        e,
                    )
                    continue
            else:
                # For multi-derivation inputs we avoid guessing.
                logger.info(
                    "Keycard signer input %d: skipping non-single-derivation input",
                    i,
                )
                continue

            tx_hash = psbt.sighash(i)
            extra_sigs = random.randint(1, in_tx_dummy_max) if random.random() < dummy_prob else 0
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
                    logger.warning("Keycard signing timed out")
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
                    logger.warning("Keycard signing failed")
                else:
                    logger.warning("Keycard signing failed: %s", format_sw_error(sw1, sw2))
                continue

            sig_der = bytes(sig)
            try:
                sig_obj = secp256k1.ecdsa_signature_parse_der(sig_der)
                sig_norm = secp256k1.ecdsa_signature_normalize(sig_obj)
                sig_der = secp256k1.ecdsa_signature_serialize_der(sig_norm)
            except Exception as e:
                logger.warning("Failed to normalize Keycard signature: %s", e)

            inp.partial_sigs[pubkey] = sig_der + b"\x01"
            signed += 1
            logger.info("Keycard signer input %d: signature appended (signed_count=%d)", i, signed)
            break

        if not matched_or_fallback:
            logger.info("Keycard signer input %d: no signable path found", i)

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
