"""Bridge between an :class:`EthSignRequest` and a paired/unlocked Keycard.

The Keycard is used purely as an oracle: the host computes the digest to be
signed, the card returns ``(r, s, public_key)``, and the host computes the
recovery id and assembles the final ``EthSignature`` payload.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from seedsigner.helpers.ethereum import eip712
from seedsigner.helpers.ethereum.keccak import keccak256
from seedsigner.helpers.ethereum.personal_sign import personal_sign_hash
from seedsigner.helpers.ethereum.ur_codec import (
    DATA_TYPE_LEGACY_TX, DATA_TYPE_PERSONAL_MESSAGE, DATA_TYPE_TYPED_DATA,
    DATA_TYPE_TYPED_TX, EthSignature, EthSignRequest,
)
from seedsigner.helpers.keycard.client import KeycardClient, recover_id_for

logger = logging.getLogger(__name__)


def signing_hash_for(request: EthSignRequest) -> bytes:
    """Compute the 32-byte hash that the Keycard SIGN APDU expects.

    The exact pre-image depends on ``data_type``: the upstream wallet has
    already framed legacy and EIP-1559 transactions (sign_data is the
    canonical to-be-signed bytes), so we just hash with keccak256.  For
    typed-data we parse the JSON and run the EIP-712 algorithm; for a
    personal-message we apply the EIP-191 prefix.
    """
    dt = request.data_type
    if dt == DATA_TYPE_LEGACY_TX:
        return keccak256(request.sign_data)
    if dt == DATA_TYPE_TYPED_TX:
        # sign_data = type-byte || rlp(payload)
        return keccak256(request.sign_data)
    if dt == DATA_TYPE_TYPED_DATA:
        try:
            typed = json.loads(request.sign_data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"typed-data payload is not valid JSON: {exc}") from exc
        return eip712.signing_hash(typed)
    if dt == DATA_TYPE_PERSONAL_MESSAGE:
        return personal_sign_hash(request.sign_data)
    raise ValueError(f"unsupported eth-sign-request data-type: {dt}")


def compute_v(request: EthSignRequest, recovery_id: int) -> int:
    """Compose the final ``v`` byte to pack into the eth-signature."""
    dt = request.data_type
    if dt == DATA_TYPE_LEGACY_TX:
        # EIP-155: v = 35 + chainId*2 + recId
        if request.chain_id == 0:
            return 27 + recovery_id  # pre-EIP-155
        return 35 + request.chain_id * 2 + recovery_id
    if dt == DATA_TYPE_TYPED_TX:
        return recovery_id  # yParity (0 or 1)
    if dt in (DATA_TYPE_TYPED_DATA, DATA_TYPE_PERSONAL_MESSAGE):
        return 27 + recovery_id
    raise ValueError(f"unsupported eth-sign-request data-type: {dt}")


def sign_with_keycard(client: KeycardClient, request: EthSignRequest) -> EthSignature:
    """Drive the Keycard to produce a signature for ``request``.

    The caller is responsible for having (a) selected the applet,
    (b) opened a secure channel, (c) verified the PIN.
    """
    digest = signing_hash_for(request)
    sig = client.sign(digest, path_components=request.derivation_path.components,
                      derive_and_make_current=False)
    rec_id = recover_id_for(sig.public_key, digest, sig.r, sig.s)
    v = compute_v(request, rec_id)

    v_bytes = v.to_bytes(_required_v_bytes(v), "big")
    return EthSignature(
        request_id=request.request_id,
        signature=sig.r + sig.s + v_bytes,
        origin=request.origin,
    )


def _required_v_bytes(v: int) -> int:
    if v < 0:
        raise ValueError("v must be non-negative")
    if v == 0:
        return 1
    return (v.bit_length() + 7) // 8
