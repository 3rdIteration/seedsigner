"""Thin wrapper over ``embit.psbt.PSBT`` for the Tools > Keycard >
Bitcoin sign flow.

Scope:
  - Parse PSBT (raw bytes / base64).
  - Enumerate inputs (path, amount, script-type guess).
  - Enumerate outputs (amount, change marker via BIP-32 derivation
    matching the wallet's master fingerprint).
  - Compute the BIP-143 sighash for each input (P2WPKH-only at MVP).
  - Insert ``PSBT_IN_PARTIAL_SIG`` after the signer returns DER bytes.

We deliberately reject non-P2WPKH inputs at parse time with a clear
error: that bound matches keycard-shell's ``BTC_INPUT_TYPE_P2WPKH``
single-sig pre-condition. P2WSH / P2SH-P2WPKH / P2TR support is the
follow-up, not the MVP.

Limit: 40 inputs / 40 outputs (matches keycard-shell). Larger PSBTs
yield a clear error instead of silently signing only the first 40.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from embit.psbt import PSBT
from embit.script import Script

MAX_INPUTS = 40
MAX_OUTPUTS = 40


@dataclass
class BtcInputView:
    index: int
    derivation: list[int]      # full path components, hardened bit set
    derivation_str: str        # human-readable e.g. "m/84'/0'/0'/0/3"
    amount_sats: int
    sighash_hex: str | None    # populated when sighash_for_input() is called


@dataclass
class BtcOutputView:
    index: int
    address: str | None
    amount_sats: int
    is_change: bool
    script_hex: str


@dataclass
class ParsedPsbt:
    psbt: PSBT
    inputs: list[BtcInputView]
    outputs: list[BtcOutputView]
    fee_sats: int
    master_fingerprint: bytes  # the one we matched change against (4 bytes)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_psbt(blob: bytes | str) -> PSBT:
    """Accept raw PSBT bytes or a base64 string. Caller is expected to
    have already converted UR ``crypto-psbt`` payloads to raw bytes."""
    if isinstance(blob, str):
        blob = base64.b64decode(blob)
    return PSBT.parse(blob)


def _format_derivation(path: list[int]) -> str:
    HARDENED = 0x80000000
    out = ["m"]
    for idx in path:
        if idx & HARDENED:
            out.append(f"{idx & ~HARDENED}'")
        else:
            out.append(str(idx))
    return "/".join(out)


def _first_bip32_derivation(per_pubkey: dict, master_fp: bytes | None):
    """Return the (pubkey, derivation) tuple whose origin matches
    ``master_fp``; falls back to the first entry if no match (lets the
    review screen still surface the path before signing).
    """
    if not per_pubkey:
        return None, None
    if master_fp is not None:
        for pub, der in per_pubkey.items():
            if der.fingerprint == master_fp:
                return pub, der
    pub, der = next(iter(per_pubkey.items()))
    return pub, der


def extract(psbt: PSBT, master_fingerprint: bytes) -> ParsedPsbt:
    """Build a ``ParsedPsbt`` view scoped to the given master fingerprint.

    Raises:
        ValueError: if the PSBT exceeds ``MAX_INPUTS`` / ``MAX_OUTPUTS``,
            contains a non-P2WPKH input, or is missing a witness UTXO
            for any input.
    """
    if len(psbt.inputs) > MAX_INPUTS:
        raise ValueError(f"too many inputs: {len(psbt.inputs)} > {MAX_INPUTS}")
    if len(psbt.outputs) > MAX_OUTPUTS:
        raise ValueError(f"too many outputs: {len(psbt.outputs)} > {MAX_OUTPUTS}")

    inputs: list[BtcInputView] = []
    total_in = 0
    for i, inp in enumerate(psbt.inputs):
        if inp.witness_utxo is None:
            raise ValueError(f"input {i}: missing witness UTXO (P2WPKH required)")
        spk = inp.witness_utxo.script_pubkey
        if not _looks_like_p2wpkh(spk):
            raise ValueError(f"input {i}: not P2WPKH (unsupported at MVP)")

        pub, der = _first_bip32_derivation(inp.bip32_derivations, master_fingerprint)
        if der is None:
            raise ValueError(f"input {i}: PSBT missing BIP-32 derivation hints")
        path = list(der.derivation)
        amount = inp.witness_utxo.value
        total_in += amount
        inputs.append(BtcInputView(
            index=i,
            derivation=path,
            derivation_str=_format_derivation(path),
            amount_sats=amount,
            sighash_hex=None,
        ))

    outputs: list[BtcOutputView] = []
    total_out = 0
    for i, (out, pout) in enumerate(zip(psbt.tx.vout, psbt.outputs)):
        is_change = False
        if pout.bip32_derivations:
            for pub, der in pout.bip32_derivations.items():
                if der.fingerprint == master_fingerprint:
                    is_change = True
                    break
        try:
            address = out.script_pubkey.address()
        except Exception:
            address = None
        amount = out.value
        total_out += amount
        outputs.append(BtcOutputView(
            index=i,
            address=address,
            amount_sats=amount,
            is_change=is_change,
            script_hex=out.script_pubkey.data.hex() if hasattr(out.script_pubkey, "data") else "",
        ))

    fee_sats = total_in - total_out
    if fee_sats < 0:
        raise ValueError(f"PSBT fee is negative: {fee_sats}")

    return ParsedPsbt(
        psbt=psbt,
        inputs=inputs,
        outputs=outputs,
        fee_sats=fee_sats,
        master_fingerprint=master_fingerprint,
    )


def _looks_like_p2wpkh(spk: Script) -> bool:
    """P2WPKH = OP_0 <20-byte hash>. We only need to recognise the
    canonical layout so we can refuse anything else explicitly."""
    raw = spk.data
    return len(raw) == 22 and raw[0] == 0x00 and raw[1] == 0x14


# ---------------------------------------------------------------------------
# Sighash
# ---------------------------------------------------------------------------


def sighash_for_input(psbt: PSBT, input_index: int, sighash_type: int = 0x01) -> bytes:
    """BIP-143 sighash for a P2WPKH input. Matches keycard-shell's
    ``SIGHASH_ALL`` default.
    """
    inp = psbt.inputs[input_index]
    if inp.witness_utxo is None:
        raise ValueError(f"input {input_index}: missing witness UTXO")
    return psbt.sighash_segwit(input_index, sighash=sighash_type)


# ---------------------------------------------------------------------------
# Signature insertion
# ---------------------------------------------------------------------------


def add_partial_signature(
    psbt: PSBT,
    input_index: int,
    pubkey_compressed: bytes,
    der_sig: bytes,
    sighash_type: int = 0x01,
) -> None:
    """Append the ``[r||s||sighash_byte]`` partial signature to the
    matching input's ``PSBT_IN_PARTIAL_SIG`` map.

    ``der_sig`` is the DER-encoded ECDSA signature returned by the
    Keycard SIGN APDU (low-S enforced by the applet). We tack on the
    sighash flag byte the way embit / Core expect.
    """
    inp = psbt.inputs[input_index]
    inp.partial_sigs[pubkey_compressed] = der_sig + bytes([sighash_type])
