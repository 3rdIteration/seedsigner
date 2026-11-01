#!/usr/bin/env python3
"""
Derives the "Follow-up of 2026-10-31" vectors (see PROVENANCE.md) from vendored
psbt_faker fixtures.

Each vector is a vendored NORMAL-* (or multisig negative control) fixture with one
surgical edit, so the trap is the only thing that differs from a psbt that must sign
cleanly. Run from the repository root:

    python tests/data/psbt_test_suite/derive_followup_vectors.py

The output is deterministic; re-running rewrites the same bytes.
"""
import hashlib
import os

from embit import bip32, script
from embit.psbt import PSBT, OutputScope


HERE = os.path.dirname(os.path.abspath(__file__))


def load(name: str) -> PSBT:
    with open(os.path.join(HERE, name + ".psbt"), "rb") as f:
        return PSBT.parse(f.read())


def write(name: str, psbt: PSBT):
    with open(os.path.join(HERE, name + ".psbt"), "wb") as f:
        f.write(psbt.serialize())


def foreign_key(index: int):
    """A key no corpus seed derives: a fixed throwaway root, mainnet BIP49 receive path."""
    root = bip32.HDKey.from_seed(hashlib.sha256(b"seedsigner-followup-2026-10-31-foreign").digest())
    return root.derive(f"m/49h/0h/0h/0/{index}").get_public_key()


def with_op_return(base: str, script_bytes: bytes) -> PSBT:
    """Appends a zero-value OP_RETURN output with the given raw script. The fee is unchanged."""
    psbt = load(base)
    out = OutputScope()
    out.script_pubkey = script.Script(script_bytes)
    out.value = 0
    psbt.outputs.append(out)
    return psbt


RUNESTONE = bytes.fromhex("00c0a2331414010203")

# (name, raw OP_RETURN script). Each gets a v0 and a _V2 twin.
OP_RETURN_VECTORS = [
    # Runes: OP_RETURN OP_13 <pushes>. Push-only per Core's IsPushOnly.
    ("XTRAS.OP_RETURN_RUNESTONE", b"\x6a\x5d" + bytes([len(RUNESTONE)]) + RUNESTONE),
    # OP_0, OP_1NEGATE, OP_1, OP_16: pushes that carry no data bytes.
    ("XTRAS.OP_RETURN_SMALLINT", b"\x6a\x00\x4f\x51\x60"),
    # A direct push, an OP_PUSHDATA2 and an OP_PUSHDATA1, concatenated: "helloabcde".
    ("XTRAS.OP_RETURN_MULTI_PUSH", b"\x6a\x05hello" + b"\x4d\x03\x00abc" + b"\x4c\x02de"),
    # OP_PUSHDATA2 declaring 255 bytes, with 3 present.
    ("XTRAS.OP_RETURN_TRUNCATED_PUSH", b"\x6a\x4d\xff\x00abc"),
    # A valid push followed by OP_CHECKSIG.
    ("XTRAS.OP_RETURN_NON_PUSH", b"\x6a\x05hello\xac"),
]


def main():
    for name, raw in OP_RETURN_VECTORS:
        write(name, with_op_return("NORMAL-1_p2wpkh", raw))
        write(name + "_V2", with_op_return("NORMAL-1_p2wpkh_V2", raw))

    for suffix in ("", "_V2"):
        # Native segwit input carrying a redeem_script it does not commit to.
        psbt = load("NORMAL-1_p2wpkh" + suffix)
        psbt.inputs[0].redeem_script = script.Script(b"\x51")
        write("XTRAS.STRAY_REDEEM_SCRIPT" + suffix, psbt)

        # Nested segwit input with its redeem_script left out.
        psbt = load("NORMAL-2_wrapped" + suffix)
        psbt.inputs[0].redeem_script = None
        write("XTRAS.MISSING_REDEEM_SCRIPT" + suffix, psbt)

        # Nested segwit input whose redeem_script wraps a different key than the one its
        # scriptPubKey commits to.
        psbt = load("NORMAL-2_wrapped" + suffix)
        psbt.inputs[0].redeem_script = script.p2wpkh(foreign_key(0))
        write("XTRAS.WRONG_REDEEM_SCRIPT" + suffix, psbt)

        # Genuine nested segwit change, minus its (BIP-174 optional) redeem_script.
        psbt = load("NORMAL-2_wrapped" + suffix)
        psbt.outputs[1].redeem_script = None
        write("XTRAS.NESTED_CHANGE_NO_REDEEM" + suffix, psbt)

        # The same redeem-less change output, repointed at a stranger's key while it
        # keeps this seed's derivation claim.
        psbt = load("NORMAL-2_wrapped" + suffix)
        psbt.outputs[1].redeem_script = None
        psbt.outputs[1].script_pubkey = script.p2sh(script.p2wpkh(foreign_key(1)))
        write("TX-21.nested_bare_p2sh_claims_us_pays_other" + suffix, psbt)

    # p2wsh multisig input with its witness_script left out.
    psbt = load("TX-21.ms_honest_change_no_xpubs")
    psbt.inputs[0].witness_script = None
    write("XTRAS.MISSING_WITNESS_SCRIPT", psbt)

    # A collaborative spend: our nested segwit input plus another party's, whose
    # redeem_script is not the one its scriptPubKey commits to. The other party's input
    # claims none of our keys, but its scripts are checked all the same.
    psbt = load("NORMAL-2_wrapped")
    from copy import deepcopy
    other = deepcopy(psbt.inputs[0])
    other.txid = hashlib.sha256(b"followup-foreign-outpoint").digest()
    other.vout = 0
    other.bip32_derivations.clear()
    other.non_witness_utxo = None
    other.witness_utxo.script_pubkey = script.p2sh(script.p2wpkh(foreign_key(2)))
    other.redeem_script = script.p2wpkh(foreign_key(3))
    psbt.inputs.append(other)
    write("XTRAS.FOREIGN_INPUT_BAD_SCRIPT", psbt)

    # Zero fee: the change output absorbs the original 10,000 sat fee.
    for suffix in ("", "_V2"):
        psbt = load("NORMAL-1_p2wpkh" + suffix)
        psbt.outputs[1].value += 10_000
        write("XTRAS.ZERO_FEE" + suffix, psbt)


if __name__ == "__main__":
    main()
