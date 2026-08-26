"""
Loader and expectation table for the vendored `psbt_faker` adversarial PSBT corpus.

See `tests/data/psbt_test_suite/PROVENANCE.md` for where the fixtures come from.

Every vector derives from the canonical BIP39 all-zeros test vector, so a single
seed unlocks the whole corpus:

    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about

    master fingerprint  73c5da0a
    network             mainnet
    accounts            m/84h/0h/0h, m/49h/0h/0h, m/44h/0h/0h

`VECTORS` records, for each fixture, the trap it sets and the behavior a secure
signer must exhibit. The `expect` field is the *target* behavior, not necessarily
what SeedSigner does today.
"""
import os

from base64 import b64encode
from binascii import a2b_base64
from dataclasses import dataclass, field
from typing import Optional

from embit.psbt import PSBT

from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants


DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "psbt_test_suite")

SUITE_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
SUITE_FINGERPRINT = "73c5da0a"
SUITE_NETWORK = SettingsConstants.MAINNET

# Consensus ceiling on any single amount, in sats.
MAX_MONEY = 21_000_000 * 100_000_000


def suite_seed() -> Seed:
    """A fresh Seed for the corpus mnemonic (Seed caches derived keys; don't share)."""
    return Seed(SUITE_MNEMONIC.split())


class Expect:
    """Target outcome when a vector is fed to embit + PSBTParser."""

    # Parses cleanly; the review screens must render it accurately.
    PARSES = "parses"

    # embit's PSBT.parse() refuses the bytes outright.
    REJECT_EMBIT = "reject_embit"

    # embit accepts the bytes but PSBTParser must refuse with InvalidPSBTError.
    REJECT_PARSER = "reject_parser"


class RejectCode:
    """
    Why PSBTParser refused a transaction. Carried on `InvalidPSBTError.code` so
    tests can assert the *reason* for a rejection, not merely that one happened.
    """

    MIXED_INPUTS = "MIXED_INPUTS"
    MISSING_UTXO = "MISSING_UTXO"
    NEGATIVE_FEE = "NEGATIVE_FEE"
    AMOUNT_OUT_OF_RANGE = "AMOUNT_OUT_OF_RANGE"
    INVALID_WITNESS_UTXO = "INVALID_WITNESS_UTXO"
    EXTRANEOUS_WITNESS_SCRIPT = "EXTRANEOUS_WITNESS_SCRIPT"
    UTXO_MISMATCH = "UTXO_MISMATCH"
    SCRIPT_HASH_MISMATCH = "SCRIPT_HASH_MISMATCH"
    UNREACHABLE_CHANGE_PATH = "UNREACHABLE_CHANGE_PATH"
    NONZERO_OP_RETURN = "NONZERO_OP_RETURN"
    UNSUPPORTED_SIGHASH = "UNSUPPORTED_SIGHASH"
    CHANGE_INDEX_TOO_FAR = "CHANGE_INDEX_TOO_FAR"
    UNSUPPORTED_PSBT_VERSION = "UNSUPPORTED_PSBT_VERSION"
    UNDISPLAYABLE_OUTPUT = "UNDISPLAYABLE_OUTPUT"


class Advisory:
    """
    Risk codes a secure signer must raise for review, without necessarily
    refusing the transaction. Populated by `PSBTParser.risk_warnings`.
    """

    HIGH_FEE = "HIGH_FEE"
    DUST_OUTPUT = "DUST_OUTPUT"
    FUTURE_LOCKTIME = "FUTURE_LOCKTIME"
    RELATIVE_TIMELOCK = "RELATIVE_TIMELOCK"
    LOCKTIME_FAR_FUTURE = "LOCKTIME_FAR_FUTURE"
    RBF = "RBF"


# Fee at or above this fraction of the input total is flagged HIGH_FEE.
HIGH_FEE_NUMERATOR = 1
HIGH_FEE_DENOMINATOR = 10

# Outputs below this many sats are flagged DUST_OUTPUT.
DUST_THRESHOLD = 546

# How far above the highest index seen on the inputs a change output may sit
# before LARGE_CHANGE_INDEX fires. Mirrors the shipped default of the
# "Change Gap Limit" setting.
CHANGE_INDEX_LOOKAHEAD = 100


@dataclass
class Vector:
    name: str
    category: str
    trap: str
    expect: str

    # Ground truth read straight off the unsigned tx, independent of PSBTParser.
    # None when the vector never gets far enough to have them.
    input_amount: Optional[int] = None
    output_amount: Optional[int] = None       # sum of ALL outputs, OP_RETURN included
    op_return_amount: int = 0
    num_outputs: Optional[int] = None

    # How many outputs a correct signer may attribute to the signing seed.
    owned_outputs: Optional[int] = None

    # Risk codes that must fire (only meaningful when expect == PARSES).
    advisories: frozenset = field(default_factory=frozenset)

    # Which RejectCode PSBTParser must raise (only when expect == REJECT_PARSER).
    reject_code: Optional[str] = None

    # True when the vector's shipped bytes do not actually encode the trap its
    # upstream README describes; kept as a regression fixture regardless.
    vacuous: bool = False

    @property
    def fee_amount(self) -> Optional[int]:
        if self.input_amount is None or self.output_amount is None:
            return None
        return self.input_amount - self.output_amount

    @property
    def path(self) -> str:
        return os.path.join(DATA_DIR, self.name + ".psbt")


VECTORS = [
    # ------------------------------------------------------------------ normal
    Vector(
        "NORMAL-1_p2wpkh", "normal",
        "Standard 1-in/2-out native segwit at m/84h/0h/0h. Must sign cleanly.",
        Expect.PARSES,
        input_amount=100_000_000, output_amount=99_990_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "NORMAL-2_wrapped", "normal",
        "Standard wrapped segwit (P2SH-P2WPKH) at m/49h/0h/0h. Must sign cleanly. "
        "Its outputs carry a bogus redeem_script, which must not break parsing.",
        Expect.PARSES,
        input_amount=100_000_000, output_amount=99_990_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "NORMAL-3_legacy", "normal",
        "Standard legacy P2PKH at m/44h/0h/0h. Must sign cleanly.",
        Expect.PARSES,
        input_amount=100_000_000, output_amount=99_990_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "NORMAL-4_multi_input", "normal",
        "3-in/2-out native segwit. Must sign cleanly, all three inputs.",
        Expect.PARSES,
        input_amount=300_000_000, output_amount=299_990_000, num_outputs=2, owned_outputs=1,
    ),

    # ----------------------------------------------------------------- binding
    Vector(
        "TX-01", "binding",
        "Extra non-hardened level spliced into the change path "
        "(m/84h/0h/0h/127/1/0). path[-2]==1 so a naive check labels it change, but "
        "the depth is 6 and the funds fall outside the wallet's 5-level scanner.",
        Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=99_000, num_outputs=2,
        reject_code=RejectCode.UNREACHABLE_CHANGE_PATH,
    ),
    Vector(
        "TX-06.depth6", "binding",
        "Six-level change path. Same trap as TX-01: depth must be pinned.",
        Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=99_000, num_outputs=2,
        reject_code=RejectCode.UNREACHABLE_CHANGE_PATH,
    ),
    Vector(
        "TX-06.branch127", "binding",
        "Change branch 127 instead of {0,1}. Not reachable by any standard scanner.",
        Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=99_000, num_outputs=2,
        reject_code=RejectCode.UNREACHABLE_CHANGE_PATH,
    ),
    Vector(
        "TX-18", "binding",
        "Non-hardened account slot (m/84h/0h/0h/0/1/0/0) — cross-account splice.",
        Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=99_000, num_outputs=2,
        reject_code=RejectCode.UNREACHABLE_CHANGE_PATH,
    ),
    Vector(
        "TX-17", "binding",
        "Change index 99,999, against inputs at index 0. The path is structurally "
        "valid, so this is a threshold rather than an impossibility — which is why "
        "the Change Gap Limit is adjustable.",
        Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=99_000, num_outputs=2,
        reject_code=RejectCode.CHANGE_INDEX_TOO_FAR,
    ),
    Vector(
        "TX-03.bare", "binding",
        "Segwit input with witness_utxo only, no non_witness_utxo. Legal under "
        "BIP-143 and accepted by every signer; kept as the control for fee_inflate.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "TX-03.fee_inflate", "binding",
        "witness_utxo.amount lowered to 20,000 while outputs still total 199,000. "
        "Implied fee is negative — arithmetically impossible.",
        Expect.REJECT_PARSER,
        input_amount=20_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.NEGATIVE_FEE,
    ),
    Vector(
        "TX-12", "binding",
        "Declares PSBT_GLOBAL_VERSION 2 (BIP-370) while still carrying a v0 "
        "unsigned tx, and leaves PSBT_GLOBAL_TX_MODIFIABLE set. Reading it as v0 "
        "means silently discarding every v2 field, including the one saying what "
        "a coordinator may still change after we sign.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.UNSUPPORTED_PSBT_VERSION,
    ),
    Vector(
        "TX-14.cross_net", "binding",
        "Mainnet chain params with testnet-labeled derivation.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=1,
        vacuous=True,  # shipped derivation is m/84h/0h/0h — mainnet coin type, nothing crossed
    ),
    Vector(
        "TX-16.foreign_fingerprint", "binding",
        "Output bip32_derivation with a foreign master fingerprint and an "
        "unparseable pubkey.",
        Expect.REJECT_EMBIT,
    ),
    Vector(
        "TX-16.global_xpub_injected", "binding",
        "Injected PSBT_GLOBAL_XPUB claiming a foreign xpub is ours. Ownership must "
        "be decided by re-derivation from the seed, never by a PSBT-supplied xpub.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "TX-16.unknown_field", "binding",
        "Unknown proprietary field ('OWNERSHIP_HINT: trust_me') offered as an "
        "ownership decision. Must be ignored.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "TX-09.attacker_internal_key", "binding",
        "p2tr change with an attacker-supplied internal key.",
        Expect.REJECT_EMBIT,
    ),
    Vector(
        "TX-09.hidden_taptree", "binding",
        "p2tr change with an unverifiable taptree leaf.",
        Expect.REJECT_EMBIT,
    ),

    # ------------------------------------------------------------------ crypto
    Vector(
        "TX-07", "crypto",
        "SIGHASH_SINGLE with no output at the input's index. Signing would commit "
        "to the SIGHASH_SINGLE bug value. All 100,000 sats go to fee.",
        Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=0, num_outputs=0,
        reject_code=RejectCode.UNSUPPORTED_SIGHASH,
    ),
    Vector(
        "TX-08.SINGLE", "crypto", "SIGHASH_SINGLE.", Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=99_000, num_outputs=2,
        reject_code=RejectCode.UNSUPPORTED_SIGHASH,
    ),
    Vector(
        "TX-08.SINGLE_ACP", "crypto", "SIGHASH_SINGLE|ANYONECANPAY.", Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=99_000, num_outputs=2,
        reject_code=RejectCode.UNSUPPORTED_SIGHASH,
    ),
    Vector(
        "TX-08.NONE", "crypto", "SIGHASH_NONE — signs no outputs at all.", Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=99_000, num_outputs=2,
        reject_code=RejectCode.UNSUPPORTED_SIGHASH,
    ),
    Vector(
        "TX-08.NONE_ACP", "crypto", "SIGHASH_NONE|ANYONECANPAY.", Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=99_000, num_outputs=2,
        reject_code=RejectCode.UNSUPPORTED_SIGHASH,
    ),
    Vector(
        "TX-08.ANYONECANPAY", "crypto", "SIGHASH_ANYONECANPAY.", Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=99_000, num_outputs=2,
        reject_code=RejectCode.UNSUPPORTED_SIGHASH,
    ),

    # ---------------------------------------------------------------- coverage
    Vector(
        "TX-02", "coverage",
        "Value-bearing OP_RETURN (50,000 sats) escapes a branch-chain parser's "
        "accounting. Outputs exceed inputs, so the implied fee is negative.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=249_000, op_return_amount=50_000, num_outputs=3,
        reject_code=RejectCode.NONZERO_OP_RETURN,
    ),
    Vector(
        "XTRAS.OP_RETURN_BURN", "coverage",
        "Same shape as TX-02: meaningful value sent to a value-bearing OP_RETURN.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=249_000, op_return_amount=50_000, num_outputs=3,
        reject_code=RejectCode.NONZERO_OP_RETURN,
    ),
    Vector(
        "TX-10", "coverage",
        "Destination address ground to collide on the first 6 + last 6 characters "
        "with the change address, defeating truncated verification.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=1,
        vacuous=True,  # the shipped outputs share no visible prefix or suffix
    ),
    Vector(
        "TX-15.mismatch", "coverage",
        "Implied fee (1,000,000 on 10,000,000 in — 10%) is many multiples of what a "
        "coordinator would display. Fee must be recomputed on-device and flagged.",
        Expect.PARSES,
        input_amount=10_000_000, output_amount=9_000_000, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.HIGH_FEE}),
    ),

    # --------------------------------------------------------------- catalogue
    Vector(
        "TX-11.v0_bech32m", "catalogue",
        "v0 witness program encoded with bech32m.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=1,
        vacuous=True,  # a PSBT carries scriptPubKey bytes; the address encoding is display-layer
    ),
    Vector(
        "TX-11.v1_bech32", "catalogue",
        "v1+ witness program encoded with bech32 instead of bech32m.",
        Expect.REJECT_EMBIT,
        vacuous=True,
    ),

    # ------------------------------------------------------------------ extras
    Vector(
        "XTRAS.NEGATIVE_AMOUNT", "extras",
        "Output value 0xFFFFFFFFFFFFFFFF — far beyond MAX_MONEY. Must never reach "
        "the display as a real amount.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=18446744073709651615, num_outputs=2,
        # This vector also happens to declare PSBT_GLOBAL_VERSION 2, which is
        # refused before any amount is read -- an unsupported container format
        # means every value inside it is being misread, so there is nothing to
        # say about the amount yet. The AMOUNT_OUT_OF_RANGE path is still covered:
        # see test_amount_bound_still_fires_on_a_v0_psbt.
        reject_code=RejectCode.UNSUPPORTED_PSBT_VERSION,
    ),
    Vector(
        "XTRAS.NEGATIVE_FEE", "extras",
        "sum(outputs) > sum(inputs) — mathematically impossible fee.",
        Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=299_000, num_outputs=2,
        reject_code=RejectCode.NEGATIVE_FEE,
    ),
    Vector(
        "XTRAS.MIXED_INPUT_TYPES", "extras",
        "One p2wpkh and one p2pkh input in the same transaction.",
        Expect.REJECT_PARSER,
        input_amount=400_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.MIXED_INPUTS,
    ),
    Vector(
        "XTRAS.WITNESS_UTXO_MISMATCH", "extras",
        "witness_utxo declares a p2pkh scriptPubKey — a segwit input's witness_utxo "
        "must carry a witness program.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        vacuous=True,  # no non_witness_utxo ships, so the real cross-check is untested here
        reject_code=RejectCode.INVALID_WITNESS_UTXO,
    ),
    Vector(
        "XTRAS.MISMATCHED_WITNESS_SCRIPT", "extras",
        "A 200-byte witness_script attached to a p2wpkh input, hashing to nothing.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.EXTRANEOUS_WITNESS_SCRIPT,
    ),
    Vector(
        "XTRAS.HUGE_FEE", "extras",
        "90% of the input value goes to the miner fee.",
        Expect.PARSES,
        input_amount=1_000_000, output_amount=100_000, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.HIGH_FEE}),
    ),
    Vector(
        "XTRAS.DUST_OUTPUT", "extras",
        "A 100-sat output, below the dust threshold (and 50% of the value to fee).",
        Expect.PARSES,
        input_amount=200_000, output_amount=100_100, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.DUST_OUTPUT, Advisory.HIGH_FEE}),
    ),
    Vector(
        "XTRAS.LOCKTIME_FUTURE", "extras",
        "nLocktime 2,000,000,000 — a unix timestamp in 2033.",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.FUTURE_LOCKTIME}),
    ),
    Vector(
        "XTRAS.RBF_SIGNAL", "extras",
        "nSequence 0xfdffffff — the transaction is replaceable.",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.RBF}),
    ),
    Vector(
        "XTRAS.NETWORK_HRP_MISMATCH", "extras",
        "Output address HRP does not match the active network.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=1,
        vacuous=True,  # the shipped output is an ordinary mainnet bc1q address
    ),
    Vector(
        "XTRAS.TRUNCATED_PSBT", "parser",
        "PSBT cut off mid-record.",
        Expect.REJECT_EMBIT,
    ),
]

VECTORS_BY_NAME = {v.name: v for v in VECTORS}

PARSING_VECTORS = [v for v in VECTORS if v.expect == Expect.PARSES]
REJECT_EMBIT_VECTORS = [v for v in VECTORS if v.expect == Expect.REJECT_EMBIT]
REJECT_PARSER_VECTORS = [v for v in VECTORS if v.expect == Expect.REJECT_PARSER]

NORMAL_VECTORS = [v for v in VECTORS if v.category == "normal"]

# Vectors whose sighash flag is anything other than SIGHASH_ALL; signing must be
# refused outright rather than producing a partial signature.
NON_SIGHASH_ALL_VECTORS = [v for v in VECTORS if v.category == "crypto"]


def load_bytes(name: str) -> bytes:
    """Raw fixture bytes, exactly as vendored."""
    with open(VECTORS_BY_NAME[name].path if name in VECTORS_BY_NAME
              else os.path.join(DATA_DIR, name + ".psbt"), "rb") as f:
        return f.read()


def load_base64(name: str) -> str:
    """Fixture as a base64 string, for feeding DecodeQR / ScanView in flow tests."""
    raw = load_bytes(name)
    if raw[:5] == b"psbt\xff":
        return b64encode(raw).decode()
    return raw.decode().strip()


def load_psbt(name: str) -> PSBT:
    """Parse a fixture with embit. Raises whatever embit raises."""
    raw = load_bytes(name)
    if raw[:5] == b"psbt\xff":
        return PSBT.parse(raw)
    return PSBT.parse(a2b_base64(raw.strip()))


def build_huge_witness_psbt(witness_bytes: int = 1_500_000) -> bytes:
    """
    Stand-in for the upstream XTRAS.HUGE_WITNESS_STACK vector, which ships as
    1.5 MB of incompressible witness data and is not worth vendoring.

    Takes NORMAL-1 and attaches an absurdly large final_scriptwitness, so the
    parser meets an unrealistic witness stack declaration without the repo
    carrying the payload.
    """
    from embit.psbt import PSBT as _PSBT
    from embit.script import Witness

    psbt = load_psbt("NORMAL-1_p2wpkh")
    psbt.inputs[0].final_scriptwitness = Witness([b"\x00" * witness_bytes])
    return _PSBT.parse(psbt.serialize()).serialize()


def build_nonzero_op_return_psbt() -> PSBT:
    """
    A well-formed transaction that nonetheless carries a value-bearing OP_RETURN.

    The shipped TX-02 / XTRAS.OP_RETURN_BURN vectors bundle two defects at once:
    the OP_RETURN carries value *and* the outputs exceed the inputs. That makes
    them useless for testing the accounting rule on its own, because the negative
    fee trips first. This variant keeps the value-bearing OP_RETURN but trims it
    so the fee stays positive.
    """
    psbt = load_psbt("TX-02")
    # Both PSBT.tx and OutputScope.vout are derived properties; the writable
    # field is OutputScope.value.
    for out in psbt.outputs:
        if out.script_pubkey.data and out.script_pubkey.data[0] == 0x6A:  # OP_RETURN
            out.value = 500
    return PSBT.parse(psbt.serialize())


def build_utxo_mismatch_psbt() -> PSBT:
    """
    An input carrying BOTH witness_utxo and non_witness_utxo, where the
    witness_utxo is not the real prevout — the actual BIP-143 amount-binding
    attack, and the one thing the shipped XTRAS.WITNESS_UTXO_MISMATCH vector
    does not test (no vector in the corpus ships a non_witness_utxo alongside a
    witness_utxo, so there is nothing to cross-check against).

    Built from NORMAL-3, which carries a full previous transaction, with a
    well-formed but false witness_utxo grafted on: it *is* a witness program, so
    it clears the structural checks and can only be caught by comparing it
    against the real prevout.
    """
    from copy import deepcopy

    psbt = load_psbt("NORMAL-3_legacy")
    inp = psbt.inputs[0]
    assert inp.non_witness_utxo is not None, "NORMAL-3 is expected to ship a non_witness_utxo"

    donor = load_psbt("NORMAL-1_p2wpkh").inputs[0].witness_utxo
    lying_utxo = deepcopy(donor)
    # Inflate the value so the implied fee stays positive and the NEGATIVE_FEE
    # check cannot fire first, isolating the cross-check.
    lying_utxo.value = donor.value * 2
    inp.witness_utxo = lying_utxo
    return psbt
