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
    TX_MODIFIABLE = "TX_MODIFIABLE"
    UNDISPLAYABLE_OUTPUT = "UNDISPLAYABLE_OUTPUT"
    FORGED_OUTPUT_OWNERSHIP = "FORGED_OUTPUT_OWNERSHIP"
    FORGED_INPUT_OWNERSHIP = "FORGED_INPUT_OWNERSHIP"
    SEED_CANNOT_SIGN = "SEED_CANNOT_SIGN"
    SURPLUS_DERIVATIONS = "SURPLUS_DERIVATIONS"
    MISLABELED_OUTPUT_OWNERSHIP = "MISLABELED_OUTPUT_OWNERSHIP"
    MIXED_DERIVATION_MAPS = "MIXED_DERIVATION_MAPS"


class Advisory:
    """
    Risk codes a secure signer must raise for review, without necessarily
    refusing the transaction. Populated by `PSBTParser.risk_warnings`.
    """

    HIGH_FEE = "HIGH_FEE"
    HIGH_FEE_RATE = "HIGH_FEE_RATE"
    DUST_OUTPUT = "DUST_OUTPUT"
    FUTURE_LOCKTIME = "FUTURE_LOCKTIME"
    RELATIVE_TIMELOCK = "RELATIVE_TIMELOCK"
    SCRIPT_TIMELOCK = "SCRIPT_TIMELOCK"
    LOCKTIME_FAR_FUTURE = "LOCKTIME_FAR_FUTURE"
    RBF = "RBF"


# Fee-rate threshold the corpus expectations are written against. Pinned rather
# than read from settings: the shipped default tracks recent blocks via
# resources/latest-block.json, which a scheduled job rewrites, and the corpus
# must not change verdict because mempool conditions moved.
SUITE_MAX_FEE_RATE = 120

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
        "A spec-valid BIP-370 v2 psbt that leaves PSBT_GLOBAL_TX_MODIFIABLE = 0x03, "
        "so a coordinator may still add or remove inputs and outputs after we sign. "
        "The review screens would show one transaction while the signature authorises "
        "a different one -- refused as not final rather than merely warned about.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.TX_MODIFIABLE,
    ),
    Vector(
        "TX-14.cross_net", "binding",
        "Mainnet transaction whose input derivation is relabelled to coin type 1h "
        "(testnet) while the change stays at 0h. The input key is really our 0h key, "
        "so the 1h claim is false -- refused as forged rather than by a network rule.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.FORGED_INPUT_OWNERSHIP,
    ),
    Vector(
        "TX-16.foreign_fingerprint", "binding",
        "Output bip32_derivation with a foreign master fingerprint. A foreign "
        "fingerprint only means 'not claimed as ours': the output is shown as an "
        "external payment, and ownership of the real change is still decided by "
        "re-derivation.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=1,
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
        "p2tr change with an attacker-supplied internal key. Must not be labelled "
        "change: the output key cannot be rebuilt from anything this seed derives.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=0,
    ),
    Vector(
        "TX-09.hidden_taptree", "binding",
        "p2tr change with an unverifiable taptree leaf. Must not be labelled change.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=0,
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
        "Destination copies the first program bytes of the change output, so both "
        "addresses share the HRP and leading characters and differ in the middle. "
        "A display-layer trap: only full-address rendering catches it.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "TX-15.mismatch", "coverage",
        "Implied fee (1,000,000 on 10,000,000 in — 10%) is many multiples of what a "
        "coordinator would display. Fee must be recomputed on-device and flagged.",
        Expect.PARSES,
        input_amount=10_000_000, output_amount=9_000_000, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.HIGH_FEE, Advisory.HIGH_FEE_RATE}),
    ),

    # --------------------------------------------------------------- catalogue
    Vector(
        "TX-11.v0_bech32m", "catalogue",
        "A wrong-variant (bech32m) address string for a v0 output planted in a "
        "non-standard global field. Display addresses must be re-derived from the "
        "scriptPubKey, never read from the psbt.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "TX-11.v1_bech32", "catalogue",
        "The v1/taproot counterpart: a bech32 (not bech32m) address string planted "
        "in a non-standard global field.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=0,
    ),

    # ------------------------------------------------------------------ extras
    Vector(
        "XTRAS.NEGATIVE_AMOUNT", "extras",
        "Output value 0xFFFFFFFFFFFFFFFF — far beyond MAX_MONEY. Must never reach "
        "the display as a real amount.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=18446744073709651615, num_outputs=2,
        # This vector is a spec-valid BIP-370 v2 psbt (version 2), so it now passes
        # the version gate and is refused at the amount bound instead: an output past
        # MAX_MONEY cannot be displayed or signed. See _assert_v2_complete, which
        # catches it before any value is trusted for display.
        reject_code=RejectCode.AMOUNT_OUT_OF_RANGE,
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
        # No non_witness_utxo ships, so the real cross-check is left to
        # XTRAS.WITNESS_NONWITNESS_MISMATCH.
        vacuous=True,
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
        advisories=frozenset({Advisory.HIGH_FEE, Advisory.HIGH_FEE_RATE}),
    ),
    Vector(
        "XTRAS.DUST_OUTPUT", "extras",
        "A 100-sat output, below the dust threshold (and 50% of the value to fee).",
        Expect.PARSES,
        input_amount=200_000, output_amount=100_100, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.DUST_OUTPUT, Advisory.HIGH_FEE, Advisory.HIGH_FEE_RATE}),
    ),
    Vector(
        # Dropped upstream in favour of TX-19.timestamp_future; kept as a local
        # fixture because TestTimelocks mutates it.
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
        "Two inputs claiming different networks: input 0 at coin type 0h, input 1 "
        "relabelled to 1h. scriptPubKeys carry no network, so the coin type is the "
        "only cross-network signal -- and input 1's key is really our 0h key, so the "
        "claim is false.",
        Expect.REJECT_PARSER,
        input_amount=400_000, output_amount=399_000, num_outputs=2,
        reject_code=RejectCode.FORGED_INPUT_OWNERSHIP,
    ),
    Vector(
        "XTRAS.TRUNCATED_PSBT", "parser",
        "PSBT cut off mid-record.",
        Expect.REJECT_EMBIT,
    ),

    # ------------------------------------------------- BIP-370 (v2) twins
    # The v2 counterparts of the vectors above: same traps, carried in a spec-valid
    # BIP-370 container whose inputs/outputs are described by their own fields rather
    # than an embedded unsigned tx. They must be accepted and judged exactly like
    # their v0 twins -- the version is not a reason to refuse or to misread them.

    Vector(
        "NORMAL-1_p2wpkh_V2", "normal",
        "BIP-370 v2 twin of NORMAL-1: standard 1-in/2-out native segwit at m/84h/0h/0h, "
        "described by per-input/per-output fields. Must parse and sign cleanly.",
        Expect.PARSES,
        input_amount=100_000_000, output_amount=99_990_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "NORMAL-2_wrapped_V2", "normal",
        "BIP-370 v2 twin of NORMAL-2: wrapped segwit (P2SH-P2WPKH) at m/49h/0h/0h. "
        "Must parse and sign cleanly.",
        Expect.PARSES,
        input_amount=100_000_000, output_amount=99_990_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "NORMAL-3_legacy_V2", "normal",
        "BIP-370 v2 twin of NORMAL-3: legacy P2PKH at m/44h/0h/0h, carrying a full "
        "non_witness_utxo. Must parse and sign cleanly.",
        Expect.PARSES,
        input_amount=100_000_000, output_amount=99_990_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "NORMAL-4_multi_input_V2", "normal",
        "BIP-370 v2 twin of NORMAL-4: 3-in/2-out native segwit. Must parse and sign "
        "cleanly, all three inputs.",
        Expect.PARSES,
        input_amount=300_000_000, output_amount=299_990_000, num_outputs=2, owned_outputs=1,
    ),

    Vector(
        "TX-03.fee_inflate_V2", "binding",
        "BIP-370 v2 twin of TX-03.fee_inflate: witness_utxo amount lowered to 20,000 "
        "while outputs still total 199,000. Implied fee is negative -- impossible.",
        Expect.REJECT_PARSER,
        input_amount=20_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.NEGATIVE_FEE,
    ),
    Vector(
        "XTRAS.NEGATIVE_FEE_V2", "extras",
        "BIP-370 v2 twin of XTRAS.NEGATIVE_FEE: sum(outputs) > sum(inputs).",
        Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=299_000, num_outputs=2,
        reject_code=RejectCode.NEGATIVE_FEE,
    ),
    Vector(
        "XTRAS.OP_RETURN_BURN_V2", "coverage",
        "BIP-370 v2 twin of XTRAS.OP_RETURN_BURN: meaningful value sent to a "
        "value-bearing OP_RETURN.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=249_000, op_return_amount=50_000, num_outputs=3,
        reject_code=RejectCode.NONZERO_OP_RETURN,
    ),
    Vector(
        "XTRAS.HUGE_FEE_V2", "extras",
        "BIP-370 v2 twin of XTRAS.HUGE_FEE: 90% of the input value goes to the miner fee.",
        Expect.PARSES,
        input_amount=1_000_000, output_amount=100_000, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.HIGH_FEE, Advisory.HIGH_FEE_RATE}),
    ),
    Vector(
        "TX-19.relative_time_V2", "extras",
        "BIP-370 v2 transaction with a BIP-68 relative timelock in nSequence. The "
        "sequence is also below the RBF ceiling, so both must be surfaced -- "
        "'replaceable' alone understates a long lock.",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.RBF, Advisory.RELATIVE_TIMELOCK}),
    ),
    Vector(
        "TX-19.height_far_V2", "extras",
        "BIP-370 v2 transaction with a block-height nLockTime far in the future. With "
        "no block anchor it parses as an ordinary spend; dated against an anchor it is "
        "flagged LOCKTIME_FAR_FUTURE (see TestPSBTv2).",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
    ),

    # ------------------------------------------------------ structural (XTRAS)
    Vector(
        "XTRAS.MISSING_UTXO", "extras",
        "The sole input carries neither witness_utxo nor non_witness_utxo: no "
        "amount, no script, nothing to sign against.",
        Expect.REJECT_PARSER,
        reject_code=RejectCode.MISSING_UTXO,
    ),
    Vector(
        "XTRAS.MISSING_UTXO_V2", "extras",
        "BIP-370 twin of XTRAS.MISSING_UTXO: a v2 input naming its prevout but "
        "carrying no utxo.",
        Expect.REJECT_PARSER,
        reject_code=RejectCode.MISSING_UTXO,
    ),
    Vector(
        "XTRAS.V2_MISSING_PREVOUT", "extras",
        "A v2 input with a witness_utxo but no previous_txid / output_index. "
        "BIP-370 requires the outpoint; without it there is no transaction to sign.",
        Expect.REJECT_PARSER,
        reject_code=RejectCode.MISSING_UTXO,
    ),
    Vector(
        "XTRAS.UNSUPPORTED_PSBT_VERSION", "extras",
        "A v0 psbt declaring PSBT_GLOBAL_VERSION 1, which BIP-370 reserves.",
        Expect.REJECT_PARSER,
        reject_code=RejectCode.UNSUPPORTED_PSBT_VERSION,
    ),
    Vector(
        "XTRAS.UNSUPPORTED_PSBT_VERSION_V2", "extras",
        "A structurally complete v2 psbt declaring version 3, which is undefined.",
        Expect.REJECT_PARSER,
        reject_code=RejectCode.UNSUPPORTED_PSBT_VERSION,
    ),
    Vector(
        "XTRAS.ANYONE_CAN_SPEND_OUTPUT", "extras",
        "The spend output pays witness version 2: no address form, and "
        "anyone-can-spend until a soft fork defines it.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.UNDISPLAYABLE_OUTPUT,
    ),
    Vector(
        "XTRAS.ANYONE_CAN_SPEND_OUTPUT_V2", "extras",
        "BIP-370 twin of XTRAS.ANYONE_CAN_SPEND_OUTPUT.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.UNDISPLAYABLE_OUTPUT,
    ),
    Vector(
        "XTRAS.BARE_MULTISIG_OUTPUT", "extras",
        "The spend output is a bare 2-of-2 multisig script, which has no address "
        "and so cannot be reviewed.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.UNDISPLAYABLE_OUTPUT,
    ),
    Vector(
        "XTRAS.BARE_MULTISIG_OUTPUT_V2", "extras",
        "BIP-370 twin of XTRAS.BARE_MULTISIG_OUTPUT.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.UNDISPLAYABLE_OUTPUT,
    ),
    Vector(
        "XTRAS.WITNESS_NONWITNESS_MISMATCH", "extras",
        "An input ships both utxo forms and they disagree (100,000 vs 200,000 sats, "
        "different scripts) -- the BIP-143 amount-binding attack.",
        Expect.REJECT_PARSER,
        num_outputs=2,
        reject_code=RejectCode.UTXO_MISMATCH,
    ),

    # --------------------------------------------------------------- timelocks
    Vector(
        "TX-19.timestamp_future", "extras",
        "nLocktime 2,000,000,000 (~2033) with a non-final input: unconfirmable until then.",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.FUTURE_LOCKTIME}),
    ),
    Vector(
        "TX-19.height_far", "extras",
        "Block-height nLockTime ~4 years out. With no block anchor it parses as an "
        "ordinary spend, like its v2 twin.",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "TX-19.height_near", "extras",
        "Negative control: nLockTime at the chain tip (anti-fee-sniping). Normal; "
        "must not warn.",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "TX-19.inert", "extras",
        "Negative control: far-future nLockTime with every input final, so the "
        "locktime is not enforced. Must not warn.",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "TX-19.relative_blocks", "extras",
        "BIP-68 block-based relative timelock (0x0000ffff, ~15 months).",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.RBF, Advisory.RELATIVE_TIMELOCK}),
    ),
    Vector(
        "TX-19.relative_time", "extras",
        "BIP-68 time-based relative timelock (512-second units, ~24 days).",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.RBF, Advisory.RELATIVE_TIMELOCK}),
    ),
    Vector(
        "TX-19.relative_rbf_masquerade", "extras",
        "Same bytes as relative_blocks, presented as mere RBF. 'Replaceable' alone "
        "would hide a ~15-month hold.",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.RBF, Advisory.RELATIVE_TIMELOCK}),
    ),
    Vector(
        "TX-20.cltv_time", "coverage",
        "A P2SH output whose redeem script is CLTV-locked until ~2033. Consensus "
        "rejects any earlier spend of those funds; the address alone hides it.",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
        advisories=frozenset({Advisory.SCRIPT_TIMELOCK}),
    ),
    Vector(
        "TX-20.cltv_height", "coverage",
        "Meant as a CLTV-locked P2WSH output.",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
        # The shipped scriptPubKey is still a p2wpkh; the CLTV witness script is
        # attached but not committed, so there is correctly nothing to flag.
        vacuous=True,
    ),
    Vector(
        "TX-20.csv_relative", "coverage",
        "Meant as a CSV-locked P2WSH output.",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
        vacuous=True,  # same upstream defect as TX-20.cltv_height
    ),

    # --------------------------------------------------------------- ownership
    Vector(
        "TX-21.claims_us_pays_other", "ownership",
        "Change annotated with one of our genuine keys and paths, but the script "
        "pays a stranger. The key re-derives; the output is not locked to it.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.FORGED_OUTPUT_OWNERSHIP,
    ),
    Vector(
        "TX-21.claims_us_pays_other_V2", "ownership",
        "BIP-370 twin of TX-21.claims_us_pays_other.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.FORGED_OUTPUT_OWNERSHIP,
    ),
    Vector(
        "TX-21.pays_us_claims_other", "ownership",
        "Change pays our key but is annotated with a foreign fingerprint. The "
        "funds are ours, but the psbt misdescribes who owns its outputs, which is "
        "refused just like the opposite lie.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.MISLABELED_OUTPUT_OWNERSHIP,
    ),
    Vector(
        "TX-21.pays_us_claims_other_V2", "ownership",
        "BIP-370 twin of TX-21.pays_us_claims_other.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.MISLABELED_OUTPUT_OWNERSHIP,
    ),
    Vector(
        "TX-21.taproot_claims_other", "ownership",
        "P2TR change paying our internal key but claiming a foreign fingerprint.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.MISLABELED_OUTPUT_OWNERSHIP,
    ),
    Vector(
        "TX-22.surplus_paths", "ownership",
        "A single-sig output naming two of our keys. Only one can be the key the "
        "script pays; the other is a decoy for a first-entry-only checker.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.SURPLUS_DERIVATIONS,
    ),
    Vector(
        "TX-22.taproot_surplus_internal_key", "ownership",
        "A P2TR output claiming two internal keys; a taproot output has one.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.SURPLUS_DERIVATIONS,
    ),
    Vector(
        "TX-22.mixed_path_maps", "ownership",
        "An output scope naming us in both the ecdsa and taproot derivation maps.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.MIXED_DERIVATION_MAPS,
    ),
    Vector(
        "TX-22.mixed_path_maps_input", "ownership",
        "The input-side variant of TX-22.mixed_path_maps.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.MIXED_DERIVATION_MAPS,
    ),
    Vector(
        "TX-23.forged_output_claim", "ownership",
        "Change claims our fingerprint at a plausible change path, on a key we do "
        "not derive.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.FORGED_OUTPUT_OWNERSHIP,
    ),
    Vector(
        "TX-23.forged_output_claim_V2", "ownership",
        "BIP-370 twin of TX-23.forged_output_claim.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.FORGED_OUTPUT_OWNERSHIP,
    ),
    Vector(
        "TX-23.forged_taproot_claim", "ownership",
        "P2TR change claiming our fingerprint on an internal key we do not derive.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.FORGED_OUTPUT_OWNERSHIP,
    ),
    Vector(
        "TX-23.forged_input_claim", "ownership",
        "An extra input derivation naming our fingerprint on a foreign key, "
        "alongside the genuine one.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.FORGED_INPUT_OWNERSHIP,
    ),
    Vector(
        "TX-23.forged_input_claim_V2", "ownership",
        "BIP-370 twin of TX-23.forged_input_claim.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.FORGED_INPUT_OWNERSHIP,
    ),

    # ---------------------------------------------------------------- multisig
    # Built against the suite's 2-of-3 wallet (MULTISIG_DESCRIPTOR). Parsed with
    # the seed alone, as the flow does before a descriptor is loaded; the
    # descriptor checks are in TestMultisigPolicy.
    Vector(
        "TX-04", "multisig",
        "Mixed input script types in a multisig flow, carrying an invalid pubkey.",
        Expect.REJECT_EMBIT,
    ),
    Vector(
        "TX-13.duplicate", "multisig",
        "Duplicated cosigner key: nominally 2-of-3, effectively 2-of-2.",
        Expect.REJECT_EMBIT,
    ),
    Vector(
        "TX-13.substitute", "multisig",
        "One cosigner key swapped for an attacker's; ours is gone from the inputs.",
        Expect.REJECT_PARSER,
        input_amount=100_000, output_amount=99_000, num_outputs=2,
        reject_code=RejectCode.SEED_CANNOT_SIGN,
    ),
    Vector(
        "TX-13.threshold", "multisig",
        "Change script reduced to 1-of-3. Only a registered descriptor can tell.",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "TX-13.reorder", "multisig",
        "Cosigner keys reordered, which breaks sortedmulti. Only a registered "
        "descriptor can tell.",
        Expect.PARSES,
        input_amount=100_000, output_amount=99_000, num_outputs=2, owned_outputs=1,
    ),
    Vector(
        "TX-05", "multisig",
        "Multisig change built from attacker-only xpubs. Must not be labelled change.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=0,
    ),
    Vector(
        "TX-21.honest_foreign_annotated_spend", "multisig",
        "Negative control: an honest payment to a stranger's M-of-N, fully "
        "annotated with their keys. An external payment, not an attack.",
        Expect.PARSES,
        input_amount=200_000, output_amount=199_000, num_outputs=2, owned_outputs=0,
    ),
    Vector(
        "TX-21.ms_fp_relabeled", "multisig",
        "Genuine multisig change with our cosigner entry relabelled to a foreign "
        "fingerprint: our key, attributed to another wallet.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.MISLABELED_OUTPUT_OWNERSHIP,
    ),
    Vector(
        "TX-21.ms_repointed_keys", "multisig",
        "Change witness script swapped for a stranger's M-of-N while our "
        "derivation entry stays: the script no longer contains our key.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.FORGED_OUTPUT_OWNERSHIP,
    ),
    Vector(
        "TX-21.ms_repointed_spk", "multisig",
        "Change scriptPubKey repointed while the supplied witness script stays "
        "ours: the script no longer hashes to the output.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.FORGED_OUTPUT_OWNERSHIP,
    ),
    Vector(
        "TX-22.ms_decoy_first", "multisig",
        "Genuine multisig change with a decoy entry of ours listed first.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.FORGED_OUTPUT_OWNERSHIP,
    ),
    Vector(
        "TX-22.ms_decoy_last", "multisig",
        "The same decoy listed last, which a first-match check never reaches.",
        Expect.REJECT_PARSER,
        input_amount=200_000, output_amount=199_000, num_outputs=2,
        reject_code=RejectCode.FORGED_OUTPUT_OWNERSHIP,
    ),
]

VECTORS_BY_NAME = {v.name: v for v in VECTORS}

PARSING_VECTORS = [v for v in VECTORS if v.expect == Expect.PARSES]
REJECT_EMBIT_VECTORS = [v for v in VECTORS if v.expect == Expect.REJECT_EMBIT]
REJECT_PARSER_VECTORS = [v for v in VECTORS if v.expect == Expect.REJECT_PARSER]

NORMAL_VECTORS = [v for v in VECTORS if v.category == "normal"]

MULTISIG_VECTORS = [v for v in VECTORS if v.category == "multisig"]

# The suite's 2-of-3 wallet, from psbt_test_suite/test_vectors.json ("multisig").
# The corpus seed is the 73c5da0a cosigner.
MULTISIG_DESCRIPTOR = (
    "wsh(sortedmulti(2,"
    "[73c5da0a/48h/0h/0h/2h]xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/<0;1>/*,"
    "[28645006/48h/0h/0h/2h]xpub6DnEBNkSJKBYQmsbhS1sP9cNdtU5c9PLFGCjTJmxicxc13WB8zNNGQazabQpyFAGW5bV9tMko4uBxDxjUKL6dSAcx1tEbgEHtgSqyRsekh6/<0;1>/*,"
    "[3f635a63/48h/0h/0h/2h]xpub6FHZCoNb3tg3o1GAJQxSwgFNF8mLRtTk2GgkF7n5rwzoxBhUEdFWa8cyZRHqytAzKZWsKz8627cQEMCCfR5GDSv6yXegqirpgDUX41Pxybr/<0;1>/*"
    "))"
)

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
