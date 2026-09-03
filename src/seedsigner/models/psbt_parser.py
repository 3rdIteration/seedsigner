from __future__ import annotations

import logging
import time
from binascii import hexlify
from embit import psbt, script, ec, bip32
from embit.base import EmbitError
from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath, InputScope, OutputScope
from embit.ec import PublicKey
from io import BytesIO
from typing import List

from seedsigner.models.seed import Seed
from seedsigner.models.wif import WIFKey
from seedsigner.models.settings import SettingsConstants

logger = logging.getLogger(__name__)

class OPCODES:
    OP_RETURN = 106
    OP_PUSHDATA1 = 76


# Consensus ceiling on any single amount, in sats.
MAX_MONEY = 21_000_000 * 100_000_000

# Outputs below this are uneconomic to spend and are flagged for review.
DUST_THRESHOLD = 546

# Fee at or above input_amount * HIGH_FEE_NUMERATOR / HIGH_FEE_DENOMINATOR is flagged.
HIGH_FEE_NUMERATOR = 1
HIGH_FEE_DENOMINATOR = 10

# How far above the highest index seen on the inputs a change output may sit
# before it is flagged. Every input is a utxo the wallet already found, so the
# highest index among them shows roughly how far its scanner has walked; change
# is normally issued at the next unused index. Overridable via
# SETTING__CHANGE_INDEX_LOOKAHEAD; 0 disables the check.
DEFAULT_CHANGE_INDEX_LOOKAHEAD = 100

# nLocktime values at or above this are unix timestamps rather than block heights.
LOCKTIME_TIMESTAMP_THRESHOLD = 500_000_000

# nSequence below this signals opt-in RBF (BIP-125).
RBF_SEQUENCE_CEILING = 0xFFFFFFFE

# A sequence of 0xffffffff is "final": it opts the input out of both BIP-125
# replaceability and BIP-68 relative timelocks, and leaves nLockTime unenforced.
SEQUENCE_FINAL = 0xFFFFFFFF

# BIP-68: bit 31 set disables the relative timelock; the low 16 bits carry the
# delay, in blocks or in 512-second units depending on bit 22.
SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
SEQUENCE_LOCKTIME_MASK = 0x0000FFFF

# How far past the reference time a locktime must sit before it is treated as
# abusive rather than merely unusual. Legitimate long timelocks exist (vaults,
# inheritance), but the user who set one up knows about it.
FAR_FUTURE_LOCKTIME_SECONDS = 2 * 365 * 24 * 60 * 60

# The only sighash flags that commit to the whole transaction. SIGHASH_DEFAULT
# (0x00) is taproot's spelling of SIGHASH_ALL (BIP-341) and is valid only there.
SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01


class RiskWarning:
    """
    Conditions worth showing the user before they approve. Unlike RejectCode
    these do not block signing; they are surfaced for review.
    """

    HIGH_FEE = "HIGH_FEE"
    HIGH_FEE_RATE = "HIGH_FEE_RATE"
    DUST_OUTPUT = "DUST_OUTPUT"
    FUTURE_LOCKTIME = "FUTURE_LOCKTIME"
    LOCKTIME_FAR_FUTURE = "LOCKTIME_FAR_FUTURE"
    RELATIVE_TIMELOCK = "RELATIVE_TIMELOCK"
    RBF = "RBF"

    # Recorded, but not worth interrupting the user for. Opt-in RBF is the
    # default in every modern coordinator; an interstitial on every ordinary
    # transaction just teaches people to click past the ones that matter.
    # Shown on the approval screen instead -- see PSBTFinalizeScreen.
    INFORMATIONAL = frozenset({RBF})


class RejectCode:
    """
    Why a psbt was refused. See `InvalidPSBTError`.

    These are the constructions with no innocent explanation -- a psbt is only
    built this way to make the review screens say something other than what the
    signature will actually authorise. Conditions that are merely unusual, and
    that an honest coordinator might legitimately produce, belong in
    `RiskWarning` instead, where they are shown but do not block.
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

    # An output scope claims this seed's fingerprint on a key the seed does not
    # derive. This is not a psbt that merely fails to be ours. A fingerprint is
    # coordinator-supplied metadata, so this is a psbt asserting that a key
    # belongs to this seed when it does not. On an output that assertion is how a
    # fake change output is dressed up as the user's own, so it is treated as an
    # attack.
    FORGED_OUTPUT_OWNERSHIP = "FORGED_OUTPUT_OWNERSHIP"

    # The same false claim, but on an input, where the threat picture inverts. A
    # forged input claim has no path to losing funds: it cannot produce a
    # signature (embit re-derives the real key and refuses on a mismatch), and it
    # cannot alter the amounts, the fee, or how outputs are classified. The likely
    # causes are instead a psbt assembled for a different wallet, a corrupted
    # entry, or a collaborative spend that happens to include a key whose 4-byte
    # fingerprint collides with ours (1 in 2^32 chance).
    #
    # The psbt still fails, deliberately, following embit's lead: sign_with raises
    # on this same condition and abandons the entire signing pass, so tolerating
    # the entry here would only defer the failure to a worse spot. Changing this
    # behavior, if desired, should happen in embit first. Until then the trade-off
    # is accepted: a collaborative-spend counterparty could grief such a
    # transaction into unsignability.
    FORGED_INPUT_OWNERSHIP = "FORGED_INPUT_OWNERSHIP"

    # The selected seed holds no key that could sign any input. Alone among these
    # codes this is a mismatch rather than a refusal of the psbt: the usual cause
    # is the user picking the wrong seed. It is raised so the flow can say so up
    # front, instead of walking the user through reviewing and approving a
    # transaction that would then produce no signatures. The view layer keeps the
    # psbt and routes back to seed selection -- see REJECT_PRESENTATION.
    SEED_CANNOT_SIGN = "SEED_CANNOT_SIGN"


class InvalidPSBTError(Exception):
    """
    The psbt is well-formed enough for embit to parse, but SeedSigner refuses to
    present or sign it.

    Distinct from an unexpected exception: this is a decision, and the UI shows
    it to the user as a warning rather than as a crash.
    """

    def __init__(self, message: str, code: str = None):
        super().__init__(message)
        self.code = code



class PSBTParser():
    """
    Reads a psbt on behalf of one seed and works out everything the signing flow shows the
    user before they approve: the wallet policy (script type, plus m-of-n and the
    cosigners for multisig), the amount coming in, what is being spent, what comes back as
    change, the fee, where the spend is going, and any OP_RETURN payload.

    Constructing it with a seed parses immediately; see parse() for what that establishes
    in what order and which psbts it turns away.

    The parse fully processes the psbt, validates what it can, then stores the organized
    results in the instance attributes (spend_amount, fee_amount, destination_addresses,
    etc.). Note that change_data and change_amount cover EVERY output coming back to this
    seed, including self-transfers to a receive address. The view layer tells the two
    apart by the branch index in the derivation path.

    A psbt is written by an untrusted coordinator. The metadata it carries about keys
    (fingerprints, derivation paths, xpubs) is a claim, not a fact. The onus is on us to
    verify by re-deriving from the signing seed. For multisig, verification depends on the
    user providing a "known good" descriptor (i.e. can be trusted) from which we can
    verify the outputs by deriving from the cosigners' xpubs.

    This class makes the difference visible in its own names:

      claimed_...   coordinator-supplied metadata (fingerprints, derivation paths, xpubs).
                    Safe to read and display; never safe to make a decision on.
      verified_...  a fact this device proved by re-deriving from the signing seed and
                    matching real key material. Only assigned by code that performed that
                    derivation.

    Invariant: no verified_ value is ever assigned from a claimed_ value without an
    intervening re-derivation from self.root or from a user-supplied "known good"
    descriptor.

    The invariant is enforced, not merely documented: a claim that cannot be turned
    into a fact is refused rather than displayed. See RejectCode for the specific
    constructions that have no honest explanation, and RiskWarning for the ones that
    do and are surfaced for review instead.
    """

    # Upper bound on how many levels of derivation a single parse will cache. 1000 is
    # just slightly under a 3-of-5 multisig consolidating 200 inputs, which costs roughly
    # 650 kilobytes. A psbt that needs more levels than that still parses correctly; it
    # just stops getting cache hits once the cache is full.
    MAX_CACHED_DERIVATIONS = 1000



    def __init__(
        self,
        p: PSBT,
        seed: Seed | WIFKey | None = None,
        *,
        root: bip32.HDKey | None = None,
        root_path: list[int] | None = None,
        master_fingerprint: bytes | None = None,
        network: str = SettingsConstants.MAINNET,
        change_index_lookahead: int | None = None,
        reference_time: int | None = None,
        max_fee_rate: float | None = None,
        block_anchor: tuple[int, int] | None = None,
    ):
        self.psbt: PSBT = p
        self.seed = seed
        self.network = network
        self.root = root
        self.root_path = root_path or []
        self.root_path_str = bip32.path_to_str(self.root_path) if self.root_path else "m"
        self.master_fingerprint = master_fingerprint
        # Best available estimate of "now", and the (height, unix_time) pair used
        # to date a block-height locktime. Both are optional; without them the
        # far-future check simply does not run. See _check_far_future_locktime.
        self.reference_time = reference_time
        self.block_anchor = block_anchor

        self.change_index_lookahead = (
            change_index_lookahead
            if change_index_lookahead is not None
            else PSBTParser._configured_change_index_lookahead()
        )

        self.policy = None
        self.spend_amount = 0
        self.change_amount = 0
        self.change_data = []
        self.fee_amount = 0
        self.input_amount = 0
        self.num_inputs = 0
        self.verified_input_prefixes: set = set()
        self.verified_max_input_index: int = -1
        self.can_verify_derivations: bool = False
        self.destination_addresses = []
        self.destination_amounts = []
        self.op_return_data: bytes = None
        self.op_return_amount: int = 0
        self.risk_warnings: set[str] = set()
        # Fee rate in sat/vB, computed during the parse from an estimated vsize.
        self.fee_rate: float = 0.0
        self.max_fee_rate = (
            max_fee_rate if max_fee_rate is not None
            else PSBTParser._configured_max_fee_rate()
        )
        # Whether nLockTime is actually enforced (needs a non-final input), and
        # its raw value. Shown on the approval screen: the device has no RTC, so
        # the wall-clock comparison below cannot be relied on to judge whether a
        # locktime is "far" in the future, and a block-height locktime cannot be
        # judged at all without a chain tip. Stating it lets the user decide.
        self.locktime_is_enforced: bool = False
        self.locktime: int = 0

        # Indexed alongside psbt.inputs / psbt.outputs. Each entry is the derivation path
        # the seed genuinely owns in each scope or None where it owns nothing. Determined
        # in _verify_claimed_derivation_paths. Left empty when there is no BIP32 tree to
        # verify against (WIF / BIP38 signing) -- see can_verify_derivations.
        self.verified_input_derivation_paths: List[List[int] | None] = []
        self.verified_output_derivation_paths: List[List[int] | None] = []

        if self.seed is not None or self.root is not None:
            self.parse()


    @staticmethod
    def _configured_change_index_lookahead() -> int:
        """
        The user's Change Gap Limit, or the default if settings aren't available
        (the parser is usable standalone, e.g. from tests and scripts).
        """
        try:
            from seedsigner.models.settings import Settings
            return Settings.get_instance().get_value(
                SettingsConstants.SETTING__CHANGE_INDEX_LOOKAHEAD
            )
        except Exception as e:
            logger.debug("Falling back to the default change gap limit: %s", e)
            return DEFAULT_CHANGE_INDEX_LOOKAHEAD


    def get_change_data(self, change_num: int) -> dict:
        if change_num < len(self.change_data):
            return self.change_data[change_num]


    @property
    def num_change_outputs(self):
        return len(self.change_data)


    @property
    def is_multisig(self):
        """
            Multisig psbts will have "m" and "n" defined in policy
        """
        return isinstance(self.policy, dict) and "m" in self.policy


    @property
    def num_destinations(self):
        return len(self.destination_addresses)


    def _set_root(self):
        if self.seed is not None:
            if isinstance(self.seed, WIFKey):
                # root is a simple private key
                self.root = self.seed.privkey
            else:
                self.root = self.seed.get_root(self.network)
        elif self.root is None:
            raise RuntimeError("No seed or root key available")


    def parse(self):
        """
        Establishes, in order:

          0. _validate_psbt_version / _check_tx_modifiable / _assert_v2_complete: the
             psbt must be one whose bytes can only mean one transaction before any of its
             claims are worth reading. See RejectCode.

          1. _fill_missing_fingerprints: backfills all-zero fingerprints, but only for
             scopes the seed provably derives.

          2. _verify_claimed_derivation_paths: each input and output scope that claims to
             be controlled by the seed is verified. Raises InvalidPSBTError with
             RejectCode.FORGED_[INPUT|OUTPUT]_OWNERSHIP if a claimed scope fails
             verification.

          3. _reject_if_seed_cannot_sign: raises RejectCode.SEED_CANNOT_SIGN if none of
             the inputs can be signed by the seed. A mismatch rather than an attack,
             caught here so the flow can say so before showing a transaction.

             Steps 2 and 3 need a BIP32 tree to derive against, so both are skipped when
             there is none -- WIF / BIP38 signing, or a seedless multisig pre-parse. See
             can_verify_derivations.

          4. _parse_inputs: every input must resolve to the same policy, otherwise
             RejectCode.MIXED_INPUTS. Each input is also structurally validated here
             (RejectCode.MISSING_UTXO, UNSUPPORTED_SIGHASH, and the rest).

             A policy is one of:
               - single-sig: the script type alone. Says nothing about keys.
               - multisig, cosigners resolved: script type, m-of-n, and the cosigner
                 xpubs that every key in the script was traced back to.
               - multisig, cosigners unresolved: script type and m-of-n only.
                 _get_policy doesn't propagate cosigner errors, so two such policies match
                 without anything having tied them to the same keys. TODO: don't let a
                 policy with no cosigner information pass as a match.

          5. _parse_outputs: works out which outputs come back to this seed. For
             single-sig this proves the output script derives from the seed at the
             claimed path. TODO: reject outputs at a path the user's wallet would never
             scan.

        Optimization via child_key_derivation_cache:
        Parsing traverses a derivation path down to an individual address one level at a
        time, over and over, and where that traversal begins depends on the wallet.

        Single-sig traverses the full path down from our own master key, on every OUTPUT
        the PSBT claims is ours.

        Multisig instead traverses just the last two levels down from each cosigner's
        account xpub, once per cosigner, on every INPUT and on every OUTPUT carrying the
        multisig script.

        Deriving each level costs a hash and an elliptic curve operation, and these
        traversals overlap heavily: everything in one account shares the same opening
        levels, differing only in the address at the end.

        So every level derived during this parse is kept in a cache and reused. See
        _derive_with_cache.

        Note that the cache is only useful within a single parse so it is not preserved.
        """
        if self.psbt is None:
            logger.info(f"self.psbt is None!!")
            return False

        self._validate_psbt_version()
        self._check_tx_modifiable()
        self._assert_v2_complete()

        if self.seed is not None and self.root is None:
            self._set_root()

        # A derivable BIP32 root is what makes verification possible at all. Without
        # one -- WIF/BIP38 signing, or a seedless multisig pre-parse -- no evidence can
        # be gathered and none is expected. Established here rather than in
        # _parse_inputs because the ownership scan below needs it first.
        self.can_verify_derivations = self.root is not None and hasattr(self.root, "derive")

        child_key_derivation_cache = {}

        # Try to fix missing fingerprints before parsing
        self._fill_missing_fingerprints(child_key_derivation_cache)

        # Work out what this seed actually owns before anything below reads the psbt's
        # claims about it.
        self._verify_claimed_derivation_paths(child_key_derivation_cache)
        self._reject_if_seed_cannot_sign()

        rt = self._parse_inputs(child_key_derivation_cache)
        if rt == False:
            return False

        if self.root is None and self.seed is None and not self.is_multisig:
            raise RuntimeError("No seed or root key available")

        rt = self._parse_outputs(child_key_derivation_cache)
        if rt == False:
            return False

        return True


    @staticmethod
    def _is_witness_program(script_pubkey) -> bool:
        """
        A witness program per BIP-141: a single version byte (OP_0, or OP_1
        through OP_16) followed by a 2-40 byte push.

        Tested structurally rather than against a list of known script types, so
        that a future witness version isn't mistaken for a fabricated prevout.
        """
        data = script_pubkey.data
        if len(data) < 4 or len(data) > 42:
            return False
        version_byte = data[0]
        if version_byte != 0x00 and not (0x51 <= version_byte <= 0x60):
            return False
        push_len = data[1]
        return 2 <= push_len <= 40 and push_len == len(data) - 2


    def _check_fee_rate(self):
        """
        Flag a fee that is extortionate *per byte*, which the share-of-inputs
        check cannot see.

        The two miss opposite things. A 9%-of-inputs fee on a large consolidation
        stays under the relative threshold while burning a fortune; a modest
        absolute fee on a tiny transaction can be a wild rate. Both are worth a
        look, so both are checked.

        The threshold is a setting because fee rates move by orders of magnitude
        between quiet periods and congestion -- see
        SettingsConstants.ALL_MAX_FEE_RATES. Warning only: paying a high rate is
        sometimes exactly what the user intends.
        """
        if self.fee_amount <= 0:
            return

        threshold = self.max_fee_rate
        if not threshold or threshold <= 0:
            # 0 means the user turned the check off.
            return

        try:
            vsize = self.estimate_vsize()
        except Exception as e:
            # An estimate we cannot compute must not take the parse down with it.
            logger.debug("Could not estimate vsize: %s", e)
            return

        if vsize <= 0:
            return

        self.fee_rate = self.fee_amount / vsize
        if self.fee_rate >= threshold:
            self.risk_warnings.add(RiskWarning.HIGH_FEE_RATE)


    @staticmethod
    def _configured_max_fee_rate() -> float:
        """
        The user's Max Fee Rate in sat/vB, resolving AUTO against
        resources/latest-block.json. 0 means the check is off.
        """
        from seedsigner.models.settings_definition import SettingsConstants as SC

        try:
            from seedsigner.models.settings import Settings
            configured = Settings.get_instance().get_value(SC.SETTING__MAX_FEE_RATE)
        except Exception as e:
            logger.debug("Falling back to the default max fee rate: %s", e)
            configured = SC.DEFAULT_MAX_FEE_RATE

        if configured != SC.MAX_FEE_RATE__AUTO:
            return configured

        try:
            from seedsigner.controller import Controller
            rate = Controller.RECENT_MAX_FEE_RATE
            if rate and rate > 0:
                return rate
        except Exception as e:
            logger.debug("No recent fee-rate anchor available: %s", e)

        return SC.FALLBACK_MAX_FEE_RATE


    def _check_far_future_locktime(self, locktime: int):
        """
        Flag a locktime sitting years beyond when this psbt was created.

        The device has no RTC, so it cannot ask what today is. When a psbt is
        loaded from microSD its file mtime is a usable stand-in: it was written by
        a machine that did have a clock. `reference_time` carries that; it is None
        for QR-delivered psbts, where no such hint exists.

        SECURITY PROPERTY: this may only ever *raise* a warning, never suppress
        one. A file mtime is attacker-influenceable -- whoever wrote the file
        chose it -- so a forged mtime can hide a long lock. That is acceptable
        precisely because the fallback is the existing behaviour: the locktime is
        still stated on the approval screen either way. An attacker who forges the
        mtime buys back the status quo and nothing more. What they must never be
        able to do is use it to turn a warning off, which is why nothing here
        clears a warning and why an implausible reference is discarded rather than
        trusted.
        """
        if not self.locktime_is_enforced or not locktime:
            return
        if not self.reference_time or self.reference_time <= 0:
            return

        if locktime >= LOCKTIME_TIMESTAMP_THRESHOLD:
            locktime_as_time = locktime
        else:
            # A block height means nothing without something to date it against.
            if not self.block_anchor:
                return
            anchor_height, anchor_time = self.block_anchor
            if anchor_height <= 0 or anchor_time <= 0:
                return
            locktime_as_time = anchor_time + (locktime - anchor_height) * 600

        if locktime_as_time - self.reference_time >= FAR_FUTURE_LOCKTIME_SECONDS:
            self.risk_warnings.add(RiskWarning.LOCKTIME_FAR_FUTURE)


    @staticmethod
    def _estimate_input_vsize(inp: InputScope) -> float:
        """
        Virtual size this input will occupy once signed, in vbytes.

        The psbt is unsigned, so the signature is not there to measure. Its size
        is however almost entirely determined by the script type, and the parts
        that vary (low-S DER encoding is 71 or 72 bytes) vary by a byte or two --
        irrelevant at the resolution a "is this fee rate absurd" check needs.

        Witness data is quarter-weight, hence the /4 terms.
        """
        # outpoint (36) + scriptSig length varint (1) + sequence (4)
        vsize = 41.0

        utxo = inp.witness_utxo
        if utxo is None and inp.non_witness_utxo is not None:
            utxo = inp.non_witness_utxo.vout[inp.vout]
        if utxo is None:
            return vsize

        script_type = utxo.script_pubkey.script_type()

        # A signature is 71-72 bytes DER + 1 sighash byte; assume the larger.
        SIG = 72
        PUBKEY = 33

        if script_type == "p2wpkh":
            # witness: count + sig + pubkey
            return vsize + (1 + (1 + SIG) + (1 + PUBKEY)) / 4

        if script_type == "p2tr":
            # BIP-341 key-path: count + 64-byte schnorr signature
            return vsize + (1 + (1 + 64)) / 4

        if script_type == "p2wsh":
            m, n = PSBTParser._multisig_m_n(inp.witness_script)
            if m is None:
                # Unknown script: assume a single signature plus the script.
                script_len = len(inp.witness_script.data) if inp.witness_script else 34
                return vsize + (1 + (1 + SIG) + (1 + script_len)) / 4
            script_len = len(inp.witness_script.data)
            # count + OP_0 dummy + m signatures + the witness script
            witness = 1 + 1 + m * (1 + SIG) + (1 + script_len)
            return vsize + witness / 4

        if script_type == "p2sh":
            redeem = inp.redeem_script
            if redeem is not None and PSBTParser._is_witness_program(redeem):
                # p2sh-wrapped segwit: the redeem script sits in scriptSig at
                # full weight, the signature stays in the witness.
                vsize += 1 + len(redeem.data)
                if len(redeem.data) == 22:  # p2sh-p2wpkh
                    return vsize + (1 + (1 + SIG) + (1 + PUBKEY)) / 4
                m, _n = PSBTParser._multisig_m_n(inp.witness_script)
                m = m or 1
                script_len = len(inp.witness_script.data) if inp.witness_script else 34
                return vsize + (1 + 1 + m * (1 + SIG) + (1 + script_len)) / 4

            # Legacy p2sh multisig: everything is in scriptSig, full weight.
            m, _n = PSBTParser._multisig_m_n(redeem)
            m = m or 1
            script_len = len(redeem.data) if redeem else 34
            return vsize + 1 + m * (1 + SIG) + (1 + script_len)

        if script_type == "p2pkh":
            # scriptSig: sig + pubkey, all at full weight
            return vsize + (1 + SIG) + (1 + PUBKEY)

        # Unknown: a single-signature spend is the least-bad guess.
        return vsize + (1 + SIG) + (1 + PUBKEY)


    @staticmethod
    def _multisig_m_n(script) -> tuple:
        """(m, n) for a bare multisig script, or (None, None)."""
        if script is None:
            return (None, None)
        try:
            m, n, _pubkeys = PSBTParser._parse_multisig(script)
            return (m, n)
        except Exception:
            return (None, None)


    def estimate_vsize(self) -> float:
        """
        Virtual size of the finished transaction, in vbytes.

        Needed because a fee is only interpretable as a rate. 50,000 sats is
        nothing on a 200-input consolidation and extortionate on a 1-in 2-out
        payment, and the absolute-fee check (fee as a share of inputs) cannot
        tell those apart.
        """
        tx = self.psbt.tx

        # version (4) + locktime (4) + the two count varints
        vsize = 8.0
        vsize += PSBTParser._varint_size(len(tx.vin))
        vsize += PSBTParser._varint_size(len(tx.vout))

        has_witness = any(
            PSBTParser._is_witness_program(
                (inp.witness_utxo or (inp.non_witness_utxo.vout[inp.vout]
                                      if inp.non_witness_utxo else None)).script_pubkey
            )
            if (inp.witness_utxo or inp.non_witness_utxo) else False
            for inp in self.psbt.inputs
        )
        if has_witness:
            # segwit marker + flag, 2 weight units
            vsize += 0.5

        for inp in self.psbt.inputs:
            vsize += PSBTParser._estimate_input_vsize(inp)

        for vout in tx.vout:
            # amount (8) + scriptPubKey length varint + the script
            script_len = len(vout.script_pubkey.data)
            vsize += 8 + PSBTParser._varint_size(script_len) + script_len

        return vsize


    @staticmethod
    def _varint_size(n: int) -> int:
        if n < 0xFD:
            return 1
        if n <= 0xFFFF:
            return 3
        if n <= 0xFFFFFFFF:
            return 5
        return 9


    def _validate_psbt_version(self):
        """
        Refuse a psbt that declares a format we do not implement.

        BIP-174 defines version 0 (the field may be absent, which means 0) and
        BIP-370 defines version 2; both are supported here. Any other value is a
        future or unknown format whose fields we would misread, so it is refused
        rather than guessed at.

        A v2 psbt has no PSBT_GLOBAL_UNSIGNED_TX -- inputs and outputs carry their
        own fields (PSBT_IN_PREVIOUS_TXID, PSBT_OUT_AMOUNT, ...). Two further checks
        apply to v2 specifically: _check_tx_modifiable refuses a transaction a
        coordinator may still change after we sign, and _assert_v2_complete refuses
        one whose mandatory per-input/per-output fields are missing.
        """
        version = getattr(self.psbt, "version", None)

        # Absent is v0 by definition. embit surfaces that as either None or 0
        # depending on whether the field was written out explicitly.
        if version in (None, 0, 2):
            return

        raise InvalidPSBTError(
            f"PSBT version {version} is not supported.",
            code=RejectCode.UNSUPPORTED_PSBT_VERSION,
        )


    def _check_tx_modifiable(self):
        """
        Refuse a v2 psbt whose transaction may still be modified after signing.

        BIP-370 PSBT_GLOBAL_TX_MODIFIABLE (key 0x06) is a one-byte flag field: bit 0
        allows adding or removing inputs, bit 1 outputs. A nonzero value means the
        coordinator can change what we are about to sign -- add an output that steals
        our coins, drop the destination, and so on -- after we have approved exactly
        what the screen showed. That voids the review entirely, so it is a refusal
        rather than a warning.

        embit does not parse this key into a named field (it lands in psbt.unknown),
        so it must be inspected explicitly. Absent means final: BIP-370 treats a
        missing TX_MODIFIABLE as 0x00, and the valid corpus vectors omit it.

        Only meaningful for v2 -- on a v0 psbt key 0x06 is just an unknown field with
        no modifiability semantics, so it must not trigger this refusal there.
        """
        if getattr(self.psbt, "version", None) != 2:
            return

        value = self.psbt.unknown.get(b"\x06")
        if value is None:
            return

        # The field is a single byte; the low two bits are the flags. Anything set
        # there means the transaction is not final.
        if int.from_bytes(value, "little") & 0x03:
            raise InvalidPSBTError(
                "Modifiable (TX_MODIFIABLE): inputs or outputs can change after you sign.",
                code=RejectCode.TX_MODIFIABLE,
            )


    def _assert_v2_complete(self):
        """
        Refuse a v2 psbt that omits fields BIP-370 makes mandatory per input and
        output, before any of its values are trusted for display or signing.

        embit parses a v2 record even when required fields are missing -- it simply
        leaves the slot empty: an output's amount becomes None (which would later die
        on `0 <= None`, a crash screen rather than a decision), an output's script
        becomes blank, and an input can lose its previous txid/vout while keeping a
        witness_utxo. Each of those is refused here instead of reaching the
        accounting or signing code half-described:

          * every input must name the utxo it spends (previous txid + vout) as well
            as carry utxo data -- the latter already trips MISSING_UTXO in
            _validate_input, exactly as for v0;
          * every output must carry an amount and a script.
        """
        if getattr(self.psbt, "version", None) != 2:
            return

        for i, inp in enumerate(self.psbt.inputs):
            if inp.txid is None or inp.vout is None:
                raise InvalidPSBTError(
                    f"Input {i} has no previous output (txid/vout).",
                    code=RejectCode.MISSING_UTXO,
                )

        vout = self.psbt.tx.vout
        for i, out in enumerate(vout):
            value = out.value
            if value is None or not (0 <= value <= MAX_MONEY):
                raise InvalidPSBTError(
                    f"Output {i} has no valid amount.",
                    code=RejectCode.AMOUNT_OUT_OF_RANGE,
                )
            script = out.script_pubkey
            if script is None or len(script.data) == 0:
                # An empty script has no address to show the user, so it cannot be
                # authorised -- the same reason an unknown witness version is refused.
                raise InvalidPSBTError(
                    f"Output {i} has no script.",
                    code=RejectCode.UNDISPLAYABLE_OUTPUT,
                )


    @staticmethod
    def _validate_input(index: int, inp: InputScope):
        """
        Structural checks on a single input, before any of its values are
        trusted for display.

        A signature commits to the input amount (BIP-143) and to the script being
        satisfied. If the psbt's own description of the prevout is internally
        inconsistent, nothing derived from it -- the fee, the amounts on screen --
        means anything.
        """
        witness_utxo = inp.witness_utxo
        non_witness_utxo = inp.non_witness_utxo

        if witness_utxo is None and non_witness_utxo is None:
            # Without a prevout there is no amount and no script to show; the
            # old code left `script_pubkey` unbound and died with a NameError.
            raise InvalidPSBTError(
                f"Input {index} has no utxo",
                code=RejectCode.MISSING_UTXO,
            )

        if witness_utxo is not None and non_witness_utxo is not None:
            # Both forms supplied: they must describe the same prevout. This is
            # the BIP-143 amount-binding attack -- a lowered witness_utxo value
            # understates the fee on screen while the signature stays valid.
            real = non_witness_utxo.vout[inp.vout]
            if (witness_utxo.value != real.value
                    or witness_utxo.script_pubkey.data != real.script_pubkey.data):
                raise InvalidPSBTError(
                    f"Input {index} utxo does not match the previous tx.",
                    code=RejectCode.UTXO_MISMATCH,
                )

        utxo = witness_utxo if witness_utxo is not None else non_witness_utxo.vout[inp.vout]

        if not 0 <= utxo.value <= MAX_MONEY:
            raise InvalidPSBTError(
                f"Input {index} amount out of range: {utxo.value}",
                code=RejectCode.AMOUNT_OUT_OF_RANGE,
            )

        script_pubkey = utxo.script_pubkey
        script_type = script_pubkey.script_type()

        # Anything other than SIGHASH_ALL hands the coordinator authority the
        # user was never shown: over the other inputs (ANYONECANPAY), over the
        # outputs (NONE), or over the SIGHASH_SINGLE bug value. embit's
        # sign_with() already declines to produce such a signature, but that
        # only surfaces as a generic error after the user has reviewed the whole
        # transaction. Refuse at load, with a reason.
        allowed_sighash = (None, SIGHASH_ALL)
        if script_type == "p2tr":
            # BIP-341: 0x00 means "default", which is SIGHASH_ALL.
            allowed_sighash += (SIGHASH_DEFAULT,)
        if inp.sighash_type not in allowed_sighash:
            raise InvalidPSBTError(
                f"Input {index} needs sighash {inp.sighash_type:#04x}, not SIGHASH_ALL.",
                code=RejectCode.UNSUPPORTED_SIGHASH,
            )

        if witness_utxo is not None and not (
            PSBTParser._is_witness_program(script_pubkey) or script_type == "p2sh"
        ):
            # witness_utxo is only meaningful for a segwit (or segwit-wrapped)
            # prevout; anything else is a fabricated prevout description.
            raise InvalidPSBTError(
                f"Input {index} utxo declares a {script_type} script.",
                code=RejectCode.INVALID_WITNESS_UTXO,
            )

        effective_type = script_type
        if script_type == "p2sh":
            if inp.redeem_script is None:
                raise InvalidPSBTError(
                    f"Input {index} is p2sh with no redeem_script.",
                    code=RejectCode.SCRIPT_HASH_MISMATCH,
                )
            if script.p2sh(inp.redeem_script).data != script_pubkey.data:
                raise InvalidPSBTError(
                    f"Input {index} redeem_script does not match.",
                    code=RejectCode.SCRIPT_HASH_MISMATCH,
                )
            effective_type = inp.redeem_script.script_type()

        if effective_type == "p2wsh":
            if inp.witness_script is None:
                raise InvalidPSBTError(
                    f"Input {index} is p2wsh with no witness_script.",
                    code=RejectCode.SCRIPT_HASH_MISMATCH,
                )
            expected = inp.redeem_script if script_type == "p2sh" else script_pubkey
            if script.p2wsh(inp.witness_script).data != expected.data:
                raise InvalidPSBTError(
                    f"Input {index} witness_script does not match.",
                    code=RejectCode.SCRIPT_HASH_MISMATCH,
                )
        elif inp.witness_script is not None:
            # A witness_script on anything but a p2wsh input hashes to nothing and
            # can only mislead.
            raise InvalidPSBTError(
                f"Input {index} has a stray witness_script.",
                code=RejectCode.EXTRANEOUS_WITNESS_SCRIPT,
            )


    def _parse_inputs(self, child_key_derivation_cache: dict):
        self.input_amount = 0
        self.num_inputs = len(self.psbt.inputs)
        self.verified_input_prefixes = set()
        self.verified_max_input_index = -1
        # can_verify_derivations is established in parse(), before the ownership
        # scan that also depends on it.
        for i, inp in enumerate(self.psbt.inputs):
            PSBTParser._validate_input(i, inp)

            # Everything above the trailing branch/index pair, for the inputs this
            # seed actually produces. Each is a utxo the wallet already found, so
            # once re-derived it is evidence of where this wallet keeps its keys --
            # which is what the change-binding check measures against. Cosigners'
            # derivations, and any the coordinator made up, simply do not verify.
            # Skipped when there is no key to verify against: a seedless multisig
            # pre-parse, or WIF / BIP38 signing. Nothing there can become
            # evidence, and the absence of evidence must not read as evidence of
            # absence -- is_reachable_derivation gets None rather than an empty
            # set in that case.
            if self.can_verify_derivations:
                for public_key, derivation, is_taproot in self._scope_keyed_derivations(inp):
                    if not derivation:
                        continue
                    if not self._verify_derivation(
                        inp, public_key, derivation, child_key_derivation_cache,
                        is_taproot=is_taproot,
                    ):
                        # A path we cannot re-derive, or one the utxo does not
                        # commit to: a cosigner's, or a fabrication. Not evidence.
                        continue
                    if len(derivation) >= 2:
                        self.verified_input_prefixes.add(tuple(derivation[:-2]))
                    self.verified_max_input_index = max(
                        self.verified_max_input_index,
                        derivation[-1] & 0x7FFFFFFF,
                    )

            if inp.witness_utxo:
                self.input_amount += inp.witness_utxo.value
                script_pubkey = inp.witness_utxo.script_pubkey
            elif inp.non_witness_utxo:
                self.input_amount += inp.utxo.value
                script_pubkey = inp.script_pubkey

            inp_policy = PSBTParser._get_policy(inp, script_pubkey, self.psbt.xpubs, child_key_derivation_cache)
            if self.policy == None:
                self.policy = inp_policy
            else:
                if self.policy != inp_policy:
                    raise InvalidPSBTError(
                        "Mixed inputs in the transaction",
                        code=RejectCode.MIXED_INPUTS,
                    )

    @staticmethod
    def is_reachable_derivation(derivation: list[int], input_prefixes: set | None) -> bool:
        """
        Whether a wallet scanning for this seed's addresses will ever find this
        one.

        The expectation is taken from the inputs rather than hardcoded: every
        input is a utxo the wallet already found, so the account prefix they
        share -- everything above the trailing branch/index pair -- is proof of
        where this wallet actually keeps its keys. A change output has to sit
        under that same prefix, on the receive (0) or change (1) branch.

        Deriving the rule from the inputs rather than asserting a fixed depth
        lets a genuinely unusual wallet layout work unchanged, while still
        refusing a change path that has been moved somewhere the wallet will
        never look.

        `input_prefixes` is None when no evidence could be gathered at all --
        the psbt carries no input bip32 derivations, or there was no key to
        verify them against (WIF/BIP38, or a seedless multisig pre-parse). Only
        the branch is checked then.

        An *empty set* is different and deliberately fails everything: we had a
        key to verify with and still gathered nothing, either because the inputs
        carried no derivations or because none held up. Such a psbt cannot be
        signed anyway -- without a usable input derivation there is no key to
        sign with -- and treating "no evidence" as permission would let an
        attacker switch the check off just by withholding it.
        """
        if len(derivation) < 2:
            return False
        if derivation[-2] not in (0, 1):
            return False
        if input_prefixes is not None and tuple(derivation[:-2]) not in input_prefixes:
            return False
        return True


    @staticmethod
    def is_change_branch(derivation: list[int]) -> bool:
        """True for the change branch, False for receive (i.e. a self-transfer)."""
        return len(derivation) >= 2 and derivation[-2] == 1


    @staticmethod
    def _scope_derivations(scope: InputScope | OutputScope) -> list[list[int]]:
        """Every claimed bip32 derivation on a scope, taproot and non-taproot alike."""
        derivations = [d.derivation for d in scope.bip32_derivations.values()]
        derivations += [d.derivation for _, d in scope.taproot_bip32_derivations.values()]
        return derivations


    @staticmethod
    def _scope_keyed_derivations(scope: InputScope | OutputScope) -> list[tuple]:
        """
        Every claimed derivation paired with the pubkey it claims to produce, and
        whether that claim is a taproot one. Taproot keys are stored x-only and so
        have to be compared differently -- see seed_owns_pubkey.
        """
        triples = [(pub, d.derivation, False) for pub, d in scope.bip32_derivations.items()]
        triples += [(pub, d.derivation, True) for pub, (_, d) in scope.taproot_bip32_derivations.items()]
        return triples


    @staticmethod
    def _input_commits_to_key(inp: InputScope, derived_key) -> bool:
        """
        Whether the input being spent actually commits to `derived_key`.

        Re-deriving proves a path belongs to this seed, but not that it is the
        path of *this utxo*: an attacker holding the account xpub can supply a
        matched path/pubkey pair from somewhere else in our own tree. Only the
        prevout's script says which key really unlocks these coins.
        """
        utxo = inp.witness_utxo or (
            inp.non_witness_utxo.vout[inp.vout] if inp.non_witness_utxo else None
        )
        if utxo is None:
            return False

        script_pubkey = utxo.script_pubkey
        script_type = script_pubkey.script_type()
        if script_type == "p2sh" and inp.redeem_script is not None:
            # Unwrap the p2sh: what matters is the script it commits to.
            script_pubkey = inp.redeem_script
            script_type = script_pubkey.script_type()

        sec = derived_key.key.sec()

        if script_type == "p2wpkh":
            return script.p2wpkh(derived_key).data == script_pubkey.data
        if script_type == "p2pkh":
            return script.p2pkh(derived_key).data == script_pubkey.data
        if script_type == "p2wsh":
            # Multisig: our key is one of the cosigners named in the witness script.
            return inp.witness_script is not None and sec in inp.witness_script.data
        if script_type == "p2tr":
            # A taproot output key is the internal key tweaked by the merkle root,
            # so it never equals the derived key directly. The internal key is the
            # nearest thing the psbt commits to.
            if inp.taproot_internal_key is not None:
                return inp.taproot_internal_key.xonly() == derived_key.key.xonly()
            return script.p2tr(derived_key).data == script_pubkey.data
        if script_type is None:
            # Bare multisig inside a p2sh redeem script.
            return sec in script_pubkey.data

        return False


    def _verify_derivation(self, inp: InputScope, public_key, derivation: list[int],
                           child_key_derivation_cache: dict | None = None,
                           is_taproot: bool = False) -> bool:
        """
        Whether this seed really does produce `public_key` at `derivation`, *and*
        whether the utxo being spent actually commits to that key.

        The path and the pubkey both come from the coordinator, so on their own
        they are a matched pair of claims -- an attacker who knows our xpub can
        supply a self-consistent lie drawn from elsewhere in our own tree. Both
        halves are needed: re-deriving makes it a fact about this seed, and the
        script check makes it a fact about this utxo.

        The first half is seed_owns_pubkey, which compares x-only for taproot and
        the full key for ecdsa. The second half is this file's own contribution
        and has no equivalent upstream.
        """
        if not self.can_verify_derivations:
            # WIF/BIP38 signing has no BIP32 tree to check against.
            return False
        try:
            if not PSBTParser.seed_owns_pubkey(
                self.root, derivation, public_key, child_key_derivation_cache,
                is_taproot=is_taproot, root_path=self.root_path,
            ):
                return False
            derived = PSBTParser._derive_with_cache(
                self.root, derivation[len(self.root_path):], child_key_derivation_cache
            )
        except Exception as e:
            logger.debug("Could not derive %s: %s", derivation, e)
            return False
        return PSBTParser._input_commits_to_key(inp, derived)


    def _parse_outputs(self, child_key_derivation_cache: dict):
        self.spend_amount = 0
        self.change_amount = 0
        self.change_data = []
        self.fee_amount = 0
        self.op_return_amount = 0
        self.risk_warnings = set()
        self.destination_addresses = []
        self.destination_amounts = []

        # Asking the PSBT for its transaction rebuilds that entire transaction from
        # scratch on every single request. The outputs are consulted a dozen times
        # over the course of the loop below, so grab them once now.
        vout = self.psbt.tx.vout

        for i, out in enumerate(self.psbt.outputs):
            value = vout[i].value
            if not 0 <= value <= MAX_MONEY:
                raise InvalidPSBTError(
                    f"Output {i} amount out of range: {value}",
                    code=RejectCode.AMOUNT_OUT_OF_RANGE,
                )
            out_policy = PSBTParser._get_policy(out, vout[i].script_pubkey, self.psbt.xpubs, child_key_derivation_cache)
            is_change = False

            # if policy is the same - probably change
            if out_policy == self.policy:
                # double-check that it's change
                # we already checked in get_cosigners and parse_multisig
                # that pubkeys are generated from cosigners,
                # and witness script is corresponding multisig
                # so we only need to check that scriptpubkey is generated from
                # witness script

                # empty script by default
                sc = script.Script(b"")

                # multisig, we know witness script
                if self.policy["type"] == "p2wsh":
                    sc = script.p2wsh(out.witness_script)

                elif self.policy["type"] == "p2sh-p2wsh":
                    sc = script.p2sh(script.p2wsh(out.witness_script))
                
                # Arbitrary p2sh; includes pre-segwit multisig (m/45')
                elif self.policy["type"] == "p2sh":
                    sc = script.p2sh(out.redeem_script)

                # single-sig
                elif "pkh" in self.policy["type"]:
                    my_pubkey = None

                    # should be one or zero for single-key addresses
                    if hasattr(self.root, "derive") and len(out.bip32_derivations.values()) > 0:
                        der = list(out.bip32_derivations.values())[0].derivation
                        der = der[len(self.root_path):]
                        my_pubkey = PSBTParser._derive_with_cache(self.root, der, child_key_derivation_cache)

                    if self.policy["type"] == "p2pkh" and my_pubkey is not None:
                        sc = script.p2pkh(my_pubkey)
                    if self.policy["type"] == "p2wpkh" and my_pubkey is not None:
                        sc = script.p2wpkh(my_pubkey)

                    elif self.policy["type"] == "p2sh-p2wpkh" and my_pubkey is not None:
                        sc = script.p2sh(script.p2wpkh(my_pubkey))

                    elif self.policy["type"] == "p2wpkh" and my_pubkey is not None:
                        sc = script.p2wpkh(my_pubkey)

                elif "p2tr" in self.policy["type"]:
                    my_pubkey = None
                    # should have one or zero derivations for single-key addresses
                    if hasattr(self.root, "derive") and len(out.taproot_bip32_derivations.values()) > 0:
                        # TODO: Support keys in taptree leaves
                        leaf_hashes, derivation = list(out.taproot_bip32_derivations.values())[0]
                        der = derivation.derivation[len(self.root_path):]
                        my_pubkey = PSBTParser._derive_with_cache(self.root, der, child_key_derivation_cache)
                        sc = script.p2tr(my_pubkey)

                if sc.data == vout[i].script_pubkey.data:
                    is_change = True

            if is_change:
                # The seed can derive this scriptPubKey, but the path is not one
                # any wallet will scan for. There is no honest reason to build
                # this: splicing an extra level in, or moving off branch 0/1,
                # exists solely so a naive `path[-2] == 1` check labels the
                # output "your change" while the funds land somewhere the wallet
                # can never find them. Refuse rather than relabel -- a psbt that
                # tried to deceive the display should not be signed at all.
                derivations = self._scope_derivations(out)
                unreachable = [
                    d for d in derivations
                    if not PSBTParser.is_reachable_derivation(
                        d,
                        self.verified_input_prefixes
                        if self.can_verify_derivations
                        else None,
                    )
                ]
                if unreachable:
                    raise InvalidPSBTError(
                        f"Change path {bip32.path_to_str(unreachable[0])} is "
                        f"outside this wallet.",
                        code=RejectCode.UNREACHABLE_CHANGE_PATH,
                    )

                # Change is normally issued at the next unused index, so an index
                # far beyond what the inputs demonstrate is one the wallet's own
                # scanner may never walk to. Unlike the other refusals this is a
                # threshold rather than an impossibility, which is why it is
                # adjustable -- the view tells the user where.
                if self.change_index_lookahead > 0 and self.verified_max_input_index >= 0:
                    ceiling = self.verified_max_input_index + self.change_index_lookahead
                    for derivation in derivations:
                        index = derivation[-1] & 0x7FFFFFFF
                        if index > ceiling:
                            raise InvalidPSBTError(
                                f"Change index {index} past gap limit "
                                f"(inputs {self.verified_max_input_index}).",
                                code=RejectCode.CHANGE_INDEX_TOO_FAR,
                            )

            if vout[i].script_pubkey.data[0] == OPCODES.OP_RETURN:
                # The data is written as: OP_RETURN + OP_PUSHDATA1 + len(payload) + payload
                self.op_return_data = vout[i].script_pubkey.data[3:]

                # Bitcoin Core v30 relaxed OP_RETURN standardness, so the amount
                # cannot be assumed to be zero. An OP_RETURN is provably
                # unspendable, so value attached to it is destroyed -- and the
                # only reason to attach any is that a signer might not count it.
                self.op_return_amount += self.psbt.tx.vout[i].value
                if self.psbt.tx.vout[i].value > 0:
                    raise InvalidPSBTError(
                        f"Output {i} burns {self.psbt.tx.vout[i].value} sats "
                        f"in an OP_RETURN.",
                        code=RejectCode.NONZERO_OP_RETURN,
                    )

            elif is_change:
                addr = vout[i].script_pubkey.address(NETWORKS[SettingsConstants.map_network_to_embit(self.network)])
                claimed_fingerprints = []
                claimed_derivation_paths = []

                # extract info from non-taproot outputs
                if len(self.psbt.outputs[i].bip32_derivations) > 0:
                    for d, derivation_path in self.psbt.outputs[i].bip32_derivations.items():
                        claimed_fingerprints.append(hexlify(derivation_path.fingerprint).decode())
                        claimed_derivation_paths.append(bip32.path_to_str(derivation_path.derivation))

                # extract info from taproot outputs
                if len(self.psbt.outputs[i].taproot_bip32_derivations) > 0:
                    for d, (leaf_hashes, derivation) in self.psbt.outputs[i].taproot_bip32_derivations.items():
                        claimed_fingerprints.append(hexlify(derivation.fingerprint).decode())
                        claimed_derivation_paths.append(bip32.path_to_str(derivation.derivation))

                self.change_data.append({
                    "output_index": i,
                    "address": addr,
                    "amount": vout[i].value,
                    "claimed_fingerprints": claimed_fingerprints,
                    "claimed_derivation_paths": claimed_derivation_paths,
                })
                self.change_amount += vout[i].value

            else:
                try:
                    addr = vout[i].script_pubkey.address(NETWORKS[SettingsConstants.map_network_to_embit(self.network)])
                except (ValueError, EmbitError) as e:
                    # No address representation. The signing model here is that the
                    # user authorises what the screen shows, so a destination that
                    # cannot be displayed cannot be authorised -- and this used to
                    # escape as a bare ValueError, i.e. a crash screen rather than a
                    # decision.
                    #
                    # The case that matters is an output to witness version 2-16.
                    # Those versions are reserved for future soft forks and are
                    # currently anyone-can-spend, so value sent there is not merely
                    # unaddressable, it is takeable by anyone who notices. Bare
                    # multisig and other non-standard scripts land here too and are
                    # equally unreviewable.
                    raise InvalidPSBTError(
                        f"Output {i} script cannot be shown as an address.",
                        code=RejectCode.UNDISPLAYABLE_OUTPUT,
                    ) from e
                self.destination_addresses.append(addr)
                self.destination_amounts.append(vout[i].value)
                self.spend_amount += vout[i].value

        self.fee_amount = self.psbt.fee()

        if self.fee_amount < 0:
            # sum(outputs) > sum(inputs). Either the psbt understates an input
            # amount or overstates an output; either way the fee on screen would
            # be a fiction.
            raise InvalidPSBTError(
                f"Outputs exceed inputs by {-self.fee_amount} sats",
                code=RejectCode.NEGATIVE_FEE,
            )

        accounted = self.spend_amount + self.change_amount + self.op_return_amount + self.fee_amount
        if accounted != self.input_amount:
            raise InvalidPSBTError(
                f"Amounts do not add up: {accounted} vs {self.input_amount} in.",
                code=RejectCode.AMOUNT_OUT_OF_RANGE,
            )

        self._collect_risk_warnings()
        return True


    def _collect_risk_warnings(self):
        """
        Flag the things a user would want to know before approving, none of
        which make the transaction invalid.
        """
        if self.input_amount > 0 and (
            self.fee_amount * HIGH_FEE_DENOMINATOR >= self.input_amount * HIGH_FEE_NUMERATOR
        ):
            self.risk_warnings.add(RiskWarning.HIGH_FEE)

        self._check_fee_rate()

        for vout in self.psbt.tx.vout:
            if vout.script_pubkey.data and vout.script_pubkey.data[0] == OPCODES.OP_RETURN:
                continue
            if vout.value < DUST_THRESHOLD:
                self.risk_warnings.add(RiskWarning.DUST_OUTPUT)
                break

        # nLockTime is only enforced by consensus if at least one input is
        # non-final; with every sequence at 0xffffffff the field is inert and
        # warning about it would be a false alarm.
        self.locktime_is_enforced = any(
            vin.sequence != SEQUENCE_FINAL for vin in self.psbt.tx.vin
        )

        locktime = self.psbt.tx.locktime or 0
        self.locktime = locktime
        if (self.locktime_is_enforced
                and locktime >= LOCKTIME_TIMESTAMP_THRESHOLD
                and locktime > time.time()):
            # Block-height locktimes are left alone: anti-fee-sniping sets one on
            # every ordinary transaction, and we have no chain tip to compare to.
            self.risk_warnings.add(RiskWarning.FUTURE_LOCKTIME)

        for vin in self.psbt.tx.vin:
            if vin.sequence < RBF_SEQUENCE_CEILING:
                self.risk_warnings.add(RiskWarning.RBF)
                break

        self._check_far_future_locktime(locktime)

        # BIP-68 relative timelocks. For a version 2+ transaction, an input whose
        # sequence has the disable bit clear cannot be spent until a delay has
        # elapsed since the *input* confirmed -- up to 65535 blocks (~15 months)
        # or 65535*512 seconds (~1 year).
        #
        # This has to be called out separately rather than folded into RBF. Any
        # such sequence is below RBF_SEQUENCE_CEILING, so it already trips the RBF
        # check -- and a user told only "replaceable" would have no idea the
        # transaction cannot confirm for a year. Same harm as a future nLockTime,
        # so it interrupts for the same reason.
        if (self.psbt.tx.version or 0) >= 2:
            for vin in self.psbt.tx.vin:
                if vin.sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
                    continue
                if vin.sequence & SEQUENCE_LOCKTIME_MASK:
                    self.risk_warnings.add(RiskWarning.RELATIVE_TIMELOCK)
                    break



    @staticmethod
    def trim(tx):
        trimmed_psbt = psbt.PSBT(tx.tx)
        for i, inp in enumerate(tx.inputs):
            if inp.final_scriptwitness:
                # Taproot sign; trim to only final_scriptwitness
                # From BIP-371 and BIP-174, once final script witness is populated
                # it contains all necessary signatures
                trimmed_psbt.inputs[i].final_scriptwitness = inp.final_scriptwitness
            else:
                trimmed_psbt.inputs[i].partial_sigs = inp.partial_sigs

        return trimmed_psbt


    @staticmethod
    def sig_count(tx):
        cnt = 0
        for i, inp in enumerate(tx.inputs):
            if inp.final_scriptwitness is not None:
                # Taproot sign
                cnt += 1
            else:
                cnt += len(list(inp.partial_sigs.keys()))

        return cnt


    @staticmethod
    def _get_policy(scope, scriptpubkey, xpubs, child_key_derivation_cache: dict | None):
        """Parse scope and get policy"""
        # we don't know the policy yet, let's parse it
        script_type = scriptpubkey.script_type()
        # p2sh can be either legacy multisig, or nested segwit multisig
        # or nested segwit singlesig
        if script_type == "p2sh":
            if scope.witness_script is not None:
                script_type = "p2sh-p2wsh"
            elif (
                scope.redeem_script is not None
                and scope.redeem_script.script_type() == "p2wpkh"
            ):
                script_type = "p2sh-p2wpkh"
        policy = {"type": script_type}

        # expected multisig
        script = None
        if script_type:
            if "p2wsh" in script_type and scope.witness_script is not None:
                script = scope.witness_script

            elif "p2sh" == script_type and scope.redeem_script is not None:
                script = scope.redeem_script

            if script is not None:
                # A scope may carry a redeem/witness script that isn't multisig at
                # all -- a coordinator quirk on ordinary outputs, or an attacker
                # feeding us arbitrary bytes. Either way it must not abort the
                # parse; the scope just isn't multisig.
                try:
                    m, n, pubkeys = PSBTParser._parse_multisig(script)
                except (ValueError, EmbitError) as e:
                    logger.debug("Scope script is not multisig: %s", e)
                    return policy

                # check pubkeys are derived from cosigners
                try:
                    cosigners = PSBTParser._get_cosigners(pubkeys, scope.bip32_derivations, xpubs, child_key_derivation_cache)
                    policy.update({"m": m, "n": n, "cosigners": cosigners})
                except:
                    # TODO: stop swallowing everything here. This also catches bugs in the
                    # cosigner check itself, and cannot tell those apart from the psbt
                    # simply not supplying xpubs to check against, which is valid and must
                    # not be rejected outright. The fallback policy carries no cosigner
                    # information at all, and two of those compare equal on script type
                    # and m-of-n alone. Fix pending with the multisig verification work.
                    policy.update({"m": m, "n": n})

        return policy


    @staticmethod
    def _parse_multisig(sc):
        """Takes a script and extracts m,n and pubkeys from it"""
        # OP_m <len:pubkey> ... <len:pubkey> OP_n OP_CHECKMULTISIG
        # check min size
        if len(sc.data) < 37 or sc.data[-1] != 0xAE:
            raise ValueError("Not a multisig script")
        m = sc.data[0] - 0x50
        if m < 1 or m > 16:
            raise ValueError("Invalid multisig script")
        n = sc.data[-2] - 0x50
        if n < m or n > 16:
            raise ValueError("Invalid multisig script")
        s = BytesIO(sc.data)
        # drop first byte
        s.read(1)
        # read pubkeys
        pubkeys = []
        for i in range(n):
            char = s.read(1)
            if char != b"\x21":
                raise ValueError("Invlid pubkey")
            pubkeys.append(ec.PublicKey.parse(s.read(33)))
        # check that nothing left
        if s.read() != sc.data[-2:]:
            raise ValueError("Invalid multisig script")
        return m, n, pubkeys


    @staticmethod
    def _derive_with_cache(parent_key: bip32.HDKey, derivation_path: List[int], child_key_derivation_cache: dict | None = None) -> bip32.HDKey:
        """
        Derives the key that sits at the given derivation path below parent_key, reusing
        any levels along the way that have already been derived during this parse.

        A derivation path is traversed one level at a time, and two derivation paths that
        begin the same way share those opening levels. Each level reached is stored in the
        cache, so a later derivation running through that level picks it up instead of
        deriving it a second time.

        Entries are keyed on (id(parent_key), derivation_path_so_far), the path traversed
        down from that parent to reach this point. id() is the Python built-in for an
        object's identity; the parent belongs in the key because a multisig parse runs
        these same derivations below each cosigner's xpub in turn.

        Each entry also holds on to the parent it was derived from. id() is only the
        object's address, which Python is free to hand to a new object once the original
        is released. Keeping the parent means its address cannot be reused for as long as
        the entry it belongs to is alive.

        Keying on the parent's fingerprint was rejected: four bytes is small enough for a
        malicious coordinator to grind a deliberate collision, and the cosigner xpubs come
        from the psbt.

        The cache stops accepting new levels at MAX_CACHED_DERIVATIONS.
        """
        if child_key_derivation_cache is None:
            return parent_key.derive(derivation_path)

        derived_key = parent_key
        derivation_path_so_far = ()

        # Traverse the derivation path...
        for index in derivation_path:
            derivation_path_so_far += (index,)
            cache_key = (id(parent_key), derivation_path_so_far)
            cached_entry = child_key_derivation_cache.get(cache_key)
            if cached_entry is None:
                # First time deriving this level. Do the work to derive this level's child
                # and store it in the cache.
                already_derived = derived_key.child(index)
                if len(child_key_derivation_cache) < PSBTParser.MAX_CACHED_DERIVATIONS:
                    # Parent must also be stored to keep its id() from being reused
                    child_key_derivation_cache[cache_key] = (parent_key, already_derived)
            else:
                cached_parent, already_derived = cached_entry
            derived_key = already_derived
        return derived_key


    @staticmethod
    def _get_cosigners(pubkeys, derivations, xpubs, child_key_derivation_cache: dict | None):
        """Returns xpubs used to derive pubkeys using global xpub field from psbt"""
        cosigners = []
        for i, pubkey in enumerate(pubkeys):
            if pubkey not in derivations:
                raise ValueError("Missing derivation")
            der = derivations[pubkey]
            for xpub in xpubs:
                origin_der = xpubs[xpub]
                # check fingerprint
                if origin_der.fingerprint == der.fingerprint:
                    # check derivation - last two indexes give pub from xpub
                    if origin_der.derivation == der.derivation[:-2]:
                        # check that it derives to pubkey actually
                        derived_key = PSBTParser._derive_with_cache(
                            xpub, der.derivation[-2:], child_key_derivation_cache)
                        if derived_key.key == pubkey:
                            # append strings so they can be sorted and compared
                            cosigners.append(xpub.to_base58())
                            break
        if len(cosigners) != len(pubkeys):
            raise RuntimeError("Can't get all cosigners")
        return sorted(cosigners)


    @staticmethod
    def get_input_fingerprints(psbt: PSBT) -> List[str]:
        """
            Exctracts the fingerprint from each input's derivation path.

            TODO: It's unclear if these derivations/fingerprints would ever be missing.
            Research on PSBT standard and known wallet coordinator implementations
            needed.
        """
        fingerprints = set()
        for input in psbt.inputs:
            for pub, derivation_path in input.bip32_derivations.items():
                fingerprints.add(hexlify(derivation_path.fingerprint).decode())

            for pub, (leaf_hashes, derivation_path) in input.taproot_bip32_derivations.items():
                # TODO: Support spends from leaves; depends on support in embit
                if len(leaf_hashes) > 0:
                    raise Exception("Signing keyspends from within a taptree not yet implemented")
                fingerprints.add(hexlify(derivation_path.fingerprint).decode())
        return list(fingerprints)


    @staticmethod
    def has_matching_input_fingerprint(
        psbt: PSBT,
        seed: Seed | None = None,
        network: str = SettingsConstants.MAINNET,
        *,
        root: bip32.HDKey | None = None,
    ):
        """
            Extracts the claimed fingerprint from each psbt input. Returns True if any
            match the provided seed.

            This is merely a routing hint to help the user select a seed that looks like
            it should be able to sign the psbt; it verifies nothing. Actual verification
            only begins once a seed has been selected and passed into a PSBTParser
            instance.
        """
        if seed is not None:
            seed_fingerprint = seed.get_fingerprint(network)
        elif root is not None:
            seed_fingerprint = hexlify(root.child(0).fingerprint).decode()
        else:
            return False

        def check_fingerprint_match(public_key: PublicKey, derivation_path_obj: DerivationPath, is_taproot: bool):
            """Check fingerprint match with missing fingerprint fallback"""

            # If exact fingerprint match
            if hexlify(derivation_path_obj.fingerprint).decode() == seed_fingerprint:
                return True

            # Missing fingerprint fallback
            if derivation_path_obj.fingerprint == b"\x00\x00\x00\x00":
                fallback_root = root
                if fallback_root is None:
                    fallback_root = bip32.HDKey.from_seed(seed.seed_bytes, version=NETWORKS[SettingsConstants.map_network_to_embit(network)]["xprv"])
                try:
                    # fallback_root, not root: the caller may have passed no root at
                    # all, in which case the master key was just derived from the seed
                    # above.
                    return PSBTParser.seed_owns_pubkey(fallback_root, derivation_path_obj.derivation, public_key, child_key_derivation_cache=None, is_taproot=is_taproot)
                except Exception as e:
                    logger.debug("Fingerprint fallback derive failed: %s", e, exc_info=True)
            return False

        # Check all derivations in all inputs
        for input in psbt.inputs:
            # Check regular BIP32 derivations
            for public_key, derivation_path_obj in input.bip32_derivations.items():
                if check_fingerprint_match(public_key, derivation_path_obj, is_taproot=False):
                    return True

            # Check Taproot derivations
            for public_key, (leaf_hashes, derivation_path_obj) in input.taproot_bip32_derivations.items():
                if check_fingerprint_match(public_key, derivation_path_obj, is_taproot=True):
                    return True
        
        return False


    @staticmethod
    def seed_owns_pubkey(root: bip32.HDKey, claimed_derivation_path: List[int], public_key: PublicKey, child_key_derivation_cache: dict | None, is_taproot: bool = False, root_path: List[int] | None = None) -> bool:
        """
        Returns True if the signing seed (root) really does derive public_key at
        claimed_derivation_path.

        This is the canonical ownership check. The fingerprint a psbt or a descriptor
        carries alongside a key is metadata that whoever wrote the file chose, so it can
        say anything. Ownership is established here and only here, by deriving the key
        again from the seed and comparing the actual key material.

        claimed_derivation_path is always the psbt's full path, measured from the master
        key. `root` need not be the master key: a smartcard exports an account-level xpub
        and nothing below it, so root_path names where that xpub sits and the leading
        levels are dropped before deriving. See PSBTParser.root_path.
        """
        if root_path:
            if list(claimed_derivation_path[:len(root_path)]) != list(root_path):
                # The claim starts somewhere this root cannot reach, so this root
                # derives nothing at that path and owns nothing there.
                return False
            claimed_derivation_path = claimed_derivation_path[len(root_path):]

        derived_public_key = PSBTParser._derive_with_cache(root, claimed_derivation_path, child_key_derivation_cache).get_public_key()

        if is_taproot:
            # A psbt carries a taproot key as its bare 32-byte x coordinate, but embit
            # rebuilds a full key from it by just assuming even parity. The key derived
            # from the seed carries its real parity, so a naive full-key comparison
            # succeeds only when that real parity happens to be even, wrongly rejecting
            # roughly half of the keys this seed genuinely owns. Only the x coordinate is
            # real information: compare x-only.
            return derived_public_key.xonly() == public_key.xonly()

        # For ecdsa the parity byte IS part of the identity, so compare the full key.
        # This is deliberately stricter than embit, whose sign_with compares x-only even
        # for ecdsa. embit would sign a psbt whose entry names the parity-flipped twin of
        # our real key. The flipped key is still one this seed does NOT derive, and the
        # signature embit produces under it is one no standard finalizer can use. So this
        # extra strictness only rejects transactions that could never actually complete.
        return derived_public_key == public_key


    @staticmethod
    def _get_seed_derivation_path(scope: InputScope | OutputScope, root: bip32.HDKey, child_key_derivation_cache: dict, seed_fingerprint: bytes, root_path: List[int] | None = None) -> List[int] | None:
        """
        Scans the derivation path(s) in the provided input or output scope to determine
        which, if any, are provably derived from the signing seed (for multisig a path is
        provided per key; if the seed is part of the multisig, one of the n paths will
        match). Returns the verified derivation path (as a list of ints) or None.

        Every key in the scope that claims this seed's fingerprint is re-derived and
        checked. A claim that does not hold up raises InvalidPSBTError with
        RejectCode.FORGED_[OUTPUT|INPUT]_OWNERSHIP. This includes fingerprint collisions
        (two different keys with the same 4-byte fingerprint):
        * On the output side, a collision is considered an attack.
        * On the input side it is merely disallowed because it is unsignable by embit.

        seed_fingerprint is passed in rather than read off `root`, because `root` is not
        always the master key: with a smartcard it is an account-level xpub whose own
        fingerprint is not the one the psbt names. See PSBTParser.master_fingerprint.

        One edge case:
        * A multisig could use this seed in more than one cosigner slot, each
          at its own derivation path. The scope then carries several entries that all
          verify against this seed; we return the first but still check the rest.

        The path itself is still whatever the psbt supplied: it can be any length or
        shape, since any path that derives from the seed will pass. Whether the path is
        one the user's wallet would ever look at is a separate question, answered
        elsewhere.
        """
        verified_derivation_path = None

        def _check_claim(public_key: PublicKey, derivation_path_obj: DerivationPath, is_taproot: bool):
            nonlocal verified_derivation_path

            if derivation_path_obj.fingerprint != seed_fingerprint:
                # Claims to belong to some other key. Nothing to prove or disprove here.
                return

            if not PSBTParser.seed_owns_pubkey(root, derivation_path_obj.derivation, public_key, child_key_derivation_cache, is_taproot=is_taproot, root_path=root_path):
                code = (RejectCode.FORGED_INPUT_OWNERSHIP if isinstance(scope, InputScope) else RejectCode.FORGED_OUTPUT_OWNERSHIP)
                raise InvalidPSBTError(
                    f"Key at {bip32.path_to_str(derivation_path_obj.derivation)} claims this seed's fingerprint but does not derive from it",
                    code=code,
                )

            # Store only the first verified path
            if verified_derivation_path is None:
                verified_derivation_path = derivation_path_obj.derivation

        # Note that both loops check EVERY claim
        for public_key, derivation_path_obj in scope.bip32_derivations.items():
            _check_claim(public_key, derivation_path_obj, is_taproot=False)

        for public_key, (leaf_hashes, derivation_path_obj) in scope.taproot_bip32_derivations.items():
            # TODO: Support keys in taptree leaves
            _check_claim(public_key, derivation_path_obj, is_taproot=True)

        return verified_derivation_path


    def _verify_claimed_derivation_paths(self, child_key_derivation_cache: dict):
        """
        Verifies every claimed derivation path that names this seed's fingerprint. The
        result, stored in verified_[input|output]_derivation_paths, is either the verified
        derivation path or None (the seed was not named) for each input/output scope.

        The coordinator-supplied fingerprints cannot be trusted as-is. We must derive and
        verify the ownership of each one that claims to belong to this seed.

        Outputs are verified before inputs; a false claim on an output (e.g. fake-change
        forgery) is likely an attack whereas a false claim on an input is merely
        unsignable.

        Raises InvalidPSBTError with RejectCode.FORGED_[OUTPUT|INPUT]_OWNERSHIP on the
        first false claim detected.

        Does nothing when there is no BIP32 tree to derive against -- WIF / BIP38
        signing, or a seedless multisig pre-parse. Both lists stay empty, which
        _reject_if_seed_cannot_sign reads as "no evidence expected" rather than as
        "no ownership found".
        """
        if not self.can_verify_derivations:
            return

        seed_fingerprint = self.master_fingerprint or self.root.my_fingerprint

        self.verified_output_derivation_paths = [
            PSBTParser._get_seed_derivation_path(out, self.root, child_key_derivation_cache, seed_fingerprint, self.root_path)
            for out in self.psbt.outputs
        ]

        self.verified_input_derivation_paths = [
            PSBTParser._get_seed_derivation_path(inp, self.root, child_key_derivation_cache, seed_fingerprint, self.root_path)
            for inp in self.psbt.inputs
        ]


    def _reject_if_seed_cannot_sign(self):
        """
        Rejects the psbt when none of its inputs rely on a key derived by this seed.

        We detect it here, early, so the psbt can be rejected without sending the user
        through the full verification flow only for signing to fail at the end anyway.

        (embit's sign_with is marginally more permissive: it also signs an input whose
        script names the master key directly, with no derivation. That runs against how HD
        wallets are built. The master key is a derivation root, not a spending key, so no
        standard wallet produces such a psbt. We deliberately ignore this case.

        Similarly, it's not worth the effort to verify that each key is included in its
        input's script. A psbt that excludes a key in that way would be nonsensical but
        harmless: the excluded key cannot spend the input, so nothing of this seed's is
        at risk.)

        Skipped when there is no BIP32 tree to derive against, because then nothing was
        verified and an empty result is not evidence of absence. WIF / BIP38 signing
        matches its key against the input script in _parse_inputs instead.
        """
        if not self.can_verify_derivations:
            return

        # An input names a key at a derivation path and _verify_claimed_derivation_paths
        # proved the seed derives it (single-sig: one such key; multisig: one per
        # cosigner, ours among them). One verified input path is enough for the psbt to
        # be signable.
        if any(path is not None for path in self.verified_input_derivation_paths):
            return

        # There's nothing for this seed to sign
        raise InvalidPSBTError(
            "None of the inputs in this transaction are controlled by this seed.",
            code=RejectCode.SEED_CANNOT_SIGN,
        )


    def verify_multisig_output(self, descriptor: Descriptor, change_num: int) -> bool:
        change_data = self.get_change_data(change_num)
        i = change_data["output_index"]
        output = self.psbt.outputs[i]
        is_owner = descriptor.owns(output)
        # print(f"{self.psbt.tx.vout[i].script_pubkey.address()} | {output.value} | {is_owner}")
        return is_owner


    def _fill_missing_fingerprints(self, child_key_derivation_cache: dict):
        """
        Fix for when fingerprint is missing (defaults to all zeros). Happens when the user
        creates a new wallet in an external coordinator but only provides the xpub
        (fingerprint and derivation path are omitted).

        Filling the missing fingerprints allows SeedSigner to correctly identify inputs /
        outputs that belong to the signing seed.

        see: https://github.com/SeedSigner/seedsigner/issues/359
        """
        if not self.root:
            return 0

        if not isinstance(self.root, bip32.HDKey):
            # WIF/BIP38 signing uses a bare private key; there are no BIP32
            # derivations to reconcile.
            return 0

        def _fill_scope(scope: InputScope | OutputScope):
            """Helper function to fill missing fingerprints in a scope (input/output)"""

            # Helper function to check and fix fingerprint
            def _get_updated_fingerprint(public_key: PublicKey, derivation_path_obj: DerivationPath, is_taproot: bool) -> DerivationPath | None:
                if derivation_path_obj.fingerprint != b"\x00\x00\x00\x00":
                    return None

                # If the signing seed really derives the psbt-provided public key at the
                # claimed derivation path, this input/output is owned by the signing seed.
                # In that case we populate the missing (zero) fingerprint with the signing
                # seed's master fingerprint so downstream parsing/signing can treat it as
                # owned by this seed.
                # root_path / master_fingerprint keep this correct when `root` is an
                # account-level xpub from a smartcard rather than the master key.
                if PSBTParser.seed_owns_pubkey(self.root, derivation_path_obj.derivation, public_key, child_key_derivation_cache, is_taproot=is_taproot, root_path=self.root_path):
                    return DerivationPath(self.master_fingerprint or self.root.my_fingerprint, derivation_path_obj.derivation)
                return None

            # Handle regular BIP32 derivations
            for public_key, derivation_path_obj in list(scope.bip32_derivations.items()):
                new_derivation = _get_updated_fingerprint(public_key, derivation_path_obj, is_taproot=False)
                if new_derivation:
                    scope.bip32_derivations[public_key] = new_derivation
                    logger.debug(f"Filled missing fingerprint for pubkey {public_key.sec().hex()} derivation {bip32.path_to_str(derivation_path_obj.derivation)}")

            # Handle Taproot derivations
            for public_key, (leaf_hashes, derivation_path_obj) in list(scope.taproot_bip32_derivations.items()):
                new_derivation = _get_updated_fingerprint(public_key, derivation_path_obj, is_taproot=True)
                if new_derivation:
                    scope.taproot_bip32_derivations[public_key] = (leaf_hashes, new_derivation)
                    logger.debug(f"Filled missing fingerprint for pubkey {public_key.sec().hex()} derivation {bip32.path_to_str(derivation_path_obj.derivation)}")

        for inp in self.psbt.inputs:
            _fill_scope(inp)

        for out in self.psbt.outputs:
            _fill_scope(out)