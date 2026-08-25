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
    DUST_OUTPUT = "DUST_OUTPUT"
    FUTURE_LOCKTIME = "FUTURE_LOCKTIME"
    RBF = "RBF"

    # Recorded, but not worth interrupting the user for. Opt-in RBF is the
    # default in every modern coordinator; an interstitial on every ordinary
    # transaction just teaches people to click past the ones that matter.
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
    ):
        self.psbt: PSBT = p
        self.seed = seed
        self.network = network
        self.root = root
        self.root_path = root_path or []
        self.root_path_str = bip32.path_to_str(self.root_path) if self.root_path else "m"
        self.master_fingerprint = master_fingerprint
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
        self.input_derivation_prefixes: set = set()
        self.max_input_derivation_index: int = -1
        self.destination_addresses = []
        self.destination_amounts = []
        self.op_return_data: bytes = None
        self.op_return_amount: int = 0
        self.risk_warnings: set[str] = set()

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
        if self.psbt is None:
            logger.info(f"self.psbt is None!!")
            return False

        if self.seed is not None and self.root is None:
            self._set_root()

        # Try to fix missing fingerprints before parsing
        self._fill_missing_fingerprints()

        rt = self._parse_inputs()
        if rt == False:
            return False

        if self.root is None and self.seed is None and not self.is_multisig:
            raise RuntimeError("No seed or root key available")

        rt = self._parse_outputs()
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


    def _parse_inputs(self):
        self.input_amount = 0
        self.num_inputs = len(self.psbt.inputs)
        self.input_derivation_prefixes = set()
        self.max_input_derivation_index = -1
        for i, inp in enumerate(self.psbt.inputs):
            PSBTParser._validate_input(i, inp)

            # Everything above the trailing branch/index pair. These utxos are
            # already in the wallet, so this is evidence of where it keeps keys.
            for derivation in self._scope_derivations(inp):
                if len(derivation) >= 2:
                    self.input_derivation_prefixes.add(tuple(derivation[:-2]))
                if derivation:
                    self.max_input_derivation_index = max(
                        self.max_input_derivation_index,
                        derivation[-1] & 0x7FFFFFFF,
                    )

            if inp.witness_utxo:
                self.input_amount += inp.witness_utxo.value
                script_pubkey = inp.witness_utxo.script_pubkey
            elif inp.non_witness_utxo:
                self.input_amount += inp.utxo.value
                script_pubkey = inp.script_pubkey

            inp_policy = PSBTParser._get_policy(inp, script_pubkey, self.psbt.xpubs)
            if self.policy == None:
                self.policy = inp_policy
            else:
                if self.policy != inp_policy:
                    raise InvalidPSBTError(
                        "Mixed inputs in the transaction",
                        code=RejectCode.MIXED_INPUTS,
                    )

    @staticmethod
    def is_reachable_derivation(derivation: list[int], input_prefixes: set) -> bool:
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

        `input_prefixes` empty means the psbt carries no input derivations at
        all (WIF and BIP38 signing have no BIP32 paths); there is nothing to
        compare against, so only the branch is checked.
        """
        if len(derivation) < 2:
            return False
        if derivation[-2] not in (0, 1):
            return False
        if input_prefixes and tuple(derivation[:-2]) not in input_prefixes:
            return False
        return True


    @staticmethod
    def is_change_branch(derivation: list[int]) -> bool:
        """True for the change branch, False for receive (i.e. a self-transfer)."""
        return len(derivation) >= 2 and derivation[-2] == 1


    @staticmethod
    def _scope_derivations(scope: InputScope | OutputScope) -> list[list[int]]:
        """Every bip32 derivation on a scope, taproot and non-taproot alike."""
        derivations = [d.derivation for d in scope.bip32_derivations.values()]
        derivations += [d.derivation for _, d in scope.taproot_bip32_derivations.values()]
        return derivations


    def _parse_outputs(self):
        self.spend_amount = 0
        self.change_amount = 0
        self.change_data = []
        self.fee_amount = 0
        self.op_return_amount = 0
        self.risk_warnings = set()
        self.destination_addresses = []
        self.destination_amounts = []
        for i, out in enumerate(self.psbt.outputs):
            value = self.psbt.tx.vout[i].value
            if not 0 <= value <= MAX_MONEY:
                raise InvalidPSBTError(
                    f"Output {i} amount out of range: {value}",
                    code=RejectCode.AMOUNT_OUT_OF_RANGE,
                )
            out_policy = PSBTParser._get_policy(out, self.psbt.tx.vout[i].script_pubkey, self.psbt.xpubs)
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
                # if older multisig, just use existing script
                if self.policy["type"] == "p2sh":
                    sc = script.p2sh(out.redeem_script)

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
                        my_pubkey = self.root.derive(der)

                    if self.policy["type"] == "p2pkh" and my_pubkey is not None:
                        sc = script.p2pkh(my_pubkey)
                    if self.policy["type"] == "p2wpkh" and my_pubkey is not None:
                        sc = script.p2wpkh(my_pubkey)

                    elif self.policy["type"] == "p2sh-p2wpkh" and my_pubkey is not None:
                        sc = script.p2sh(script.p2wpkh(my_pubkey))

                    elif self.policy["type"] == "p2wpkh" and my_pubkey is not None:
                        sc = script.p2wpkh(my_pubkey)

                    if sc.data == self.psbt.tx.vout[i].script_pubkey.data:
                        is_change = True

                elif "p2tr" in self.policy["type"]:
                    my_pubkey = None
                    # should have one or zero derivations for single-key addresses
                    if hasattr(self.root, "derive") and len(out.taproot_bip32_derivations.values()) > 0:
                        # TODO: Support keys in taptree leaves
                        leaf_hashes, derivation = list(out.taproot_bip32_derivations.values())[0]
                        der = derivation.derivation[len(self.root_path):]
                        my_pubkey = self.root.derive(der)
                        sc = script.p2tr(my_pubkey)

                    if sc.data == self.psbt.tx.vout[i].script_pubkey.data:
                        is_change = True

                if sc.data == self.psbt.tx.vout[i].script_pubkey.data:
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
                        d, self.input_derivation_prefixes
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
                if self.change_index_lookahead > 0 and self.max_input_derivation_index >= 0:
                    ceiling = self.max_input_derivation_index + self.change_index_lookahead
                    for derivation in derivations:
                        index = derivation[-1] & 0x7FFFFFFF
                        if index > ceiling:
                            raise InvalidPSBTError(
                                f"Change index {index} past gap limit "
                                f"(inputs {self.max_input_derivation_index}).",
                                code=RejectCode.CHANGE_INDEX_TOO_FAR,
                            )

            if self.psbt.tx.vout[i].script_pubkey.data[0] == OPCODES.OP_RETURN:
                # The data is written as: OP_RETURN + OP_PUSHDATA1 + len(payload) + payload
                self.op_return_data = self.psbt.tx.vout[i].script_pubkey.data[3:]

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
                addr = self.psbt.tx.vout[i].script_pubkey.address(NETWORKS[SettingsConstants.map_network_to_embit(self.network)])
                fingerprints = []
                derivation_paths = []

                # extract info from non-taproot outputs
                if len(self.psbt.outputs[i].bip32_derivations) > 0:
                    for d, derivation_path in self.psbt.outputs[i].bip32_derivations.items():
                        fingerprints.append(hexlify(derivation_path.fingerprint).decode())
                        derivation_paths.append(bip32.path_to_str(derivation_path.derivation))

                # extract info from taproot outputs
                if len(self.psbt.outputs[i].taproot_bip32_derivations) > 0:
                    for d, (leaf_hashes, derivation) in self.psbt.outputs[i].taproot_bip32_derivations.items():
                        fingerprints.append(hexlify(derivation.fingerprint).decode())
                        derivation_paths.append(bip32.path_to_str(derivation.derivation))

                self.change_data.append({
                    "output_index": i,
                    "address": addr,
                    "amount": self.psbt.tx.vout[i].value,
                    "fingerprint": fingerprints,
                    "derivation_path": derivation_paths,
                })
                self.change_amount += self.psbt.tx.vout[i].value

            else:
                addr = self.psbt.tx.vout[i].script_pubkey.address(NETWORKS[SettingsConstants.map_network_to_embit(self.network)])
                self.destination_addresses.append(addr)
                self.destination_amounts.append(self.psbt.tx.vout[i].value)
                self.spend_amount += self.psbt.tx.vout[i].value

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

        for vout in self.psbt.tx.vout:
            if vout.script_pubkey.data and vout.script_pubkey.data[0] == OPCODES.OP_RETURN:
                continue
            if vout.value < DUST_THRESHOLD:
                self.risk_warnings.add(RiskWarning.DUST_OUTPUT)
                break

        locktime = self.psbt.tx.locktime or 0
        if locktime >= LOCKTIME_TIMESTAMP_THRESHOLD and locktime > time.time():
            # Block-height locktimes are left alone: anti-fee-sniping sets one on
            # every ordinary transaction, and we have no chain tip to compare to.
            self.risk_warnings.add(RiskWarning.FUTURE_LOCKTIME)

        for vin in self.psbt.tx.vin:
            if vin.sequence < RBF_SEQUENCE_CEILING:
                self.risk_warnings.add(RiskWarning.RBF)
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
    def _get_policy(scope, scriptpubkey, xpubs):
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
                    cosigners = PSBTParser._get_cosigners(pubkeys, scope.bip32_derivations, xpubs)
                    policy.update({"m": m, "n": n, "cosigners": cosigners})
                except:
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
    def _get_cosigners(pubkeys, derivations, xpubs):
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
                        if xpub.derive(der.derivation[-2:]).key == pubkey:
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
            Extracts the fingerprint from each psbt input utxo. Returns True if any match
            the current seed or root xpub.
        """
        if seed is not None:
            seed_fingerprint = seed.get_fingerprint(network)
        elif root is not None:
            seed_fingerprint = hexlify(root.child(0).fingerprint).decode()
        else:
            return False

        def check_fingerprint_match(public_key: PublicKey, derivation_path_obj: DerivationPath):
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
                    derived_key = fallback_root.derive(derivation_path_obj.derivation)
                    return derived_key.key.sec() == public_key.sec() # Public keys match
                except Exception as e:
                    logger.debug("Fingerprint fallback derive failed: %s", e, exc_info=True)
            return False
        
        # Check all derivations in all inputs
        for input in psbt.inputs:
            # Check regular BIP32 derivations
            for public_key, derivation_path_obj in input.bip32_derivations.items():
                if check_fingerprint_match(public_key, derivation_path_obj):
                    return True
            
            # Check Taproot derivations
            for public_key, (leaf_hashes, derivation_path_obj) in input.taproot_bip32_derivations.items():
                if check_fingerprint_match(public_key, derivation_path_obj):
                    return True
        
        return False


    def verify_multisig_output(self, descriptor: Descriptor, change_num: int) -> bool:
        change_data = self.get_change_data(change_num)
        i = change_data["output_index"]
        output = self.psbt.outputs[i]
        is_owner = descriptor.owns(output)
        # print(f"{self.psbt.tx.vout[i].script_pubkey.address()} | {output.value} | {is_owner}")
        return is_owner


    def _fill_missing_fingerprints(self):
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
            signing_seed_fingerprint = self.root.child(0).fingerprint
            
            # Helper function to check and fix fingerprint
            def _get_updated_fingerprint(public_key: PublicKey, derivation_path_obj: DerivationPath) -> DerivationPath | None:
                if derivation_path_obj.fingerprint != b"\x00\x00\x00\x00":
                    return None
                
                # Derive the public key from the currently loaded seed using the derivation 
                # contained in the PSBT. If the derived public key exactly matches 
                # the PSBT-provided public key, we can be confident that this input/output 
                # is owned by the signing seed. In that case we populate the missing (zero) 
                # fingerprint with the signing seed's master fingerprint so downstream 
                # parsing/signing can treat it as owned by this seed.
                derived_key = self.root.derive(derivation_path_obj.derivation)
                if derived_key.key.sec() == public_key.sec():
                    return DerivationPath(signing_seed_fingerprint, derivation_path_obj.derivation)
                return None
            
            # Handle regular BIP32 derivations
            for public_key, derivation_path_obj in list(scope.bip32_derivations.items()):
                new_derivation = _get_updated_fingerprint(public_key, derivation_path_obj)
                if new_derivation:
                    scope.bip32_derivations[public_key] = new_derivation
                    logger.debug(f"Filled missing fingerprint for pubkey {public_key.sec().hex()} derivation {bip32.path_to_str(derivation_path_obj.derivation)}")
            
            # Handle Taproot derivations  
            for public_key, (leaf_hashes, derivation_path_obj) in list(scope.taproot_bip32_derivations.items()):
                new_derivation = _get_updated_fingerprint(public_key, derivation_path_obj)
                if new_derivation:
                    scope.taproot_bip32_derivations[public_key] = (leaf_hashes, new_derivation)
                    logger.debug(f"Filled missing fingerprint for pubkey {public_key.sec().hex()} derivation {bip32.path_to_str(derivation_path_obj.derivation)}")

        for inp in self.psbt.inputs:
            _fill_scope(inp)

        for out in self.psbt.outputs:
            _fill_scope(out)