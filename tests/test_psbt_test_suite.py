"""
The `psbt_faker` adversarial PSBT corpus, run against SeedSigner's model layer.

Each vector encodes a trap that a vulnerable signer falls for. The expectations
here describe what a *secure* signer must do — see `tests/psbt_suite_util.py` for
the per-vector table and `tests/data/psbt_test_suite/PROVENANCE.md` for where the
fixtures come from.

Nothing here is marked xfail: a failure means SeedSigner is currently vulnerable
to that vector.
"""
import time

import pytest

from embit.base import EmbitError

from seedsigner.models.psbt_parser import InvalidPSBTError, PSBTParser, RejectCode
from seedsigner.models.settings_definition import SettingsConstants

from embit import bip32

from psbt_suite_util import (
    Advisory,
    CHANGE_INDEX_LOOKAHEAD,
    DUST_THRESHOLD,
    HIGH_FEE_DENOMINATOR,
    HIGH_FEE_NUMERATOR,
    MAX_MONEY,
    NON_SIGHASH_ALL_VECTORS,
    NORMAL_VECTORS,
    PARSING_VECTORS,
    REJECT_EMBIT_VECTORS,
    REJECT_PARSER_VECTORS,
    SUITE_FINGERPRINT,
    SUITE_NETWORK,
    VECTORS,
    VECTORS_BY_NAME,
    Vector,
    build_huge_witness_psbt,
    build_nonzero_op_return_psbt,
    build_utxo_mismatch_psbt,
    load_psbt,
    suite_seed,
)


def ids(vectors):
    return [v.name for v in vectors]


def parse_vector(vector: Vector) -> PSBTParser:
    """embit-parse then PSBTParser a vector with the corpus seed."""
    return PSBTParser(p=load_psbt(vector.name), seed=suite_seed(), network=SUITE_NETWORK)


class TestCorpusIntegrity:
    """The fixtures themselves, before any SeedSigner code touches them."""

    def test_seed_matches_the_corpus_fingerprint(self):
        assert suite_seed().get_fingerprint(SUITE_NETWORK) == SUITE_FINGERPRINT

    @pytest.mark.parametrize("vector", VECTORS, ids=ids(VECTORS))
    def test_fixture_is_present(self, vector: Vector):
        import os
        assert os.path.exists(vector.path), f"missing fixture {vector.path}"


class TestNormalVectors:
    """
    The four benign transactions. A false positive here is a trust-destroying
    bug in its own right: the device refusing or misdisplaying a valid spend.
    """

    @pytest.mark.parametrize("vector", NORMAL_VECTORS, ids=ids(NORMAL_VECTORS))
    def test_parses_and_accounts_correctly(self, vector: Vector):
        parser = parse_vector(vector)

        assert parser.input_amount == vector.input_amount
        assert parser.fee_amount == vector.fee_amount
        assert parser.spend_amount + parser.change_amount == vector.output_amount
        assert parser.num_change_outputs == vector.owned_outputs
        assert parser.op_return_data is None

    @pytest.mark.parametrize("vector", NORMAL_VECTORS, ids=ids(NORMAL_VECTORS))
    def test_signs_every_input(self, vector: Vector):
        psbt = load_psbt(vector.name)
        seed = suite_seed()

        assert PSBTParser.has_matching_input_fingerprint(psbt, seed, SUITE_NETWORK) is True

        sigs_added = psbt.sign_with(seed.get_root(SUITE_NETWORK))
        assert sigs_added == len(psbt.inputs)
        assert PSBTParser.sig_count(psbt) == len(psbt.inputs)


class TestRobustness:
    """
    Every vector must land in exactly one of three buckets: it parses, embit
    refuses the bytes, or PSBTParser refuses it with InvalidPSBTError. Any other
    exception type is an uncaught crash that reaches the user as the SeedSigner
    error screen.
    """

    @pytest.mark.parametrize("vector", REJECT_EMBIT_VECTORS, ids=ids(REJECT_EMBIT_VECTORS))
    def test_embit_refuses_the_bytes(self, vector: Vector):
        with pytest.raises(EmbitError):
            load_psbt(vector.name)

    @pytest.mark.parametrize("vector", REJECT_PARSER_VECTORS, ids=ids(REJECT_PARSER_VECTORS))
    def test_parser_refuses_with_a_reason(self, vector: Vector):
        with pytest.raises(InvalidPSBTError) as excinfo:
            parse_vector(vector)

        assert excinfo.value.code == vector.reject_code, (
            f"{vector.name} was refused as {excinfo.value.code!r}, "
            f"expected {vector.reject_code!r}: {vector.trap}"
        )

    @pytest.mark.parametrize("vector", PARSING_VECTORS, ids=ids(PARSING_VECTORS))
    def test_parses_without_raising(self, vector: Vector):
        parser = parse_vector(vector)
        assert parser.input_amount == vector.input_amount

    def test_huge_witness_stack_is_bounded(self):
        """
        An unrealistic witness stack declaration must not wedge the parser. The
        upstream vector is 1.5 MB of incompressible witness data, synthesized
        here rather than vendored.
        """
        from embit.psbt import PSBT

        raw = build_huge_witness_psbt()
        started = time.monotonic()
        parser = PSBTParser(p=PSBT.parse(raw), seed=suite_seed(), network=SUITE_NETWORK)
        elapsed = time.monotonic() - started

        assert parser.input_amount == 100_000_000
        assert elapsed < 30, f"parsing a 1.5MB witness took {elapsed:.1f}s"


class TestAccounting:
    """
    Money must be conserved and every amount must be a real amount. These
    invariants are what stop an attacker from hiding value in a corner of the
    transaction the review screens never total up.
    """

    @pytest.mark.parametrize("vector", PARSING_VECTORS, ids=ids(PARSING_VECTORS))
    def test_amounts_reconcile(self, vector: Vector):
        parser = parse_vector(vector)

        accounted = (
            parser.spend_amount
            + parser.change_amount
            + parser.op_return_amount
            + parser.fee_amount
        )
        assert accounted == parser.input_amount, (
            f"{vector.name}: spend {parser.spend_amount} + change {parser.change_amount} "
            f"+ op_return {parser.op_return_amount} + fee {parser.fee_amount} "
            f"!= inputs {parser.input_amount}"
        )
        assert parser.input_amount == vector.input_amount

    @pytest.mark.parametrize("vector", PARSING_VECTORS, ids=ids(PARSING_VECTORS))
    def test_fee_is_never_negative(self, vector: Vector):
        parser = parse_vector(vector)
        assert parser.fee_amount >= 0
        assert parser.fee_amount == vector.fee_amount

    @pytest.mark.parametrize("vector", PARSING_VECTORS, ids=ids(PARSING_VECTORS))
    def test_every_amount_is_within_max_money(self, vector: Vector):
        parser = parse_vector(vector)

        for amount in (parser.input_amount, parser.spend_amount,
                       parser.change_amount, parser.fee_amount):
            assert 0 <= amount <= MAX_MONEY

        for out in parser.psbt.tx.vout:
            assert 0 <= out.value <= MAX_MONEY

    def test_value_bearing_op_return_is_refused(self):
        """
        A locally-built variant of TX-02 whose OP_RETURN carries value while the
        fee stays positive, so the burn is tested on its own rather than being
        short-circuited by the negative-fee check.

        An OP_RETURN is provably unspendable, so the only reason to attach value
        is that a signer might not count it.
        """
        from psbt_suite_util import RejectCode

        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(p=build_nonzero_op_return_psbt(), seed=suite_seed(),
                       network=SUITE_NETWORK)

        assert excinfo.value.code == RejectCode.NONZERO_OP_RETURN

    def test_witness_utxo_contradicting_non_witness_utxo_is_refused(self):
        """
        The real BIP-143 amount-binding attack, which no shipped vector covers:
        an input supplying both utxo forms where the witness_utxo is not the
        real prevout.
        """
        from psbt_suite_util import RejectCode

        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(p=build_utxo_mismatch_psbt(), seed=suite_seed(), network=SUITE_NETWORK)

        assert excinfo.value.code == RejectCode.UTXO_MISMATCH


class TestSighash:
    """
    Anything other than SIGHASH_ALL hands the coordinator authority the user did
    not grant — over other inputs (ANYONECANPAY), over the outputs (NONE), or
    over the SIGHASH_SINGLE bug value (TX-07). Signing must be refused outright.
    """

    @pytest.mark.parametrize("vector", NON_SIGHASH_ALL_VECTORS, ids=ids(NON_SIGHASH_ALL_VECTORS))
    def test_refused_at_load_not_only_at_signing(self, vector: Vector):
        """
        embit's sign_with() already declines these, but only after the user has
        reviewed the whole transaction and pressed approve, and then only as a
        generic error. Refusing at load gives them a reason instead.
        """
        from psbt_suite_util import RejectCode

        with pytest.raises(InvalidPSBTError) as excinfo:
            parse_vector(vector)

        assert excinfo.value.code == RejectCode.UNSUPPORTED_SIGHASH

    @pytest.mark.parametrize("vector", NON_SIGHASH_ALL_VECTORS, ids=ids(NON_SIGHASH_ALL_VECTORS))
    def test_no_signature_is_produced(self, vector: Vector):
        """Belt and braces: even bypassing the parser, no signature is produced."""
        psbt = load_psbt(vector.name)
        sigs_added = psbt.sign_with(suite_seed().get_root(SUITE_NETWORK))

        assert sigs_added == 0, f"{vector.name}: signed a non-SIGHASH_ALL input"
        assert PSBTParser.sig_count(psbt) == 0


class TestChangeBinding:
    """
    An output may only be presented as the user's own when its derivation is
    structurally reachable by the wallet that will later scan for it. Labelling
    an unreachable path 'your change' turns a spend into a silent burn.
    """

    @pytest.mark.parametrize("vector", PARSING_VECTORS, ids=ids(PARSING_VECTORS))
    def test_owned_output_count(self, vector: Vector):
        parser = parse_vector(vector)
        assert parser.num_change_outputs == vector.owned_outputs, (
            f"{vector.name}: {parser.num_change_outputs} output(s) attributed to the "
            f"signing seed, expected {vector.owned_outputs}. {vector.trap}"
        )

    @pytest.mark.parametrize("vector", PARSING_VECTORS, ids=ids(PARSING_VECTORS))
    def test_owned_paths_sit_under_an_input_prefix(self, vector: Vector):
        """
        The inputs are utxos the wallet already found, so the prefix they share
        is evidence of where this wallet keeps its keys. Change has to sit under
        that same prefix, on branch 0 or 1 — no fixed depth is assumed, so an
        unusual-but-consistent layout still passes.
        """
        from embit import bip32

        parser = parse_vector(vector)

        for change in parser.change_data:
            for path_str in change["claimed_derivation_paths"]:
                path = bip32.parse_path(path_str)

                assert path[-2] in (0, 1), (
                    f"{vector.name}: {path_str} uses branch {path[-2]}, "
                    f"outside the receive/change branches {{0, 1}}"
                )
                assert tuple(path[:-2]) in parser.verified_input_prefixes, (
                    f"{vector.name}: {path_str} sits under "
                    f"{bip32.path_to_str(list(path[:-2]))}, but the inputs are all "
                    f"under {[bip32.path_to_str(list(x)) for x in parser.verified_input_prefixes]}"
                )


class TestEvidenceCannotBeForged:
    """
    Change binding measures a claimed change path against the prefixes the
    *inputs* demonstrate. That is only worth anything if the inputs themselves
    cannot be forged, so each way of manufacturing or withholding that evidence
    gets its own test.
    """

    def _tx01_with(self, mutate):
        from psbt_suite_util import RejectCode

        psbt = load_psbt("TX-01")
        mutate(psbt)
        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)
        assert excinfo.value.code == RejectCode.UNREACHABLE_CHANGE_PATH

    def test_self_consistent_input_path_lie_is_rejected(self):
        """
        An attacker holding the account xpub can compute a matching path/pubkey
        pair from elsewhere in our own tree and put it on the input, so the
        malicious change path shares its prefix. Re-deriving alone accepts that
        pair -- it really is ours -- so the input's script has to be checked too:
        only the prevout says which key actually unlocks these coins.
        """
        from embit.psbt import DerivationPath

        root = suite_seed().get_root(SUITE_NETWORK)

        def graft_lie(psbt):
            inp = psbt.inputs[0]
            public_key, derivation = list(inp.bip32_derivations.items())[0]
            forged = list(derivation.derivation[:3]) + [127, 0, 0]
            del inp.bip32_derivations[public_key]
            inp.bip32_derivations[root.derive(forged).key] = DerivationPath(
                derivation.fingerprint, forged
            )

        self._tx01_with(graft_lie)

    def test_withholding_input_derivations_is_rejected(self):
        """
        The cheaper attack: supply no input derivations at all, so no evidence
        can be gathered and a naive check has nothing to compare against. No
        evidence must not read as permission.
        """
        def strip(psbt):
            for inp in psbt.inputs:
                inp.bip32_derivations.clear()
                inp.taproot_bip32_derivations.clear()

        self._tx01_with(strip)

    def test_cosigner_derivations_are_not_treated_as_our_evidence(self):
        """
        A multisig input carries a derivation per cosigner. Only the one this
        seed reproduces is evidence about *this* wallet.
        """
        from binascii import a2b_base64

        from embit.psbt import PSBT

        from psbt_testing_util import PSBTTestData

        psbt = PSBT.parse(a2b_base64(PSBTTestData.MULTISIG_NATIVE_SEGWIT_1_INPUT))
        parser = PSBTParser(p=psbt, seed=PSBTTestData.seed,
                            network=SettingsConstants.REGTEST)

        # Three cosigners on the input, one prefix verified: ours.
        assert len(psbt.inputs[0].bip32_derivations) == 3
        assert len(parser.verified_input_prefixes) == 1

    def test_no_key_to_verify_with_is_not_an_empty_verdict(self):
        """
        A seedless multisig pre-parse has nothing to verify against. That must
        read as "no opinion", not as "verified nothing" -- otherwise the
        smartcard flow's first look at a psbt would refuse every change output.
        """
        from binascii import a2b_base64

        from embit.psbt import PSBT

        from psbt_testing_util import PSBTTestData

        psbt = PSBT.parse(a2b_base64(PSBTTestData.MULTISIG_NATIVE_SEGWIT_1_INPUT))
        parser = PSBTParser(psbt)
        parser.parse()

        assert parser.can_verify_derivations is False
        assert parser.num_change_outputs >= 0  # parsed without refusing


class TestAdvisories:
    """
    Conditions a signer must surface for review even though the transaction is
    structurally valid. `PSBTParser.risk_warnings` is the surface these tests
    specify.
    """

    @pytest.mark.parametrize("vector", PARSING_VECTORS, ids=ids(PARSING_VECTORS))
    def test_expected_advisories_fire(self, vector: Vector):
        parser = parse_vector(vector)
        assert vector.advisories <= parser.risk_warnings, (
            f"{vector.name}: missing {set(vector.advisories) - parser.risk_warnings}. "
            f"{vector.trap}"
        )

    @pytest.mark.parametrize("vector", PARSING_VECTORS, ids=ids(PARSING_VECTORS))
    def test_no_spurious_advisories(self, vector: Vector):
        """A signer that cries wolf on ordinary transactions gets ignored."""
        parser = parse_vector(vector)
        assert parser.risk_warnings <= set(vector.advisories), (
            f"{vector.name}: unexpected {parser.risk_warnings - set(vector.advisories)}"
        )

    def test_high_fee_threshold_matches_the_vectors(self):
        """Guards the table itself: the thresholds must classify as documented."""
        for vector in PARSING_VECTORS:
            if vector.input_amount == 0:
                continue
            over_threshold = (
                vector.fee_amount * HIGH_FEE_DENOMINATOR
                >= vector.input_amount * HIGH_FEE_NUMERATOR
            )
            assert over_threshold == (Advisory.HIGH_FEE in vector.advisories), vector.name

    def test_dust_threshold_matches_the_vectors(self):
        for vector in PARSING_VECTORS:
            psbt = load_psbt(vector.name)
            has_dust = any(
                out.value < DUST_THRESHOLD
                and not (out.script_pubkey.data and out.script_pubkey.data[0] == 0x6A)
                for out in psbt.tx.vout
            )
            assert has_dust == (Advisory.DUST_OUTPUT in vector.advisories), vector.name

    def test_change_index_lookahead_leaves_headroom_for_real_wallets(self):
        """
        Guards the threshold itself. The allowance is measured from the highest
        index the inputs demonstrate, so it stays meaningful for a wallet at any
        point in its life — but it must not be so tight that ordinary wallets
        trip it.
        """
        for vector in PARSING_VECTORS:
            parser = parse_vector(vector)
            if parser.verified_max_input_index < 0:
                continue
            for change in parser.change_data:
                for path_str in change["claimed_derivation_paths"]:
                    gap = (bip32.parse_path(path_str)[-1] & 0x7FFFFFFF) - parser.verified_max_input_index
                    assert gap <= CHANGE_INDEX_LOOKAHEAD, (
                        f"{vector.name}: {path_str} is {gap} past the highest input index"
                    )

    def test_change_index_refusal_is_adjustable(self):
        """
        Unlike the other refusals this one is a threshold, not an impossibility,
        so a user with a genuinely far-ahead wallet must be able to raise the
        Change Gap Limit rather than being locked out. "Off" disables it.
        """
        from psbt_suite_util import RejectCode

        vector = VECTORS_BY_NAME["TX-17"]

        with pytest.raises(InvalidPSBTError) as excinfo:
            parse_vector(vector)
        assert excinfo.value.code == RejectCode.CHANGE_INDEX_TOO_FAR

        # Raised high enough, the same psbt is accepted.
        relaxed = PSBTParser(p=load_psbt(vector.name), seed=suite_seed(),
                             network=SUITE_NETWORK, change_index_lookahead=100_000)
        assert relaxed.num_change_outputs == 1

        # And "Off" skips the check entirely.
        off = PSBTParser(p=load_psbt(vector.name), seed=suite_seed(),
                         network=SUITE_NETWORK, change_index_lookahead=0)
        assert off.num_change_outputs == 1


class TestPSBTVersion:
    """
    SeedSigner implements BIP-174 (v0) only. A psbt declaring BIP-370 (v2) is
    refused rather than read as v0.

    A v2 psbt has no PSBT_GLOBAL_UNSIGNED_TX -- inputs and outputs carry their own
    fields, and PSBT_GLOBAL_TX_MODIFIABLE says whether a coordinator may still add
    or remove them. Anything declaring v2 while also carrying a v0 unsigned tx is
    internally inconsistent, and reading either half means ignoring the other.
    """

    def test_v2_psbt_is_refused(self):
        with pytest.raises(InvalidPSBTError) as excinfo:
            parse_vector(VECTORS_BY_NAME["TX-12"])
        assert excinfo.value.code == RejectCode.UNSUPPORTED_PSBT_VERSION

    def test_v0_psbts_are_unaffected(self):
        """The check must not catch the ordinary case: absent or explicit 0."""
        for name in ("NORMAL-1_p2wpkh", "NORMAL-3_legacy", "NORMAL-4_multi_input"):
            psbt = load_psbt(name)
            assert getattr(psbt, "version", None) in (None, 0)
            PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)

    def test_amount_bound_still_fires_on_a_v0_psbt(self):
        """
        XTRAS.NEGATIVE_AMOUNT happens to also declare v2, so the version check
        refuses it first and its stated trap -- an output past MAX_MONEY -- stops
        being exercised by that vector. Strip the version declaration and confirm
        the amount bound is still what catches it.
        """
        psbt = load_psbt("XTRAS.NEGATIVE_AMOUNT")
        psbt.version = 0

        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)
        assert excinfo.value.code == RejectCode.AMOUNT_OUT_OF_RANGE


class TestTimelocks:
    """
    Both ways a transaction can be prevented from confirming until later.

    nLockTime is absolute and lives on the transaction; BIP-68 relative timelocks
    are per-input and live in nSequence, where they are easy to mistake for a
    plain RBF signal -- every relative-timelock sequence is also below the RBF
    ceiling, so a signer that only checks for RBF reports "replaceable" on a
    transaction that cannot confirm for a year.
    """

    def _rbf_vector_with(self, tx_version: int, sequence: int) -> PSBTParser:
        # PSBT.tx is a property that rebuilds a fresh Tx on every access, so
        # mutating psbt.tx.vin[i] writes to a throwaway. The real fields are
        # psbt.tx_version and psbt.inputs[i].sequence.
        psbt = load_psbt("XTRAS.RBF_SIGNAL")
        psbt.tx_version = tx_version
        psbt.inputs[0].sequence = sequence
        return PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)

    @pytest.mark.parametrize("sequence,label", [
        (0x0000FFFF, "65535 blocks (~15 months)"),
        (0x00400001, "512-second units (time-based)"),
    ])
    def test_relative_timelock_is_flagged(self, sequence, label):
        parser = self._rbf_vector_with(tx_version=2, sequence=sequence)
        assert Advisory.RELATIVE_TIMELOCK in parser.risk_warnings, label

    def test_relative_timelock_interrupts_rather_than_being_informational(self):
        """
        It must not be filed alongside RBF as informational: the whole point is
        that "replaceable" massively understates a year-long lock.
        """
        from seedsigner.models.psbt_parser import RiskWarning
        assert RiskWarning.RELATIVE_TIMELOCK not in RiskWarning.INFORMATIONAL

    @pytest.mark.parametrize("tx_version,sequence,reason", [
        (2, 0xFFFFFFFD, "disable bit set -- plain RBF, not a timelock"),
        (2, 0xFFFFFFFF, "final sequence"),
        (1, 0x0000FFFF, "BIP-68 is inactive below tx version 2"),
    ])
    def test_relative_timelock_not_flagged(self, tx_version, sequence, reason):
        parser = self._rbf_vector_with(tx_version, sequence)
        assert Advisory.RELATIVE_TIMELOCK not in parser.risk_warnings, reason

    def test_locktime_needs_a_non_final_input_to_be_enforced(self):
        """
        Consensus ignores nLockTime when every input is final, so warning about
        it then would be a false alarm.
        """
        psbt = load_psbt("XTRAS.LOCKTIME_FUTURE")
        psbt.inputs[0].sequence = 0xFFFFFFFF
        parser = PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)
        assert Advisory.FUTURE_LOCKTIME not in parser.risk_warnings
        assert parser.locktime_is_enforced is False

    def test_locktime_is_flagged_when_enforced(self):
        psbt = load_psbt("XTRAS.LOCKTIME_FUTURE")
        psbt.inputs[0].sequence = 0xFFFFFFFE
        parser = PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)
        assert Advisory.FUTURE_LOCKTIME in parser.risk_warnings
        assert parser.locktime_is_enforced is True


class TestUndisplayableOutputs:
    """
    The signing model is that the user authorises what the screen shows, so an
    output whose script has no address representation cannot be authorised.

    The case that matters is witness versions 2-16: reserved for future soft
    forks and currently anyone-can-spend, so value sent there is takeable by
    anyone who notices. These used to escape `_parse_outputs` as a bare
    ValueError -- a crash screen rather than a decision.
    """

    def _psbt_with_output_script(self, raw_script: bytes):
        from embit.script import Script
        psbt = load_psbt("NORMAL-1_p2wpkh")
        psbt.outputs[0].script_pubkey = Script(raw_script)
        return psbt

    @pytest.mark.parametrize("witness_version,opcode", [(2, 0x52), (5, 0x55), (16, 0x60)])
    def test_unknown_witness_version_is_refused(self, witness_version, opcode):
        psbt = self._psbt_with_output_script(bytes([opcode, 32]) + bytes(32))
        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)
        assert excinfo.value.code == RejectCode.UNDISPLAYABLE_OUTPUT

    def test_refusal_is_a_decision_not_a_crash(self):
        """A bare ValueError here would reach the user as an unhandled exception."""
        psbt = self._psbt_with_output_script(bytes([0x52, 32]) + bytes(32))
        with pytest.raises(InvalidPSBTError):
            PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)

    def test_known_witness_versions_still_parse(self):
        """v0 and v1 (taproot) must be unaffected."""
        for name in ("NORMAL-1_p2wpkh", "NORMAL-4_multi_input"):
            PSBTParser(p=load_psbt(name), seed=suite_seed(), network=SUITE_NETWORK)
