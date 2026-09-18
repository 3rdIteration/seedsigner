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
    SUITE_MAX_FEE_RATE,
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
    return PSBTParser(p=load_psbt(vector.name), seed=suite_seed(), network=SUITE_NETWORK,
                      max_fee_rate=SUITE_MAX_FEE_RATE)


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

    def _tx01_with(self, mutate, expected_code=None):
        from psbt_suite_util import RejectCode

        psbt = load_psbt("TX-01")
        mutate(psbt)
        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)
        assert excinfo.value.code == (expected_code or RejectCode.UNREACHABLE_CHANGE_PATH)

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

        The refusal now comes from the ownership scan rather than from the change
        binding check, and says so: with every input derivation stripped, the seed
        provably owns nothing on any input, which is what SEED_CANNOT_SIGN means. It
        runs first, so it answers before the change path is ever examined. The
        invariant this test exists to protect is unchanged -- the psbt is refused,
        never displayed -- and the diagnosis is the more accurate of the two.
        """
        from psbt_suite_util import RejectCode

        def strip(psbt):
            for inp in psbt.inputs:
                inp.bip32_derivations.clear()
                inp.taproot_bip32_derivations.clear()

        self._tx01_with(strip, RejectCode.SEED_CANNOT_SIGN)

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


class TestPSBTv2:
    """
    BIP-370 (v2) support. A v2 psbt describes its inputs and outputs with their own
    fields instead of an embedded unsigned tx, and carries PSBT_GLOBAL_TX_MODIFIABLE
    saying whether a coordinator may still change them after we sign.

    The version itself is not a reason to refuse: valid v2 transactions parse and
    sign exactly like their v0 twins (see TestNormalVectors), while the traps that
    matter -- a modifiable transaction, an out-of-range amount, a structurally
    incomplete record -- are caught by the same checks as for v0.
    """

    # A block anchor far enough in the past that TX-19.height_far_V2's locktime
    # (height 1,110,000) sits years ahead of it. Mirrors TestFarFutureLocktime.
    ANCHOR = (963_408, 1_787_616_000)

    def _v2(self, name="NORMAL-1_p2wpkh_V2"):
        """A fresh embit parse of a v2 fixture."""
        return load_psbt(name)

    @staticmethod
    def _reparse(psbt):
        """Round-trip through the wire format: what an attacker's bytes actually yield."""
        from embit.psbt import PSBT
        return PSBT.parse(psbt.serialize())

    # ------------------------------------------------------------- version gate

    def test_v0_and_v2_are_both_accepted(self):
        """Absent (None), explicit 0, and 2 all pass the version gate."""
        for name in ("NORMAL-1_p2wpkh", "NORMAL-3_legacy", "NORMAL-4_multi_input"):
            assert getattr(load_psbt(name), "version", None) in (None, 0)
            PSBTParser(p=load_psbt(name), seed=suite_seed(), network=SUITE_NETWORK)
        for name in ("NORMAL-1_p2wpkh_V2", "NORMAL-4_multi_input_V2"):
            assert load_psbt(name).version == 2
            PSBTParser(p=load_psbt(name), seed=suite_seed(), network=SUITE_NETWORK)

    @pytest.mark.parametrize("bad_version", [1, 3, 7])
    def test_unknown_future_version_is_refused(self, bad_version):
        """Anything other than None/0/2 is a format we would misread."""
        psbt = self._v2()
        psbt.version = bad_version
        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)
        assert excinfo.value.code == RejectCode.UNSUPPORTED_PSBT_VERSION

    # ------------------------------------------------------- TX_MODIFIABLE

    def test_modifiable_v2_is_refused(self):
        """TX-12 leaves TX_MODIFIABLE = 0x03: a coordinator could change it after we sign."""
        with pytest.raises(InvalidPSBTError) as excinfo:
            parse_vector(VECTORS_BY_NAME["TX-12"])
        assert excinfo.value.code == RejectCode.TX_MODIFIABLE

    @pytest.mark.parametrize("flags", [b"\x01", b"\x02", b"\x03"])
    def test_any_modifiable_flag_is_refused(self, flags):
        """Inputs-only (bit 0), outputs-only (bit 1), or both -- all void the review."""
        psbt = self._v2()
        psbt.unknown[b"\x06"] = flags
        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)
        assert excinfo.value.code == RejectCode.TX_MODIFIABLE

    def test_explicit_zero_modifiable_is_final(self):
        """TX_MODIFIABLE = 0x00 is the same as omitting it: the transaction is final."""
        psbt = self._v2()
        psbt.unknown[b"\x06"] = b"\x00"
        parser = PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)
        assert parser.input_amount == 100_000_000

    def test_v0_unknown_0x06_is_not_treated_as_modifiable(self):
        """On a v0 psbt key 0x06 is just an unknown field, not BIP-370 modifiability."""
        psbt = load_psbt("NORMAL-1_p2wpkh")
        assert getattr(psbt, "version", None) in (None, 0)
        psbt.unknown[b"\x06"] = b"\x03"
        parser = PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)
        assert parser.input_amount == 100_000_000

    # ------------------------------------------------- structural completeness

    def test_missing_output_amount_is_refused_not_crashed(self):
        """A v2 output with no amount would otherwise die on `0 <= None`."""
        psbt = self._v2()
        psbt.outputs[0].value = None
        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(p=self._reparse(psbt), seed=suite_seed(), network=SUITE_NETWORK)
        assert excinfo.value.code == RejectCode.AMOUNT_OUT_OF_RANGE

    def test_empty_output_script_is_refused(self):
        """A v2 output with no script has no address to show, so it cannot be authorised."""
        from embit.script import Script
        psbt = self._v2()
        psbt.outputs[0].script_pubkey = Script(b"")
        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(p=self._reparse(psbt), seed=suite_seed(), network=SUITE_NETWORK)
        assert excinfo.value.code == RejectCode.UNDISPLAYABLE_OUTPUT

    def test_missing_input_prevout_is_refused(self):
        """A v2 input must name the utxo it spends; a witness_utxo alone is not enough."""
        psbt = self._v2()
        psbt.inputs[0].txid = None
        psbt.inputs[0].vout = None
        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(p=self._reparse(psbt), seed=suite_seed(), network=SUITE_NETWORK)
        assert excinfo.value.code == RejectCode.MISSING_UTXO

    # ------------------------------------------------- parse and sign end-to-end

    def test_valid_v2_vectors_parse_and_sign(self):
        """The benign v2 twins are genuinely version 2, and they parse and sign."""
        for name in ("NORMAL-1_p2wpkh_V2", "NORMAL-2_wrapped_V2",
                     "NORMAL-3_legacy_V2", "NORMAL-4_multi_input_V2"):
            psbt = load_psbt(name)
            assert psbt.version == 2, f"{name} is not a v2 psbt"

            vector = VECTORS_BY_NAME[name]
            parser = parse_vector(vector)
            assert parser.input_amount == vector.input_amount

            seed = suite_seed()
            sigs_added = psbt.sign_with(seed.get_root(SUITE_NETWORK))
            assert sigs_added == len(psbt.inputs), name

    # ------------------------------------------------- far-future height locktime

    def test_height_far_v2_is_flagged_against_an_anchor(self):
        """TX-19.height_far_V2 carries a block-height locktime years out; dated, it warns."""
        psbt = load_psbt("TX-19.height_far_V2")
        parser = PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK,
                            reference_time=self.ANCHOR[1], block_anchor=self.ANCHOR)
        assert Advisory.LOCKTIME_FAR_FUTURE in parser.risk_warnings


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


class TestFarFutureLocktime:
    """
    A locktime years beyond when the psbt was written.

    The device has no RTC, so it cannot ask what today is. A psbt loaded from
    microSD carries one usable hint -- the file's mtime, written by a machine
    that did have a clock.

    The security property that makes this safe to use: a file mtime is
    attacker-influenceable, so it may only ever *raise* a warning, never suppress
    one. Forging the mtime buys back the previous behaviour (the locktime is
    still stated on the approval screen) and nothing more.
    """

    ANCHOR = (963_408, 1_787_616_000)
    NOW = 1_787_616_000
    BLOCKS_PER_YEAR = 52_560

    def _parse(self, locktime, reference_time=NOW, anchor=ANCHOR, sequence=0xFFFFFFFE):
        psbt = load_psbt("NORMAL-1_p2wpkh")
        psbt.locktime = locktime
        psbt.inputs[0].sequence = sequence
        return PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK,
                          reference_time=reference_time, block_anchor=anchor)

    @pytest.mark.parametrize("years,expected", [
        (0.5, False),
        (1, False),
        (2, True),
        (5, True),
    ])
    def test_block_height_locktime_threshold(self, years, expected):
        height = self.ANCHOR[0] + int(self.BLOCKS_PER_YEAR * years)
        parser = self._parse(height)
        fired = Advisory.LOCKTIME_FAR_FUTURE in parser.risk_warnings
        assert fired is expected, f"{years} years out"

    def test_timestamp_locktime_threshold(self):
        near = self._parse(self.NOW + 30 * 86_400)
        far = self._parse(self.NOW + 3 * 365 * 86_400)
        assert Advisory.LOCKTIME_FAR_FUTURE not in near.risk_warnings
        assert Advisory.LOCKTIME_FAR_FUTURE in far.risk_warnings

    def test_it_interrupts_rather_than_being_informational(self):
        from seedsigner.models.psbt_parser import RiskWarning
        assert RiskWarning.LOCKTIME_FAR_FUTURE not in RiskWarning.INFORMATIONAL

    @pytest.mark.parametrize("reference_time,anchor,reason", [
        (None, ANCHOR, "QR-delivered psbt has no file and so no mtime"),
        (0, ANCHOR, "implausible reference is discarded, not trusted"),
        (NOW, None, "no anchor means a height cannot be dated"),
    ])
    def test_degrades_to_display_only(self, reference_time, anchor, reason):
        """
        Missing inputs must silently disable the check, never crash and never
        guess. The locktime is still shown on the approval screen either way.
        """
        far = self.ANCHOR[0] + self.BLOCKS_PER_YEAR * 5
        parser = self._parse(far, reference_time=reference_time, anchor=anchor)
        assert Advisory.LOCKTIME_FAR_FUTURE not in parser.risk_warnings, reason

    def test_inert_locktime_never_warns(self):
        """All inputs final means consensus ignores nLockTime entirely."""
        far = self.ANCHOR[0] + self.BLOCKS_PER_YEAR * 5
        parser = self._parse(far, sequence=0xFFFFFFFF)
        assert Advisory.LOCKTIME_FAR_FUTURE not in parser.risk_warnings

    def test_a_forged_mtime_is_no_worse_than_no_mtime(self):
        """
        The failure mode has to be bounded: an attacker who backdates the file so
        the lock looks near gets the same outcome as supplying no file at all.
        """
        far = self.ANCHOR[0] + self.BLOCKS_PER_YEAR * 5
        forged = self._parse(far, reference_time=self.NOW + 10 * 365 * 86_400)
        absent = self._parse(far, reference_time=None)
        assert Advisory.LOCKTIME_FAR_FUTURE not in forged.risk_warnings
        assert forged.risk_warnings == absent.risk_warnings
        # ...and in both cases the locktime is still recorded for display.
        assert forged.locktime == far and forged.locktime_is_enforced


class TestFeeRate:
    """
    A fee is only interpretable as a rate.

    The share-of-inputs check and the per-byte check miss opposite things: a
    9%-of-inputs fee on a large consolidation stays under the relative threshold
    while burning a fortune, and a modest absolute fee on a tiny transaction can
    still be a wild rate. Both are checked.
    """

    # Reference vsizes from the standard size tables, for the estimator.
    @pytest.mark.parametrize("name,expected,tolerance", [
        ("NORMAL-1_p2wpkh", 141, 0.05),    # 1-in 2-out P2WPKH
        ("NORMAL-3_legacy", 226, 0.05),    # 1-in 2-out P2PKH
        ("NORMAL-2_wrapped", 167, 0.05),   # 1-in 2-out P2SH-P2WPKH
    ])
    def test_vsize_estimate_matches_known_sizes(self, name, expected, tolerance):
        """
        The psbt is unsigned, so the signature has to be estimated. Anchor that
        estimate against transaction sizes that are publicly documented.
        """
        parser = PSBTParser(p=load_psbt(name), seed=suite_seed(), network=SUITE_NETWORK)
        estimate = parser.estimate_vsize()
        error = abs(estimate - expected) / expected
        assert error <= tolerance, f"{name}: estimated {estimate:.1f} vB, expected ~{expected}"

    def test_normal_transactions_are_below_the_threshold(self):
        """The default must leave headroom for ordinary transactions."""
        for vector in NORMAL_VECTORS:
            parser = parse_vector(vector)
            assert Advisory.HIGH_FEE_RATE not in parser.risk_warnings, (
                f"{vector.name} at {parser.fee_rate:.1f} sat/vB trips a "
                f"{SUITE_MAX_FEE_RATE} sat/vB threshold"
            )

    def test_extreme_rate_is_flagged(self):
        parser = PSBTParser(p=load_psbt("XTRAS.HUGE_FEE"), seed=suite_seed(),
                            network=SUITE_NETWORK, max_fee_rate=SUITE_MAX_FEE_RATE)
        assert Advisory.HIGH_FEE_RATE in parser.risk_warnings
        assert parser.fee_rate > 1000

    def test_threshold_is_configurable(self):
        """The same transaction must flip verdict with the setting."""
        psbt_name = "NORMAL-1_p2wpkh"
        strict = PSBTParser(p=load_psbt(psbt_name), seed=suite_seed(),
                            network=SUITE_NETWORK, max_fee_rate=10)
        lenient = PSBTParser(p=load_psbt(psbt_name), seed=suite_seed(),
                             network=SUITE_NETWORK, max_fee_rate=10_000)
        assert Advisory.HIGH_FEE_RATE in strict.risk_warnings
        assert Advisory.HIGH_FEE_RATE not in lenient.risk_warnings

    def test_zero_disables_the_check(self):
        parser = PSBTParser(p=load_psbt("XTRAS.HUGE_FEE"), seed=suite_seed(),
                            network=SUITE_NETWORK, max_fee_rate=0)
        assert Advisory.HIGH_FEE_RATE not in parser.risk_warnings

    def test_it_warns_rather_than_refuses(self):
        """Paying a high rate is sometimes exactly what the user intends."""
        from seedsigner.models.psbt_parser import RiskWarning
        parser = PSBTParser(p=load_psbt("XTRAS.HUGE_FEE"), seed=suite_seed(),
                            network=SUITE_NETWORK, max_fee_rate=1)
        assert parser.fee_amount > 0          # parsed fine, was not refused
        assert RiskWarning.HIGH_FEE_RATE not in RiskWarning.INFORMATIONAL  # but interrupts


class TestOutputClaimsMatchScripts:
    """
    Re-deriving a claimed key proves it is ours. It does not prove the output
    pays it: a psbt can annotate a stranger's output with a genuine key and path
    of ours (TX-21.claims_us_pays_other). Both halves have to hold.
    """

    def _with_other_genuine_key(self, name: str):
        """The fixture's change output, re-annotated with a different key of ours."""
        from embit.psbt import DerivationPath

        psbt = load_psbt(name)
        root = suite_seed().get_root(SUITE_NETWORK)
        for out in psbt.outputs:
            for pub, der in list(out.bip32_derivations.items()):
                path = list(der.derivation[:-1]) + [der.derivation[-1] + 7]
                del out.bip32_derivations[pub]
                out.bip32_derivations[root.derive(path).key] = DerivationPath(der.fingerprint, path)
        return psbt

    @pytest.mark.parametrize("name", ["NORMAL-1_p2wpkh", "NORMAL-2_wrapped", "NORMAL-3_legacy",
                                      "NORMAL-1_p2wpkh_V2"])
    def test_genuine_key_on_a_script_that_does_not_pay_it_is_refused(self, name):
        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(p=self._with_other_genuine_key(name), seed=suite_seed(), network=SUITE_NETWORK)
        assert excinfo.value.code == RejectCode.FORGED_OUTPUT_OWNERSHIP

    def test_a_bogus_script_on_a_foreign_output_is_not_a_claim(self):
        """NORMAL-2's destination carries a redeem script that hashes to nothing; it names no key of ours."""
        parser = PSBTParser(p=load_psbt("NORMAL-2_wrapped"), seed=suite_seed(), network=SUITE_NETWORK)
        assert parser.num_change_outputs == 1


class TestMultisigPolicy:
    """
    The multisig vectors against the suite's registered 2-of-3 wallet. Without a
    descriptor the parser can only tell whether this seed's key is in a script;
    whether the script is the *wallet's* is the descriptor's job.
    """

    @staticmethod
    def _descriptor():
        from embit.descriptor import Descriptor
        from psbt_suite_util import MULTISIG_DESCRIPTOR
        return Descriptor.from_string(MULTISIG_DESCRIPTOR)

    @staticmethod
    def _honest_change():
        """TX-22.ms_decoy_first with its decoy removed: genuine multisig change."""
        psbt = load_psbt("TX-22.ms_decoy_first")
        out = psbt.outputs[0]
        decoys = [pub for pub in out.bip32_derivations if pub.sec() not in out.witness_script.data]
        assert len(decoys) == 1
        decoy = (decoys[0], out.bip32_derivations.pop(decoys[0]))
        return psbt, decoy

    @pytest.mark.parametrize("name", ["TX-13.threshold", "TX-13.reorder"])
    def test_tampered_change_is_not_the_wallets(self, name):
        parser = parse_vector(VECTORS_BY_NAME[name])
        assert parser.num_change_outputs == 1
        assert parser.verify_multisig_output(self._descriptor(), 0) is False

    def test_genuine_change_is_the_wallets(self):
        psbt, _decoy = self._honest_change()
        parser = PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)
        assert parser.num_change_outputs == 1
        assert parser.verify_multisig_output(self._descriptor(), 0) is True

    @pytest.mark.parametrize("position", ["first", "last"])
    def test_a_decoy_fails_in_either_position(self, position):
        """
        embit's Descriptor.owns stops at the first matching entry, so a decoy listed
        after a genuine one used to pass. Checked here on an already-parsed psbt,
        because the parser itself now refuses the decoy before it gets this far.
        """
        from collections import OrderedDict

        psbt, (decoy_pub, decoy_der) = self._honest_change()
        parser = PSBTParser(p=psbt, seed=suite_seed(), network=SUITE_NETWORK)

        out = parser.psbt.outputs[parser.get_change_data(0)["output_index"]]
        entries = list(out.bip32_derivations.items())
        entries = [(decoy_pub, decoy_der)] + entries if position == "first" else entries + [(decoy_pub, decoy_der)]
        out.bip32_derivations = OrderedDict(entries)

        assert parser.verify_multisig_output(self._descriptor(), 0) is False


class TestScriptTimelock:
    """CLTV / CSV inside an output's own script lock the funds, not the transaction."""

    def test_committed_cltv_script_is_flagged(self):
        assert Advisory.SCRIPT_TIMELOCK in parse_vector(VECTORS_BY_NAME["TX-20.cltv_time"]).risk_warnings

    def test_uncommitted_script_is_ignored(self):
        """TX-20.cltv_height's CLTV script does not hash to its p2wpkh output; it says nothing."""
        assert Advisory.SCRIPT_TIMELOCK not in parse_vector(VECTORS_BY_NAME["TX-20.cltv_height"]).risk_warnings

    def test_push_data_is_not_mistaken_for_an_opcode(self):
        from embit.script import Script
        # <b1b2b1> OP_DROP: the bytes are pushed as data, never executed.
        assert PSBTParser._script_has_timelock(Script(bytes([0x03, 0xB1, 0xB2, 0xB1, 0x75]))) is False
        # <0x0100> OP_CHECKSEQUENCEVERIFY
        assert PSBTParser._script_has_timelock(Script(bytes([0x02, 0x00, 0x01, 0xB2]))) is True

    def test_it_interrupts_rather_than_being_informational(self):
        from seedsigner.models.psbt_parser import RiskWarning
        from seedsigner.views.psbt_views import PSBTRiskWarningView
        assert RiskWarning.SCRIPT_TIMELOCK not in RiskWarning.INFORMATIONAL
        assert RiskWarning.SCRIPT_TIMELOCK in PSBTRiskWarningView.RISK_TEXT
