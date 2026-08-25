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

from seedsigner.models.psbt_parser import InvalidPSBTError, PSBTParser

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
            for path_str in change["derivation_path"]:
                path = bip32.parse_path(path_str)

                assert path[-2] in (0, 1), (
                    f"{vector.name}: {path_str} uses branch {path[-2]}, "
                    f"outside the receive/change branches {{0, 1}}"
                )
                assert tuple(path[:-2]) in parser.input_derivation_prefixes, (
                    f"{vector.name}: {path_str} sits under "
                    f"{bip32.path_to_str(list(path[:-2]))}, but the inputs are all "
                    f"under {[bip32.path_to_str(list(x)) for x in parser.input_derivation_prefixes]}"
                )


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
            if parser.max_input_derivation_index < 0:
                continue
            for change in parser.change_data:
                for path_str in change["derivation_path"]:
                    gap = (bip32.parse_path(path_str)[-1] & 0x7FFFFFFF) - parser.max_input_derivation_index
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
