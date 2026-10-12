"""
libwally cross-check of psbt parsing and signing (seedsigner.crosscheck.psbt).

The corpus suites (test_psbt_test_suite.py and friends) already run every vector
with the cross-check active, which is what shows it has no false refusals. These
tests show the other half: that each check fires when embit's reading, or its
signature, is wrong.
"""
import copy
from binascii import a2b_base64

import pytest
from embit.psbt import PSBT

from base import FlowTest, FlowStep
from psbt_suite_util import PARSING_VECTORS, SUITE_NETWORK, load_wire_bytes, suite_seed
from psbt_testing_util import PSBTTestData

from seedsigner.crosscheck import CrossCheckCode, CrossCheckError
from seedsigner.crosscheck import psbt as xpsbt
from seedsigner.models.crosscheck_claims import psbt_claims, signer_claims
from seedsigner.models.psbt_framing import parse_psbt
from seedsigner.models.psbt_parser import InvalidPSBTError, PSBTParser, RejectCode
from seedsigner.models.settings import SettingsConstants
from seedsigner.views import psbt_views, scan_views, seed_views
from seedsigner.views.view import CrossCheckErrorView, MainMenuView


REGTEST = SettingsConstants.REGTEST


def _two_input_parser() -> PSBTParser:
    """Single-sig p2wpkh: 2 inputs, 1 payment, 3 change outputs (regtest)."""
    psbt = parse_psbt(a2b_base64(PSBTTestData.SINGLE_SIG_NATIVE_SEGWIT_2_INPUTS))
    return PSBTParser(psbt, seed=PSBTTestData.two_input_seed, network=REGTEST)


def _taproot_parser() -> PSBTParser:
    psbt = parse_psbt(a2b_base64(PSBTTestData.SINGLE_SIG_TAPROOT_WITH_CHANGE))
    return PSBTParser(psbt, seed=PSBTTestData.two_input_seed, network=REGTEST)


def _sign(parser: PSBTParser) -> bytes:
    parser.psbt.sign_with(parser.root)
    return parser.psbt.serialize()


def _expect(code: str, fn, *args):
    with pytest.raises(CrossCheckError) as excinfo:
        fn(*args)
    assert excinfo.value.code == code, excinfo.value
    return excinfo.value



class TestParseAgreement:

    def test_parser_records_claims_and_binding(self):
        parser = _two_input_parser()
        assert parser.crosscheck_claims is not None
        assert parser.reviewed_binding is not None
        assert len(parser.crosscheck_claims.change) == 3

    @pytest.mark.parametrize("mutate, detail", [
        (lambda c: setattr(c.outputs[0], "amount", c.outputs[0].amount + 1), "output 0 amount"),
        (lambda c: setattr(c.outputs[0], "address", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"), "output 0 address"),
        (lambda c: setattr(c, "fee", c.fee + 1), "fee"),
        (lambda c: setattr(c, "input_total", c.input_total - 1), "input total"),
        (lambda c: setattr(c.inputs[1], "amount", c.inputs[1].amount - 1), "input 1 spent output"),
        (lambda c: setattr(c.inputs[0], "sequence", 0), "input 0 sequence"),
        (lambda c: setattr(c, "locktime", c.locktime + 1), "locktime"),
        (lambda c: setattr(c, "txid", bytes(32)), "txid"),
        (lambda c: c.outputs.pop(), "output count"),
    ])
    def test_summary_disagreement_is_refused(self, mutate, detail):
        claims = copy.deepcopy(_two_input_parser().crosscheck_claims)
        mutate(claims)
        error = _expect(CrossCheckCode.MISMATCH, xpsbt.check_parsed, claims)
        assert detail in error.detail

    def test_change_at_a_path_that_does_not_pay_us_is_refused(self):
        claims = copy.deepcopy(_two_input_parser().crosscheck_claims)
        claims.change[0].path[-1] += 1
        _expect(CrossCheckCode.CHANGE, xpsbt.check_parsed, claims)

    def test_change_on_a_payment_output_is_refused(self):
        claims = copy.deepcopy(_two_input_parser().crosscheck_claims)
        payment = next(i for i, o in enumerate(claims.outputs) if i not in {c.output_index for c in claims.change})
        claims.change[0].output_index = payment
        _expect(CrossCheckCode.CHANGE, xpsbt.check_parsed, claims)

    def test_own_output_shown_as_payment_is_refused(self):
        """embit missing a change output: wally proves it pays us, so it can't be shown as a payment."""
        claims = copy.deepcopy(_two_input_parser().crosscheck_claims)
        claims.change.pop()
        error = _expect(CrossCheckCode.CHANGE, xpsbt.check_parsed, claims)
        assert "shown as a payment" in error.detail

    def test_taproot_change_is_reverified(self):
        claims = copy.deepcopy(_taproot_parser().crosscheck_claims)
        assert claims.change
        xpsbt.check_parsed(claims)
        claims.change[0].path[-1] += 1
        _expect(CrossCheckCode.CHANGE, xpsbt.check_parsed, claims)

    def test_parser_maps_disagreement_to_a_reject_code(self, monkeypatch):
        def wrong_fee(parser):
            claims = psbt_claims(parser)
            claims.fee += 1
            return claims
        monkeypatch.setattr("seedsigner.models.crosscheck_claims.psbt_claims", wrong_fee)
        with pytest.raises(InvalidPSBTError) as excinfo:
            _two_input_parser()
        assert excinfo.value.code == RejectCode.CROSSCHECK_MISMATCH

    def test_unparseable_bytes_are_refused(self):
        claims = copy.deepcopy(_two_input_parser().crosscheck_claims)
        claims.raw = claims.raw[:-10]
        _expect(CrossCheckCode.PARSE, xpsbt.check_parsed, claims)



class TestBinding:

    def test_same_psbt_passes(self):
        parser = _two_input_parser()
        xpsbt.check_binding(parser.reviewed_binding, parser.psbt.serialize())

    def test_modified_psbt_is_refused(self):
        parser = _two_input_parser()
        parser.psbt.outputs[0].value -= 1
        _expect(CrossCheckCode.SWAPPED, xpsbt.check_binding, parser.reviewed_binding, parser.psbt.serialize())

    def test_missing_record_is_refused(self):
        parser = _two_input_parser()
        _expect(CrossCheckCode.SWAPPED, xpsbt.check_binding, None, parser.psbt.serialize())



class TestSigned:

    @pytest.mark.parametrize("make_parser", [_two_input_parser, _taproot_parser], ids=["p2wpkh", "p2tr"])
    def test_embit_signatures_verify(self, make_parser):
        parser = make_parser()
        signed = _sign(parser)
        xpsbt.check_signed(signed, parser.crosscheck_claims, signer_claims(parser, seed_signed=True))
        xpsbt.check_trimmed(PSBTParser.trim(parser.psbt).serialize(), signed, parser.crosscheck_claims)

    @pytest.mark.parametrize("vector", PARSING_VECTORS, ids=lambda v: v.name)
    def test_corpus_signatures_verify(self, vector):
        """Every corpus psbt that parses, signed by embit, passes libwally's signature checks."""
        parser = PSBTParser(parse_psbt(load_wire_bytes(vector.name)), seed=suite_seed(), network=SUITE_NETWORK)
        signed = _sign(parser)
        xpsbt.check_signed(signed, parser.crosscheck_claims, signer_claims(parser, seed_signed=True))
        xpsbt.check_trimmed(PSBTParser.trim(parser.psbt).serialize(), signed, parser.crosscheck_claims)

    def test_signature_over_another_message_is_refused(self):
        parser = _two_input_parser()
        _sign(parser)
        inp = parser.psbt.inputs[0]
        pub = next(iter(inp.partial_sigs))
        path = list(inp.bip32_derivations[pub].derivation)
        bogus = parser.root.derive(path).key.sign(bytes(32))
        inp.partial_sigs[pub] = bogus.serialize() + b"\x01"
        error = _expect(CrossCheckCode.SIGNATURE, xpsbt.check_signed, parser.psbt.serialize(),
                        parser.crosscheck_claims, signer_claims(parser, seed_signed=True))
        assert "does not verify" in error.detail

    def test_valid_but_different_signature_is_refused(self):
        """A signature that verifies but is not what libwally produces (e.g. a different nonce)."""
        import wallycore as w
        parser = _two_input_parser()
        signed = _sign(parser)
        wp = w.psbt_from_bytes(signed, 0)
        tx = w.psbt_extract(wp, w.WALLY_PSBT_EXTRACT_NON_FINAL)
        inp = parser.psbt.inputs[0]
        pub = next(iter(inp.partial_sigs))
        key = parser.root.derive(list(inp.bip32_derivations[pub].derivation)).key
        digest = w.tx_get_btc_signature_hash(
            tx, 0, w.scriptpubkey_p2pkh_from_bytes(pub.sec(), w.WALLY_SCRIPT_HASH160),
            inp.utxo.value, 1, w.WALLY_TX_FLAG_USE_WITNESS)
        # Valid signature, but from an alternative nonce (no low-R grinding,
        # plus extra entropy), so it differs from the deterministic one.
        compact = w.ec_sig_from_bytes_aux(key.secret, bytes(digest), b"\x01" * 32, w.EC_FLAG_ECDSA)
        inp.partial_sigs[pub] = bytes(w.ec_sig_to_der(compact)) + b"\x01"
        error = _expect(CrossCheckCode.SIGNATURE, xpsbt.check_signed, parser.psbt.serialize(),
                        parser.crosscheck_claims, signer_claims(parser, seed_signed=True))
        assert "differs from libwally's" in error.detail
        # A smartcard's signature is only verified, not compared.
        xpsbt.check_signed(parser.psbt.serialize(), parser.crosscheck_claims, signer_claims(parser, seed_signed=False))

    def test_missing_signature_is_refused(self):
        parser = _two_input_parser()
        _sign(parser)
        parser.psbt.inputs[1].partial_sigs.clear()
        error = _expect(CrossCheckCode.SIGNATURE, xpsbt.check_signed, parser.psbt.serialize(),
                        parser.crosscheck_claims, signer_claims(parser, seed_signed=True))
        assert "signed inputs differ" in error.detail

    def test_signed_psbt_of_another_transaction_is_refused(self):
        parser = _two_input_parser()
        _sign(parser)
        parser.psbt.outputs[0].value -= 1
        error = _expect(CrossCheckCode.SIGNATURE, xpsbt.check_signed, parser.psbt.serialize(),
                        parser.crosscheck_claims, signer_claims(parser, seed_signed=True))
        assert "differs from the reviewed" in error.detail

    def test_exported_psbt_must_carry_the_verified_signatures(self):
        parser = _two_input_parser()
        signed = _sign(parser)
        trimmed = PSBTParser.trim(parser.psbt)
        trimmed.inputs[0].partial_sigs.clear()
        _expect(CrossCheckCode.SIGNATURE, xpsbt.check_trimmed, trimmed.serialize(), signed, parser.crosscheck_claims)



class TestFinalizeViewRefuses(FlowTest):
    """The view-level wiring: a refused check discards the psbt and shows CrossCheckErrorView."""

    def _run_to_finalize(self, finalize_step: FlowStep):
        psbt_b64 = PSBTTestData.SINGLE_SIG_NATIVE_SEGWIT_2_INPUTS
        self.settings.set_value(SettingsConstants.SETTING__NETWORK, REGTEST)

        def load_psbt(view):
            view.decoder.add_data(psbt_b64)

        def load_seed(view):
            view.decoder.add_data("080115060387063104071857067618681125136207731354")

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt),
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=psbt_views.PSBTSelectSeedView.SCAN_SEED),
            FlowStep(scan_views.ScanSeedQRView, before_run=load_seed),
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTMathView),
            FlowStep(psbt_views.PSBTAddressDetailsView, button_data_selection=0),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            finalize_step,
            FlowStep(CrossCheckErrorView),
        ])
        assert self.controller.psbt is None
        assert self.controller.psbt_parser is None

    def test_psbt_swapped_after_review_is_not_signed(self):
        def swap(view):
            view.controller.psbt.outputs[0].value -= 1

        self._run_to_finalize(FlowStep(
            psbt_views.PSBTFinalizeView,
            button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT,
            before_run=swap,
        ))

    def test_bad_signature_is_not_exported(self, monkeypatch):
        real_sign_with = PSBT.sign_with

        def corrupting_sign_with(self, root, *args, **kwargs):
            count = real_sign_with(self, root, *args, **kwargs)
            inp = self.inputs[0]
            pub = next(iter(inp.partial_sigs))
            path = list(inp.bip32_derivations[pub].derivation)
            inp.partial_sigs[pub] = root.derive(path).key.sign(bytes(32)).serialize() + b"\x01"
            return count

        monkeypatch.setattr(PSBT, "sign_with", corrupting_sign_with)
        self._run_to_finalize(FlowStep(
            psbt_views.PSBTFinalizeView,
            button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT,
        ))
