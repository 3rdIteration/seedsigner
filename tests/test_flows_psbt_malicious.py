"""
Flow-level coverage for the adversarial PSBT corpus.

`test_psbt_test_suite.py` covers the model layer. These cases cover the vectors
where the *routing* is the finding: a valid transaction that used to crash the
parser, a refusal that must reach the user as a warning rather than the error
screen, a signing refusal, and a PSBT that embit cannot parse at all.
"""
from base import FlowStep, FlowTest

from seedsigner.models.settings import SettingsConstants
from seedsigner.views import psbt_views, scan_views
from seedsigner.views.view import MainMenuView

from psbt_suite_util import load_base64, load_bytes, suite_seed


class TestMaliciousPSBTFlows(FlowTest):

    def setup_method(self):
        super().setup_method()
        # The whole corpus is mainnet.
        self.settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.MAINNET)
        self.controller.storage.seeds = [suite_seed()]

    def load_psbt(self, name: str):
        """before_run hook: feed a base64 PSBT straight into the ScanView decoder."""
        def _load(view: scan_views.ScanView):
            view.decoder.add_data(load_base64(name))
        return _load

    def load_psbt_as_ur2(self, name: str):
        """
        before_run hook: feed the PSBT the way a real device receives it — as an
        animated UR2 `crypto-psbt`.

        This matters for vectors embit cannot parse. Fed as base64, DecodeQR
        validates during type detection and rejects the QR outright. Fed as UR2,
        the type comes from the UR string, so `is_psbt` is True while
        `get_psbt()` returns None — a different, reachable code path.
        """
        def _load(view: scan_views.ScanView):
            from urtypes.crypto import PSBT as UR_PSBT

            from seedsigner.helpers.ur2.ur import UR
            from seedsigner.helpers.ur2.ur_encoder import UREncoder

            encoder = UREncoder(
                ur=UR("crypto-psbt", UR_PSBT(load_bytes(name)).to_cbor()),
                max_fragment_len=200,
            )
            while not view.decoder.is_complete:
                view.decoder.add_data(encoder.next_part())
        return _load

    def scan_and_select_seed(self, name: str, loader=None):
        """The common prefix: scan a PSBT, then pick the only stored seed."""
        loader = loader or self.load_psbt
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=loader(name)),
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
        ]

    def test_wrapped_segwit_psbt_is_reviewable(self):
        """
        NORMAL-2_wrapped is a perfectly valid P2SH-P2WPKH transaction whose
        outputs carry a coordinator-supplied redeem_script that is not a multisig
        script. That used to raise ValueError out of PSBTParser._get_policy and
        land the user on the error screen — a false positive on a legitimate
        spend.
        """
        self.run_sequence(
            self.scan_and_select_seed("NORMAL-2_wrapped") + [
                FlowStep(psbt_views.PSBTOverviewView, screen_return_value=0),
                FlowStep(psbt_views.PSBTMathView, screen_return_value=0),
            ]
        )

    def test_mixed_input_types_is_refused_with_a_warning(self):
        """
        Mixed input script types are refused by design. The refusal must reach
        the user as an "Invalid PSBT" warning, not as an unhandled exception.
        """
        self.run_sequence(
            self.scan_and_select_seed("XTRAS.MIXED_INPUT_TYPES") + [
                # The refusal redirects out of the overview before any transaction
                # detail is rendered; PSBTRefusalView draws the screen.
                FlowStep(psbt_views.PSBTOverviewView, is_redirect=True),
                FlowStep(psbt_views.PSBTRefusalView, screen_return_value=0),
                FlowStep(MainMenuView),
            ]
        )

    def test_non_sighash_all_psbt_is_refused_at_load(self):
        """
        TX-08.SINGLE asks for a SIGHASH_SINGLE signature. embit would decline to
        produce it anyway, but only after the user has reviewed every screen and
        pressed approve, and then only as a generic signing error. A sighash
        other than ALL is authority the user was never shown, so refuse it up
        front with a reason.
        """
        self.run_sequence(
            self.scan_and_select_seed("TX-08.SINGLE") + [
                # The refusal redirects out of the overview before any transaction
                # detail is rendered; PSBTRefusalView draws the screen.
                FlowStep(psbt_views.PSBTOverviewView, is_redirect=True),
                FlowStep(psbt_views.PSBTRefusalView, screen_return_value=0),
                FlowStep(MainMenuView),
            ]
        )

    def test_spliced_change_path_is_refused(self):
        """
        TX-01 splices an extra non-hardened level into the change path
        (m/84h/0h/0h/127/1/0) while the inputs sit under m/84h/0h/0h. The seed
        really does control that address, but no wallet will scan for it.

        There is no honest reason to build this — it exists so a naive
        `path[-2] == 1` check says "your change" while the funds are burned — so
        the transaction is refused rather than relabelled.
        """
        self.run_sequence(
            self.scan_and_select_seed("TX-01") + [
                # The refusal redirects out of the overview before any transaction
                # detail is rendered; PSBTRefusalView draws the screen.
                FlowStep(psbt_views.PSBTOverviewView, is_redirect=True),
                FlowStep(psbt_views.PSBTRefusalView, screen_return_value=0),
                FlowStep(MainMenuView),
            ]
        )

    def test_unparseable_psbt_is_rejected_at_scan(self):
        """
        TX-04 carries a pubkey embit cannot parse. Delivered
        as UR2 (how a real scan arrives), `DecodeQR.is_psbt` is True but
        `get_psbt()` returns None. ScanView must refuse it there, rather than
        routing on with `controller.psbt = None` — which PSBTSelectSeedView
        turns into a bare "No transaction currently loaded" exception and the
        generic error screen.
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView,
                     before_run=self.load_psbt_as_ur2("TX-04")),
            FlowStep(MainMenuView),
        ])


    def test_unidentified_multisig_change_is_a_payment_until_identified(self):
        """
        With no global xpubs, genuine multisig change looks exactly like a different
        wallet that shares our key (TX-21.ms_foreign_quorum_no_xpubs). Without the
        descriptor it is shown as a payment, and the user is told a descriptor would
        identify it. Continuing without one reviews it as the full spend it appears to be.
        """
        def assert_unidentified(view):
            assert view.controller.psbt_parser.unidentified_change_outputs == [0]
            assert view.controller.psbt_parser.num_change_outputs == 0

        self.run_sequence(
            self.scan_and_select_seed("TX-21.ms_honest_change_no_xpubs") + [
                FlowStep(psbt_views.PSBTOverviewView, screen_return_value=0),
                FlowStep(psbt_views.PSBTIdentifyChangeView, before_run=assert_unidentified,
                         button_data_selection=psbt_views.PSBTIdentifyChangeView.CONTINUE_AS_PAYMENT),
                FlowStep(psbt_views.PSBTNoChangeWarningView),
            ]
        )

    def test_loading_the_descriptor_identifies_the_change(self):
        """"Load descriptor" goes to the descriptor loader, resuming the psbt flow."""
        from seedsigner.controller import Controller
        from seedsigner.views.seed_views import LoadMultisigWalletDescriptorView

        def assert_resumes(view):
            assert view.controller.resume_main_flow == Controller.FLOW__PSBT

        self.run_sequence(
            self.scan_and_select_seed("TX-21.ms_honest_change_no_xpubs") + [
                FlowStep(psbt_views.PSBTOverviewView, screen_return_value=0),
                FlowStep(psbt_views.PSBTIdentifyChangeView,
                         button_data_selection=psbt_views.PSBTIdentifyChangeView.LOAD_DESCRIPTOR),
                FlowStep(LoadMultisigWalletDescriptorView, before_run=assert_resumes),
            ]
        )

    def test_returning_with_a_descriptor_re_reads_the_psbt(self):
        """
        Once a descriptor is loaded, "Return to transaction" discards the parse that
        couldn't identify the change and restarts review, now with the change shown as
        change. (Starts at MultisigWalletDescriptorView, as after a descriptor scan.)
        """
        from embit.descriptor import Descriptor

        from seedsigner.controller import Controller
        from seedsigner.models.psbt_parser import PSBTParser
        from seedsigner.views.seed_views import MultisigWalletDescriptorView

        from psbt_suite_util import MULTISIG_DESCRIPTOR, SUITE_NETWORK, load_psbt

        seed = self.controller.storage.seeds[0]
        psbt = load_psbt("TX-21.ms_honest_change_no_xpubs")
        self.controller.psbt = psbt
        self.controller.psbt_seed = seed
        self.controller.psbt_parser = PSBTParser(psbt, seed=seed, network=SUITE_NETWORK)
        assert self.controller.psbt_parser.unidentified_change_outputs == [0]
        self.controller.multisig_wallet_descriptor = Descriptor.from_string(MULTISIG_DESCRIPTOR)
        self.controller.resume_main_flow = Controller.FLOW__PSBT
        # On a device the descriptor screen is on the back stack when RETURN skips it.
        from seedsigner.views.view import Destination
        self.controller.back_stack.append(Destination(MultisigWalletDescriptorView))

        def assert_identified(view):
            parser = view.controller.psbt_parser
            assert parser.unidentified_change_outputs == []
            assert parser.num_change_outputs == 1

        self.run_sequence([
            FlowStep(MultisigWalletDescriptorView,
                     button_data_selection=MultisigWalletDescriptorView.RETURN),
            FlowStep(psbt_views.PSBTOverviewView, screen_return_value=0),
            FlowStep(psbt_views.PSBTMathView, before_run=assert_identified),
        ])
