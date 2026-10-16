# pylint: disable=missing-function-docstring
# Must import base before any seedsigner modules
from base import BaseTest, FlowStep, FlowTest

from test_psbt_mixed_account_paths import NETWORK, mixed_account_psbt
from psbt_testing_util import PSBTTestData

from seedsigner.models.psbt_parser import PSBTParser


class TestRootlessMultisigNeedsADescriptor(BaseTest):
    """
    The card's multisig flow parses before any key is available, so nothing it
    can check says an m-of-n output is ours: the script's shape matches the
    inputs', and at most the psbt's own global xpub map -- which the psbt's
    author wrote -- names its cosigners. Accepting that labels an attacker's
    output as change, and in a 1-of-2 that output is one the attacker alone can
    spend. Only a descriptor the user loaded can identify change here.
    """

    def test_global_xpubs_alone_do_not_make_an_output_change(self):
        parser = PSBTParser(mixed_account_psbt(), network=NETWORK)
        parser.parse()

        assert parser.change_amount == 0
        assert parser.change_data == []
        # Which is what puts the "Load descriptor" prompt in front of the user.
        assert parser.unidentified_change_outputs == [0]

    def test_without_global_xpubs_an_output_is_not_change_either(self):
        psbt = mixed_account_psbt()
        psbt.xpubs.clear()

        parser = PSBTParser(psbt, network=NETWORK)
        parser.parse()

        assert parser.change_amount == 0
        assert parser.unidentified_change_outputs == [0]

    def test_a_seed_still_identifies_its_own_change(self):
        """The seeded path is untouched: it proves ownership by deriving."""
        parser = PSBTParser(mixed_account_psbt(), seed=PSBTTestData.seed, network=NETWORK)

        assert parser.change_amount == 90_000
        assert parser.unidentified_change_outputs == []


class TestChangeDetailsWithoutChangeData(BaseTest):
    """
    Swapping the loaded descriptor for one that does not own the output leaves
    the change list empty while the view is still being asked for change 0. That
    is a mismatch, not a crash.
    """

    def test_a_missing_change_entry_is_a_mismatch_not_a_crash(self, monkeypatch):
        from seedsigner.controller import Controller
        from seedsigner.views import psbt_views

        controller = Controller.get_instance()
        controller.psbt = mixed_account_psbt()
        controller.psbt_parser = PSBTParser(controller.psbt, network=NETWORK)
        controller.psbt_parser.parse()
        controller.multisig_wallet_descriptor = object()

        view = psbt_views.PSBTChangeDetailsView(change_address_num=0)
        screens = []
        monkeypatch.setattr(view, "run_screen", lambda *a, **kw: screens.append(a) or 0)

        destination = view.run()

        assert controller.multisig_wallet_descriptor is None
        assert destination.View_cls is psbt_views.PSBTOverviewView
        assert len(screens) == 1


class TestWrongDescriptorCanBeReplaced(BaseTest):
    """
    Loading the wrong descriptor is the ordinary way to arrive at "change not
    identified". Offering only "Continue" there left the right descriptor
    unreachable: the only way back to it was to abandon the transaction.
    """

    def test_a_loaded_descriptor_that_identifies_nothing_still_offers_to_load_one(self, monkeypatch):
        from seedsigner.controller import Controller
        from seedsigner.views import psbt_views

        controller = Controller.get_instance()
        controller.psbt = mixed_account_psbt()
        controller.psbt_parser = PSBTParser(controller.psbt, network=NETWORK)
        controller.psbt_parser.parse()
        controller.multisig_wallet_descriptor = object()

        view = psbt_views.PSBTIdentifyChangeView()
        captured = {}

        def fake_screen(*args, **kwargs):
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(view, "run_screen", fake_screen)

        destination = view.run()

        assert captured["button_data"][0] is psbt_views.PSBTIdentifyChangeView.LOAD_DESCRIPTOR
        assert destination.View_cls.__name__ == "LoadMultisigWalletDescriptorView"


# The 2-of-2 wallet that MULTISIG_PSBT_B64 spends from, and whose change it pays.
MULTISIG_DESCRIPTOR = (
    "wsh(sortedmulti(2,[3531cd75/48h/1h/0h/2h]tpubDEvs8aQCFkexBPVGJoqctrxgK9zeFwejWUWsAn7fKeSbbSUQ8sW6BJHrkKpNGRXwAfk7UWZDKz6amomvE2bo7DzokRtH8gnfweyQZf2ufFz/{0,1}/*,"
    "[0948d268/48h/1h/0h/2h]tpubDEkn1ih27ZcgHeu4tLzDw5EceCBa8hYMhRoCP7QmfijsrxDgchvMEC8ukFncE9Y7qBCBozBzYjEz4ophQ2quGRZsbN2bTziJxpLeK7mHq4L/{0,1}/*))"
)


class TestCardMultisigReviewsWithTheLoadedDescriptor(FlowTest):
    """
    A descriptor loaded earlier in the session survives Home, so the card's
    multisig flow often starts with one in place. The review has to use it: a
    parser built without it identifies no change, and the user was then told
    that their own descriptor did not identify it.
    """

    def test_a_descriptor_loaded_before_the_card_identifies_change(self, monkeypatch):
        from embit.descriptor import Descriptor
        from embit.psbt import PSBT

        from seedsigner.helpers import seedkeeper_utils
        from seedsigner.views import psbt_views
        from test_psbt_overview_card_flow import MULTISIG_PSBT_B64

        monkeypatch.setattr(seedkeeper_utils, "init_satochip", lambda *args, **kwargs: object())
        self.controller.storage.seeds = []
        self.controller.psbt = PSBT.from_string(MULTISIG_PSBT_B64)
        self.controller.multisig_wallet_descriptor = Descriptor.from_string(MULTISIG_DESCRIPTOR)

        self.run_sequence([
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=psbt_views.PSBTSelectSeedView.SATOCHIP),
            FlowStep(psbt_views.PSBTOverviewView, screen_return_value=0),
            FlowStep(psbt_views.PSBTMathView),
        ])

        parser = self.controller.psbt_parser
        assert self.controller.psbt_sign_with_satochip is True
        assert parser.unidentified_change_outputs == []
        assert parser.change_amount == 2_807
