# pylint: disable=missing-function-docstring
# Must import base before any seedsigner modules
from base import BaseTest, FlowStep, FlowTest

import pytest

from embit import bip32
from embit.descriptor import Descriptor
from embit.ec import PrivateKey
from embit.psbt import DerivationPath

from test_psbt_mixed_account_paths import NETWORK, OUR_ACCOUNT, THEIR_ACCOUNT, mixed_account_psbt
from psbt_testing_util import PSBTTestData, root_for_seed

from seedsigner.models.psbt_parser import InvalidPSBTError, PSBTParser


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



def mixed_account_descriptor():
    """The known-good descriptor for mixed_account_psbt's 2-of-2."""
    keys = []
    for seed, account in ((PSBTTestData.seed, OUR_ACCOUNT),
                          (PSBTTestData.multisig_key_2, THEIR_ACCOUNT)):
        root = root_for_seed(seed)
        xpub = root.derive(account).to_public().to_base58()
        keys.append(f"[{root.my_fingerprint.hex()}{account[1:]}]{xpub}/{{0,1}}/*")
    return Descriptor.from_string(f"wsh(multi(2,{','.join(keys)}))")


class TestRootlessChangeShowsTheDescriptorsPath(BaseTest):
    """
    With no BIP32 tree, the path on the change screen is all the user has to
    judge a change output by: its branch picks "Your Change" or "Self-Transfer"
    and its last level is the index shown. The descriptor skips any entry whose
    fingerprint names none of its keys, so an entry listed first for a key it
    never checked chose that path, and the index the user saw was not the one
    the funds went to.
    """

    # Real change, but at receive index 50000: past any wallet's gap limit.
    CHANGE_BRANCH_INDEX = "0/50000"

    @staticmethod
    def with_decoy_first(psbt, path, replacing_the_cosigner=False):
        """List an entry for a key the descriptor has never seen ahead of the real ones."""
        real = list(psbt.outputs[0].bip32_derivations.items())
        if replacing_the_cosigner:
            real = real[:1]
        decoy = PrivateKey(b"\x0d" * 32).get_public_key()
        psbt.outputs[0].bip32_derivations = {
            decoy: DerivationPath(bytes.fromhex("deadbeef"), bip32.parse_path(path)),
            **dict(real),
        }
        return psbt

    def parse(self, psbt):
        parser = PSBTParser(psbt, network=NETWORK, multisig_descriptor=mixed_account_descriptor())
        parser.parse()
        return parser

    def test_the_path_shown_is_one_the_descriptor_matched(self):
        # The decoy agrees on branch and index, so only its prefix is false.
        psbt = self.with_decoy_first(
            mixed_account_psbt(change_branch_index=self.CHANGE_BRANCH_INDEX),
            f"m/84h/1h/0h/{self.CHANGE_BRANCH_INDEX}",
            replacing_the_cosigner=True,
        )

        parser = self.parse(psbt)

        assert parser.change_amount == 90_000
        assert parser.change_data[0]["verified_derivation_path"] == bip32.parse_path(
            f"{OUR_ACCOUNT}/{self.CHANGE_BRANCH_INDEX}"
        )

    def test_an_entry_beyond_the_scripts_keys_is_refused(self):
        """The seeded parse's refusal: the script has two keys and three are listed."""
        psbt = self.with_decoy_first(
            mixed_account_psbt(change_branch_index=self.CHANGE_BRANCH_INDEX),
            f"{OUR_ACCOUNT}/1/0",
        )

        with pytest.raises(InvalidPSBTError) as excinfo:
            self.parse(psbt)

        assert excinfo.value.code == "SURPLUS_DERIVATIONS"

    def test_an_entry_on_another_branch_and_index_is_refused(self):
        """
        The seeded parse's other refusal: shown at 1/0, "Your Change" at index 0,
        while the script pays receive index 50000.
        """
        psbt = self.with_decoy_first(
            mixed_account_psbt(change_branch_index=self.CHANGE_BRANCH_INDEX),
            f"{OUR_ACCOUNT}/1/0",
            replacing_the_cosigner=True,
        )

        with pytest.raises(InvalidPSBTError) as excinfo:
            self.parse(psbt)

        assert excinfo.value.code == "UNREACHABLE_CHANGE_PATH"

    def test_honest_change_keeps_its_path(self):
        parser = self.parse(mixed_account_psbt(change_branch_index="1/3"))

        assert parser.change_amount == 90_000
        assert parser.change_data[0]["verified_derivation_path"] == bip32.parse_path(f"{OUR_ACCOUNT}/1/3")
