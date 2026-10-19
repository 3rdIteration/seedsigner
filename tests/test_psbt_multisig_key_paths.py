"""
Issue #477: multisig wallets whose cosigners sit at different account paths.

A managed-multisig provider commonly serves many clients (or one client's
sub-accounts) from a single key by giving each its own account, e.g.
m/48h/1h/778h/2h next to the user's m/48h/1h/0h/2h. Such a wallet's change used to
be refused as "outside this wallet", because every cosigner's path on the change
was measured against *this seed's* inputs rather than its own.

Vectors are built in multisig_key_path_vectors.py.
"""
import pytest
from embit import bip32

from base import BaseTest, FlowTest, FlowStep
from multisig_key_path_vectors import (
    NETWORK, COSIGNER_SEED, NONSTANDARD_ACCOUNT, OUR_SEED, PROVIDER_ACCOUNT, PROVIDER_SEED,
    STANDARD_ACCOUNT, Cosigner, MultisigVector, nonstandard_wallet, provider_wallet,
    standard_wallet,
)
from seedsigner.models.psbt_parser import InvalidPSBTError, PSBTParser, RejectCode, RiskWarning
from seedsigner.models.settings import SettingsConstants
from seedsigner.views import psbt_views, seed_views
from seedsigner.views.view import MainMenuView


H = bip32.HARDENED_INDEX


def parse(vector: MultisigVector, seed=OUR_SEED, descriptor=None, **kwargs) -> PSBTParser:
    return PSBTParser(
        vector.build(), seed, network=SettingsConstants.TESTNET,
        change_index_lookahead=100, multisig_descriptor=descriptor, **kwargs,
    )


def prefix(path: str) -> tuple:
    return tuple(bip32.parse_path(path))



class TestParserAcceptsMixedAccounts:
    def test_standard_wallet_is_unremarkable(self):
        parser = parse(standard_wallet())
        assert [c["output_index"] for c in parser.change_data] == [1]
        assert parser.key_path_irregularity is None
        assert not parser.has_nonstandard_key_paths


    def test_issue_477_provider_account_change_is_identified(self):
        """The reported psbt: change used to be refused as outside this wallet."""
        parser = parse(provider_wallet())
        assert [c["output_index"] for c in parser.change_data] == [1]
        assert parser.change_data[0]["verified_derivation_path"] == list(bip32.parse_path(f"{STANDARD_ACCOUNT}/1/4"))
        assert parser.key_path_irregularity == PSBTParser.KEY_PATHS__MIXED_ACCOUNTS
        assert not parser.inputs_match_descriptor


    @pytest.mark.parametrize("seed", [OUR_SEED, COSIGNER_SEED, PROVIDER_SEED])
    def test_every_cosigner_can_review_it(self, seed):
        """Including the provider itself, whose own path is the unusual one."""
        parser = parse(provider_wallet(), seed=seed)
        assert parser.num_change_outputs == 1


    def test_cosigner_key_origins_name_each_account(self):
        origins = dict(parse(provider_wallet()).cosigner_key_origins)
        provider_fp = bip32.HDKey.from_seed(PROVIDER_SEED.seed_bytes).child(0).fingerprint.hex()
        assert origins[provider_fp] == PROVIDER_ACCOUNT


    def test_without_global_xpubs_the_descriptor_identifies_change(self):
        """Loading the descriptor used to hit the same refusal."""
        vector = provider_wallet(include_global_xpubs=False)
        parser = parse(vector)
        assert parser.unidentified_change_outputs == [1]

        parser = parse(vector, descriptor=vector.descriptor())
        assert parser.num_change_outputs == 1
        assert parser.unidentified_change_outputs == []
        assert parser.inputs_match_descriptor


    def test_seedless_card_parse_accepts_it(self):
        """The smartcard multisig flow parses with no seed at all."""
        vector = provider_wallet()
        parser = PSBTParser(vector.build(), network=SettingsConstants.TESTNET,
                            multisig_descriptor=vector.descriptor())
        parser.parse()
        assert parser.num_change_outputs == 1
        assert parser.inputs_match_descriptor


    def test_another_wallets_descriptor_does_not_match(self):
        parser = parse(provider_wallet(), descriptor=standard_wallet().descriptor())
        assert not parser.inputs_match_descriptor



class TestParserStillRefusesMovedChange:
    """
    Each cosigner is held to its own account, not waved through. Change with a key
    moved off its cosigner's account is never shown as change: it is a payment the
    user reviews, whether or not the psbt carries global xpubs, and a descriptor
    doesn't claim it either.
    """

    MOVED = {
        "provider_to_another_account": [
            Cosigner(OUR_SEED, STANDARD_ACCOUNT),
            Cosigner(COSIGNER_SEED, STANDARD_ACCOUNT),
            Cosigner(PROVIDER_SEED, PROVIDER_ACCOUNT, change_account="m/48h/1h/779h/2h"),
        ],
        "provider_to_our_account": [
            Cosigner(OUR_SEED, STANDARD_ACCOUNT),
            Cosigner(COSIGNER_SEED, STANDARD_ACCOUNT),
            Cosigner(PROVIDER_SEED, PROVIDER_ACCOUNT, change_account=STANDARD_ACCOUNT),
        ],
        "ours_to_the_providers_account": [
            Cosigner(OUR_SEED, STANDARD_ACCOUNT, change_account=PROVIDER_ACCOUNT),
            Cosigner(COSIGNER_SEED, STANDARD_ACCOUNT),
            Cosigner(PROVIDER_SEED, PROVIDER_ACCOUNT),
        ],
    }

    @pytest.mark.parametrize("name", MOVED)
    @pytest.mark.parametrize("include_global_xpubs", [True, False])
    @pytest.mark.parametrize("with_descriptor", [False, True])
    def test_moved_change_is_shown_as_a_payment(self, name, include_global_xpubs, with_descriptor):
        vector = MultisigVector(cosigners=self.MOVED[name], include_global_xpubs=include_global_xpubs)
        descriptor = provider_wallet().descriptor() if with_descriptor else None
        try:
            parser = parse(vector, descriptor=descriptor)
        except InvalidPSBTError as e:
            # Refusing outright is at least as safe as showing a payment.
            assert e.code == RejectCode.UNREACHABLE_CHANGE_PATH
            return
        assert parser.num_change_outputs == 0
        change_address = vector.build().tx.vout[1].script_pubkey.address(NETWORK)
        assert change_address in parser.destination_addresses


    def test_cosigner_path_check_refuses_a_moved_key(self):
        """
        The cosigner-reachability check itself, below the cosigner-set and
        descriptor checks that normally catch this first.
        """
        parser = parse(provider_wallet())
        provider_fp = bip32.HDKey.from_seed(PROVIDER_SEED.seed_bytes).child(0).fingerprint
        from embit.psbt import DerivationPath
        ok = DerivationPath(provider_fp, list(bip32.parse_path(f"{PROVIDER_ACCOUNT}/1/4")))
        moved = DerivationPath(provider_fp, list(bip32.parse_path("m/48h/1h/779h/2h/1/4")))
        ours = DerivationPath(provider_fp, list(bip32.parse_path(f"{STANDARD_ACCOUNT}/1/4")))
        assert parser._is_reachable_cosigner_derivation(ok)
        assert not parser._is_reachable_cosigner_derivation(moved)
        assert not parser._is_reachable_cosigner_derivation(ours)


    def test_change_off_the_receive_and_change_branches(self):
        with pytest.raises(InvalidPSBTError) as e:
            parse(provider_wallet(change_branch=2))
        assert e.value.code == RejectCode.UNREACHABLE_CHANGE_PATH


    def test_change_index_past_the_gap_limit(self):
        with pytest.raises(InvalidPSBTError) as e:
            parse(provider_wallet(change_index=500))
        assert e.value.code == RejectCode.CHANGE_INDEX_TOO_FAR



class TestKeyPathIrregularity:
    def test_nonstandard_shape(self):
        parser = parse(nonstandard_wallet())
        assert parser.key_path_irregularity == PSBTParser.KEY_PATHS__NONSTANDARD
        assert parser.num_change_outputs == 1


    def test_mixed_schemes_are_nonstandard(self):
        """BIP-48 and BIP-87 cosigners in one wallet: not merely another account."""
        vector = MultisigVector(cosigners=[
            Cosigner(OUR_SEED, STANDARD_ACCOUNT),
            Cosigner(COSIGNER_SEED, STANDARD_ACCOUNT),
            Cosigner(PROVIDER_SEED, "m/87h/1h/0h"),
        ])
        assert parse(vector).key_path_irregularity == PSBTParser.KEY_PATHS__NONSTANDARD


    def test_all_at_one_unusual_account_is_standard(self):
        vector = MultisigVector(cosigners=[
            Cosigner(OUR_SEED, PROVIDER_ACCOUNT),
            Cosigner(COSIGNER_SEED, PROVIDER_ACCOUNT),
            Cosigner(PROVIDER_SEED, PROVIDER_ACCOUNT),
        ])
        assert parse(vector).key_path_irregularity is None


    @pytest.mark.parametrize("path,policy_type,expected", [
        ("m/48h/1h/0h/2h", "p2wsh", True),
        ("m/48h/0h/778h/2h", "p2wsh", True),
        ("m/48h/1h/0h/1h", "p2sh-p2wsh", True),
        ("m/48h/1h/0h/1h", "p2wsh", False),        # script index for sh(wsh)
        ("m/48h/1h/0h", "p2wsh", False),           # too short
        ("m/48h/1h/0h/2h/0h", "p2wsh", False),     # too long
        ("m/48h/1h/0/2h", "p2wsh", False),         # unhardened account
        ("m/48h/5h/0h/2h", "p2wsh", False),        # unknown coin
        ("m/45h", "p2sh", True),
        ("m/45h", "p2wsh", False),
        ("m/87h/0h/3h", "p2wsh", True),
        ("m/99h/1h/0h/2h", "p2wsh", False),
    ])
    def test_is_standard_multisig_prefix(self, path, policy_type, expected):
        assert PSBTParser.is_standard_multisig_prefix(prefix(path), policy_type) == expected



class TestKeyPathReviewPolicy(BaseTest):
    def policy_for(self, vector, setting, descriptor=None, acknowledged=False):
        self.settings.set_value(SettingsConstants.SETTING__MULTISIG_KEY_PATHS, setting)
        parser = parse(vector, descriptor=descriptor)
        parser.key_paths_acknowledged = acknowledged
        return psbt_views.key_path_review_policy(parser, self.settings)


    def test_default_is_block(self):
        assert self.settings.get_value(SettingsConstants.SETTING__MULTISIG_KEY_PATHS) == SettingsConstants.MULTISIG_KEY_PATHS__BLOCK


    def test_mixed_accounts_only_ever_warn(self):
        """The user may not have the descriptor to hand; never a hard block."""
        B, W = SettingsConstants.MULTISIG_KEY_PATHS__BLOCK, SettingsConstants.MULTISIG_KEY_PATHS__WARN
        assert self.policy_for(provider_wallet(), B) == W
        assert self.policy_for(provider_wallet(), W) == W


    def test_nonstandard_follows_the_setting(self):
        for setting in (SettingsConstants.MULTISIG_KEY_PATHS__BLOCK, SettingsConstants.MULTISIG_KEY_PATHS__WARN):
            assert self.policy_for(nonstandard_wallet(), setting) == setting


    def test_off_says_nothing(self):
        off = SettingsConstants.MULTISIG_KEY_PATHS__OFF
        assert self.policy_for(provider_wallet(), off) is None
        assert self.policy_for(nonstandard_wallet(), off) is None


    def test_a_matching_descriptor_settles_it(self):
        vector = nonstandard_wallet()
        assert self.policy_for(vector, SettingsConstants.MULTISIG_KEY_PATHS__BLOCK, descriptor=vector.descriptor()) is None


    def test_a_mismatched_descriptor_does_not(self):
        policy = self.policy_for(
            nonstandard_wallet(), SettingsConstants.MULTISIG_KEY_PATHS__BLOCK,
            descriptor=standard_wallet().descriptor(),
        )
        assert policy == SettingsConstants.MULTISIG_KEY_PATHS__BLOCK


    def test_acknowledging_a_warning_clears_it_but_not_a_block(self):
        assert self.policy_for(provider_wallet(), SettingsConstants.MULTISIG_KEY_PATHS__BLOCK, acknowledged=True) is None
        assert self.policy_for(nonstandard_wallet(), SettingsConstants.MULTISIG_KEY_PATHS__BLOCK, acknowledged=True) == SettingsConstants.MULTISIG_KEY_PATHS__BLOCK


    def test_standard_wallet_is_never_reviewed(self):
        assert self.policy_for(standard_wallet(), SettingsConstants.MULTISIG_KEY_PATHS__BLOCK) is None



class TestKeyPathFlows(FlowTest):
    def load(self, vector, descriptor=None):
        self.settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.TESTNET)
        self.controller.psbt = vector.build()
        self.controller.psbt_seed = OUR_SEED
        self.controller.multisig_wallet_descriptor = descriptor
        self.controller.psbt_parser = parse(vector, descriptor=descriptor)


    def test_mixed_accounts_warn_then_continue(self):
        self.load(provider_wallet())
        self.run_sequence([
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTMultisigKeyPathsView, button_data_selection=psbt_views.PSBTMultisigKeyPathsView.CONTINUE),
            FlowStep(psbt_views.PSBTMathView),
        ])
        assert self.controller.psbt_parser.key_paths_acknowledged


    def test_nonstandard_block_offers_no_continue(self):
        self.load(nonstandard_wallet())
        self.run_sequence([
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTMultisigKeyPathsView, button_data_selection=psbt_views.PSBTMultisigKeyPathsView.DISCARD),
            FlowStep(MainMenuView),
        ])
        assert self.controller.psbt is None
        assert self.controller.psbt_parser is None


    def test_load_descriptor_routes_to_the_loader(self):
        self.load(nonstandard_wallet())
        self.run_sequence([
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTMultisigKeyPathsView, button_data_selection=psbt_views.PSBTMultisigKeyPathsView.LOAD_DESCRIPTOR),
            FlowStep(seed_views.LoadMultisigWalletDescriptorView),
        ])


    def test_finalize_refuses_while_blocked(self):
        """Defence in depth: a route that skips the overview still can't sign."""
        self.load(nonstandard_wallet())
        self.run_sequence([
            FlowStep(psbt_views.PSBTFinalizeView, is_redirect=True),
            FlowStep(psbt_views.PSBTMultisigKeyPathsView),
        ])


    def test_matching_descriptor_goes_straight_through(self):
        vector = nonstandard_wallet()
        self.load(vector, descriptor=vector.descriptor())
        self.run_sequence([
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTMathView),
        ])



class TestOpReturnBurn:
    def burn_psbt(self):
        from psbt_suite_util import build_nonzero_op_return_psbt
        return build_nonzero_op_return_psbt()


    def test_refused_by_default(self):
        from psbt_suite_util import suite_seed
        with pytest.raises(InvalidPSBTError) as e:
            PSBTParser(self.burn_psbt(), suite_seed(), allow_op_return_burn=False)
        assert e.value.code == RejectCode.NONZERO_OP_RETURN


    def test_warn_counts_it_and_flags_it(self):
        from psbt_suite_util import suite_seed
        parser = PSBTParser(self.burn_psbt(), suite_seed(), allow_op_return_burn=True)
        assert parser.op_return_amount > 0
        assert RiskWarning.OP_RETURN_BURN in parser.risk_warnings
        assert RiskWarning.OP_RETURN_BURN in psbt_views.pending_risk_warnings(parser)



class TestOpReturnBurnSetting(BaseTest):
    def test_default_is_block(self):
        assert self.settings.get_value(SettingsConstants.SETTING__OP_RETURN_BURN) == SettingsConstants.OP_RETURN_BURN__BLOCK
        assert PSBTParser._configured_allow_op_return_burn() is False


    def test_warn_is_read_from_settings(self):
        self.settings.set_value(SettingsConstants.SETTING__OP_RETURN_BURN, SettingsConstants.OP_RETURN_BURN__WARN)
        assert PSBTParser._configured_allow_op_return_burn() is True



class TestAddressVerificationCosignerPaths:
    rows = staticmethod(seed_views.SeedAddressVerificationSuccessView.cosigner_path_rows)

    def test_shared_path_needs_no_rows(self):
        assert self.rows(standard_wallet().descriptor(), SettingsConstants.NATIVE_SEGWIT) is None


    def test_provider_account_gets_its_own_row(self):
        rows = self.rows(provider_wallet().descriptor(), SettingsConstants.NATIVE_SEGWIT)
        provider_fp = bip32.HDKey.from_seed(PROVIDER_SEED.seed_bytes).child(0).fingerprint.hex()
        assert rows == [
            ("2x m/48'/1'/0'/2'", False),
            (f"{provider_fp}: m/48'/1'/778'/2'", False),
        ]


    def test_nonstandard_row_is_marked(self):
        rows = self.rows(nonstandard_wallet().descriptor(), SettingsConstants.NATIVE_SEGWIT)
        assert rows[0] == ("2x m/48'/1'/0'/2'", False)
        assert rows[1][0].endswith(NONSTANDARD_ACCOUNT.replace("h", "'"))
        assert rows[1][1] is True


    def test_three_paths_each_get_a_row(self):
        vector = MultisigVector(cosigners=[
            Cosigner(OUR_SEED, "m/48h/1h/0h/2h"),
            Cosigner(COSIGNER_SEED, "m/48h/1h/1h/2h"),
            Cosigner(PROVIDER_SEED, "m/48h/1h/2h/2h"),
        ])
        rows = self.rows(vector.descriptor(), SettingsConstants.NATIVE_SEGWIT)
        assert [label.split(": ")[1] for label, _ in rows] == ["m/48'/1'/0'/2'", "m/48'/1'/1'/2'", "m/48'/1'/2'/2'"]


    def test_too_many_paths_are_summarized(self):
        from psbt_testing_util import PSBTTestData
        vector = MultisigVector(cosigners=[
            Cosigner(OUR_SEED, "m/48h/1h/0h/2h"),
            Cosigner(COSIGNER_SEED, "m/48h/1h/1h/2h"),
            Cosigner(PROVIDER_SEED, "m/48h/1h/2h/2h"),
            Cosigner(PSBTTestData.two_input_seed, "m/48h/1h/3h/2h"),
        ])
        rows = self.rows(vector.descriptor(), SettingsConstants.NATIVE_SEGWIT)
        assert len(rows) == seed_views.SeedAddressVerificationSuccessView.MAX_COSIGNER_PATH_ROWS
        assert rows[-1] == ("+2 more", False)
