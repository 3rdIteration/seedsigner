# pylint: disable=missing-function-docstring
# Must import base before any seedsigner modules
from base import BaseTest

import pytest

from embit import bip32, script
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from psbt_testing_util import PSBTTestData, root_for_seed

from seedsigner.models.psbt_parser import InvalidPSBTError, PSBTParser
from seedsigner.models.settings_definition import SettingsConstants


NETWORK = SettingsConstants.REGTEST
EMBIT_NETWORK = NETWORKS["regtest"]

OUR_ACCOUNT = "m/48h/1h/0h/2h"
# A cosigner is free to keep the same wallet under a different account index.
# Mixed-vendor multisig setups do this routinely.
THEIR_ACCOUNT = "m/48h/1h/1h/2h"

PREVIOUS_TXID = bytes(range(32))


def _multisig_scope_keys(our_branch_index, their_branch_index):
    """The 2-of-2 script for one branch/index, plus the derivations that describe it."""
    our_root = root_for_seed(PSBTTestData.seed)
    their_root = root_for_seed(PSBTTestData.multisig_key_2)

    our_path = f"{OUR_ACCOUNT}/{our_branch_index}"
    their_path = f"{THEIR_ACCOUNT}/{their_branch_index}"
    our_key = our_root.derive(our_path).get_public_key()
    their_key = their_root.derive(their_path).get_public_key()

    witness_script = script.multisig(2, [our_key, their_key])
    derivations = {
        our_key: DerivationPath(our_root.my_fingerprint, bip32.parse_path(our_path)),
        their_key: DerivationPath(their_root.my_fingerprint, bip32.parse_path(their_path)),
    }
    return witness_script, derivations


def mixed_account_psbt(change_branch_index="1/0", cosigner_branch_index=None):
    """
    A 2-of-2 psbt whose two cosigners hold the wallet at different account paths.

    Everything else about it is ordinary: one input the wallet already owns, change
    back to the same 2-of-2 on the change branch, and a payment out.
    """
    input_script, input_derivations = _multisig_scope_keys("0/0", "0/0")
    change_script, change_derivations = _multisig_scope_keys(
        change_branch_index, cosigner_branch_index or change_branch_index
    )

    payment = script.p2wpkh(
        root_for_seed(PSBTTestData.multisig_key_3).derive("m/84h/1h/0h/0/0").get_public_key()
    )

    tx = Transaction(
        vin=[TransactionInput(PREVIOUS_TXID, 0)],
        vout=[
            TransactionOutput(90_000, script.p2wsh(change_script)),
            TransactionOutput(9_500, payment),
        ],
    )
    psbt = PSBT(tx)

    psbt.inputs[0].witness_utxo = TransactionOutput(100_000, script.p2wsh(input_script))
    psbt.inputs[0].witness_script = input_script
    psbt.inputs[0].bip32_derivations = input_derivations

    psbt.outputs[0].witness_script = change_script
    psbt.outputs[0].bip32_derivations = change_derivations

    # The global xpubs are what let the parser name the cosigners, without which
    # change is withheld for a different reason entirely.
    for seed, account in ((PSBTTestData.seed, OUR_ACCOUNT),
                          (PSBTTestData.multisig_key_2, THEIR_ACCOUNT)):
        root = root_for_seed(seed)
        psbt.xpubs[root.derive(account).to_public()] = DerivationPath(
            root.my_fingerprint, bip32.parse_path(account)
        )

    return psbt


class TestMixedAccountPathsMultisig(BaseTest):
    """
    Change binding measures a change path against the account prefixes the inputs
    demonstrate. Those prefixes are gathered from the keys this seed owns, so a
    cosigner keeping the wallet at a different account index has no bearing on
    whether our own change is reachable.
    """

    def test_change_survives_a_cosigner_on_another_account(self):
        parser = PSBTParser(mixed_account_psbt(), seed=PSBTTestData.seed, network=NETWORK)

        assert parser.change_amount == 90_000
        assert len(parser.change_data) == 1

    def test_our_own_spliced_change_path_is_still_refused(self):
        """
        The refusal this check exists for: our key moved off the branch any wallet
        scans. Relaxing the cosigner case must not relax this one.
        """
        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(mixed_account_psbt(change_branch_index="7/0"),
                       seed=PSBTTestData.seed, network=NETWORK)

        assert excinfo.value.code == "UNREACHABLE_CHANGE_PATH"


class TestCosignerBranchAndIndexMustAgree(BaseTest):
    """
    A multisig address is built from every cosigner's key, so change is only
    recoverable if all of them sit at the same branch and index. The account
    prefix above that may differ; the last two levels may not.
    """

    def test_a_cosigner_on_another_index_is_refused(self):
        # Our own path stays at 1/0; the cosigner's is moved to 1/9999, so the
        # address is one no wallet's change scan will ever reproduce.
        psbt = mixed_account_psbt(cosigner_branch_index="1/9999")

        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(psbt, seed=PSBTTestData.seed, network=NETWORK)

        assert excinfo.value.code == "UNREACHABLE_CHANGE_PATH"

    def test_a_cosigner_on_another_branch_is_refused(self):
        psbt = mixed_account_psbt(cosigner_branch_index="0/0")

        with pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(psbt, seed=PSBTTestData.seed, network=NETWORK)

        assert excinfo.value.code == "UNREACHABLE_CHANGE_PATH"
