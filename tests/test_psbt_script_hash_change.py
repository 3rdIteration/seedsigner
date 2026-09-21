# pylint: disable=missing-function-docstring
# Must import base before any seedsigner modules
from base import BaseTest

from embit import bip32, script
from embit.ec import PrivateKey
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from psbt_testing_util import PSBTTestData, root_for_seed

from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.models.wif import WIFKey


NETWORK = SettingsConstants.REGTEST
ACCOUNT = "m/48h/1h/0h/2h"
STRANGER = PrivateKey(bytes([77]) * 32).get_public_key()
OTHER = PrivateKey(bytes([99]) * 32).get_public_key()
WIF_KEY = PrivateKey(bytes([55]) * 32)

PREVIOUS_TXID = bytes(range(32))


def our_key(branch_index):
    """This seed's key at branch_index under ACCOUNT, and the derivation naming it."""
    root = root_for_seed(PSBTTestData.seed)
    path = f"{ACCOUNT}/{branch_index}"
    public_key = root.derive(path).get_public_key()
    return public_key, {public_key: DerivationPath(root.my_fingerprint, bip32.parse_path(path))}


def single_key_script(public_key):
    """<key> OP_CHECKSIG: a script-hash wallet whose script is not an m-of-n."""
    return script.Script(b"\x21" + public_key.sec() + b"\xac")


def script_hash_psbt(input_script, input_derivations, output_script,
                     output_derivations=None, supply_output_script=True):
    """
    One p2wsh input spending input_script, then 90,000 sats to the p2wsh of
    output_script and a payment out. The output's witness script is supplied unless
    supply_output_script is False.
    """
    tx = Transaction(
        vin=[TransactionInput(PREVIOUS_TXID, 0)],
        vout=[
            TransactionOutput(90_000, script.p2wsh(output_script)),
            TransactionOutput(9_500, script.p2wpkh(OTHER)),
        ],
    )
    psbt = PSBT(tx)

    psbt.inputs[0].witness_utxo = TransactionOutput(100_000, script.p2wsh(input_script))
    psbt.inputs[0].witness_script = input_script
    psbt.inputs[0].bip32_derivations = input_derivations

    if supply_output_script:
        psbt.outputs[0].witness_script = output_script
    if output_derivations:
        psbt.outputs[0].bip32_derivations = output_derivations

    return psbt


class TestScriptHashChange(BaseTest):
    """
    A script-hash output is change only if its script is an m-of-n with our key among
    the cosigners. A wallet whose script is anything else is one this parser cannot
    reason about, so its outputs are payments rather than a crash.
    """

    def test_a_script_our_key_cannot_spend_is_not_change(self):
        """
        Our key appearing in the script's bytes is not the same as our key being
        able to spend it. `<our key> OP_DROP <their key> OP_CHECKSIG` drops our
        key on the stack and checks theirs, so only they can spend -- however
        truthfully the psbt names our key on it.
        """
        input_key, input_derivations = our_key("0/0")
        change_key, change_derivations = our_key("1/0")
        drop_script = script.Script(
            b"\x21" + change_key.sec() + b"\x75" + b"\x21" + STRANGER.sec() + b"\xac"
        )
        psbt = script_hash_psbt(
            single_key_script(input_key), input_derivations,
            drop_script, change_derivations,
        )

        parser = PSBTParser(psbt, seed=PSBTTestData.seed, network=NETWORK)

        assert parser.change_amount == 0
        assert parser.spend_amount == 99_500

    def test_a_missing_witness_script_is_not_change_and_does_not_raise(self):
        input_key, input_derivations = our_key("0/0")
        change_key, change_derivations = our_key("1/0")
        psbt = script_hash_psbt(
            single_key_script(input_key), input_derivations,
            single_key_script(change_key), change_derivations,
            supply_output_script=False,
        )

        parser = PSBTParser(psbt, seed=PSBTTestData.seed, network=NETWORK)

        assert parser.change_amount == 0
        assert parser.spend_amount == 99_500


class TestWIFMultisigChange(BaseTest):
    """
    WIF and BIP38 signing has no BIP32 tree to derive from, but it does hold one key,
    and that key either is a cosigner of an output's script or is not.
    """

    def _wif_psbt(self, output_keys):
        cosigner_root = root_for_seed(PSBTTestData.multisig_key_2)
        path = f"{ACCOUNT}/0/0"
        cosigner_key = cosigner_root.derive(path).get_public_key()
        input_script = script.multisig(2, [WIF_KEY.get_public_key(), cosigner_key])
        input_derivations = {
            cosigner_key: DerivationPath(cosigner_root.my_fingerprint, bip32.parse_path(path)),
        }
        return script_hash_psbt(input_script, input_derivations, script.multisig(2, output_keys))

    def _parse(self, psbt):
        wif = WIFKey(WIF_KEY.wif(NETWORKS["regtest"]))
        return PSBTParser(psbt, seed=wif, network=NETWORK)

    def test_a_wif_that_cannot_spend_the_multisig_is_not_change(self):
        """
        Treating "no tree" as "no way to tell" labelled any multisig output of
        the right shape as change, which hides an attacker's payment behind the
        change screen.
        """
        parser = self._parse(self._wif_psbt([STRANGER, OTHER]))

        assert parser.change_amount == 0
        assert parser.spend_amount == 99_500

    def test_a_wif_that_is_a_cosigner_is_change(self):
        parser = self._parse(self._wif_psbt([WIF_KEY.get_public_key(), STRANGER]))

        assert parser.change_amount == 90_000
