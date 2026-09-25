# pylint: disable=missing-function-docstring
# Must import base before any seedsigner modules
from base import BaseTest

from embit import bip32, script
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from seedsigner.controller import Controller
from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import psbt_views


MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()
PATH = "m/84'/0'/0'/0/0"


def card_psbt():
    """A PSBT the card's key can sign, as the card flow would have built it."""
    seed = Seed(mnemonic=MNEMONIC)
    root = seed.get_root(SettingsConstants.MAINNET)
    child = root.derive(PATH)
    spk = script.p2wpkh(child.key.get_public_key())
    prev = Transaction(vin=[TransactionInput(b"\x11" * 32, 0)], vout=[TransactionOutput(100000, spk)])
    tx = Transaction(vin=[TransactionInput(prev.txid(), 0)], vout=[TransactionOutput(90000, spk)])
    psbt = PSBT(tx)
    psbt.inputs[0].witness_utxo = prev.vout[0]
    psbt.inputs[0].bip32_derivations[child.key.get_public_key()] = DerivationPath(
        root.my_fingerprint, bip32.parse_path(PATH)
    )
    return psbt, root


class TestOverviewRebuildInTheCardFlow(BaseTest):
    """Rebuilding the parser must not throw away the card's key material."""

    def test_rebuild_uses_the_cards_root(self):
        controller = Controller.get_instance()
        psbt, root = card_psbt()
        controller.psbt = psbt
        controller.psbt_seed = None
        controller.psbt_parser = None
        controller.psbt_sign_with_satochip = True
        controller.psbt_card_keys = dict(
            root=root.derive("m/84'/0'/0'"),
            root_path=bip32.parse_path("m/84'/0'/0'"),
            master_fingerprint=root.my_fingerprint,
        )

        view = psbt_views.PSBTOverviewView()

        assert not view.has_redirect
        parser = controller.psbt_parser
        assert parser is not None
        assert parser.root is not None
        # The card can sign this input, so the parser must see it
        assert parser.num_inputs == 1

    def test_card_flow_without_card_keys_refuses_instead_of_parsing_blind(self):
        controller = Controller.get_instance()
        psbt, _root = card_psbt()
        controller.psbt = psbt
        controller.psbt_seed = None
        controller.psbt_parser = None
        controller.psbt_sign_with_satochip = True
        controller.psbt_card_keys = None

        view = psbt_views.PSBTOverviewView()

        assert view.has_redirect

    def test_a_single_key_psbt_with_no_key_refuses_instead_of_crashing(self):
        """
        Only the multisig card flow records an empty key set, so a single-key
        psbt should never reach a parse with nothing to parse it with. If it
        does, parse() raises rather than returning, and the user is owed a
        refusal rather than a crash screen.
        """
        controller = Controller.get_instance()
        psbt, _root = card_psbt()
        controller.psbt = psbt
        controller.psbt_seed = None
        controller.psbt_parser = None
        controller.psbt_sign_with_satochip = True
        controller.psbt_card_keys = {}

        view = psbt_views.PSBTOverviewView()

        assert view.has_redirect

MULTISIG_PSBT_B64 = "cHNidP8BAIkCAAAAAc9dCSh2RcRPfHaT5bNVBpbg0jAekRLqOK+bpN/QA0jeAAAAAAD9////AtAHAAAAAAAAIlEg24shYsV3IRCzlgmMKjAsR4Ad9tX896z7zDAi5q0TU9H3CgAAAAAAACIAIByGQg/VP2aRID62ty40E64HYZeRRsKRGLt8J/76R6stQ04FAE8BBDWHzwSLLGdzgAAAAq3q6nR20JnHR+vKrBQdWxN9C7xU8zNX942mVF7AQpl2ArrdLwVlkGxaatQJ4wwkvypNBKbwOq9hXGLNlKi7rZWAFDUxzXUwAACAAQAAgAAAAIACAACATwEENYfPBHOCZmWAAAACmH6KTXIny0vueRgQFBq4M6oMuG8f1QM0I/RzKQ03bCgCHrF0fyUtV0+FD2N34u/woqb8MAt/o+7Ed58RddhY8zYUCUjSaDAAAIABAACAAAAAgAIAAIAAAQEriBMAAAAAAAAiACBY4WsjDgJXLj3VW222jU1tkIIhT26ce/2efH73BWGGBiICAqyfkrdUO662QBrdvJcSOZMFxniD7M1awm9U0Kb5XCm5RzBEAiAPkQTY84YjFFkpD6MI2cc5rJySqws5fsTQA/8XEZFpbAIgTNVykbEH4Z7bqyzhhy6lty0K8rtCUDCaHNv+47NNIWgBAQMEAQAAAAEFR1IhApL4XO+VE1pPYn5wnRFyJQKVSc9TX2dO6KIBH6jwvgPaIQKsn5K3VDuutkAa3byXEjmTBcZ4g+zNWsJvVNCm+VwpuVKuIgYCkvhc75UTWk9ifnCdEXIlApVJz1NfZ07oogEfqPC+A9ocNTHNdTAAAIABAACAAAAAgAIAAIAAAAAAAAAAACIGAqyfkrdUO662QBrdvJcSOZMFxniD7M1awm9U0Kb5XCm5HAlI0mgwAACAAQAAgAAAAIACAACAAAAAAAAAAAAAAAEBR1IhApYXaczuYbBM/A+EH639Ir2yIB4PxL46dK/I1V1O9aHgIQLa02HCI/+EP+9gGpxHskjYWFN5hZzXY7RRvwV4UF42ylKuIgIClhdpzO5hsEz8D4Qfrf0ivbIgHg/Evjp0r8jVXU71oeAcNTHNdTAAAIABAACAAAAAgAIAAIABAAAAAAAAACICAtrTYcIj/4Q/72AanEeySNhYU3mFnNdjtFG/BXhQXjbKHAlI0mgwAACAAQAAgAAAAIACAACAAQAAAAAAAAAA"


class TestMultisigCardRebuildIsParsed(BaseTest):
    """
    The card's multisig flow builds its parser with no key material, and a
    PSBTParser built that way does not parse on construction -- it is the one
    case where the caller has to finish the job. Handed to the review screens
    unparsed it reports no inputs, no outputs and no fee, which reads as a
    transaction that moves nothing.
    """

    def test_the_rebuilt_multisig_parser_has_read_the_transaction(self):
        from embit.psbt import PSBT as EmbitPSBT

        controller = Controller.get_instance()
        controller.psbt = EmbitPSBT.from_string(MULTISIG_PSBT_B64)
        controller.psbt_seed = None
        controller.psbt_parser = None
        controller.psbt_sign_with_satochip = True
        # What the multisig card branch records: parsed against a descriptor,
        # not against any one cosigner's key.
        controller.psbt_card_keys = {}

        view = psbt_views.PSBTOverviewView()

        assert not view.has_redirect
        parser = controller.psbt_parser
        assert parser.num_inputs == 1
        assert parser.input_amount > 0
        assert parser.fee_amount > 0
        assert len(parser.destination_addresses) > 0
        assert parser.parsed is True
