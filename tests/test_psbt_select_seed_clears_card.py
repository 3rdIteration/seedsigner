# pylint: disable=missing-function-docstring
# Must import base before any seedsigner modules
from base import BaseTest

from embit import script
from embit.psbt import PSBT
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from seedsigner.controller import Controller
from seedsigner.models.seed import Seed
from seedsigner.views import psbt_views
from seedsigner.views.view import Destination


MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()


class TestChoosingASeedLeavesTheCardFlow(BaseTest):
    """Backing out of card signing and picking a seed must sign with the seed."""

    def test_selecting_a_seed_clears_the_card_flag(self, monkeypatch):
        controller = Controller.get_instance()
        seed = Seed(mnemonic=MNEMONIC)
        from seedsigner.models.settings_definition import SettingsConstants
        root = seed.get_root(SettingsConstants.MAINNET)
        spk = script.p2wpkh(root.derive("m/84'/0'/0'/0/0").key.get_public_key())
        prev = Transaction(vin=[TransactionInput(b"\x11" * 32, 0)], vout=[TransactionOutput(100000, spk)])
        controller.psbt = PSBT(Transaction(vin=[TransactionInput(prev.txid(), 0)],
                                          vout=[TransactionOutput(90000, spk)]))
        controller.storage.seeds = [seed]
        # The user went into the card flow first and came back
        controller.psbt_sign_with_satochip = True

        view = psbt_views.PSBTSelectSeedView()
        monkeypatch.setattr(view, "run_screen", lambda *a, **kw: 0, raising=False)
        monkeypatch.setattr(
            psbt_views.PSBTSelectSeedView, "ensure_microsd_seed_warning",
            lambda self: True, raising=False,
        )

        destination = view.run()

        assert controller.psbt_seed is seed
        assert controller.psbt_sign_with_satochip is False
        assert isinstance(destination, Destination)


class TestAnySeedLeavesTheCardFlow(BaseTest):
    """
    A seed can be chosen from many places -- the stored list, a scan, manual
    entry, WIF and BIP38 keys, a Satodime slot -- and every one of them used
    to leave card mode standing, so the flow signed with the card the user had
    navigated away from. The flag is cleared where the seed is stored, which is
    the one line all of them pass through.
    """

    def test_storing_any_seed_leaves_card_mode(self):
        controller = Controller.get_instance()
        controller.psbt_sign_with_satochip = True
        controller.psbt_card_keys = {"root": object()}

        controller.psbt_seed = Seed(mnemonic=MNEMONIC)

        assert controller.psbt_sign_with_satochip is False
        assert controller.psbt_card_keys is None

    def test_clearing_the_seed_does_not_disturb_card_mode(self):
        """The card flow sets psbt_seed = None on its way in."""
        controller = Controller.get_instance()
        controller.psbt_seed = None
        controller.psbt_sign_with_satochip = True
        controller.psbt_card_keys = {"root": object()}

        controller.psbt_seed = None

        assert controller.psbt_sign_with_satochip is True
        assert controller.psbt_card_keys is not None
