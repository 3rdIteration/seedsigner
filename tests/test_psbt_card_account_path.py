# pylint: disable=missing-function-docstring
# Must import base before any seedsigner modules
from base import BaseTest

from embit import bip32, script
from embit.psbt import DerivationPath, InputScope, PSBT
from embit.ec import PrivateKey
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import psbt_views
from seedsigner.views.psbt_views import account_path_for_inputs


HARDENED = 0x80000000
ACCOUNT = [84 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0]


def psbt_with(derivation_flags):
    """A PSBT whose inputs carry a derivation only where flagged True."""
    psbt = PSBT()
    psbt.inputs = []
    for i, has_derivation in enumerate(derivation_flags):
        inp = InputScope()
        if has_derivation:
            pub = PrivateKey(bytes([i + 1]) * 32).get_public_key()
            inp.bip32_derivations[pub] = DerivationPath(b"\x00" * 4, list(ACCOUNT))
        psbt.inputs.append(inp)
    return psbt


class TestAccountPathFromInputs(BaseTest):
    """The account path must come from an input that actually has one."""

    def test_uses_the_first_input_with_a_derivation(self):
        # Input 0 is bare -- a taproot input, or one another wallet finished
        psbt = psbt_with([False, True])

        assert account_path_for_inputs(psbt) == [84 + HARDENED, 0 + HARDENED, 0 + HARDENED]

    def test_plain_case_still_uses_input_zero(self):
        psbt = psbt_with([True, True])

        assert account_path_for_inputs(psbt) == [84 + HARDENED, 0 + HARDENED, 0 + HARDENED]

    def test_no_derivations_anywhere_is_none_not_an_exception(self):
        psbt = psbt_with([False, False])

        assert account_path_for_inputs(psbt) is None


class TestAccountPathBelongsToTheCard(BaseTest):
    """
    A psbt can carry inputs from more than one wallet. The account to export
    from the card is the one the *card's* fingerprint claims, not whichever
    input happens to come first -- reading the wrong one exports an account
    the card has no business in and then rejects the input it could have signed.
    """

    def _psbt_with_fingerprints(self, entries):
        """entries: [(fingerprint, path)] -- one input each."""
        psbt = PSBT()
        psbt.inputs = []
        for i, (fingerprint, path) in enumerate(entries):
            inp = InputScope()
            pub = PrivateKey(bytes([i + 1]) * 32).get_public_key()
            inp.bip32_derivations[pub] = DerivationPath(fingerprint, list(path))
            psbt.inputs.append(inp)
        return psbt

    def test_picks_the_input_matching_the_card_fingerprint(self):
        stranger = [49 + HARDENED, 0 + HARDENED, 7 + HARDENED, 0, 0]
        psbt = self._psbt_with_fingerprints([
            (b"\xaa" * 4, stranger),
            (b"\xbb" * 4, ACCOUNT),
        ])

        path = account_path_for_inputs(psbt, master_fingerprint=b"\xbb" * 4)

        assert path == [84 + HARDENED, 0 + HARDENED, 0 + HARDENED]

    def test_a_card_named_by_no_input_gets_no_path(self):
        psbt = self._psbt_with_fingerprints([(b"\xaa" * 4, ACCOUNT)])

        assert account_path_for_inputs(psbt, master_fingerprint=b"\xbb" * 4) is None

    def test_a_blank_fingerprint_is_read_when_none_names_the_card(self):
        """
        A coordinator given only an xpub writes 00000000 for the master it was
        never told. The parser backfills that from the card's key if the key
        derives it, so the account still has to be read from it.
        """
        psbt = self._psbt_with_fingerprints([(b"\x00" * 4, ACCOUNT)])

        path = account_path_for_inputs(psbt, master_fingerprint=b"\xbb" * 4)

        assert path == [84 + HARDENED, 0 + HARDENED, 0 + HARDENED]

    def test_the_cards_own_fingerprint_wins_over_a_blank_one(self):
        blank = [49 + HARDENED, 0 + HARDENED, 7 + HARDENED, 0, 0]
        psbt = self._psbt_with_fingerprints([
            (b"\x00" * 4, blank),
            (b"\xbb" * 4, ACCOUNT),
        ])

        path = account_path_for_inputs(psbt, master_fingerprint=b"\xbb" * 4)

        assert path == [84 + HARDENED, 0 + HARDENED, 0 + HARDENED]


CARD_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()
STRANGER_MNEMONIC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong".split()


class MockCard:
    """Answers xpub requests the way a card holding `root` would, and keeps a list of them."""

    def __init__(self, root):
        self.root = root
        self.exported = []

    def card_bip32_get_xpub(self, path, xtype, is_mainnet):
        self.exported.append(path)
        key = self.root.derive(path) if path else self.root
        return key.to_public().to_base58()


def spend_from(owners, locktime=0, sequence=0xFFFFFFFF):
    """A PSBT spending one p2wpkh coin per (root, path, fingerprint) in `owners`."""
    coins = []
    for i, (root, path, fingerprint) in enumerate(owners):
        public_key = root.derive(path).get_public_key()
        spk = script.p2wpkh(public_key)
        prev = Transaction(vin=[TransactionInput(bytes([i + 1]) * 32, 0)], vout=[TransactionOutput(100_000, spk)])
        coins.append((prev, public_key, DerivationPath(fingerprint, bip32.parse_path(path))))

    payee = script.p2wpkh(PrivateKey(b"\x07" * 32).get_public_key())
    tx = Transaction(
        vin=[TransactionInput(prev.txid(), 0, sequence=sequence) for prev, _, _ in coins],
        vout=[TransactionOutput(100_000 * len(coins) - 1_000, payee)],
        locktime=locktime,
    )
    psbt = PSBT(tx)
    for inp, (prev, public_key, derivation) in zip(psbt.inputs, coins):
        inp.witness_utxo = prev.vout[0]
        inp.bip32_derivations[public_key] = derivation
    return psbt


class TestCardFlowReadsTheCardsAccount(BaseTest):
    """
    What PSBTSelectSeedView asks the card for. The account it exports decides
    which inputs the card can be shown to sign, so reading it from the wrong
    derivation turns a psbt the card can sign into a refusal.
    """

    def choose_the_card(self, monkeypatch, card, psbt):
        from seedsigner.helpers import seedkeeper_utils

        monkeypatch.setattr(seedkeeper_utils, "init_satochip", lambda *args, **kwargs: card)
        self.controller.storage.seeds = []
        self.controller.psbt = psbt

        view = psbt_views.PSBTSelectSeedView()
        warnings = []

        def run_screen(screen_cls, **kwargs):
            if screen_cls.__name__ == "ButtonListScreen":
                return kwargs["button_data"].index(psbt_views.PSBTSelectSeedView.SATOCHIP)
            warnings.append(kwargs.get("text"))
            return 0

        monkeypatch.setattr(view, "run_screen", run_screen)
        return view.run(), warnings

    def test_another_wallets_input_first_does_not_pick_the_account(self, monkeypatch):
        card_root = Seed(mnemonic=CARD_MNEMONIC).get_root(SettingsConstants.MAINNET)
        stranger_root = Seed(mnemonic=STRANGER_MNEMONIC).get_root(SettingsConstants.MAINNET)
        psbt = spend_from([
            (stranger_root, "m/84h/0h/5h/0/0", stranger_root.my_fingerprint),
            (card_root, "m/84h/0h/0h/0/0", card_root.my_fingerprint),
        ])
        card = MockCard(card_root)

        destination, warnings = self.choose_the_card(monkeypatch, card, psbt)

        assert warnings == []
        assert destination.View_cls is psbt_views.PSBTOverviewView
        assert "m/84'/0'/0'" in card.exported
        assert "m/84'/0'/5'" not in card.exported
        assert self.controller.psbt_parser.root_path == bip32.parse_path("m/84h/0h/0h")

    def test_a_blank_fingerprint_on_the_cards_input_still_signs(self, monkeypatch):
        card_root = Seed(mnemonic=CARD_MNEMONIC).get_root(SettingsConstants.MAINNET)
        psbt = spend_from([(card_root, "m/84h/0h/0h/0/3", b"\x00" * 4)])

        destination, warnings = self.choose_the_card(monkeypatch, MockCard(card_root), psbt)

        assert warnings == []
        assert destination.View_cls is psbt_views.PSBTOverviewView
        assert self.controller.psbt_sign_with_satochip is True


class TestCardParserKnowsTheClock(BaseTest):
    """
    A psbt loaded from microSD is dated by its file, and the review uses that
    date to flag a locktime years away. The card's parser is built in the
    signer menu and the overview keeps it, so it needs the same clock the
    overview would have given it: without it, a lock the seed flow warns about
    went unmentioned when a card signed.
    """

    choose_the_card = TestCardFlowReadsTheCardsAccount.choose_the_card

    def test_a_far_future_locktime_is_flagged_for_the_card(self, monkeypatch):
        from seedsigner.controller import Controller
        from seedsigner.models.psbt_parser import RiskWarning

        card_root = Seed(mnemonic=CARD_MNEMONIC).get_root(SettingsConstants.MAINNET)
        # About 2.9 years of blocks past the release anchor, in a file written then.
        psbt = spend_from(
            [(card_root, "m/84h/0h/0h/0/0", card_root.my_fingerprint)],
            locktime=Controller.RELEASE_BLOCK_HEIGHT + 150_000,
            sequence=0xFFFFFFFE,
        )
        self.controller.psbt_source_time = Controller.RELEASE_BLOCK_TIME

        destination, warnings = self.choose_the_card(monkeypatch, MockCard(card_root), psbt)
        assert warnings == []
        assert destination.View_cls is psbt_views.PSBTOverviewView

        psbt_views.PSBTOverviewView()
        parser = self.controller.psbt_parser

        assert RiskWarning.LOCKTIME_FAR_FUTURE in parser.risk_warnings
        assert psbt_views.post_overview_destination(parser).View_cls is psbt_views.PSBTRiskWarningView
