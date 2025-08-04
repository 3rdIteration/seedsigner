from embit import ec, script, psbt
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from seedsigner.models.bip38 import BIP38Key
from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.models.decode_qr import DecodeQR
from base import BaseTest


def test_bip38_signs_psbt():
    enc = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"
    bip38 = BIP38Key(enc)
    key = bip38.decrypt("TestingOneTwoThree")

    priv = key.privkey
    pub = priv.get_public_key()
    spk = script.p2wpkh(pub)
    tx = Transaction(1, [TransactionInput(b"\x00" * 32, 0)], [TransactionOutput(900, spk)], 0)
    p = psbt.PSBT(tx)
    p.inputs[0].witness_utxo = TransactionOutput(1000, spk)
    parser = PSBTParser(p, seed=key, network=SettingsConstants.MAINNET)
    assert isinstance(parser.root, ec.PrivateKey)
    p.sign_with(parser.root)
    assert PSBTParser.sig_count(p) == 1


def test_decode_qr_bip38():
    enc = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"
    decoder = DecodeQR()
    decoder.add_data(enc)
    assert decoder.is_complete
    assert decoder.is_bip38
    assert decoder.get_bip38() == enc


class TestBIP38Settings(BaseTest):
    def test_bip38_setting_disables_options(self):
        from seedsigner.views import psbt_views
        from embit import ec, script, psbt
        from embit.transaction import Transaction, TransactionInput, TransactionOutput
        import os

        self.settings.set_value(SettingsConstants.SETTING__BIP38_KEYS, SettingsConstants.OPTION__DISABLED)

        priv = ec.PrivateKey(os.urandom(32))
        pub = priv.get_public_key()
        spk = script.p2wpkh(pub)
        tx = Transaction(1, [TransactionInput(b"\x00" * 32, 0)], [TransactionOutput(900, spk)], 0)
        p = psbt.PSBT(tx)
        p.inputs[0].witness_utxo = TransactionOutput(1000, spk)
        self.controller.psbt = p
        self.controller._storage = type("s", (), {})()
        self.controller._storage.seeds = []

        # Build button list as PSBTSelectSeedView would
        buttons = [
            psbt_views.PSBTSelectSeedView.SATOCHIP,
            psbt_views.PSBTSelectSeedView.SCAN_SEED,
        ]
        if self.settings.get_value(SettingsConstants.SETTING__WIF_KEYS) == SettingsConstants.OPTION__ENABLED:
            buttons.append(psbt_views.PSBTSelectSeedView.SCAN_WIF)
        if self.settings.get_value(SettingsConstants.SETTING__BIP38_KEYS) == SettingsConstants.OPTION__ENABLED:
            buttons.append(psbt_views.PSBTSelectSeedView.SCAN_BIP38)

        seed_lengths = self.settings.get_value(SettingsConstants.SETTING__SEED_WORD_LENGTHS)
        options = {
            12: psbt_views.PSBTSelectSeedView.TYPE_12WORD,
            15: psbt_views.PSBTSelectSeedView.TYPE_15WORD,
            18: psbt_views.PSBTSelectSeedView.TYPE_18WORD,
            21: psbt_views.PSBTSelectSeedView.TYPE_21WORD,
            24: psbt_views.PSBTSelectSeedView.TYPE_24WORD,
        }
        for l in seed_lengths:
            buttons.append(options[l])
        if self.settings.get_value(SettingsConstants.SETTING__ELECTRUM_SEEDS) == SettingsConstants.OPTION__ENABLED:
            buttons.append(psbt_views.PSBTSelectSeedView.TYPE_ELECTRUM)
        if self.settings.get_value(SettingsConstants.SETTING__WIF_KEYS) == SettingsConstants.OPTION__ENABLED:
            buttons.append(psbt_views.PSBTSelectSeedView.TYPE_WIF)
        if self.settings.get_value(SettingsConstants.SETTING__BIP38_KEYS) == SettingsConstants.OPTION__ENABLED:
            buttons.append(psbt_views.PSBTSelectSeedView.TYPE_BIP38)

        assert psbt_views.PSBTSelectSeedView.SCAN_BIP38 not in buttons
        assert psbt_views.PSBTSelectSeedView.TYPE_BIP38 not in buttons

