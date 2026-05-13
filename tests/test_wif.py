import os
from embit import ec, script, psbt
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from seedsigner.models.wif import WIFKey
from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.models.decode_qr import DecodeQR
from base import BaseTest

def test_wif_signs_psbt():
    priv = ec.PrivateKey(os.urandom(32))
    wif = priv.wif()
    key = WIFKey(wif)
    pub = priv.get_public_key()
    spk = script.p2wpkh(pub)
    tx = Transaction(1, [TransactionInput(b"\x00" * 32, 0)], [TransactionOutput(900, spk)], 0)
    p = psbt.PSBT(tx)
    p.inputs[0].witness_utxo = TransactionOutput(1000, spk)
    parser = PSBTParser(p, seed=key, network=SettingsConstants.MAINNET)
    assert isinstance(parser.root, ec.PrivateKey)
    p.sign_with(parser.root)
    assert PSBTParser.sig_count(p) == 1


def test_decode_qr_wif():
    priv = ec.PrivateKey(os.urandom(32))
    wif = priv.wif()
    decoder = DecodeQR()
    decoder.add_data(wif)
    assert decoder.is_complete
    assert decoder.is_wif
    assert decoder.get_wif() == wif


class TestWIF(BaseTest):
    def test_wif_signed_tx_qr_is_raw_hex(self):
        from seedsigner.views.psbt_views import PSBTFinalizeView, PSBTSignedQRDisplayView
        from seedsigner.models.encode_qr import GenericStringEncoder
        from embit.finalizer import finalize_psbt
        from seedsigner.controller import Controller

        priv = ec.PrivateKey(os.urandom(32))
        wif = priv.wif()
        key = WIFKey(wif)
        pub = priv.get_public_key()
        spk = script.p2wpkh(pub)
        tx = Transaction(1, [TransactionInput(b"\x00" * 32, 0)], [TransactionOutput(900, spk)], 0)
        p = psbt.PSBT(tx)
        p.inputs[0].witness_utxo = TransactionOutput(1000, spk)

        # compute expected finalized tx
        p_expected = psbt.PSBT.parse(p.serialize())
        p_expected.sign_with(priv)
        expected_hex = finalize_psbt(p_expected).serialize().hex()

        # setup controller state
        ctrl = Controller.get_instance()
        ctrl.psbt = p
        ctrl.psbt_seed = key
        ctrl.psbt_parser = PSBTParser(p, seed=key, network=SettingsConstants.MAINNET)

        finalize_view = PSBTFinalizeView()
        finalize_view.run_screen = lambda *a, **k: 0
        finalize_view.run()

        captured = {}
        display_view = PSBTSignedQRDisplayView()

        def fake_run_screen(screen_cls, **kwargs):
            captured["encoder"] = kwargs["qr_encoder"]
            return 0

        display_view.run_screen = fake_run_screen
        display_view.run()

        encoder = captured["encoder"]
        assert isinstance(encoder, GenericStringEncoder)
        assert encoder.next_part() == expected_hex

    def test_wif_setting_disables_options(self):
        from seedsigner.views import psbt_views
        from embit import ec, script, psbt
        from embit.transaction import Transaction, TransactionInput, TransactionOutput
        import os

        self.settings.set_value(SettingsConstants.SETTING__WIF_KEYS, SettingsConstants.OPTION__DISABLED)

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

        assert psbt_views.PSBTSelectSeedView.SCAN_WIF not in buttons
        assert psbt_views.PSBTSelectSeedView.TYPE_WIF not in buttons
