import os
from embit import ec, script, psbt
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from seedsigner.models.wif import WIFKey
from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.models.decode_qr import DecodeQR

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
