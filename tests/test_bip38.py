from embit import ec, script, psbt
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from seedsigner.models.bip38 import BIP38Key
from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.models.decode_qr import DecodeQR


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

