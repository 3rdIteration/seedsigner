import os
import pytest
from pysatochip.CardConnector import CardConnector
from embit import bip32


def _setup_card() -> CardConnector:
    cc = CardConnector(card_filter="seedkeeper")
    _, _, _, status = cc.card_get_status()

    pin = list(b"1234")
    if not status.get("setup_done", False):
        zeros = [0] * 16
        cc.card_setup(0x05, 0x01, pin, zeros, 0x01, 0x01, zeros, zeros,
                       32, 0x0000, 0x01, 0x01, 0x01)
    cc.set_pin(0, pin)
    cc.card_verify_PIN_simple()
    return cc


def test_seedkeeper_roundtrip(jcardsim_emulator):
    cc = _setup_card()

    seed = bytes.fromhex("00" * 32)
    cc.card_bip32_import_seed(seed)
    xprv = cc.card_bip32_get_xprv("m", "p2wpkh", False)
    expected = bip32.HDKey.from_seed(seed, version=bip32.NETWORKS['test']['xprv']).to_base58()
    assert xprv == expected


def test_seedkeeper_save_load_seed(jcardsim_emulator):
    cc = _setup_card()

    seed = bytes.fromhex("11" * 32)
    header = cc.make_header("Masterseed", "Plaintext export allowed", "test-seed")
    secret_list = [len(seed)] + list(seed)
    sid, fingerprint = cc.seedkeeper_import_secret({"header": header, "secret_list": secret_list})

    exported = cc.seedkeeper_export_secret(sid, None)
    assert exported["secret"] == seed.hex()


def test_seedkeeper_save_load_descriptor(jcardsim_emulator):
    cc = _setup_card()
    seed = bytes.fromhex("22" * 32)
    master = bip32.HDKey.from_seed(seed, version=bip32.NETWORKS['test']['xprv'])
    xpub = master.derive("m/48h/1h/0h/2h").to_public()
    descriptor = f"wsh({{sortedmulti(1,{xpub.to_base58()})}})"

    header = cc.make_header("Data", "Plaintext export allowed", "desc")
    data = descriptor.encode()
    secret_list = list(len(data).to_bytes(2, "big")) + list(data)
    sid, fp = cc.seedkeeper_import_secret({"header": header, "secret_list": secret_list})

    exported = cc.seedkeeper_export_secret(sid, None)
    retrieved = bytes.fromhex(exported["secret"])[2:].decode()
    assert retrieved == descriptor
