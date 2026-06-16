import random
import types

from embit.psbt import PSBT, InputScope, DerivationPath
from embit.ec import PrivateKey

from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants


class DummySettings:
    def get_value(self, setting):
        if setting == SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT:
            return 1
        return 0


class DummyKey:
    def __init__(self, pub):
        self._pub = pub

    def get_public_key_bytes(self, compressed=True):
        return self._pub


class DummyConnector:
    def __init__(self, pubkeys):
        self.pubkeys = pubkeys
        self.sign_order = []

    def card_bip32_get_extendedkey(self, path):
        idx = int(path.split("/")[1])
        return DummyKey(self.pubkeys[idx]), b""

    def card_sign_transaction_hash(self, keynbr, h, none):
        idx = h[0]
        self.sign_order.append(idx)
        # return a deterministic signature unique to the input index so we
        # can later verify that signatures are written back in the original
        # order, despite the randomized signing sequence
        return (bytes([idx]) * 70, 0x90, 0x00)



def test_sign_psbt_processes_inputs_in_random_order(monkeypatch):
    psbt = PSBT()
    psbt.inputs = [InputScope(), InputScope(), InputScope()]
    pubkeys = []
    for i, inp in enumerate(psbt.inputs):
        priv = PrivateKey(bytes([i + 1]) * 32)
        pub = priv.get_public_key()
        inp.bip32_derivations[pub] = DerivationPath(b"\x00" * 4, [i])
        pubkeys.append(pub.sec())

    psbt.sighash = types.MethodType(lambda self, idx, sighash=None: bytes([idx]) * 32, psbt)

    connector = DummyConnector(pubkeys)
    monkeypatch.setattr(Settings, "get_instance", classmethod(lambda cls: DummySettings()))
    random.seed(0)
    result = sign_psbt_with_satochip(psbt, connector)
    assert result.signed_count == 3
    assert not result.timed_out
    assert connector.sign_order != [0, 1, 2]
    assert sorted(connector.sign_order) == [0, 1, 2]

    # Verify that each input's signature corresponds to its original
    # index, confirming that results are returned in input order even
    # though the signing operations occurred in a shuffled sequence
    for i, inp in enumerate(psbt.inputs):
        pub = next(iter(inp.bip32_derivations.keys()))
        assert inp.partial_sigs[pub] == bytes([i]) * 70 + b"\x01"




