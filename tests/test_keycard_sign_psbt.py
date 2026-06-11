import random
import types

from embit.ec import PrivateKey
from embit.psbt import DerivationPath, InputScope, PSBT

from seedsigner.helpers.keycard_signer import sign_psbt_with_keycard
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants


class DummySettings:
    def get_value(self, setting):
        if setting == SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT:
            return 1
        return 0


class DummyKeycardConnector:
    is_keycard_backend = True

    def __init__(self):
        self.sign_order = []

    def card_sign_transaction_hash(self, keynbr, h, none):
        _ = keynbr
        _ = none
        idx = h[0]
        self.sign_order.append(idx)
        return (bytes([idx]) * 70, 0x90, 0x00)


def test_sign_psbt_with_keycard_path_fallback_single_derivation(monkeypatch):
    psbt = PSBT()
    psbt.inputs = [InputScope()]

    priv = PrivateKey(bytes([7]) * 32)
    pub = priv.get_public_key()
    psbt.inputs[0].bip32_derivations[pub] = DerivationPath(
        b"\x00" * 4,
        [0x80000054, 0x80000000, 0x80000000, 0, 0],
    )

    psbt.sighash = types.MethodType(
        lambda self, idx, sighash=None: bytes([idx]) * 32,
        psbt,
    )

    connector = DummyKeycardConnector()
    monkeypatch.setattr(Settings, "get_instance", classmethod(lambda cls: DummySettings()))
    random.seed(0)

    signed = sign_psbt_with_keycard(psbt, connector)

    assert signed == 1
    assert getattr(connector, "_last_path", None) == "m/84'/0'/0'/0/0"
    assert psbt.inputs[0].partial_sigs[pub].endswith(b"\x01")
