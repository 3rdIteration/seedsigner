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
        if setting == SettingsConstants.SETTING__KEYCARD_SIGN_TIMEOUT:
            return 2
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

    result = sign_psbt_with_keycard(psbt, connector)

    assert result.signed_count == 1
    assert not result.timed_out
    assert getattr(connector, "_last_path", None) == "m/84'/0'/0'/0/0"
    assert psbt.inputs[0].partial_sigs[pub].endswith(b"\x01")


class _DummyKey:
    def __init__(self, pub):
        self._pub = pub

    def get_public_key_bytes(self, compressed=True):
        return self._pub


class DummyMultisigKeycardConnector(DummyKeycardConnector):
    """A Keycard whose key lives at exactly one of the input's derivations."""

    def __init__(self, card_pubkey, card_path):
        super().__init__()
        self.card_pubkey = card_pubkey
        self.card_path = card_path

    def card_bip32_get_extendedkey(self, path):
        if path == self.card_path:
            return _DummyKey(self.card_pubkey), b""
        raise Exception("pubkey export rejected")


def test_sign_psbt_with_keycard_multisig_matches_card_pubkey(monkeypatch):
    """
    A multisig input carries a derivation per cosigner. The Keycard signer must
    sign the one derivation whose public key the card reproduces, rather than
    skipping the whole input (the pre-fix behaviour that made multisig signing
    silently do nothing).
    """
    psbt = PSBT()
    psbt.inputs = [InputScope()]

    # Three cosigners on the same input, only the middle one is on the card.
    card_priv = PrivateKey(bytes([9]) * 32)
    card_pub = card_priv.get_public_key()
    other_a = PrivateKey(bytes([7]) * 32).get_public_key()
    other_b = PrivateKey(bytes([8]) * 32).get_public_key()

    card_path = "m/48'/1'/0'/2'/0/0"
    psbt.inputs[0].bip32_derivations[other_a] = DerivationPath(
        b"\x00" * 4, [0x80000030, 0x80000001, 0x80000000, 0x80000002, 0, 0]
    )
    psbt.inputs[0].bip32_derivations[card_pub] = DerivationPath(
        b"\x00" * 4, [0x80000030, 0x80000001, 0x80000000, 0x80000002, 0, 0]
    )
    psbt.inputs[0].bip32_derivations[other_b] = DerivationPath(
        b"\x00" * 4, [0x80000030, 0x80000001, 0x80000000, 0x80000002, 0, 0]
    )

    psbt.sighash = types.MethodType(
        lambda self, idx, sighash=None: bytes([idx]) * 32,
        psbt,
    )

    connector = DummyMultisigKeycardConnector(card_pub.sec(), card_path)
    monkeypatch.setattr(Settings, "get_instance", classmethod(lambda cls: DummySettings()))
    random.seed(0)

    result = sign_psbt_with_keycard(psbt, connector)

    assert result.signed_count == 1
    assert not result.timed_out
    # The signature must be attached to the card's own pubkey, not a cosigner's.
    assert card_pub in psbt.inputs[0].partial_sigs
    assert other_a not in psbt.inputs[0].partial_sigs
    assert other_b not in psbt.inputs[0].partial_sigs
    assert getattr(connector, "_last_path", None) == card_path
    assert psbt.inputs[0].partial_sigs[card_pub].endswith(b"\x01")


def test_sign_psbt_with_keycard_multisig_skips_when_no_pubkey_matches(monkeypatch):
    """
    If the card cannot reproduce any of the input's cosigner pubkeys, nothing
    is signed for that input (no guessing).
    """
    psbt = PSBT()
    psbt.inputs = [InputScope()]

    other_a = PrivateKey(bytes([7]) * 32).get_public_key()
    other_b = PrivateKey(bytes([8]) * 32).get_public_key()
    card_pub = PrivateKey(bytes([9]) * 32).get_public_key()

    psbt.inputs[0].bip32_derivations[other_a] = DerivationPath(
        b"\x00" * 4, [0x80000030, 0x80000001, 0x80000000, 0x80000002, 0, 0]
    )
    psbt.inputs[0].bip32_derivations[other_b] = DerivationPath(
        b"\x00" * 4, [0x80000030, 0x80000001, 0x80000000, 0x80000002, 0, 0]
    )

    psbt.sighash = types.MethodType(
        lambda self, idx, sighash=None: bytes([idx]) * 32,
        psbt,
    )

    # The card's key is at a path that isn't claimed by any derivation.
    connector = DummyMultisigKeycardConnector(card_pub.sec(), "m/48'/1'/0'/2'/9/9")
    monkeypatch.setattr(Settings, "get_instance", classmethod(lambda cls: DummySettings()))
    random.seed(0)

    result = sign_psbt_with_keycard(psbt, connector)

    assert result.signed_count == 0
    assert not psbt.inputs[0].partial_sigs

