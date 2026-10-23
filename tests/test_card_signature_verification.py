# pylint: disable=missing-function-docstring
import random
import types

from embit.ec import PrivateKey, Signature
from embit.psbt import DerivationPath, InputScope, PSBT

from seedsigner.helpers.keycard_signer import sign_psbt_with_keycard
from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants


WALLET_KEY = PrivateKey(bytes([7]) * 32)   # the key the PSBT names
FOREIGN_KEY = PrivateKey(bytes([9]) * 32)  # the key the card actually holds


class DummySettings:
    def get_value(self, setting):
        if setting == SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT:
            return 1
        if setting == SettingsConstants.SETTING__KEYCARD_SIGN_TIMEOUT:
            return 2
        return 0


def make_psbt(pubkey):
    psbt = PSBT()
    psbt.inputs = [InputScope()]
    psbt.inputs[0].bip32_derivations[pubkey] = DerivationPath(
        b"\x00" * 4, [0x80000054, 0x80000000, 0x80000000, 0, 0]
    )
    psbt.sighash = types.MethodType(
        lambda self, idx, sighash=None: bytes([idx + 1]) * 32, psbt
    )
    return psbt


class CardPubkey:
    """The pubkey shape a Satochip connector returns from a derivation."""

    def __init__(self, key):
        self._sec = key.get_public_key().sec()

    def get_public_key_bytes(self, compressed=True):
        return self._sec


class SigningCard:
    """A card that signs with `key`, whatever key the PSBT asked for."""

    def __init__(self, key, der_override=None, derives=None):
        self.key = key
        self.der_override = der_override
        # The key the card reports for the input's path, when that is not the
        # key it signs with
        self.derives = derives or key

    def card_sign_transaction_hash(self, keynbr, h, _none):
        if self.der_override is not None:
            return (self.der_override, 0x90, 0x00)
        sig = self.key.sign(bytes(h))
        return (sig.serialize(), 0x90, 0x00)

    # Satochip path: the signer derives and compares the card's pubkey first
    def card_bip32_get_extendedkey(self, path, *args, **kwargs):
        return (CardPubkey(self.derives), b"\x00" * 32)


def sign(signer, psbt, card, monkeypatch):
    monkeypatch.setattr(Settings, "get_instance", classmethod(lambda cls: DummySettings()))
    random.seed(0)
    return signer(psbt, card)


class TestOnlyAVerifiedSignatureIsFiled:
    """A partial_sig is a claim that `pubkey` signed this input."""

    def test_keycard_does_not_file_a_foreign_signature(self, monkeypatch):
        pub = WALLET_KEY.get_public_key()
        psbt = make_psbt(pub)

        result = sign(sign_psbt_with_keycard, psbt, SigningCard(FOREIGN_KEY), monkeypatch)

        assert result.signed_count == 0
        assert pub not in psbt.inputs[0].partial_sigs

    def test_keycard_files_a_signature_that_verifies(self, monkeypatch):
        pub = WALLET_KEY.get_public_key()
        psbt = make_psbt(pub)

        result = sign(sign_psbt_with_keycard, psbt, SigningCard(WALLET_KEY), monkeypatch)

        assert result.signed_count == 1
        filed = psbt.inputs[0].partial_sigs[pub]
        assert filed.endswith(b"\x01")
        assert pub.verify(Signature.parse(filed[:-1]), psbt.sighash(0))

    def test_keycard_does_not_file_garbage(self, monkeypatch):
        pub = WALLET_KEY.get_public_key()
        psbt = make_psbt(pub)

        result = sign(
            sign_psbt_with_keycard, psbt, SigningCard(WALLET_KEY, der_override=b"\x07" * 70), monkeypatch
        )

        assert result.signed_count == 0
        assert pub not in psbt.inputs[0].partial_sigs


class TestTheSatochipSignerFilesOnlyAVerifiedSignature:
    """
    The Satochip signer compares the card's derived pubkey with the input's
    before signing, but that says nothing about what the card then returns.
    """

    def test_satochip_does_not_file_garbage(self, monkeypatch):
        pub = WALLET_KEY.get_public_key()
        psbt = make_psbt(pub)
        card = SigningCard(WALLET_KEY, der_override=b"\x07" * 70)

        result = sign(sign_psbt_with_satochip, psbt, card, monkeypatch)

        assert result.signed_count == 0
        assert pub not in psbt.inputs[0].partial_sigs

    def test_satochip_does_not_file_a_signature_by_another_key(self, monkeypatch):
        pub = WALLET_KEY.get_public_key()
        psbt = make_psbt(pub)
        card = SigningCard(FOREIGN_KEY, derives=WALLET_KEY)

        result = sign(sign_psbt_with_satochip, psbt, card, monkeypatch)

        assert result.signed_count == 0
        assert pub not in psbt.inputs[0].partial_sigs

    def test_satochip_files_a_signature_that_verifies(self, monkeypatch):
        pub = WALLET_KEY.get_public_key()
        psbt = make_psbt(pub)

        result = sign(sign_psbt_with_satochip, psbt, SigningCard(WALLET_KEY), monkeypatch)

        assert result.signed_count == 1
        filed = psbt.inputs[0].partial_sigs[pub]
        assert pub.verify(Signature.parse(filed[:-1]), psbt.sighash(0))
