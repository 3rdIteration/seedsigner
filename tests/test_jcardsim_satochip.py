"""
    Satochip (and Satodime) as real applet bytecode in jcardsim, driven by SeedSigner's
    real pysatochip client.

    Unlike SeedKeeper, these applets are not prebuilt in their repo -- `Satochip-DIY`'s
    ant build sets no `classes=` attribute, so it keeps only the CAP and discards the
    .class files jcardsim needs. `tests/jcardsim/applets.py` compiles them with javac
    instead, against the JavaCard SDK the repo already vendors.

    The interesting result is that jcardsim's crypto is good enough for the real thing:
    seed import and BIP32 xpub derivation both work, which means secp256k1, the
    derivation itself, and the authentikey signature the client verifies are all
    exercised here rather than stubbed.
"""

import sys
from unittest.mock import MagicMock

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401

# base.py stubs pysatochip so the ordinary suite runs cardless; these tests need it real.
for _name in [m for m in sys.modules if m == "pysatochip" or m.startswith("pysatochip.")]:
    if isinstance(sys.modules[_name], MagicMock):
        del sys.modules[_name]

from jcardsim import JCardSimUnavailable, SimulatedCard, resolve_applet, why_unavailable
from jcardsim.pcsc_shim import patched_pcsc

from seedsigner.models.settings_definition import SettingsConstants


pytestmark = pytest.mark.skipif(
    why_unavailable() is not None, reason=f"jcardsim unavailable: {why_unavailable()}"
)

PIN = list(b"1234")

# A fixed 64-byte BIP32 seed, so the derived keys below are reproducible.
TEST_SEED = bytes.fromhex("00" * 32 + "11" * 32)


@pytest.fixture
def satochip():
    try:
        spec, classes = resolve_applet("satochip")
    except JCardSimUnavailable as exc:
        pytest.skip(str(exc))
    with SimulatedCard(spec, classes) as card:
        card.select()
        yield card


@pytest.fixture
def connector(satochip):
    with patched_pcsc(satochip):
        from pysatochip.CardConnector import CardConnector

        yield CardConnector(card_filter=["satochip"])


def setup_and_login(cc) -> None:
    cc.card_setup(5, 1, PIN, PIN, 5, 1, PIN, PIN, 32, 32, 0x01, 0x01, 0x01)
    cc.set_pin(0, PIN)
    cc.card_verify_PIN()



class TestSatochipBasics:

    def test_card_is_recognised(self, connector):
        assert connector.card_present
        assert connector.card_type == "Satochip"

    def test_setup_then_pin(self, connector):
        response, sw1, sw2, _ = connector.card_get_status()
        assert (sw1, sw2) == (0x90, 0x00)
        assert connector.setup_done is False, "a fresh applet should not be set up"

        setup_and_login(connector)
        assert connector.card_get_status()[3]["setup_done"] is True

    def test_wrong_pin_is_rejected(self, connector):
        """A wrong PIN must fail rather than being quietly accepted."""
        setup_and_login(connector)
        connector.set_pin(0, list(b"9999"))
        with pytest.raises(Exception):
            connector.card_verify_PIN()



class TestSatochipSeedAndDerivation:
    """
    The crypto path: importing a seed and deriving from it on-card.

    pysatochip verifies the card's authentikey signature over the derived key, so a
    success here means the applet's secp256k1 and BIP32 code really ran -- this is not
    a stub returning canned bytes.
    """

    def test_import_seed_returns_the_authentikey(self, connector):
        setup_and_login(connector)
        authentikey = connector.card_bip32_import_seed(list(TEST_SEED))
        assert authentikey is not None
        assert hasattr(authentikey, "get_public_key_bytes")

    @pytest.mark.parametrize(
        "xtype, prefix",
        [("standard", "xpub"), ("p2wpkh", "zpub")],
    )
    def test_derive_xpub(self, connector, xtype, prefix):
        setup_and_login(connector)
        connector.card_bip32_import_seed(list(TEST_SEED))

        xpub = connector.card_bip32_get_xpub("m/84'/0'/0'", xtype, True)
        assert xpub.startswith(prefix)

    def test_derivation_is_deterministic(self, connector):
        """The same path on the same seed must give the same key twice running."""
        setup_and_login(connector)
        connector.card_bip32_import_seed(list(TEST_SEED))

        first = connector.card_bip32_get_xpub("m/84'/0'/0'", "standard", True)
        second = connector.card_bip32_get_xpub("m/84'/0'/0'", "standard", True)
        assert first == second

    def test_different_paths_give_different_keys(self, connector):
        setup_and_login(connector)
        connector.card_bip32_import_seed(list(TEST_SEED))

        first = connector.card_bip32_get_xpub("m/84'/0'/0'", "standard", True)
        second = connector.card_bip32_get_xpub("m/84'/0'/1'", "standard", True)
        assert first != second



class TestSatochipPSBTSigning:
    """
    sign_psbt_with_satochip against the real applet.

    Unlike the Keycard adapter, this backend always exports each derivation and matches
    the public key itself, so these tests cover the export-and-match path end to end, with
    every signature verified off-card against its sighash.
    """

    def _seed(self, connector) -> None:
        setup_and_login(connector)
        assert connector.card_bip32_import_seed(list(TEST_SEED)) is not None

    @pytest.mark.parametrize(
        "script_type, path",
        [
            (SettingsConstants.NATIVE_SEGWIT, "m/84'/0'/0'/0/0"),
            (SettingsConstants.NESTED_SEGWIT, "m/49'/0'/0'/0/0"),
        ],
    )
    def test_single_sig_signs_and_verifies(self, connector, monkeypatch, script_type, path):
        from card_signing_helpers import (
            assert_signed_and_verifies,
            make_psbt,
            patch_signing_settings,
            single_sig_input,
        )
        from embit import bip32
        from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip

        patch_signing_settings(monkeypatch)
        self._seed(connector)

        root = bip32.HDKey.from_seed(TEST_SEED)
        pub = root.derive(path).get_public_key()
        psbt = make_psbt([
            single_sig_input(pub, root.my_fingerprint, path, script_type, txid=bytes(range(32))),
        ])

        result = sign_psbt_with_satochip(psbt, connector)

        assert result.signed_count == 1
        assert not result.timed_out
        assert_signed_and_verifies(psbt, 0, pub)

    def test_multi_input_signs_every_input(self, connector, monkeypatch):
        from card_signing_helpers import (
            assert_signed_and_verifies,
            make_psbt,
            patch_signing_settings,
            single_sig_input,
        )
        from embit import bip32
        from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip

        patch_signing_settings(monkeypatch)
        self._seed(connector)

        root = bip32.HDKey.from_seed(TEST_SEED)
        paths = ["m/84'/0'/0'/0/0", "m/84'/0'/0'/0/1"]
        psbt = make_psbt([
            single_sig_input(
                root.derive(path).get_public_key(), root.my_fingerprint, path,
                SettingsConstants.NATIVE_SEGWIT, txid=bytes([index]) * 32, vout=index,
            )
            for index, path in enumerate(paths)
        ])

        result = sign_psbt_with_satochip(psbt, connector)

        assert result.signed_count == len(paths)
        for index, path in enumerate(paths):
            assert_signed_and_verifies(psbt, index, root.derive(path).get_public_key())

    def test_multisig_signs_only_the_card_cosigner(self, connector, monkeypatch):
        from card_signing_helpers import (
            assert_signed_and_verifies,
            make_psbt,
            multisig_input,
            patch_signing_settings,
        )
        from embit import bip32
        from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip

        patch_signing_settings(monkeypatch)
        self._seed(connector)

        path = "m/48'/0'/0'/2'/0/0"
        card_root = bip32.HDKey.from_seed(TEST_SEED)
        cosigners = [(card_root.derive(path).get_public_key(), card_root.my_fingerprint, path)]
        for foreign_seed in (bytes([0xAA]) * 64, bytes([0xBB]) * 64):
            foreign_root = bip32.HDKey.from_seed(foreign_seed)
            cosigners.append(
                (foreign_root.derive(path).get_public_key(), foreign_root.my_fingerprint, path)
            )

        inp = multisig_input(cosigners, 2, SettingsConstants.NATIVE_SEGWIT, txid=bytes(range(32)))
        psbt = make_psbt([inp])

        result = sign_psbt_with_satochip(psbt, connector)

        assert result.signed_count == 1
        assert_signed_and_verifies(psbt, 0, cosigners[0][0])
        for foreign_pub, _fingerprint, _path in cosigners[1:]:
            assert foreign_pub not in inp.partial_sigs

    def test_multisig_without_the_card_signs_nothing(self, connector, monkeypatch):
        from card_signing_helpers import make_psbt, multisig_input, patch_signing_settings
        from embit import bip32
        from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip

        patch_signing_settings(monkeypatch)
        self._seed(connector)

        path = "m/48'/0'/0'/2'/0/0"
        cosigners = []
        for foreign_seed in (bytes([0xAA]) * 64, bytes([0xBB]) * 64):
            foreign_root = bip32.HDKey.from_seed(foreign_seed)
            cosigners.append(
                (foreign_root.derive(path).get_public_key(), foreign_root.my_fingerprint, path)
            )

        inp = multisig_input(cosigners, 2, SettingsConstants.NATIVE_SEGWIT, txid=bytes(range(32)))
        psbt = make_psbt([inp])

        result = sign_psbt_with_satochip(psbt, connector)

        assert result.signed_count == 0
        assert not inp.partial_sigs


class TestSatochipMessageSigning:

    def test_sign_message_matches_the_derived_key(self, connector, monkeypatch):
        from card_signing_helpers import assert_message_signature, patch_signing_settings
        from embit import bip32
        from seedsigner.helpers.satochip_signer import sign_message_with_satochip

        patch_signing_settings(monkeypatch)
        setup_and_login(connector)
        assert connector.card_bip32_import_seed(list(TEST_SEED)) is not None

        path = "m/84'/0'/0'/0/0"
        message = "SeedSigner jcardsim Satochip message"
        signature = sign_message_with_satochip(path, message, connector)

        expected_pub = bip32.HDKey.from_seed(TEST_SEED).derive(path).get_public_key()
        assert_message_signature(signature, message, expected_pub)


class TestSatodime:
    """Satodime builds and installs from the same aggregator repo."""

    def test_applet_selects(self):
        try:
            spec, classes = resolve_applet("satodime")
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with SimulatedCard(spec, classes) as card:
            _, sw1, sw2 = card.select()
            assert (sw1, sw2) == (0x90, 0x00)
