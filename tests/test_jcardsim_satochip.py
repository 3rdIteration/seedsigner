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
