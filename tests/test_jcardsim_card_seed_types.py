"""
    Every seed type SeedSigner can initialise a Satochip or Keycard with, against the
    real applets in jcardsim.

    The card "Initialise with Seed" screen passes ``seed.seed_bytes`` straight to the
    connector, so each Seed subclass below reaches the card exactly as it does in
    production. What comes back must match ``seed.get_root(network)`` -- which for SLIP-39
    and Aezeed is derived from the master secret (16 or 32 bytes), not a 64-byte BIP-39
    seed, so the Keycard's BIP39_SEED import cannot carry them and its EXTENDED_ECC root
    path is exercised instead.

    XprvSeed is deliberately absent: it has no ``seed_bytes`` (its root is the secret) and
    neither card has an import-xprv command, so the import screen rejects it. It is
    covered as a rejection in tests/test_flows_seed.py.
"""

import sys
from unittest.mock import MagicMock

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401

# base.py stubs pysatochip so the ordinary suite runs cardless; the Satochip fixture
# below needs the real client.
for _name in [m for m in sys.modules if m == "pysatochip" or m.startswith("pysatochip.")]:
    if isinstance(sys.modules[_name], MagicMock):
        del sys.modules[_name]

from jcardsim import JCardSimUnavailable, SimulatedCard, resolve_applet, why_unavailable
from jcardsim.pcsc_shim import patched_pcsc

from seedsigner.models.seed import AezeedSeed, ElectrumSeed, Seed, Slip39Seed, XprvSeed


pytestmark = pytest.mark.skipif(
    why_unavailable() is not None, reason=f"jcardsim unavailable: {why_unavailable()}"
)

KEYCARD_PIN = "123456"
KEYCARD_PUK = "987654321012"
SATOCHIP_PIN = list(b"1234")

# One derivation with hardened elements and one with non-hardened children, so both
# CKD modes are exercised on every seed type.
DERIVATION_PATHS = ("m/84'/0'/0'", "m/0/1")


def _sample_seeds() -> dict[str, Seed]:
    """
    One Seed per loadable type, each with a known-good vector.

    The Electrum, SLIP-39 and Aezeed mnemonics are the ones tests/test_seed.py asserts
    fixed bytes for, so a failure here points at the card path rather than the parser.
    """
    return {
        "bip39": Seed(mnemonic="abandon abandon abandon abandon abandon abandon "
                              "abandon abandon abandon abandon abandon about".split()),
        "electrum": ElectrumSeed(
            mnemonic="regular reject rare profit once math fringe chase until "
                     "ketchup century escape".split()
        ),
        "slip39": Slip39Seed(mnemonics=[
            "testify swimming academic academic column loyalty smear include exotic "
            "bedroom exotic wrist lobe cover grief golden smart junior estimate learn"
        ]),
        "aezeed": AezeedSeed(mnemonic=(
            "absorb original enlist once climb erode kid thrive kitchen giant define "
            "tube orange leader harbor comfort olive fatal success suggest drink "
            "penalty chimney ritual"
        ).split()),
    }


@pytest.fixture(params=sorted(_sample_seeds()))
def sample(request) -> Seed:
    return _sample_seeds()[request.param]


@pytest.fixture
def keycard():
    from jcardsim import why_keycard_unavailable

    reason = why_keycard_unavailable()
    if reason:
        pytest.skip(reason)
    try:
        spec, classes = resolve_applet("keycard")
    except JCardSimUnavailable as exc:
        pytest.skip(str(exc))

    with SimulatedCard(spec, classes) as card:
        card.select()
        with patched_pcsc(card):
            from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

            connector = KeycardSatochipConnector.create(card_filter=["satochip"])
            connector.card_setup(
                3, 5, KEYCARD_PIN, KEYCARD_PUK, 3, 5, KEYCARD_PIN, KEYCARD_PUK,
                32, 32, 0x01, 0x01, 0x01,
            )
            assert connector.card_verify_PIN()[1:] == (0x90, 0x00)
            yield connector


@pytest.fixture
def satochip():
    try:
        spec, classes = resolve_applet("satochip")
    except JCardSimUnavailable as exc:
        pytest.skip(str(exc))

    with SimulatedCard(spec, classes) as card:
        card.select()
        with patched_pcsc(card):
            from pysatochip.CardConnector import CardConnector

            connector = CardConnector(card_filter=["satochip"])
            connector.card_setup(
                5, 1, SATOCHIP_PIN, SATOCHIP_PIN, 5, 1, SATOCHIP_PIN, SATOCHIP_PIN,
                32, 32, 0x01, 0x01, 0x01,
            )
            connector.set_pin(0, SATOCHIP_PIN)
            connector.card_verify_PIN()
            yield connector


def _assert_card_derives_the_seed(connector, seed: Seed) -> None:
    """
    Import ``seed.seed_bytes`` and check both derived paths against ``seed.get_root()``.

    Per AGENTS.md, always derive through ``seed.get_root(network)`` -- never rebuild the
    root from ``seed.seed_bytes`` (None for XprvSeed, and the whole point here is that the
    card must reproduce exactly what get_root() produces).
    """
    assert isinstance(seed.seed_bytes, (bytes, bytearray)) and seed.seed_bytes, \
        f"{type(seed).__name__} did not produce seed bytes"

    import_result = connector.card_bip32_import_seed(list(seed.seed_bytes))
    # Keycard returns (response, sw1, sw2); pysatochip returns the authentikey.
    if isinstance(import_result, tuple) and len(import_result) == 3:
        assert import_result[1:] == (0x90, 0x00), "card import failed"
    else:
        assert import_result is not None, "card import did not return an authentikey"

    root = seed.get_root()
    for path in DERIVATION_PATHS:
        expected = root.derive(path)
        pub, chain_code = connector.card_bip32_get_extendedkey(path)
        assert bytes(pub.get_public_key_bytes(compressed=True)) == \
            expected.key.get_public_key().serialize(), f"{path} public key mismatch"
        assert bytes(chain_code) == expected.chain_code, f"{path} chain code mismatch"


class TestKeycardSeedTypes:
    """Every loadable Seed type seeds a Keycard and derives the same tree as get_root()."""

    def test_seed_type_initialises_the_card(self, keycard, sample):
        _assert_card_derives_the_seed(keycard, sample)


class TestSatochipSeedTypes:
    """As above, for the Satochip applet."""

    def test_seed_type_initialises_the_card(self, satochip, sample):
        _assert_card_derives_the_seed(satochip, sample)


def test_seed_type_lengths_are_what_the_cards_receive():
    """
    Pin the seed_bytes lengths the card import sees, so it is obvious which types fit the
    Keycard's 64-byte BIP39_SEED command and which need the root-material path.
    """
    seeds = _sample_seeds()
    assert len(seeds["bip39"].seed_bytes) == 64
    assert len(seeds["electrum"].seed_bytes) == 64
    assert len(seeds["slip39"].seed_bytes) in (16, 32)
    assert len(seeds["aezeed"].seed_bytes) == 16


def test_xprv_seed_cannot_initialise_a_card():
    """XprvSeed carries no seed bytes, and neither card has an import-xprv command."""
    xprv = (
        "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQp"
        "Um98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
    )
    seed = XprvSeed(xprv)
    assert seed.seed_bytes is None
    assert seed.get_root() is not None
