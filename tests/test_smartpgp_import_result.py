# pylint: disable=missing-function-docstring
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from pgpy.constants import EllipticCurveOID, KeyFlags

from seedsigner.helpers import smartpgp_import
from seedsigner.helpers.smartpgp import commands, highlevel


class DummyKey:
    """A subkey whose flags name no card slot, so it cannot be imported."""

    def __init__(self, fingerprint="AAAA BBBB CCCC DDDD"):
        self.fingerprint = fingerprint
        self.key_flags = set()
        self._key = SimpleNamespace(keymaterial=SimpleNamespace())


class DummyContext:
    """A card that accepts the connection but is never asked to store anything."""

    instances = []

    def __init__(self):
        self.admin_pin = None
        self.put_keys = []
        self.put_data = []
        DummyContext.instances.append(self)

    def connect(self):
        pass

    def verify_admin_pin(self):
        pass

    def cmd_switch_crypto(self, alg, role):
        pass

    def cmd_put_key(self, role, pubkey=None, privkey=None, *, components=None):
        self.put_keys.append(role)

    def cmd_put_data(self, tag, value):
        self.put_data.append(tag)


@pytest.fixture
def exported_key(monkeypatch):
    DummyContext.instances = []
    monkeypatch.setattr(
        smartpgp_import, "run",
        lambda *a, **kw: SimpleNamespace(stdout=b"-----BEGIN PGP-----", returncode=0),
    )
    monkeypatch.setattr(smartpgp_import, "CardConnectionContext", DummyContext)
    return DummyKey


class TestImportResult:
    """"Imported" must mean key material actually reached the card."""

    def test_no_importable_subkey_is_not_success(self, monkeypatch, exported_key):
        subkey = exported_key()
        key = SimpleNamespace(subkeys={"x": subkey})
        monkeypatch.setattr(
            smartpgp_import.pgpy.PGPKey, "from_blob",
            classmethod(lambda cls, blob: (key, None)),
        )

        result = smartpgp_import.import_keys_with_smartpgp("FPR", "12345678")

        assert result is False
        assert DummyContext.instances[0].put_keys == []


PRIMARY_FPR = "AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111 2222 3333"
SUBKEY_FPR = "1111 2222 3333 4444 5555 6666 7777 8888 9999 0000"


def p256_key(fingerprint, flags):
    """A key the importer can write: P-256 material with the given usage flags."""
    material = SimpleNamespace(
        oid=EllipticCurveOID.NIST_P256, s=7, p=SimpleNamespace(x=1, y=2)
    )
    return SimpleNamespace(
        fingerprint=fingerprint,
        key_flags=set(flags),
        created=datetime(2024, 1, 1, tzinfo=timezone.utc),
        _key=SimpleNamespace(keymaterial=material),
    )


class TestSelectionMisses:
    """Asking for specific subkeys must never import the primary key instead."""

    def test_a_selection_that_matches_nothing_is_not_success(self, monkeypatch, exported_key):
        # Primaries made here certify and sign, so falling back to one put it
        # in the signature slot.
        key = p256_key(PRIMARY_FPR, {KeyFlags.Certify, KeyFlags.Sign})
        key.subkeys = {"x": p256_key(SUBKEY_FPR, {KeyFlags.Sign})}
        monkeypatch.setattr(
            smartpgp_import.pgpy.PGPKey, "from_blob",
            classmethod(lambda cls, blob: (key, None)),
        )

        result = smartpgp_import.import_keys_with_smartpgp(
            "FPR", "12345678", subkeys={"s": "DEAD BEEF DEAD BEEF"}
        )

        assert DummyContext.instances[0].put_keys == []
        assert result is False


class ScriptedCard:
    """A card connection that answers SELECT and VERIFY, and optionally nothing else."""

    def __init__(self, refuse_writes):
        self.refuse_writes = refuse_writes
        self.apdus = []

    def transmit(self, apdu):
        self.apdus.append(list(apdu))
        if not self.refuse_writes or apdu[1] in (0xA4, 0x20):  # SELECT, VERIFY
            return ([], 0x90, 0x00)
        # Wrong data: what a curve or key size the applet lacks gets back
        return ([], 0x6A, 0x80)


@pytest.fixture
def card_holding(monkeypatch):
    """Run the import against `card` through the real SmartPGP commands."""

    def install(card):
        key = SimpleNamespace(subkeys={"s": p256_key(SUBKEY_FPR, {KeyFlags.Sign})})
        monkeypatch.setattr(
            smartpgp_import, "run",
            lambda *a, **kw: SimpleNamespace(stdout=b"-----BEGIN PGP-----", returncode=0),
        )
        monkeypatch.setattr(
            smartpgp_import.pgpy.PGPKey, "from_blob",
            classmethod(lambda cls, blob: (key, None)),
        )
        monkeypatch.setattr(highlevel, "select_reader", lambda reader_index: card)

    return install


class TestTheCardsAnswerDecides:
    """A command sent is not a key stored: the card's status word says which."""

    def test_writes_the_card_refused_are_not_success(self, card_holding):
        card = ScriptedCard(refuse_writes=True)
        card_holding(card)

        assert smartpgp_import.import_keys_with_smartpgp("FPR", "12345678") is False

    def test_writes_the_card_accepted_are_success(self, card_holding):
        card = ScriptedCard(refuse_writes=False)
        card_holding(card)

        assert smartpgp_import.import_keys_with_smartpgp("FPR", "12345678") is True
        # SELECT, VERIFY, then the slot's algorithm, key, fingerprint, timestamp
        assert [apdu[1] for apdu in card.apdus] == [0xA4, 0x20, 0xDA, 0xDB, 0xDA, 0xDA]


class RefusesChainedChunks:
    def __init__(self):
        self.apdus = []

    def transmit(self, apdu):
        self.apdus.append(list(apdu))
        if apdu[0] == 0x10:  # a chunk with more to follow
            return ([], 0x6A, 0x80)
        return ([], 0x90, 0x00)


class TestAChainedKeyChecksEveryChunk:
    """A key too big for one APDU is only stored if every chunk was taken."""

    def test_a_refused_chunk_stops_the_key(self):
        card = RefusesChainedChunks()

        with pytest.raises(commands.CardRefusedCommand):
            commands.put_key_components(card, "sig", [(0x92, bytes(300))])

        assert len(card.apdus) == 1, "chunks went on after the card refused one"
