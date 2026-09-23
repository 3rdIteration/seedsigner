"""
    SpecterDIY (specter-javacard's MemoryCardApplet) as real applet bytecode in jcardsim,
    driven by SeedSigner's real client stack -- the specter_card module that
    smartcard_views loads through _get_specter_card_api().

    This is a full protocol test rather than an APDU echo: opening the secure channel
    performs secp256k1 ECDH between Python (cryptography) and the applet's pure-Java
    Secp256k1 implementation, and every get/store afterwards travels as an encrypted,
    MAC'd secure message. A pass means the on-card crypto really ran.

    The spec is pinned to 0.1-pytest; master is one commit ahead of it and that commit
    only adds py/, so a plain clone compiles identical bytecode either way (see
    applets.py).
"""

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401

from jcardsim import JCardSimUnavailable, open_card, resolve_applet, why_unavailable
from jcardsim.pcsc_shim import patched_pcsc


pytestmark = pytest.mark.skipif(
    why_unavailable() is not None, reason=f"jcardsim unavailable: {why_unavailable()}"
)

# SPECTER_JAVACARD_DEFAULT_AID in smartcard_views.
AID = "B00B5111CB01"


@pytest.fixture
def specterdij():
    try:
        card = open_card("specterdij")
    except JCardSimUnavailable as exc:
        pytest.skip(str(exc))
    with card:
        yield card


@pytest.fixture
def client(specterdij):
    """SeedSigner's own discovery of the specter_card module, against a simulated card."""
    from seedsigner.views.smartcard_views import _get_specter_card_api

    try:
        Card, MemoryCardApplet, SecureApplet = _get_specter_card_api()
    except ImportError as exc:
        pytest.skip(f"specter_card module unavailable: {exc}")
    with patched_pcsc(specterdij):
        conn = Card(AID)
        conn.connect()  # SELECTs the applet; raises ISOException on a bad AID
        yield Card, MemoryCardApplet, SecureApplet, conn


def open_channel(SecureApplet, conn):
    """smartcard_views' own mode fallback (ee -> es -> ss)."""
    from seedsigner.views.smartcard_views import _open_specter_secure_channel

    return _open_specter_secure_channel(SecureApplet(conn))


class TestSpecterDIYBasics:

    def test_applet_compiles(self):
        """The toys package builds against the repo's own jc304_kit."""
        try:
            spec, classes = resolve_applet("specterdij")
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        assert (classes / "toys/MemoryCardApplet.class").is_file()


class TestSpecterDIYConnection:

    def test_connect_and_select(self, client):
        """Card(AID).connect() -- pyscard readers(), T=1 connect, SELECT by AID."""
        Card, MemoryCardApplet, SecureApplet, conn = client
        assert conn is not None


class TestSpecterDIYSecureChannel:

    def test_store_get_roundtrip(self, client):
        """ECDH key agreement plus an encrypted store and fetch of 64 bytes."""
        Card, MemoryCardApplet, SecureApplet, conn = client
        sc = open_channel(SecureApplet, conn)

        mem = MemoryCardApplet(conn)
        payload = bytes(range(64))
        stored = mem.store_data(sc, payload)
        assert stored == payload

        assert mem.get_data(sc) == payload

    def test_wipe_stores_empty(self, client):
        """The Wipe Seed path: store b"" and read back nothing."""
        Card, MemoryCardApplet, SecureApplet, conn = client
        sc = open_channel(SecureApplet, conn)

        mem = MemoryCardApplet(conn)
        mem.store_data(sc, bytes(range(32)))
        mem.store_data(sc, b"")
        assert mem.get_data(sc) == b""
