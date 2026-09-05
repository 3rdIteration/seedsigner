"""
    SeedKeeper v0.1 and v0.2, running as real applet bytecode in jcardsim, driven by
    SeedSigner's real pysatochip client.

    The real-screen suites stand in for the card, which proves the screens behave but
    says nothing about whether SeedSigner and the applet agree on the wire. These tests
    close that: every status word here came out of the actual applet.

    The case that matters most is a full card. `describe_seedkeeper_error` gives a
    different message for v0.1 than v0.2, because v0.1 has no reset-secret instruction
    and so cannot free space -- a factory reset is the only way out. Until now that
    branch, and the `is_seedkeeper_v1` check it turns on, could only be exercised
    against a physical card. Here both versions are filled for real and the resulting
    0x9C01 is put through SeedSigner's own error handling.
"""

import sys
from unittest.mock import MagicMock

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401

# base.py replaces pysatochip with MagicMocks so the ordinary suite can run without a
# card. These tests need the real library, so drop the stubs before anything imports it.
for _name in [m for m in sys.modules if m == "pysatochip" or m.startswith("pysatochip.")]:
    if isinstance(sys.modules[_name], MagicMock):
        del sys.modules[_name]

from jcardsim import JCardSimUnavailable, SimulatedCard, resolve_applet, why_unavailable
from jcardsim.applets import APPLETS
from jcardsim.pcsc_shim import patched_pcsc


pytestmark = pytest.mark.skipif(
    why_unavailable() is not None, reason=f"jcardsim unavailable: {why_unavailable()}"
)

PIN = list(b"1234")
VERSIONS = ["seedkeeper_v01", "seedkeeper_v02"]


@pytest.fixture(params=VERSIONS)
def seedkeeper(request):
    """
    A freshly installed SeedKeeper of each version.

    Function-scoped on purpose: a card carries its state, and a test that inherited a
    previous test's secrets or PIN would be reasoning about the wrong card.
    """
    try:
        spec, classes = resolve_applet(request.param)
    except JCardSimUnavailable as exc:
        pytest.skip(str(exc))

    with SimulatedCard(spec, classes) as card:
        card.select()
        card.version = request.param
        yield card


@pytest.fixture
def connector(seedkeeper):
    """SeedSigner's real pysatochip client, talking to the simulated card."""
    with patched_pcsc(seedkeeper):
        from pysatochip.CardConnector import CardConnector

        cc = CardConnector(card_filter=["seedkeeper"])
        cc.version = seedkeeper.version
        yield cc


def setup_and_login(cc) -> None:
    """Take a blank card through setup and PIN verification."""
    cc.card_setup(5, 1, PIN, PIN, 5, 1, PIN, PIN, 32, 32, 0x01, 0x01, 0x01)
    cc.set_pin(0, PIN)
    cc.card_verify_PIN()


def import_password(cc, label: str, secret: bytes = b"pass") -> tuple[int, str]:
    header = cc.make_header("Password", "Plaintext export allowed", label)
    return cc.seedkeeper_import_secret(
        {"header": header, "secret_list": [len(secret)] + list(secret)}
    )



class TestRegistryConsistency:
    """The simulator must be pointed at the same applets the app installs."""

    def test_class_names_and_aids_match_the_app(self):
        """
        `_JAVACARD_APPLETS` in smartcard_views is what the device builds and installs.
        If the simulator registry drifts from it, these tests would be exercising an
        applet the app never talks to.
        """
        from seedsigner.views.smartcard_views import _JAVACARD_APPLETS

        app_seedkeeper = _JAVACARD_APPLETS["seedkeeper"]
        for name in VERSIONS:
            spec = APPLETS[name]
            assert spec.applet_class == app_seedkeeper["applet_class"]
            # The app records the package AID; the instance AID appends 00.
            assert spec.aid.upper() == app_seedkeeper["aid"].upper() + "00"

        app_satochip = _JAVACARD_APPLETS["satochip"]
        assert APPLETS["satochip"].applet_class == app_satochip["applet_class"]
        assert APPLETS["satochip"].aid.upper() == app_satochip["aid"].upper() + "00"



class TestAppletResponds:
    """Raw APDUs, before any client library is involved."""

    def test_select_and_status(self, seedkeeper):
        data, sw1, sw2 = seedkeeper.select()
        assert (sw1, sw2) == (0x90, 0x00)

        data, sw1, sw2 = seedkeeper.transmit([0xB0, 0x3C, 0x00, 0x00, 0x00])
        assert (sw1, sw2) == (0x90, 0x00)
        # First two bytes of the status block are the protocol version.
        expected = 1 if seedkeeper.version == "seedkeeper_v01" else 2
        assert data[0] == 0 and data[1] == expected

    def test_listing_secrets_before_pin_is_refused(self, seedkeeper):
        """An unauthenticated card must refuse to enumerate its secrets."""
        _, sw1, sw2 = seedkeeper.transmit([0xB0, 0xA7, 0x00, 0x00, 0x00])
        assert (sw1, sw2) == (0x9C, 0x20), "expected SW_UNAUTHORIZED before PIN"



class TestSeedKeeperThroughPysatochip:
    """The same card, through the client stack SeedSigner actually uses."""

    def test_card_is_recognised(self, connector):
        assert connector.card_present
        assert connector.card_type == "SeedKeeper"

    def test_protocol_version_distinguishes_the_two_applets(self, connector):
        expected = 0x0001 if connector.version == "seedkeeper_v01" else 0x0002
        assert connector.protocol_version == expected

    def test_is_seedkeeper_v1_matches_the_applet(self, connector):
        """
        The v1 check drives a user-facing branch (a full v1 card needs a factory reset),
        so it has to agree with the applet actually on the card.
        """
        from seedsigner.helpers.seedkeeper_utils import is_seedkeeper_v1

        setup_and_login(connector)
        assert is_seedkeeper_v1(connector) is (connector.version == "seedkeeper_v01")

    def test_import_list_export_round_trip(self, connector):
        setup_and_login(connector)

        sid, fingerprint = import_password(connector, "sim-test", b"correct horse")
        assert fingerprint

        headers = connector.seedkeeper_list_secret_headers()
        assert [h["label"] for h in headers] == ["sim-test"]
        assert headers[0]["id"] == sid

        exported = connector.seedkeeper_export_secret(sid)
        assert exported["label"] == "sim-test"
        # The stored blob is length-prefixed.
        assert bytes(exported["secret_list"][1:]) == b"correct horse"

    def test_secrets_accumulate(self, connector):
        setup_and_login(connector)
        for i in range(3):
            import_password(connector, f"secret-{i}")
        labels = sorted(h["label"] for h in connector.seedkeeper_list_secret_headers())
        assert labels == ["secret-0", "secret-1", "secret-2"]



class TestFullCard:
    """
    Filling a card for real, and checking SeedSigner says the right thing about it.

    This is the path commit 49095f60 fixed: a full card answers 0x9C01, and the advice
    that follows differs by applet version because v0.1 cannot delete secrets.
    """

    def fill_until_full(self, cc):
        """Import until the applet refuses; returns the exception it raised."""
        blob = [0x80] + [0x41] * 128
        for i in range(400):
            try:
                cc.seedkeeper_import_secret({
                    "header": cc.make_header("Data", "Plaintext export allowed", f"f{i}"),
                    "secret_list": blob,
                })
            except Exception as exc:
                return exc
        pytest.fail("the card never filled up")

    def test_full_card_reports_no_memory_left(self, connector):
        from seedsigner.helpers.seedkeeper_utils import sw_from_exception

        setup_and_login(connector)
        exc = self.fill_until_full(connector)

        assert sw_from_exception(exc) == 0x9C01, (
            f"expected SW_NO_MEMORY_LEFT from a full card, got {exc!r}"
        )

    def test_full_card_advice_depends_on_the_applet_version(self, connector):
        """
        v0.1 has no reset-secret instruction, so "delete a secret" is useless advice --
        it must tell the user a factory reset is required instead.
        """
        from seedsigner.helpers.seedkeeper_utils import describe_seedkeeper_error

        setup_and_login(connector)
        exc = self.fill_until_full(connector)

        message = describe_seedkeeper_error(exc, connector=connector)
        assert "memory is full" in message.lower()

        if connector.version == "seedkeeper_v01":
            assert "factory reset" in message.lower()
        else:
            assert "delete a secret" in message.lower()
            assert "factory reset" not in message.lower()
