"""
    Put a simulated card in front of SeedSigner's real client stacks.

    There is no single seam for this. The four clients reach PC/SC at different levels,
    so each needs its own patch:

    * ``pysatochip`` (Satochip, SeedKeeper) never calls ``readers()`` -- it uses
      ``CardRequest``/``CardMonitor`` from pyscard's higher-level API and takes whichever
      card turns up first. Patched in ``pysatochip.CardConnector``'s own namespace.
    * ``keycard-py`` and the vendored SmartPGP module both do
      ``readers()[0].createConnection()``. Patched at ``smartcard.System.readers``.
    * ``pygp`` uses the low-level ``smartcard.scard`` ctypes binding. Not covered here --
      and GlobalPlatform install/uninstall is not simulatable anyway, since jcardsim
      installs applets programmatically and has no card manager.

    Everything funnels into one `SimulatedCard.transmit`, which already returns pyscard's
    ``(data, sw1, sw2)`` shape.
"""

from contextlib import ExitStack, contextmanager
from unittest.mock import patch

# A plausible JavaCard ATR. Nothing in SeedSigner parses it, but pysatochip's insert
# observer compares one against the Windows Hello virtual-device ATR, so it must exist
# and must not be that.
SIMULATED_ATR = [0x3B, 0xF9, 0x18, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x45, 0x4A, 0x43, 0x4F,
                 0x50, 0x76, 0x32, 0x34, 0x31, 0xB7]


class SimulatedConnection:
    """pyscard `CardConnection`-shaped, backed by the jcardsim socket."""

    def __init__(self, card):
        self._card = card
        self.connected = False

    # pyscard surface ------------------------------------------------------
    def connect(self, *args, **kwargs):
        self.connected = True

    def disconnect(self):
        self.connected = False

    def transmit(self, apdu, protocol=None):
        return self._card.transmit(apdu)

    def getATR(self):
        return list(SIMULATED_ATR)

    def getReader(self):
        return "jcardsim simulator"

    # Observers are a pyscard logging hook; pysatochip attaches one and never reads it.
    def addObserver(self, observer):
        pass

    def deleteObserver(self, observer):
        pass


class SimulatedCardService:
    """What `CardRequest.waitforcard()` hands back."""

    def __init__(self, card):
        self.connection = SimulatedConnection(card)
        self.atr = list(SIMULATED_ATR)

    def createConnection(self):
        return self.connection


class SimulatedReader:
    """What `readers()` returns."""

    def __init__(self, card):
        self._card = card
        self.name = "jcardsim simulator"

    def createConnection(self):
        return SimulatedConnection(self._card)

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"<SimulatedReader {self.name}>"


@contextmanager
def patched_pcsc(card):
    """
    Route every pyscard-based client at `card` for the duration of the block.

    Applied narrowly and by name so a failure to patch shows up as the real client
    raising, rather than as a test that silently talks to nothing.
    """
    service = SimulatedCardService(card)

    class _CardRequest:
        def __init__(self, *args, **kwargs):
            pass

        def waitforcard(self):
            return service

        def waitforcardevent(self):
            return [service]

    class _CardMonitor:
        def addObserver(self, observer):
            # Hand the observer the card straight away, the way pyscard would on insert.
            # pysatochip's RemovalObserver uses this to set card_present and to read the
            # CPLC/IIN/CIN, so skipping it would leave the connector half-initialised.
            observer.update(self, ([service], []))

        def deleteObserver(self, observer):
            pass

    with ExitStack() as stack:
        # pysatochip: patched inside its own module, since that is where the names are
        # bound (`from smartcard.CardRequest import CardRequest`).
        try:
            import pysatochip.CardConnector as cc  # noqa: F401

            stack.enter_context(patch.object(cc, "CardRequest", _CardRequest))
            stack.enter_context(patch.object(cc, "CardMonitor", _CardMonitor))
        except ImportError:
            pass

        # keycard-py and the vendored SmartPGP module both go through readers()[0].
        stack.enter_context(
            patch("smartcard.System.readers", lambda *a, **kw: [SimulatedReader(card)])
        )
        try:
            import keycard.transport as keycard_transport  # noqa: F401

            stack.enter_context(
                patch.object(keycard_transport, "readers", lambda *a, **kw: [SimulatedReader(card)])
            )
        except ImportError:
            pass
        try:
            from seedsigner.helpers.smartpgp import commands as smartpgp_commands  # noqa: F401

            stack.enter_context(
                patch.object(smartpgp_commands, "readers", lambda *a, **kw: [SimulatedReader(card)])
            )
        except ImportError:
            pass

        yield card
