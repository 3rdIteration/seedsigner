"""
    Run the real JavaCard applets under test, in jcardsim.

    The real-screen suites stand in for the card at
    ``seedkeeper_utils.init_satochip``; that proves the *screens* behave, but says
    nothing about whether SeedSigner's client code and the applet agree. This package
    closes that gap by putting the actual applet bytecode -- SeedKeeper, Satochip,
    Keycard, SmartPGP -- behind SeedSigner's real client stacks, so a status word the
    applet returns is the status word the app has to handle. That is where this fork's
    recent card bugs actually were (e.g. the SeedKeeper 0x9C01 card-full mapping).

    Everything here skips cleanly when Java or the applet sources are absent, so a
    checkout without them still runs the rest of the suite.
"""

from .simulator import (  # noqa: F401
    JCardSimUnavailable,
    SimulatedCard,
    simulator_available,
    why_unavailable,
)
from .applets import APPLETS, AppletSpec, resolve_applet  # noqa: F401
