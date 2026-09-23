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
from .applets import APPLETS, AppletSpec, open_card, resolve_applet  # noqa: F401


def why_keycard_unavailable() -> str | None:
    """
    A reason the Keycard *client* cannot be exercised, or None if keycard-py imports.

    The Keycard tests here drive SeedSigner's real keycard-py adapter (the same one used
    against a physical card), which is a desktop/jcardsim dependency rather than part of
    the device requirements -- CI installs it from requirements-keycard.txt. Returning a
    reason lets a checkout without it skip cleanly instead of erroring on import.
    """
    from seedsigner.helpers.keycard_connector import get_keycard_class

    if get_keycard_class() is None:
        return "keycard-py not importable (install it or set SEEDSIGNER_KEYCARD_PY_PATH)"
    return None
