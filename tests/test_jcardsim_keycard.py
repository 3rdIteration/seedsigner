"""
    Keycard and SmartPGP under jcardsim -- and the two reasons neither runs yet.

    SeedKeeper and Satochip both work (see test_jcardsim_seedkeeper.py and
    test_jcardsim_satochip.py): they compile from source, install, and answer real
    status words through SeedSigner's own client stacks. These two do not, for reasons
    that are specific and worth recording rather than leaving as a silent gap:

    * **Keycard** compiles and loads, but its `install()` fails inside jcardsim. The
      cause is unrecoverable from the outside: `Simulator.createApplet` catches whatever
      the applet threw and rethrows a bare `SW_APPLET_CREATION_FAILED` (0x6444), so the
      real reason never surfaces. It is not the install-parameter format -- all four
      combinations of block style and registration AID fail identically. status-keycard
      vendors jcardsim's full source, so surfacing the cause means building a patched
      jcardsim, which is a bigger piece of work than it looks.

    * **SmartPGP** cannot compile against this simulator's API at all. Its current
      source imports `javacard.security.NamedParameterSpec` and `javacard.security.XECKey`,
      which are JavaCard 3.1; jcardsim 3.0.5 implements 3.0.x and contains neither class.
      Compiling against a 3.1 SDK would only move the failure to a NoClassDefFoundError
      at load time. Simulating SmartPGP needs a jcardsim with 3.1 support, or an older
      SmartPGP revision predating those imports.

    These tests are written to *pass the moment either becomes possible*: they attempt
    the real thing and skip with the specific diagnosis, rather than asserting the
    failure and having to be rewritten when it is fixed.
"""

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401

from jcardsim import JCardSimUnavailable, open_card, why_unavailable


pytestmark = pytest.mark.skipif(
    why_unavailable() is not None, reason=f"jcardsim unavailable: {why_unavailable()}"
)


class TestKeycard:

    def test_applet_compiles(self):
        """
        Keycard's sources do build, given keycard-math.jar.

        Worth asserting separately from the install: the applet references
        `im.status.keycard.math.BigNumberMath`, which the repo ships only as a compiled
        JavaCard library with no sources, so the compile step is a real dependency
        question and not a formality.
        """
        from jcardsim import resolve_applet

        try:
            spec, classes = resolve_applet("keycard")
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        assert (classes / "im/status/keycard/KeycardApplet.class").is_file()

    def test_applet_installs_and_selects(self):
        try:
            card = open_card("keycard")
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        try:
            with card:
                _, sw1, sw2 = card.select()
        except JCardSimUnavailable as exc:
            # See the module docstring: jcardsim swallows the applet's own exception, so
            # this is as much detail as exists.
            pytest.skip(f"Keycard does not install in jcardsim 3.0.5: {exc}")

        assert (sw1, sw2) == (0x90, 0x00)



class TestSmartPGP:

    def test_applet_installs_and_selects(self):
        try:
            card = open_card("smartpgp")
        except JCardSimUnavailable as exc:
            # Reached both when the repo is absent (the usual case -- only the built CAPs
            # ship in javacard-cap/) and when the compile fails on the JavaCard 3.1 EC
            # API that jcardsim does not implement.
            pytest.skip(f"SmartPGP not simulatable: {exc}")

        try:
            with card:
                _, sw1, sw2 = card.select()
        except JCardSimUnavailable as exc:
            pytest.skip(f"SmartPGP does not install in jcardsim 3.0.5: {exc}")

        assert (sw1, sw2) == (0x90, 0x00)
