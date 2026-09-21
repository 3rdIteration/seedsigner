# pylint: disable=missing-function-docstring
import threading
import time

import pytest

# Must import base before any seedsigner modules
from base import BaseTest

from embit.ec import PrivateKey
from seedsigner.views import satochip_bias
from seedsigner.hardware.microsd import MicroSD


KEY = PrivateKey(bytes([3]) * 32)


class RecordingScreens:
    def __init__(self):
        self.calls = []

    def __call__(self, screen_cls, **kwargs):
        self.calls.append(kwargs)
        return 0

    @property
    def texts(self):
        return [c.get("text") or "" for c in self.calls]


class TimingOutCard:
    """A card that signs, but whose 5th signature never comes back.

    The stall is real -- the call blocks past the timeout rather than raising
    TimeoutError itself -- so this also covers _call_with_timeout returning
    without waiting for its worker.
    """

    transport = "test"

    def __init__(self, timeout_at=5):
        self.calls = 0
        self.timeout_at = timeout_at
        self.release = threading.Event()

    def card_sign_transaction_hash(self, keynbr, txhash, chalresponse=None):
        self.calls += 1
        if self.calls == self.timeout_at:
            self.release.wait(30)
            return (b"", 0x6F, 0x00)
        return (KEY.sign(bytes(txhash)).serialize(), 0x90, 0x00)


class DummyLoadingScreenThread:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        pass

    def stop(self):
        pass


class TestHardTimeoutsFailTheTest(BaseTest):
    """A signature that never arrives is the strongest timeout evidence there is."""

    def test_a_timed_out_signature_fails_the_bias_test(self, monkeypatch, tmp_path):
        # Note: do NOT patch time.sleep here. It is the global clock, and the
        # Controller's WipeTimerThread sleeps on it once a second -- no-oping it
        # turns that thread into a hot loop that starves the whole test session.
        monkeypatch.setattr(satochip_bias.ToolsSatochipBiasCheckView, "NUM_SAMPLES", 20)
        monkeypatch.setattr(
            "seedsigner.gui.screens.screen.LoadingScreenThread", DummyLoadingScreenThread
        )
        monkeypatch.setattr(MicroSD, "get_microsd_dir", staticmethod(lambda: tmp_path))
        card = TimingOutCard()
        monkeypatch.setattr(
            satochip_bias.seedkeeper_utils, "init_satochip", lambda *a, **kw: card
        )

        view = satochip_bias.ToolsSatochipBiasCheckView()
        screens = RecordingScreens()
        monkeypatch.setattr(view, "run_screen", screens, raising=False)

        started = time.monotonic()
        try:
            view.run()
        finally:
            card.release.set()
        elapsed = time.monotonic() - started

        # The stalled signature must cost the configured timeout, not 30s
        assert elapsed < 10, f"the stalled call held the run for {elapsed:.1f}s"
        report = (tmp_path / "satochip_bias_test.txt").read_text()
        assert "hard=1" in report, report
        assert "Status: FAIL" in report, report
        assert "HardTimeout" in report, report
        # The fifth request never came back, so that worker may still be talking
        # to the card; the verdict is already FAIL, and any further request would
        # only queue behind it.
        assert card.calls == 5, f"{card.calls - 5} requests went to a busy card"


class TestKeycardHardTimeoutsFailTheTest(BaseTest):
    """
    The Keycard bias check had the same shape as the Satochip one before it was
    fixed: a signature that never arrived was filed as a generic "exception",
    which feeds no verdict, so a Keycard that stalls could still pass.
    """

    def test_a_timed_out_signature_fails_the_keycard_bias_test(self, monkeypatch, tmp_path):
        from seedsigner.views import keycard_bias

        monkeypatch.setattr(keycard_bias.ToolsKeycardBiasCheckView, "NUM_SAMPLES", 20)
        monkeypatch.setattr(
            "seedsigner.gui.screens.screen.LoadingScreenThread", DummyLoadingScreenThread
        )
        monkeypatch.setattr(MicroSD, "get_microsd_dir", staticmethod(lambda: tmp_path))
        card = TimingOutCard()
        monkeypatch.setattr(
            keycard_bias.seedkeeper_utils, "init_satochip", lambda *a, **kw: card
        )

        view = keycard_bias.ToolsKeycardBiasCheckView()
        monkeypatch.setattr(view, "run_screen", RecordingScreens(), raising=False)

        started = time.monotonic()
        try:
            view.run()
        finally:
            card.release.set()
        elapsed = time.monotonic() - started

        assert elapsed < 10, f"the stalled call held the run for {elapsed:.1f}s"
        report = (tmp_path / "keycard_bias_test.txt").read_text()
        assert "hard=1" in report, report
        assert "Status: FAIL" in report, report
        assert "HardTimeout" in report, report
        assert card.calls == 5, f"{card.calls - 5} requests went to a busy card"
