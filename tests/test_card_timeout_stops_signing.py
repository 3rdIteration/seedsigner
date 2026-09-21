# pylint: disable=missing-function-docstring
"""
The first request a card does not answer ends the job.

A timed-out request cannot be stopped, so the card goes on working on it, and
every request after it waits for that one out of its own timeout before it is
refused. A signing or benchmark loop that carried on after a timeout therefore
waited once more for every input, dummy and sample left, and only then offered
the retry.
"""
import threading
import time
from types import SimpleNamespace

import pytest

# Must import base before any seedsigner modules: seedkeeper_utils pulls in the
# GUI, and imported first it keeps the real hardware and renderer modules.
import base  # noqa: F401

from embit.ec import PrivateKey
from embit.psbt import DerivationPath, InputScope, PSBT

from seedsigner.helpers import keycard_signer, satochip_signer
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import smartcard_views


TIMEOUT = 0.3


class StallingCard:
    """A card that never answers a signing request; derivations still work."""

    def __init__(self, pubkeys):
        self.pubkeys = pubkeys
        self.requests = []
        self.release = threading.Event()

    def card_bip32_get_extendedkey(self, path):
        self.requests.append(("derive", path))
        idx = int(path.split("/")[1])
        return SimpleNamespace(get_public_key_bytes=lambda compressed=True: self.pubkeys[idx]), b""

    def card_sign_transaction_hash(self, keynbr, h, none):
        self.requests.append(("sign", bytes(h)))
        self.release.wait(10)
        return None, 0x6F, 0x00


class TimeoutSettings:
    def __init__(self, pre_dummies=0, post_dummies=0):
        self.pre_dummies = pre_dummies
        self.post_dummies = post_dummies

    def get_value(self, setting):
        if setting in (
            SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT,
            SettingsConstants.SETTING__KEYCARD_SIGN_TIMEOUT,
        ):
            return TIMEOUT
        if setting == SettingsConstants.SETTING__SATOCHIP_MAX_PRE_DUMMIES:
            return self.pre_dummies
        if setting == SettingsConstants.SETTING__SATOCHIP_MAX_POST_DUMMIES:
            return self.post_dummies
        return 0


def five_input_psbt():
    psbt = PSBT()
    psbt.inputs = [InputScope() for _ in range(5)]
    pubkeys = []
    for i, inp in enumerate(psbt.inputs):
        pub = PrivateKey(bytes([i + 1]) * 32).get_public_key()
        inp.bip32_derivations[pub] = DerivationPath(b"\x00" * 4, [i])
        pubkeys.append(pub.sec())
    psbt.sighash = lambda idx, sighash=None: bytes([idx]) * 32
    return psbt, pubkeys


@pytest.fixture
def card(monkeypatch):
    # The abandoned request is module state; each test starts with none and
    # leaves none behind.
    monkeypatch.setattr(satochip_signer, "_abandoned_request", None)
    psbt, pubkeys = five_input_psbt()
    stalling = StallingCard(pubkeys)
    yield psbt, stalling
    stalling.release.set()


SIGNERS = [satochip_signer.sign_psbt_with_satochip, keycard_signer.sign_psbt_with_keycard]


@pytest.mark.parametrize("sign", SIGNERS)
def test_signing_stops_at_the_first_timeout(monkeypatch, card, sign):
    psbt, stalling = card
    monkeypatch.setattr(Settings, "get_instance", classmethod(lambda cls: TimeoutSettings()))

    start = time.monotonic()
    result = sign(psbt, stalling)
    elapsed = time.monotonic() - start

    assert result.timed_out
    assert result.signed_count == 0
    assert [r for r in stalling.requests if r[0] == "sign"] == stalling.requests[-1:]
    # One timeout, not one for each of the four inputs left.
    assert elapsed < 2 * TIMEOUT, elapsed


@pytest.mark.parametrize("sign", SIGNERS)
def test_a_dummy_that_times_out_reaches_the_retry(monkeypatch, card, sign):
    psbt, stalling = card
    monkeypatch.setattr(Settings, "get_instance", classmethod(lambda cls: TimeoutSettings(pre_dummies=3)))
    monkeypatch.setattr("random.randint", lambda a, b: b)
    monkeypatch.setattr("random.random", lambda: 1.0)

    start = time.monotonic()
    result = sign(psbt, stalling)
    elapsed = time.monotonic() - start

    # A dummy is a real request: it timing out leaves the card as busy as a
    # real signature would, so the user is offered the same retry.
    assert result.timed_out
    assert len(stalling.requests) == 1
    assert elapsed < 2 * TIMEOUT, elapsed


@pytest.mark.parametrize("sign", SIGNERS)
def test_a_post_signing_dummy_that_times_out_ends_the_dummies(monkeypatch, sign):
    monkeypatch.setattr(satochip_signer, "_abandoned_request", None)
    # Nothing to sign, so the only requests are the three dummies after it.
    psbt = PSBT()
    stalling = StallingCard([])
    monkeypatch.setattr(Settings, "get_instance", classmethod(lambda cls: TimeoutSettings(post_dummies=3)))
    monkeypatch.setattr("random.randint", lambda a, b: b if b == 3 else a)
    monkeypatch.setattr("random.random", lambda: 1.0)

    try:
        start = time.monotonic()
        result = sign(psbt, stalling)
        elapsed = time.monotonic() - start
    finally:
        stalling.release.set()

    assert result.timed_out
    assert len(stalling.requests) == 1
    # One timeout, not one more for each dummy left.
    assert elapsed < 2 * TIMEOUT, elapsed


def test_the_satochip_benchmark_stops_at_the_first_timeout(monkeypatch, card):
    _, stalling = card
    shown, sent = [], []

    def times_out(func, timeout, *args):
        sent.append(func.__name__)
        raise satochip_signer.TimeoutError()

    monkeypatch.setattr(smartcard_views.seedkeeper_utils, "init_satochip", lambda *a, **kw: stalling)
    monkeypatch.setattr(smartcard_views, "_call_with_timeout", times_out)
    monkeypatch.setattr(
        "seedsigner.gui.screens.screen.LoadingScreenThread",
        lambda **kw: SimpleNamespace(start=lambda: None, stop=lambda: None),
    )
    view = smartcard_views.ToolsSatochipBenchmarkSignView()
    monkeypatch.setattr(view, "run_screen", lambda cls, **kw: shown.append(kw.get("text")))

    view.run()

    # 20 samples, each waiting a full timeout behind the first, took minutes.
    assert sent == ["card_sign_transaction_hash"]
    assert shown == ["Benchmark signing failed"]
